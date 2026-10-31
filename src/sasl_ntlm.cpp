// SASL NTLM (NTLMv2, MS-NLMP) client. See sasl_ntlm.hpp.
#include "jhetz/ldap/sasl_ntlm.hpp"

#include "format_util.hpp"
#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/ntlm_message.hpp"
#include "scope_util.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <memory_resource>
#include <optional>
#include <ratio>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

namespace {

	using detail::ntlm_challenge;
	using detail::ntlm_key;

	constexpr unsigned byte_bits = 8;
	constexpr std::uint32_t byte_mask = 0xFF;
	constexpr std::size_t max_av_length = 0xFFFF;// AvLen is a USHORT

	// The flags of the NEGOTIATE_MESSAGE (MS-NLMP section 2.2.2.5): Unicode,
	// the target's name, NTLM with extended session security (NTLMv2's),
	// TargetInfo, a Version, 128-bit keys; no signing, sealing nor key
	// exchange without a security layer.
	constexpr std::uint32_t client_flags =
	  detail::ntlmssp_negotiate_unicode | detail::ntlmssp_request_target | detail::ntlmssp_negotiate_ntlm
	  | detail::ntlmssp_negotiate_extended_sessionsecurity | detail::ntlmssp_negotiate_target_info
	  | detail::ntlmssp_negotiate_version | detail::ntlmssp_negotiate_128;

	// What a security layer adds (MS-NLMP section 3.4): signing with key
	// exchange, and sealing for confidentiality.
	auto requested_flags(sasl_protection layer) -> std::uint32_t
	{
		switch (layer) {
		case sasl_protection::none:
			break;
		case sasl_protection::integrity:
			return client_flags | detail::ntlmssp_negotiate_sign | detail::ntlmssp_negotiate_key_exch;
		case sasl_protection::confidentiality:
			return client_flags | detail::ntlmssp_negotiate_sign | detail::ntlmssp_negotiate_seal
				   | detail::ntlmssp_negotiate_key_exch;
		}
		return client_flags;
	}

	// The flags a layer needs the server to grant, and their names.
	constexpr std::array<std::pair<std::uint32_t, std::string_view>, 4> layer_flag_names{ {
	  { detail::ntlmssp_negotiate_sign, "NTLMSSP_NEGOTIATE_SIGN" },
	  { detail::ntlmssp_negotiate_seal, "NTLMSSP_NEGOTIATE_SEAL" },
	  { detail::ntlmssp_negotiate_key_exch, "NTLMSSP_NEGOTIATE_KEY_EXCH" },
	  { detail::ntlmssp_negotiate_128, "NTLMSSP_NEGOTIATE_128" },
	} };

	// SIGNKEY and SEALKEY's magic constants (MS-NLMP sections 3.4.5.2 and
	// 3.4.5.3), with their terminating NUL, which the MD5 covers.
	using namespace std::string_view_literals;
	constexpr std::string_view client_signing_magic = "session key to client-to-server signing key magic constant\0"sv;
	constexpr std::string_view server_signing_magic = "session key to server-to-client signing key magic constant\0"sv;
	constexpr std::string_view client_sealing_magic = "session key to client-to-server sealing key magic constant\0"sv;
	constexpr std::string_view server_sealing_magic = "session key to server-to-client sealing key magic constant\0"sv;

	// Whether the server's flags grant the layer: security_layer_unavailable
	// naming the flags missing otherwise.
	auto layer_granted(sasl_protection layer, std::uint32_t server_flags) -> result<void>
	{
		const std::uint32_t flags = requested_flags(layer);
		std::string missing;
		for (const auto &[flag, flag_name] : layer_flag_names) {
			if ((flags & flag) != 0 && (server_flags & flag) == 0) {
				missing += missing.empty() ? "" : ", ";
				missing += flag_name;
			}
		}
		if (missing.empty()) {
			return {};
		}
		return fail(client_errc::security_layer_unavailable,
		  detail::format("the server does not grant the {} security layer (no {} in the CHALLENGE_MESSAGE)",
			layer == sasl_protection::integrity ? "integrity" : "confidentiality",
			missing));
	}

	constexpr std::uint64_t max_seq_num = std::numeric_limits<std::uint32_t>::max();

	// The Version sent (for debugging only, MS-NLMP section 2.2.2.10): no
	// product version, NTLMSSP_REVISION_W2K3.
	constexpr detail::ntlm_version client_version{};

	// Responserversion and HiResponserversion of the NTLMv2 temp structure.
	constexpr char ntlmv2_response_version = 1;

	// 100 ns intervals between 1601-01-01 (FILETIME's epoch) and 1970-01-01.
	constexpr std::uint64_t filetime_unix_epoch = 116'444'736'000'000'000ull;
	constexpr std::intmax_t filetime_per_second = 10'000'000;

	auto input_error(std::string_view what) -> std::unexpected<error> { return fail(client_errc::encode_error, what); }

	auto library_error(std::string_view what) -> std::unexpected<error>
	{
		return fail(client_errc::internal_error, what);
	}

	auto refused(std::string_view what) -> std::unexpected<error>
	{
		return fail(client_errc::unexpected_response, what);
	}

	// Wipes a string's whole buffer, also the bytes past size() that a move
	// out of a short (SSO) string leaves behind.
	void wipe_string(std::string &s) noexcept
	{
		s.resize(s.capacity());// NOLINT(clang-analyzer-cplusplus.Move): wipes what a move left
		OPENSSL_cleanse(s.data(), s.size());
		s.clear();
	}

	// A string holding the password's UTF-16, wiped when it goes out of
	// scope. It is filled in place (ntlm_unicode's out-parameter form), never
	// moved from another string, which would leave the short-string bytes
	// behind in the source.
	struct wiped_string
	{
		std::string s;
		wiped_string() = default;
		wiped_string(const wiped_string &) = delete;
		auto operator=(const wiped_string &) -> wiped_string & = delete;
		~wiped_string() { wipe_string(s); }
	};

	struct wiped_key
	{
		ntlm_key k{};
		wiped_key() = default;
		explicit wiped_key(const ntlm_key &v) noexcept : k(v) {}
		wiped_key(const wiped_key &) = delete;
		auto operator=(const wiped_key &) -> wiped_key & = delete;
		~wiped_key() { OPENSSL_cleanse(k.data(), k.size()); }
	};

	auto as_chars(std::span<const unsigned char> s) -> std::string_view
	{
		return { reinterpret_cast<const char *>(s.data()), s.size() };
	}

	auto as_chars(std::span<const std::byte> s) -> std::string_view
	{
		return { reinterpret_cast<const char *>(s.data()), s.size() };
	}

	// MD5(ConcatenationOf(key, magic)) into `out`, the concatenation in a
	// wiped buffer.
	auto derive_key(const ntlm_key &key, std::string_view magic, ntlm_key &out) -> result<void>
	{
		wiped_string input;
		input.s.reserve(key.size() + magic.size());
		input.s.append(as_chars(key));
		input.s.append(magic);
		unsigned int n = 0;
		if (EVP_Digest(input.s.data(), input.s.size(), out.data(), &n, EVP_md5(), nullptr) != 1 || n != out.size()) {
			return library_error("OpenSSL MD5 failed");
		}
		return {};
	}

	void put_seq_num(std::span<std::byte> out, std::uint32_t v) noexcept
	{
		for (std::size_t i = 0; i < 4; ++i) {
			out[i] = static_cast<std::byte>((v >> (byte_bits * i)) & byte_mask);
		}
	}

	void put32(std::string &out, std::uint32_t v)
	{
		for (unsigned i = 0; i < 4; ++i) {
			out += static_cast<char>((v >> (byte_bits * i)) & byte_mask);
		}
	}

	void put64(std::string &out, std::uint64_t v)
	{
		for (unsigned i = 0; i < 8; ++i) {
			out += static_cast<char>((v >> (byte_bits * i)) & byte_mask);
		}
	}

	auto now_filetime() -> std::uint64_t
	{
		const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
		using filetime_ticks = std::chrono::duration<std::int64_t, std::ratio<1, filetime_per_second>>;
		const auto ticks = std::chrono::duration_cast<filetime_ticks>(since_epoch).count();
		return filetime_unix_epoch + static_cast<std::uint64_t>(std::max<std::int64_t>(ticks, 0));
	}

	auto md5(std::string_view data) -> result<ntlm_key>
	{
		ntlm_key out{};
		unsigned int n = 0;
		if (EVP_Digest(data.data(), data.size(), out.data(), &n, EVP_md5(), nullptr) != 1 || n != out.size()) {
			return library_error("OpenSSL MD5 failed");
		}
		return out;
	}

	// "DOMAIN\user" split at its first backslash; anything else is a user
	// name with no domain.
	auto split_user(std::string_view username) -> std::pair<std::string_view, std::string_view>
	{
		if (const auto at = username.find('\\'); at != std::string_view::npos) {
			return { username.substr(at + 1), username.substr(0, at) };
		}
		return { username, {} };
	}

}// namespace

namespace detail {

	auto ntlm_hmac_md5(std::span<const unsigned char> key, std::string_view data, ntlm_key &out) -> result<void>
	{
		unsigned int n = 0;
		const unsigned char *r = HMAC(EVP_md5(),
		  key.data(),
		  static_cast<int>(key.size()),
		  reinterpret_cast<const unsigned char *>(data.data()),
		  data.size(),
		  out.data(),
		  &n);
		if (r == nullptr || n != out.size()) {
			return library_error("OpenSSL HMAC-MD5 failed");
		}
		return {};
	}

	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): MS-NLMP's NTOWFv2(Passwd, User, UserDom)
	auto ntowfv2(std::string_view password, std::string_view user, std::string_view domain, ntlm_key &out)
	  -> result<void>
	{
		wiped_string pw;
		if (!ntlm_unicode(password, pw.s)) {// in place: no copy to wipe
			return input_error("the password is not valid UTF-8");
		}
		wiped_key nt_hash;
		md4(std::as_bytes(std::span(pw.s)), nt_hash.k);// in place: no temporary copy
		auto upper_user = ntlm_uppercase_unicode(user);
		if (!upper_user) {
			return input_error("the user name is not valid UTF-8");
		}
		auto unicode_domain = ntlm_unicode(domain);
		if (!unicode_domain) {
			return input_error("the domain is not valid UTF-8");
		}
		return ntlm_hmac_md5(nt_hash.k, *upper_user + *unicode_domain, out);
	}

	auto ntlm_compute_response(const ntlm_key &response_key,
	  const ntlm_challenge &server_challenge,
	  const ntlm_challenge &client_challenge,
	  std::uint64_t time,
	  std::string_view server_name,
	  bool server_timestamp,
	  ntlm_responses &out) -> result<void>
	{
		constexpr std::size_t z6 = 6;
		constexpr std::size_t z4 = 4;
		constexpr std::size_t z24 = 24;
		// temp = ConcatenationOf(Responserversion, HiResponserversion, Z(6),
		//   Time, ClientChallenge, Z(4), ServerName, Z(4))
		std::string temp{ ntlmv2_response_version, ntlmv2_response_version };
		temp.append(z6, '\0');
		put64(temp, time);
		temp += as_chars(client_challenge);
		temp.append(z4, '\0');
		temp += server_name;
		temp.append(z4, '\0');

		// NTProofStr = HMAC_MD5(ResponseKeyNT, ConcatenationOf(ServerChallenge, temp))
		ntlm_key proof{};// not secret: it goes on the wire
		if (auto r = ntlm_hmac_md5(response_key, std::string(as_chars(server_challenge)) + temp, proof); !r) {
			return r;
		}
		out.nt_challenge_response = std::string(as_chars(proof)) + temp;
		// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr), straight
		// into the caller's storage
		if (auto r = ntlm_hmac_md5(response_key, as_chars(proof), out.session_base_key); !r) {
			return r;
		}
		if (server_timestamp) {
			out.lm_challenge_response.assign(z24, '\0');
			return {};
		}
		// LmChallengeResponse = ConcatenationOf(HMAC_MD5(ResponseKeyLM,
		//   ConcatenationOf(ServerChallenge, ClientChallenge)), ClientChallenge)
		ntlm_key lm{};// not secret: it goes on the wire
		if (auto r = ntlm_hmac_md5(
			  response_key, std::string(as_chars(server_challenge)) + std::string(as_chars(client_challenge)), lm);
		  !r) {
			return r;
		}
		out.lm_challenge_response = std::string(as_chars(lm)) + std::string(as_chars(client_challenge));
		return {};
	}

	auto ntlm_channel_bindings_hash(std::string_view application_data) -> result<ntlm_key>
	{
		// initiator_addrtype, initiator_address (length 0), acceptor_addrtype,
		// acceptor_address (length 0), application_data (length, value).
		constexpr std::size_t no_addresses = 16;
		std::string flat(no_addresses, '\0');
		put32(flat, static_cast<std::uint32_t>(application_data.size()));
		flat += application_data;
		return md5(flat);
	}

	auto ntlm_derive_session_keys(const ntlm_key &exported_session_key, ntlm_session_keys &out) -> result<void>
	{
		// With NTLMSSP_NEGOTIATE_128 SEALKEY starts from the whole key.
		for (const auto &[magic, key] : { std::pair{ client_signing_magic, &out.client_signing_key },
			   std::pair{ client_sealing_magic, &out.client_sealing_key },
			   std::pair{ server_signing_magic, &out.server_signing_key },
			   std::pair{ server_sealing_magic, &out.server_sealing_key } }) {
			if (auto r = derive_key(exported_session_key, magic, *key); !r) {
				return r;
			}
		}
		return {};
	}

	ntlm_security_layer::ntlm_security_layer(const ntlm_session_keys &keys,
	  sasl_protection protection,
	  std::size_t max_received) noexcept
	  : protection_(protection), max_received_(max_received), client_signing_key_(keys.client_signing_key),
		server_signing_key_(keys.server_signing_key), client_handle_(keys.client_sealing_key),
		server_handle_(keys.server_sealing_key)
	{}

	ntlm_security_layer::~ntlm_security_layer()
	{
		OPENSSL_cleanse(client_signing_key_.data(), client_signing_key_.size());
		OPENSSL_cleanse(server_signing_key_.data(), server_signing_key_.size());
	}

	// SEAL (MS-NLMP section 3.4.3) or, for integrity, MAC (section 3.4.4.2):
	// the checksum over ConcatenationOf(SeqNum, Message) before sealing,
	// then the message sealed, then the checksum, with the same handle.
	auto ntlm_security_layer::wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
	  -> result<void>
	{
		if (send_seq_num_ > max_seq_num) {
			return fail(client_errc::encode_error, "NTLM: 2^32 buffers sent, the sequence number would wrap");
		}
		const auto seq_num = static_cast<std::uint32_t>(send_seq_num_++);
		const std::size_t base = out.size();
		out.resize(base + ntlm_signature_size + plaintext.size());
		const std::span<std::byte> buffer = std::span(out).subspan(base);
		// The signature's SeqNum, then the message: what the MAC covers.
		put_seq_num(buffer.subspan(ntlm_signature_seq_num_offset, 4), seq_num);
		std::ranges::copy(plaintext, buffer.begin() + static_cast<std::ptrdiff_t>(ntlm_signature_size));
		ntlm_key mac{};
		const scope_exit wipe_mac([&mac] { OPENSSL_cleanse(mac.data(), mac.size()); });
		if (auto r = ntlm_hmac_md5(client_signing_key_, as_chars(buffer.subspan(ntlm_signature_seq_num_offset)), mac);
		  !r) {
			out.resize(base);
			return r;
		}
		ntlm_message_signature signature{ .version = ntlm_signature_version, .checksum = {}, .seq_num = seq_num };
		std::copy_n(mac.begin(), ntlm_checksum_size, signature.checksum.begin());
		if (protection_ == sasl_protection::confidentiality) {
			client_handle_.apply(buffer.subspan(ntlm_signature_size));
		}
		client_handle_.apply(signature.checksum);// with key exchange
		encode_ntlm_signature(signature, buffer.first<ntlm_signature_size>());
		return {};
	}

	auto ntlm_security_layer::unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
	  -> result<void>
	{
		auto parsed = parse_ntlm_protected_buffer(buffer);
		if (!parsed) {
			return std::unexpected(std::move(parsed.error()));
		}
		if (receive_seq_num_ > max_seq_num) {
			return fail(
			  client_errc::unexpected_response, "NTLM: 2^32 buffers received, the sequence number would wrap");
		}
		const auto expected = static_cast<std::uint32_t>(receive_seq_num_++);
		// The expected SeqNum, then the message (unsealed in place): what the
		// server's MAC covers.
		const std::size_t base = out.size();
		out.resize(base + 4 + parsed->message.size());
		const std::span<std::byte> covered = std::span(out).subspan(base);
		put_seq_num(covered, expected);
		std::ranges::copy(parsed->message, covered.begin() + 4);
		if (protection_ == sasl_protection::confidentiality) {
			server_handle_.apply(covered.subspan(4));
		}
		auto checksum = parsed->signature.checksum;
		server_handle_.apply(checksum);
		ntlm_key mac{};
		const scope_exit wipe_mac([&mac] { OPENSSL_cleanse(mac.data(), mac.size()); });
		if (auto r = ntlm_hmac_md5(server_signing_key_, as_chars(covered), mac); !r) {
			out.resize(base);
			return r;
		}
		if (parsed->signature.seq_num != expected) {
			out.resize(base);
			return fail(client_errc::unexpected_response,
			  detail::format("NTLM: a buffer with sequence number {}, {} expected (replayed, reordered or dropped)",
				parsed->signature.seq_num,
				expected));
		}
		if (CRYPTO_memcmp(mac.data(), checksum.data(), ntlm_checksum_size) != 0) {
			out.resize(base);
			return fail(client_errc::unexpected_response,
			  "NTLM: a buffer whose checksum does not verify (changed in transit, or not the server's)");
		}
		out.erase(out.begin() + static_cast<std::ptrdiff_t>(base), out.begin() + static_cast<std::ptrdiff_t>(base + 4));
		return {};
	}

}// namespace detail

sasl_ntlm::sasl_ntlm(std::string username, std::string password, sasl_ntlm_options options)
  : sasl_ntlm(std::move(username), std::move(password), std::move(options), std::nullopt)
{
	// This body runs after the target constructor: its moved-from argument,
	// which may keep a short password in its buffer, is wiped here.
	wipe_string(password);
}

sasl_ntlm::sasl_ntlm(std::string username,
  std::string password,
  sasl_ntlm_options options,
  std::optional<detail::ntlm_challenge> client_challenge)
  : username_(std::move(username)), password_(std::move(password)), options_(std::move(options)),
	fixed_client_challenge_(client_challenge)
{
	// The moved-from argument may keep the password in its short buffer.
	wipe_string(password);
}

sasl_ntlm::~sasl_ntlm()
{
	wipe();
	wipe_string(password_);
}

void sasl_ntlm::wipe() noexcept
{
	OPENSSL_cleanse(response_key_.data(), response_key_.size());
	negotiate_.clear();
	layer_.reset();
}

void sasl_ntlm::prepare(const sasl_bind_context &context)
{
	host_ = context.host;
	tls_ = context.tls;
	binding_data_.clear();
	binding_error_.clear();
	if (!tls_ || options_.channel_binding == ntlm_channel_binding::none) {
		return;
	}
	// Never a silent fallback to no bindings: the certificate is the TLS
	// peer's choice, so a man in the middle could pick one without a hash.
	if (context.bindings.tls_server_end_point.empty()) {
		binding_error_ =
		  "the TLS connection has no tls-server-end-point channel binding data (no hash for the "
		  "server's certificate, e.g. Ed25519 or Ed448, or no certificate)";
		return;
	}
	binding_data_ =
	  prefixed_channel_binding(channel_binding_type::tls_server_end_point, context.bindings.tls_server_end_point);
}

auto sasl_ntlm::start() -> result<std::optional<std::string>>
{
	state_ = state::idle;
	wipe();
	if (options_.security_layer != sasl_protection::none) {
		// A layer stands in for TLS, and Active Directory refuses one over
		// TLS (MS-ADTS section 5.1.1.1.2).
		if (tls_) {
			return fail(client_errc::security_layer_unavailable,
			  "a SASL security layer cannot be used over TLS (Active Directory refuses one there; "
			  "sasl_ntlm_options::security_layer)");
		}
		if (options_.max_receive_size < detail::ntlm_signature_size) {
			return input_error(detail::format("max_receive_size {} out of range (16 to {})",
			  options_.max_receive_size,
			  std::numeric_limits<std::uint32_t>::max()));
		}
	} else if (options_.require_tls && !tls_) {
		return fail(
		  client_errc::tls_required, "NTLM needs a TLS-protected connection (sasl_ntlm_options::require_tls)");
	}
	if (!binding_error_.empty()) {
		return fail(client_errc::tls_required, binding_error_);
	}
	auto [user, domain] = split_user(username_);
	if (!options_.domain.empty()) {
		user = username_;
		domain = options_.domain;
	}
	if (user.empty()) {
		return input_error("empty user name");
	}
	const auto convert = [](std::string_view utf8, std::string_view what, std::string &out) -> result<void> {
		auto u = detail::ntlm_unicode(utf8);
		if (!u) {
			return input_error(std::string(what) + " is not valid UTF-8");
		}
		out = std::move(*u);
		return {};
	};
	if (auto r = convert(user, "the user name", user_); !r) {
		return std::unexpected(std::move(r.error()));
	}
	if (auto r = convert(domain, "the domain", domain_); !r) {
		return std::unexpected(std::move(r.error()));
	}
	if (auto r = convert(options_.workstation, "the workstation", workstation_); !r) {
		return std::unexpected(std::move(r.error()));
	}
	std::string spn = options_.target;
	if (spn.empty() && !host_.empty()) {
		spn = "ldap/" + host_;
	}
	if (auto r = convert(spn, "the target", target_); !r) {
		return std::unexpected(std::move(r.error()));
	}
	if (target_.size() > max_av_length) {
		return input_error("the target is longer than 65535 octets in UTF-16");
	}
	// The password last: NTOWFv2 needs only it, the user and the domain.
	if (auto r = detail::ntowfv2(password_, user, domain, response_key_); !r) {
		wipe();
		return std::unexpected(std::move(r.error()));
	}
	negotiate_ = detail::encode_ntlm_negotiate(requested_flags(options_.security_layer), client_version);
	state_ = state::sent_negotiate;
	return std::optional<std::string>(negotiate_);
}

auto sasl_ntlm::step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>>
{
	if (state_ != state::sent_negotiate) {
		return refused("a challenge after the AUTHENTICATE_MESSAGE");
	}
	// Whatever happens below, this exchange is over: only success leads on
	// to complete().
	state_ = state::idle;
	const wiped_key response_key(response_key_);
	OPENSSL_cleanse(response_key_.data(), response_key_.size());
	if (!challenge) {
		return fail(client_errc::decode_error, "no CHALLENGE_MESSAGE");
	}
	auto parsed = detail::parse_ntlm_challenge(*challenge);
	if (!parsed) {
		return std::unexpected(std::move(parsed.error()));
	}
	const auto &c = *parsed;
	if ((c.negotiate_flags & detail::ntlmssp_negotiate_unicode) == 0) {
		return refused("the server does not offer Unicode (no NTLMSSP_NEGOTIATE_UNICODE)");
	}
	if ((c.negotiate_flags & detail::ntlmssp_negotiate_extended_sessionsecurity) == 0) {
		return refused("the server does not offer NTLMv2 (no NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)");
	}
	if ((c.negotiate_flags & detail::ntlmssp_negotiate_target_info) == 0 || c.target_info.empty()) {
		return refused("the server does not offer NTLMv2 (no TargetInfo in the CHALLENGE_MESSAGE)");
	}
	const bool layer = options_.security_layer != sasl_protection::none;
	const std::uint32_t flags = requested_flags(options_.security_layer);
	if (auto granted = layer_granted(options_.security_layer, c.negotiate_flags); !granted) {
		return std::unexpected(std::move(granted.error()));
	}

	ntlm_key bindings{};// Z(16) without channel binding
	if (!binding_data_.empty()) {
		auto h = detail::ntlm_channel_bindings_hash(binding_data_);
		if (!h) {
			return std::unexpected(std::move(h.error()));
		}
		bindings = *h;
	}
	const auto server_time = detail::ntlm_timestamp(c.target_info);
	const std::uint64_t time = server_time.value_or(now_filetime());
	ntlm_challenge client_challenge{};
	if (fixed_client_challenge_) {
		client_challenge = *fixed_client_challenge_;
	} else if (RAND_bytes(client_challenge.data(), static_cast<int>(client_challenge.size())) != 1) {
		return library_error("OpenSSL RAND_bytes failed");
	}
	const auto info = detail::ntlm_client_target_info(c.target_info, true, bindings, target_);
	detail::ntlm_responses responses;
	auto computed = detail::ntlm_compute_response(response_key.k,
	  c.server_challenge,
	  client_challenge,
	  time,
	  detail::encode_ntlm_av_pairs(info),
	  server_time.has_value(),
	  responses);
	// The KeyExchangeKey: NTLMv2 makes it the SessionBaseKey (MS-NLMP
	// section 3.4.5.1).
	const wiped_key key_exchange_key(responses.session_base_key);
	OPENSSL_cleanse(responses.session_base_key.data(), responses.session_base_key.size());
	if (!computed) {
		return std::unexpected(std::move(computed.error()));
	}
	// Without key exchange the ExportedSessionKey is the KeyExchangeKey;
	// with it (a security layer), a random key sent as
	// EncryptedRandomSessionKey = RC4K(KeyExchangeKey, ExportedSessionKey)
	// (section 3.1.5.1.2).
	wiped_key exported(key_exchange_key.k);
	std::string encrypted_random_session_key;
	if (layer) {
		if (fixed_session_key_) {
			exported.k = *fixed_session_key_;
		} else if (RAND_bytes(exported.k.data(), static_cast<int>(exported.k.size())) != 1) {
			return library_error("OpenSSL RAND_bytes failed");
		}
		ntlm_key encrypted = exported.k;// encrypted in place, below
		detail::ntlm_rc4(key_exchange_key.k).apply(encrypted);
		encrypted_random_session_key = as_chars(encrypted);
	}

	const detail::ntlm_authenticate_message message{
		.lm_challenge_response = std::move(responses.lm_challenge_response),
		.nt_challenge_response = std::move(responses.nt_challenge_response),
		.domain_name = domain_,
		.user_name = user_,
		.workstation = workstation_,
		.encrypted_random_session_key = std::move(encrypted_random_session_key),
		// The flags both sides set, and the Version this message carries.
		.negotiate_flags = (flags & c.negotiate_flags) | detail::ntlmssp_negotiate_version,
		.version = client_version,
		.mic = {},
	};
	auto authenticate = detail::encode_ntlm_authenticate(message);
	if (!authenticate) {
		return std::unexpected(std::move(authenticate.error()));
	}
	// MIC = HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE,
	//   CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE)), its own field zero.
	ntlm_key mic{};// not secret: it goes on the wire
	if (auto r = detail::ntlm_hmac_md5(exported.k, negotiate_ + std::string(*challenge) + *authenticate, mic); !r) {
		return std::unexpected(std::move(r.error()));
	}
	std::ranges::copy(
	  as_chars(mic), authenticate->begin() + static_cast<std::ptrdiff_t>(detail::ntlm_authenticate_mic_offset));
	if (layer) {
		detail::ntlm_session_keys keys;
		const detail::scope_exit wipe_keys([&keys] {
			for (auto *k : { &keys.client_signing_key,
				   &keys.client_sealing_key,
				   &keys.server_signing_key,
				   &keys.server_sealing_key }) {
				OPENSSL_cleanse(k->data(), k->size());
			}
		});
		if (auto r = detail::ntlm_derive_session_keys(exported.k, keys); !r) {
			return std::unexpected(std::move(r.error()));
		}
		layer_ =
		  std::make_unique<detail::ntlm_security_layer>(keys, options_.security_layer, options_.max_receive_size);
	}
	negotiate_.clear();
	state_ = state::sent_authenticate;
	return std::optional<std::string>(std::move(*authenticate));
}

auto sasl_ntlm::take_security_layer() -> std::unique_ptr<sasl_security_layer> { return std::move(layer_); }

auto sasl_ntlm::complete(std::optional<std::string_view> server_creds) -> result<void>
{
	(void)server_creds;
	if (state_ != state::sent_authenticate) {
		return refused("the server reported success before the exchange was complete");
	}
	return {};
}

}// namespace jhetz::ldap
