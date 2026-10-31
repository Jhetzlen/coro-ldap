// SASL NTLM (NTLMv2, MS-NLMP) client. See sasl_ntlm.hpp.
#include "jhetz/ldap/sasl_ntlm.hpp"

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/ntlm_message.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ratio>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

namespace {

	using detail::ntlm_challenge;
	using detail::ntlm_key;

	constexpr unsigned byte_bits = 8;
	constexpr std::uint32_t byte_mask = 0xFF;
	constexpr std::size_t max_av_length = 0xFFFF;// AvLen is a USHORT

	// The flags of the NEGOTIATE_MESSAGE (MS-NLMP section 2.2.2.5): Unicode,
	// the target's name, NTLM with extended session security (NTLMv2's),
	// TargetInfo, a Version; no signing, sealing nor key exchange (no
	// security layer).
	constexpr std::uint32_t client_flags =
	  detail::ntlmssp_negotiate_unicode | detail::ntlmssp_request_target | detail::ntlmssp_negotiate_ntlm
	  | detail::ntlmssp_negotiate_extended_sessionsecurity | detail::ntlmssp_negotiate_target_info
	  | detail::ntlmssp_negotiate_version | detail::ntlmssp_negotiate_128;

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

	// A string holding key material or the password's UTF-16, wiped when
	// it goes out of scope.
	struct wiped_string
	{
		std::string s;
		wiped_string() = default;
		explicit wiped_string(std::string v) noexcept : s(std::move(v)) {}
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

	auto ntlm_hmac_md5(std::span<const unsigned char> key, std::string_view data) -> result<ntlm_key>
	{
		ntlm_key out{};
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
		return out;
	}

	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): MS-NLMP's NTOWFv2(Passwd, User, UserDom)
	auto ntowfv2(std::string_view password, std::string_view user, std::string_view domain) -> result<ntlm_key>
	{
		auto unicode_password = ntlm_unicode(password);
		if (!unicode_password) {
			return input_error("the password is not valid UTF-8");
		}
		const wiped_string pw(std::move(*unicode_password));
		wipe_string(*unicode_password);// what a move out of a short string leaves
		const wiped_key nt_hash(md4(std::as_bytes(std::span(pw.s))));
		auto upper_user = ntlm_uppercase_unicode(user);
		if (!upper_user) {
			return input_error("the user name is not valid UTF-8");
		}
		auto unicode_domain = ntlm_unicode(domain);
		if (!unicode_domain) {
			return input_error("the domain is not valid UTF-8");
		}
		return ntlm_hmac_md5(nt_hash.k, *upper_user + *unicode_domain);
	}

	auto ntlm_compute_response(const ntlm_key &response_key,
	  const ntlm_challenge &server_challenge,
	  const ntlm_challenge &client_challenge,
	  std::uint64_t time,
	  std::string_view server_name,
	  bool server_timestamp) -> result<ntlm_responses>
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

		ntlm_responses out;
		// NTProofStr = HMAC_MD5(ResponseKeyNT, ConcatenationOf(ServerChallenge, temp))
		auto proof = ntlm_hmac_md5(response_key, std::string(as_chars(server_challenge)) + temp);
		if (!proof) {
			return std::unexpected(std::move(proof.error()));
		}
		out.nt_challenge_response = std::string(as_chars(*proof)) + temp;
		// SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
		auto session = ntlm_hmac_md5(response_key, as_chars(*proof));
		if (!session) {
			return std::unexpected(std::move(session.error()));
		}
		out.session_base_key = *session;
		OPENSSL_cleanse(session->data(), session->size());
		if (server_timestamp) {
			out.lm_challenge_response.assign(z24, '\0');
			return out;
		}
		// LmChallengeResponse = ConcatenationOf(HMAC_MD5(ResponseKeyLM,
		//   ConcatenationOf(ServerChallenge, ClientChallenge)), ClientChallenge)
		auto lm = ntlm_hmac_md5(
		  response_key, std::string(as_chars(server_challenge)) + std::string(as_chars(client_challenge)));
		if (!lm) {
			return std::unexpected(std::move(lm.error()));
		}
		out.lm_challenge_response = std::string(as_chars(*lm)) + std::string(as_chars(client_challenge));
		return out;
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

}// namespace detail

sasl_ntlm::sasl_ntlm(std::string username, std::string password, sasl_ntlm_options options)
  : sasl_ntlm(std::move(username), std::move(password), std::move(options), std::nullopt)
{}

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
	if (options_.require_tls && !tls_) {
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
	auto key = detail::ntowfv2(password_, user, domain);
	if (!key) {
		return std::unexpected(std::move(key.error()));
	}
	response_key_ = *key;
	OPENSSL_cleanse(key->data(), key->size());
	negotiate_ = detail::encode_ntlm_negotiate(client_flags, client_version);
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
	auto responses = detail::ntlm_compute_response(response_key.k,
	  c.server_challenge,
	  client_challenge,
	  time,
	  detail::encode_ntlm_av_pairs(info),
	  server_time.has_value());
	if (!responses) {
		return std::unexpected(std::move(responses.error()));
	}
	// No key exchange: the exported session key is the KeyExchangeKey,
	// which NTLMv2 makes the SessionBaseKey (MS-NLMP section 3.4.5.1).
	const wiped_key exported(responses->session_base_key);
	OPENSSL_cleanse(responses->session_base_key.data(), responses->session_base_key.size());

	const detail::ntlm_authenticate_message message{
		.lm_challenge_response = std::move(responses->lm_challenge_response),
		.nt_challenge_response = std::move(responses->nt_challenge_response),
		.domain_name = domain_,
		.user_name = user_,
		.workstation = workstation_,
		.encrypted_random_session_key = {},
		// The flags both sides set, and the Version this message carries.
		.negotiate_flags = (client_flags & c.negotiate_flags) | detail::ntlmssp_negotiate_version,
		.version = client_version,
		.mic = {},
	};
	auto authenticate = detail::encode_ntlm_authenticate(message);
	if (!authenticate) {
		return std::unexpected(std::move(authenticate.error()));
	}
	// MIC = HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE,
	//   CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE)), its own field zero.
	auto mic = detail::ntlm_hmac_md5(exported.k, negotiate_ + std::string(*challenge) + *authenticate);
	if (!mic) {
		return std::unexpected(std::move(mic.error()));
	}
	std::ranges::copy(
	  as_chars(*mic), authenticate->begin() + static_cast<std::ptrdiff_t>(detail::ntlm_authenticate_mic_offset));
	negotiate_.clear();
	state_ = state::sent_authenticate;
	return std::optional<std::string>(std::move(*authenticate));
}

auto sasl_ntlm::complete(std::optional<std::string_view> server_creds) -> result<void>
{
	(void)server_creds;
	if (state_ != state::sent_authenticate) {
		return refused("the server reported success before the exchange was complete");
	}
	return {};
}

}// namespace jhetz::ldap
