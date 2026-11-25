// SCRAM-SHA-256 client (RFC 5802, RFC 7677). See sasl_scram.hpp.
#include "jhetz/ldap/sasl_scram.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"
#include "sasl_util.hpp"
#include "scope_util.hpp"
#include "wipe_util.hpp"

#include "net/channel_binding.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <unicode/uchar.h>
#include <unicode/usprep.h>
#include <unicode/utypes.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

using detail::icu_failed;
using detail::input_error;
using detail::library_error;
using detail::refused;
using detail::wipe_string;
using detail::wiped;

namespace {

	constexpr std::size_t key_size = 32;// SHA-256 output
	constexpr std::size_t nonce_bytes = 18;// 24 base64 characters, no padding

	auto malformed(std::string_view what) -> std::unexpected<error> { return fail(client_errc::decode_error, what); }

	// ------------------------------------------------------------ base64

	constexpr std::string_view b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	constexpr unsigned b64_bits = 6;
	constexpr std::size_t b64_group_chars = 4;
	constexpr std::size_t b64_group_octets = 3;
	constexpr unsigned octet_bits = 8;
	constexpr std::uint32_t octet_mask = 0xff;

	// ICU lengths are int32_t, with room for SASLprep to lengthen the input.
	constexpr std::size_t max_saslprep_input = INT32_MAX / 4;
	constexpr std::size_t max_quoted = 64;

	auto base64_encode(std::span<const unsigned char> data) -> std::string
	{
		std::string out(((data.size() + b64_group_octets - 1) / b64_group_octets * b64_group_chars) + 1, '\0');
		const int n =
		  EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data.data(), static_cast<int>(data.size()));
		out.resize(static_cast<std::size_t>(n));
		return out;
	}

	auto base64_encode(std::string_view s) -> std::string
	{
		return base64_encode(std::span(reinterpret_cast<const unsigned char *>(s.data()), s.size()));
	}

	// The value of a base64 character, -1 for any other.
	auto b64_value(char c) -> int
	{
		const auto at = b64_alphabet.find(c);
		return at == std::string_view::npos ? -1 : static_cast<int>(at);
	}

	// Strict decoding: length a multiple of 4, padding only at the end, no
	// stray bits in the last group (RFC 4648 section 3.5 canonical form).
	auto base64_decode(std::string_view s) -> std::optional<std::string>
	{
		if (s.size() % b64_group_chars != 0) {
			return std::nullopt;
		}
		std::string out;
		out.reserve(s.size() / b64_group_chars * b64_group_octets);
		for (std::size_t i = 0; i < s.size(); i += b64_group_chars) {
			const bool last = i + b64_group_chars == s.size();
			std::size_t pad = 0;
			if (last && s[i + 3] == '=') {
				pad = s[i + 2] == '=' ? 2 : 1;
			}
			std::uint32_t v = 0;
			for (std::size_t k = 0; k < b64_group_chars; ++k) {
				int d = 0;
				if (k < b64_group_chars - pad) {
					d = b64_value(s[i + k]);
					if (d < 0) {
						return std::nullopt;
					}
				}
				v = v << b64_bits | static_cast<std::uint32_t>(d);
			}
			out += static_cast<char>(v >> (2 * octet_bits) & octet_mask);
			if (pad < 2) {
				out += static_cast<char>(v >> octet_bits & octet_mask);
			}
			if (pad < 1) {
				out += static_cast<char>(v & octet_mask);
			}
			// The padded octets' bits must be zero.
			if (pad != 0 && (v & ((std::uint32_t{ 1 } << (octet_bits * pad)) - 1)) != 0) {
				return std::nullopt;
			}
		}
		return out;
	}

	// ------------------------------------------------------------ input preparation

	// Treat the string as RFC 3454's "stored string" (unassigned code points
	// are refused) or as a "query" (they are passed through).
	enum class prep_kind : std::uint8_t { query, stored };

	auto icu_failure(std::string_view what, UErrorCode status) -> std::unexpected<error>
	{
		return library_error(std::string(what) + ": SASLprep failed (ICU " + u_errorName(status) + ")");
	}

	// SASLprep (RFC 4013) with ICU's usprep, into `out` (wiped first, sized
	// once, wiped on failure). `what` names the input in errors.
	auto saslprep(std::string_view s, std::string_view what, prep_kind kind, std::string &out) -> result<void>
	{
		wipe_string(out);
		const std::string name(what);
		if (s.empty()) {
			return input_error("empty " + name);
		}
		if (s.size() > max_saslprep_input) {
			return input_error(name + " is too long");
		}

		std::vector<UChar> in;
		std::vector<UChar> prepared;
		const detail::scope_exit wipe{ [&] noexcept {
			detail::wipe_vector(in);
			detail::wipe_vector(prepared);
		} };
		UErrorCode status = detail::to_utf16(s, in);
		if (detail::is_invalid_utf8(status)) {
			return input_error(name + " is not valid UTF-8");
		}
		if (icu_failed(status)) {
			return icu_failure(name, status);
		}

		status = U_ZERO_ERROR;
		const detail::usprep_ptr profile(usprep_openByType(USPREP_RFC4013_SASLPREP, &status));
		if (icu_failed(status)) {
			return icu_failure(name, status);
		}
		const int32_t options = kind == prep_kind::stored ? USPREP_DEFAULT : USPREP_ALLOW_UNASSIGNED;
		status = detail::stringprep(profile.get(), options, in, prepared);
		if (status == U_STRINGPREP_PROHIBITED_ERROR) {
			return input_error(name + " contains a character prohibited by SASLprep (RFC 4013 section 2.3)");
		}
		if (status == U_STRINGPREP_UNASSIGNED_ERROR) {
			return input_error(name + " contains a code point unassigned in Unicode 3.2 (RFC 4013 section 2.5)");
		}
		if (status == U_STRINGPREP_CHECK_BIDI_ERROR) {
			return input_error(name + " breaks the bidirectional text rules of SASLprep (RFC 3454 section 6)");
		}
		if (icu_failed(status)) {
			return icu_failure(name, status);
		}
		if (prepared.empty()) {
			return input_error(name + " is empty after SASLprep");
		}

		if (status = detail::to_utf8(prepared, out); icu_failed(status)) {
			wipe_string(out);
			return icu_failure(name, status);
		}
		return {};
	}

	// saslname (RFC 5802 section 5.1): '=' -> "=3D", ',' -> "=2C".
	auto escape_saslname(std::string_view s) -> std::string
	{
		std::string out;
		out.reserve(s.size());
		for (const char c : s) {
			if (c == '=') {
				out += "=3D";
			} else if (c == ',') {
				out += "=2C";
			} else {
				out += c;
			}
		}
		return out;
	}

	// printable (RFC 5802 section 7): %x21-2B / %x2D-7E, i.e. no ','.
	auto printable(std::string_view s) -> bool
	{
		return std::ranges::none_of(s, [](char ch) {
			const auto c = static_cast<unsigned char>(ch);
			return c <= ' ' || c >= detail::ascii_delete || c == ',';
		});
	}

	// ------------------------------------------------------------ message parsing

	// One "a=value" attribute of a SCRAM message, split on ','.
	struct attribute_reader
	{
		std::string_view rest;
		bool more = true;// false once the last attribute was read
		[[nodiscard]] auto done() const -> bool { return !more; }
		// The next attribute: its name (a letter) and value. nullopt if it is
		// not of the form ALPHA "=" value (an empty one after a trailing ',').
		auto next() -> std::optional<std::pair<char, std::string_view>>
		{
			if (!more) {
				return std::nullopt;
			}
			const auto comma = rest.find(',');
			const std::string_view a = rest.substr(0, comma);
			if (comma == std::string_view::npos) {
				more = false;
				rest = {};
			} else {
				rest = rest.substr(comma + 1);
			}
			if (a.size() < 2 || a[1] != '=') {
				return std::nullopt;
			}
			const char n = a[0];
			if ((n < 'a' || n > 'z') && (n < 'A' || n > 'Z')) {
				return std::nullopt;
			}
			return std::pair{ n, a.substr(2) };
		}
	};

	auto parse_count(std::string_view s) -> std::optional<std::uint32_t>
	{
		constexpr std::size_t max_digits = 10;// UINT32_MAX is 4294967295
		if (s.empty() || s.size() > max_digits || s[0] == '0') {
			return std::nullopt;
		}
		std::uint64_t v = 0;
		for (const char c : s) {
			if (c < '0' || c > '9') {
				return std::nullopt;
			}
			v = (v * 10) + static_cast<std::uint64_t>(c - '0');
		}
		if (v > UINT32_MAX) {
			return std::nullopt;
		}
		return static_cast<std::uint32_t>(v);
	}

	// A server-supplied string for an error context, quoted, sanitized and
	// cut to at most 64 bytes (detail::append_sanitized).
	auto quoted(std::string_view s) -> std::string
	{
		std::string out = "\"";
		detail::append_sanitized(out, s, max_quoted);
		out += '"';
		return out;
	}

	// ------------------------------------------------------------ crypto

	// HMAC-SHA-256 of `data` keyed with `key`, into `out`. False if OpenSSL
	// fails.
	[[nodiscard]] auto
	  hmac(std::span<const unsigned char> key, std::string_view data, std::span<unsigned char, key_size> out) -> bool
	{
		unsigned int n = 0;
		const unsigned char *r = HMAC(EVP_sha256(),
		  key.data(),
		  static_cast<int>(key.size()),
		  reinterpret_cast<const unsigned char *>(data.data()),
		  data.size(),
		  out.data(),
		  &n);
		return r != nullptr && n == key_size;
	}


	// The client proof (base64) and ServerSignature from the SaltedPassword (RFC
	// 5802 section 3); false if OpenSSL fails.
	//   ClientKey       := HMAC(SaltedPassword, "Client Key")
	//   StoredKey       := H(ClientKey)
	//   ClientSignature := HMAC(StoredKey, AuthMessage)
	//   ClientProof     := ClientKey XOR ClientSignature
	//   ServerKey       := HMAC(SaltedPassword, "Server Key")
	//   ServerSignature := HMAC(ServerKey, AuthMessage)
	[[nodiscard]] auto keys(std::span<const unsigned char, key_size> salted,
	  std::string_view auth_message,
	  std::string &proof_b64,
	  std::span<unsigned char, key_size> server_signature) -> bool
	{
		wiped<key_size> client_key;
		wiped<key_size> stored_key;
		wiped<key_size> client_signature;
		wiped<key_size> proof;
		wiped<key_size> server_key;
		if (!hmac(salted, "Client Key", client_key.span())
			|| SHA256(client_key.data(), client_key.size(), stored_key.data()) == nullptr
			|| !hmac(stored_key.span(), auth_message, client_signature.span())
			|| !hmac(salted, "Server Key", server_key.span())
			|| !hmac(server_key.span(), auth_message, server_signature)) {
			OPENSSL_cleanse(server_signature.data(), server_signature.size());
			return false;
		}
		for (std::size_t k = 0; k < key_size; ++k) {
			proof[k] = static_cast<unsigned char>(client_key[k] ^ client_signature[k]);
		}
		proof_b64 = base64_encode(proof.span());
		return true;
	}

	// SaltedPassword := Hi(Normalize(password), salt, i), PBKDF2-HMAC-SHA-256.
	[[nodiscard]] auto salted_password(std::string_view password,
	  std::string_view salt,
	  std::uint32_t iterations,
	  std::span<unsigned char, key_size> out) -> bool
	{
		return PKCS5_PBKDF2_HMAC(password.data(),
				 static_cast<int>(password.size()),
				 reinterpret_cast<const unsigned char *>(salt.data()),
				 static_cast<int>(salt.size()),
				 static_cast<int>(iterations),
				 EVP_sha256(),
				 static_cast<int>(out.size()),
				 out.data())
			   == 1;
	}

	// Moves the text of `from` into `to` without leaving a copy behind in
	// `from` (a move out of a short (SSO) string copies the characters).
	void move_wiped(std::string &from, std::string &to)
	{
		wipe_string(to);
		to.assign(from);
		wipe_string(from);
	}

}// namespace

// The parsed server-first-message: views into the message, but the salt.
struct sasl_scram_sha256::server_first
{
	std::string_view nonce;
	std::string salt;
	std::uint32_t iterations = 0;
};

// PBKDF2's inputs and outputs, shared with an offloaded step: read by the
// mechanism only once `done` is true (acquire). Wiped by its last owner.
struct sasl_scram_sha256::derivation
{
	std::string password;// prepared
	std::string salt;
	std::uint32_t iterations = 0;
	std::string auth_message;
	std::array<unsigned char, key_size> salted{};
	std::array<unsigned char, key_size> server_signature{};
	bool ok = false;// the outputs are valid
	std::atomic<bool> done{ false };

	derivation() = default;
	derivation(const derivation &) = delete;
	auto operator=(const derivation &) -> derivation & = delete;
	~derivation()
	{
		wipe_string(password);
		OPENSSL_cleanse(salted.data(), salted.size());
		OPENSSL_cleanse(server_signature.data(), server_signature.size());
	}
};

sasl_scram_sha256::sasl_scram_sha256(std::string username, std::string password, std::string authz_id)
  : sasl_scram_sha256(std::move(username),
	  password,
	  sasl_scram_options{ .authz_id = std::move(authz_id) },
	  std::nullopt)
{}

sasl_scram_sha256::sasl_scram_sha256(std::string username, std::string password, sasl_scram_options options)
  : sasl_scram_sha256(std::move(username), password, std::move(options), std::nullopt)
{}

sasl_scram_sha256::sasl_scram_sha256(std::string username,
  std::string &password,
  sasl_scram_options options,
  std::optional<std::string> fixed_nonce)
  : username_(std::move(username)), password_(password), options_(std::move(options)),
	fixed_nonce_(std::move(fixed_nonce))
{
	wipe_string(password);// copied to password_
}

sasl_scram_sha256::~sasl_scram_sha256()
{
	wipe();
	wipe_cache();
	wipe_string(password_);
	wipe_string(prepared_password_);
}

void sasl_scram_sha256::wipe() noexcept
{
	OPENSSL_cleanse(server_signature_.data(), server_signature_.size());
	have_signature_ = false;
	pending_.reset();
}

void sasl_scram_sha256::wipe_cache() noexcept
{
	OPENSSL_cleanse(cache_salted_.data(), cache_salted_.size());
	cache_salt_.clear();
	cache_iterations_ = 0;
}

void sasl_scram_sha256::prepare(const sasl_bind_context &context)
{
	can_offload_ = context.can_offload;
	tls_ = context.tls;
	binding_type_.reset();
	binding_data_.clear();
	if (!tls_) {
		return;
	}
	const bool plus = options_.channel_binding == scram_channel_binding::plus;
	if (plus && options_.binding_form == scram_channel_binding_form::openldap) {
		// tls-server-end-point with OpenLDAP's hash; an explicit
		// tls-exporter is refused by start().
		binding_type_ = options_.binding_type.value_or(channel_binding_type::tls_server_end_point);
		if (binding_type_ == channel_binding_type::tls_server_end_point) {
			const auto hash = net::detail::openldap_tls_server_end_point(context.peer_certificate);
			binding_data_.assign(reinterpret_cast<const char *>(hash.data()), hash.size());
		}
		return;
	}
	// not_offered: whether any type is available; plus: the chosen type, or the
	// default.
	binding_type_ = context.bindings.default_type;
	if (plus && options_.binding_type) {
		binding_type_ = options_.binding_type;
	}
	if (binding_type_) {
		const auto data = context.bindings.get(*binding_type_);
		binding_data_.assign(reinterpret_cast<const char *>(data.data()), data.size());
	}
}

// The outcome of a finished offloaded step; one still running is dropped.
void sasl_scram_sha256::collect() noexcept
{
	if (pending_ == nullptr) {
		return;
	}
	const std::shared_ptr<derivation> d = std::move(pending_);
	pending_.reset();
	if (!d->done.load(std::memory_order_acquire) || !d->ok) {
		return;
	}
	server_signature_ = d->server_signature;
	have_signature_ = true;
	wipe_cache();
	cache_salted_ = d->salted;
	cache_salt_ = d->salt;
	cache_iterations_ = d->iterations;
}

auto sasl_scram_sha256::start() -> result<std::optional<std::string>>
{
	collect();// the cache, from an offloaded step of the last bind
	state_ = state::idle;
	wipe();
	wipe_string(prepared_password_);
	if (options_.max_iterations < min_iterations || options_.max_iterations > static_cast<std::uint32_t>(INT32_MAX)) {
		return input_error(
		  detail::format("max_iterations {} is outside {} .. 2^31-1", options_.max_iterations, min_iterations));
	}
	const bool openldap_form = options_.binding_form == scram_channel_binding_form::openldap;
	if (options_.channel_binding == scram_channel_binding::plus && openldap_form
		&& options_.binding_type == channel_binding_type::tls_exporter) {
		return input_error("OpenLDAP's channel binding form has no tls-exporter");
	}
	const std::string &authz_id = options_.authz_id;
	// RFC 5802 section 5.1: the username is prepared as a query (unassigned
	// code points allowed).
	std::string user;
	if (auto r = saslprep(username_, "username", prep_kind::query, user); !r) {
		return std::unexpected(std::move(r.error()));
	}
	// The authorization identity: well-formed UTF-8 without control characters,
	// not prepared.
	for (std::size_t i = 0; i < authz_id.size();) {
		const auto [c, n] = detail::utf8_next(authz_id, i);
		if (c < 0) {
			return input_error("authorization identity is not valid UTF-8");
		}
		if (u_charType(c) == U_CONTROL_CHAR) {
			return input_error("authorization identity contains a control character");
		}
		i += n;
	}

	// gs2-cbind-flag (RFC 5802 sections 6 and 7), and with "p" the prefix
	// of the binding data in cbind-input (OpenLDAP's form only).
	std::string flag = "n";
	std::string data_prefix;
	switch (options_.channel_binding) {
	case scram_channel_binding::none:
		break;
	case scram_channel_binding::not_offered:
		if (!binding_data_.empty()) {
			flag = "y";
		}
		break;
	case scram_channel_binding::plus: {
		if (!tls_) {
			return fail(client_errc::tls_required, "channel binding needs a TLS-protected connection");
		}
		if (!binding_type_) {
			return fail(client_errc::tls_required, "the TLS connection has no channel binding data");
		}
		const std::string type(to_string(*binding_type_));
		if (binding_data_.empty()) {
			return fail(client_errc::tls_required, "the TLS connection has no " + type + " channel binding data");
		}
		if (openldap_form) {
			flag = "p=ldap";
			data_prefix = type + ":";
		} else {
			flag = "p=" + type;
		}
		break;
	}
	}

	if (fixed_nonce_) {
		if (fixed_nonce_->empty() || !printable(*fixed_nonce_)) {
			return input_error("invalid fixed nonce");
		}
		client_nonce_ = *fixed_nonce_;
	} else {
		wiped<nonce_bytes> raw;
		if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
			return library_error("OpenSSL RAND_bytes failed");
		}
		client_nonce_ = base64_encode(raw.span());
	}

	// The password last; prepared as a stored string (RFC 5802 section 2.2).
	if (auto r = saslprep(password_, "password", prep_kind::stored, prepared_password_); !r) {
		return std::unexpected(std::move(r.error()));
	}

	gs2_header_ = flag + (authz_id.empty() ? std::string(",,") : ",a=" + escape_saslname(authz_id) + ",");
	cbind_input_ = gs2_header_;
	if (options_.channel_binding == scram_channel_binding::plus) {
		cbind_input_ += data_prefix;
		cbind_input_ += binding_data_;
	}
	client_first_bare_ = "n=" + escape_saslname(user) + ",r=" + client_nonce_;
	state_ = state::sent_first;
	return std::optional<std::string>(gs2_header_ + client_first_bare_);
}

auto sasl_scram_sha256::step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>>
{
	switch (state_) {
	case state::sent_first:
		if (!challenge) {
			return malformed("server-first-message: no challenge");
		}
		return client_final(*challenge);
	case state::sent_final: {
		if (!challenge) {
			return malformed("server-final-message: no challenge");
		}
		if (auto r = verify(*challenge); !r) {
			return std::unexpected(std::move(r.error()));
		}
		// RFC 4422 section 5: the server-final-message came as a challenge,
		// so the response is empty and the server then reports success.
		return std::optional<std::string>(std::string());
	}
	case state::idle:
	case state::verified:
		break;
	}
	state_ = state::idle;
	return refused("a challenge after the exchange ended");
}

auto sasl_scram_sha256::parse_server_first(std::string_view message) -> result<server_first>
{
	// server-first-message = [reserved-mext ","] nonce "," salt ","
	//                        iteration-count ["," extensions]
	attribute_reader in{ .rest = message };
	auto a = in.next();
	if (!a) {
		return malformed("server-first-message");
	}
	if (a->first == 'm') {
		return refused("server-first-message has a mandatory extension (m=) this client does not support");
	}
	if (a->first != 'r') {
		return malformed("server-first-message: no nonce (r=)");
	}
	server_first out;
	out.nonce = a->second;
	if (out.nonce.empty() || !printable(out.nonce)) {
		return malformed("server-first-message: nonce");
	}
	if (!out.nonce.starts_with(client_nonce_)) {
		return refused("the server nonce does not start with the client nonce");
	}
	if (out.nonce.size() <= client_nonce_.size()) {
		return refused("the server nonce does not extend the client nonce (no server part)");
	}

	a = in.next();
	if (!a || a->first != 's') {
		return malformed("server-first-message: no salt (s=)");
	}
	auto salt = base64_decode(a->second);
	if (!salt || salt->empty()) {
		return malformed("server-first-message: salt is not valid base64");
	}
	out.salt = std::move(*salt);

	a = in.next();
	if (!a || a->first != 'i') {
		return malformed("server-first-message: no iteration count (i=)");
	}
	const auto iterations = parse_count(a->second);
	if (!iterations) {
		return malformed("server-first-message: iteration count");
	}
	if (*iterations < min_iterations) {
		return refused(detail::format(
		  "iteration count {} is below the minimum of {} (RFC 7677 section 4)", *iterations, min_iterations));
	}
	if (*iterations > options_.max_iterations) {
		return refused(
		  detail::format("iteration count {} is above the maximum of {}", *iterations, options_.max_iterations));
	}
	out.iterations = *iterations;
	while (!in.done()) {
		if (!in.next()) {
			return malformed("server-first-message: extension");
		}
	}
	return out;
}

namespace {
	// AuthMessage := client-first-message-bare + "," + server-first-message
	//                + "," + client-final-message-without-proof
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto auth_message_of(std::string_view first_bare, std::string_view server_first, std::string_view without_proof)
	  -> std::string
	{
		std::string out(first_bare);
		out += ',';
		out += server_first;
		out += ',';
		out += without_proof;
		return out;
	}
}// namespace

auto sasl_scram_sha256::client_final(std::string_view message) -> result<std::optional<std::string>>
{
	state_ = state::idle;// any failure below ends the exchange
	// The prepared password is needed only for PBKDF2, below.
	const detail::scope_exit wipe_password{ [this] { wipe_string(prepared_password_); } };
	auto parsed = parse_server_first(message);
	if (!parsed) {
		return std::unexpected(std::move(parsed.error()));
	}

	std::string without_proof = "c=" + base64_encode(cbind_input_) + ",r=";
	without_proof += parsed->nonce;
	const std::string auth_message = auth_message_of(client_first_bare_, message, without_proof);

	if (cache_iterations_ != parsed->iterations || cache_salt_ != parsed->salt) {
		wipe_cache();
		if (!salted_password(prepared_password_, parsed->salt, parsed->iterations, cache_salted_)) {
			wipe_cache();
			return library_error("OpenSSL PBKDF2 failed");
		}
		cache_salt_ = std::move(parsed->salt);
		cache_iterations_ = parsed->iterations;
	}
	std::string proof;
	if (!keys(cache_salted_, auth_message, proof, server_signature_)) {
		wipe();
		return library_error("OpenSSL HMAC or SHA-256 failed");
	}
	have_signature_ = true;
	state_ = state::sent_final;
	return std::optional<std::string>(without_proof + ",p=" + proof);
}

auto sasl_scram_sha256::offload_step(std::optional<std::string_view> challenge) -> sasl_work
{
	if (!can_offload_ || state_ != state::sent_first || !challenge) {
		return {};
	}
	auto parsed = parse_server_first(*challenge);
	// A malformed message, a cached SaltedPassword or a cheap PBKDF2: step().
	if (!parsed || parsed->iterations <= options_.offload_above_iterations
		|| (cache_iterations_ == parsed->iterations && cache_salt_ == parsed->salt)) {
		return {};
	}

	std::string without_proof = "c=" + base64_encode(cbind_input_) + ",r=";
	without_proof += parsed->nonce;
	auto d = std::make_shared<derivation>();
	d->auth_message = auth_message_of(client_first_bare_, *challenge, without_proof);
	d->salt = std::move(parsed->salt);
	d->iterations = parsed->iterations;
	move_wiped(prepared_password_, d->password);
	pending_ = d;
	state_ = state::sent_final;
	// The step owns copies of everything it uses (the mechanism may be
	// destroyed or start another bind while it runs).
	return [d = std::move(d), without_proof = std::move(without_proof)] -> result<std::optional<std::string>> {
		const detail::scope_exit done{ [&d] {
			wipe_string(d->password);
			d->done.store(true, std::memory_order_release);
		} };
		if (!salted_password(d->password, d->salt, d->iterations, d->salted)) {
			return library_error("OpenSSL PBKDF2 failed");
		}
		std::string proof;
		if (!keys(d->salted, d->auth_message, proof, d->server_signature)) {
			return library_error("OpenSSL HMAC or SHA-256 failed");
		}
		d->ok = true;
		return std::optional<std::string>(without_proof + ",p=" + proof);
	};
}

auto sasl_scram_sha256::verify(std::string_view server_final) -> result<void>
{
	collect();
	state_ = state::idle;
	// server-final-message = (server-error / verifier) ["," extensions]
	attribute_reader in{ .rest = server_final };
	auto a = in.next();
	if (!a) {
		return malformed("server-final-message");
	}
	if (a->first == 'e') {
		return refused("the server reported an error: " + quoted(a->second));
	}
	if (a->first != 'v') {
		return malformed("server-final-message: no server signature (v=)");
	}
	const auto signature = base64_decode(a->second);
	if (!signature) {
		return malformed("server-final-message: server signature is not valid base64");
	}
	while (!in.done()) {
		if (!in.next()) {
			return malformed("server-final-message: extension");
		}
	}
	const bool match = have_signature_ && signature->size() == key_size
					   && CRYPTO_memcmp(signature->data(), server_signature_.data(), key_size) == 0;
	wipe();
	if (!match) {
		return refused("wrong server signature: the server could not be authenticated");
	}
	state_ = state::verified;
	return {};
}

auto sasl_scram_sha256::complete(std::optional<std::string_view> server_creds) -> result<void>
{
	switch (state_) {
	case state::sent_final:
		if (!server_creds || server_creds->empty()) {
			return refused("the server reported success without a server signature (v=)");
		}
		return verify(*server_creds);
	case state::verified:
		state_ = state::idle;
		if (server_creds && !server_creds->empty()) {
			return refused("unexpected data after the server signature");
		}
		return {};
	case state::idle:
	case state::sent_first:
		break;
	}
	state_ = state::idle;
	wipe();
	return refused("the server reported success before the exchange was complete (no server signature)");
}

}// namespace jhetz::ldap
