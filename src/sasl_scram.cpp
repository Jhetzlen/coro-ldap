// SCRAM-SHA-256 client (RFC 5802, RFC 7677). See sasl_scram.hpp.
#include "jhetz/ldap/sasl_scram.hpp"

#include "format_util.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <unicode/usprep.h>
#include <unicode/ustring.h>
#include <unicode/utf8.h>
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
namespace {

	constexpr std::size_t key_size = 32;// SHA-256 output
	constexpr std::size_t nonce_bytes = 18;// 24 base64 characters, no padding

	// Key material, wiped when it goes out of scope.
	template<std::size_t N> struct wiped
	{
		std::array<unsigned char, N> bytes{};
		wiped() = default;
		wiped(const wiped &) = delete;
		auto operator=(const wiped &) -> wiped & = delete;
		~wiped() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
		auto data() -> unsigned char * { return bytes.data(); }
		static constexpr auto size() -> std::size_t { return N; }
		auto span() -> std::span<unsigned char, N> { return bytes; }
		auto operator[](std::size_t i) -> unsigned char & { return bytes[i]; }
	};

	// Error contexts say what is wrong, not the code's own text (message()
	// appends it), and not the mechanism's name: connection::sasl_bind
	// prefixes "sasl bind SCRAM-SHA-256".
	auto input_error(std::string_view what) -> std::unexpected<error> { return fail(client_errc::encode_error, what); }

	// OpenSSL or ICU failed (memory, missing ICU data): the environment, not
	// the caller's username or password.
	auto library_error(std::string_view what) -> std::unexpected<error>
	{
		return fail(client_errc::internal_error, what);
	}

	auto malformed(std::string_view what) -> std::unexpected<error> { return fail(client_errc::decode_error, what); }

	auto refused(std::string_view what) -> std::unexpected<error>
	{
		return fail(client_errc::unexpected_response, what);
	}

	// Wipes a string's whole buffer, also the bytes past size() that a move
	// out of a short (SSO) string leaves behind.
	void wipe_string(std::string &s) noexcept
	{
		// Callers pass moved-from strings on purpose.
		s.resize(s.capacity());// NOLINT(clang-analyzer-cplusplus.Move): wipes what a move left
		OPENSSL_cleanse(s.data(), s.size());
		s.clear();
	}

	// ------------------------------------------------------------ base64

	constexpr std::string_view b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	auto base64_encode(std::span<const unsigned char> data) -> std::string
	{
		const std::size_t n = data.size();
		std::string out;
		out.reserve((n + 2) / 3 * 4);
		std::size_t i = 0;
		for (; i + 3 <= n; i += 3) {
			const std::uint32_t v = std::uint32_t{ data[i] } << 16 | std::uint32_t{ data[i + 1] } << 8 | data[i + 2];
			out += b64_alphabet[v >> 18 & 63];
			out += b64_alphabet[v >> 12 & 63];
			out += b64_alphabet[v >> 6 & 63];
			out += b64_alphabet[v & 63];
		}
		if (n - i == 1) {
			const std::uint32_t v = std::uint32_t{ data[i] } << 16;
			out += b64_alphabet[v >> 18 & 63];
			out += b64_alphabet[v >> 12 & 63];
			out += "==";
		} else if (n - i == 2) {
			const std::uint32_t v = std::uint32_t{ data[i] } << 16 | std::uint32_t{ data[i + 1] } << 8;
			out += b64_alphabet[v >> 18 & 63];
			out += b64_alphabet[v >> 12 & 63];
			out += b64_alphabet[v >> 6 & 63];
			out += '=';
		}
		return out;
	}

	auto base64_encode(std::string_view s) -> std::string
	{
		return base64_encode(std::span(reinterpret_cast<const unsigned char *>(s.data()), s.size()));
	}

	auto b64_value(char c) -> int
	{
		if (c >= 'A' && c <= 'Z') {
			return c - 'A';
		}
		if (c >= 'a' && c <= 'z') {
			return c - 'a' + 26;
		}
		if (c >= '0' && c <= '9') {
			return c - '0' + 52;
		}
		if (c == '+') {
			return 62;
		}
		if (c == '/') {
			return 63;
		}
		return -1;
	}

	// Strict decoding: length a multiple of 4, padding only at the end, no
	// stray bits in the last group (RFC 4648 section 3.5 canonical form).
	auto base64_decode(std::string_view s) -> std::optional<std::string>
	{
		if (s.size() % 4 != 0) {
			return std::nullopt;
		}
		std::string out;
		out.reserve(s.size() / 4 * 3);
		for (std::size_t i = 0; i < s.size(); i += 4) {
			const bool last = i + 4 == s.size();
			std::size_t pad = 0;
			if (last && s[i + 3] == '=') {
				pad = s[i + 2] == '=' ? 2 : 1;
			}
			std::uint32_t v = 0;
			for (std::size_t k = 0; k < 4; ++k) {
				int d = 0;
				if (k < 4 - pad) {
					d = b64_value(s[i + k]);
					if (d < 0) {
						return std::nullopt;
					}
				}
				v = v << 6 | static_cast<std::uint32_t>(d);
			}
			out += static_cast<char>(v >> 16 & 0xff);
			if (pad < 2) {
				out += static_cast<char>(v >> 8 & 0xff);
			}
			if (pad < 1) {
				out += static_cast<char>(v & 0xff);
			}
			if ((pad == 1 && (v & 0xff) != 0) || (pad == 2 && (v & 0xffff) != 0)) {
				return std::nullopt;
			}
		}
		return out;
	}

	// ------------------------------------------------------------ input preparation

	// A buffer that may hold (a form of) the password, wiped before it is freed.
	template<class T> struct wiped_buffer
	{
		std::vector<T> v;
		explicit wiped_buffer(std::size_t n) : v(n) {}
		wiped_buffer(const wiped_buffer &) = delete;
		auto operator=(const wiped_buffer &) -> wiped_buffer & = delete;
		~wiped_buffer() { OPENSSL_cleanse(v.data(), v.size() * sizeof(T)); }
	};

	struct usprep_closer
	{
		void operator()(UStringPrepProfile *p) const noexcept { usprep_close(p); }
	};

	// Treat the string as RFC 3454's "stored string" (unassigned code points
	// are refused) or as a "query" (they are passed through).
	enum class prep_kind : std::uint8_t { query, stored };

	auto icu_failure(std::string_view what, UErrorCode status) -> std::unexpected<error>
	{
		return library_error(std::string(what) + ": SASLprep failed (ICU " + u_errorName(status) + ")");
	}

	// SASLprep (RFC 4013, the RFC 3454 stringprep profile) with ICU's
	// usprep: map table B.1 to nothing and the non-ASCII spaces of C.1.2 to
	// U+0020, NFKC, refuse the prohibited tables (C.1.2, C.2.1 .. C.9), check
	// the bidi rules (RFC 3454 section 6) and, for a stored string, refuse
	// the unassigned code points of table A.1 (Unicode 3.2). The input must
	// be UTF-8; the result is UTF-8. `what` names the input in error
	// contexts, which never quote it (it may be the password). The result
	// is written into `out`, whose old content is wiped first (resizing a
	// non-empty string could free a buffer still holding it, or leave its
	// bytes past size()); it is then sized once and wiped on failure, so no
	// other copy of the prepared text is made (returning a std::string
	// would move it, and a move out of a short (SSO) string copies the
	// characters and leaves them in the moved-from one). Every buffer of
	// ours that held the text is wiped; ICU's internal working buffers
	// cannot be.
	auto saslprep(std::string_view s, std::string_view what, prep_kind kind, std::string &out) -> result<void>
	{
		wipe_string(out);
		const std::string name(what);
		if (s.empty()) {
			return input_error("empty " + name);
		}
		if (s.size() > static_cast<std::size_t>(INT32_MAX / 4)) {
			return input_error(name + " is too long");
		}

		// UTF-8 -> UTF-16. u_strFromUTF8 refuses ill-formed UTF-8 (overlong
		// forms, surrogates, code points above U+10FFFF, truncated sequences).
		UErrorCode status = U_ZERO_ERROR;
		int32_t n16 = 0;
		u_strFromUTF8(nullptr, 0, &n16, s.data(), static_cast<int32_t>(s.size()), &status);
		if (status == U_INVALID_CHAR_FOUND || status == U_ILLEGAL_CHAR_FOUND) {
			return input_error(name + " is not valid UTF-8");
		}
		if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status) != 0) {
			return icu_failure(name, status);
		}
		wiped_buffer<UChar> in(static_cast<std::size_t>(n16));
		status = U_ZERO_ERROR;
		u_strFromUTF8(in.v.data(), n16, &n16, s.data(), static_cast<int32_t>(s.size()), &status);
		if (U_FAILURE(status) != 0) {
			return icu_failure(name, status);
		}

		status = U_ZERO_ERROR;
		const std::unique_ptr<UStringPrepProfile, usprep_closer> profile(
		  usprep_openByType(USPREP_RFC4013_SASLPREP, &status));
		if (U_FAILURE(status) != 0) {
			return icu_failure(name, status);
		}
		const int32_t options = kind == prep_kind::stored ? USPREP_DEFAULT : USPREP_ALLOW_UNASSIGNED;
		const auto prepare = [&](UChar *dest, int32_t capacity) {
			UParseError where{};
			status = U_ZERO_ERROR;
			return usprep_prepare(profile.get(), in.v.data(), n16, dest, capacity, options, &where, &status);
		};
		// The prepared length first (NFKC may make the string longer).
		int32_t nprep = prepare(nullptr, 0);
		switch (status) {
		case U_BUFFER_OVERFLOW_ERROR:
		case U_STRING_NOT_TERMINATED_WARNING:
		case U_ZERO_ERROR:
			break;
		case U_STRINGPREP_PROHIBITED_ERROR:
			return input_error(name + " contains a character prohibited by SASLprep (RFC 4013 section 2.3)");
		case U_STRINGPREP_UNASSIGNED_ERROR:
			return input_error(name + " contains a code point unassigned in Unicode 3.2 (RFC 4013 section 2.5)");
		case U_STRINGPREP_CHECK_BIDI_ERROR:
			return input_error(name + " breaks the bidirectional text rules of SASLprep (RFC 3454 section 6)");
		default:
			return icu_failure(name, status);
		}
		if (nprep == 0) {
			return input_error(name + " is empty after SASLprep");
		}
		wiped_buffer<UChar> prepared(static_cast<std::size_t>(nprep));
		nprep = prepare(prepared.v.data(), nprep);
		if (U_FAILURE(status) != 0) {
			return icu_failure(name, status);
		}

		// UTF-16 -> UTF-8, straight into `out` (sized once: no copy of the
		// text is left in a freed buffer).
		status = U_ZERO_ERROR;
		int32_t n8 = 0;
		u_strToUTF8(nullptr, 0, &n8, prepared.v.data(), nprep, &status);
		if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status) != 0) {
			return icu_failure(name, status);
		}
		out.resize(static_cast<std::size_t>(n8));
		status = U_ZERO_ERROR;
		u_strToUTF8(out.data(), n8, &n8, prepared.v.data(), nprep, &status);
		if (U_FAILURE(status) != 0) {
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
			return c < 0x21 || c > 0x7e || c == ',';
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
		if (s.empty() || s.size() > 10 || s[0] == '0') {
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
		detail::append_sanitized(out, s, 64);
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


	// The keys of RFC 5802 section 3 from the SaltedPassword: the
	// client-final-message's proof (base64) and the ServerSignature. False
	// if OpenSSL fails.
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

// What PBKDF2 and the keys need and give, shared between the mechanism and
// its offloaded step (offload_step). The step reads the inputs and writes
// the outputs, then sets `done` (release); the mechanism touches neither
// until it reads `done` (acquire) as true (collect()), and drops its
// reference without reading them otherwise (a step sasl_bind gave up on:
// it runs on with this block). Wiped by its last owner.
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
	  std::move(password),
	  sasl_scram_options{ .authz_id = std::move(authz_id) },
	  std::nullopt)
{}

sasl_scram_sha256::sasl_scram_sha256(std::string username, std::string password, sasl_scram_options options)
  : sasl_scram_sha256(std::move(username), std::move(password), std::move(options), std::nullopt)
{}

sasl_scram_sha256::sasl_scram_sha256(std::string username,
  std::string password,
  sasl_scram_options options,
  std::optional<std::string> fixed_nonce)
  : username_(std::move(username)), password_(std::move(password)), options_(std::move(options)),
	fixed_nonce_(std::move(fixed_nonce))
{
	wipe_string(password);// a short password was copied, not moved
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

void sasl_scram_sha256::prepare(const sasl_bind_context &context) { can_offload_ = context.can_offload; }

// The outcome of an offloaded step, once it is over: its ServerSignature
// for verify(), its SaltedPassword for the cache. A step still running
// (sasl_bind gave up on it) is dropped: this exchange has no signature.
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
	const std::string &authz_id = options_.authz_id;
	// RFC 5802 section 5.1: the username is prepared as a query (unassigned
	// code points allowed).
	std::string user;
	if (auto r = saslprep(username_, "username", prep_kind::query, user); !r) {
		return std::unexpected(std::move(r.error()));
	}
	// The authorization identity is a saslname too (UTF-8), but RFC 5802
	// does not prepare it: it is sent as given (escaped) once checked. It
	// must be well-formed UTF-8 (RFC 3629: U8_NEXT refuses overlong forms,
	// surrogates and code points above U+10FFFF) without control characters
	// (C0, DEL, C1); every other code point is accepted.
	{
		const auto *p = reinterpret_cast<const std::uint8_t *>(authz_id.data());
		const auto n = static_cast<std::int64_t>(authz_id.size());
		for (std::int64_t i = 0; i < n;) {
			UChar32 c = 0;
			// NOLINTNEXTLINE(bugprone-inc-dec-in-conditions): ICU's macro, i is read and advanced in sequence
			U8_NEXT(p, i, n, c);
			if (c < 0) {
				return input_error("authorization identity is not valid UTF-8");
			}
			if (c < 0x20 || (c >= 0x7f && c < 0xa0)) {
				return input_error("authorization identity contains a control character");
			}
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

	// The password last, after every other check: a failure above leaves
	// no prepared password behind, and saslprep() wipes its own on failure.
	// RFC 5802 section 2.2: the password is prepared as a stored string
	// (unassigned code points refused).
	if (auto r = saslprep(password_, "password", prep_kind::stored, prepared_password_); !r) {
		return std::unexpected(std::move(r.error()));
	}

	gs2_header_ = authz_id.empty() ? "n,," : "n,a=" + escape_saslname(authz_id) + ",";
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
	// RFC 5802 section 3 AuthMessage order, which the two callers follow.
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
	struct wipe_on_exit
	{
		std::string &s;
		~wipe_on_exit() { wipe_string(s); }
	} const wipe_password{ prepared_password_ };
	auto parsed = parse_server_first(message);
	if (!parsed) {
		return std::unexpected(std::move(parsed.error()));
	}

	std::string without_proof = "c=" + base64_encode(gs2_header_) + ",r=";
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

	std::string without_proof = "c=" + base64_encode(gs2_header_) + ",r=";
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
	return [d = std::move(d), without_proof = std::move(without_proof)]() -> result<std::optional<std::string>> {
		struct done_on_exit
		{
			derivation &d;
			~done_on_exit()
			{
				wipe_string(d.password);
				d.done.store(true, std::memory_order_release);
			}
		} const done{ *d };
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
