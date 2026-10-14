// SASL SCRAM-SHA-256 (RFC 5802, RFC 7677), client side, for
// connection::sasl_bind:
//
//   ldap::sasl_scram_sha256 mech("jdoe", password);
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// A password mechanism with mutual authentication: the password never
// crosses the wire, and the bind fails unless the server proves that it
// knows the stored keys (the "v=" server signature of the last message).
// Use it over TLS anyway: SCRAM does not protect the rest of the session.
//
// Part of jhetz::ldap_net (the implementation needs OpenSSL and ICU), not
// of the codec library jhetz::ldap.
//
// Scope and limits:
// - No channel binding: the GS2 header is "n,," ("n,a=<authzid>," with an
//   authorization identity). SCRAM-SHA-256-PLUS is not provided.
// - Usernames and passwords are UTF-8 and are prepared with SASLprep (RFC
//   4013, with ICU), as RFC 5802 requires: soft hyphens and the like are
//   mapped to nothing, non-ASCII spaces to U+0020, the text is normalized
//   to NFKC, and prohibited characters (controls, private use,
//   non-characters, ...) or text breaking the bidi rules are refused. The
//   password is a "stored string" (code points unassigned in Unicode 3.2
//   are refused), the username a "query" (they are allowed), as RFC 5802
//   sections 2.2 and 5.1 say. Invalid UTF-8 is refused.
//   Interoperability: cyrus-sasl's SCRAM (OpenLDAP's slapd) does not
//   SASLprep the password it reads from userPassword, so a stored password
//   that SASLprep changes (e.g. one with a non-ASCII space or not in NFKC)
//   does not match there. Passwords already in SASLprep form work.
// - The authorization identity must be valid UTF-8 without control
//   characters (C0, DEL, C1: U+0000-U+001F, U+007F-U+009F); any other code
//   point is accepted. It is not SASLprep'ed (RFC 5802 does not ask for it).
// - '=' and ',' in the username and authorization identity are escaped as
//   "=3D" and "=2C" (RFC 5802 section 5.1).
// - The server's iteration count must be in [min_iterations,
//   options.max_iterations] (4096 .. 1'000'000 by default): RFC 7677
//   section 4 asks for at least 4096, and the upper bound keeps a hostile
//   server from making the client spend seconds in PBKDF2 on every bind
//   (about 0.45 s for 1'000'000 on a 2020s x86-64 core). Lower it
//   (sasl_scram_options::max_iterations) when the servers are known.
// - PBKDF2 (the SaltedPassword) runs on a thread of its own when the
//   server asks for more than options.offload_above_iterations (16'384 by
//   default) and the io_context can be woken from another thread (Corosio's
//   default locking_mode::safe): sasl_bind hands it the step through
//   offload_step() (sasl.hpp), so other operations on the io_context go on
//   meanwhile. Up to that count, or under locking_mode::unsafe, it runs on
//   the I/O thread, inside step() (a few ms at most by default: less than a
//   thread start is worth). The bind's timeout and cancellation apply to
//   the wait; a step given up on runs to its end with copies of what it
//   needs, and its result is dropped. locking_mode::unsafe_io cannot be
//   told from safe and is unsupported for an offloaded step (its wakeup may
//   be lost under io_uring): set offload_above_iterations to
//   max_iterations to keep PBKDF2 inline there.
// - The SaltedPassword is cached per (salt, iteration count): a later bind
//   with the same object to a server that sends the same salt and count
//   (the same stored keys) skips PBKDF2. A different salt or count replaces
//   the cached value. It is a key that authenticates as the user to such a
//   server, so it is kept like the password: wiped with OPENSSL_cleanse
//   when replaced or when the object is destroyed.
// - The server nonce must extend the client nonce (start with it and be
//   longer).
// - The password is kept (to allow later binds with the same object) and
//   wiped with OPENSSL_cleanse when the object is destroyed; the buffers
//   of the SASLprep preparation when start() returns; the prepared
//   password and the derived keys (but the cached SaltedPassword, above)
//   as soon as the proof is built (a start() that fails leaves no
//   prepared password).
//   ICU's own internal working buffers cannot be wiped. Copies the caller
//   made of the password are the caller's to wipe.
//
// Errors (contexts never contain the password, nor name the mechanism):
// - client_errc::encode_error (cond::invalid_input): an empty username or
//   password (also after SASLprep), invalid UTF-8, a character SASLprep
//   prohibits (e.g. a control character) or that is unassigned, a bidi
//   rule violation; options.max_iterations outside [min_iterations,
//   2^31-1] (start() refuses it).
// - client_errc::decode_error (cond::protocol_error): a malformed server
//   message.
// - client_errc::unexpected_response (cond::protocol_error): a server
//   message out of order, a nonce that does not extend ours, an iteration
//   count out of bounds (the context gives the count and the bound), an unknown mandatory extension ("m="), a server
//   error ("e=", its text quoted in the context: at most 64 bytes, UTF-8,
//   with control characters, bidi controls, U+2028/U+2029 and ill-formed
//   sequences replaced by U+FFFD), a wrong server signature, or a server
//   that reports success without a valid signature. The last three mean
//   the server could not be authenticated: do not trust that connection.
//   When the server had already reported success (the error comes from
//   complete()), connection::sasl_bind closes the connection, since the
//   server considers it bound.
// - client_errc::internal_error (no condition): OpenSSL (RAND_bytes,
//   PBKDF2, HMAC, SHA-256) or ICU (e.g. out of memory, ICU data without
//   the SASLprep profile) failed: the environment, not the credentials.
// Error contexts do not name the mechanism: sasl_bind prefixes
// "sasl bind SCRAM-SHA-256".
// A server that refuses the proof normally answers invalidCredentials,
// which sasl_bind returns as errc::invalid_credentials (cond::auth_failed).
#pragma once

#include "jhetz/ldap/sasl.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

namespace detail {
	struct scram_test_access;// defined by the tests only
}

// Tuning of sasl_scram_sha256 (see the header comment).
struct sasl_scram_options
{
	// An identity to act as ("dn:...", "u:..."); empty: the authenticated
	// identity itself.
	std::string authz_id{};
	// The largest iteration count accepted from the server: PBKDF2's cost,
	// which the server chooses. In [sasl_scram_sha256::min_iterations,
	// 2^31-1]. Servers use 4096 to a few hundred thousand.
	std::uint32_t max_iterations = 1'000'000;
	// PBKDF2 with more iterations than this runs on a thread of its own
	// (when sasl_bind can offload it); up to it, on the I/O thread. 0:
	// always offloaded; max_iterations or more: never.
	std::uint32_t offload_above_iterations = 16'384;
};

class sasl_scram_sha256 final : public sasl_mechanism
{
  public:
	// RFC 7677 section 4: the iteration count "SHOULD be at least 4096".
	static constexpr std::uint32_t min_iterations = 4096;

	// `username`: the SASL authentication identity (for slapd, mapped to a DN
	// with authz-regexp). `authz_id`: an identity to act as ("dn:...",
	// "u:..."), empty: the authenticated identity itself. The inputs are
	// checked by start(), so the constructors cannot fail.
	// The moved-from `password` argument is wiped too.
	sasl_scram_sha256(std::string username, std::string password, std::string authz_id = {});
	sasl_scram_sha256(std::string username, std::string password, sasl_scram_options options);
	~sasl_scram_sha256() override;

	// Holds a password: not copyable, not movable (no stray copies to wipe).
	sasl_scram_sha256(const sasl_scram_sha256 &) = delete;
	auto operator=(const sasl_scram_sha256 &) -> sasl_scram_sha256 & = delete;

	auto name() const noexcept -> std::string_view override { return "SCRAM-SHA-256"; }
	// Notes whether sasl_bind can run a step on another thread
	// (sasl_bind_context::can_offload).
	void prepare(const sasl_bind_context &context) override;
	// client-first-message: GS2 header, n=<username>, r=<client nonce>.
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// After the client-first-message: the server-first-message gives the
	// client-final-message (c=, r=, p=<proof>), PBKDF2 included. After the
	// client-final-message (a server that sends its server-final-message as
	// a challenge rather than with the success result): verifies it and
	// answers with an empty response.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// The work of step() on the server-first-message when its PBKDF2 is to
	// run on a thread of its own (above options.offload_above_iterations,
	// not cached, after a prepare() that allowed it); empty otherwise, step()
	// then does it (a malformed message included: step() reports it).
	[[nodiscard]] auto offload_step(std::optional<std::string_view> challenge) -> sasl_work override;
	// Verifies the server-final-message ("v=") unless step() already did.
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;

  private:
	friend struct detail::scram_test_access;
	// `fixed_nonce`: tests only (detail::scram_test_access), a fixed client
	// nonce (e.g. the RFC 7677 test vector's) instead of a fresh random one.
	sasl_scram_sha256(std::string username,
	  std::string password,
	  sasl_scram_options options,
	  std::optional<std::string> fixed_nonce);

	enum class state : std::uint8_t { idle, sent_first, sent_final, verified };
	struct server_first;// the parsed server-first-message
	struct derivation;// PBKDF2 and the keys, shared with an offloaded step

	auto parse_server_first(std::string_view message) -> result<server_first>;
	auto client_final(std::string_view message) -> result<std::optional<std::string>>;
	void collect() noexcept;
	auto verify(std::string_view server_final) -> result<void>;
	void wipe() noexcept;
	void wipe_cache() noexcept;

	std::string username_;
	std::string password_;
	std::string prepared_password_;// SASLprep'ed, from start() until PBKDF2
	sasl_scram_options options_;
	std::optional<std::string> fixed_nonce_;
	bool can_offload_ = false;// from prepare()
	state state_ = state::idle;
	std::string gs2_header_;
	std::string client_nonce_;
	std::string client_first_bare_;
	std::array<unsigned char, 32> server_signature_{};
	bool have_signature_ = false;// server_signature_ was computed for this exchange
	// The step offloaded for this exchange, until its result is collected.
	std::shared_ptr<derivation> pending_;
	// The SaltedPassword of the last PBKDF2, for (cache_salt_, cache_iterations_).
	std::array<unsigned char, 32> cache_salted_{};
	std::string cache_salt_;
	std::uint32_t cache_iterations_ = 0;// 0: nothing cached
};

}// namespace jhetz::ldap
