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
//   max_iterations] (4096 .. 1'000'000): RFC 7677 section 4 asks for at
//   least 4096, and the upper bound keeps a hostile server from making the
//   client spend seconds in PBKDF2 (which runs on the calling thread, inside
//   step(), so it blocks the event loop meanwhile).
// - The server nonce must extend the client nonce (start with it and be
//   longer).
// - The password is kept (to allow later binds with the same object) and
//   wiped with OPENSSL_cleanse when the object is destroyed; the buffers
//   of the SASLprep preparation when start() returns; the prepared
//   password, the salted password and the derived keys as soon as the
//   proof is built (a start() that fails leaves no prepared password).
//   ICU's own internal working buffers cannot be wiped. Copies the caller
//   made of the password are the caller's to wipe.
//
// Errors (contexts never contain the password, nor name the mechanism):
// - client_errc::encode_error (cond::invalid_input): an empty username or
//   password (also after SASLprep), invalid UTF-8, a character SASLprep
//   prohibits (e.g. a control character) or that is unassigned, a bidi
//   rule violation; also an ICU failure.
// - client_errc::decode_error (cond::protocol_error): a malformed server
//   message.
// - client_errc::unexpected_response (cond::protocol_error): a server
//   message out of order, a nonce that does not extend ours, an iteration
//   count out of bounds, an unknown mandatory extension ("m="), a server
//   error ("e=", its text quoted in the context: at most 64 bytes, UTF-8,
//   with control characters, bidi controls, U+2028/U+2029 and ill-formed
//   sequences replaced by U+FFFD), a wrong server signature, or a server
//   that reports success without a valid signature. The last three mean
//   the server could not be authenticated: do not trust that connection.
//   When the server had already reported success (the error comes from
//   complete()), connection::sasl_bind closes the connection, since the
//   server considers it bound.
// - client_errc::encode_error also for an OpenSSL failure (RAND_bytes,
//   PBKDF2, HMAC, SHA-256).
// Error contexts do not name the mechanism: sasl_bind prefixes
// "sasl bind SCRAM-SHA-256".
// A server that refuses the proof normally answers invalidCredentials,
// which sasl_bind returns as errc::invalid_credentials (cond::auth_failed).
#pragma once

#include "jhetz/ldap/sasl.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

namespace detail {
	struct scram_test_access;// defined by the tests only
}

class sasl_scram_sha256 final : public sasl_mechanism
{
  public:
	// RFC 7677 section 4: the iteration count "SHOULD be at least 4096".
	static constexpr std::uint32_t min_iterations = 4096;
	// Upper bound on the iteration count the client accepts: PBKDF2 runs on
	// the calling thread (the event loop) with a cost the server chooses.
	// Servers use 4096 to a few hundred thousand.
	static constexpr std::uint32_t max_iterations = 1'000'000;

	// `username`: the SASL authentication identity (for slapd, mapped to a DN
	// with authz-regexp). `authz_id`: an identity to act as ("dn:...",
	// "u:..."), empty: the authenticated identity itself. The inputs are
	// checked by start(), so the constructor cannot fail.
	// The moved-from `password` argument is wiped too.
	sasl_scram_sha256(std::string username, std::string password, std::string authz_id = {});
	~sasl_scram_sha256() override;

	// Holds a password: not copyable, not movable (no stray copies to wipe).
	sasl_scram_sha256(const sasl_scram_sha256 &) = delete;
	sasl_scram_sha256 &operator=(const sasl_scram_sha256 &) = delete;

	std::string_view name() const noexcept override { return "SCRAM-SHA-256"; }
	// client-first-message: GS2 header, n=<username>, r=<client nonce>.
	[[nodiscard]] result<std::optional<std::string>> start() override;
	// After the client-first-message: the server-first-message gives the
	// client-final-message (c=, r=, p=<proof>). After the client-final-message
	// (a server that sends its server-final-message as a challenge rather than
	// with the success result): verifies it and answers with an empty response.
	[[nodiscard]] result<std::optional<std::string>> step(std::optional<std::string_view> challenge) override;
	// Verifies the server-final-message ("v=") unless step() already did.
	[[nodiscard]] result<void> complete(std::optional<std::string_view> server_creds) override;

  private:
	friend struct detail::scram_test_access;
	// `fixed_nonce`: tests only (detail::scram_test_access), a fixed client
	// nonce (e.g. the RFC 7677 test vector's) instead of a fresh random one.
	sasl_scram_sha256(std::string username,
	  std::string password,
	  std::string authz_id,
	  std::optional<std::string> fixed_nonce);

	enum class state : std::uint8_t { idle, sent_first, sent_final, verified };

	result<std::optional<std::string>> client_final(std::string_view server_first);
	result<void> verify(std::string_view server_final);
	void wipe() noexcept;

	std::string username_;
	std::string password_;
	std::string prepared_password_;// SASLprep'ed, from start() until PBKDF2
	std::string authz_id_;
	std::optional<std::string> fixed_nonce_;
	state state_ = state::idle;
	std::string gs2_header_;
	std::string client_nonce_;
	std::string client_first_bare_;
	std::array<unsigned char, 32> server_signature_{};
	bool have_signature_ = false;// server_signature_ was computed for this exchange
};

}// namespace jhetz::ldap
