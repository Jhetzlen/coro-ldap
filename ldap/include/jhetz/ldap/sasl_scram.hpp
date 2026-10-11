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
// Part of jhetz::ldap_net (the implementation needs OpenSSL), not of the
// codec library jhetz::ldap.
//
// Scope and limits:
// - No channel binding: the GS2 header is "n,," ("n,a=<authzid>," with an
//   authorization identity). SCRAM-SHA-256-PLUS is not provided.
// - SASLprep (RFC 4013) is implemented for ASCII only. For ASCII input the
//   profile maps nothing and only prohibits the control characters
//   (U+0000..U+001F, U+007F); NFKC leaves ASCII unchanged. A username or
//   password with a non-ASCII byte is rejected (client_errc::encode_error)
//   rather than sent unnormalized, since that would only work by chance.
//   The authorization identity is not SASLprep'ed (RFC 5802 does not ask
//   for it): control characters are rejected, other bytes are sent as is.
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
//   wiped with OPENSSL_cleanse when the object is destroyed; the salted
//   password and the derived keys are wiped as soon as the proof is built.
//   Copies the caller made of the password are the caller's to wipe.
//
// Errors (contexts start with "SCRAM-SHA-256: ", never contain the password):
// - client_errc::encode_error (cond::invalid_input): empty or non-ASCII
//   username or password, control characters.
// - client_errc::decode_error (cond::protocol_error): a malformed server
//   message.
// - client_errc::unexpected_response (cond::protocol_error): a server
//   message out of order, a nonce that does not extend ours, an iteration
//   count out of bounds, an unknown mandatory extension ("m="), a server
//   error ("e="), a wrong server signature, or a server that reports
//   success without a valid signature. The last three mean the server could
//   not be authenticated: do not trust that connection. When the server had
//   already reported success (the error comes from complete()),
//   connection::sasl_bind closes the connection, since the server considers
//   it bound.
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
	result<std::optional<std::string>> start() override;
	// After the client-first-message: the server-first-message gives the
	// client-final-message (c=, r=, p=<proof>). After the client-final-message
	// (a server that sends its server-final-message as a challenge rather than
	// with the success result): verifies it and answers with an empty response.
	result<std::optional<std::string>> step(std::optional<std::string_view> challenge) override;
	// Verifies the server-final-message ("v=") unless step() already did.
	result<void> complete(std::optional<std::string_view> server_creds) override;

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
