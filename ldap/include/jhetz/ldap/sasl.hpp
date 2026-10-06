// SASL mechanisms for connection::sasl_bind (RFC 4513 section 5.2, RFC 4422).
//
// A mechanism produces the credentials of each BindRequest and reads the
// server's challenges; the connection drives the exchange (one BindRequest
// per step while the server answers saslBindInProgress):
//
//   ldap::sasl_external mech;                       // identity from TLS / ldapi://
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// Implement sasl_mechanism to add one (SCRAM-SHA-256 and GSSAPI would fit
// this interface; they are not provided). A mechanism object serves one
// bind at a time.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

class sasl_mechanism
{
  public:
	virtual ~sasl_mechanism() = default;

	// The mechanism name sent in the BindRequest, e.g. "EXTERNAL".
	virtual std::string_view name() const noexcept = 0;
	// Credentials of the first BindRequest (nullopt: none sent). Called at
	// the start of each bind, so it also resets the mechanism.
	virtual result<std::optional<std::string>> start() = 0;
	// After saslBindInProgress: the server's challenge (serverSaslCreds,
	// nullopt if absent) gives the credentials of the next BindRequest. An
	// error aborts the bind.
	virtual result<std::optional<std::string>> step(std::optional<std::string_view> challenge) = 0;
	// After success: the server's final serverSaslCreds, if any (e.g. a
	// SCRAM server signature to verify). An error fails the bind. Default:
	// accept anything.
	virtual result<void> complete(std::optional<std::string_view> server_creds)
	{
		(void)server_creds;
		return {};
	}
};

// EXTERNAL (RFC 4422 appendix A): the server takes the identity from the
// layer below, a TLS client certificate or the peer credentials of an
// ldapi:// socket. `authz_id` asks to act as another identity ("dn:...",
// "u:..."); empty: the authenticated identity itself. One step: a challenge
// from the server is a protocol error.
class sasl_external final : public sasl_mechanism
{
  public:
	explicit sasl_external(std::string authz_id = {}) : authz_id_(std::move(authz_id)) {}

	std::string_view name() const noexcept override { return "EXTERNAL"; }
	result<std::optional<std::string>> start() override { return std::optional<std::string>(authz_id_); }
	result<std::optional<std::string>> step(std::optional<std::string_view>) override
	{
		return fail(
		  client_errc::unexpected_response, "EXTERNAL: the server sent a challenge (EXTERNAL has a single step)");
	}

  private:
	std::string authz_id_;
};

}// namespace jhetz::ldap
