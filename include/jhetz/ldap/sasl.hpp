// SASL mechanisms for connection::sasl_bind (RFC 4513 section 5.2, RFC 4422).
//
// A mechanism produces the credentials of each BindRequest and reads the
// server's challenges; the connection drives the exchange (one BindRequest
// per step while the server answers saslBindInProgress):
//
//   ldap::sasl_external mech;                       // identity from TLS / ldapi://
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// SCRAM-SHA-256 is sasl_scram_sha256 (sasl_scram.hpp, in jhetz::ldap_net),
// GSSAPI (Kerberos) sasl_gssapi (sasl_gssapi.hpp, in jhetz::ldap_net when
// built with JHETZ_LDAP_WITH_GSSAPI). Implement sasl_mechanism to add
// another. A mechanism object serves one bind at a time.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

// What connection::sasl_bind tells a mechanism about the server, before
// start() (sasl_mechanism::prepare). Valid only during that call.
struct sasl_bind_context
{
	// The host of the URL connected to (ldap://, ldaps://), as decoded:
	// a name or an IP address (without brackets). Empty for ldapi:// and
	// for transports wrap()ped by the caller.
	std::string_view host{};
};

class sasl_mechanism
{
  public:
	virtual ~sasl_mechanism() = default;

	// Called by sasl_bind at the start of each bind, before start(), e.g.
	// for GSSAPI's default target (ldap@<host>). Default: ignored.
	virtual void prepare(const sasl_bind_context &context) { (void)context; }

	// The mechanism name sent in the BindRequest, e.g. "EXTERNAL".
	virtual std::string_view name() const noexcept = 0;
	// Credentials of the first BindRequest (nullopt: none sent). Called at
	// the start of each bind, so it also resets the mechanism.
	[[nodiscard]] virtual result<std::optional<std::string>> start() = 0;
	// After saslBindInProgress: the server's challenge (serverSaslCreds,
	// nullopt if absent) gives the credentials of the next BindRequest. An
	// error aborts the bind.
	[[nodiscard]] virtual result<std::optional<std::string>> step(std::optional<std::string_view> challenge) = 0;
	// After success: the server's final serverSaslCreds, if any (e.g. a
	// SCRAM server signature to verify). An error fails the bind. Default:
	// accept anything.
	[[nodiscard]] virtual result<void> complete(std::optional<std::string_view> server_creds)
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
	[[nodiscard]] result<std::optional<std::string>> start() override { return std::optional<std::string>(authz_id_); }
	[[nodiscard]] result<std::optional<std::string>> step(std::optional<std::string_view>) override
	{
		return fail(
		  client_errc::unexpected_response, "EXTERNAL: the server sent a challenge (EXTERNAL has a single step)");
	}

  private:
	std::string authz_id_;
};

}// namespace jhetz::ldap
