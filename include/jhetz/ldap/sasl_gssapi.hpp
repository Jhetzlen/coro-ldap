// SASL GSSAPI (RFC 4752): Kerberos V5 binds, as Active Directory and
// OpenLDAP (cyrus-sasl's gssapi plugin) accept them, for
// connection::sasl_bind:
//
//   ldap::sasl_gssapi mech;                  // ldap@<host>, default credentials
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// The credentials come from the GSS-API library (MIT krb5's
// libgssapi_krb5): a ticket-granting ticket in the default credential cache
// (kinit, KRB5CCNAME), or a client keytab (KRB5_CLIENT_KTNAME). The library
// never sees a password.
//
// Part of jhetz::ldap_net only when it is built with JHETZ_LDAP_WITH_GSSAPI
// (an optional dependency, off by default).
//
// Behaviour:
// - Threading: gss_acquire_cred and gss_init_sec_context may block for a
//   long time (MIT krb5 resolves the KDC and the realm through DNS and
//   sends the TGS-REQ for the service ticket, with its own retries and
//   timeouts: krb5.conf's kdc_timeout and max_retries, several seconds per
//   unreachable KDC). connection::sasl_bind runs them on a thread of its
//   own (one per call, offload_start and offload_step), so the io_context
//   (or the sync::connection's I/O thread) goes on with other work. The
//   bind's timeout (connection_options::operation_timeout) and
//   cancellation stop the wait, not the call: the bind then fails with
//   capy::error::timeout or canceled, and the call runs to its end on its
//   thread, with handles of its own, released there. The io_context keeps
//   the call as outstanding work: run() returns only once it is over, and
//   destroying the io_context (a sync::connection's destructor too) waits
//   for its thread to end. The io_context must accept posts from other
//   threads (Corosio's default locking_mode::safe). Before the first
//   BindRequest (the first call, which contacts the KDC) nothing was sent:
//   the connection stays usable. start() and step() called directly still
//   block their caller.
// - The target is a host-based service name (GSS_C_NT_HOSTBASED_SERVICE),
//   "ldap@<host>" with the host of the URL connected to (ldap://,
//   ldaps://), unless sasl_gssapi_options::target names another. Kerberos
//   turns it into the service principal ldap/<host>@<realm>: connect with
//   the server's DNS name, not an address, or set the target (an ldapi://
//   connection, or a wrap()ped transport, must). Whether the name is
//   canonicalized through DNS first is krb5.conf's business
//   (dns_canonicalize_hostname, rdns).
// - Mutual authentication is required: the bind fails unless the server
//   proved its identity (it holds the service principal's key).
// - Security layer (RFC 4752 section 3.1): the client always chooses "no
//   security layer", with a maximum buffer size of 0, so the rest of the
//   session is neither signed nor sealed by SASL. Use it over TLS (ldaps://
//   or StartTLS) unless the network is trusted. A server that does not
//   offer "no security layer" (only integrity or confidentiality) fails the
//   bind with client_errc::security_layer_required. Active Directory
//   offers it, but with the "LDAP server signing requirements" policy set
//   to require signing it refuses binds over plain ldap:// that do not sign
//   (errc::stronger_auth_required, diagnostic 00002028): use TLS, which
//   satisfies the policy.
// - No channel binding (GSS_C_NO_CHANNEL_BINDINGS): an Active Directory
//   whose "LDAP channel binding" policy is "Always" refuses the bind over
//   TLS.
// - Names are UTF-8 and passed to the GSS-API library as given (Kerberos
//   principals are byte strings; UTF-8 is what MIT krb5 and Active
//   Directory use). The target, principal and authorization identity must
//   be well-formed UTF-8 without control characters (C0, DEL, C1).
// - Every GSS-API handle (names, credentials, the security context, output
//   buffers) is released when no longer needed: the security context when
//   the bind succeeds (no security layer: nothing uses it afterwards), when
//   the mechanism fails, at the next start(), or with the object; those of
//   a call sasl_bind gave up on, by its thread once it ends.
//
// Errors (contexts never contain tokens or credentials, nor name the
// mechanism: connection::sasl_bind prefixes "sasl bind GSSAPI"):
// - client_errc::gssapi_failure (cond::auth_failed): a GSS-API call failed,
//   e.g. no ticket in the cache, an expired ticket, an unknown service
//   principal, an unreachable KDC, or a server that did not authenticate.
//   The context names the call and quotes gss_display_status's major and
//   minor status messages: "gss_init_sec_context: Unspecified GSS failure.
//   Minor code may provide more information (Server ldap/x@EXAMPLE.ORG not
//   found in Kerberos database)".
// - client_errc::security_layer_required (cond::access_denied): see above.
// - client_errc::encode_error (cond::invalid_input): no target (no host to
//   default to), or a target, principal or authorization identity that is
//   not well-formed UTF-8 or holds a control character.
// - client_errc::decode_error, unexpected_response (cond::protocol_error):
//   a malformed security layer message, a challenge out of order, or a
//   server that reports success before the exchange is complete (then
//   connection::sasl_bind closes the connection).
// A server that refuses the client normally answers invalidCredentials or
// inappropriateAuthentication (errc, cond::auth_failed).
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

struct sasl_gssapi_options
{
	// The service to authenticate to, a host-based service name
	// "service@host" (e.g. "ldap@dc1.example.org"). Empty: "ldap@<host>",
	// the host of the URL connected to.
	std::string target{};
	// The client principal ("jdoe@EXAMPLE.ORG", or "jdoe" in the default
	// realm) whose credentials to use, found in the credential cache
	// collection. Empty: the default credentials (the default cache's
	// principal).
	std::string principal{};
	// An identity to act as ("dn:...", "u:..."), sent in the security layer
	// reply. Empty: the authenticated identity itself.
	std::string authz_id{};
};

class sasl_gssapi final : public sasl_mechanism
{
  public:
	explicit sasl_gssapi(sasl_gssapi_options options = {});
	~sasl_gssapi() override;
	sasl_gssapi(sasl_gssapi &&) noexcept;
	sasl_gssapi &operator=(sasl_gssapi &&) noexcept;
	sasl_gssapi(const sasl_gssapi &) = delete;
	sasl_gssapi &operator=(const sasl_gssapi &) = delete;

	std::string_view name() const noexcept override { return "GSSAPI"; }
	// Keeps the host, for the default target.
	void prepare(const sasl_bind_context &context) override;
	// The first token of the Kerberos exchange (an AP-REQ). Blocks while
	// the KDC is contacted: sasl_bind calls offload_start() instead.
	[[nodiscard]] result<std::optional<std::string>> start() override;
	// The next token while the security context is being established, then
	// the wrapped security layer reply to the server's wrapped offer.
	[[nodiscard]] result<std::optional<std::string>> step(std::optional<std::string_view> challenge) override;
	// start()'s work for another thread, and step()'s while the security
	// context is being established (the gss_init_sec_context calls). The
	// work shares the GSS-API handles with the mechanism, which leaves them
	// alone until it is done: a step meanwhile is refused, and start()
	// begins with new handles.
	[[nodiscard]] sasl_work offload_start() override;
	[[nodiscard]] sasl_work offload_step(std::optional<std::string_view> challenge) override;
	// Succeeds only once the security layer reply was sent.
	[[nodiscard]] result<void> complete(std::optional<std::string_view> server_creds) override;

  private:
	struct state;// GSS-API handles; gssapi.h stays out of this header
	sasl_gssapi_options options_;
	std::string host_;
	std::shared_ptr<state> state_;// shared with an offloaded step
};

namespace detail {

	// The security layer messages of RFC 4752 section 3.1, without the
	// GSS_Wrap around them (exposed for the tests).
	inline constexpr std::uint8_t gssapi_no_layer = 1;
	inline constexpr std::uint8_t gssapi_integrity = 2;
	inline constexpr std::uint8_t gssapi_confidentiality = 4;

	// The server's offer: the layers it accepts (a bit mask of the above)
	// and the largest message it can receive (0 to 2^24 - 1).
	struct gssapi_layer_offer
	{
		std::uint8_t layers = 0;
		std::uint32_t max_size = 0;
		friend bool operator==(const gssapi_layer_offer &, const gssapi_layer_offer &) = default;
	};

	// The server's (unwrapped) message: exactly four octets, the layer mask
	// and the size in network byte order. Else client_errc::decode_error.
	[[nodiscard]] result<gssapi_layer_offer> parse_gssapi_layer_offer(std::string_view message);

	// The client's reply (to be wrapped): "no security layer", maximum size
	// 0, then `authz_id`. client_errc::security_layer_required if the offer
	// lacks "no security layer" but has another layer, unexpected_response
	// if it has none at all, encode_error for an `authz_id` that is not
	// well-formed UTF-8 or holds a control character.
	[[nodiscard]] result<std::string> gssapi_layer_reply(const gssapi_layer_offer &offer, std::string_view authz_id);

}// namespace detail

}// namespace jhetz::ldap
