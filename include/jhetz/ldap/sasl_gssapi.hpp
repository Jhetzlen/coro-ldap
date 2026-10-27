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
//   sends the TGS-REQ for the service ticket, retrying with backoff over
//   the KDCs, several seconds per unreachable one; the total is bounded
//   only by krb5.conf's [libdefaults] request_timeout, MIT 1.22 and later,
//   default none; DNS by resolv.conf's timeout and attempts; Heimdal has
//   kdc_timeout and max_retries instead). connection::sasl_bind runs them
//   on a thread of its own (one per call, offload_start and offload_step),
//   so the io_context (or the sync::connection's I/O thread) goes on with
//   other work. The bind's timeout (connection_options::operation_timeout)
//   and cancellation stop the wait, not the call: the bind then fails with
//   capy::error::timeout or canceled, and the call runs to its end on its
//   thread, with handles of its own, released there. The io_context keeps
//   the call as outstanding work: run() returns only once it is over, and
//   destroying the io_context (a sync::connection's destructor too) waits
//   for its thread to end. The io_context must accept posts from other
//   threads (Corosio's default locking_mode::safe; under unsafe the bind
//   fails with std::errc::operation_not_supported, nothing sent; unsafe_io
//   is unsupported). Before the first BindRequest (the first call, which
//   contacts the KDC) nothing was sent: the connection stays usable.
//   start() and step() called directly still block their caller.
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
// - Channel binding (RFC 5056, RFC 5929 section 4), chosen with
//   sasl_gssapi_options::channel_binding: over TLS (ldaps:// or StartTLS),
//   gss_init_sec_context is given a gss_channel_bindings_struct with no
//   addresses (GSS_C_AF_UNSPEC, empty) and the application data
//   "tls-server-end-point:" followed by the hash of the server's
//   certificate (prefixed_channel_binding, channel_binding.hpp). Kerberos
//   puts its MD5 into the authenticator's checksum (RFC 4121 section
//   4.1.1.2), and the server compares it with the hash of the certificate
//   it sent: a man in the middle that terminates TLS with a certificate of
//   its own cannot relay the bind. This is the form Active Directory checks
//   for its "LDAP channel binding" policy (LdapEnforceChannelBinding: with
//   "Always" it refuses a bind over TLS without it; with "When supported"
//   it refuses a wrong one): Windows' own clients pass Schannel's
//   SECPKG_ATTR_ENDPOINT_BINDINGS, which begins with "tls-server-end-point:"
//   (Microsoft's SEC_CHANNEL_BINDINGS documentation; OpenJDK's
//   JDK-8245527 does the same for AD). OpenLDAP's libldap builds the same
//   bytes ("sasl-cbinding tls-endpoint": ldap_pvt_sasl_cbinding), but
//   cyrus-sasl's gssapi plugin ignores them in its latest release, 2.1.28
//   (GSS_C_NO_CHANNEL_BINDINGS on both sides): slapd does not check GSSAPI
//   bindings. Its unreleased master passes them as application_data
//   (addresses zeroed) only with the security property
//   SASL_SEC_NONSTD_CBIND (OpenLDAP's "sasl-secprops ...,nonstdcbind" in
//   slapd, SASL_SECPROPS for libldap, beside "sasl-cbinding tls-endpoint";
//   only in an OpenLDAP built against such a cyrus-sasl), a flag the same
//   master's mechanism selection (lib/server.c mech_permitted) also asks
//   of every mechanism and no plugin declares, so, from the sources, a
//   slapd with it offers no SASL mechanism at all. Active Directory is the
//   server that checks them. MIT krb5
//   1.19 and later also tells the server that the client binds
//   (Microsoft's KERB_AP_OPTIONS_CBT) when krb5.conf sets
//   client_aware_gss_bindings: an acceptor given bindings then requires
//   them. The hash is RFC 5929's
//   (channel_bindings::tls_server_end_point), or OpenLDAP's
//   (sasl_gssapi_options::binding_form openldap, the bytes libldap builds,
//   for a slapd that checks them, see above: they differ only for an
//   RSASSA-PSS, Ed25519 or Ed448 certificate, see sasl_scram.hpp). Without TLS no bindings are sent
//   (GSS_C_NO_CHANNEL_BINDINGS). Over TLS without a hash (RFC 5929 has none
//   for Ed25519 and Ed448 certificates; the openldap form, none for a
//   certificate it cannot parse), start() fails with
//   client_errc::tls_required (cond::access_denied) before anything is
//   sent, as SCRAM-SHA-256-PLUS does: the certificate is chosen by whoever
//   terminates TLS, so going on without bindings would let a man in the
//   middle that the certificate check let through present an Ed25519
//   certificate and relay the unbound bind, which an acceptor given
//   bindings accepts unless the client announced that it binds (AD with
//   "When supported" too). gssapi_channel_binding::none is the explicit
//   opt-out. A server whose acceptor is given no bindings (slapd, AD with
//   the policy "Never") ignores them; one given
//   others (TLS terminated by a proxy in front of the server, whose
//   certificate the client sees) refuses the bind (GSS_S_BAD_BINDINGS):
//   gssapi_channel_binding::none turns them off. tls-exporter (RFC 9266)
//   is not used: neither Active Directory nor OpenLDAP knows it.
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

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap {

// Whether the Kerberos exchange is bound to the TLS channel (see the header
// comment).
enum class gssapi_channel_binding : std::uint8_t {
	// Over TLS: "tls-server-end-point:<hash>" (RFC 5929); start() fails
	// with client_errc::tls_required when the connection has no such hash.
	tls_server_end_point,
	none,// GSS_C_NO_CHANNEL_BINDINGS, even over TLS
};

// The hash of gssapi_channel_binding::tls_server_end_point.
enum class gssapi_channel_binding_form : std::uint8_t {
	// RFC 5929 section 4.1, as Active Directory computes it.
	rfc5929,
	// OpenLDAP's (scram_channel_binding_form::openldap's hash): differs
	// only for RSASSA-PSS, Ed25519 and Ed448 certificates, which libldap
	// hashes with SHA-256 (a slapd checks GSSAPI bindings only with
	// cyrus-sasl's SASL_SEC_NONSTD_CBIND: see the header comment).
	openldap,
};

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
	// Channel binding over TLS; none for a server that refuses the
	// connection's (behind a TLS-terminating proxy).
	gssapi_channel_binding channel_binding = gssapi_channel_binding::tls_server_end_point;
	// The hash of the tls-server-end-point binding.
	gssapi_channel_binding_form binding_form = gssapi_channel_binding_form::rfc5929;
};

class sasl_gssapi final : public sasl_mechanism
{
  public:
	explicit sasl_gssapi(sasl_gssapi_options options = {});
	~sasl_gssapi() override;
	sasl_gssapi(sasl_gssapi &&) noexcept;
	auto operator=(sasl_gssapi &&) noexcept -> sasl_gssapi &;
	sasl_gssapi(const sasl_gssapi &) = delete;
	auto operator=(const sasl_gssapi &) -> sasl_gssapi & = delete;

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "GSSAPI"; }
	// Keeps the host, for the default target, and the channel bindings.
	void prepare(const sasl_bind_context &context) override;
	// The first token of the Kerberos exchange (an AP-REQ). Blocks while
	// the KDC is contacted: sasl_bind calls offload_start() instead.
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// The next token while the security context is being established, then
	// the wrapped security layer reply to the server's wrapped offer.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// start()'s work for another thread, and step()'s while the security
	// context is being established (the gss_init_sec_context calls). The
	// work shares the GSS-API handles with the mechanism, which leaves them
	// alone until it is done: a step meanwhile is refused, and start()
	// begins with new handles.
	[[nodiscard]] auto offload_start() -> sasl_work override;
	[[nodiscard]] auto offload_step(std::optional<std::string_view> challenge) -> sasl_work override;
	// Succeeds only once the security layer reply was sent.
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;
	// tls_server_end_point when the exchange carries channel bindings,
	// else nullopt (never tls-exporter).
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<channel_binding_type> override
	{
		if (bindings_.empty()) {
			return std::nullopt;
		}
		return channel_binding_type::tls_server_end_point;
	}

  private:
	struct state;// GSS-API handles; gssapi.h stays out of this header
	sasl_gssapi_options options_;
	std::string host_;
	std::string bindings_;// the application data; empty: no bindings
	// Why the TLS connection cannot be bound (start() fails with it);
	// empty: it can be, or no bindings are wanted.
	std::string binding_error_;
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
		friend auto operator==(const gssapi_layer_offer &, const gssapi_layer_offer &) -> bool = default;
	};

	// The server's (unwrapped) message: exactly four octets, the layer mask
	// and the size in network byte order. Else client_errc::decode_error.
	[[nodiscard]] auto parse_gssapi_layer_offer(std::string_view message) -> result<gssapi_layer_offer>;

	// The client's reply (to be wrapped): "no security layer", maximum size
	// 0, then `authz_id`. client_errc::security_layer_required if the offer
	// lacks "no security layer" but has another layer, unexpected_response
	// if it has none at all, encode_error for an `authz_id` that is not
	// well-formed UTF-8 or holds a control character.
	[[nodiscard]] auto gssapi_layer_reply(const gssapi_layer_offer &offer, std::string_view authz_id)
	  -> result<std::string>;

	// The application data of the channel bindings for a bind on a
	// connection described by `context` (its tls, bindings and
	// peer_certificate): "tls-server-end-point:" and the hash of the
	// `form`, or empty (no bindings) for gssapi_channel_binding::none or no
	// TLS. client_errc::tls_required over TLS without a hash.
	[[nodiscard]] auto gssapi_channel_binding_data(const sasl_bind_context &context,
	  gssapi_channel_binding binding,
	  gssapi_channel_binding_form form) -> result<std::string>;

}// namespace detail

}// namespace jhetz::ldap
