// SASL GSSAPI (RFC 4752): Kerberos V5 binds, as Active Directory and
// OpenLDAP (cyrus-sasl's gssapi plugin) accept them, for
// connection::sasl_bind (DESIGN.md section 3, "GSSAPI"):
//
//   ldap::sasl_gssapi mech;                  // ldap@<host>, default credentials
//   if (auto r = co_await conn.sasl_bind(mech); !r) ...
//
// The credentials come from the GSS-API library (MIT krb5): a TGT in the
// default credential cache (kinit, KRB5CCNAME) or a client keytab
// (KRB5_CLIENT_KTNAME). The library never sees a password. Part of
// jhetz::ldap_net only when built with JHETZ_LDAP_WITH_GSSAPI (off by
// default).
//
// - Threading: gss_acquire_cred and gss_init_sec_context may block for long
//   (DNS, KDC retries; bounded only by krb5.conf and resolv.conf).
//   connection::sasl_bind runs them on a thread of their own
//   (offload_start, offload_step); see connection::sasl_bind for timeouts,
//   cancellation and the io_context's locking_mode. start() and step()
//   called directly block their caller.
// - The target is the host-based service "ldap@<host>" with the URL's host,
//   unless sasl_gssapi_options::target names another; Kerberos maps it to
//   ldap/<host>@<realm>. Connect by DNS name, or set the target (required
//   for ldapi:// and wrapped transports).
// - Mutual authentication is required.
// - Security layer (RFC 4752 section 3.1, sasl_gssapi_options::
//   security_layer): none by default (maximum buffer size 0), so use TLS
//   unless the network is trusted; a server not offering "no security layer"
//   fails the bind with client_errc::security_layer_required. AD requiring
//   LDAP signing refuses unsigned binds over plain ldap://
//   (errc::stronger_auth_required). integrity, confidentiality or
//   best_offered selects that layer from the server's offer and announces
//   max_receive_size; the context must provide that protection and
//   GSS_C_SEQUENCE_FLAG, else client_errc::gssapi_failure.
//   connection::sasl_bind installs it after the successful BindResponse;
//   outgoing PDUs are cut to the server's maximum buffer size, and an
//   incoming buffer that is too large, fails gss_unwrap, is replayed or out
//   of sequence, or lacks confidentiality on a confidentiality layer closes
//   the connection. With a layer in effect, start_tls() and a bind
//   negotiating another layer fail (client_errc::security_layer_in_effect);
//   a bind without a layer leaves it in place.
// - Channel binding (RFC 5056, RFC 5929 section 4,
//   sasl_gssapi_options::channel_binding): over TLS, the bindings carry
//   "tls-server-end-point:" and the certificate hash (RFC 5929's, or
//   OpenLDAP's with binding_form openldap), with GSS_C_CHANNEL_BOUND_FLAG;
//   AD checks them (LdapEnforceChannelBinding), slapd does not. Without TLS
//   none are sent. Over TLS without a hash (e.g. an Ed25519 certificate, or
//   none), start() fails with client_errc::tls_required before anything is
//   sent. gssapi_channel_binding::none turns them off (needed behind a
//   TLS-terminating proxy, where the acceptor refuses them). tls-exporter is
//   not used.
// - Names are UTF-8, passed as given; the target, principal and
//   authorization identity must be well-formed UTF-8 without control
//   characters.
// - GSS-API handles are released as soon as they are not needed; with a
//   security layer, the layer owns the security context until the
//   connection closes.
//
// Errors (contexts never contain tokens or credentials; connection::sasl_bind
// prefixes "sasl bind GSSAPI"):
// - client_errc::gssapi_failure (cond::auth_failed): a GSS-API call failed
//   (no or expired ticket, unknown service principal, unreachable KDC,
//   server not authenticated); the context names the call and quotes
//   gss_display_status's major and minor messages.
// - client_errc::security_layer_required, security_layer_unavailable
//   (cond::access_denied): see above.
// - client_errc::tls_required (cond::access_denied): no hash for channel
//   binding over TLS.
// - client_errc::encode_error (cond::invalid_input): no target, or a target,
//   principal or authorization identity not well-formed UTF-8 or holding a
//   control character.
// - client_errc::decode_error, unexpected_response (cond::protocol_error):
//   a malformed security layer message, a challenge out of order, or success
//   reported early (connection::sasl_bind then closes the connection).
// - errc::invalid_credentials or inappropriate_authentication
//   (cond::auth_failed): the server refused the client.
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

// The SASL security layer to negotiate (RFC 4752 section 3.1): the client
// selects one of the layers the server offers.
enum class gssapi_security_layer : std::uint8_t {
	// No security layer (the default). A server that does not offer it
	// fails the bind with client_errc::security_layer_required.
	none,
	// Integrity: every later PDU is signed (gss_wrap without
	// confidentiality). Confidentiality instead when the server offers only
	// that; client_errc::security_layer_unavailable when it offers neither.
	integrity,
	// Confidentiality: every later PDU is signed and encrypted.
	// client_errc::security_layer_unavailable when the server does not
	// offer it.
	confidentiality,
	// The strongest layer the server offers (confidentiality, integrity,
	// none), except over TLS, which protects the connection already: no
	// layer there when the server offers that.
	best_offered,
};

// The largest maximum buffer size RFC 4752 can express (three octets).
inline constexpr std::uint32_t gssapi_max_buffer_limit = 0xff'ffff;

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
	// The security layer to select (see the header comment).
	gssapi_security_layer security_layer = gssapi_security_layer::none;
	// With a security layer: the maximum buffer size announced to the
	// server, the largest protected buffer accepted from it (1 to
	// gssapi_max_buffer_limit; else start() fails with
	// client_errc::encode_error). A larger one closes the connection. LDAP
	// PDUs larger than it still pass, in several buffers.
	std::uint32_t max_receive_size = 65536;
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
	// After the step that sent the security layer reply, when it selected
	// integrity or confidentiality: the layer, which owns the security
	// context from then on. Null otherwise.
	[[nodiscard]] auto take_security_layer() -> std::unique_ptr<sasl_security_layer> override;
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
	bool tls_ = false;// the connection is TLS (prepare())
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

	// The layer (one of the bits above) to select from `offer` for
	// `requested`, on a TLS connection when `tls`. unexpected_response if
	// the offer has no layer at all, not even none;
	// security_layer_required for gssapi_security_layer::none without
	// "no security layer" offered; security_layer_unavailable when the
	// layer asked for is not offered; unexpected_response for a layer
	// selected from an offer whose maximum size is 0.
	[[nodiscard]] auto gssapi_select_layer(const gssapi_layer_offer &offer, gssapi_security_layer requested, bool tls)
	  -> result<std::uint8_t>;

	// What the established security context provides, from
	// gss_init_sec_context's ret_flags (GSS_C_INTEG_FLAG, GSS_C_CONF_FLAG,
	// GSS_C_SEQUENCE_FLAG).
	struct gssapi_context_flags
	{
		bool integrity = false;
		bool confidentiality = false;
		bool sequence = false;
	};

	// Whether a context with `flags` can carry the selected layer (a
	// confidentiality layer when `confidentiality`, else integrity): that
	// protection and sequence detection (RFC 4752 section 3.1: without it
	// gss_unwrap reports no replayed or reordered buffer for the layer to
	// refuse). client_errc::gssapi_failure otherwise.
	[[nodiscard]] auto gssapi_check_context_flags(const gssapi_context_flags &flags, bool confidentiality)
	  -> result<void>;

	// The client's reply (to be wrapped): `layer`, then the maximum size
	// `max_size` (0 for gssapi_no_layer, whatever is given; else 1 to
	// gssapi_max_buffer_limit) in network byte order, then `authz_id`.
	// encode_error for a maximum size out of range, or an `authz_id` that
	// is not well-formed UTF-8 or holds a control character.
	[[nodiscard]] auto gssapi_layer_reply(std::uint8_t layer, std::uint32_t max_size, std::string_view authz_id)
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
