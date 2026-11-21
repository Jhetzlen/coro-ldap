// SASL GSSAPI (RFC 4752): Kerberos V5 binds for connection::sasl_bind
// (docs/API.md, "SASL GSSAPI"). Built with JHETZ_LDAP_WITH_GSSAPI.
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

enum class gssapi_channel_binding : std::uint8_t {
	// "tls-server-end-point:<hash>" (RFC 5929) over TLS.
	tls_server_end_point,
	none,// GSS_C_NO_CHANNEL_BINDINGS, even over TLS
};

// The hash of gssapi_channel_binding::tls_server_end_point.
enum class gssapi_channel_binding_form : std::uint8_t {
	// RFC 5929 section 4.1, as Active Directory computes it.
	rfc5929,
	// OpenLDAP's: SHA-256 for RSASSA-PSS, Ed25519 and Ed448 certificates.
	openldap,
};

// The SASL security layer to select from the server's offer (RFC 4752
// section 3.1).
enum class gssapi_security_layer : std::uint8_t {
	// The default; fails with security_layer_required if not offered.
	none,
	// Signed PDUs; confidentiality if the server offers only that.
	integrity,
	// Signed and encrypted PDUs.
	confidentiality,
	// The strongest offered; none over TLS when offered.
	best_offered,
};

// The largest maximum buffer size RFC 4752 can express (three octets).
inline constexpr std::uint32_t gssapi_max_buffer_limit = 0xff'ffff;

struct sasl_gssapi_options
{
	// "service@host"; empty: "ldap@<host>".
	std::string target{};
	// "jdoe@EXAMPLE.ORG" or "jdoe"; empty: the default credentials.
	std::string principal{};
	// "dn:..." or "u:..."; empty: the authenticated identity.
	std::string authz_id{};
	gssapi_channel_binding channel_binding = gssapi_channel_binding::tls_server_end_point;
	gssapi_channel_binding_form binding_form = gssapi_channel_binding_form::rfc5929;
	// Without TLS, a security layer stands in for it.
	bool require_tls = true;
	gssapi_security_layer security_layer = gssapi_security_layer::none;
	// With a security layer: the largest protected buffer accepted (1 to
	// gssapi_max_buffer_limit).
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
	void prepare(const sasl_bind_context &context) override;
	// The first token (an AP-REQ). Blocks while the KDC is contacted.
	[[nodiscard]] auto start() -> result<std::optional<std::string>> override;
	// The next context token, then the wrapped security layer reply.
	[[nodiscard]] auto step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>> override;
	// start()'s and step()'s gss_init_sec_context work for another thread.
	[[nodiscard]] auto offload_start() -> sasl_work override;
	[[nodiscard]] auto offload_step(std::optional<std::string_view> challenge) -> sasl_work override;
	// Succeeds only once the security layer reply was sent.
	[[nodiscard]] auto complete(std::optional<std::string_view> server_creds) -> result<void> override;
	// The selected layer, which owns the security context from then on; null
	// without one.
	[[nodiscard]] auto take_security_layer() -> std::unique_ptr<sasl_security_layer> override;
	// tls_server_end_point when the exchange carries channel bindings.
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
	bool tls_ = false;// from prepare()
	std::string bindings_;// the application data; empty: no bindings
	// Why the TLS connection cannot be bound; empty: it can be.
	std::string binding_error_;
	std::shared_ptr<state> state_;// shared with an offloaded step

	// require_tls without TLS and without a security layer.
	[[nodiscard]] auto unprotected() const noexcept -> bool;
};

namespace detail {

	// The security layer messages of RFC 4752 section 3.1, unwrapped.
	inline constexpr std::uint8_t gssapi_no_layer = 1;
	inline constexpr std::uint8_t gssapi_integrity = 2;
	inline constexpr std::uint8_t gssapi_confidentiality = 4;

	// The server's offer: a layer mask and its largest receivable message.
	struct gssapi_layer_offer
	{
		std::uint8_t layers = 0;
		std::uint32_t max_size = 0;
		friend auto operator==(const gssapi_layer_offer &, const gssapi_layer_offer &) -> bool = default;
	};

	// Exactly four octets: the layer mask and the size in network byte order.
	[[nodiscard]] auto parse_gssapi_layer_offer(std::string_view message) -> result<gssapi_layer_offer>;

	// The layer to select from `offer` for `requested`; with `require_tls`
	// and without `tls`, never none.
	[[nodiscard]] auto
	  gssapi_select_layer(const gssapi_layer_offer &offer, gssapi_security_layer requested, bool tls, bool require_tls)
		-> result<std::uint8_t>;

	// From gss_init_sec_context's ret_flags.
	struct gssapi_context_flags
	{
		bool integrity = false;
		bool confidentiality = false;
		bool sequence = false;
	};

	// Whether a context with `flags` can carry the selected layer (its
	// protection and sequence detection); gssapi_failure otherwise.
	[[nodiscard]] auto gssapi_check_context_flags(const gssapi_context_flags &flags, bool confidentiality)
	  -> result<void>;

	// The client's reply (to be wrapped): `layer`, `max_size`, `authz_id`.
	[[nodiscard]] auto gssapi_layer_reply(std::uint8_t layer, std::uint32_t max_size, std::string_view authz_id)
	  -> result<std::string>;

	// "tls-server-end-point:" and the hash, or empty for none or no TLS.
	[[nodiscard]] auto gssapi_channel_binding_data(const sasl_bind_context &context,
	  gssapi_channel_binding binding,
	  gssapi_channel_binding_form form) -> result<std::string>;

}// namespace detail

}// namespace jhetz::ldap
