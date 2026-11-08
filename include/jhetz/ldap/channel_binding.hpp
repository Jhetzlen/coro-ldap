// TLS channel bindings (RFC 5056): data identifying one TLS connection, which
// an authentication exchange (SCRAM-SHA-256-PLUS, GSSAPI) includes so it
// cannot be relayed by a man in the middle terminating TLS.
//
//   tls-server-end-point  RFC 5929 section 4.1: the hash of the server's
//                         certificate with its signature algorithm's hash
//                         (MD5 and SHA-1 become SHA-256). Absent for an
//                         algorithm without exactly one hash (Ed25519,
//                         Ed448). Any TLS version.
//   tls-exporter          RFC 9266: 32 bytes of TLS keying material, label
//                         "EXPORTER-Channel-Binding", empty context. TLS 1.3,
//                         and TLS 1.2 with the extended master secret (RFC
//                         7627); absent otherwise.
//
// tls-unique is not provided; on TLS 1.2 the default is tls-server-end-point
// where the certificate defines it (channel_bindings::default_type).
//
// They are computed once after the handshake, when the server sent a
// certificate; the client then refuses TLS 1.2 renegotiation (RFC 9266
// section 4.2), so they describe the connection for its lifetime. Without a
// server certificate nothing is recorded.
//
// tls-exporter serves one authentication per TLS connection (RFC 9266
// section 4.1): connection::channel_bindings() always reports it, but
// connection::sasl_bind passes no tls-exporter to mechanisms once a bind used
// it (sasl_mechanism::channel_binding_used); default_type then falls back to
// tls-server-end-point, or none. This header is part of the codec; the bytes
// come from jhetz::ldap_net's TLS layer.
// dependencies); the bytes come from jhetz::ldap_net's TLS layer.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace jhetz::ldap {

enum class channel_binding_type : std::uint8_t {
	tls_server_end_point,// RFC 5929 section 4
	tls_exporter,// RFC 9266
};

// The registered name of the type ("tls-server-end-point", "tls-exporter"),
// as SCRAM's GS2 header "p=<name>" carries it.
[[nodiscard]] constexpr auto to_string(channel_binding_type t) noexcept -> std::string_view
{
	switch (t) {
	case channel_binding_type::tls_server_end_point:
		return "tls-server-end-point";
	case channel_binding_type::tls_exporter:
		return "tls-exporter";
	}
	return {};
}

// The channel bindings of one TLS connection: views into the connection's
// state (see where they come from for how long they stay valid). An empty
// span means that type is not available on this connection.
struct channel_bindings
{
	std::span<const std::byte> tls_server_end_point{};
	std::span<const std::byte> tls_exporter{};
	// The type to use when the caller does not choose one: tls-exporter on
	// TLS 1.3 (RFC 9266 section 3 makes it SCRAM's default there), else
	// tls-server-end-point, else tls-exporter (TLS 1.2 with the extended
	// master secret, a certificate without a single hash function). nullopt
	// when neither is available (no TLS).
	std::optional<channel_binding_type> default_type{};

	// The data of type `t`; empty when it is not available.
	[[nodiscard]] constexpr auto get(channel_binding_type t) const noexcept -> std::span<const std::byte>
	{
		switch (t) {
		case channel_binding_type::tls_server_end_point:
			return tls_server_end_point;
		case channel_binding_type::tls_exporter:
			return tls_exporter;
		}
		return {};
	}
};

// The channel bindings of type `t` with their unique prefix (RFC 5056
// section 2.1): the type's name, a colon, then `data`. The form GSS-API's
// application_data carries (sasl_gssapi, Windows SSPI, OpenLDAP's libldap);
// SCRAM's RFC 5802 form has no prefix.
[[nodiscard]] inline auto prefixed_channel_binding(channel_binding_type t, std::span<const std::byte> data)
  -> std::string
{
	std::string out(to_string(t));
	out += ':';
	for (const std::byte b : data) {
		out += static_cast<char>(b);
	}
	return out;
}

}// namespace jhetz::ldap
