// TLS channel bindings (RFC 5056): data that identifies one TLS connection,
// which an authentication exchange (SCRAM-SHA-256-PLUS, GSSAPI) includes so
// that it cannot be relayed through a man in the middle that terminates TLS
// with a certificate of its own.
//
// Two channel binding types are provided:
//
//   tls-server-end-point  RFC 5929 section 4.1: the hash of the server's
//                         certificate, with the hash function of the
//                         certificate's signature algorithm (MD5 and SHA-1
//                         are replaced by SHA-256). Undefined, so absent,
//                         for a signature algorithm without exactly one hash
//                         function (Ed25519, Ed448). Any TLS version.
//   tls-exporter          RFC 9266: 32 bytes of TLS keying material
//                         (RFC 5705 / RFC 8446 section 7.5 exporter), label
//                         "EXPORTER-Channel-Binding", zero-length context.
//                         TLS 1.3, and TLS 1.2 with the extended master
//                         secret extension (RFC 7627; RFC 9266 section 2
//                         ties the binding's uniqueness to it); absent
//                         otherwise.
//
// tls-unique (RFC 5929 section 3) is not provided: it is undefined for TLS
// 1.3 (RFC 9266 section 3), and without the extended master secret it is
// open to the triple handshake attack (RFC 9266 section 1, RFC 7627). For
// TLS 1.2, where RFC 5802 makes tls-unique SCRAM's default, this library
// defaults to tls-server-end-point instead (when the certificate defines
// it; see channel_bindings::default_type), which servers support widely
// (Active Directory, PostgreSQL; OpenLDAP's "sasl-cbinding tls-endpoint" in
// a form of its own, see sasl_scram.hpp).
//
// They are computed once, after the handshake, when the server sent a
// certificate (the client's verify callback, which reaches OpenSSL's
// session, ran). The client then refuses TLS 1.2 renegotiation (RFC 9266
// section 4.2: tls-exporter is undefined where renegotiation is enabled),
// so they and the peer certificate describe the connection for its
// lifetime. Without a server certificate nothing is recorded (no peer
// certificate, no channel bindings) and renegotiation is left at
// OpenSSL's default.
//
// RFC 9266 section 4.1: tls-exporter MUST NOT be used for more than one
// authentication mechanism instance on a TLS connection.
// ldap::connection::channel_bindings() gives the connection's bindings,
// tls-exporter included, whatever was done with them; connection::sasl_bind
// passes them to mechanisms (sasl_bind_context) without tls-exporter once
// a bind used it (sasl_mechanism::channel_binding_used), default_type then
// tls-server-end-point, or none. This header is part of the codec (no
// dependencies); the bytes come from jhetz::ldap_net's TLS layer.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
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

}// namespace jhetz::ldap
