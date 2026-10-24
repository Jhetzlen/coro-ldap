// Internal: TLS channel bindings (channel_binding.hpp) and the peer
// certificate, read from the client's OpenSSL session after the handshake
// (tls.cpp) into the transport; and OpenLDAP's variant of
// tls-server-end-point for SCRAM (sasl_scram.cpp).
#pragma once

#include "jhetz/ldap/net/transport.hpp"

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

struct ssl_st;// OpenSSL's SSL

namespace jhetz::ldap::net::detail {

// The tls-server-end-point channel binding of a DER certificate (RFC 5929
// section 4.1): its hash with the hash function of its signature
// algorithm, SHA-256 in place of MD5 or SHA-1. Empty when the type is
// undefined for the certificate (a signature algorithm without exactly one
// hash function, e.g. Ed25519) or the certificate does not parse.
[[nodiscard]] auto tls_server_end_point(std::span<const std::byte> certificate) -> std::vector<std::byte>;

// The same hash as OpenLDAP computes it (libldap's tlso_session_endpoint,
// which slapd's "sasl-cbinding tls-endpoint" uses): the hash function
// named by the signature algorithm's OID alone, SHA-256 when the OID names
// none or a weak one. Differs from tls_server_end_point() for RSASSA-PSS
// (SHA-256 whatever the PSS hash) and Ed25519 / Ed448 (SHA-256, where RFC
// 5929 has no value). Empty when the certificate does not parse or its
// signature algorithm is unknown to OpenSSL.
[[nodiscard]] auto openldap_tls_server_end_point(std::span<const std::byte> certificate) -> std::vector<std::byte>;

// RFC 9266: the tls-exporter label and length.
inline constexpr std::string_view tls_exporter_label = "EXPORTER-Channel-Binding";
inline constexpr std::size_t tls_exporter_size = 32;

// After a successful client handshake on `ssl`: fills im.peer_certificate,
// the channel bindings and the default type. tls-exporter only for TLS 1.3
// or TLS 1.2 with the extended master secret (RFC 9266 section 2). Turns
// off renegotiation on `ssl` (SSL_OP_NO_RENEGOTIATION), so that what it
// records describes the connection for its lifetime and tls-exporter is
// defined (RFC 9266 section 4.2). Leaves what it cannot compute empty, and
// OpenSSL's error queue as it found it (ERR_set_mark / ERR_pop_to_mark).
// tls_handshake() never passes a null `ssl` (it fails closed when the
// verify callback did not run); a null one is handled defensively by
// only clearing im.
void record_tls_session(transport::impl &im, ssl_st *ssl);

// Clears what record_tls_session() set, and tls_exporter_used.
void clear_tls_session(transport::impl &im) noexcept;

// The channel bindings that sasl_bind hands a mechanism
// (sasl_bind_context::bindings): im's, without tls-exporter once an
// authentication used it (im.tls_exporter_used; RFC 9266 section 4.1:
// tls-exporter MUST NOT be used for more than one authentication mechanism
// instance on a TLS connection). The default type is then
// tls-server-end-point when the connection has it, else none. Views into
// im, as transport::channel_bindings()'s.
[[nodiscard]] auto authentication_channel_bindings(const transport::impl &im) noexcept -> ldap::channel_bindings;

}// namespace jhetz::ldap::net::detail
