// TLS channel bindings and the peer certificate, read from the OpenSSL
// session after the handshake; OpenLDAP's tls-server-end-point variant.
#pragma once

#include "jhetz/ldap/net/transport.hpp"

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

struct ssl_st;// OpenSSL's SSL

namespace jhetz::ldap::net::detail {

// tls-server-end-point of a DER certificate (RFC 5929 section 4.1); empty
// when undefined or unparsable.
[[nodiscard]] auto tls_server_end_point(std::span<const std::byte> certificate) -> std::vector<std::byte>;

// The same hash as OpenLDAP computes it; empty when the certificate does
// not parse or its algorithm is unknown.
[[nodiscard]] auto openldap_tls_server_end_point(std::span<const std::byte> certificate) -> std::vector<std::byte>;

// RFC 9266: the tls-exporter label and length.
inline constexpr std::string_view tls_exporter_label = "EXPORTER-Channel-Binding";
inline constexpr std::size_t tls_exporter_size = 32;

// After a successful handshake: records the peer certificate, channel
// bindings and default type, and turns renegotiation off. Leaves OpenSSL's
// error queue as it found it.
void record_tls_session(transport::layers &im, ssl_st *ssl);

// Clears what record_tls_session() set, and tls_exporter_used.
void clear_tls_session(transport::layers &im) noexcept;

// im's channel bindings without tls-exporter once an authentication used
// it (RFC 9266 section 4.1).
[[nodiscard]] auto authentication_channel_bindings(const transport::layers &im) noexcept -> ldap::channel_bindings;

}// namespace jhetz::ldap::net::detail
