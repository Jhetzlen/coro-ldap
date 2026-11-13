// TLS channel bindings (RFC 5056): tls-server-end-point (RFC 5929 section
// 4.1) and tls-exporter (RFC 9266), computed once after the handshake.
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

// The registered name, as SCRAM's GS2 header "p=<name>" carries it.
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

// Views into the connection's state; an empty span: not available.
struct channel_bindings
{
	std::span<const std::byte> tls_server_end_point{};
	std::span<const std::byte> tls_exporter{};
	// tls-exporter on TLS 1.3, else tls-server-end-point, else tls-exporter;
	// nullopt without TLS.
	std::optional<channel_binding_type> default_type{};

	// Empty when not available.
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

// "<type name>:" then `data` (RFC 5056 section 2.1), the form GSS-API's
// application_data carries.
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
