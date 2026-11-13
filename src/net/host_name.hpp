// Internal: host names as compared by referral chasing (loop detection,
// make_same_policy_connector's allow-list and connection reuse).
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap::net::detail {

// The ASCII form of a host name for comparisons: one trailing dot dropped,
// lowered, IDNA ToASCII for non-ASCII names (nullopt if that fails).
[[nodiscard]] auto ascii_host_name(std::string_view host) -> std::optional<std::string>;

// No octet of `s` is outside ASCII.
[[nodiscard]] auto is_ascii(std::string_view s) noexcept -> bool;

}// namespace jhetz::ldap::net::detail
