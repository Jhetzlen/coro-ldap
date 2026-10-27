// Internal: host names as compared by referral chasing (loop detection,
// make_same_policy_connector's allow-list and connection reuse).
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap::net::detail {

// The ASCII form of a host name, for comparisons: one trailing dot dropped,
// then ASCII letters lowered. A name with non-ASCII characters (an
// internationalized domain name) is converted first as RFC 4513 section
// 3.1.3.1 asks before a comparison: IDNA ToASCII with UseSTD3ASCIIRules
// (ICU's UTS #46 transitional processing, the IDNA2003-compatible mapping,
// which also folds case and normalizes); nullopt if that fails (a label ICU
// reports an error for). An all-ASCII name is not checked against STD3
// (internal names with '_' stay usable). IP literals pass through lowered.
[[nodiscard]] auto ascii_host_name(std::string_view host) -> std::optional<std::string>;

// No octet of `s` is outside ASCII.
[[nodiscard]] auto is_ascii(std::string_view s) noexcept -> bool;

}// namespace jhetz::ldap::net::detail
