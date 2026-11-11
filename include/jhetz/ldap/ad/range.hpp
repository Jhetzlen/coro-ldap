// Active Directory's range option of an attribute description
// (MS-ADTS 3.1.1.3.1.3.3, "range=<low>-<high>"), which ranged retrieval of
// large multi-valued attributes uses: a request for `member;range=1500-*`
// is answered with `member;range=1500-2999`, or `member;range=1500-*` for
// the last values. ad/ranged_values.hpp follows the ranges.
//
//   auto r = ldap::ad::parse_range("member;range=0-1499");   // {"member", {0, 1499}}
//   ldap::ad::with_range("member", {.low = 1500});           // "member;range=1500-*"
#pragma once

#include "jhetz/ldap/error.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap::ad {

// The values from index `low` to `high`, both included, counted from 0;
// `high` nullopt is "*": up to the last value.
struct value_range
{
	std::uint32_t low = 0;
	std::optional<std::uint32_t> high{};

	friend auto operator==(const value_range &, const value_range &) -> bool = default;
};

// An attribute description with a range option, split: `type` is the
// description without the option (its other options kept in order).
struct ranged_description
{
	std::string type;
	value_range range;

	friend auto operator==(const ranged_description &, const ranged_description &) -> bool = default;
};

// Splits `description` at its range option (the option name compared
// case-insensitively). nullopt for a description without one. Fails with
// client_errc::decode_error for a malformed range ("range=" not followed
// by decimal digits, '-' and decimal digits or '*'; a bound above
// 2^32 - 1; `high` below `low`), for two range options, and for an empty
// attribute type.
[[nodiscard]] auto parse_range(std::string_view description) -> result<std::optional<ranged_description>>;

// `type` with the range option appended: "type;range=low-high" or
// "type;range=low-*".
[[nodiscard]] auto with_range(std::string_view type, value_range range) -> std::string;

}// namespace jhetz::ldap::ad
