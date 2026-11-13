// Active Directory's range option of an attribute description (MS-ADTS
// 3.1.1.3.1.3.3): `member;range=1500-2999`, `member;range=1500-*`.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap::ad {

// Indices from 0, both included; `high` nullopt is "*".
struct value_range
{
	std::uint32_t low = 0;
	std::optional<std::uint32_t> high{};

	friend auto operator==(const value_range &, const value_range &) -> bool = default;
};

// `type` is the description without the range option.
struct ranged_description
{
	std::string type;
	value_range range;

	friend auto operator==(const ranged_description &, const ranged_description &) -> bool = default;
};

// nullopt without a range option; decode_error for a malformed one, two of
// them, or an empty type.
[[nodiscard]] auto parse_range(std::string_view description) -> result<std::optional<ranged_description>>;

// "type;range=low-high" or "type;range=low-*".
[[nodiscard]] auto with_range(std::string_view type, value_range range) -> std::string;

}// namespace jhetz::ldap::ad
