// Internal: the GeneralizedTime parser (RFC 4517 section 3.3.13) shared by
// the struct mapping (parse_generalized_time, mapping.cpp) and the
// generalizedTime matching rules (matching.cpp).
#pragma once

#include <chrono>
#include <expected>
#include <optional>
#include <string_view>

namespace jhetz::ldap::detail {

// A GeneralizedTime's fields as written, checked against the ABNF and the
// calendar (February 31 is refused, as section 3.3.13 recommends).
struct generalized_time_fields
{
	std::chrono::year_month_day date{};
	int hour = 0;
	std::optional<int> minute{};
	std::optional<int> second{};// 0 to 60 (60: a leap second)
	// The fraction's digits (after "." or ","), of the last unit given:
	// hour, minute or second. Empty if there is none.
	std::string_view fraction{};
	// The g-differential: local time minus UTC ("Z" is 0).
	std::chrono::minutes offset{ 0 };
};

// The fields of `text` (views into it); the error is the reason, for a
// diagnostic.
[[nodiscard]] auto parse_generalized_time_fields(std::string_view text)
  -> std::expected<generalized_time_fields, const char *>;

}// namespace jhetz::ldap::detail
