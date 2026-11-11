#include "jhetz/ldap/ad/range.hpp"

#include "../format_util.hpp"

#include "jhetz/ldap/attribute.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace jhetz::ldap::ad {

namespace {

	constexpr std::string_view range_prefix = "range=";
	constexpr std::size_t max_quoted = 128;

	auto bad(std::string_view description, const char *why) -> std::unexpected<error>
	{
		std::string context = "range option of ";
		detail::append_sanitized(context, description, max_quoted);
		context += ": ";
		context += why;
		return fail(client_errc::decode_error, context);
	}

	// A bound: one or more decimal digits, at most 2^32 - 1.
	auto read_bound(std::string_view digits) -> std::optional<std::uint32_t>
	{
		if (digits.empty() || !std::ranges::all_of(digits, detail::is_digit)) {
			return std::nullopt;
		}
		std::uint32_t v = 0;
		const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), v);
		if (ec != std::errc{} || end != digits.data() + digits.size()) {
			return std::nullopt;
		}
		return v;
	}

	auto is_range_option(std::string_view option) -> bool
	{
		return option.size() >= range_prefix.size()
			   && detail::iequals(option.substr(0, range_prefix.size()), range_prefix);
	}

}// namespace

auto parse_range(std::string_view description) -> result<std::optional<ranged_description>>
{
	std::optional<value_range> range;
	std::string type;
	std::size_t start = 0;
	bool first = true;
	while (true) {
		const std::size_t semi = description.find(';', start);
		const std::string_view part = description.substr(start, semi == std::string_view::npos ? semi : semi - start);
		if (!first && is_range_option(part)) {
			if (range) {
				return bad(description, "two range options");
			}
			const std::string_view bounds = part.substr(range_prefix.size());
			const std::size_t dash = bounds.find('-');
			if (dash == std::string_view::npos) {
				return bad(description, "no '-' between the bounds");
			}
			const auto low = read_bound(bounds.substr(0, dash));
			if (!low) {
				return bad(description, "the low bound is not a 32-bit decimal number");
			}
			const std::string_view high_text = bounds.substr(dash + 1);
			value_range r{ .low = *low };
			if (high_text != "*") {
				const auto high = read_bound(high_text);
				if (!high) {
					return bad(description, "the high bound is neither '*' nor a 32-bit decimal number");
				}
				if (*high < *low) {
					return bad(description, "the high bound is below the low bound");
				}
				r.high = high;
			}
			range = r;
		} else {
			if (!first) {
				type += ';';
			}
			type += part;
		}
		first = false;
		if (semi == std::string_view::npos) {
			break;
		}
		start = semi + 1;
	}
	if (!range) {
		return std::optional<ranged_description>{};
	}
	if (type.empty()) {
		return bad(description, "no attribute type");
	}
	return ranged_description{ .type = std::move(type), .range = *range };
}

auto with_range(std::string_view type, value_range range) -> std::string
{
	std::string out(type);
	out += ';';
	out += range_prefix;
	out += std::to_string(range.low);
	out += '-';
	out += range.high ? std::to_string(*range.high) : std::string("*");
	return out;
}

}// namespace jhetz::ldap::ad
