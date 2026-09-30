#include "jhetz/ldap/attribute.hpp"

#include <algorithm>
#include <cstdint>

namespace jhetz::ldap {

result<attribute> attribute::parse(std::string_view text, std::pmr::memory_resource *mr)
{
	if (!detail::is_attribute_description(text))
		return fail(
		  client_errc::invalid_attribute, "attribute: \"" + std::string(text) + "\" is not an attribute description");
	return unchecked(text, mr);
}

std::weak_ordering operator<=>(const attribute &a, const attribute &b) noexcept
{
	const std::string_view x = a.name_;
	const std::string_view y = b.name_;
	const std::size_t n = std::min(x.size(), y.size());
	for (std::size_t i = 0; i < n; ++i) {
		const auto cx = static_cast<unsigned char>(detail::ascii_lower(x[i]));
		const auto cy = static_cast<unsigned char>(detail::ascii_lower(y[i]));
		if (cx != cy) return cx < cy ? std::weak_ordering::less : std::weak_ordering::greater;
	}
	return x.size() <=> y.size();
}

std::size_t hash_value(std::string_view attribute_name) noexcept
{
	// FNV-1a over the lower-cased bytes.
	std::uint64_t h = 0xCBF2'9CE4'8422'2325ull;
	for (char c : attribute_name) {
		h ^= static_cast<unsigned char>(detail::ascii_lower(c));
		h *= 0x0000'0100'0000'01B3ull;
	}
	return static_cast<std::size_t>(h);
}

}// namespace jhetz::ldap
