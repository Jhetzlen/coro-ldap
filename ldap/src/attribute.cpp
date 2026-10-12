#include "jhetz/ldap/attribute.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>

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

namespace {

	// The bytes 'A'-'Z' of w lower-cased, all others (bytes >= 0x80
	// included) unchanged: ascii_lower on 8 bytes at once.
	constexpr std::uint64_t ascii_lower8(std::uint64_t w) noexcept
	{
		constexpr std::uint64_t ones = 0x0101'0101'0101'0101ull;
		const std::uint64_t low7 = w & (0x7F * ones);
		const std::uint64_t ge_a = low7 + (0x80 - 'A') * ones;// bit 7 set where low7 >= 'A'
		const std::uint64_t gt_z = low7 + (0x7F - 'Z') * ones;// bit 7 set where low7 > 'Z'
		const std::uint64_t upper = ge_a & ~gt_z & ~w & (0x80 * ones);
		return w | (upper >> 2);// 0x80 >> 2 == 'a' - 'A'
	}

	std::uint64_t load8(const char *p) noexcept
	{
		std::uint64_t w;
		std::memcpy(&w, p, 8);
		return w;
	}

	// The last s.size() % 8 bytes of s as a word (0 if none); when s has at
	// least 8 bytes, its last 8 (overlapping the previous word).
	std::uint64_t tail8(std::string_view s) noexcept
	{
		if (s.size() >= 8) return load8(s.data() + s.size() - 8);
		std::uint64_t w = 0;
		for (std::size_t i = 0; i < s.size(); ++i) w |= std::uint64_t{ static_cast<unsigned char>(s[i]) } << (8 * i);
		return w;
	}

	constexpr std::uint64_t mix(std::uint64_t h, std::uint64_t w) noexcept
	{
		h = (h ^ w) * 0x9E37'79B9'7F4A'7C15ull;
		return h ^ (h >> 32);
	}

}// namespace

std::size_t hash_value(std::string_view attribute_name) noexcept
{
	// Eight lower-cased bytes at a time (names and OIDs are often longer
	// than a byte-wise hash is fast for).
	const std::size_t n = attribute_name.size();
	std::uint64_t h = 0xCBF2'9CE4'8422'2325ull ^ n;
	std::size_t i = 0;
	for (; i + 8 <= n; i += 8) h = mix(h, ascii_lower8(load8(attribute_name.data() + i)));
	if (i != n) h = mix(h, ascii_lower8(tail8(attribute_name)));
	h *= 0xFF51'AFD7'ED55'8CCDull;
	return static_cast<std::size_t>(h ^ (h >> 33));
}

namespace detail {

	bool iequals_fast(std::string_view a, std::string_view b) noexcept
	{
		const std::size_t n = a.size();
		if (n != b.size()) return false;
		const auto same = [](std::uint64_t x, std::uint64_t y) { return x == y || ascii_lower8(x) == ascii_lower8(y); };
		std::size_t i = 0;
		for (; i + 8 <= n; i += 8)
			if (!same(load8(a.data() + i), load8(b.data() + i))) return false;
		return i == n || same(tail8(a), tail8(b));
	}

}// namespace detail

}// namespace jhetz::ldap
