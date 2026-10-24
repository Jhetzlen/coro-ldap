#include "jhetz/ldap/attribute.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <random>

namespace jhetz::ldap {

auto attribute::parse(std::string_view text, std::pmr::memory_resource *mr) -> result<attribute>
{
	if (!detail::is_attribute_description(text)) {
		// The text may be a value a server sent.
		std::string context = "attribute: \"";
		detail::append_sanitized(context, text, 64);
		context += "\" is not an attribute description";
		return fail(client_errc::invalid_attribute, context);
	}
	return unchecked(text, mr);
}

auto operator<=>(const attribute &a, const attribute &b) noexcept -> std::weak_ordering
{
	const std::string_view x = a.name_;
	const std::string_view y = b.name_;
	const std::size_t n = std::min(x.size(), y.size());
	for (std::size_t i = 0; i < n; ++i) {
		const auto cx = static_cast<unsigned char>(detail::ascii_lower(x[i]));
		const auto cy = static_cast<unsigned char>(detail::ascii_lower(y[i]));
		if (cx != cy) {
			return cx < cy ? std::weak_ordering::less : std::weak_ordering::greater;
		}
	}
	return x.size() <=> y.size();
}

namespace {

	// The bytes 'A'-'Z' of w lower-cased, all others (bytes >= 0x80
	// included) unchanged: ascii_lower on 8 bytes at once.
	constexpr auto ascii_lower8(std::uint64_t w) noexcept -> std::uint64_t
	{
		constexpr std::uint64_t ones = 0x0101'0101'0101'0101ull;
		const std::uint64_t low7 = w & (0x7F * ones);
		const std::uint64_t ge_a = low7 + ((0x80 - 'A') * ones);// bit 7 set where low7 >= 'A'
		const std::uint64_t gt_z = low7 + ((0x7F - 'Z') * ones);// bit 7 set where low7 > 'Z'
		const std::uint64_t upper = ge_a & ~gt_z & ~w & (0x80 * ones);
		return w | (upper >> 2);// 0x80 >> 2 == 'a' - 'A'
	}

	auto load8(const char *p) noexcept -> std::uint64_t
	{
		std::uint64_t w{};
		std::memcpy(&w, p, 8);
		return w;
	}

	// The bytes of s packed little-endian when it is shorter than 8, else its
	// last 8 (overlapping the previous word). On big-endian the two paths
	// pack differently, but each is self-consistent, so equal strings still
	// hash equally; hash_value mixes in the length to separate strings that
	// only differ by trailing zero bytes ("a" / "a\0").
	auto tail8(std::string_view s) noexcept -> std::uint64_t
	{
		if (s.size() >= 8) {
			return load8(s.data() + s.size() - 8);
		}
		std::uint64_t w = 0;
		for (std::size_t i = 0; i < s.size(); ++i) {
			w |= std::uint64_t{ static_cast<unsigned char>(s[i]) } << (8 * i);
		}
		return w;
	}

	// Two multiply / xor-shift rounds: one alone cannot carry a difference
	// in a word's high bytes down past the next word, so OIDs differing
	// only there ("1.3.6.1.4.1.0.14.1.8" / "...0.18.1.4") collided in all
	// 64 bits. Portable (no 128-bit product).
	constexpr auto mix(std::uint64_t h, std::uint64_t w) noexcept -> std::uint64_t
	{
		h = (h ^ w) * 0x9E37'79B9'7F4A'7C15ull;
		h ^= h >> 32;
		h *= 0xD6E8'FEB8'6659'FD93ull;
		return h ^ (h >> 32);
	}

	// The hash's starting state, random per process. The rounds above are
	// invertible, so with a fixed start anyone can compute names that
	// collide in all 64 bits, and a server sending them makes the
	// unordered containers keyed by its names (entry::from, schema name
	// indexes) quadratic. Not knowing the start, it cannot.
	auto make_seed() noexcept -> std::uint64_t
	{
		try {
			std::random_device random;
			return (std::uint64_t{ random() } << 32) ^ random();
		} catch (const std::exception &) {
			// No random device: the clock and an address (ASLR), weaker
			// but not fixed.
			const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
			return mix(static_cast<std::uint64_t>(now), reinterpret_cast<std::uintptr_t>(&now));
		}
	}

}// namespace

auto hash_value(std::string_view attribute_name) noexcept -> std::size_t
{
	static const std::uint64_t seed = make_seed();
	// Eight lower-cased bytes at a time (names and OIDs are often longer
	// than a byte-wise hash is fast for).
	const std::size_t n = attribute_name.size();
	std::uint64_t h = seed;
	std::size_t i = 0;
	for (; i + 8 <= n; i += 8) {
		h = mix(h, ascii_lower8(load8(attribute_name.data() + i)));
	}
	if (i != n) {
		h = mix(h, ascii_lower8(tail8(attribute_name)));
	}
	// The length goes in after the data: XORed into the seed it landed in
	// the same bits as the first word, so "1.1.1.1.1" and "3.1.1.1.1.1"
	// collided in all 64 bits.
	h ^= n;
	h *= 0xFF51'AFD7'ED55'8CCDull;
	return static_cast<std::size_t>(h ^ (h >> 33));
}

namespace detail {

	auto iequals_fast(std::string_view a, std::string_view b) noexcept -> bool
	{
		const std::size_t n = a.size();
		if (n != b.size()) {
			return false;
		}
		const auto same = [](std::uint64_t x, std::uint64_t y) { return x == y || ascii_lower8(x) == ascii_lower8(y); };
		std::size_t i = 0;
		for (; i + 8 <= n; i += 8) {
			if (!same(load8(a.data() + i), load8(b.data() + i))) {
				return false;
			}
		}
		return i == n || same(tail8(a), tail8(b));
	}

	auto icu_utf8_sequence_length(std::string_view s, std::size_t i) noexcept -> std::size_t
	{
		const utf8_step step = utf8_next(s, i);
		return step.code_point < 0 ? 0 : step.length;
	}

}// namespace detail

}// namespace jhetz::ldap
