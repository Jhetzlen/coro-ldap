#include "jhetz/ldap/attribute.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <random>
#include <ranges>

namespace jhetz::ldap {

auto attribute_description::parse(std::string_view text, std::pmr::memory_resource *mr) -> result<attribute_description>
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

auto operator<=>(const attribute_description &a, const attribute_description &b) noexcept -> std::weak_ordering
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

	// The bytes of s packed little-endian when shorter than 8, else its last 8
	// (overlapping the previous word).
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

	// Two multiply / xor-shift rounds (moremur multipliers).
	constexpr std::uint64_t mix_multiplier_1 = 0x9E37'79B9'7F4A'7C15ull;
	constexpr std::uint64_t mix_multiplier_2 = 0xD6E8'FEB8'6659'FD93ull;
	// MurmurHash3's fmix64: its first multiplier and its shift.
	constexpr std::uint64_t finish_multiplier = 0xFF51'AFD7'ED55'8CCDull;
	constexpr unsigned finish_shift = 33;

	constexpr auto mix(std::uint64_t h, std::uint64_t w) noexcept -> std::uint64_t
	{
		h = (h ^ w) * mix_multiplier_1;
		h ^= h >> 32;
		h *= mix_multiplier_2;
		return h ^ (h >> 32);
	}

	// The hash's starting state, random per process.
	auto make_seed() noexcept -> std::uint64_t
	{
		try {
			std::random_device random;
			return (std::uint64_t{ random() } << 32) ^ random();
		} catch (const std::exception &) {
			// No random device: the clock and an address.
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
	// The length is mixed in after the data.
	h ^= n;
	h *= finish_multiplier;
	return static_cast<std::size_t>(h ^ (h >> finish_shift));
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

	namespace {

		// Whether every ';'-separated option of `options` is one of `among`,
		// case-insensitively.
		auto options_within(std::string_view options, std::string_view among) noexcept -> bool
		{
			return std::ranges::all_of(std::views::split(options, ';'), [&](const auto option) {
				const std::string_view o(option.begin(), option.end());
				return std::ranges::any_of(std::views::split(among, ';'), [&](const auto candidate) {
					return iequals(std::string_view(candidate.begin(), candidate.end()), o);
				});
			});
		}

	}// namespace

	auto same_description(std::string_view a, std::string_view b) noexcept -> bool
	{
		if (iequals_fast(a, b)) {
			return true;
		}
		const std::size_t a_semi = a.find(';');
		const std::size_t b_semi = b.find(';');
		if (a_semi == std::string_view::npos || b_semi == std::string_view::npos
			|| !iequals(a.substr(0, a_semi), b.substr(0, b_semi))) {
			return false;
		}
		const std::string_view a_options = a.substr(a_semi + 1);
		const std::string_view b_options = b.substr(b_semi + 1);
		return options_within(a_options, b_options) && options_within(b_options, a_options);
	}

	auto has_description_options(std::string_view description, std::string_view base) noexcept -> bool
	{
		const std::size_t semi = description.find(';');
		const std::size_t base_semi = base.find(';');
		if (!iequals(description.substr(0, semi), base.substr(0, base_semi))) {
			return false;
		}
		if (base_semi == std::string_view::npos) {
			return true;
		}
		return semi != std::string_view::npos
			   && options_within(base.substr(base_semi + 1), description.substr(semi + 1));
	}

	auto icu_utf8_sequence_length(std::string_view s, std::size_t i) noexcept -> std::size_t
	{
		const utf8_step step = utf8_next(s, i);
		return step.code_point < 0 ? 0 : step.length;
	}

	auto invalid_utf8_offset(std::string_view s) noexcept -> std::size_t
	{
		constexpr std::uint64_t high_bits = 0x8080'8080'8080'8080ull;
		constexpr std::size_t word = 8;
		const std::size_t n = s.size();
		std::size_t i = 0;
		// An eight-octet ASCII block is tried at the start and after an ASCII octet.
		bool ascii = true;
		while (i < n) {
			if (ascii && i + word <= n && (load8(s.data() + i) & high_bits) == 0) {
				i += word;
				continue;
			}
			const utf8_step step = utf8_next(s, i);
			if (step.code_point < 0) {
				return i;
			}
			i += step.length;
			ascii = step.length == 1;
		}
		return std::string_view::npos;
	}

}// namespace detail

}// namespace jhetz::ldap
