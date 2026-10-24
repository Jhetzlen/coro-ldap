// Attribute descriptions (RFC 4512 section 2.5), DESIGN.md section 1.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <functional>
#include <memory_resource>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

namespace detail {

	constexpr auto is_alpha(char c) noexcept -> bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
	constexpr auto is_digit(char c) noexcept -> bool { return c >= '0' && c <= '9'; }
	constexpr auto is_keychar(char c) noexcept -> bool { return is_alpha(c) || is_digit(c) || c == '-'; }
	constexpr auto ascii_lower(char c) noexcept -> char
	{
		return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
	}

	constexpr auto is_hex(char c) noexcept -> bool
	{
		return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	}

	// The value of the hex digits 'a' and 'A'.
	inline constexpr int hex_letter_value = 10;

	constexpr auto hex_value(char c) noexcept -> unsigned
	{
		if (is_digit(c)) {
			return static_cast<unsigned>(c - '0');
		}
		if (c >= 'a' && c <= 'f') {
			return static_cast<unsigned>(c - 'a' + hex_letter_value);
		}
		return static_cast<unsigned>(c - 'A' + hex_letter_value);
	}

	constexpr auto iequals(std::string_view a, std::string_view b) noexcept -> bool
	{
		if (a.size() != b.size()) {
			return false;
		}
		for (std::size_t i = 0; i < a.size(); ++i) {
			if (ascii_lower(a[i]) != ascii_lower(b[i])) {
				return false;
			}
		}
		return true;
	}

	// Length of the well-formed UTF-8 sequence starting at s[i] (RFC 3629;
	// RFC 4512 UTF1 / UTFMB: no overlong forms, surrogates or code points
	// above U+10FFFF), or 0 if there is none. Precondition: i < s.size().
	// Defined in src/attribute.cpp with ICU (U8_NEXT).
	auto icu_utf8_sequence_length(std::string_view s, std::size_t i) noexcept -> std::size_t;

	// Offset of the first octet of s that does not start a well-formed UTF-8
	// sequence (the same rule as icu_utf8_sequence_length), or
	// std::string_view::npos if all of s is well-formed. ASCII runs are
	// skipped eight octets at a time (tried at the start and after an ASCII
	// octet). Defined in src/attribute.cpp with ICU.
	auto invalid_utf8_offset(std::string_view s) noexcept -> std::size_t;

	inline auto is_valid_utf8(std::string_view s) noexcept -> bool
	{
		return invalid_utf8_offset(s) == std::string_view::npos;
	}

	// Well-formed UTF-8 (Unicode section 3.9, table 3-7): an octet below
	// 0x80 stands alone; a lead octet in [lead_first, lead_last] starts a
	// sequence of `length` octets whose second is in [second_first,
	// second_last] (excluding overlongs, surrogates and code points above
	// U+10FFFF) and whose others are continuation octets.
	inline constexpr unsigned char utf8_continuation_first = 0x80u;
	inline constexpr unsigned char utf8_continuation_last = 0xBFu;
	struct utf8_lead_range
	{
		unsigned char lead_first = 0;
		unsigned char lead_last = 0;
		std::size_t length = 0;
		unsigned char second_first = 0;
		unsigned char second_last = 0;
	};
	inline constexpr std::array utf8_lead_ranges{
		utf8_lead_range{ .lead_first = 0xC2u,
		  .lead_last = 0xDFu,
		  .length = 2,
		  .second_first = 0x80u,
		  .second_last = 0xBFu },
		utf8_lead_range{ .lead_first = 0xE0u,
		  .lead_last = 0xE0u,
		  .length = 3,
		  .second_first = 0xA0u,
		  .second_last = 0xBFu },
		utf8_lead_range{ .lead_first = 0xE1u,
		  .lead_last = 0xECu,
		  .length = 3,
		  .second_first = 0x80u,
		  .second_last = 0xBFu },
		utf8_lead_range{ .lead_first = 0xEDu,
		  .lead_last = 0xEDu,
		  .length = 3,
		  .second_first = 0x80u,
		  .second_last = 0x9Fu },
		utf8_lead_range{ .lead_first = 0xEEu,
		  .lead_last = 0xEFu,
		  .length = 3,
		  .second_first = 0x80u,
		  .second_last = 0xBFu },
		utf8_lead_range{ .lead_first = 0xF0u,
		  .lead_last = 0xF0u,
		  .length = 4,
		  .second_first = 0x90u,
		  .second_last = 0xBFu },
		utf8_lead_range{ .lead_first = 0xF1u,
		  .lead_last = 0xF3u,
		  .length = 4,
		  .second_first = 0x80u,
		  .second_last = 0xBFu },
		utf8_lead_range{ .lead_first = 0xF4u,
		  .lead_last = 0xF4u,
		  .length = 4,
		  .second_first = 0x80u,
		  .second_last = 0x8Fu },
	};

	// The same check, hand-rolled, for compile time only: utf8_sequence_length
	// uses it in constant evaluation (the consteval ldap::dn / ldap::rdn /
	// attribute literals go through detail::scan_dn), where ICU's functions
	// cannot run. ICU's U8_NEXT macro would be constexpr-friendly but needs
	// <unicode/utf8.h>, which the public headers do not include (ICU is a
	// private dependency of jhetz::ldap). Its answers match ICU's for every
	// input (tests/attribute_tests.cpp, "utf8_sequence_length").
	constexpr auto constexpr_utf8_sequence_length(std::string_view s, std::size_t i) noexcept -> std::size_t
	{
		const auto at = [&](std::size_t k) { return static_cast<unsigned char>(s[i + k]); };
		const unsigned char c = at(0);
		if (c < utf8_continuation_first) {
			return 1;
		}
		for (const auto &r : utf8_lead_ranges) {
			if (c < r.lead_first || c > r.lead_last) {
				continue;
			}
			if (s.size() - i < r.length || at(1) < r.second_first || at(1) > r.second_last) {
				return 0;
			}
			for (std::size_t k = 2; k < r.length; ++k) {
				if (at(k) < utf8_continuation_first || at(k) > utf8_continuation_last) {
					return 0;
				}
			}
			return r.length;
		}
		return 0;
	}

	// Length of the well-formed UTF-8 sequence starting at s[i], or 0 if
	// there is none: ICU at run time, the hand-rolled check above in constant
	// evaluation. Precondition: i < s.size().
	constexpr auto utf8_sequence_length(std::string_view s, std::size_t i) noexcept -> std::size_t
	{
		if consteval {
			return constexpr_utf8_sequence_length(s, i);
		}
		return icu_utf8_sequence_length(s, i);
	}

	// descr = keystring = ALPHA *(ALPHA / DIGIT / HYPHEN)
	constexpr auto is_descr(std::string_view s) noexcept -> bool
	{
		if (s.empty() || !is_alpha(s[0])) {
			return false;
		}
		return std::ranges::all_of(s, is_keychar);
	}

	// numericoid = number 1*( DOT number ); number = DIGIT / ( LDIGIT 1*DIGIT )
	// (no leading zeros).
	constexpr auto is_numericoid(std::string_view s) noexcept -> bool
	{
		std::size_t parts = 0;
		std::size_t i = 0;
		while (true) {
			const std::size_t start = i;
			while (i < s.size() && is_digit(s[i])) {
				++i;
			}
			if (i == start) {
				return false;
			}
			if (s[start] == '0' && i - start > 1) {
				return false;
			}
			++parts;
			if (i == s.size()) {
				break;
			}
			if (s[i] != '.') {
				return false;
			}
			++i;
		}
		return parts >= 2;
	}

	// oid = descr / numericoid (RFC 4512 section 1.4)
	constexpr auto is_oid(std::string_view s) noexcept -> bool { return is_descr(s) || is_numericoid(s); }

	// attributedescription = attributetype options; options = *( SEMI option );
	// option = 1*keychar
	constexpr auto is_attribute_description(std::string_view s) noexcept -> bool
	{
		const std::size_t semi = s.find(';');
		if (!is_oid(s.substr(0, semi))) {
			return false;
		}
		if (semi == std::string_view::npos) {
			return true;
		}
		std::size_t i = semi;
		while (i < s.size()) {
			++i;// skip ';'
			const std::size_t start = i;
			while (i < s.size() && is_keychar(s[i])) {
				++i;
			}
			if (i == start) {
				return false;
			}
			if (i < s.size() && s[i] != ';') {
				return false;
			}
		}
		return true;
	}

}// namespace detail

// An attribute description such as `cn`, `2.5.4.3` or `userCertificate;binary`.
// Equality, ordering and hashing ignore ASCII case (RFC 4512: descriptors and
// options are case-insensitive); the original spelling is kept for output.
//
// Built three ways:
// - from a string literal, checked at compile time: `ldap::attribute a{"mail"};`
//   (a runtime `const char*` does not compile; use parse());
// - `attribute::parse(text)` for runtime text, returning invalid_attribute on
//   failure;
// - `attribute::unchecked(text)` for names received from a server, which are
//   kept as sent (Active Directory, for one, sends `member;range=0-1499`,
//   which is not RFC 4512 syntax). Only use it for data that is not going
//   back into a request unvalidated.
//
// Memory: allocator-aware (std::pmr); the name is allocated from the resource
// given to the constructor, parse() or unchecked(). A plain copy uses the
// default resource, assignment keeps the target's resource.
class attribute
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// Compile-time checked literal (consteval: invalid text fails to compile).
	struct literal
	{
		// Implicit on purpose: `"..."` converts to the literal, checked at compile time.
		// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_attribute_description(s)) {
				// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
				throw "ldap::attribute: invalid attribute description";
			}
		}
		const char *text;
	};

	attribute() = default;
	explicit attribute(const allocator_type &alloc) : name_(alloc) {}
	explicit attribute(literal l, const allocator_type &alloc = {}) : name_(l.text, alloc) {}
	attribute(const attribute &) = default;
	attribute(attribute &&) noexcept = default;
	attribute(const attribute &other, const allocator_type &alloc) : name_(other.name_, alloc) {}
	attribute(attribute &&other, const allocator_type &alloc) : name_(std::move(other.name_), alloc) {}
	auto operator=(const attribute &) -> attribute & = default;
	auto operator=(attribute &&) -> attribute & = default;
	~attribute() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return name_.get_allocator(); }

	[[nodiscard]] static auto parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<attribute>;
	[[nodiscard]] static auto unchecked(std::string_view text, const allocator_type &alloc = {}) -> attribute
	{
		attribute a(alloc);
		a.name_.assign(text);
		return a;
	}
	[[nodiscard]] static auto unchecked(const char *text, const allocator_type &alloc = {}) -> attribute
	{
		return unchecked(std::string_view(text), alloc);
	}
	// Takes the string, with its resource.
	[[nodiscard]] static auto unchecked(std::pmr::string &&text) noexcept -> attribute
	{
		return attribute(std::move(text), adopt{});
	}

	[[nodiscard]] auto name() const noexcept -> const std::pmr::string & { return name_; }
	[[nodiscard]] auto empty() const noexcept -> bool { return name_.empty(); }

	friend auto operator==(const attribute &a, const attribute &b) noexcept -> bool
	{
		return detail::iequals(a.name_, b.name_);
	}
	friend auto operator<=>(const attribute &a, const attribute &b) noexcept -> std::weak_ordering;

  private:
	struct adopt
	{
	};
	attribute(std::pmr::string &&name, adopt) noexcept : name_(std::move(name)) {}

	std::pmr::string name_{};
};

// Case-insensitive hash, consistent with operator==. Seeded at random per
// process, so a server cannot craft names that collide: values differ from
// one run to the next and must not be stored or sent anywhere.
[[nodiscard]] auto hash_value(std::string_view attribute_name) noexcept -> std::size_t;

namespace detail {

	// iequals, 8 bytes at a time (not constexpr).
	auto iequals_fast(std::string_view a, std::string_view b) noexcept -> bool;

	// Hash and equality for unordered containers keyed by names that compare
	// case-insensitively (A-Z only, as iequals and hash_value: other bytes as
	// they are). Transparent, so a std::string-keyed container is searched
	// with a std::string_view, without a copy.
	struct ci_hash
	{
		using is_transparent = void;
		// Never throws, but deliberately not noexcept: libstdc++ then caches
		// the hash code in each node, as it does for std::hash<std::string>.
		// Without it, a find hashes the key of every node it walks past (to
		// see where the bucket ends): measured about 10% slower lookups.
		auto operator()(std::string_view s) const -> std::size_t { return hash_value(s); }
	};
	struct ci_equal
	{
		using is_transparent = void;
		auto operator()(std::string_view a, std::string_view b) const noexcept -> bool { return iequals_fast(a, b); }
	};

}// namespace detail

}// namespace jhetz::ldap

template<> struct std::hash<jhetz::ldap::attribute>
{
	auto operator()(const jhetz::ldap::attribute &a) const noexcept -> std::size_t
	{
		return jhetz::ldap::hash_value(a.name());
	}
};
