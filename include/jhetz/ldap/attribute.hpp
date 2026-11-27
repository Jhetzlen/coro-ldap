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

	constexpr auto hex_value(char c) noexcept -> unsigned
	{
		if (is_digit(c)) {
			return static_cast<unsigned>(c - '0');
		}
		if (c >= 'a' && c <= 'f') {
			return static_cast<unsigned>(c - 'a' + 10);
		}
		return static_cast<unsigned>(c - 'A' + 10);
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

	// Length of the well-formed UTF-8 sequence at s[i], or 0. ICU, in
	// src/attribute.cpp.
	auto icu_utf8_sequence_length(std::string_view s, std::size_t i) noexcept -> std::size_t;

	// Offset of the first octet not starting a well-formed UTF-8 sequence, or
	// npos.
	auto invalid_utf8_offset(std::string_view s) noexcept -> std::size_t;

	inline auto is_valid_utf8(std::string_view s) noexcept -> bool
	{
		return invalid_utf8_offset(s) == std::string_view::npos;
	}

	// Well-formed UTF-8 (Unicode section 3.9, table 3-7).
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

	// The same check for constant evaluation, where ICU cannot run; it matches
	// ICU's answers.
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

	// ICU at run time, the hand-rolled check in constant evaluation.
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

	// numericoid = number 1*( DOT number ), no leading zeros
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

	// attributedescription = attributetype options
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

// An attribute description such as `cn` or `userCertificate;binary`;
// compared case-insensitively, spelling kept.
class attribute_description
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// Compile-time checked literal.
	struct literal
	{
		// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_attribute_description(s)) {
				// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
				throw "ldap::attribute_description: invalid attribute description";
			}
		}
		const char *text;
	};

	attribute_description() = default;
	explicit attribute_description(const allocator_type &alloc) : name_(alloc) {}
	explicit attribute_description(literal l, const allocator_type &alloc = {}) : name_(l.text, alloc) {}
	attribute_description(const attribute_description &) = default;
	attribute_description(attribute_description &&) noexcept = default;
	attribute_description(const attribute_description &other, const allocator_type &alloc) : name_(other.name_, alloc)
	{}
	attribute_description(attribute_description &&other, const allocator_type &alloc)
	  : name_(std::move(other.name_), alloc)
	{}
	auto operator=(const attribute_description &) -> attribute_description & = default;
	auto operator=(attribute_description &&) -> attribute_description & = default;
	~attribute_description() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return name_.get_allocator(); }

	[[nodiscard]] static auto parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<attribute_description>;
	[[nodiscard]] static auto unchecked(std::string_view text, const allocator_type &alloc = {})
	  -> attribute_description
	{
		attribute_description a(alloc);
		a.name_.assign(text);
		return a;
	}
	[[nodiscard]] static auto unchecked(const char *text, const allocator_type &alloc = {}) -> attribute_description
	{
		return unchecked(std::string_view(text), alloc);
	}
	// Takes the string, with its resource.
	[[nodiscard]] static auto unchecked(std::pmr::string &&text) noexcept -> attribute_description
	{
		return attribute_description(std::move(text), adopt{});
	}

	// The whole description as given: "cn;lang-de".
	[[nodiscard]] auto text() const noexcept -> const std::pmr::string & { return name_; }
	// The attribute type, without options: "cn" for "cn;lang-de", as spelled.
	[[nodiscard]] auto name() const noexcept -> std::string_view
	{
		const std::string_view t = name_;
		return t.substr(0, t.find(';'));
	}
	[[nodiscard]] auto empty() const noexcept -> bool { return name_.empty(); }

	friend auto operator==(const attribute_description &a, const attribute_description &b) noexcept -> bool
	{
		return detail::iequals(a.name_, b.name_);
	}
	friend auto operator<=>(const attribute_description &a, const attribute_description &b) noexcept
	  -> std::weak_ordering;

  private:
	struct adopt
	{
	};
	attribute_description(std::pmr::string &&name, adopt) noexcept : name_(std::move(name)) {}

	std::pmr::string name_{};
};

// Case-insensitive hash, seeded per process.
[[nodiscard]] auto hash_value(std::string_view attribute_name) noexcept -> std::size_t;

namespace detail {

	auto iequals_fast(std::string_view a, std::string_view b) noexcept -> bool;

	// The same type and set of options (RFC 4512 section 2.5).
	auto same_description(std::string_view a, std::string_view b) noexcept -> bool;

	// `description` holds `base`'s type and at least its options.
	auto has_description_options(std::string_view description, std::string_view base) noexcept -> bool;

	// Transparent case-insensitive (A-Z) hash and equality.
	struct ci_hash
	{
		using is_transparent = void;
		// Not noexcept so libstdc++ caches the hash code in each node.
		auto operator()(std::string_view s) const -> std::size_t { return hash_value(s); }
	};
	struct ci_equal
	{
		using is_transparent = void;
		auto operator()(std::string_view a, std::string_view b) const noexcept -> bool { return iequals_fast(a, b); }
	};

}// namespace detail

}// namespace jhetz::ldap

template<> struct std::hash<jhetz::ldap::attribute_description>
{
	auto operator()(const jhetz::ldap::attribute_description &a) const noexcept -> std::size_t
	{
		return jhetz::ldap::hash_value(a.text());
	}
};
