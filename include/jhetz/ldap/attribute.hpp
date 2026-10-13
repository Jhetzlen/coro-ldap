// Attribute descriptions (RFC 4512 section 2.5), DESIGN.md section 1.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <compare>
#include <cstddef>
#include <functional>
#include <memory_resource>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

namespace detail {

	constexpr bool is_alpha(char c) noexcept { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
	constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }
	constexpr bool is_keychar(char c) noexcept { return is_alpha(c) || is_digit(c) || c == '-'; }
	constexpr char ascii_lower(char c) noexcept { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

	constexpr bool is_hex(char c) noexcept { return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

	constexpr unsigned hex_value(char c) noexcept
	{
		if (is_digit(c)) return static_cast<unsigned>(c - '0');
		if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
		return static_cast<unsigned>(c - 'A' + 10);
	}

	constexpr bool iequals(std::string_view a, std::string_view b) noexcept
	{
		if (a.size() != b.size()) return false;
		for (std::size_t i = 0; i < a.size(); ++i)
			if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
		return true;
	}

	// The UTF-8 sequence starting at s[i] (RFC 3629; RFC 4512 UTF1 / UTFMB:
	// no overlong forms, surrogates or code points above U+10FFFF). If it is
	// well-formed, its length; if not, the length of its maximal subpart
	// (Unicode section 3.9: the longest prefix of a well-formed sequence, at
	// least one octet), which one U+FFFD replaces in a decoder following the
	// Unicode recommendation (ICU's U8_NEXT, WHATWG). Precondition:
	// i < s.size().
	struct utf8_sequence
	{
		std::size_t length;
		bool well_formed;
	};
	constexpr utf8_sequence utf8_sequence_at(std::string_view s, std::size_t i) noexcept
	{
		const auto at = [&](std::size_t k) { return static_cast<unsigned char>(s[i + k]); };
		const unsigned char c = at(0);
		if (c < 0x80u) return { 1, true };
		std::size_t n = 0;
		unsigned char lo = 0x80u, hi = 0xBFu;// range of the second octet
		if (c >= 0xC2u && c <= 0xDFu) {
			n = 2;
		} else if (c >= 0xE0u && c <= 0xEFu) {
			n = 3;
			if (c == 0xE0u) lo = 0xA0u;// overlong
			if (c == 0xEDu) hi = 0x9Fu;// surrogates
		} else if (c >= 0xF0u && c <= 0xF4u) {
			n = 4;
			if (c == 0xF0u) lo = 0x90u;// overlong
			if (c == 0xF4u) hi = 0x8Fu;// above U+10FFFF
		} else {
			return { 1, false };
		}
		const std::size_t avail = s.size() - i;
		std::size_t k = 1;
		if (avail > 1 && at(1) >= lo && at(1) <= hi) {
			k = 2;
			while (k < n && k < avail && at(k) >= 0x80u && at(k) <= 0xBFu) ++k;
		}
		return { k, k == n };
	}

	// Length of the valid UTF-8 sequence starting at s[i], or 0 if there is
	// none (see utf8_sequence_at). Precondition: i < s.size().
	constexpr std::size_t utf8_sequence_length(std::string_view s, std::size_t i) noexcept
	{
		const utf8_sequence q = utf8_sequence_at(s, i);
		return q.well_formed ? q.length : 0;
	}

	// descr = keystring = ALPHA *(ALPHA / DIGIT / HYPHEN)
	constexpr bool is_descr(std::string_view s) noexcept
	{
		if (s.empty() || !is_alpha(s[0])) return false;
		for (char c : s)
			if (!is_keychar(c)) return false;
		return true;
	}

	// numericoid = number 1*( DOT number ); number = DIGIT / ( LDIGIT 1*DIGIT )
	// (no leading zeros).
	constexpr bool is_numericoid(std::string_view s) noexcept
	{
		std::size_t parts = 0;
		std::size_t i = 0;
		while (true) {
			const std::size_t start = i;
			while (i < s.size() && is_digit(s[i])) ++i;
			if (i == start) return false;
			if (s[start] == '0' && i - start > 1) return false;
			++parts;
			if (i == s.size()) break;
			if (s[i] != '.') return false;
			++i;
		}
		return parts >= 2;
	}

	// oid = descr / numericoid (RFC 4512 section 1.4)
	constexpr bool is_oid(std::string_view s) noexcept { return is_descr(s) || is_numericoid(s); }

	// attributedescription = attributetype options; options = *( SEMI option );
	// option = 1*keychar
	constexpr bool is_attribute_description(std::string_view s) noexcept
	{
		const std::size_t semi = s.find(';');
		if (!is_oid(s.substr(0, semi))) return false;
		if (semi == std::string_view::npos) return true;
		std::size_t i = semi;
		while (i < s.size()) {
			++i;// skip ';'
			const std::size_t start = i;
			while (i < s.size() && is_keychar(s[i])) ++i;
			if (i == start) return false;
			if (i < s.size() && s[i] != ';') return false;
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
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_attribute_description(s)) throw "ldap::attribute: invalid attribute description";
		}
		const char *text;
	};

	attribute() = default;
	explicit attribute(const allocator_type &alloc) : name_(alloc) {}
	attribute(literal l, const allocator_type &alloc = {}) : name_(l.text, alloc) {}
	attribute(const attribute &) = default;
	attribute(attribute &&) noexcept = default;
	attribute(const attribute &other, const allocator_type &alloc) : name_(other.name_, alloc) {}
	attribute(attribute &&other, const allocator_type &alloc) : name_(std::move(other.name_), alloc) {}
	attribute &operator=(const attribute &) = default;
	attribute &operator=(attribute &&) = default;
	~attribute() = default;

	allocator_type get_allocator() const noexcept { return name_.get_allocator(); }

	[[nodiscard]] static result<attribute> parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	[[nodiscard]] static attribute unchecked(std::string_view text, const allocator_type &alloc = {})
	{
		attribute a(alloc);
		a.name_.assign(text);
		return a;
	}
	[[nodiscard]] static attribute unchecked(const char *text, const allocator_type &alloc = {})
	{
		return unchecked(std::string_view(text), alloc);
	}
	// Takes the string, with its resource.
	[[nodiscard]] static attribute unchecked(std::pmr::string &&text) noexcept
	{
		return attribute(std::move(text), adopt{});
	}

	const std::pmr::string &name() const noexcept { return name_; }
	[[nodiscard]] bool empty() const noexcept { return name_.empty(); }

	friend bool operator==(const attribute &a, const attribute &b) noexcept
	{
		return detail::iequals(a.name_, b.name_);
	}
	friend std::weak_ordering operator<=>(const attribute &a, const attribute &b) noexcept;

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
[[nodiscard]] std::size_t hash_value(std::string_view attribute_name) noexcept;

namespace detail {

	// iequals, 8 bytes at a time (not constexpr).
	bool iequals_fast(std::string_view a, std::string_view b) noexcept;

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
		std::size_t operator()(std::string_view s) const { return hash_value(s); }
	};
	struct ci_equal
	{
		using is_transparent = void;
		bool operator()(std::string_view a, std::string_view b) const noexcept { return iequals_fast(a, b); }
	};

}// namespace detail

}// namespace jhetz::ldap

template<> struct std::hash<jhetz::ldap::attribute>
{
	std::size_t operator()(const jhetz::ldap::attribute &a) const noexcept { return jhetz::ldap::hash_value(a.name()); }
};
