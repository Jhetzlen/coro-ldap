// Attribute descriptions (RFC 4512 section 2.5), DESIGN.md section 1.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <compare>
#include <cstddef>
#include <functional>
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
class attribute
{
  public:
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
	attribute(literal l) : name_(l.text) {}

	static result<attribute> parse(std::string_view text);
	static attribute unchecked(std::string text)
	{
		attribute a;
		a.name_ = std::move(text);
		return a;
	}

	const std::string &name() const noexcept { return name_; }
	bool empty() const noexcept { return name_.empty(); }

	friend bool operator==(const attribute &a, const attribute &b) noexcept
	{
		return detail::iequals(a.name_, b.name_);
	}
	friend std::weak_ordering operator<=>(const attribute &a, const attribute &b) noexcept;

  private:
	std::string name_;
};

// Case-insensitive hash, consistent with operator==.
std::size_t hash_value(std::string_view attribute_name) noexcept;

}// namespace jhetz::ldap

template<> struct std::hash<jhetz::ldap::attribute>
{
	std::size_t operator()(const jhetz::ldap::attribute &a) const noexcept { return jhetz::ldap::hash_value(a.name()); }
};
