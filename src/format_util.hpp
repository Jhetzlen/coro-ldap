// Internal: std::format for diagnostics, and server text in them (below).
// Calling std::format directly instantiates the whole formatting engine
// (about 100 KB of code and seconds of -O3 compile time) in every
// translation unit that builds a message; these wrappers type-erase the
// arguments and run the engine once, in format_util.cpp. The format string is
// still checked at compile time.
#pragma once

#include <cstddef>
#include <format>
#include <memory_resource>
#include <string>
#include <string_view>

namespace jhetz::ldap::detail {

// The low four bits of an octet: one hex digit.
inline constexpr unsigned nibble_mask = 0xFu;

// DEL, the last ASCII character.
inline constexpr unsigned char ascii_delete = 0x7Fu;

// An ASCII control character: C0 (below ' ') or DEL.
constexpr auto is_ascii_control(unsigned char c) noexcept -> bool { return c < ' ' || c == ascii_delete; }

auto vformat(std::string_view fmt, std::format_args args) -> std::string;
void vformat_to(std::string &out, std::string_view fmt, std::format_args args);

// std::format(fmt, args...).
template<class... Args> auto format(std::format_string<const Args &...> fmt, const Args &...args) -> std::string
{
	return detail::vformat(fmt.get(), std::make_format_args(args...));
}

// std::format_to(std::back_inserter(out), fmt, args...).
template<class... Args> void format_to(std::string &out, std::format_string<const Args &...> fmt, const Args &...args)
{
	detail::vformat_to(out, fmt.get(), std::make_format_args(args...));
}

// Appends text a server or peer sent (a diagnosticMessage, a DN, a value,
// ...) to a human-readable message: at most `max_bytes` bytes of `s`, cut on
// a code point boundary, then "..." if cut. Valid UTF-8 is kept; ill-formed
// sequences (one U+FFFD per maximal subpart), control characters (Cc), bidi
// controls (Bidi_Control) and LINE / PARAGRAPH SEPARATOR (Zl, Zp) become
// U+FFFD. Other format characters are kept.
void append_sanitized(std::string &out, std::string_view s, std::size_t max_bytes);
void append_sanitized(std::pmr::string &out, std::string_view s, std::size_t max_bytes);

}// namespace jhetz::ldap::detail
