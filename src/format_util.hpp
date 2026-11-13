// std::format wrappers instantiating the engine once (format_util.cpp), and
// sanitizing of server text.
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

// Appends at most `max_bytes` of peer text, cut on a code point boundary
// ("..." if cut); ill-formed UTF-8, Cc, Bidi_Control, Zl and Zp become
// U+FFFD.
void append_sanitized(std::string &out, std::string_view s, std::size_t max_bytes);
void append_sanitized(std::pmr::string &out, std::string_view s, std::size_t max_bytes);

}// namespace jhetz::ldap::detail
