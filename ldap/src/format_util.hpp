// Internal: std::format for diagnostics, and server text in them (below).
// Calling std::format directly instantiates the whole formatting engine
// (about 100 KB of code and seconds of -O3 compile time) in every
// translation unit that builds a message; these wrappers type-erase the
// arguments and run the engine once, in error.cpp. The format string is
// still checked at compile time.
#pragma once

#include <cstddef>
#include <format>
#include <memory_resource>
#include <string>
#include <string_view>

namespace jhetz::ldap::detail {

std::string vformat(std::string_view fmt, std::format_args args);
void vformat_to(std::string &out, std::string_view fmt, std::format_args args);

// std::format(fmt, args...).
template<class... Args> std::string format(std::format_string<const Args &...> fmt, const Args &...args)
{
	return detail::vformat(fmt.get(), std::make_format_args(args...));
}

// std::format_to(std::back_inserter(out), fmt, args...).
template<class... Args> void format_to(std::string &out, std::format_string<const Args &...> fmt, const Args &...args)
{
	detail::vformat_to(out, fmt.get(), std::make_format_args(args...));
}

// Appends text a server or peer sent (a diagnosticMessage, a DN, an
// attribute value, ...) to a human-readable message, so it cannot break
// the message's line or change how it is displayed. At most `max_bytes`
// bytes of `s`, cut on a code point boundary, then "..." if cut. Valid
// UTF-8 is kept; these become U+FFFD: ill-formed sequences (one per
// maximal subpart), control characters (C0, DEL, C1), the bidi controls
// (Unicode property Bidi_Control: U+061C, U+200E, U+200F, U+202A-U+202E,
// U+2066-U+2069), which could reorder how the rest of a log line or
// terminal message is displayed ("Trojan Source"), and LINE/PARAGRAPH
// SEPARATOR (U+2028, U+2029), which log viewers may show as line breaks.
// Other format characters (ZWJ, ZWNJ, emoji tags, ...) are ordinary text
// and are kept.
void append_sanitized(std::string &out, std::string_view s, std::size_t max_bytes);
void append_sanitized(std::pmr::string &out, std::string_view s, std::size_t max_bytes);

}// namespace jhetz::ldap::detail
