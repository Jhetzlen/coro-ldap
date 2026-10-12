// Internal: std::format for diagnostics. Calling std::format directly
// instantiates the whole formatting engine (about 100 KB of code and seconds
// of -O3 compile time) in every translation unit that builds a message; these
// wrappers type-erase the arguments and run the engine once, in error.cpp.
// The format string is still checked at compile time.
#pragma once

#include <format>
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

}// namespace jhetz::ldap::detail
