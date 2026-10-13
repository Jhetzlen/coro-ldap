#include "format_util.hpp"

#include <format>
#include <iterator>
#include <string>
#include <string_view>

namespace jhetz::ldap::detail {

// The one instantiation of the formatting engine (see format_util.hpp).
std::string vformat(std::string_view fmt, std::format_args args) { return std::vformat(fmt, args); }

void vformat_to(std::string &out, std::string_view fmt, std::format_args args)
{
	std::vformat_to(std::back_inserter(out), fmt, args);
}

}// namespace jhetz::ldap::detail
