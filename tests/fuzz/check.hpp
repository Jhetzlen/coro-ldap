// Property check for the fuzz targets: aborts with the failed condition.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <print>
#include <source_location>
#include <string_view>

namespace jhetz::ldap::fuzz {

struct checker
{
	std::string_view target;// for messages

	void operator()(bool ok, std::string_view what, std::source_location where = std::source_location::current()) const
	{
		if (!ok) [[unlikely]] {
			failed(what, where);
		}
	}

	[[noreturn]] void failed(std::string_view what, std::source_location where) const
	{
		std::println(stderr, "{}: property violated: {} (line {})", target, what, where.line());
		std::abort();
	}
};

}// namespace jhetz::ldap::fuzz
