// Property check for the fuzz targets: aborts (a libFuzzer crash, a failed
// replay test) with the failed condition.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <print>

namespace jhetz::ldap::fuzz {

[[noreturn]] inline void property_failed(const char *target, const char *what, int line)
{
	std::println(stderr, "{}: property violated: {} (line {})", target, what, line);
	std::abort();
}

}// namespace jhetz::ldap::fuzz

#define LDAP_FUZZ_CHECK(cond)                                                            \
	do {                                                                                 \
		if (!(cond)) ::jhetz::ldap::fuzz::property_failed(FUZZ_TARGET, #cond, __LINE__); \
	} while (false)
