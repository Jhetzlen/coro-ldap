// Property check for the fuzz targets: aborts (a libFuzzer crash, a failed
// replay test) with the failed condition.
#pragma once

#include <cstdio>
#include <cstdlib>

namespace jhetz::ldap::fuzz {

[[noreturn]] inline void property_failed(const char *target, const char *what, int line)
{
	std::fprintf(stderr, "%s: property violated: %s (line %d)\n", target, what, line);
	std::abort();
}

}// namespace jhetz::ldap::fuzz

#define LDAP_FUZZ_CHECK(cond)                                                            \
	do {                                                                                 \
		if (!(cond)) ::jhetz::ldap::fuzz::property_failed(FUZZ_TARGET, #cond, __LINE__); \
	} while (false)
