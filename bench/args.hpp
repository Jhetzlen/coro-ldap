// The benchmarks' command-line arguments.
#pragma once

#include <cstddef>
#include <cstdlib>

namespace jhetz::ldap::bench {

// argv[i] as a number, `fallback` when absent.
inline auto arg(int argc, char *const *argv, int i, std::size_t fallback) -> std::size_t
{
	if (i >= argc) {
		return fallback;
	}
	return std::strtoull(argv[i], nullptr, 10);// NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

}// namespace jhetz::ldap::bench
