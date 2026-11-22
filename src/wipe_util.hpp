// Internal: wiping secrets before their memory is freed.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace jhetz::ldap::detail {

// Zeroes `n` bytes at `p` with volatile stores the compiler keeps.
inline void wipe_bytes(void *p, std::size_t n) noexcept
{
	auto *v = static_cast<volatile unsigned char *>(p);
	for (std::size_t i = 0; i < n; ++i) {
		v[i] = 0;
	}
}

// Wipes a string's whole buffer, also the bytes past size() that a move
// out of a short (SSO) string leaves behind.
template<class Traits, class Alloc> void wipe_string(std::basic_string<char, Traits, Alloc> &s) noexcept
{
	s.resize(s.capacity());// NOLINT(clang-analyzer-cplusplus.Move): wipes what a move left
	wipe_bytes(s.data(), s.size());
	s.clear();
}

// Wipes a vector's whole buffer and empties it.
template<class T, class Alloc> void wipe_vector(std::vector<T, Alloc> &v) noexcept
{
	v.resize(v.capacity());
	wipe_bytes(v.data(), v.size() * sizeof(T));
	v.clear();
}

}// namespace jhetz::ldap::detail
