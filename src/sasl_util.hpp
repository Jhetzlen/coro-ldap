// Internal: helpers shared by the SASL mechanisms.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace jhetz::ldap::detail {

// An encode_error with `what` as its context.
inline auto input_error(std::string_view what) -> std::unexpected<error>
{
	return fail(client_errc::encode_error, what);
}

// OpenSSL or ICU failed (memory, missing ICU data): the environment, not
// the caller's input.
inline auto library_error(std::string_view what) -> std::unexpected<error>
{
	return fail(client_errc::internal_error, what);
}

// The server's message does not fit the exchange.
inline auto refused(std::string_view what) -> std::unexpected<error>
{
	return fail(client_errc::unexpected_response, what);
}

// Wipes a string's whole buffer, also the bytes past size() that a move
// out of a short (SSO) string leaves behind.
inline void wipe_string(std::string &s) noexcept
{
	s.resize(s.capacity());// NOLINT(clang-analyzer-cplusplus.Move): wipes what a move left
	OPENSSL_cleanse(s.data(), s.size());
	s.clear();
}

// Key material, wiped when it goes out of scope.
template<std::size_t N> struct wiped
{
	std::array<unsigned char, N> bytes{};
	wiped() = default;
	explicit wiped(const std::array<unsigned char, N> &v) noexcept : bytes(v) {}
	wiped(const wiped &) = delete;
	auto operator=(const wiped &) -> wiped & = delete;
	~wiped() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
	auto data() -> unsigned char * { return bytes.data(); }
	static constexpr auto size() -> std::size_t { return N; }
	auto span() -> std::span<unsigned char, N> { return bytes; }
	auto operator[](std::size_t i) -> unsigned char & { return bytes[i]; }
};

// The octets as text, without copying.
inline auto as_chars(std::span<const unsigned char> s) noexcept -> std::string_view
{
	return { reinterpret_cast<const char *>(s.data()), s.size() };
}

}// namespace jhetz::ldap::detail
