#pragma once

#include <chrono>
#include <optional>

namespace jhetz::ldap {

// For any timeout: no client-side limit.
inline constexpr std::chrono::milliseconds no_timeout = std::chrono::milliseconds::max();

namespace detail {

	// nullopt for no_timeout.
	[[nodiscard]] constexpr auto limit_of(std::chrono::milliseconds timeout) noexcept
	  -> std::optional<std::chrono::milliseconds>
	{
		if (timeout == no_timeout) {
			return std::nullopt;
		}
		return timeout;
	}

}// namespace detail

}// namespace jhetz::ldap
