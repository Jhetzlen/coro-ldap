// Internal: deadlines for net::connect, the TLS handshake and shutdown,
// and the connection's operations.
#pragma once

#include <boost/capy/concept/context_awaitable.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/timeout.hpp>

#include <chrono>
#include <optional>
#include <type_traits>
#include <utility>

namespace jhetz::ldap::net::detail {

using clock = std::chrono::steady_clock;
using deadline_t = std::optional<clock::time_point>;

// No deadline for nullopt or a timeout that would overflow the clock.
inline auto deadline_after(std::optional<std::chrono::milliseconds> timeout, clock::time_point now = clock::now())
  -> deadline_t
{
	if (!timeout) {
		return std::nullopt;
	}
	const auto room = std::chrono::duration_cast<std::chrono::milliseconds>(clock::time_point::max() - now);
	if (*timeout >= room) {
		return std::nullopt;
	}
	return now + *timeout;
}

// Awaits `a`, cancelled at `deadline` (then capy::cond::timeout). Only for
// operations that stop promptly when cancelled.
template<class A>
auto bounded(A a, deadline_t deadline) -> boost::capy::task<std::remove_cvref_t<boost::capy::awaitable_result_t<A>>>
{
	if (deadline) {
		co_return co_await boost::corosio::timeout(std::move(a), *deadline);
	}
	co_return co_await std::move(a);
}

}// namespace jhetz::ldap::net::detail
