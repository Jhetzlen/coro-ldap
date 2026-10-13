// Internal: deadlines for net::connect and the TLS handshake.
#pragma once

#include <boost/capy/concept/io_awaitable.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/timeout.hpp>

#include <chrono>
#include <optional>
#include <type_traits>
#include <utility>

namespace jhetz::ldap::net::detail {

using clock = std::chrono::steady_clock;
using deadline_t = std::optional<clock::time_point>;

// Awaits `a`, cancelled at `deadline` if there is one (the result then
// compares equal to capy::cond::timeout). Only for operations that stop
// promptly when cancelled; see resolve_bounded in connect.cpp for one that
// does not.
template<class A>
boost::capy::task<std::remove_cvref_t<boost::capy::awaitable_result_t<A>>> bounded(A a, deadline_t deadline)
{
	if (deadline) co_return co_await boost::corosio::timeout(std::move(a), *deadline);
	co_return co_await std::move(a);
}

}// namespace jhetz::ldap::net::detail
