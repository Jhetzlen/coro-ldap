// Cancelling an operation: raceable() for capy::when_any, with_stop() for a
// std::stop_token of your own (docs/API.md, connection.hpp section).
#pragma once

#include "jhetz/ldap/error.hpp"

#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/results.hpp>
#include <boost/capy/task.hpp>

#include <stop_token>
#include <system_error>
#include <utility>

namespace jhetz::ldap {

// Adapts an operation for capy::when_any: its result<T> becomes the payload
// of an error-free capy::results, so it wins once it completes.
template<class T> auto raceable(boost::capy::task<result<T>> op) -> boost::capy::task<boost::capy::results<result<T>>>
{
	result<T> r = co_await std::move(op);
	std::error_code ec;
	if (!r && r.error().code == cond::canceled && (co_await boost::capy::this_coro::stop_token).stop_requested()) {
		ec = r.error().code;
	}
	co_return boost::capy::results<result<T>>{ ec, std::move(r) };
}

// Awaits `op` with a stop token set when either `token` or the awaiting
// task's own is.
template<class T> auto with_stop(std::stop_token token, boost::capy::task<T> op) -> boost::capy::task<T>
{
	std::stop_source either;
	const auto forward = [&either] { either.request_stop(); };
	const std::stop_callback on_outer(co_await boost::capy::this_coro::stop_token, forward);
	const std::stop_callback on_token(std::move(token), forward);
	co_return co_await boost::capy::run(either.get_token())(std::move(op));
}

}// namespace jhetz::ldap
