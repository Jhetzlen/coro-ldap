// Cancelling an operation from a coroutine: raceable() for capy::when_any,
// with_stop() for a std::stop_source of your own. Works with any task
// returning ldap::result<T>. Part of jhetz::ldap_net (header-only, on Capy).
//
// Race an operation against another event (a timer, Ctrl-C, a
// capy::async_event) with capy::when_any through raceable(); the losers are
// stopped, so a losing operation is abandoned (a losing bind or StartTLS
// closes the connection):
//
//   auto r = co_await capy::when_any(ldap::raceable(c->search(params)),
//                                    corosio::delay(std::chrono::seconds(5)));
//   if (r.index() == 1) use(std::get<1>(r));  // the search's result<T>, success or not
//   else ...                                  // the delay won (2), or our task was stopped (0)
//
// with_stop(source.get_token(), op) stops on either that token or the
// awaiting task's (capy::run(token)(op) would replace the task's token).
// request_stop() may be called from any thread only under Corosio's default
// locking_mode::safe; under unsafe_io and unsafe, only on the thread running
// the io_context.
//
// Either way the operation fails with cond::canceled and is abandoned, or,
// for a bind or StartTLS, closes the connection (connection.hpp
// "Cancellation and timeouts").
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
// of an error-free capy::results, so it wins once it completes, successfully
// or not. Cancelled (lost, or the awaiting task stopped), the results carry
// its error and cannot win: the operation was abandoned, or for a bind or
// StartTLS the connection closed; one stopped before it starts is not sent.
// Abandon is best effort (RFC 4511 section 4.11): an update that lost may
// still have been applied.
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
// task's own is: the operation is cancelled as by raceable() losing. A stop
// after `op` completed has no effect. `token` may be stopped from any thread
// only under locking_mode::safe (see the top of this header).
template<class T> auto with_stop(std::stop_token token, boost::capy::task<T> op) -> boost::capy::task<T>
{
	std::stop_source either;
	const auto forward = [&either] { either.request_stop(); };
	const std::stop_callback on_outer(co_await boost::capy::this_coro::stop_token, forward);
	const std::stop_callback on_token(std::move(token), forward);
	co_return co_await boost::capy::run(either.get_token())(std::move(op));
}

}// namespace jhetz::ldap
