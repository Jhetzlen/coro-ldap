// Cancelling an operation from a coroutine: raceable() for
// capy::when_any, with_stop() for a std::stop_source of your own. Works with
// any task returning ldap::result<T>, ldap::connection's operations
// (connection.hpp) in particular. Part of jhetz::ldap_net (header-only, on
// Capy).
//
// The per-operation timeout covers the common case. To give up on an
// operation when something else happens first (a timer, Ctrl-C, a
// capy::async_event), race it with capy::when_any through raceable(): when_any only takes awaitables returning
// capy::io_result. The first to complete wins and the others are stopped, so a losing operation is abandoned (a losing
// bind or StartTLS closes the connection):
//
//   auto r = co_await capy::when_any(ldap::raceable(c->search(params)),
//                                    corosio::delay(std::chrono::seconds(5)));
//   if (r.index() == 1) use(std::get<1>(r));  // the search's result<T>, success or not
//   else ...                                  // the delay won (2), or our task was stopped (0)
//
// To cancel it from a std::stop_source of your own (a "Cancel" button, a
// parent giving up), await it with with_stop(source.get_token(), op): it then
// stops on either that token or the awaiting task's. (capy::run(token)(op)
// replaces the task's token instead, so stopping the task would be ignored.)
// request_stop() may be called from any thread only while the io_context
// uses Corosio's default locking_mode::safe; the operation still completes on
// the connection's executor. Under locking_mode::unsafe_io and unsafe, call
// it only on the thread running the io_context: posting from another thread
// is unsupported there (io_uring, for one, then skips the wake, so a run()
// blocked in the ring would not see the stop).
//
// Either way the operation is cancelled as by its own timeout (see
// "Cancellation and timeouts" in connection.hpp): it fails with
// cond::canceled and is abandoned, or, for a bind or StartTLS, closes the
// connection.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/io_result.hpp>
#include <boost/capy/task.hpp>

#include <stop_token>
#include <system_error>
#include <utility>

namespace jhetz::ldap {

// Adapts an operation for capy::when_any, which races only awaitables
// returning capy::io_result: the operation's result<T> becomes the payload
// of an io_result with no error, so it wins the race once it completes,
// successfully or not. If it is cancelled (it lost the race, or the awaiting
// task was stopped) the io_result carries its error code instead and cannot
// win; the operation was then abandoned, or, for a bind or StartTLS, the
// connection closed (one stopped before it starts is not sent: nothing is
// abandoned and the connection stays open). At the operation's index,
// when_any's result holds the result<T>. Abandon is best effort (RFC 4511
// section 4.11): an update (add, modify, delete, modify DN) that lost the
// race may still have been applied by the server; re-read the entry if the
// outcome matters.
template<class T> boost::capy::task<boost::capy::io_result<result<T>>> raceable(boost::capy::task<result<T>> op)
{
	result<T> r = co_await std::move(op);
	std::error_code ec;
	if (!r && r.error().code == cond::canceled && (co_await boost::capy::this_coro::stop_token).stop_requested()) {
		ec = r.error().code;
	}
	co_return boost::capy::io_result<result<T>>{ ec, std::move(r) };
}

// Awaits `op` with a stop token that is set when either `token` or the
// awaiting task's own stop token is: either cancels the operation (an LDAP
// operation then fails with cond::canceled and is abandoned, or, for a bind
// or StartTLS, closes the connection; one stopped before it starts is not
// sent: nothing is abandoned and the connection stays open). Abandon is best
// effort (RFC 4511 section 4.11): a stopped update (add, modify, delete,
// modify DN) may still have been applied by the server; re-read the entry if
// the outcome matters.
// A stop requested after `op` has completed has no effect. `token` may be
// stopped from any thread only under the io_context's default
// locking_mode::safe; under unsafe_io and unsafe, only from the thread
// running the io_context (see the top of this header).
template<class T> boost::capy::task<T> with_stop(std::stop_token token, boost::capy::task<T> op)
{
	std::stop_source either;
	const auto forward = [&either] { either.request_stop(); };
	const std::stop_callback on_outer(co_await boost::capy::this_coro::stop_token, forward);
	const std::stop_callback on_token(std::move(token), forward);
	co_return co_await boost::capy::run(either.get_token())(std::move(op));
}

}// namespace jhetz::ldap
