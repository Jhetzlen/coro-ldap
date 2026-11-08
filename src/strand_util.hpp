// Internal: running coroutines and noexcept cleanups on a capy::strand.
#pragma once

#include <boost/capy/ex/executor_ref.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/strand.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <utility>

namespace jhetz::ldap::detail {

using io_strand = boost::capy::strand<boost::corosio::io_context::executor_type>;

// Runs `body` on `strand`: inline when the awaiting task already runs on
// it, else through capy::run, which posts it there and resumes the caller
// on its own executor.
template<class T> auto on_strand(io_strand strand, boost::capy::task<T> body) -> boost::capy::task<T>
{
	// The analyzer does not model the promise's construction: Capy's env_ is
	// nullptr-initialised and set by the awaiting caller before the first resume.
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
	if ((co_await boost::capy::this_coro::executor) == boost::capy::executor_ref(strand)) {
		co_return co_await std::move(body);
	}
	co_return co_await boost::capy::run(strand)(std::move(body));
}

template<class F> auto invoke_detached(F f) -> boost::capy::task<void>
{
	f();
	co_return;
}

// Runs `f` on `strand`: at once when the calling thread runs on it, or when
// the io_context is stopped and the calling thread is not inside its run();
// else posted there (the call returns first). For the noexcept paths
// (destructors, close()): an allocation failure ends the program, as
// capy::run_async's own does.
template<class F> void run_on_strand(const io_strand &strand, F f) noexcept
{
	if (strand.running_in_this_thread()
		|| (strand.context().stopped() && !strand.get_inner_executor().running_in_this_thread())) {
		f();
		return;
	}
	boost::capy::run_async(strand)(invoke_detached(std::move(f)));
}

}// namespace jhetz::ldap::detail
