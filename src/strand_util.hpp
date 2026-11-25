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

// Whether `ex` is `strand` (or a copy of it). Compares the strands, not the
// executor_refs: executor_ref's == first compares the addresses of Capy's
// per-type vtables (inline variables), and with DLLs on Windows each module
// has its own, so an executor_ref made in the application never equals one
// made here. target() compares the types by their type_info.
inline auto is_strand(const boost::capy::executor_ref &ex, const io_strand &strand) noexcept -> bool
{
	const auto *s = ex.target<io_strand>();
	return s != nullptr && *s == strand;
}

// Runs `body` on `strand`: inline when already there, else through
// capy::run (which resumes the caller with a post, after what is already
// queued on its executor).
template<class T> auto on_strand(io_strand strand, boost::capy::task<T> body) -> boost::capy::task<T>
{
	// The analyzer does not model the promise's construction: Capy's env_ is
	// nullptr-initialised and set by the awaiting caller before the first resume.
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
	if (is_strand(co_await boost::capy::this_coro::executor, strand)) {
		co_return co_await std::move(body);
	}
	co_return co_await boost::capy::run(strand)(std::move(body));
}

template<class F> auto invoke_detached(F f) -> boost::capy::task<void>
{
	f();
	co_return;
}

// Runs `f` on `strand`: at once when on it, or when the io_context is
// stopped and not running; else posted. Allocation failure terminates.
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
