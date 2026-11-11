// ldap::run: runs a task to completion from a plain function such as main()
// and returns its result. Part of jhetz::ldap_net (header-only, on Capy and
// Corosio).
//
//   auto work(boost::corosio::io_context &ioc) -> boost::capy::task<int>
//   {
//       auto c = co_await ldap::connect(ioc, "ldap://localhost");
//       ...
//   }
//
//   auto main() -> int
//   {
//       boost::corosio::io_context ioc;
//       return ldap::run(ioc, work(ioc));
//   }
//
// run(ioc, task) starts the task on ioc's executor and calls ioc.run() on
// the calling thread (restarting a stopped ioc first), so it returns once
// ioc has no work left: the task, and what it leaves behind (a connection
// closing, a detached name lookup). Other threads may run ioc too. It must
// not be called from a thread already running ioc. run(task) does the same
// on an io_context of its own, for a task that needs none.
//
// The task's value is returned, an exception it throws is rethrown. If
// ioc.run() returns before the task ended (ioc stopped, or the task
// abandoned), run throws std::system_error with capy::error::canceled.
#pragma once

#include <boost/capy/error.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <type_traits>
#include <utility>

namespace jhetz::ldap {

namespace detail {
	template<class T> struct run_state
	{
		std::optional<T> value{};
		std::exception_ptr error{};
	};
	template<> struct run_state<void>
	{
		bool finished = false;
		std::exception_ptr error{};
	};

	struct run_fn
	{
		template<class T> auto operator()(boost::corosio::io_context &ioc, boost::capy::task<T> t) const -> T
		{
			// Shared with the handlers: a task ending after run threw (a stopped
			// ioc run again later) writes here, not into a destroyed frame.
			const auto state = std::make_shared<run_state<T>>();
			if (ioc.stopped()) {
				ioc.restart();
			}
			const auto fail = [state](std::exception_ptr e) { state->error = std::move(e); };
			if constexpr (std::is_void_v<T>) {
				boost::capy::run_async(ioc.get_executor(), [state] { state->finished = true; }, fail)(std::move(t));
			} else {
				boost::capy::run_async(
				  ioc.get_executor(), [state](T v) { state->value.emplace(std::move(v)); }, fail)(std::move(t));
			}
			ioc.run();
			if (state->error) {
				std::rethrow_exception(state->error);
			}
			if constexpr (std::is_void_v<T>) {
				if (state->finished) {
					return;
				}
			} else {
				if (state->value) {
					return std::move(*state->value);
				}
			}
			throw std::system_error(
			  make_error_code(boost::capy::error::canceled), "ldap::run: the task did not finish");
		}

		template<class T> auto operator()(boost::capy::task<T> t) const -> T
		{
			boost::corosio::io_context ioc;
			return (*this)(ioc, std::move(t));
		}
	};
}// namespace detail

// A function object, so argument-dependent lookup never finds it.
inline constexpr detail::run_fn run{};

}// namespace jhetz::ldap
