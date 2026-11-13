// ldap::run: runs a coroutine task to completion from a plain function such as
// main() (docs/API.md, run.hpp).
#pragma once

#include <boost/capy/error.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <concepts>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <type_traits>
#include <utility>

namespace jhetz::ldap {

class connection;
class client;
class search_stream;
class paged_search;
class lease;
class exclusive_lease;
class transaction;
template<class T, class Stream> class record_stream;

namespace detail {
	// Types that must be destroyed on their connection's I/O thread, alone or
	// inside result, std::optional, std::unique_ptr or std::shared_ptr.
	template<class T> inline constexpr bool io_thread_bound = false;
	template<> inline constexpr bool io_thread_bound<search_stream> = true;
	template<> inline constexpr bool io_thread_bound<paged_search> = true;
	template<> inline constexpr bool io_thread_bound<lease> = true;
	template<> inline constexpr bool io_thread_bound<exclusive_lease> = true;
	template<> inline constexpr bool io_thread_bound<transaction> = true;
	template<class T, class Stream> inline constexpr bool io_thread_bound<record_stream<T, Stream>> = true;
	template<class T, class E> inline constexpr bool io_thread_bound<std::expected<T, E>> = io_thread_bound<T>;
	template<class T> inline constexpr bool io_thread_bound<std::optional<T>> = io_thread_bound<T>;
	template<class T, class Del> inline constexpr bool io_thread_bound<std::unique_ptr<T, Del>> = io_thread_bound<T>;
	template<class T> inline constexpr bool io_thread_bound<std::shared_ptr<T>> = io_thread_bound<T>;

	// Types that must not outlive the io_context they run on.
	template<class T> inline constexpr bool io_context_bound = io_thread_bound<T>;
	template<> inline constexpr bool io_context_bound<connection> = true;
	template<> inline constexpr bool io_context_bound<client> = true;
	template<class T, class E> inline constexpr bool io_context_bound<std::expected<T, E>> = io_context_bound<T>;
	template<class T> inline constexpr bool io_context_bound<std::optional<T>> = io_context_bound<T>;
	template<class T, class Del> inline constexpr bool io_context_bound<std::unique_ptr<T, Del>> = io_context_bound<T>;
	template<class T> inline constexpr bool io_context_bound<std::shared_ptr<T>> = io_context_bound<T>;

	// The T of a capy::task<T>.
	template<class> struct task_value_of
	{
	};
	template<class T> struct task_value_of<boost::capy::task<T>>
	{
		using type = T;
	};
	template<class F, class... Args>
	using run_value_t = task_value_of<std::invoke_result_t<F, boost::corosio::io_context &, Args...>>::type;

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
			// Shared with the handlers, which may run after run() returned.
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

		template<class F, class... Args>
			requires std::invocable<F, boost::corosio::io_context &, Args...>
					 && requires { typename run_value_t<F, Args...>; }
		auto operator()(F &&f, Args &&...args) const -> run_value_t<F, Args...>
		{
			static_assert(!io_context_bound<run_value_t<F, Args...>>,
			  "ldap::run(f, ...): the task's result is bound to the io_context run destroys; use run(ioc, task) or "
			  "return plain values");
			boost::corosio::io_context ioc;
			// Calls f here so its argument temporaries live until the run ends.
			return (*this)(ioc, std::forward<F>(f)(ioc, std::forward<Args>(args)...));
		}
	};
}// namespace detail

inline constexpr detail::run_fn run{};

}// namespace jhetz::ldap
