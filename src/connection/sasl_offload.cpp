#include "sasl_offload.hpp"

#include "../net/deadline.hpp"

#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/corosio/detail/scheduler.hpp>

#include <atomic>
#include <exception>
#include <iterator>
#include <list>
#include <memory>
#include <mutex>
#include <system_error>
#include <thread>
#include <utility>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap::detail {

namespace {

	// The threads of the offloaded SASL steps, an io_context service joining
	// them on destruction; an ended thread is joined when the next one starts.
	class offload_threads final : public capy::execution_context::service
	{
	  public:
		explicit offload_threads(capy::execution_context &) noexcept {}
		offload_threads(const offload_threads &) = delete;
		auto operator=(const offload_threads &) -> offload_threads & = delete;
		~offload_threads() override { join(workers_); }// after shutdown(): nothing left

		// Runs `f` on a thread of its own. Throws std::system_error.
		template<class F> void start(F f)
		{
			reap();
			const std::scoped_lock lock(mutex_);
			auto &w = workers_.emplace_back();
			try {
				w.thread = std::thread([f = std::move(f), &ended = w.ended] mutable noexcept {
					f();
					ended.store(true, std::memory_order_release);
				});
			} catch (...) {
				workers_.pop_back();
				throw;
			}
		}

	  protected:
		// Waits for the threads: as long as the steps still running take.
		void shutdown() override
		{
			std::list<worker> all;
			{
				const std::scoped_lock lock(mutex_);
				all.swap(workers_);
			}
			join(all);
		}

	  private:
		struct worker
		{
			std::thread thread{};
			std::atomic<bool> ended{ false };// set by the thread, last
		};

		// Joins the threads that have ended (quick: they are exiting).
		void reap() noexcept
		{
			std::list<worker> ended;
			{
				const std::scoped_lock lock(mutex_);
				for (auto it = workers_.begin(); it != workers_.end();) {
					const auto next = std::next(it);
					if (it->ended.load(std::memory_order_acquire)) {
						ended.splice(ended.end(), workers_, it);
					}
					it = next;
				}
			}
			join(ended);
		}

		static void join(std::list<worker> &workers) noexcept
		{
			for (auto &w : workers) {
				if (w.thread.joinable()) {
					w.thread.join();
				}
			}
			workers.clear();
		}

		std::mutex mutex_;
		std::list<worker> workers_;
	};

	// An offloaded step's state, shared by its thread and the wait.
	struct offloaded
	{
		explicit offloaded(sasl_work w) noexcept : work(std::move(w)) {}
		sasl_work work;
		std::optional<result<std::optional<std::string>>> value{};
		std::exception_ptr thrown{};
		capy::async_waker done{};
	};

}// namespace

auto run_offloaded(corosio::io_context::executor_type ex,
  std::optional<std::chrono::milliseconds> timeout,
  sasl_work work) -> capy::task<result<std::optional<std::string>>>
{
	// The thread posts from outside the I/O thread: not under
	// locking_mode::unsafe.
	if (corosio::detail::get_scheduler(ex.context()).scheduler_locking_disabled()) {
		co_return fail(std::make_error_code(std::errc::operation_not_supported),
		  "the mechanism's step runs on a thread of its own, which needs an io_context in locking_mode::safe or "
		  "unsafe_io");
	}
	auto shared = std::make_shared<offloaded>(std::move(work));
	try {
		auto &threads = ex.context().use_service<offload_threads>();
		threads.start([shared, guard = capy::work_guard(ex)] mutable noexcept {
			try {
				shared->value.emplace(shared->work());
			} catch (...) {
				shared->thrown = std::current_exception();
			}
			shared->work = nullptr;// the mechanism's state, released on this thread
			shared->done.wake();
			shared.reset();
			// Last: run() may return after this. The io_context's
			// destructor joins this thread before the scheduler goes.
			guard.reset();
		});
	} catch (const std::system_error &e) {
		co_return fail(e.code(), "could not start a thread for the mechanism's step");
	}
	const net::detail::deadline_t deadline = net::detail::deadline_after(timeout);
	auto [ec] = co_await net::detail::bounded(shared->done.wait(), deadline);
	if (ec) {
		co_return fail(ec, "gave up on the mechanism's step (it runs on, on its own thread)");
	}
	// The thread set exactly one of the two: no value means it threw.
	if (!shared->value) {
		std::rethrow_exception(shared->thrown);
	}
	co_return std::move(*shared->value);
}

}// namespace jhetz::ldap::detail
