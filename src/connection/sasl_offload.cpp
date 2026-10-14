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

	// The threads of the offloaded SASL steps (run_offloaded), owned by
	// the io_context as one of its services, which joins them when the
	// io_context is destroyed. A service is shut down and destroyed before
	// the ones created earlier, the scheduler (created by the io_context's
	// constructor) among them, so the join happens while the scheduler is
	// still alive: a thread may post its wakeup and drop its work_guard
	// until it ends. A thread that has ended is joined (reaped) when the
	// next one starts.
	class offload_threads final : public capy::execution_context::service
	{
	  public:
		explicit offload_threads(capy::execution_context &) noexcept {}
		offload_threads(const offload_threads &) = delete;
		offload_threads &operator=(const offload_threads &) = delete;
		~offload_threads() override { join(workers_); }// after shutdown(): nothing left

		// Runs `f` on a thread of its own. Throws std::system_error.
		template<class F> void start(F f)
		{
			reap();
			const std::lock_guard lock(mutex_);
			auto &w = workers_.emplace_back();
			try {
				w.thread = std::thread([f = std::move(f), &ended = w.ended]() mutable noexcept {
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
				const std::lock_guard lock(mutex_);
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
				const std::lock_guard lock(mutex_);
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

	// Runs a mechanism's offloaded step (sasl_work) on a thread of its own
	// (offload_threads) and waits for its result, within the operation
	// timeout and the stop token. Errors are without the bind's context
	// (sasl_bind adds it). The thread shares `offloaded` with this wait, so
	// giving up (timeout, cancellation, the task destroyed) leaves the work
	// running with what it owns; its wake() then latches a token nobody
	// reads, and the last owner frees the work and its result. The thread
	// holds work on the io_context until it is done, so run() returns only
	// after the work, and destroying the io_context waits for the thread to
	// end. A thread per call: the work blocks for as long as the network
	// takes (a Kerberos KDC), which a shared pool would spend its threads on.
	struct offloaded
	{
		explicit offloaded(sasl_work w) noexcept : work(std::move(w)) {}
		sasl_work work;
		std::optional<result<std::optional<std::string>>> value{};
		std::exception_ptr thrown{};
		capy::async_waker done{};
	};

}// namespace

capy::task<result<std::optional<std::string>>>
  run_offloaded(corosio::io_context::executor_type ex, std::optional<std::chrono::milliseconds> timeout, sasl_work work)
{
	// The thread posts its wakeup and drops its work from outside the
	// I/O thread, undefined behaviour under locking_mode::unsafe, so the
	// step fails at once there, as Corosio's resolver does (unsafe_io
	// cannot be told from safe: documented instead).
	if (corosio::detail::get_scheduler(ex.context()).scheduler_locking_disabled()) {
		co_return fail(std::make_error_code(std::errc::operation_not_supported),
		  "the mechanism's step runs on a thread of its own, which needs an io_context in locking_mode::safe");
	}
	auto shared = std::make_shared<offloaded>(std::move(work));
	try {
		auto &threads = ex.context().use_service<offload_threads>();
		threads.start([shared, guard = capy::work_guard(ex)]() mutable noexcept {
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
	const net::detail::deadline_t deadline =
	  timeout ? std::optional(net::detail::clock::now() + *timeout) : std::nullopt;
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
