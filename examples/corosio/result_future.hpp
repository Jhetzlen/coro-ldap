// Bridges between Corosio/Capy coroutines and synchronous code, without
// exceptions: results come back as std::expected<T, std::error_code>.
//
//   spawn_future(ex, task)  start a task, get a result_future<T> (any thread)
//   sync_wait(ioc, task)    run a task to completion on the calling thread
//
// A task may return either T or std::expected<T, std::error_code>; the
// latter is flattened, so both give a result_future<T>. Anything that would
// otherwise surface as an exception is turned into an error_code instead:
//
//   std::system_error escaping the task  -> its code()
//   std::bad_alloc                       -> std::errc::not_enough_memory
//   any other exception                  -> bridge_errc::unhandled_exception
//   task destroyed before completing     -> std::future_errc::broken_promise
//   get() called twice / empty future    -> std::future_errc::no_state
//
// Requires C++23 (<expected>).

#pragma once

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <future>
#include <memory>
#include <new>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

namespace jhetz {

// ---- error category for exceptions that are not std::system_error ------

enum class bridge_errc
{
    unhandled_exception = 1,
};

inline std::error_category const& bridge_category() noexcept
{
    struct category final : std::error_category
    {
        char const* name() const noexcept override { return "jhetz.bridge"; }
        std::string message(int ev) const override
        {
            switch (static_cast<bridge_errc>(ev))
            {
            case bridge_errc::unhandled_exception:
                return "task exited with an unhandled exception";
            }
            return "unknown bridge error";
        }
    };
    static category const cat;
    return cat;
}

inline std::error_code make_error_code(bridge_errc e) noexcept
{
    return {static_cast<int>(e), bridge_category()};
}

} // namespace jhetz

template<>
struct std::is_error_code_enum<jhetz::bridge_errc> : std::true_type
{
};

namespace jhetz {

template<class T>
using result = std::expected<T, std::error_code>;

namespace detail {

// task<T> and task<result<T>> both produce a result_future<T>.
template<class T>
struct unwrap_result
{
    using type = T;
};
template<class T>
struct unwrap_result<std::expected<T, std::error_code>>
{
    using type = T;
};

inline std::error_code to_error_code(std::exception_ptr ep) noexcept
{
    try
    {
        std::rethrow_exception(ep);
    }
    catch (std::system_error const& e)
    {
        return e.code();
    }
    catch (std::bad_alloc const&)
    {
        return std::make_error_code(std::errc::not_enough_memory);
    }
    catch (...)
    {
        return bridge_errc::unhandled_exception;
    }
}

} // namespace detail

/** A std::future whose get() returns result<T> and never throws. */
template<class T>
class result_future
{
    std::future<result<T>> f_;

public:
    result_future() = default;
    explicit result_future(std::future<result<T>> f) noexcept : f_(std::move(f)) {}

    /// Block until the task finishes; the result can be taken only once.
    [[nodiscard]] result<T> get() noexcept
    {
        try
        {
            return f_.get();
        }
        catch (std::future_error const& e)
        {
            return std::unexpected(e.code());
        }
    }

    /// True once get() would return without blocking.
    [[nodiscard]] bool ready() const
    {
        return valid() && f_.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    }

    /// Wait up to `d`; returns ready().
    template<class Rep, class Period>
    bool wait_for(std::chrono::duration<Rep, Period> d) const
    {
        return valid() && f_.wait_for(d) == std::future_status::ready;
    }

    void wait() const
    {
        if (valid())
            f_.wait();
    }

    /// False after get() or when default-constructed.
    [[nodiscard]] bool valid() const noexcept { return f_.valid(); }
};

/** Start `t` on executor `ex` and return a future for its result.

    Safe to call from any thread. Never block on the future from the
    thread that runs `ex`'s context: that thread is the one that has
    to finish the task, so it would wait forever.
*/
template<class Ex, class R>
auto spawn_future(Ex ex, boost::capy::task<R> t)
    -> result_future<typename detail::unwrap_result<R>::type>
{
    using T = typename detail::unwrap_result<R>::type;

    auto p = std::make_shared<std::promise<result<T>>>();
    auto f = p->get_future();

    auto on_error = [p](std::exception_ptr ep) { p->set_value(std::unexpected(detail::to_error_code(ep))); };

    if constexpr (std::is_void_v<R>)
        boost::capy::run_async(ex, [p] { p->set_value(result<void>{}); }, on_error)(std::move(t));
    else
        // Covers both R = T (wrapped into result<T>) and R = result<T> (moved as is).
        boost::capy::run_async(ex, [p](R v) { p->set_value(result<T>(std::move(v))); }, on_error)(std::move(t));

    return result_future<T>(std::move(f));
}

/** Run `t` to completion on the calling thread and return its result.

    Drives `ioc` until it has no more work, so use it only where nothing
    else is running that context (main, tests, a synchronous facade).
*/
template<class R>
auto sync_wait(boost::corosio::io_context& ioc, boost::capy::task<R> t)
    -> result<typename detail::unwrap_result<R>::type>
{
    auto f = spawn_future(ioc.get_executor(), std::move(t));
    ioc.restart();
    ioc.run();
    return f.get();
}

} // namespace jhetz
