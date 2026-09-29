// Demonstrates result_future.hpp: getting results out of coroutines into
// synchronous code as std::expected values instead of exceptions.

#include "result_future.hpp"

#include <boost/capy/ex/work_guard.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace corosio = boost::corosio;
namespace capy    = boost::capy;
using namespace std::chrono_literals;

// A plain task returning a value.
capy::task<int> compute(int x)
{
    co_await corosio::delay(50ms);
    co_return x * 2;
}

// Error-code style task: reports failure through its return value.
// Pairs naturally with Corosio, whose operations return error codes.
capy::task<jhetz::result<void>> try_connect(corosio::io_context& ioc, std::uint16_t port)
{
    corosio::tcp_socket sock(ioc);
    auto [ec] = co_await sock.connect(corosio::endpoint(corosio::ipv4_address::loopback(), port));
    if (ec)
        co_return std::unexpected(ec);
    co_return jhetz::result<void>{};
}

// A task that throws: the exception becomes an error_code in the result.
capy::task<int> throws_logic_error()
{
    co_await corosio::delay(1ms);
    throw std::logic_error("boom");
}

template<class T>
void print(char const* label, jhetz::result<T> const& r)
{
    std::cout << label << ": ";
    if (!r)
        std::cout << "error [" << r.error().category().name() << "] " << r.error().message() << '\n';
    else if constexpr (std::is_void_v<T>)
        std::cout << "ok\n";
    else
        std::cout << "ok " << *r << '\n';
}

int main()
{
    // ---- 1) sync_wait on the calling thread --------------------------
    corosio::io_context ioc;

    print("compute(21)       ", jhetz::sync_wait(ioc, compute(21)));
    print("connect closed port", jhetz::sync_wait(ioc, try_connect(ioc, 1)));
    print("throwing task     ", jhetz::sync_wait(ioc, throws_logic_error()));

    // Monadic chaining works as with any std::expected.
    auto doubled = jhetz::sync_wait(ioc, compute(5)).transform([](int v) { return v * 10; });
    print("compute(5) * 10   ", doubled);

    // ---- 2) io_context on a background thread, futures elsewhere -----
    corosio::io_context bg;
    auto guard = capy::work_guard(bg.get_executor()); // keep run() alive while idle
    std::thread io_thread([&] { bg.run(); });

    auto f1 = jhetz::spawn_future(bg.get_executor(), compute(1));
    auto f2 = jhetz::spawn_future(bg.get_executor(), compute(2));

    std::cout << "f1 ready right away? " << std::boolalpha << f1.ready() << '\n';
    print("f1                ", f1.get());
    print("f2                ", f2.get());
    print("f1 again          ", f1.get()); // no_state, still no exception

    guard.reset();
    io_thread.join();

    // ---- 3) task never finishes: its context is destroyed first -------
    jhetz::result_future<int> orphan;
    {
        corosio::io_context never_run;
        orphan = jhetz::spawn_future(never_run.get_executor(), compute(3));
    } // never_run destroyed with the task still queued
    print("orphaned task     ", orphan.get());
}
