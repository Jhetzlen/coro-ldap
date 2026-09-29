// Echo server built on Boost.Corosio.
//
// Accepts TCP connections and writes back every byte it receives.
// Each connection runs in its own coroutine; there are no callbacks
// and no completion tokens: every I/O call is simply co_await'ed and
// returns a structured result (error code + bytes transferred).
//
// Usage: corosio_echo_server [port]   (default 8080)

#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/write.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

namespace corosio = boost::corosio;
namespace capy    = boost::capy;

// One coroutine per client. The socket is taken by value so the
// coroutine frame owns it for the whole session.
capy::task<> echo_session(corosio::tcp_socket sock, int id)
{
    char buf[4096];
    for (;;)
    {
        // read_some completes as soon as *some* bytes are available.
        auto [ec, n] = co_await sock.read_some(capy::mutable_buffer(buf, sizeof buf));
        if (ec)
            break; // EOF (client closed) or a real error

        // capy::write loops until the whole buffer has been sent.
        auto [wec, wn] = co_await capy::write(sock, capy::const_buffer(buf, n));
        if (wec)
            break;
    }
    std::cout << "[server] client #" << id << " disconnected" << std::endl;
    sock.close();
}

// Accept loop: wait for a connection, hand it to its own coroutine,
// go back to waiting.
capy::task<> accept_loop(corosio::io_context& ioc, std::uint16_t port)
{
    // Convenience constructor: open + SO_REUSEADDR + bind + listen.
    // Throws std::system_error on failure.
    corosio::tcp_acceptor acceptor(ioc, corosio::endpoint(port));
    std::cout << "[server] listening on port " << acceptor.local_endpoint().port() << std::endl;

    for (int next_id = 1;; ++next_id)
    {
        auto [ec, peer] = co_await acceptor.accept();
        if (ec)
        {
            std::cerr << "[server] accept failed: " << ec.message() << '\n';
            co_return;
        }
        std::cout << "[server] client #" << next_id << " connected" << std::endl;

        // Launch the session detached; the accept loop does not wait
        // for it. The task starts on the io_context's executor.
        capy::run_async(ioc.get_executor())(echo_session(std::move(peer), next_id));
    }
}

int main(int argc, char* argv[])
{
    std::uint16_t port = 8080;
    if (argc > 1)
    {
        int p = std::atoi(argv[1]);
        if (p <= 0 || p > 65535)
        {
            std::cerr << "Invalid port: " << argv[1] << '\n';
            return EXIT_FAILURE;
        }
        port = static_cast<std::uint16_t>(p);
    }

    corosio::io_context ioc;
    bool failed = false;

    // Without a handler, an exception escaping the task would call
    // std::terminate; report it instead (e.g. "address in use").
    capy::run_async(
        ioc.get_executor(),
        [] {},
        [&](std::exception_ptr ep)
        {
            failed = true;
            try
            {
                std::rethrow_exception(ep);
            }
            catch (std::exception const& e)
            {
                std::cerr << "[server] fatal: " << e.what() << '\n';
            }
        })(accept_loop(ioc, port));

    ioc.run();
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
