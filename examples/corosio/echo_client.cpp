// Echo client built on Boost.Corosio.
//
// Connects to the echo server, sends a few lines, reads each echo back
// and checks it matches.
//
// Usage: corosio_echo_client [ip] [port]   (default 127.0.0.1 8080)

#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/write.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace corosio = boost::corosio;
namespace capy    = boost::capy;

// Returns true when every message was echoed back unchanged.
capy::task<bool> run_client(corosio::io_context& ioc, corosio::endpoint ep)
{
    corosio::tcp_socket sock(ioc);

    // connect() opens the socket automatically.
    if (auto [ec] = co_await sock.connect(ep); ec)
    {
        std::cerr << "[client] connect failed: " << ec.message() << '\n';
        co_return false;
    }
    std::cout << "[client] connected to " << ep.address().to_string() << ':' << ep.port() << '\n';

    std::vector<std::string> const messages{"hello", "corosio", "coroutines all the way down"};

    for (auto const& msg : messages)
    {
        // Send the whole message...
        auto [wec, wn] = co_await capy::write(sock, capy::const_buffer(msg.data(), msg.size()));
        if (wec)
        {
            std::cerr << "[client] write failed: " << wec.message() << '\n';
            co_return false;
        }

        // ...then read exactly as many bytes back. capy::read keeps
        // reading until the buffer is full (unlike read_some).
        std::string reply(msg.size(), '\0');
        auto [rec, rn] = co_await capy::read(sock, capy::mutable_buffer(reply.data(), reply.size()));
        if (rec)
        {
            std::cerr << "[client] read failed: " << rec.message() << '\n';
            co_return false;
        }

        std::cout << "[client] sent \"" << msg << "\", got \"" << reply << "\"\n";
        if (reply != msg)
            co_return false;
    }

    sock.close();
    co_return true;
}

int main(int argc, char* argv[])
{
    char const* ip = argc > 1 ? argv[1] : "127.0.0.1";

    auto [aec, addr] = corosio::make_ipv4_address(ip);
    if (aec)
    {
        std::cerr << "Invalid IPv4 address: " << ip << '\n';
        return EXIT_FAILURE;
    }

    std::uint16_t port = 8080;
    if (argc > 2)
    {
        int p = std::atoi(argv[2]);
        if (p <= 0 || p > 65535)
        {
            std::cerr << "Invalid port: " << argv[2] << '\n';
            return EXIT_FAILURE;
        }
        port = static_cast<std::uint16_t>(p);
    }

    corosio::io_context ioc;

    // The first handler receives the task's result.
    bool ok = false;
    capy::run_async(ioc.get_executor(), [&](bool result) { ok = result; })(
        run_client(ioc, corosio::endpoint(addr, port)));

    ioc.run();

    std::cout << (ok ? "[client] all echoes matched\n" : "[client] FAILED\n");
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
