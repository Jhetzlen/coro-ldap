#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <iostream>

using boost::asio::as_tuple;
using boost::asio::use_awaitable;
namespace exp = boost::asio::experimental;

// Define a channel that passes an error_code and an integer
using my_channel = exp::channel<void(boost::system::error_code, int)>;

boost::asio::awaitable<void> producer(my_channel& ch) {
    for (int i = 0; i < 5; ++i) {
        // Send the value 'i' into the channel
        co_await ch.async_send(boost::system::error_code{}, i, use_awaitable);
        std::cout << "Sent: " << i << std::endl;
    }
    ch.close();
}

boost::asio::awaitable<void> consumer(my_channel& ch) {
    while (ch.is_open()) {
        // Receive the value from the channel
        auto [ec, val] = co_await ch.async_receive(as_tuple(use_awaitable));
        if (!ec) {
            std::cout << "Received: " << val << std::endl;
        }
    }
}

int main() {
    try {
        boost::asio::io_context ctx;

        my_channel ch(ctx.get_executor(), 2);

        boost::asio::co_spawn(ctx, producer(ch), boost::asio::detached);
        boost::asio::co_spawn(ctx, consumer(ch), boost::asio::detached);

        ctx.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
