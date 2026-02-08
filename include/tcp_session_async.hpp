#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/redirect_error.hpp>

#include <cstdlib>
#include <string>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;

template<typename T>
class tcp_session_async
{
    net::any_io_executor context_;
    net::ip::tcp::resolver resolver_;
    beast::tcp_stream stream_;
    beast::flat_buffer buffer;
     
public:
    tcp_session_async(
        net::any_io_executor exec)
        : context_{exec}, 
        resolver_{context_},
        stream_{context_}
    {
    }
    
    auto connect(std::string host, std::string port) -> net::awaitable<beast::error_code> 
    {
        boost::beast::error_code ec;
        stream_.expires_after(std::chrono::seconds(30));
        auto const results = co_await resolver_.async_resolve(host, port,net::redirect_error(net::use_awaitable, ec));
        if(ec)
            co_return ec;
        co_await stream_.async_connect(results, net::redirect_error(net::use_awaitable, ec));
        co_return ec;
    }

    template<typename Body>
    auto request(http::request<Body> request) -> net::awaitable<http::response<http::dynamic_body>>
    {   
        // TODO return error code 
        request.prepare_payload();
        co_await http::async_write(stream_, request);
        http::response<http::dynamic_body> res;
        co_await http::async_read(stream_, buffer, res, net::use_awaitable);
        co_return res;
    }

    auto close() -> net::awaitable<void>
    {
        // TODO: waht about closing ? uh
    }
};
