#include <boost/capy.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <cstdio>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

auto mark(bool &ran) -> capy::task<>
{
	ran = true;
	co_return;
}

auto main() -> int
{
	corosio::io_context ioc;
	corosio::tls_context tls;
	corosio::tcp_socket socket(ioc);
	corosio::openssl_stream stream(&socket, tls);
	bool ran = false;
	capy::run_async(ioc.get_executor())(mark(ran));
	ioc.run();
	std::puts(ran ? "corosio ok" : "corosio: task did not run");
	return ran ? 0 : 1;
}
