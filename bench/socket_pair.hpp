// The network benchmarks' ldap::connection to an in-process server over a
// Unix socket pair.
#pragma once

#include "args.hpp"

#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/testing/message_io.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>

#include <print>
#include <variant>

namespace jhetz::ldap::bench {

struct socket_ref
{
	boost::corosio::local_stream_socket *s;
	template<boost::capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<boost::capy::ConstBufferSequence CB> auto write_some(CB buffers) { return s->write_some(buffers); }
};

// Answers each `Request` with the bytes answer(message) points to, until
// the client hangs up, another request comes, or answer() returns null.
template<class Request, class Answer> auto serve_each(net::transport t, Answer answer) -> boost::capy::task<void>
{
	net::read_buffer buf;
	const testing::read_options as_server{};
	while (true) {
		auto r = co_await testing::read_message(t, buf, as_server);
		if (!r || !std::holds_alternative<Request>(r->op)) {
			co_return;
		}
		const auto *bytes = answer(*r);
		if (bytes == nullptr || !co_await net::write_bytes(t, *bytes)) {
			co_return;
		}
	}
}

// Runs serve(server transport) and drive(ioc, connection, server socket)
// on one io_context over a Unix socket pair; false if the pair fails.
template<class Serve, class Drive> auto run_pair(Serve serve, Drive drive) -> bool
{
	boost::corosio::io_context ioc;
	boost::corosio::local_stream_socket client(ioc);
	boost::corosio::local_stream_socket server(ioc);
	if (boost::corosio::connect_pair(client, server)) {
		std::println(stderr, "connect_pair failed");
		return false;
	}
	connection c(ioc, net::transport::wrap(socket_ref{ &client }, "bench"));
	boost::capy::run_async(ioc.get_executor())(serve(net::transport::wrap(socket_ref{ &server }, "server")));
	boost::capy::run_async(ioc.get_executor())(drive(ioc, c, server));
	ioc.run();
	return true;
}

}// namespace jhetz::ldap::bench
