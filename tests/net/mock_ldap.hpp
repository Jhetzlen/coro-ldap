// The scripted in-process LDAP server used by the connection tests: the
// server end decodes requests with origin::client and answers with encoded
// responses from a script, over a Unix socket pair.
//
// Not capy::test::stream: at the pinned Capy commit its wake() posts the
// parked continuation by reference and then clears the handle while it is
// still queued, so a reader woken by the peer resumes a null handle. Its
// provide()-before-read use in message_io_tests.cpp never parks a reader.
#pragma once

#include "../../src/net/transport_layers.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace jhetz::ldap::test {

namespace net = jhetz::ldap::net;


inline const net::read_options as_server{ .decode = { .from = ldap::origin::client } };
inline constexpr std::string_view admin = "cn=admin,dc=example,dc=org";
inline constexpr std::string_view people = "ou=people,dc=example,dc=org";

// ---------------------------------------------------------------- messages

inline auto bind_resp(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {}) -> ldap::message
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ code, "", diagnostic } } };
}

inline auto entry_msg(std::int32_t id, std::string_view dn, std::string_view cn) -> ldap::message
{
	return ldap::message{
		id,
		ldap::search_result_entry{ dn,
		  { ldap::partial_attribute{ "cn", { cn } }, ldap::partial_attribute{ "objectClass", { "person", "top" } } } }
	};
}

inline auto expected_entry(std::string_view dn, std::string_view cn) -> ldap::entry
{
	return ldap::entry::from(std::get<ldap::search_result_entry>(entry_msg(1, dn, cn).op));
}

inline auto done_msg(std::int32_t id,
  std::int32_t code = 0,
  std::string_view matched = {},
  std::string_view diagnostic = {},
  std::initializer_list<std::string_view> referrals = {}) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_done{ ldap::ldap_result{ code, matched, diagnostic, referrals } } };
}

inline auto ref_msg(std::int32_t id, ldap::string_list uris) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_reference{ std::move(uris) } };
}

// ---------------------------------------------------------------- server

// One step of a server script: optionally wait for one request, then send
// `replies` (each written separately), then optionally hang up. Or, with
// expect_close, wait for the client to hang up: a request instead is logged
// and is an error. expect_close ignores read_request, replies and
// close_after.
struct step
{
	bool read_request = true;
	std::vector<std::string> replies{};
	bool close_after = false;
	bool expect_close = false;
};

inline auto answer(std::initializer_list<ldap::message> replies, bool close_after = false) -> step
{
	step s;
	for (const auto &m : replies) {
		s.replies.push_back(bytes_of(m));
	}
	s.close_after = close_after;
	return s;
}

// The client hangs up (a clean close, nothing more sent).
inline auto client_hangs_up() -> step
{
	step s;
	s.read_request = false;
	s.expect_close = true;
	return s;
}

struct server_log
{
	std::vector<ldap::message> received{};
	std::string error{};
	std::function<void()> hang_up{};
};

inline auto serve_script(net::transport t, std::vector<step> script, server_log &log) -> capy::task<void>
{
	net::read_buffer buf;
	for (auto &st : script) {
		if (st.expect_close) {
			auto r = co_await net::read_message(t, buf, as_server);
			if (r) {
				log.received.push_back(std::move(*r));
				log.error = "expected the client to hang up, got another request";
			} else if (r.error().code != capy::cond::eof) {
				log.error = "server read: " + std::string(r.error().message());
			}
			co_return;
		}
		if (st.read_request) {
			auto r = co_await net::read_message(t, buf, as_server);
			if (!r) {
				log.error = "server read: " + std::string(r.error().message());
				co_return;
			}
			log.received.push_back(std::move(*r));
		}
		for (const auto &bytes : st.replies) {
			if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
				log.error = "server write: " + std::string(w.error().message());
				co_return;
			}
		}
		if (st.close_after) {
			log.hang_up();
			co_return;
		}
	}
}

// Forwards to a socket owned elsewhere, so the test can still close it
// (transport::close() does nothing on a wrapped stream).
template<class Socket> struct socket_ref
{
	Socket *s;
	template<capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers) { return s->write_some(buffers); }
};

// Two connected Unix domain sockets.
struct socket_pair
{
	corosio::local_stream_socket client;
	corosio::local_stream_socket server;

	explicit socket_pair(corosio::io_context &ioc) : client(ioc), server(ioc)
	{
		const auto ec = corosio::connect_pair(client, server);
		if (ec) {
			throw std::system_error(ec, "connect_pair");
		}
	}
};

// What mock_ldap and tcp_mock_ldap share: `Self` has `ioc`, `log`,
// `server` (the script's outcome) and server_end().
template<class Self> struct scripted_server
{
	// Runs `script` on the server's end.
	void serve(std::vector<step> script)
	{
		auto &m = self();
		spawn(m.ioc, serve_script(m.server_end(), std::move(script), m.log), m.server);
	}

	// Runs `t` until it finishes; the server, parked on its next request,
	// is left as is.
	template<class T> auto run(capy::task<T> t) -> T { return finish(self().ioc, std::move(t)); }

	// The script ran to its end without errors.
	void check_server()
	{
		auto &m = self();
		drive_until(m.ioc, [&m] { return m.server.done(); });
		CHECK(m.log.error == "");
		CHECK(m.server.done());
	}

  private:
	friend Self;
	scripted_server() = default;

	auto self() -> Self & { return static_cast<Self &>(*this); }
};

// A connection over a socket pair, and a scripted server on the other end.
struct mock_ldap : scripted_server<mock_ldap>
{
	corosio::io_context ioc{};
	socket_pair sockets{ ioc };
	ldap::connection conn{};
	server_log log{};
	outcome<void> server{};

	explicit mock_ldap(const ldap::connection_options &options = {},
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  : conn(ioc, net::transport::wrap(socket_ref{ &sockets.client }, "mock"), options, mr)
	{
		log.hang_up = [this] { sockets.server.close(); };
	}

	// Over an io_context made with `io` (a locking_mode, say).
	explicit mock_ldap(const corosio::io_context_options &io, const ldap::connection_options &options = {})
	  : ioc(io), conn(ioc, net::transport::wrap(socket_ref{ &sockets.client }, "mock"), options)
	{
		log.hang_up = [this] { sockets.server.close(); };
	}

	mock_ldap(const mock_ldap &) = delete;
	auto operator=(const mock_ldap &) -> mock_ldap & = delete;

	~mock_ldap()
	{
		// Wake whatever still waits, so no coroutine is left suspended.
		sockets.client.close();
		sockets.server.close();
		drive(ioc);
	}

	// The server's end, to write outside the script.
	auto server_end() -> net::transport { return net::transport::wrap(socket_ref{ &sockets.server }, "server"); }
};

// The kernel buffers of tcp_mock_ldap's sockets: the system's (Linux
// autotunes them, up to the tcp_wmem / tcp_rmem sysctls), or small fixed
// ones, so that what the client can write while the server's end does not
// read is bounded whatever the host's settings (oversized_add()).
enum class socket_buffers { system, small };

// SO_SNDBUF and SO_RCVBUF asked for with socket_buffers::small. Linux
// doubles them (for its bookkeeping) and caps them at net.core.wmem_max /
// rmem_max; setting them also turns autotuning off.
inline constexpr int small_socket_buffer = 64 * 1024;

// What ldap::connect does for ldap://, but on a socket whose SO_SNDBUF is
// small_socket_buffer, set before it connects to `to`. `name` is the
// transport's name; `send_buffer` receives the SO_SNDBUF the kernel reports.
// Errors are thrown.
inline auto connect_small_tcp(corosio::io_context &ioc,
  corosio::endpoint to,
  std::string name,
  ldap::connection_options options,
  std::size_t *send_buffer) -> capy::task<ldap::connection>
{
	corosio::tcp_socket s(ioc);
	if (auto ec = s.open(); ec) {
		throw std::system_error(ec, "open");
	}
	if (auto ec = s.set_option(corosio::socket_option::send_buffer_size(small_socket_buffer)); ec) {
		throw std::system_error(ec, "SO_SNDBUF");
	}
	if (auto [ec] = co_await s.connect(to); ec) {
		throw std::system_error(ec, "connect");
	}
	const auto [sec, sent] = s.get_option<corosio::socket_option::send_buffer_size>();
	if (sec) {
		throw std::system_error(sec, "SO_SNDBUF");
	}
	*send_buffer = static_cast<std::size_t>(sent.value());
	net::transport t = net::transport_access::make(net::transport::kind::tcp, name, std::pmr::get_default_resource());
	auto &im = net::transport_access::get(t);
	im.host = "127.0.0.1";
	im.tcp.emplace(std::move(s));
	im.stream = capy::any_stream(&*im.tcp);
	co_return ldap::connection(ioc, std::move(t), options);
}

// mock_ldap over loopback TCP: the transport is plain TCP, so start_tls()
// sends its request (the server can only refuse it: it does not speak TLS).
// The connection is made by ldap::connect, or with socket_buffers::small
// from a socket of the test's own with a small send buffer (connect() sets
// no buffer sizes); the server's end has a small receive buffer then.
struct tcp_mock_ldap : scripted_server<tcp_mock_ldap>
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
	corosio::tcp_socket peer{ ioc };
	ldap::connection conn{};
	server_log log{};
	outcome<void> server{};
	// socket_buffers::small: the client's SO_SNDBUF as the kernel reports it.
	std::size_t client_send_buffer = 0;

	explicit tcp_mock_ldap(const ldap::connection_options &options = {},
	  socket_buffers buffers = socket_buffers::system)
	{
		// The accepted socket inherits it; set before the client connects,
		// so the window offered from the start is the small one.
		if (buffers == socket_buffers::small) {
			REQUIRE_FALSE(acc.set_option(corosio::socket_option::receive_buffer_size(small_socket_buffer)));
		}
		outcome<void> accepted;
		spawn(
		  ioc,
		  [](corosio::tcp_acceptor &a, corosio::tcp_socket &p) -> capy::task<void> {
			  auto [ec] = co_await a.accept(p);
			  if (ec) {
				  throw std::system_error(ec, "accept");
			  }
		  }(acc, peer),
		  accepted);
		try {
			if (buffers == socket_buffers::small) {
				conn = finish(ioc, connect_small(options));
			} else {
				auto u = ldap::url::parse(url());
				REQUIRE(u.has_value());
				auto c = finish(ioc, ldap::connect(ioc, *u, options));
				REQUIRE(c.has_value());
				conn = std::move(*c);
			}
			drive_until(ioc, [&accepted] { return accepted.done(); });
			accepted.get();
		} catch (...) {
			// No destructor runs: close the connection, as the destructor
			// does, then end the accept, which refers to `accepted`, `acc` and
			// `peer`, before they go.
			conn.close();
			acc.close();
			peer.close();
			drive_until(ioc, [&accepted] { return accepted.done(); });
			throw;
		}
		log.hang_up = [this] { peer.close(); };
	}

	tcp_mock_ldap(const tcp_mock_ldap &) = delete;
	auto operator=(const tcp_mock_ldap &) -> tcp_mock_ldap & = delete;

	~tcp_mock_ldap()
	{
		conn.close();
		peer.close();
		drive(ioc);
	}

	// The URL the connection was made to.
	auto url() const -> std::string { return "ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()); }

	// The server's end, to write outside the script.
	auto server_end() -> net::transport { return net::transport::wrap(socket_ref{ &peer }, "server"); }

	// socket_buffers::small: at most what the kernel holds of a PDU the
	// client writes while the server's end does not read (the client's send
	// buffer and the server's receive buffer, as reported: on Linux they
	// include the bookkeeping, so the data they hold is less).
	auto buffered_at_most() const -> std::size_t
	{
		const auto [ec, received] = peer.get_option<corosio::socket_option::receive_buffer_size>();
		REQUIRE_FALSE(ec);
		return client_send_buffer + static_cast<std::size_t>(received.value());
	}

  private:
	auto connect_small(ldap::connection_options options) -> capy::task<ldap::connection>
	{
		return connect_small_tcp(ioc, acc.local_endpoint(), url(), std::move(options), &client_send_buffer);
	}
};

// An AddRequest of 1 MiB: several times what tcp_mock_ldap with
// socket_buffers::small holds while the server's end does not read (check
// buffered_at_most()), so the writer is still busy with it until the server
// reads. Less than read_options::max_message_size, so the server can read
// it then.
inline constexpr std::size_t oversized_add_value = std::size_t{ 1 } << 20;
inline auto oversized_add() -> ldap::add_params
{
	return { .entry = ldap::dn{ "uid=big,ou=people,dc=example,dc=org" },
		.attributes = { ldap::partial_attribute{ "description", { std::string(oversized_add_value, 'x') } } } };
}

inline auto people_search() -> ldap::search_params
{
	return { .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .filter = ldap::filters::attr("uid") == "jdoe" };
}

// Reads a stream to its end: the entries, or the first error.
inline auto drain_stream(ldap::search_stream &s) -> capy::task<ldap::result<std::vector<ldap::entry>>>
{
	std::vector<ldap::entry> out;
	while (true) {
		auto e = co_await s.next();
		if (!e) {
			co_return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			co_return out;
		}
		out.push_back(std::move(**e));
	}
}

}// namespace jhetz::ldap::test
