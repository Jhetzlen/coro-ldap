// The scripted in-process LDAP server used by the connection tests: the
// server end decodes requests with origin::client and answers with encoded
// responses from a script, over a Unix socket pair.
//
// Not capy::test::stream: at the pinned Capy commit its wake() posts the
// parked continuation by reference and then clears the handle while it is
// still queued, so a reader woken by the peer resumes a null handle. Its
// provide()-before-read use in message_io_tests.cpp never parks a reader.
#pragma once

#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>

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

inline ldap::message bind_resp(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {})
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ code, "", diagnostic } } };
}

inline ldap::message entry_msg(std::int32_t id, std::string_view dn, std::string_view cn)
{
	return ldap::message{
		id,
		ldap::search_result_entry{ dn,
		  { ldap::partial_attribute{ "cn", { cn } }, ldap::partial_attribute{ "objectClass", { "person", "top" } } } }
	};
}

inline ldap::entry expected_entry(std::string_view dn, std::string_view cn)
{
	return ldap::entry::from(std::get<ldap::search_result_entry>(entry_msg(1, dn, cn).op));
}

inline ldap::message done_msg(std::int32_t id,
  std::int32_t code = 0,
  std::string_view matched = {},
  std::string_view diagnostic = {},
  std::initializer_list<std::string_view> referrals = {})
{
	return ldap::message{ id, ldap::search_result_done{ ldap::ldap_result{ code, matched, diagnostic, referrals } } };
}

inline ldap::message ref_msg(std::int32_t id, ldap::string_list uris)
{
	return ldap::message{ id, ldap::search_result_reference{ std::move(uris) } };
}

// ---------------------------------------------------------------- server

// One step of a server script: optionally wait for one request, then send
// `replies` (each written separately), then optionally hang up.
struct step
{
	bool read_request = true;
	std::vector<std::string> replies{};
	bool close_after = false;
};

inline step answer(std::initializer_list<ldap::message> replies, bool close_after = false)
{
	step s;
	for (const auto &m : replies) s.replies.push_back(bytes_of(m));
	s.close_after = close_after;
	return s;
}

struct server_log
{
	std::vector<ldap::message> received{};
	std::string error{};
	std::function<void()> hang_up{};
};

inline capy::task<void> serve_script(net::transport t, std::vector<step> script, server_log &log)
{
	net::read_buffer buf;
	for (auto &st : script) {
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
		if (ec) throw std::system_error(ec, "connect_pair");
	}
};

// A connection over a socket pair, and a scripted server on the other end.
struct mock_ldap
{
	corosio::io_context ioc{};
	socket_pair sockets{ ioc };
	ldap::connection conn{};
	server_log log{};
	outcome<void> server{};

	explicit mock_ldap(ldap::connection_options options = {},
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  : conn(ioc, net::transport::wrap(socket_ref{ &sockets.client }, "mock"), options, mr)
	{
		log.hang_up = [this] { sockets.server.close(); };
	}

	mock_ldap(const mock_ldap &) = delete;
	mock_ldap &operator=(const mock_ldap &) = delete;

	~mock_ldap()
	{
		// Wake whatever still waits, so no coroutine is left suspended.
		sockets.client.close();
		sockets.server.close();
		drive(ioc);
	}

	// The server's end, to write outside the script.
	net::transport server_end() { return net::transport::wrap(socket_ref{ &sockets.server }, "server"); }

	void serve(std::vector<step> script) { spawn(ioc, serve_script(server_end(), std::move(script), log), server); }

	// Runs `t` until it finishes; the server, parked on its next request,
	// is left as is.
	template<class T> T run(capy::task<T> t)
	{
		outcome<T> out;
		spawn(ioc, std::move(t), out);
		drive_until(ioc, [&out] { return out.done(); });
		if constexpr (std::is_void_v<T>)
			out.get();
		else
			return std::move(out.get());
	}

	// The script ran to its end without errors.
	void check_server()
	{
		drive_until(ioc, [this] { return server.done(); });
		CHECK(log.error == "");
		CHECK(server.done());
	}
};

// mock_ldap over loopback TCP: the connection is made by ldap::connect, so
// its transport is plain TCP and start_tls() sends its request (the server
// can only refuse it: it does not speak TLS).
struct tcp_mock_ldap
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
	corosio::tcp_socket peer{ ioc };
	ldap::connection conn{};
	server_log log{};
	outcome<void> server{};

	explicit tcp_mock_ldap(ldap::connection_options options = {})
	{
		outcome<void> accepted;
		spawn(
		  ioc,
		  [](corosio::tcp_acceptor &a, corosio::tcp_socket &p) -> capy::task<void> {
			  auto [ec] = co_await a.accept(p);
			  if (ec) throw std::system_error(ec, "accept");
		  }(acc, peer),
		  accepted);
		auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
		REQUIRE(u.has_value());
		auto c = finish(ioc, ldap::connect(ioc, *u, options));
		REQUIRE(c.has_value());
		conn = std::move(*c);
		drive_until(ioc, [&accepted] { return accepted.done(); });
		accepted.get();
		log.hang_up = [this] { peer.close(); };
	}

	tcp_mock_ldap(const tcp_mock_ldap &) = delete;
	tcp_mock_ldap &operator=(const tcp_mock_ldap &) = delete;

	~tcp_mock_ldap()
	{
		conn.close();
		peer.close();
		drive(ioc);
	}

	net::transport server_end() { return net::transport::wrap(socket_ref{ &peer }, "server"); }

	void serve(std::vector<step> script) { spawn(ioc, serve_script(server_end(), std::move(script), log), server); }

	template<class T> T run(capy::task<T> t)
	{
		outcome<T> out;
		spawn(ioc, std::move(t), out);
		drive_until(ioc, [&out] { return out.done(); });
		if constexpr (std::is_void_v<T>)
			out.get();
		else
			return std::move(out.get());
	}

	void check_server()
	{
		drive_until(ioc, [this] { return server.done(); });
		CHECK(log.error == "");
		CHECK(server.done());
	}
};

inline ldap::search_params people_search()
{
	return { .base = ldap::dn{ "ou=people,dc=example,dc=org" }, .filter = ldap::filters::attr("uid") == "jdoe" };
}

// Reads a stream to its end: the entries, or the first error.
inline capy::task<ldap::result<std::vector<ldap::entry>>> drain_stream(ldap::search_stream &s)
{
	std::vector<ldap::entry> out;
	while (true) {
		auto e = co_await s.next();
		if (!e) co_return std::unexpected(std::move(e.error()));
		if (!*e) co_return out;
		out.push_back(std::move(**e));
	}
}

}// namespace jhetz::ldap::test
