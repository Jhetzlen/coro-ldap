// The scripted in-process LDAP server of the connection tests, over a Unix
// socket pair. Not capy::test::stream: its wake() resumes a null handle.
#pragma once

#include "../../src/net/transport_layers.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/testing/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
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


inline const ldap::testing::read_options as_server{};
inline constexpr std::string_view admin = "cn=admin,dc=example,dc=org";
inline constexpr std::string_view people = "ou=people,dc=example,dc=org";

// ---------------------------------------------------------------- messages

inline auto entry_msg(std::int32_t id, std::string_view dn, std::string_view cn) -> ldap::message
{
	return ldap::message{
		id,
		ldap::search_result_entry{ dn,
		  { ldap::partial_attribute{ "cn", { cn } }, ldap::partial_attribute{ "objectClass", { "person", "top" } } } }
	};
}

// An entry with only cn, as a server answers a search for cn alone (a
// repository of a struct mapping only cn).
inline auto card_msg(std::int32_t id, std::string_view dn, std::string_view cn) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_entry{ dn, { ldap::partial_attribute{ "cn", { cn } } } } };
}

// entry_msg with only the attributes `search` asks for (all of them when it
// lists none or "*"), as a server answers.
inline auto entry_msg_for(const ldap::search_request &search, std::int32_t id, std::string_view dn, std::string_view cn)
  -> ldap::message
{
	auto m = entry_msg(id, dn, cn);
	const auto &wanted = search.attributes;
	if (wanted.empty() || std::ranges::find(wanted, "*") != wanted.end()) {
		return m;
	}
	auto &e = std::get<ldap::search_result_entry>(m.op);
	std::erase_if(e.attributes, [&](const ldap::partial_attribute &a) {
		return std::ranges::none_of(wanted, [&](std::string_view w) { return ldap::detail::iequals(w, a.type); });
	});
	return m;
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

// One script step: optionally read one request, send `replies`, optionally
// hang up; or, with expect_close, wait for the client to hang up.
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
			auto r = co_await ldap::testing::read_message(t, buf, as_server);
			if (r) {
				log.received.push_back(std::move(*r));
				log.error = "expected the client to hang up, got another request";
			} else if (r.error().code != capy::cond::eof) {
				log.error = "server read: " + std::string(r.error().message());
			}
			co_return;
		}
		if (st.read_request) {
			auto r = co_await ldap::testing::read_message(t, buf, as_server);
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

	// Over an io_context with the backend `backend` (corosio::uring, say)
	// made with `io`.
	template<class Backend>
		requires requires { Backend::construct; }
	mock_ldap(Backend backend, const corosio::io_context_options &io, const ldap::connection_options &options = {})
	  : ioc(backend, io)
	{
		conn = ldap::connection(ioc, net::transport::wrap(socket_ref{ &sockets.client }, "mock"), options);
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

// The kernel buffers of tcp_mock_ldap's sockets: the system's, or small
// fixed ones.
enum class socket_buffers { system, small };

// SO_SNDBUF and SO_RCVBUF with socket_buffers::small.
inline constexpr int small_socket_buffer = 64 * 1024;

// The client's SO_SNDBUF with socket_buffers::small. Winsock takes a whole
// overlapped send into its buffer whenever that holds less than SO_SNDBUF,
// so a 1 MiB write completes past a 64 KiB buffer and the writer never
// parks (coro-ldap-0wp). With 0 it buffers nothing: the send completes as
// the peer acknowledges it, and stays pending once the peer's window closes.
#ifdef _WIN32
inline constexpr int small_send_buffer = 0;
#else
inline constexpr int small_send_buffer = small_socket_buffer;
#endif

// ldap:// on a socket with a small SO_SNDBUF set before it connects; throws
// on error.
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
	if (auto ec = s.set_option(corosio::socket_option::send_buffer_size(small_send_buffer)); ec) {
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

// mock_ldap over loopback TCP, optionally with small socket buffers.
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

	// The connection allows cleartext passwords unless `cleartext` is false.
	explicit tcp_mock_ldap(ldap::connection_options options = {},
	  socket_buffers buffers = socket_buffers::system,
	  bool cleartext = true)
	{
		options.allow_cleartext_passwords = cleartext;
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
			// Close the connection, then end the accept before its operands go.
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

	auto url() const -> std::string { return "ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()); }

	// The server's end, to write outside the script.
	auto server_end() -> net::transport { return net::transport::wrap(socket_ref{ &peer }, "server"); }

	// socket_buffers::small: at most what the kernel holds of an unread PDU.
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

// One connection's script for script_server, over TLS from the start
// (ldaps://) or in clear.
struct session_script
{
	std::vector<step> script{};
	bool tls = false;
};

// Runs `script` on `peer`, after a server TLS handshake with `tls` unless
// it is null.
inline auto
  serve_session(corosio::tcp_socket &peer, std::vector<step> script, const corosio::tls_context *tls, server_log &log)
	-> capy::task<void>
{
	if (tls == nullptr) {
		co_await serve_script(net::transport::wrap(socket_ref{ &peer }, "server"), std::move(script), log);
		co_return;
	}
	corosio::openssl_stream s(&peer, *tls);
	auto [ec] = co_await s.handshake(corosio::tls_role::server);
	if (ec) {
		log.error = "server handshake: " + ec.message();
		co_return;
	}
	co_await serve_script(net::transport::wrap(socket_ref{ &s }, "server tls"), std::move(script), log);
}

// A loopback TCP server: accepts connections one after another, runs the
// n-th script on the n-th, then stops accepting.
class script_server
{
  public:
	// Every session over TLS with `tls`, if given. socket_buffers::small: the
	// accepted connections' receive buffer is small_socket_buffer.
	script_server(corosio::io_context &ioc,
	  std::vector<std::vector<step>> scripts,
	  std::optional<corosio::tls_context> tls = std::nullopt,
	  socket_buffers buffers = socket_buffers::system)
	  // NOLINTNEXTLINE(bugprone-use-after-move): a moved-from optional keeps its engagement
	  : script_server(ioc, sessions_of(std::move(scripts), tls.has_value()), std::move(tls), buffers)
	{}
	// The sessions with .tls over TLS with `tls`.
	script_server(corosio::io_context &ioc,
	  std::vector<session_script> sessions,
	  std::optional<corosio::tls_context> tls,
	  socket_buffers buffers = socket_buffers::system)
	  : ioc_(ioc), acc_(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), backlog),
		sessions_(std::move(sessions)), tls_(std::move(tls))
	{
		if (buffers == socket_buffers::small) {
			REQUIRE_FALSE(acc_.set_option(corosio::socket_option::receive_buffer_size(small_socket_buffer)));
		}
		spawn(ioc_, accept_loop(), accepting_);
	}
	script_server(const script_server &) = delete;
	auto operator=(const script_server &) -> script_server & = delete;
	~script_server() { shut_down(); }

	[[nodiscard]] auto port() const -> std::uint16_t { return port_; }
	[[nodiscard]] auto endpoint() const -> corosio::endpoint { return { corosio::ipv4_address::loopback(), port_ }; }
	[[nodiscard]] auto url(std::string_view scheme = "ldap") const -> ldap::url
	{
		auto u = ldap::url::parse(std::string(scheme) + "://127.0.0.1:" + std::to_string(port_));
		REQUIRE(u.has_value());
		return *u;
	}
	// Safe from another thread than the server's.
	[[nodiscard]] auto accepted() const -> std::size_t { return accepted_; }
	[[nodiscard]] auto log(std::size_t n) -> server_log & { return logs_.at(n); }
	[[nodiscard]] auto session(std::size_t n) -> outcome<void> & { return outcomes_.at(n); }
	// Every script was accepted and ran to its end.
	[[nodiscard]] auto finished() const -> bool
	{
		return accepting_.done() && std::ranges::all_of(outcomes_, [](const outcome<void> &o) { return o.done(); });
	}
	// The SO_RCVBUF of the server's end of the n-th connection, as the
	// kernel reports it.
	[[nodiscard]] auto receive_buffer(std::size_t n) const -> std::size_t
	{
		const auto [ec, received] = peers_.at(n).get_option<corosio::socket_option::receive_buffer_size>();
		REQUIRE_FALSE(ec);
		return static_cast<std::size_t>(received.value());
	}
	// The server closes the n-th connection.
	void drop(std::size_t n) { peers_.at(n).close(); }
	// The server resets the n-th connection (SO_LINGER 0: an RST, not a FIN).
	void reset(std::size_t n)
	{
		auto &p = peers_.at(n);
		REQUIRE_FALSE(p.set_option(corosio::socket_option::linger(true, 0)));
		p.close();
	}
	void shut_down()
	{
		acc_.close();
		for (auto &p : peers_) {
			p.close();
		}
	}

  private:
	static constexpr int backlog = 8;

	static auto sessions_of(std::vector<std::vector<step>> scripts, bool tls) -> std::vector<session_script>
	{
		std::vector<session_script> out;
		out.reserve(scripts.size());
		for (auto &s : scripts) {
			out.push_back({ .script = std::move(s), .tls = tls });
		}
		return out;
	}

	auto accept_loop() -> capy::task<void>
	{
		for (auto &s : sessions_) {
			auto &peer = peers_.emplace_back(ioc_);
			auto [ec] = co_await acc_.accept(peer);
			if (ec) {
				co_return;
			}
			auto &log = logs_.emplace_back();
			log.hang_up = [&peer] { peer.close(); };
			// Counted first: the session may run its whole script before
			// spawn() returns.
			++accepted_;
			const corosio::tls_context *tls = s.tls && tls_ ? &*tls_ : nullptr;
			spawn(ioc_, serve_session(peer, std::move(s.script), tls, log), outcomes_.emplace_back());
		}
		acc_.close();
	}

	corosio::io_context &ioc_;
	corosio::tcp_acceptor acc_;
	std::uint16_t port_ = acc_.local_endpoint().port();
	std::vector<session_script> sessions_;
	std::optional<corosio::tls_context> tls_;
	std::deque<corosio::tcp_socket> peers_{};
	std::deque<server_log> logs_{};
	std::deque<outcome<void>> outcomes_{};
	std::atomic<std::size_t> accepted_{ 0 };
	outcome<void> accepting_{};
};

// 1 MiB: more than the small buffers hold, less than max_message_size.
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
