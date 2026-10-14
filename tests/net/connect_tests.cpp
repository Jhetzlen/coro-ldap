// net::connect against in-process servers on loopback: TCP, TLS (throwaway
// CA generated at run time) and Unix domain sockets. No external server, no
// fixed ports (the kernel picks them), no sleeps: every wait ends on an
// event, and the timeouts tested are the library's own.
#include "../../src/net/happy_eyeballs.hpp"
#include "../../src/net/tls.hpp"
#include "../counting_resource.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/local_stream_acceptor.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <openssl/err.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <system_error>
#include <utility>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::EndsWith;
using Catch::Matchers::StartsWith;
using ldap::client_errc;

// ---------------------------------------------------------------- DNS seam
//
// getaddrinfo is interposed for this test binary (Corosio calls it on a pool
// thread; the real one is reached through RTLD_NEXT, via the sanitizer's own
// interceptor when there is one). Names outside these two test prefixes go
// to the real resolver unchanged.
//   slow-dns-*   answers 127.0.0.1 after slow_dns_delay: a lookup that no
//                timeout can interrupt
//   two-addr-*   answers 127.0.0.2, then 127.0.0.1 (same port)
//   no-ip-*      succeeds with only non-IP (AF_UNIX) entries, which the
//                resolver drops: a lookup with no usable address
//   stop-dns-*   requests stop on lookup_stop (from the lookup's thread),
//                then answers 127.0.0.1 after slow_dns_delay: a connect
//                stopped while the lookup runs
namespace {
constexpr auto slow_dns_delay = std::chrono::milliseconds(1000);
std::atomic<std::stop_source *> lookup_stop{ nullptr };
}// namespace

extern "C" auto getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
  -> int
{
	using fn = int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
	static const auto real = reinterpret_cast<fn>(dlsym(RTLD_NEXT, "getaddrinfo"));
	const std::string_view name = node != nullptr ? node : "";
	if (name.starts_with("slow-dns-")) {
		std::this_thread::sleep_for(slow_dns_delay);
		return real("127.0.0.1", service, hints, res);
	}
	if (name.starts_with("no-ip-")) {
		if (int rc = real("127.0.0.1", service, hints, res); rc != 0) {
			return rc;
		}
		for (struct addrinfo *p = *res; p != nullptr; p = p->ai_next) {
			p->ai_family = AF_UNIX;
		}
		return 0;
	}
	if (name.starts_with("stop-dns-")) {
		if (auto *stop = lookup_stop.load(); stop != nullptr) {
			stop->request_stop();
		}
		std::this_thread::sleep_for(slow_dns_delay);
		return real("127.0.0.1", service, hints, res);
	}
	if (name.starts_with("two-addr-")) {
		struct addrinfo v4 = hints != nullptr ? *hints : addrinfo{};
		v4.ai_family = AF_INET;
		struct addrinfo *first = nullptr, *second = nullptr;
		if (int rc = real("127.0.0.2", service, &v4, &first); rc != 0) {
			return rc;
		}
		if (int rc = real("127.0.0.1", service, &v4, &second); rc != 0) {
			freeaddrinfo(first);
			return rc;
		}
		struct addrinfo *tail = first;
		while (tail->ai_next != nullptr) {
			tail = tail->ai_next;
		}
		tail->ai_next = second;// glibc frees the nodes one by one, so chaining is fine
		*res = first;
		return 0;
	}
	return real(node, service, hints, res);
}

namespace {

const net::read_options as_server{ .decode = { .from = ldap::origin::client } };

// Serves one connection: [TLS handshake], read a bind request, answer it,
// then wait for the client to go away. Returns "" or what went wrong.
auto serve_one(net::transport t) -> capy::task<std::string>
{
	net::read_buffer buf;
	auto req = co_await net::read_message(t, buf, as_server);
	if (!req) {
		co_return "server read: " + std::string(req.error().message());
	}
	if (*req != bind_request_msg(1)) {
		co_return "server: unexpected request";
	}
	if (auto w = co_await net::write_message(t, bind_response_msg(1, "welcome")); !w) {
		co_return "server write: " + std::string(w.error().message());
	}
	auto end = co_await net::read_message(t, buf, as_server);
	co_return end ? "server: unexpected second request" : "";
}

template<class Acceptor>
auto accept_and_serve(Acceptor &acc, std::optional<corosio::tls_context> tls = std::nullopt) -> capy::task<std::string>
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		co_return "accept: " + ec.message();
	}
	if (!tls) {
		co_return co_await serve_one(net::transport::wrap(std::move(peer), "server"));
	}
	corosio::openssl_stream stream(std::move(peer), *tls);
	auto [hec] = co_await stream.handshake(corosio::tls_role::server);
	if (hec) {
		co_return "server handshake: " + hec.message();
	}
	co_return co_await serve_one(net::transport::wrap(std::move(stream), "server"));
}

// Accepts, then reads until the client goes away without ever writing.
auto accept_and_stay_silent(corosio::tcp_acceptor &acc) -> capy::task<void>
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		co_return;
	}
	char buf[4096];
	while (true) {
		auto [rec, n] = co_await peer.read_some(capy::mutable_buffer(buf, sizeof buf));
		if (rec) {
			co_return;
		}
	}
}

// Accepts and hangs up at once.
auto accept_and_close(corosio::tcp_acceptor &acc) -> capy::task<void>
{
	auto [ec, peer] = co_await acc.accept();
	peer.close();
}

// Connects, sends a bind request, checks the answer. Returns "" or the error.
auto exchange(corosio::io_context &ioc, std::string text, net::connect_options options = {}, bool expect_tls = false)
  -> capy::task<std::string>
{
	auto u = ldap::url::parse(text);
	if (!u) {
		co_return "url: " + std::string(u.error().message());
	}
	auto t = co_await net::connect(ioc, *u, options);
	if (!t) {
		co_return "connect: " + std::string(t.error().message());
	}
	if (!t->is_open()) {
		co_return "transport not open";
	}
	if (t->is_tls() != expect_tls) {
		co_return "unexpected is_tls()";
	}
	if (auto w = co_await net::write_message(*t, bind_request_msg(1)); !w) {
		co_return "client write: " + std::string(w.error().message());
	}
	net::read_buffer buf;
	auto r = co_await net::read_message(*t, buf);
	if (!r) {
		co_return "client read: " + std::string(r.error().message());
	}
	if (*r != bind_response_msg(1, "welcome")) {
		co_return "client: unexpected response";
	}
	t->close();
	CHECK_FALSE(t->is_open());
	co_return "";
}

struct tcp_server
{
	corosio::tcp_acceptor acc;
	std::uint16_t port;
	explicit tcp_server(corosio::io_context &ioc, int backlog = 128)
	  : acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), backlog), port(acc.local_endpoint().port())
	{}
	auto url(const char *scheme, const char *host = "127.0.0.1") const -> std::string
	{
		return std::string(scheme) + "://" + host + ":" + std::to_string(port);
	}
};

auto connect_to(corosio::io_context &ioc, const std::string &text, net::connect_options options = {})
  -> ldap::result<net::transport>
{
	auto u = ldap::url::parse(text);
	REQUIRE(u.has_value());
	return run(ioc, net::connect(ioc, *u, std::move(options)));
}

auto server_context(const test_pki::issued &leaf) -> corosio::tls_context
{
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem));
	return ctx;
}

// One PKI for the whole test binary: key generation is the slow part.
auto pki() -> test_pki &
{
	static test_pki instance;
	return instance;
}

auto localhost_cert() -> const test_pki::issued &
{
	static const auto leaf = pki().issue("localhost", "DNS:localhost,IP:127.0.0.1");
	return leaf;
}

}// namespace

// ---------------------------------------------------------------- TCP

TEST_CASE("connect ldap:// to a loopback server and exchange messages", "[net][connect][tcp]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(srv.acc), server);
	spawn(ioc, exchange(ioc, srv.url("ldap")), client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
}

TEST_CASE("connect timeout semantics", "[net][connect][tcp][timeout]")
{
	// nullopt and values too large for the clock: no limit.
	for (auto limit : { std::optional<std::chrono::milliseconds>{}, std::optional(std::chrono::milliseconds::max()) }) {
		corosio::io_context ioc;
		tcp_server srv(ioc);
		outcome<std::string> server, client;
		spawn(ioc, accept_and_serve(srv.acc), server);
		spawn(ioc, exchange(ioc, srv.url("ldap"), { .timeout = limit }), client);
		drive(ioc);
		CHECK(client.get() == "");
		CHECK(server.get() == "");
	}
	// Zero or negative: fails at once, before any traffic.
	for (auto limit : { std::chrono::milliseconds(0), std::chrono::milliseconds(-5) }) {
		corosio::io_context ioc;
		auto t = connect_to(ioc, "ldap://127.0.0.1:1", { .timeout = limit });
		REQUIRE_FALSE(t.has_value());
		CHECK(t.error().code == capy::cond::timeout);
		CHECK(t.error().code == ldap::cond::timeout);
		CHECK(std::string(t.error().context)
			  == "connect ldap://127.0.0.1:1: the connect timeout (" + std::to_string(limit.count())
				   + " ms) is not positive");
	}
}

TEST_CASE("connect timeout holds while the name lookup blocks", "[net][connect][timeout][dns]")
{
	// Timestamped when connect() returns, not when the io_context runs out
	// of work: Corosio keeps the context busy until getaddrinfo returns.
	std::chrono::steady_clock::duration elapsed{};
	{
		corosio::io_context ioc;
		outcome<ldap::error> out;
		spawn(
		  ioc,
		  [](corosio::io_context &io, std::chrono::steady_clock::duration &took) -> capy::task<ldap::error> {
			  const auto start = std::chrono::steady_clock::now();
			  auto t = co_await net::connect(
				io, *ldap::url::parse("ldap://slow-dns-a.test:1"), { .timeout = std::chrono::milliseconds(200) });
			  took = std::chrono::steady_clock::now() - start;
			  co_return t ? ldap::error{} : t.error();
		  }(ioc, elapsed),
		  out);
		drive(ioc);
		const auto &e = out.get();
		CHECK(e.code == capy::cond::timeout);
		CHECK(e.context
			  == "connect ldap://slow-dns-a.test:1: resolve slow-dns-a.test: gave up after the 200 ms connect timeout");
		// drive() waits for the lookup to finish (Corosio counts it as work),
		// so the detached lookup completes and frees everything here.
	}
	INFO("connect returned after " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms");
	CHECK(elapsed >= std::chrono::milliseconds(150));
	CHECK(elapsed < std::chrono::milliseconds(700));// the lookup itself takes 1000 ms

	// A slow lookup within the budget still succeeds.
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(srv.acc), server);
	spawn(ioc, exchange(ioc, srv.url("ldap", "slow-dns-b.test"), { .timeout = std::chrono::seconds(10) }), client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
}

namespace {

// A listener on `addr`:`port` with backlog 0 whose one queue slot is taken:
// Linux drops further SYNs, so a connect to it stays pending (see the TCP
// timeout test below).
struct blackhole
{
	corosio::tcp_acceptor acc;
	corosio::tcp_socket filler;
	blackhole(corosio::io_context &ioc, const char *addr, std::uint16_t port) : acc(make(ioc, addr, port)), filler(ioc)
	{
		auto [fec] = run(ioc, [](corosio::tcp_socket &s, corosio::endpoint ep) -> capy::task<capy::io_result<>> {
			co_return co_await s.connect(ep);
		}(filler, acc.local_endpoint()));
		REQUIRE_FALSE(fec);
	}
	static auto make(corosio::io_context &ioc, const char *addr, std::uint16_t port) -> corosio::tcp_acceptor
	{
		auto [aec, a] = corosio::make_ipv4_address(addr);
		REQUIRE_FALSE(aec);
		return corosio::tcp_acceptor(ioc, corosio::endpoint(a, port), 0);
	}
};

}// namespace

TEST_CASE("Happy Eyeballs: a black-holed first address costs the attempt delay", "[net][connect][tcp][timeout][dns]")
{
	skip_unless_linux_loopback();
	// two-addr-* resolves to 127.0.0.2 first, then 127.0.0.1. The attempt on
	// 127.0.0.2 hangs; 127.0.0.1 is tried 200 ms later, side by side, and
	// wins long before the 10 s budget.
	corosio::io_context ioc;
	tcp_server good(ioc);
	blackhole hole(ioc, "127.0.0.2", good.port);

	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(good.acc), server);
	const auto start = std::chrono::steady_clock::now();
	spawn(ioc,
	  exchange(ioc,
		good.url("ldap", "two-addr-a.test"),
		{ .timeout = std::chrono::seconds(10), .attempt_delay = std::chrono::milliseconds(200) }),
	  client);
	drive(ioc);
	const auto elapsed = std::chrono::steady_clock::now() - start;
	CHECK(client.get() == "");
	CHECK(server.get() == "");
	INFO("connected after " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms");
	CHECK(elapsed >= std::chrono::milliseconds(150));// the second attempt waited for the delay
	CHECK(elapsed < std::chrono::seconds(5));
}

TEST_CASE("Happy Eyeballs: a refused address starts the next attempt at once", "[net][connect][tcp][dns]")
{
	skip_unless_linux_loopback();
	// Nothing listens on 127.0.0.2:<port>: that attempt is refused at once,
	// so 127.0.0.1 does not wait out the (long) attempt delay.
	corosio::io_context ioc;
	tcp_server good(ioc);
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(good.acc), server);
	const auto start = std::chrono::steady_clock::now();
	spawn(ioc,
	  exchange(ioc,
		good.url("ldap", "two-addr-b.test"),
		{ .timeout = std::chrono::seconds(30), .attempt_delay = std::chrono::seconds(20) }),
	  client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
	CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(5));
}

TEST_CASE("Happy Eyeballs: every address fails", "[net][connect][tcp][dns]")
{
	skip_unless_linux_loopback();
	corosio::io_context ioc;
	std::string url;
	{
		tcp_server srv(ioc);// take a free port, then release it
		url = srv.url("ldap", "two-addr-c.test");
	}
	auto t = connect_to(ioc, url, { .attempt_delay = std::chrono::milliseconds(0) });
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == std::errc::connection_refused);
	CHECK_THAT(std::string(t.error().context), StartsWith("connect " + url + ": tcp connect 127.0.0."));
	CHECK_THAT(std::string(t.error().context), EndsWith(" (2 of 2 addresses tried)"));
}

TEST_CASE("Happy Eyeballs: the budget covers every attempt", "[net][connect][tcp][timeout][dns]")
{
	skip_unless_linux_loopback();
	corosio::io_context ioc;
	tcp_server srv(ioc, 0);
	blackhole first(ioc, "127.0.0.2", srv.port);
	corosio::tcp_socket filler(ioc);
	auto [fec] = run(ioc, [](corosio::tcp_socket &s, corosio::endpoint ep) -> capy::task<capy::io_result<>> {
		co_return co_await s.connect(ep);
	}(filler, corosio::endpoint(corosio::ipv4_address::loopback(), srv.port)));
	REQUIRE_FALSE(fec);

	const auto start = std::chrono::steady_clock::now();
	auto t = connect_to(ioc,
	  srv.url("ldap", "two-addr-d.test"),
	  { .timeout = std::chrono::milliseconds(400), .attempt_delay = std::chrono::milliseconds(100) });
	const auto elapsed = std::chrono::steady_clock::now() - start;
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == capy::cond::timeout);
	CHECK_THAT(std::string(t.error().context), ContainsSubstring("(2 of 2 addresses tried)"));
	CHECK_THAT(std::string(t.error().context), EndsWith("gave up after the 400 ms connect timeout"));
	CHECK(elapsed >= std::chrono::milliseconds(350));
	CHECK(elapsed < std::chrono::seconds(10));
}

TEST_CASE("Happy Eyeballs: address families alternate", "[net][connect]")
{
	auto v4 = [](const char *a) {
		auto [ec, addr] = corosio::make_ipv4_address(a);
		REQUIRE_FALSE(ec);
		return corosio::endpoint(addr, 389);
	};
	auto v6 = [](const char *a) {
		auto [ec, addr] = corosio::make_ipv6_address(a);
		REQUIRE_FALSE(ec);
		return corosio::endpoint(addr, 389);
	};
	using list = std::vector<corosio::endpoint>;
	CHECK(net::detail::interleave_families({}).empty());
	CHECK(
	  net::detail::interleave_families({ v4("10.0.0.1"), v4("10.0.0.2") }) == list{ v4("10.0.0.1"), v4("10.0.0.2") });
	CHECK(net::detail::interleave_families({ v6("::1"), v6("::2"), v6("::3"), v4("10.0.0.1") })
		  == list{ v6("::1"), v4("10.0.0.1"), v6("::2"), v6("::3") });
	CHECK(net::detail::interleave_families({ v4("10.0.0.1"), v4("10.0.0.2"), v6("::1"), v6("::2") })
		  == list{ v4("10.0.0.1"), v6("::1"), v4("10.0.0.2"), v6("::2") });
}

TEST_CASE("connect ldap://localhost resolves the name", "[net][connect][tcp]")
{
	corosio::io_context ioc;
	tcp_server srv(
	  ioc);// IPv4 only: if localhost resolves to ::1 first, that attempt is refused and 127.0.0.1 is tried next
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(srv.acc), server);
	spawn(ioc, exchange(ioc, srv.url("ldap", "localhost")), client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
}

TEST_CASE("transport identity after connect", "[net][connect][tcp]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<void> server;
	spawn(ioc, accept_and_close(srv.acc), server);
	auto t = connect_to(ioc, srv.url("LDAP") + "/dc=example?cn?sub");
	REQUIRE(t.has_value());
	CHECK(t->type() == net::transport::kind::tcp);
	CHECK_FALSE(t->is_tls());
	CHECK(t->is_open());
	CHECK(std::string_view(t->name()) == srv.url("ldap"));// scheme://host:port only
	server.get();
	t->close();
	CHECK_FALSE(t->is_open());
	t->close();// idempotent
}

TEST_CASE("connection refused", "[net][connect][tcp]")
{
	corosio::io_context ioc;
	std::string url;
	{
		tcp_server srv(ioc);// take a free port, then release it
		url = srv.url("ldap");
	}
	auto t = connect_to(ioc, url);
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == std::errc::connection_refused);
	CHECK(std::string(t.error().context) == "connect " + url + ": tcp connect " + url.substr(7));
	CHECK_THAT(std::string(t.error().message()), StartsWith("connect " + url + ": tcp connect "));
}

TEST_CASE("connect timeout while the TCP handshake cannot complete", "[net][connect][tcp][timeout]")
{
	skip_unless_linux_loopback();
	// A listening socket with backlog 0 whose one queue slot is taken: Linux
	// drops further SYNs, so the next connect stays pending deterministically
	// (a listening socket that merely never accepts would complete the TCP
	// handshake in the kernel).
	corosio::io_context ioc;
	tcp_server srv(ioc, 0);
	corosio::tcp_socket filler(ioc);
	auto [fec] = run(ioc, [](corosio::tcp_socket &s, corosio::endpoint ep) -> capy::task<capy::io_result<>> {
		co_return co_await s.connect(ep);
	}(filler, corosio::endpoint(corosio::ipv4_address::loopback(), srv.port)));
	REQUIRE_FALSE(fec);

	const auto start = std::chrono::steady_clock::now();
	auto t = connect_to(ioc, srv.url("ldap"), { .timeout = std::chrono::milliseconds(300) });
	const auto elapsed = std::chrono::steady_clock::now() - start;
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == capy::cond::timeout);
	CHECK(t.error().code == ldap::cond::timeout);
	CHECK_THAT(std::string(t.error().context), ContainsSubstring(": tcp connect 127.0.0.1:"));
	CHECK_THAT(std::string(t.error().context), ContainsSubstring("gave up after the 300 ms connect timeout"));
	CHECK(elapsed >= std::chrono::milliseconds(250));
	CHECK(elapsed < std::chrono::seconds(10));
}

TEST_CASE("unresolvable host", "[net][connect][tcp]")
{
	corosio::io_context ioc;
	// .invalid never resolves (RFC 6761). Without DNS access the lookup may
	// fail differently or time out; both are reported at the resolve stage.
	auto t = connect_to(ioc, "ldap://no-such-host.invalid", { .timeout = std::chrono::seconds(5) });
	REQUIRE_FALSE(t.has_value());
	CHECK_THAT(std::string(t.error().context),
	  StartsWith("connect ldap://no-such-host.invalid:389: resolve no-such-host.invalid"));
	CHECK(t.error().code);
}

TEST_CASE("a lookup with no usable address", "[net][connect][tcp][dns]")
{
	corosio::io_context ioc;
	auto t = connect_to(ioc, "ldap://no-ip-a.test:1");
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == std::errc::no_such_device_or_address);
	CHECK(std::string(t.error().context) == "connect ldap://no-ip-a.test:1: resolve no-ip-a.test");
}

TEST_CASE("connect stopped during the name lookup", "[net][connect][cancel][dns]")
{
	// The stop comes while getaddrinfo still runs: connect returns at once,
	// the late answer is dropped.
	std::chrono::steady_clock::duration elapsed{};
	corosio::io_context ioc;
	std::stop_source stop;
	lookup_stop = &stop;
	outcome<ldap::error> out;
	spawn(
	  ioc,
	  stop.get_token(),
	  [](corosio::io_context &io, std::chrono::steady_clock::duration &took) -> capy::task<ldap::error> {
		  const auto start = std::chrono::steady_clock::now();
		  auto t = co_await net::connect(io, *ldap::url::parse("ldap://stop-dns-a.test:1"));
		  took = std::chrono::steady_clock::now() - start;
		  co_return t ? ldap::error{} : t.error();
	  }(ioc, elapsed),
	  out);
	drive(ioc);// until the detached lookup has finished too
	lookup_stop = nullptr;
	const auto &e = out.get();
	CHECK(e.code == capy::cond::canceled);
	CHECK(e.code == ldap::cond::canceled);
	CHECK(e.context == "connect ldap://stop-dns-a.test:1: resolve stop-dns-a.test");
	INFO("connect returned after " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms");
	CHECK(elapsed < std::chrono::milliseconds(700));// the lookup itself takes 1000 ms
}

// The decoded host is quoted sanitized and cut (as an operation's DN): the
// URL is often a server's (a referral). U+202E and U+0085 become U+FFFD, the
// accented letter stays; the encoded URL in the prefix is ASCII already,
// cut at 256 bytes like the host. Neither name resolves (.invalid, RFC 6761;
// a label over 63 bytes): without DNS access the lookup may fail
// differently or time out, at the same stage.
TEST_CASE("connect: the resolve context quotes the decoded host sanitized and cut", "[net][connect][tcp]")
{
	corosio::io_context ioc;
	const net::connect_options limited{ .timeout = std::chrono::seconds(5) };
	auto starts_resolve = [](const ldap::error &e, const std::string &expected) {
		const std::string context(e.context);
		CHECK_THAT(context, StartsWith(expected));
		const std::string rest = context.substr(std::min(expected.size(), context.size()));
		CHECK((rest.empty() || rest == ": gave up after the 5000 ms connect timeout"));
	};

	auto bidi = connect_to(ioc, "ldap://%E2%80%AE%C2%85caf%C3%A9.invalid/", limited);
	REQUIRE_FALSE(bidi.has_value());
	starts_resolve(bidi.error(),
	  "connect ldap://%E2%80%AE%C2%85caf%C3%A9.invalid:389: resolve \xEF\xBF\xBD\xEF\xBF\xBD"
	  "caf\xC3\xA9.invalid");

	const std::string label(300, 'a');
	auto long_host = connect_to(ioc, "ldap://" + label + ".invalid/", limited);
	REQUIRE_FALSE(long_host.has_value());
	starts_resolve(long_host.error(),
	  "connect " + ("ldap://" + label).substr(0, 256) + "...: resolve " + label.substr(0, 256) + "...");
}

namespace {

// A listener on an IPv6 address, if this host has one. `zone` is the
// interface name for a link-local address, empty otherwise.
struct ipv6_server
{
	std::optional<corosio::tcp_acceptor> acc{};
	std::string address{};// as in a certificate's iPAddress ("::1")
	std::string zone{};

	// [::1]
	static auto loopback(corosio::io_context &ioc) -> ipv6_server
	{
		ipv6_server s;
		s.listen(ioc, corosio::ipv6_address::loopback(), "::1", "");
		return s;
	}

	// The first link-local address of an up, non-loopback interface (glibc
	// only accepts a zone on a link-local address, so [::1%25lo] cannot be
	// used).
	static auto link_local(corosio::io_context &ioc) -> ipv6_server
	{
		ipv6_server s;
		ifaddrs *list = nullptr;
		if (::getifaddrs(&list) != 0) {
			return s;
		}
		for (ifaddrs *i = list; i != nullptr && !s.acc; i = i->ifa_next) {
			if (i->ifa_addr == nullptr || i->ifa_addr->sa_family != AF_INET6) {
				continue;
			}
			if ((i->ifa_flags & IFF_UP) == 0 || (i->ifa_flags & IFF_LOOPBACK) != 0) {
				continue;
			}
			const auto *sa = reinterpret_cast<const sockaddr_in6 *>(i->ifa_addr);
			if (!IN6_IS_ADDR_LINKLOCAL(&sa->sin6_addr)) {
				continue;
			}
			corosio::ipv6_address::bytes_type bytes{};
			std::memcpy(bytes.data(), &sa->sin6_addr, bytes.size());
			char text[INET6_ADDRSTRLEN] = {};
			::inet_ntop(AF_INET6, &sa->sin6_addr, text, sizeof text);
			s.listen(ioc, corosio::ipv6_address(bytes, sa->sin6_scope_id), text, i->ifa_name);
		}
		::freeifaddrs(list);
		return s;
	}

	auto url(const char *scheme) const -> std::string
	{
		std::string host = "[" + address + (zone.empty() ? "" : "%25" + zone) + "]";
		return std::string(scheme) + "://" + host + ":" + std::to_string(acc->local_endpoint().port());
	}

  private:
	void listen(corosio::io_context &ioc, corosio::ipv6_address a, std::string text, std::string z)
	{
		try {
			acc.emplace(ioc, corosio::endpoint(a, 0), 16);
			address = std::move(text);
			zone = std::move(z);
		} catch (const std::system_error &) {// IPv6 disabled, or the address is not usable yet
			acc.reset();
		}
	}
};

void exchange_over(corosio::io_context &ioc, ipv6_server &v6)
{
	SECTION("ldap://")
	{
		outcome<std::string> server, client;
		spawn(ioc, accept_and_serve(*v6.acc), server);
		spawn(ioc, exchange(ioc, v6.url("ldap")), client);
		drive(ioc);
		CHECK(client.get() == "");
		CHECK(server.get() == "");
	}
	SECTION("ldaps://: the certificate's iPAddress matches (without the zone)")
	{
		const auto leaf = pki().issue("ipv6", "IP:" + v6.address);
		outcome<std::string> server, client;
		spawn(ioc, accept_and_serve(*v6.acc, server_context(leaf)), server);
		spawn(
		  ioc, exchange(ioc, v6.url("ldaps"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } }, true), client);
		drive(ioc);
		CHECK(client.get() == "");
		CHECK(server.get() == "");
	}
}

}// namespace

TEST_CASE("connect over the IPv6 loopback", "[net][connect][tcp][tls][ipv6]")
{
	corosio::io_context ioc;
	auto v6 = ipv6_server::loopback(ioc);
	if (!v6.acc) {
		SKIP("no IPv6 loopback");
	}
	exchange_over(ioc, v6);
}

TEST_CASE("connect to a link-local IPv6 address with a zone", "[net][connect][tcp][tls][ipv6]")
{
	corosio::io_context ioc;
	auto v6 = ipv6_server::link_local(ioc);
	if (!v6.acc) {
		SKIP("no usable link-local IPv6 address");
	}
	INFO(v6.url("ldap"));
	exchange_over(ioc, v6);
}

TEST_CASE("URLs connect() refuses", "[net][connect]")
{
	corosio::io_context ioc;
	auto no_host = connect_to(ioc, "ldap:///dc=example");
	REQUIRE_FALSE(no_host.has_value());
	CHECK(no_host.error().code == client_errc::invalid_url);
	CHECK(std::string(no_host.error().context)
		  == "connect ldap://:389: the URL names no host (or, for ldapi, no socket path)");

	auto no_path = connect_to(ioc, "ldapi://");
	REQUIRE_FALSE(no_path.has_value());
	CHECK(no_path.error().code == client_errc::invalid_url);

	for (auto text : { "ldaps://evil%00.example.org", "ldap://a%0Ab", "ldap://a%7F", "ldapi://%2Ftmp%2Fa%00b" }) {
		auto control = connect_to(ioc, text);
		INFO(text);
		REQUIRE_FALSE(control.has_value());
		CHECK(control.error().code == client_errc::invalid_url);
		CHECK_THAT(std::string(control.error().context), EndsWith(": control character in the host"));
	}

	auto critical = connect_to(ioc,
	  "ldap://127.0.0.1:1/????"
	  "!x-unknown");
	REQUIRE_FALSE(critical.has_value());
	CHECK(critical.error().code == client_errc::invalid_url);
	CHECK_THAT(std::string(critical.error().context), ContainsSubstring("unsupported critical extension x-unknown"));
}

// ---------------------------------------------------------------- ldapi

TEST_CASE("connect ldapi:// to a Unix domain socket", "[net][connect][ldapi]")
{
	corosio::io_context ioc;
	temp_path sock(".sock");
	corosio::local_stream_acceptor acc(ioc);
	REQUIRE_FALSE(acc.open());
	REQUIRE_FALSE(acc.bind(corosio::local_endpoint(sock.str()), corosio::bind_option::unlink_existing));
	REQUIRE_FALSE(acc.listen());

	const std::string url = "ldapi://" + percent_encode(sock.str());
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(acc), server);
	spawn(ioc, exchange(ioc, url), client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
}

TEST_CASE("ldapi:// errors", "[net][connect][ldapi]")
{
	corosio::io_context ioc;
	temp_path missing(".sock");// never created
	auto t = connect_to(ioc, "ldapi://" + percent_encode(missing.str()));
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == std::errc::no_such_file_or_directory);
	CHECK_THAT(std::string(t.error().context), ContainsSubstring(": connect " + missing.str()));

	// The decoded path is quoted sanitized: U+2028 becomes U+FFFD, the
	// accented letter stays.
	temp_path odd(
	  "-x\xE2\x80\xA8"
	  "caf\xC3\xA9.sock");// never created
	auto sanitized = connect_to(ioc, "ldapi://" + percent_encode(odd.str()));
	REQUIRE_FALSE(sanitized.has_value());
	CHECK(sanitized.error().code == std::errc::no_such_file_or_directory);
	std::string shown = odd.str();
	shown.replace(shown.find("\xE2\x80\xA8"), 3, "\xEF\xBF\xBD");
	CHECK_THAT(std::string(sanitized.error().context), StartsWith("connect ldapi://"));
	CHECK_THAT(std::string(sanitized.error().context), EndsWith(": connect " + shown));

	auto too_long = connect_to(ioc, "ldapi://" + percent_encode("/" + std::string(200, 'x')));
	REQUIRE_FALSE(too_long.has_value());
	CHECK(too_long.error().code == std::errc::filename_too_long);
}

// ---------------------------------------------------------------- TLS

TEST_CASE("ldaps:// with the CA configured", "[net][connect][tls]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server, client;

	SECTION("CA as PEM text, IP address certificate")
	{
		spawn(ioc, accept_and_serve(srv.acc, server_context(localhost_cert())), server);
		spawn(ioc,
		  exchange(ioc, srv.url("ldaps"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } }, true),
		  client);
	}
	SECTION("CA file holding a bundle, DNS name certificate")
	{
		// Our CA second in the file: every certificate of a bundle is used.
		test_pki other("unrelated CA");
		temp_path bundle(".pem");
		bundle.write(other.ca_pem() + pki().ca_pem());
		spawn(ioc, accept_and_serve(srv.acc, server_context(localhost_cert())), server);
		spawn(ioc, exchange(ioc, srv.url("ldaps", "localhost"), { .tls = { .ca_file = bundle.str() } }, true), client);
		drive(ioc);
	}
	SECTION("server_name for a certificate that does not name the address")
	{
		const auto leaf = pki().issue("ldap.example.org", "DNS:ldap.example.org");
		spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
		spawn(ioc,
		  exchange(ioc,
			srv.url("ldaps"),
			{ .tls = { .ca_pem = std::pmr::string(pki().ca_pem()), .server_name = "ldap.example.org" } },
			true),
		  client);
	}
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
}

TEST_CASE("ldaps:// verification failures", "[net][connect][tls]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server;
	std::optional<ldap::result<net::transport>> t;

	SECTION("untrusted CA with the default (system) trust store")
	{
		spawn(ioc, accept_and_serve(srv.acc, server_context(localhost_cert())), server);
		t = connect_to(ioc, srv.url("ldaps"));
		REQUIRE_FALSE(t->has_value());
		CHECK_THAT(std::string(t->error().context),
		  StartsWith("connect " + srv.url("ldaps") + ": tls handshake: server certificate: "));
	}
	SECTION("host name mismatch")
	{
		const auto leaf = pki().issue("other.example", "DNS:other.example");
		spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
		t = connect_to(ioc, srv.url("ldaps", "localhost"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
		REQUIRE_FALSE(t->has_value());
		CHECK_THAT(std::string(t->error().context),
		  ContainsSubstring("tls handshake: server certificate: hostname mismatch", Catch::CaseSensitive::No));
	}
	SECTION("IP address mismatch")
	{
		const auto leaf = pki().issue("localhost", "DNS:localhost");
		spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
		t = connect_to(ioc, srv.url("ldaps"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
		REQUIRE_FALSE(t->has_value());
		CHECK_THAT(std::string(t->error().context),
		  ContainsSubstring("tls handshake: server certificate: IP address mismatch", Catch::CaseSensitive::No));
	}
	drive(ioc);
	CHECK(t->error().code);// the handshake's own error code is kept
	CHECK(t->error().code == ldap::cond::tls_failure);
	CHECK_THAT(server.get(), StartsWith("server handshake: "));
}

// RFC 6125 / RFC 4513 section 3.1.3: by default only subjectAltName DNS
// names count (no subject CN fallback) and a wildcard is a whole leftmost
// label; host_name_matching::legacy restores OpenSSL's defaults.
TEST_CASE("ldaps:// host name matching", "[net][connect][tls][rfc]")
{
	struct case_t
	{
		const char *name;
		const char *cn;
		const char *sans;
		bool strict_ok;
		bool legacy_ok;
	};
	const std::vector<case_t> cases{
		{ "exact subjectAltName", "x", "DNS:ldap.example.org", true, true },
		{ "whole-label wildcard", "x", "DNS:*.example.org", true, true },
		{ "subject CN only, no subjectAltName", "ldap.example.org", "", false, true },
		{ "partial wildcard", "x", "DNS:ld*.example.org", false, true },
		{ "subject CN ignored when subjectAltName names another host",
		  "ldap.example.org",
		  "DNS:other.example.org",
		  false,
		  false },
	};
	for (const auto &c : cases) {
		for (const auto matching : { net::host_name_matching::strict, net::host_name_matching::legacy }) {
			const bool strict = matching == net::host_name_matching::strict;
			DYNAMIC_SECTION(c.name << (strict ? ", strict" : ", legacy"))
			{
				corosio::io_context ioc;
				tcp_server srv(ioc);
				outcome<std::string> server;
				const auto leaf = pki().issue(c.cn, c.sans);
				spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
				const net::connect_options o{ .tls = { .ca_pem = std::pmr::string(pki().ca_pem()),
												.server_name = "ldap.example.org",
												.host_matching = matching } };
				if (strict ? c.strict_ok : c.legacy_ok) {
					outcome<std::string> client;
					spawn(ioc, exchange(ioc, srv.url("ldaps"), o, true), client);
					drive(ioc);
					CHECK(client.get() == "");
					CHECK(server.get() == "");
				} else {
					auto t = connect_to(ioc, srv.url("ldaps"), o);
					REQUIRE_FALSE(t.has_value());
					CHECK(t.error().code == ldap::cond::tls_failure);
					CHECK_THAT(std::string(t.error().context),
					  ContainsSubstring("server certificate: hostname mismatch", Catch::CaseSensitive::No));
					drive(ioc);
					CHECK_THAT(server.get(), StartsWith("server handshake: "));
				}
			}
		}
	}
}

TEST_CASE("ldaps:// insecure opt-out accepts an untrusted certificate", "[net][connect][tls]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	const auto leaf = pki().issue("other.example", "DNS:other.example");// untrusted and for another name
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
	spawn(ioc,
	  exchange(ioc,
		srv.url("ldaps", "localhost"),
		{ .tls = { .verification = net::certificate_verification::insecure_accept_any } },
		true),
	  client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");
}

TEST_CASE("ldaps:// client certificate", "[net][connect][tls]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	auto ctx = server_context(localhost_cert());
	REQUIRE_FALSE(ctx.set_verify_mode(corosio::tls_verify_mode::require_peer));
	REQUIRE_FALSE(ctx.add_certificate_authority(pki().ca_pem()));

	const auto client_leaf = pki().issue("client", "DNS:client.example");
	temp_path cert(".crt"), key(".key");
	cert.write(client_leaf.cert_pem);
	key.write(client_leaf.key_pem);

	outcome<std::string> server, client;
	SECTION("presented")
	{
		spawn(ioc, accept_and_serve(srv.acc, ctx), server);
		spawn(ioc,
		  exchange(ioc,
			srv.url("ldaps"),
			{ .tls = { .ca_pem = std::pmr::string(pki().ca_pem()), .cert_file = cert.str(), .key_file = key.str() } },
			true),
		  client);
		drive(ioc);
		CHECK(client.get() == "");
		CHECK(server.get() == "");
	}
	SECTION("missing")
	{
		spawn(ioc, accept_and_serve(srv.acc, ctx), server);
		spawn(ioc,
		  exchange(ioc, srv.url("ldaps"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } }, true),
		  client);
		drive(ioc);
		// With TLS 1.3 the client may finish its handshake before the server
		// rejects it, so the failure shows up in connect or in the first read.
		CHECK_FALSE(client.get().empty());
		CHECK_THAT(server.get(), StartsWith("server handshake: "));
	}
}

TEST_CASE("ldaps:// handshake timeout against a silent server", "[net][connect][tls][timeout]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<void> server;
	spawn(ioc, accept_and_stay_silent(srv.acc), server);
	const auto start = std::chrono::steady_clock::now();
	auto t = connect_to(ioc,
	  srv.url("ldaps"),
	  { .timeout = std::chrono::milliseconds(300), .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
	const auto elapsed = std::chrono::steady_clock::now() - start;
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == capy::cond::timeout);
	CHECK(t.error().code == ldap::cond::timeout);
	CHECK(std::string(t.error().context)
		  == "connect " + srv.url("ldaps") + ": tls handshake: gave up after the 300 ms connect timeout");
	CHECK(elapsed >= std::chrono::milliseconds(250));
	CHECK(elapsed < std::chrono::seconds(10));
	server.get();
}

TEST_CASE("TLS configuration errors fail before connecting", "[net][connect][tls]")
{
	corosio::io_context ioc;
	// Port 1 on loopback: nothing is contacted, the configuration is checked first.
	auto half = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = "/nonexistent.crt" } });
	REQUIRE_FALSE(half.has_value());
	CHECK(half.error().code == std::errc::invalid_argument);
	CHECK(std::string(half.error().context)
		  == "connect ldaps://127.0.0.1:1: tls: cert_file and key_file must be given together");

	auto missing = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_file = "/nonexistent/ca.pem" } });
	REQUIRE_FALSE(missing.has_value());
	CHECK(missing.error().code == std::errc::no_such_file_or_directory);
	CHECK_THAT(std::string(missing.error().context), ContainsSubstring("tls: ca_file /nonexistent/ca.pem"));

	auto not_pem = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_pem = "garbage" } });
	REQUIRE_FALSE(not_pem.has_value());
	CHECK_THAT(std::string(not_pem.error().context), ContainsSubstring("tls: ca_pem: no PEM certificate found"));

	// PEM armour around garbage: parsed now, not at handshake time.
	const std::string broken = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
	auto bad_cert =
	  connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_pem = std::pmr::string(pki().ca_pem() + broken) } });
	REQUIRE_FALSE(bad_cert.has_value());
	CHECK(bad_cert.error().code == std::errc::invalid_argument);
	CHECK_THAT(std::string(bad_cert.error().context), EndsWith("tls: ca_pem: certificate 2 of 2 does not parse"));

	temp_path bad_file(".pem");
	bad_file.write(broken);
	auto bad_ca_file = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_file = bad_file.str() } });
	REQUIRE_FALSE(bad_ca_file.has_value());
	CHECK_THAT(std::string(bad_ca_file.error().context), EndsWith(": certificate 1 of 1 does not parse"));

	auto no_dir = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_dir = "/nonexistent/certs" } });
	REQUIRE_FALSE(no_dir.has_value());
	CHECK(no_dir.error().code == std::errc::no_such_file_or_directory);
	CHECK_THAT(std::string(no_dir.error().context), EndsWith("tls: ca_dir /nonexistent/certs"));

	auto file_dir = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_dir = bad_file.str() } });
	REQUIRE_FALSE(file_dir.has_value());
	CHECK(file_dir.error().code == std::errc::not_a_directory);

	// Client certificate and key are parsed and matched before connecting too.
	const auto one = pki().issue("client-one", "DNS:client-one");
	const auto two = pki().issue("client-two", "DNS:client-two");
	temp_path cert_one(".crt"), key_one(".key"), key_two(".key"), junk(".pem");
	cert_one.write(one.cert_pem);
	key_one.write(one.key_pem);
	key_two.write(two.key_pem);
	junk.write("not pem at all\n");

	auto junk_cert =
	  connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = junk.str(), .key_file = key_one.str() } });
	REQUIRE_FALSE(junk_cert.has_value());
	CHECK(junk_cert.error().code == std::errc::invalid_argument);
	CHECK_THAT(std::string(junk_cert.error().context), EndsWith(": no parseable PEM certificate"));

	auto junk_key =
	  connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = cert_one.str(), .key_file = junk.str() } });
	REQUIRE_FALSE(junk_key.has_value());
	CHECK(junk_key.error().code == std::errc::invalid_argument);
	CHECK_THAT(std::string(junk_key.error().context), ContainsSubstring(": no parseable PEM private key"));

	auto mismatch =
	  connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = cert_one.str(), .key_file = key_two.str() } });
	REQUIRE_FALSE(mismatch.has_value());
	CHECK(mismatch.error().code == std::errc::invalid_argument);
	CHECK_THAT(
	  std::string(mismatch.error().context), ContainsSubstring(": does not match the certificate in tls: cert_file"));

	// Each file is read before connecting: a missing one is named.
	auto no_cert = connect_to(
	  ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = "/nonexistent/client.crt", .key_file = key_one.str() } });
	REQUIRE_FALSE(no_cert.has_value());
	CHECK(no_cert.error().code == std::errc::no_such_file_or_directory);
	CHECK(
	  std::string(no_cert.error().context) == "connect ldaps://127.0.0.1:1: tls: cert_file /nonexistent/client.crt");

	auto no_key = connect_to(
	  ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = cert_one.str(), .key_file = "/nonexistent/client.key" } });
	REQUIRE_FALSE(no_key.has_value());
	CHECK(no_key.error().code == std::errc::no_such_file_or_directory);
	CHECK(std::string(no_key.error().context) == "connect ldaps://127.0.0.1:1: tls: key_file /nonexistent/client.key");

	// An encrypted key is refused without prompting for its passphrase.
	temp_path encrypted(".key");
	encrypted.write(test_pki::encrypted_key_pem(one.key_pem, "passphrase"));
	auto locked =
	  connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = cert_one.str(), .key_file = encrypted.str() } });
	REQUIRE_FALSE(locked.has_value());
	CHECK(locked.error().code == std::errc::invalid_argument);
	CHECK(std::string(locked.error().context)
		  == "connect ldaps://127.0.0.1:1: tls: key_file " + encrypted.str()
			   + ": no parseable PEM private key (encrypted keys are not supported)");

	// A CA file without any PEM certificate.
	auto empty_ca_file = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_file = junk.str() } });
	REQUIRE_FALSE(empty_ca_file.has_value());
	CHECK(empty_ca_file.error().code == std::errc::invalid_argument);
	CHECK(std::string(empty_ca_file.error().context)
		  == "connect ldaps://127.0.0.1:1: tls: ca_file " + junk.str() + ": no PEM certificate found");

	// A valid pair passes the checks and fails only when connecting.
	auto valid =
	  connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .cert_file = cert_one.str(), .key_file = key_one.str() } });
	REQUIRE_FALSE(valid.has_value());
	CHECK_THAT(std::string(valid.error().context), ContainsSubstring("tcp connect"));

	for (std::string_view name : { std::string_view("ldap\0.example.org", 17), std::string_view("a\nb") }) {
		auto bad_name = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .server_name = std::pmr::string(name) } });
		REQUIRE_FALSE(bad_name.has_value());
		CHECK(bad_name.error().code == std::errc::invalid_argument);
		CHECK(std::string(bad_name.error().context)
			  == "connect ldaps://127.0.0.1:1: tls: control character in server_name");
	}
}

TEST_CASE("TLS configuration errors leave the OpenSSL error queue empty", "[net][connect][tls]")
{
	// The checks run on the calling thread; a CA that does not parse used
	// to leave PEM errors on its queue, for the next OpenSSL user to find.
	ERR_clear_error();
	const std::string broken = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
	auto bad_ca = net::detail::make_tls_setup({ .ca_pem = std::pmr::string(pki().ca_pem() + broken) });
	REQUIRE_FALSE(bad_ca.has_value());
	CHECK_THAT(std::string(bad_ca.error().context), EndsWith("certificate 2 of 2 does not parse"));
	CHECK(ERR_peek_error() == 0);

	temp_path junk(".pem");
	junk.write("not pem at all\n");
	auto junk_cert = net::detail::make_tls_setup({ .cert_file = junk.str(), .key_file = junk.str() });
	REQUIRE_FALSE(junk_cert.has_value());
	CHECK(ERR_peek_error() == 0);

	const auto leaf = pki().issue("client-locked", "DNS:client-locked");
	temp_path cert(".crt"), encrypted(".key");
	cert.write(leaf.cert_pem);
	encrypted.write(test_pki::encrypted_key_pem(leaf.key_pem, "passphrase"));
	auto locked = net::detail::make_tls_setup({ .cert_file = cert.str(), .key_file = encrypted.str() });
	REQUIRE_FALSE(locked.has_value());
	CHECK(ERR_peek_error() == 0);
}

TEST_CASE("ldaps:// with a CA directory", "[net][connect][tls]")
{
	// A c_rehash-style directory: the CA under "<subject hash>.0". Only the
	// directory is trusted (no system store), and the server's CA is in it.
	temp_path dir("-certs");
	std::filesystem::create_directory(dir.str());
	const auto ca_name = std::format("{:08x}.0", pki().ca_subject_hash());
	struct remove_contents
	{
		std::filesystem::path p;
		~remove_contents()
		{
			std::error_code ec;
			std::filesystem::remove(p, ec);
		}
	} ca_file{ std::filesystem::path(dir.str()) / ca_name };
	{
		std::ofstream out(ca_file.p, std::ios::binary);
		out << pki().ca_pem();
		out.close();
		REQUIRE_FALSE(out.fail());
	}

	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server, client;
	spawn(ioc, accept_and_serve(srv.acc, server_context(localhost_cert())), server);
	spawn(ioc, exchange(ioc, srv.url("ldaps"), { .tls = { .ca_dir = dir.str() } }, true), client);
	drive(ioc);
	CHECK(client.get() == "");
	CHECK(server.get() == "");

	// A directory without that CA: the server's certificate is untrusted.
	std::filesystem::remove(ca_file.p);
	tcp_server srv2(ioc);
	outcome<std::string> server2;
	spawn(ioc, accept_and_serve(srv2.acc, server_context(localhost_cert())), server2);
	auto t = connect_to(ioc, srv2.url("ldaps"), { .tls = { .ca_dir = dir.str() } });
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == ldap::cond::tls_failure);
	CHECK_THAT(std::string(t.error().context),
	  StartsWith("connect " + srv2.url("ldaps") + ": tls handshake: server certificate: "));
	drive(ioc);
	CHECK_THAT(server2.get(), StartsWith("server handshake: "));
}

TEST_CASE("ldaps:// peer closing without close_notify", "[net][connect][tls]")
{
	// The server answers, then drops the TCP connection without a TLS
	// close_notify. Between PDUs that reads as a plain close.
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server, client;
	spawn(
	  ioc,
	  [](corosio::tcp_acceptor &acc, corosio::tls_context ctx) -> capy::task<std::string> {
		  auto [ec, peer] = co_await acc.accept();
		  if (ec) {
			  co_return "accept: " + ec.message();
		  }
		  corosio::openssl_stream stream(std::move(peer), ctx);
		  auto [hec] = co_await stream.handshake(corosio::tls_role::server);
		  if (hec) {
			  co_return "handshake: " + hec.message();
		  }
		  auto t = net::transport::wrap(std::move(stream), "server");
		  if (auto w = co_await net::write_message(t, bind_response_msg(1, "bye")); !w) {
			  co_return std::string(w.error().message());
		  }
		  co_return "";// the transport and its socket go away: no close_notify
	  }(srv.acc, server_context(localhost_cert())),
	  server);
	spawn(
	  ioc,
	  [](corosio::io_context &io, std::string text) -> capy::task<std::string> {
		  auto u = ldap::url::parse(text);
		  auto t = co_await net::connect(io, *u, { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
		  if (!t) {
			  co_return "connect: " + std::string(t.error().message());
		  }
		  net::read_buffer buf;
		  auto first = co_await net::read_message(*t, buf);
		  if (!first || *first != bind_response_msg(1, "bye")) {
			  co_return "first read failed";
		  }
		  auto second = co_await net::read_message(*t, buf);
		  if (second) {
			  co_return "second read succeeded";
		  }
		  co_return std::string(second.error().context) + " | " + second.error().code.message();
	  }(ioc, srv.url("ldaps")),
	  client);
	drive(ioc);
	CHECK(server.get() == "");
	const std::string result = client.get();
	INFO(result);
	// Corosio reports the missing close_notify as cond::stream_truncated.
	CHECK(result == "read " + srv.url("ldaps") + ": connection closed (without TLS close_notify) | stream truncated");
}

namespace {

// Accepts a TLS client and reads until its TLS session ends. Returns what
// the read reported ("end of file" for a close_notify). `answer`: reply to
// the close_notify with ours; otherwise stay silent until the client hangs
// up the TCP connection.
auto serve_until_close(corosio::tcp_acceptor &acc, corosio::tls_context ctx, bool answer) -> capy::task<std::string>
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		co_return "accept: " + ec.message();
	}
	corosio::openssl_stream stream(&peer, ctx);
	auto [hec] = co_await stream.handshake(corosio::tls_role::server);
	if (hec) {
		co_return "handshake: " + hec.message();
	}
	char buf[256];
	auto [rec, n] = co_await stream.read_some(capy::mutable_buffer(buf, sizeof buf));
	if (!rec) {
		co_return "unexpected data";
	}
	if (answer) {
		auto [sec] = co_await stream.shutdown();
		if (sec) {
			co_return "server shutdown: " + sec.message();
		}
	} else {
		while (true) {
			auto [pec, m] = co_await peer.read_some(capy::mutable_buffer(buf, sizeof buf));
			if (pec) {
				break;
			}
		}
	}
	co_return rec == capy::cond::eof ? "close_notify" : rec.message();
}

auto connect_and_shutdown(corosio::io_context &io, std::string text, std::chrono::milliseconds bound)
  -> capy::task<std::pair<std::string, bool>>
{
	auto u = ldap::url::parse(text);
	auto t = co_await net::connect(io, *u, { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
	if (!t) {
		co_return { "connect: " + std::string(t.error().message()), false };
	}
	auto r = co_await t->shutdown(bound);
	co_return { r ? std::string() : std::string(r.error().message()), t->is_open() };
}

}// namespace

TEST_CASE("transport shutdown: TLS close_notify both ways", "[net][connect][tls]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server;
	outcome<std::pair<std::string, bool>> client;
	spawn(ioc, serve_until_close(srv.acc, server_context(localhost_cert()), true), server);
	spawn(ioc, connect_and_shutdown(ioc, srv.url("ldaps"), std::chrono::seconds(10)), client);
	drive(ioc);
	CHECK(server.get() == "close_notify");
	CHECK(client.get().first == "");
	CHECK_FALSE(client.get().second);// closed
}

TEST_CASE("transport shutdown: a peer that does not answer costs the bound", "[net][connect][tls][timeout]")
{
	corosio::io_context ioc;
	tcp_server srv(ioc);
	outcome<std::string> server;
	outcome<std::pair<std::string, bool>> client;
	spawn(ioc, serve_until_close(srv.acc, server_context(localhost_cert()), false), server);
	const auto start = std::chrono::steady_clock::now();
	spawn(ioc, connect_and_shutdown(ioc, srv.url("ldaps"), std::chrono::milliseconds(200)), client);
	drive(ioc);
	const auto elapsed = std::chrono::steady_clock::now() - start;
	CHECK(server.get() == "close_notify");// ours arrived
	CHECK_THAT(client.get().first, StartsWith("tls shutdown " + srv.url("ldaps") + ": "));
	CHECK_FALSE(client.get().second);
	CHECK(elapsed >= std::chrono::milliseconds(150));
	CHECK(elapsed < std::chrono::seconds(10));
}

TEST_CASE("transport shutdown: plain and wrapped transports just close", "[net][connect]")
{
	corosio::io_context ioc;
	auto [a, b] = capy::test::make_stream_pair();
	auto t = net::transport::wrap(std::move(a), "pair");
	CHECK(t.is_open());
	REQUIRE(run(ioc, t.shutdown(std::chrono::milliseconds(100))).has_value());
	CHECK_FALSE(t.is_open());
	// capy::test::stream::close() ran: the peer reads end of file.
	char byte = 0;
	auto [ec, n] = run(ioc, [](capy::test::stream &s, char &c) -> capy::task<capy::io_result<std::size_t>> {
		co_return co_await s.read_some(capy::mutable_buffer(&c, 1));
	}(b, byte));
	CHECK(ec == capy::cond::eof);
}

TEST_CASE("connect allocates the transport from the given resource", "[net][connect][pmr]")
{
	jhetz::ldap::test::counting_resource counting;
	{
		corosio::io_context ioc;
		tcp_server srv(ioc);
		outcome<void> server;
		spawn(ioc, accept_and_close(srv.acc), server);
		auto u = ldap::url::parse(srv.url("ldap"));
		REQUIRE(u.has_value());
		auto t = run(ioc, net::connect(ioc, *u, {}, &counting));
		REQUIRE(t.has_value());
		server.get();
		CHECK(t->name().get_allocator().resource() == &counting);
		CHECK(counting.allocations() >= 2);// the transport block and its name
		CHECK(counting.outstanding() > 0);
	}
	CHECK(counting.outstanding() == 0);

	jhetz::ldap::test::counting_resource for_wrap;
	{
		auto [a, b] = capy::test::make_stream_pair();
		auto t = net::transport::wrap(std::move(a), "a custom stream with a long name", &for_wrap);
		CHECK(t.name().get_allocator().resource() == &for_wrap);
		CHECK(for_wrap.allocations() == 3);// the transport block, its name and the stream
	}
	CHECK(for_wrap.outstanding() == 0);
}

TEST_CASE("TLS peer name: server_name, else the host without an IPv6 zone", "[net][connect][tls]")
{
	using net::detail::tls_peer_name;
	CHECK(tls_peer_name("ldap.example.org", {}) == "ldap.example.org");
	CHECK(tls_peer_name("127.0.0.1", {}) == "127.0.0.1");
	CHECK(tls_peer_name("::1", {}) == "::1");
	CHECK(tls_peer_name("fe80::1%eth0", {}) == "fe80::1");
	CHECK(tls_peer_name("fe80::1%eth0", { .server_name = "ldap.example.org" }) == "ldap.example.org");
}

TEST_CASE("net::start_tls needs an open plain TCP transport", "[net][starttls]")
{
	corosio::io_context ioc;
	auto [a, b] = capy::test::make_stream_pair();
	auto wrapped = net::transport::wrap(std::move(a), "custom");
	const net::read_buffer none;
	auto r = run(ioc, net::start_tls(wrapped, none, { .ca_pem = std::pmr::string(pki().ca_pem()) }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == std::errc::invalid_argument);
	CHECK(std::string(r.error().context) == "start tls custom: needs an open plain TCP transport");
	CHECK(wrapped.is_open());// refused, not closed
}
