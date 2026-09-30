// net::connect against in-process servers on loopback: TCP, TLS (throwaway
// CA generated at run time) and Unix domain sockets. No external server, no
// fixed ports (the kernel picks them), no sleeps: every wait ends on an
// event, and the timeouts tested are the library's own.
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/local_stream_acceptor.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <optional>
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

namespace {

const net::read_options as_server{ .decode = { .from = ldap::origin::client } };

// Serves one connection: [TLS handshake], read a bind request, answer it,
// then wait for the client to go away. Returns "" or what went wrong.
capy::task<std::string> serve_one(net::transport t)
{
	net::read_buffer buf;
	auto req = co_await net::read_message(t, buf, as_server);
	if (!req) co_return "server read: " + req.error().message();
	if (*req != bind_request_msg(1)) co_return "server: unexpected request";
	if (auto w = co_await net::write_message(t, bind_response_msg(1, "welcome")); !w)
		co_return "server write: " + w.error().message();
	auto end = co_await net::read_message(t, buf, as_server);
	co_return end ? "server: unexpected second request" : "";
}

template<class Acceptor>
capy::task<std::string> accept_and_serve(Acceptor &acc, std::optional<corosio::tls_context> tls = std::nullopt)
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) co_return "accept: " + ec.message();
	if (!tls) co_return co_await serve_one(net::transport::wrap(std::move(peer), "server"));
	corosio::openssl_stream stream(std::move(peer), *tls);
	auto [hec] = co_await stream.handshake(corosio::tls_role::server);
	if (hec) co_return "server handshake: " + hec.message();
	co_return co_await serve_one(net::transport::wrap(std::move(stream), "server"));
}

// Accepts, then reads until the client goes away without ever writing.
capy::task<void> accept_and_stay_silent(corosio::tcp_acceptor &acc)
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) co_return;
	char buf[4096];
	while (true) {
		auto [rec, n] = co_await peer.read_some(capy::mutable_buffer(buf, sizeof buf));
		if (rec) co_return;
	}
}

// Accepts and hangs up at once.
capy::task<void> accept_and_close(corosio::tcp_acceptor &acc)
{
	auto [ec, peer] = co_await acc.accept();
	peer.close();
}

// Connects, sends a bind request, checks the answer. Returns "" or the error.
capy::task<std::string>
  exchange(corosio::io_context &ioc, std::string text, net::connect_options options = {}, bool expect_tls = false)
{
	auto u = ldap::url::parse(text);
	if (!u) co_return "url: " + u.error().message();
	auto t = co_await net::connect(ioc, *u, options);
	if (!t) co_return "connect: " + t.error().message();
	if (!t->is_open()) co_return "transport not open";
	if (t->is_tls() != expect_tls) co_return "unexpected is_tls()";
	if (auto w = co_await net::write_message(*t, bind_request_msg(1)); !w)
		co_return "client write: " + w.error().message();
	net::read_buffer buf;
	auto r = co_await net::read_message(*t, buf);
	if (!r) co_return "client read: " + r.error().message();
	if (*r != bind_response_msg(1, "welcome")) co_return "client: unexpected response";
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
	std::string url(const char *scheme, const char *host = "127.0.0.1") const
	{
		return std::string(scheme) + "://" + host + ":" + std::to_string(port);
	}
};

ldap::result<net::transport>
  connect_to(corosio::io_context &ioc, const std::string &text, net::connect_options options = {})
{
	auto u = ldap::url::parse(text);
	REQUIRE(u.has_value());
	return run(ioc, net::connect(ioc, *u, std::move(options)));
}

corosio::tls_context server_context(const test_pki::issued &leaf)
{
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem));
	return ctx;
}

// One PKI for the whole test binary: key generation is the slow part.
test_pki &pki()
{
	static test_pki instance;
	return instance;
}

const test_pki::issued &localhost_cert()
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

TEST_CASE("connect without a time limit", "[net][connect][tcp]")
{
	for (auto limit :
	  { std::chrono::milliseconds(0), std::chrono::milliseconds(-5), std::chrono::milliseconds::max() }) {
		corosio::io_context ioc;
		tcp_server srv(ioc);
		outcome<std::string> server, client;
		spawn(ioc, accept_and_serve(srv.acc), server);
		spawn(ioc, exchange(ioc, srv.url("ldap"), { .timeout = limit }), client);
		drive(ioc);
		CHECK(client.get() == "");
		CHECK(server.get() == "");
	}
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
	CHECK(t.error().context == "connect " + url + ": tcp connect " + url.substr(7));
	CHECK_THAT(t.error().message(), StartsWith("connect " + url + ": tcp connect "));
}

TEST_CASE("connect timeout while the TCP handshake cannot complete", "[net][connect][tcp][timeout]")
{
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
	CHECK_THAT(t.error().context, ContainsSubstring(": tcp connect 127.0.0.1:"));
	CHECK_THAT(t.error().context, ContainsSubstring("gave up after the 300 ms connect timeout"));
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
	CHECK_THAT(t.error().context, StartsWith("connect ldap://no-such-host.invalid:389: resolve no-such-host.invalid"));
	CHECK(t.error().code);
}

TEST_CASE("URLs connect() refuses", "[net][connect]")
{
	corosio::io_context ioc;
	auto no_host = connect_to(ioc, "ldap:///dc=example");
	REQUIRE_FALSE(no_host.has_value());
	CHECK(no_host.error().code == client_errc::invalid_url);
	CHECK(no_host.error().context == "connect ldap://:389: the URL names no host (or, for ldapi, no socket path)");

	auto no_path = connect_to(ioc, "ldapi://");
	REQUIRE_FALSE(no_path.has_value());
	CHECK(no_path.error().code == client_errc::invalid_url);

	for (auto text : { "ldaps://evil%00.example.org", "ldap://a%0Ab", "ldap://a%7F", "ldapi://%2Ftmp%2Fa%00b" }) {
		auto control = connect_to(ioc, text);
		INFO(text);
		REQUIRE_FALSE(control.has_value());
		CHECK(control.error().code == client_errc::invalid_url);
		CHECK_THAT(control.error().context, EndsWith(": control character in the host"));
	}

	auto critical = connect_to(ioc,
	  "ldap://127.0.0.1:1/????"
	  "!x-unknown");
	REQUIRE_FALSE(critical.has_value());
	CHECK(critical.error().code == client_errc::invalid_url);
	CHECK_THAT(critical.error().context, ContainsSubstring("unsupported critical extension x-unknown"));
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
	CHECK_THAT(t.error().context, ContainsSubstring(": connect " + missing.str()));

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
		spawn(ioc,
		  exchange(ioc, srv.url("ldaps", "localhost"), { .tls = { .ca_file = std::pmr::string(bundle.str()) } }, true),
		  client);
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
		CHECK_THAT(
		  t->error().context, StartsWith("connect " + srv.url("ldaps") + ": tls handshake: server certificate: "));
	}
	SECTION("host name mismatch")
	{
		const auto leaf = pki().issue("other.example", "DNS:other.example");
		spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
		t = connect_to(ioc, srv.url("ldaps", "localhost"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
		REQUIRE_FALSE(t->has_value());
		CHECK_THAT(t->error().context,
		  ContainsSubstring("tls handshake: server certificate: hostname mismatch", Catch::CaseSensitive::No));
	}
	SECTION("IP address mismatch")
	{
		const auto leaf = pki().issue("localhost", "DNS:localhost");
		spawn(ioc, accept_and_serve(srv.acc, server_context(leaf)), server);
		t = connect_to(ioc, srv.url("ldaps"), { .tls = { .ca_pem = std::pmr::string(pki().ca_pem()) } });
		REQUIRE_FALSE(t->has_value());
		CHECK_THAT(t->error().context,
		  ContainsSubstring("tls handshake: server certificate: IP address mismatch", Catch::CaseSensitive::No));
	}
	drive(ioc);
	CHECK(t->error().code);// the handshake's own error code is kept
	CHECK_THAT(server.get(), StartsWith("server handshake: "));
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
			{ .tls = { .ca_pem = std::pmr::string(pki().ca_pem()),
				.cert_file = std::pmr::string(cert.str()),
				.key_file = std::pmr::string(key.str()) } },
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
	CHECK(
	  t.error().context == "connect " + srv.url("ldaps") + ": tls handshake: gave up after the 300 ms connect timeout");
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
	CHECK(half.error().context == "connect ldaps://127.0.0.1:1: tls: cert_file and key_file must be given together");

	auto missing = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_file = "/nonexistent/ca.pem" } });
	REQUIRE_FALSE(missing.has_value());
	CHECK(missing.error().code == std::errc::no_such_file_or_directory);
	CHECK_THAT(missing.error().context, ContainsSubstring("tls: ca_file /nonexistent/ca.pem"));

	auto not_pem = connect_to(ioc, "ldaps://127.0.0.1:1", { .tls = { .ca_pem = "garbage" } });
	REQUIRE_FALSE(not_pem.has_value());
	CHECK_THAT(not_pem.error().context, ContainsSubstring("tls: ca_pem: no PEM certificate found"));
}
