// StartTLS (RFC 4511 section 4.14) against an in-process server on
// loopback: it speaks LDAP in clear, answers the StartTLS request, runs the
// server side of the TLS handshake over the same socket (reference mode,
// like the client) and then serves LDAP over TLS. Certificates come from the
// in-memory test PKI (net_test_support.hpp).
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <variant>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

test_pki &pki()
{
	static test_pki instance("jhetz-ldap StartTLS test CA");
	return instance;
}

const test_pki::issued &localhost_cert()
{
	static const auto leaf = pki().issue("localhost", "DNS:localhost,IP:127.0.0.1");
	return leaf;
}

corosio::tls_context server_context(const test_pki::issued &leaf)
{
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem));
	return ctx;
}

ldap::connection_options trusting(ldap::connection_options o = {})
{
	o.tls.ca_pem = std::pmr::string(pki().ca_pem());
	return o;
}

// Forwards to a stream owned elsewhere, so it can be wrapped in a transport
// and still used afterwards (the socket under TLS, the TLS layer itself).
template<class S> struct stream_ref
{
	S *s;
	template<capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers) { return s->write_some(buffers); }
};

enum class mode {
	upgrade,// answer success, handshake, then answer one request over TLS
	refuse,// answer StartTLS with an error, then answer one request in clear
	inject,// answer success followed by extra plaintext bytes
};

capy::task<std::string> serve_start_tls(corosio::tcp_acceptor &acc, corosio::tls_context ctx, mode m)
{
	auto [aec, peer] = co_await acc.accept();
	if (aec) co_return "accept: " + aec.message();
	net::transport plain = net::transport::wrap(stream_ref<corosio::tcp_socket>{ &peer }, "server");
	net::read_buffer buf;

	auto req = co_await net::read_message(plain, buf, as_server);
	if (!req) co_return "read StartTLS: " + std::string(req.error().message());
	const auto *x = std::get_if<ldap::extended_request>(&req->op);
	if (x == nullptr || x->request_name != ldap::start_tls_oid) co_return "expected a StartTLS request";

	std::string reply;
	if (m == mode::refuse) {
		reply =
		  bytes_of(ldap::message{ req->id, ldap::extended_response{ ldap::ldap_result{ 52, "", "no TLS here" } } });
	} else {
		reply = bytes_of(ldap::message{
		  req->id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::start_tls_oid) } });
		if (m == mode::inject) reply += bytes_of(bind_resp(99));// sent in clear, before the handshake
	}
	if (auto w = co_await net::write_bytes(plain, std::as_bytes(std::span(reply))); !w)
		co_return "write: " + std::string(w.error().message());
	if (m == mode::inject) co_return "";

	auto answer_one = [](net::transport &t, net::read_buffer &b) -> capy::task<std::string> {
		auto r = co_await net::read_message(t, b, as_server);
		if (!r) co_return "read request: " + std::string(r.error().message());
		const std::string out =
		  std::holds_alternative<ldap::bind_request>(r->op) ? bytes_of(bind_resp(r->id)) : bytes_of(done_msg(r->id));
		if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(out))); !w)
			co_return "write response: " + std::string(w.error().message());
		co_return "";
	};
	if (m == mode::refuse) co_return co_await answer_one(plain, buf);

	corosio::openssl_stream tls(&peer, ctx);
	auto [hec] = co_await tls.handshake(corosio::tls_role::server);
	if (hec) co_return "server handshake: " + hec.message();
	net::transport secure = net::transport::wrap(stream_ref<corosio::openssl_stream>{ &tls }, "server tls");
	net::read_buffer tls_buf;
	co_return co_await answer_one(secure, tls_buf);
}

struct tls_fixture
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 16 };
	outcome<std::string> server{};

	std::string url(const char *host = "127.0.0.1") const
	{
		return std::string("ldap://") + host + ":" + std::to_string(acc.local_endpoint().port());
	}

	void serve(mode m, const test_pki::issued &leaf = localhost_cert())
	{
		spawn(ioc, serve_start_tls(acc, server_context(leaf), m), server);
	}

	ldap::connection connect(const ldap::connection_options &o = trusting(), const char *host = "127.0.0.1")
	{
		auto u = ldap::url::parse(url(host));
		REQUIRE(u.has_value());
		auto c = finish(ioc, ldap::connect(ioc, *u, o));
		REQUIRE(c.has_value());
		return std::move(*c);
	}
};

}// namespace

TEST_CASE("start_tls: upgrade, then LDAP over TLS", "[net][starttls]")
{
	tls_fixture f;
	f.serve(mode::upgrade);
	auto c = f.connect();
	CHECK_FALSE(c.is_tls());
	auto r = finish(f.ioc, c.start_tls({ .ca_pem = std::pmr::string(pki().ca_pem()) }));
	REQUIRE(r.has_value());
	CHECK(c.is_tls());
	CHECK(c.is_open());
	auto b = finish(f.ioc, c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	CHECK(b.has_value());
	c.close();
	drive(f.ioc);
	CHECK(f.server.get() == "");
}

TEST_CASE("start_tls: connection_options::start_tls upgrades right after connecting", "[net][starttls]")
{
	tls_fixture f;
	f.serve(mode::upgrade);
	auto c = f.connect(trusting({ .start_tls = true }));
	CHECK(c.is_tls());
	CHECK(finish(f.ioc, c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	c.close();
	drive(f.ioc);
	CHECK(f.server.get() == "");
}

TEST_CASE("start_tls: the server refuses", "[net][starttls]")
{
	tls_fixture f;
	f.serve(mode::refuse);
	auto c = f.connect();
	auto r = finish(f.ioc, c.start_tls({ .ca_pem = std::pmr::string(pki().ca_pem()) }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::unavailable);
	CHECK(r.error().diagnostic == "no TLS here");
	CHECK(r.error().context == "start tls");
	// Still usable, in clear.
	CHECK(c.is_open());
	CHECK_FALSE(c.is_tls());
	CHECK(finish(f.ioc, c.search({})).has_value());
	c.close();
	drive(f.ioc);
	CHECK(f.server.get() == "");
}

TEST_CASE("start_tls: bytes before the handshake are refused", "[net][starttls]")
{
	tls_fixture f;
	f.serve(mode::inject);
	auto c = f.connect();
	auto r = finish(f.ioc, c.start_tls({ .ca_pem = std::pmr::string(pki().ca_pem()) }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::decode_error);
	CHECK_THAT(std::string(r.error().context), ContainsSubstring("arrived before the TLS handshake"));
	CHECK_FALSE(c.is_open());
	CHECK_FALSE(c.is_tls());
	auto later = finish(f.ioc, c.search({}));
	REQUIRE_FALSE(later.has_value());
	CHECK(later.error().code == ldap::client_errc::not_connected);
	drive(f.ioc);
	CHECK(f.server.get() == "");
}

TEST_CASE("start_tls: certificate verification failures", "[net][starttls]")
{
	SECTION("untrusted CA (system trust store)")
	{
		tls_fixture f;
		f.serve(mode::upgrade);
		auto c = f.connect(ldap::connection_options{});
		auto r = finish(f.ioc, c.start_tls());
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::tls_failure);
		CHECK_THAT(std::string(r.error().context), StartsWith("start tls ldap://127.0.0.1:"));
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("tls handshake: server certificate: "));
		CHECK_FALSE(c.is_open());
		drive(f.ioc);
		CHECK_THAT(f.server.get(), StartsWith("server handshake: "));
	}
	SECTION("host name mismatch")
	{
		tls_fixture f;
		f.serve(mode::upgrade, pki().issue("other.example", "DNS:other.example"));
		auto c = f.connect(trusting(), "localhost");
		auto r = finish(f.ioc, c.start_tls({ .ca_pem = std::pmr::string(pki().ca_pem()) }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::tls_failure);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("hostname mismatch", Catch::CaseSensitive::No));
		CHECK_FALSE(c.is_open());
		drive(f.ioc);
	}
}

TEST_CASE("start_tls: refused while an operation is outstanding", "[net][starttls]")
{
	mock_ldap m;
	m.serve({ step{} });// reads the search, never answers
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.search({}), search);
	drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
	auto r = m.run(m.conn.start_tls());
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::operation_in_progress);
	CHECK(r.error().context == "start tls: 1 operations are outstanding");
	CHECK(m.conn.is_open());
	m.conn.close();
	drive_until(m.ioc, [&search] { return search.done(); });
}

TEST_CASE("start_tls: only on plain TCP connections", "[net][starttls]")
{
	mock_ldap m;// a wrapped custom stream
	auto r = m.run(m.conn.start_tls());
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == std::errc::invalid_argument);
	CHECK(m.conn.is_open());
	CHECK(m.log.received.empty());

	corosio::io_context ioc;
	auto u = ldap::url::parse("ldaps://127.0.0.1:1");
	REQUIRE(u.has_value());
	auto c = finish(ioc, ldap::connect(ioc, *u, { .start_tls = true }));
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == ldap::client_errc::invalid_url);
	CHECK_THAT(std::string(c.error().context), ContainsSubstring("start_tls needs an ldap:// URL"));
}
