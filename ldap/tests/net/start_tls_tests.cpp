// StartTLS (RFC 4511 section 4.14) against an in-process server on
// loopback: it speaks LDAP in clear, answers the StartTLS request, runs the
// server side of the TLS handshake over the same socket (reference mode,
// like the client) and then serves LDAP over TLS. Certificates come from the
// in-memory test PKI (net_test_support.hpp).
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

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
	// upgrade, then expect an UnbindRequest followed by a TLS close_notify,
	// and answer the close_notify (or not)
	unbind,
	unbind_silent,
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
	if (auto r = co_await answer_one(secure, tls_buf); !r.empty() || (m != mode::unbind && m != mode::unbind_silent))
		co_return r;

	auto unbind = co_await net::read_message(secure, tls_buf, as_server);
	if (!unbind || !std::holds_alternative<ldap::unbind_request>(unbind->op)) co_return "expected an UnbindRequest";
	char byte = 0;
	auto [rec, n] = co_await tls.read_some(capy::mutable_buffer(&byte, 1));
	if (rec != capy::cond::eof) co_return "expected close_notify, got: " + rec.message();
	if (m == mode::unbind) {
		auto [sec] = co_await tls.shutdown();
		if (sec) co_return "server shutdown: " + sec.message();
		co_return "";
	}
	while (true) {// silent: wait for the client to hang up
		auto [pec, k] = co_await peer.read_some(capy::mutable_buffer(&byte, 1));
		if (pec) co_return "";
	}
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

TEST_CASE("start_tls: unbind ends the TLS session with close_notify", "[net][starttls]")
{
	tls_fixture f;
	f.serve(mode::unbind);
	auto c = f.connect(trusting({ .start_tls = true }));
	REQUIRE(finish(f.ioc, c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	REQUIRE(finish(f.ioc, c.unbind()).has_value());
	CHECK_FALSE(c.is_open());
	drive(f.ioc);
	CHECK(f.server.get() == "");
}

TEST_CASE("start_tls: unbind waits for the server's close_notify at most tls_shutdown_timeout",
  "[net][starttls][timeout]")
{
	tls_fixture f;
	f.serve(mode::unbind_silent);
	auto c = f.connect(trusting({ .tls_shutdown_timeout = std::chrono::milliseconds(200), .start_tls = true }));
	REQUIRE(finish(f.ioc, c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	const auto start = std::chrono::steady_clock::now();
	REQUIRE(finish(f.ioc, c.unbind()).has_value());// the TLS shutdown is best effort
	const auto elapsed = std::chrono::steady_clock::now() - start;
	CHECK_FALSE(c.is_open());
	drive(f.ioc);
	CHECK(f.server.get() == "");
	CHECK(elapsed >= std::chrono::milliseconds(150));
	CHECK(elapsed < std::chrono::seconds(10));
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
	CHECK(r.error().context == "start tls with 1 request outstanding");
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

// ---------------------------------------------------------------- RFC conformance

// RFC 4511 section 4.14.1: after the StartTLS request the client "MUST NOT
// send any LDAP PDUs at this LDAP message layer following this request until
// it receives a StartTLS extended response and, in the case of a successful
// response, completes TLS negotiations".
TEST_CASE("RFC 4511 4.14.1: requests are refused while StartTLS is in progress", "[net][starttls][rfc]")
{
	tls_fixture f;
	f.serve(mode::upgrade);
	auto c = f.connect();
	outcome<ldap::result<void>> upgrade;
	outcome<ldap::result<void>> bind;
	spawn(f.ioc, c.start_tls(trusting().tls), upgrade);
	spawn(f.ioc, c.simple_bind(ldap::dn{}, ""), bind);
	drive_until(f.ioc, [&] { return upgrade.done() && bind.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	CHECK(bind.get().error().code == ldap::client_errc::operation_in_progress);
	CHECK(bind.get().error().context == "bind \"\" during StartTLS");
	REQUIRE(upgrade.get().has_value());
	CHECK(c.is_tls());
	// The server got nothing in clear after the StartTLS request: its one
	// request over TLS is this bind.
	CHECK(finish(f.ioc, c.simple_bind(ldap::dn{}, "")).has_value());
	c.close();
	drive(f.ioc);
	CHECK(f.server.get() == "");
}

namespace {

// Reads the StartTLS request, never answers it, then reads at most one
// more request. Returns the requests.
capy::task<std::vector<ldap::message>> silent_start_tls(corosio::tcp_acceptor &acc)
{
	std::vector<ldap::message> got;
	auto [aec, peer] = co_await acc.accept();
	if (aec) co_return got;
	net::transport plain = net::transport::wrap(stream_ref<corosio::tcp_socket>{ &peer }, "server");
	net::read_buffer buf;
	for (int i = 0; i < 2; ++i) {
		auto req = co_await net::read_message(plain, buf, as_server);
		if (!req) break;
		got.push_back(std::move(*req));
	}
	co_return got;
}

}// namespace

// RFC 4511 section 4.11: "Abandon, Bind, Unbind, and StartTLS operations
// cannot be abandoned." Giving up on StartTLS closes the connection instead.
TEST_CASE("RFC 4511 4.11: a StartTLS that times out is not abandoned", "[net][starttls][rfc][timeout]")
{
	tls_fixture f;
	outcome<std::vector<ldap::message>> server;
	spawn(f.ioc, silent_start_tls(f.acc), server);
	auto c = f.connect();
	auto r = finish(f.ioc, c.start_tls(trusting().tls, std::chrono::milliseconds(100)));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::cond::timeout);
	CHECK(r.error().context == "start tls (connection closed)");
	CHECK_FALSE(c.is_open());
	drive_until(f.ioc, [&server] { return server.done(); });
	const auto &got = server.get();
	REQUIRE(got.size() == 1);// the StartTLS request, then the connection closed
	CHECK(std::holds_alternative<ldap::extended_request>(got[0].op));
}

namespace {

struct tls_account
{
	std::string uid;
};

}// namespace

template<>
constexpr auto ldap::schema<tls_account> =
  ldap::describe(ldap::object_class("inetOrgPerson"), ldap::field<&tls_account::uid>("uid"));

namespace {

// What a directory request is, for the schema test's log.
std::string kind_of(const ldap::message &m)
{
	if (const auto *s = std::get_if<ldap::search_request>(&m.op)) {
		if (s->base_object.empty() && s->attributes == ldap::string_list{ "subschemaSubentry" }) return "root DSE";
		if (s->base_object == "cn=Subschema") return "subschema";
		return "search";
	}
	if (const auto *x = std::get_if<ldap::extended_request>(&m.op);
		x != nullptr && x->request_name == ldap::start_tls_oid)
		return "StartTLS";
	return "other";
}

std::string directory_reply(const ldap::message &req)
{
	const std::string kind = kind_of(req);
	std::string out;
	if (kind == "root DSE")
		out += bytes_of(
		  ldap::message{ req.id, ldap::search_result_entry{ "", { { "subschemaSubentry", { "cn=Subschema" } } } } });
	if (kind == "subschema")
		out += bytes_of(ldap::message{ req.id,
		  ldap::search_result_entry{ "cn=Subschema",
			{ { "attributeTypes",
				{ "( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )" } },
			  { "objectClasses", { "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' STRUCTURAL )" } } } } });
	if (kind == "StartTLS")
		return bytes_of(
		  ldap::message{ req.id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::start_tls_oid) } });
	return out + bytes_of(done_msg(req.id));
}

// Answers the root DSE and subschema searches, any other search (no
// entries) and StartTLS, in clear and then over TLS, until the client hangs
// up. Logs each request's kind_of(), prefixed with "tls " over TLS.
capy::task<std::string>
  serve_directory(corosio::tcp_acceptor &acc, corosio::tls_context ctx, std::vector<std::string> &log)
{
	auto [aec, peer] = co_await acc.accept();
	if (aec) co_return "accept: " + aec.message();
	net::transport plain = net::transport::wrap(stream_ref<corosio::tcp_socket>{ &peer }, "server");
	net::read_buffer buf;
	while (true) {
		auto req = co_await net::read_message(plain, buf, as_server);
		if (!req) co_return "read in clear: " + std::string(req.error().message());
		log.push_back(kind_of(*req));
		const std::string reply = directory_reply(*req);
		if (auto w = co_await net::write_bytes(plain, std::as_bytes(std::span(reply))); !w)
			co_return "write: " + std::string(w.error().message());
		if (log.back() == "StartTLS") break;
	}
	corosio::openssl_stream tls(&peer, ctx);
	auto [hec] = co_await tls.handshake(corosio::tls_role::server);
	if (hec) co_return "server handshake: " + hec.message();
	net::transport secure = net::transport::wrap(stream_ref<corosio::openssl_stream>{ &tls }, "server tls");
	net::read_buffer tls_buf;
	while (true) {
		auto req = co_await net::read_message(secure, tls_buf, as_server);
		if (!req) co_return "";// the client hung up
		log.push_back("tls " + kind_of(*req));
		const std::string reply = directory_reply(*req);
		if (auto w = co_await net::write_bytes(secure, std::as_bytes(std::span(reply))); !w)
			co_return "write over TLS: " + std::string(w.error().message());
	}
}

}// namespace

// RFC 4513 section 3.1.5: once TLS is established, "the client SHOULD
// discard or refresh all information about the server that it obtained
// prior to the initiation of the TLS negotiation and that it did not obtain
// through secure mechanisms".
TEST_CASE("RFC 4513 3.1.5: the schema read in clear is read again after StartTLS", "[net][starttls][rfc][schema]")
{
	tls_fixture f;
	std::vector<std::string> log;
	outcome<std::string> server;
	spawn(f.ioc, serve_directory(f.acc, server_context(localhost_cert()), log), server);
	auto c = f.connect(trusting({ .schema_check = ldap::schema_check::on_first_use }));
	REQUIRE(finish(f.ioc, c.search_as<tls_account>({})).has_value());
	REQUIRE(finish(f.ioc, c.start_tls(trusting().tls)).has_value());
	REQUIRE(finish(f.ioc, c.search_as<tls_account>({})).has_value());
	c.close();
	drive_until(f.ioc, [&server] { return server.done(); });
	CHECK(server.get() == "");
	CHECK(log
		  == std::vector<std::string>{
			"root DSE", "subschema", "search", "StartTLS", "tls root DSE", "tls subschema", "tls search" });
}
