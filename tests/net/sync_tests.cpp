// ldap::sync::connection against an in-process LDAP server on loopback TCP that
// runs on its own thread and io_context and answers requests as they come.
#include "../../src/net/tls.hpp"
#include "../counting_resource.hpp"
#include "jhetz/ldap/ad/sync.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/sync_extended_operations.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"
#include "server_thread.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::IsEmpty;


TEST_CASE("sync: connect, bind, search and unbind", "[net][sync]")
{
	server_thread srv;
	auto opened = ldap::sync::connect(srv.url(), { .timeout = std::chrono::seconds(10) });
	REQUIRE(opened.has_value());
	auto &c = *opened;
	CHECK(c.is_open());
	CHECK(c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret").has_value());
	auto bad = c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::cond::auth_failed);
	auto r = c.search({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } });
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 2);
	CHECK(r->entries[0].dn == "uid=x,ou=people,dc=example,dc=org");
	auto paged = c.search_paged({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } }, 10);
	REQUIRE(paged.has_value());
	CHECK(paged->entries.size() == 2);
	CHECK(ldap::sync::who_am_i(c) == "dn:cn=me");
	REQUIRE(c.unbind().has_value());
	CHECK_FALSE(c.is_open());
	auto after = c.search({ .base = ldap::dn{} });
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == ldap::client_errc::not_sent);
}

TEST_CASE("sync: a connection without an I/O thread, moves and reconnecting", "[net][sync]")
{
	static_assert(std::is_nothrow_default_constructible_v<ldap::sync::connection>);
	static_assert(std::is_nothrow_move_constructible_v<ldap::sync::connection>);
	static_assert(std::is_nothrow_move_assignable_v<ldap::sync::connection>);
	static_assert(!std::is_copy_constructible_v<ldap::sync::connection>);
	static_assert(!std::is_copy_assignable_v<ldap::sync::connection>);
	ldap::sync::connection none;
	CHECK_FALSE(none.is_open());
	CHECK(none.security_layer() == ldap::sasl_protection::none);
	CHECK(none.executor() == boost::corosio::io_context::executor_type{});
	CHECK(none.simple_bind(ldap::dn{}, "").error().code == ldap::client_errc::not_connected);
	CHECK(none.search({ .base = ldap::dn{} }).error().code == ldap::client_errc::not_connected);
	CHECK(none.begin_transaction().error().code == ldap::client_errc::not_connected);
	none.close();

	server_thread srv;
	auto opened = ldap::sync::connect(srv.url());
	REQUIRE(opened.has_value());
	ldap::sync::connection c = std::move(*opened);
	CHECK(c.is_open());
	CHECK(c.simple_bind(ldap::dn{}, "").has_value());
	auto again = ldap::sync::connect(srv.url());
	REQUIRE(again.has_value());
	c = std::move(*again);// closes the first connection
	CHECK(c.is_open());
	CHECK(ldap::sync::who_am_i(c) == "dn:cn=me");
	c = ldap::sync::connection{};
	CHECK_FALSE(c.is_open());
}

TEST_CASE("sync: many threads share one connection", "[net][sync]")
{
	server_thread srv;
	auto opened = ldap::sync::connect(srv.url());
	REQUIRE(opened.has_value());
	auto &c = *opened;
	constexpr int threads = 8;
	constexpr int per_thread = 25;
	std::atomic<int> failures{ 0 };
	std::vector<std::thread> pool;
	pool.reserve(threads);
	for (int t = 0; t < threads; ++t) {
		pool.emplace_back([&c, &failures, t] {
			for (int i = 0; i < per_thread; ++i) {
				if (i % 2 == 0) {
					if (!c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")) {
						++failures;
					}
					continue;
				}
				const std::string base = "ou=t" + std::to_string(t) + "i" + std::to_string(i) + ",dc=example,dc=org";
				auto r = c.search({ .base = *ldap::dn::parse(base) });
				if (!r || r->entries.size() != 2 || !std::string_view(r->entries[1].dn).ends_with(base)) {
					++failures;
				}
			}
		});
	}
	for (auto &th : pool) {
		th.join();
	}
	CHECK(failures == 0);
	CHECK(srv.requests == threads * per_thread);
	CHECK(c.is_open());
}

TEST_CASE("sync: a blocking call from the I/O thread fails with would_deadlock", "[net][sync]")
{
	server_thread srv;
	auto opened = ldap::sync::connect(srv.url());
	REQUIRE(opened.has_value());
	auto &c = *opened;
	std::promise<ldap::result<std::string>> got;
	capy::run_async(c.executor())(
	  [](ldap::sync::connection &cl, std::promise<ldap::result<std::string>> &p) -> capy::task<void> {
		  p.set_value(ldap::sync::who_am_i(cl));// blocking, on the I/O thread
		  co_return;
	  }(c, got));
	auto r = got.get_future().get();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::would_deadlock);
	CHECK(r.error().context == "sync::connection");
	// The connection still works from other threads.
	CHECK(ldap::sync::who_am_i(c) == "dn:cn=me");
}

TEST_CASE("sync: search_paged leaves nothing on the caller's resource once it returns", "[net][sync]")
{
	server_thread srv;
	auto opened = ldap::sync::connect(srv.url(), { .timeout = std::chrono::seconds(10) });
	REQUIRE(opened.has_value());
	auto &c = *opened;
	auto arena = std::make_unique<counting_resource>();
	{
		auto paged = c.search_paged({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } }, 10, arena.get());
		REQUIRE(paged.has_value());
		CHECK(paged->entries.size() == 2);
	}
	CHECK(arena->allocations() > 0);
	CHECK(arena->outstanding() == 0);
	arena.reset();
	CHECK(c.search({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } }).has_value());
}

TEST_CASE("sync: connect failures and destruction without unbind", "[net][sync]")
{
	{
		const refused_port closed;// nothing listens there
		auto r = ldap::sync::connect(*ldap::url::parse(closed.url()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::connection_refused);
	}
	server_thread srv;
	{
		auto opened = ldap::sync::connect(srv.url());
		REQUIRE(opened.has_value());
		auto &c = *opened;
		REQUIRE(c.simple_bind(ldap::dn{}, "").has_value());
	}// destroyed while connected: closes and joins
	SUCCEED();
}

TEST_CASE("sync: connect with the URL as text", "[net][sync]")
{
	server_thread srv;
	const std::string where = "ldap://127.0.0.1:" + std::to_string(srv.acc.local_endpoint().port());
	auto bad = ldap::sync::connect(where + "/??sub?(cn=x");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::invalid_url);
	CHECK(bad.error() == ldap::url::parse(where + "/??sub?(cn=x").error());
	CHECK(srv.requests == 0);
	auto c = ldap::sync::connect(where);
	REQUIRE(c.has_value());
	CHECK(c->is_open());
	CHECK(ldap::sync::who_am_i(*c) == "dn:cn=me");
	CHECK(srv.requests == 1);
}

// ---------------------------------------------------------------- wrappers
//
// Each wrapper against a scripted server (mock_ldap.hpp's serve_script) on
// its own thread: the request on the wire, the value returned, and an LDAP
// error result returned as the same ldap::error as the async API's.

namespace {

// One connection accepted on loopback, served by a scripted session (or a
// StartTLS upgrade) on the server's own thread and io_context.
struct peer_server
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
	corosio::tcp_socket peer{ ioc };
	server_log log{};
	outcome<void> session{};
	std::thread thread{};

	peer_server()
	{
		log.hang_up = [this] { peer.close(); };
	}
	peer_server(const peer_server &) = delete;
	auto operator=(const peer_server &) -> peer_server & = delete;

	// Ends a session still waiting (the test failed before the client hung
	// up), then joins.
	~peer_server()
	{
		if (!thread.joinable()) {
			return;
		}
		capy::run_async(ioc.get_executor())([](corosio::tcp_acceptor &a, corosio::tcp_socket &p) -> capy::task<void> {
			a.close();
			p.close();
			co_return;
		}(acc, peer));
		thread.join();
	}

	// Runs `script`, then waits for the client to hang up: any request
	// after the script's last (an UnbindRequest, say) is logged as an error.
	void serve(std::vector<step> script)
	{
		script.push_back(client_hangs_up());
		start(serve_script(net::transport::wrap(socket_ref{ &peer }, "server"), std::move(script), log));
	}

	// Expects a StartTLS request and answers it with success, runs the
	// server side of the handshake with `leaf`, then answers binds over TLS
	// until the client hangs up.
	void serve_start_tls(test_pki::issued leaf) { start(upgrade(peer, std::move(leaf), log)); }

	auto url() const -> ldap::url
	{
		return *ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
	}

	// Waits for the session to end: the script ran out, or the client hung
	// up. After it the test thread may read the log.
	void join()
	{
		thread.join();
		session.get();
	}

  private:
	void start(capy::task<void> s)
	{
		spawn(
		  ioc,
		  [](corosio::tcp_acceptor &a, corosio::tcp_socket &p, capy::task<void> t) -> capy::task<void> {
			  auto [ec] = co_await a.accept(p);
			  if (ec) {
				  throw std::system_error(ec, "accept");
			  }
			  co_await std::move(t);
		  }(acc, peer, std::move(s)),
		  session);
		thread = std::thread([this] { ioc.run(); });
	}

	static auto upgrade(corosio::tcp_socket &peer, test_pki::issued leaf, server_log &log) -> capy::task<void>
	{
		net::transport plain = net::transport::wrap(socket_ref{ &peer }, "server");
		net::read_buffer buf;
		auto req = co_await net::read_message(plain, buf, as_server);
		if (!req) {
			log.error = "read StartTLS: " + std::string(req.error().message());
			co_return;
		}
		const std::int32_t id = req->id;
		const auto *x = std::get_if<ldap::extended_request>(&req->op);
		const bool is_start_tls = x != nullptr && x->request_name == ldap::start_tls_oid;
		log.received.push_back(std::move(*req));
		if (!is_start_tls) {
			log.error = "expected a StartTLS request";
			co_return;
		}
		const std::string ok = bytes_of(
		  ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::start_tls_oid) } });
		if (auto w = co_await net::write_bytes(plain, std::as_bytes(std::span(ok))); !w) {
			log.error = "write: " + std::string(w.error().message());
			co_return;
		}
		// This thread's first handshake may meet the client's (the
		// connection's I/O thread): see prime_corosio_openssl().
		net::detail::prime_corosio_openssl();
		corosio::tls_context ctx;
		if (ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem)
			|| ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem)) {
			log.error = "server certificate";
			co_return;
		}
		corosio::openssl_stream tls(&peer, ctx);
		if (auto [ec] = co_await tls.handshake(corosio::tls_role::server); ec) {
			log.error = "server handshake: " + ec.message();
			co_return;
		}
		net::transport secure = net::transport::wrap(socket_ref{ &tls }, "server tls");
		net::read_buffer tls_buf;
		while (true) {
			auto r = co_await net::read_message(secure, tls_buf, as_server);
			if (!r) {
				// The client hung up: close() sends no close_notify, so between
				// PDUs that reads as stream_truncated rather than eof.
				const auto code = r.error().code;
				if (code != capy::cond::eof && code != capy::cond::stream_truncated) {
					log.error = "read over TLS: " + std::string(r.error().message());
				}
				co_return;
			}
			const bool is_bind = std::holds_alternative<ldap::bind_request>(r->op);
			const std::string out = bytes_of(bind_resp(r->id));
			log.received.push_back(std::move(*r));
			if (!is_bind) {
				log.error = "expected a bind request over TLS";
				co_return;
			}
			if (auto w = co_await net::write_bytes(secure, std::as_bytes(std::span(out))); !w) {
				log.error = "write over TLS: " + std::string(w.error().message());
				co_return;
			}
		}
	}
};

// A sync::connection connected to `srv`. The operation timeout fails a call the
// server never answers (a script too short) instead of hanging the test.
struct connected
{
	ldap::sync::connection c;
	explicit connected(peer_server &srv)
	{
		auto opened = ldap::sync::connect(srv.url(), { .operation_timeout = std::chrono::seconds(10) });
		REQUIRE(opened.has_value());
		c = std::move(*opened);
	}
};

// Hangs up and waits for the server's session to end; what it received.
auto hang_up(ldap::sync::connection &c, peer_server &srv) -> std::vector<ldap::message> &
{
	c.close();
	srv.join();
	CHECK_THAT(srv.log.error, IsEmpty());
	return srv.log.received;
}

template<class Response>
auto result_msg(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {}) -> ldap::message
{
	return ldap::message{ id, Response{ ldap::ldap_result{ code, "", diagnostic } } };
}

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
constexpr std::string_view jdoe_str = "uid=jdoe,ou=people,dc=example,dc=org";

}// namespace

TEST_CASE("sync: sasl_bind", "[net][sync][sasl]")
{
	peer_server srv;
	srv.serve({ answer({ ldap::message{ 1, ldap::bind_response{ ldap::ldap_result{ 0 } } } }),
	  answer({ ldap::message{ 2, ldap::bind_response{ ldap::ldap_result{ 48, "", "no client certificate" } } } }) });
	connected k(srv);
	ldap::sasl_external as_jdoe("dn:uid=jdoe,ou=people,dc=example,dc=org");
	REQUIRE(k.c.sasl_bind(as_jdoe).has_value());
	ldap::sasl_external plain;
	auto r = k.c.sasl_bind(plain, jdoe);
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::inappropriate_authentication);
	CHECK(r.error().code == ldap::cond::auth_failed);
	CHECK(r.error().diagnostic == "no client certificate");
	CHECK(r.error().context == "sasl bind EXTERNAL");
	CHECK(k.c.is_open());
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(got[0]
		  == ldap::message{
			1, ldap::bind_request{ 3, "", ldap::sasl_auth{ "EXTERNAL", "dn:uid=jdoe,ou=people,dc=example,dc=org" } } });
	CHECK(got[1] == ldap::message{ 2, ldap::bind_request{ 3, jdoe_str, ldap::sasl_auth{ "EXTERNAL", "" } } });
}

TEST_CASE("sync: start_tls refused leaves the connection in clear", "[net][sync][starttls]")
{
	peer_server srv;
	srv.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 52, "", "no TLS here" } } } }),
	  answer({ bind_resp(2) }) });
	connected k(srv);
	CHECK_FALSE(k.c.is_tls());
	auto r = k.c.start_tls();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::unavailable);
	CHECK(r.error().diagnostic == "no TLS here");
	CHECK(r.error().context == "start tls");
	CHECK(k.c.is_open());
	CHECK_FALSE(k.c.is_tls());
	CHECK(k.c.simple_bind(*ldap::dn::parse(admin), "secret").has_value());
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(got[0] == ldap::message{ 1, ldap::extended_request{ ldap::start_tls_oid } });
	CHECK(got[1] == bind_request_msg(2));
}

TEST_CASE("sync: start_tls upgrades, then is_tls()", "[net][sync][starttls]")
{
	test_pki pki("jhetz-ldap sync StartTLS test CA");
	peer_server srv;
	const auto leaf = pki.issue("localhost", "DNS:localhost,IP:127.0.0.1");
	srv.serve_start_tls(leaf);
	connected k(srv);
	CHECK_FALSE(k.c.is_tls());
	CHECK(k.c.peer_certificate().empty());
	auto r = k.c.start_tls({ .ca_pem = std::pmr::string(pki.ca_pem()) }, std::chrono::seconds(10));
	REQUIRE(r.has_value());
	CHECK(k.c.is_tls());
	CHECK(k.c.is_open());
	CHECK(k.c.peer_certificate() == certificate_der(leaf.cert_pem));
	CHECK(k.c.simple_bind(*ldap::dn::parse(admin), "secret").has_value());
	const auto &got = hang_up(k.c, srv);
	// is_tls() describes the open connection: false once closed.
	CHECK_FALSE(k.c.is_open());
	CHECK_FALSE(k.c.is_tls());
	CHECK(k.c.peer_certificate().empty());
	REQUIRE(got.size() == 2);
	CHECK(got[0] == ldap::message{ 1, ldap::extended_request{ ldap::start_tls_oid } });
	CHECK(got[1] == bind_request_msg(2));
}

TEST_CASE("sync: add", "[net][sync]")
{
	const ldap::control post_read{ "1.3.6.1.1.13.2", false, "entry" };
	ldap::message ok = result_msg<ldap::add_response>(1);
	ok.controls.push_back(post_read);
	peer_server srv;
	srv.serve({ answer({ ok }), answer({ result_msg<ldap::add_response>(2, 68, "exists") }) });
	connected k(srv);
	auto r =
	  k.c.add({ .entry = jdoe, .attributes = { { "objectClass", { "inetOrgPerson" } }, { "cn", { "Jöhn Doe" } } } });
	REQUIRE(r.has_value());
	REQUIRE(r->controls.size() == 1);
	CHECK(r->controls[0] == post_read);
	auto again = k.c.add({ .entry = jdoe, .attributes = { { "cn", { "x" } } } });
	REQUIRE_FALSE(again.has_value());
	CHECK(again.error().code == ldap::errc::entry_already_exists);
	CHECK(again.error().code == ldap::cond::already_exists);
	CHECK(again.error().context == "add uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(again.error().diagnostic == "exists");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(got[0]
		  == ldap::message{
			1, ldap::add_request{ jdoe_str, { { "objectClass", { "inetOrgPerson" } }, { "cn", { "Jöhn Doe" } } } } });
	CHECK(got[1] == ldap::message{ 2, ldap::add_request{ jdoe_str, { { "cn", { "x" } } } } });
}

TEST_CASE("sync: modify", "[net][sync]")
{
	peer_server srv;
	srv.serve({ answer({ result_msg<ldap::modify_response>(1) }),
	  answer({ result_msg<ldap::modify_response>(2, 50, "no write access") }) });
	connected k(srv);
	auto r = k.c.modify(
	  { .object = jdoe, .changes = { ldap::mod::replace("sn", { "Doe" }), ldap::mod::remove("description") } });
	REQUIRE(r.has_value());
	CHECK(r->controls.empty());
	auto denied = k.c.modify({ .object = jdoe, .changes = { ldap::mod::replace("sn", { "X" }) } });
	REQUIRE_FALSE(denied.has_value());
	CHECK(denied.error().code == ldap::errc::insufficient_access_rights);
	CHECK(denied.error().code == ldap::cond::access_denied);
	CHECK(denied.error().context == "modify uid=jdoe,ou=people,dc=example,dc=org");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	using op = ldap::modify_operation;
	CHECK(got[0]
		  == ldap::message{ 1,
			ldap::modify_request{ jdoe_str,
			  { ldap::modify_change{ op::replace, { "sn", { "Doe" } } },
				ldap::modify_change{ op::delete_, { "description", {} } } } } });
	CHECK(got[1]
		  == ldap::message{
			2, ldap::modify_request{ jdoe_str, { ldap::modify_change{ op::replace, { "sn", { "X" } } } } } });
}

TEST_CASE("sync: del", "[net][sync]")
{
	peer_server srv;
	srv.serve({ answer({ result_msg<ldap::del_response>(1) }),
	  answer({ result_msg<ldap::del_response>(2, 66, "has children") }) });
	connected k(srv);
	REQUIRE(k.c.del({ .entry = jdoe }).has_value());
	auto busy = k.c.del({ .entry = *ldap::dn::parse(people) });
	REQUIRE_FALSE(busy.has_value());
	CHECK(busy.error().code == ldap::errc::not_allowed_on_non_leaf);
	CHECK(busy.error().context == "delete ou=people,dc=example,dc=org");
	CHECK(busy.error().diagnostic == "has children");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(got[0] == ldap::message{ 1, ldap::del_request{ jdoe_str } });
	CHECK(got[1] == ldap::message{ 2, ldap::del_request{ people } });
}

TEST_CASE("sync: modify_dn", "[net][sync]")
{
	peer_server srv;
	srv.serve({ answer({ result_msg<ldap::modify_dn_response>(1) }),
	  answer({ result_msg<ldap::modify_dn_response>(2, 68, "target exists") }) });
	connected k(srv);
	REQUIRE(k.c
		.modify_dn({ .entry = jdoe,
		  .new_rdn = ldap::rdn{ "uid=john.doe" },
		  .delete_old_rdn = false,
		  .new_superior = ldap::dn{ "ou=alumni,dc=example,dc=org" } })
		.has_value());
	auto taken = k.c.modify_dn({ .entry = jdoe, .new_rdn = ldap::rdn{ "uid=jane" } });
	REQUIRE_FALSE(taken.has_value());
	CHECK(taken.error().code == ldap::errc::entry_already_exists);
	CHECK(taken.error().diagnostic == "target exists");
	// Refused before anything is sent.
	auto empty = k.c.modify_dn({ .entry = jdoe });
	REQUIRE_FALSE(empty.has_value());
	CHECK(empty.error().code == ldap::client_errc::invalid_dn);
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(
	  got[0]
	  == ldap::message{ 1, ldap::modify_dn_request{ jdoe_str, "uid=john.doe", false, "ou=alumni,dc=example,dc=org" } });
	CHECK(got[1] == ldap::message{ 2, ldap::modify_dn_request{ jdoe_str, "uid=jane", true } });
}

TEST_CASE("sync: compare", "[net][sync]")
{
	peer_server srv;
	srv.serve({ answer({ result_msg<ldap::compare_response>(1, 6) }),
	  answer({ result_msg<ldap::compare_response>(2, 5) }),
	  answer({ result_msg<ldap::compare_response>(3, 16, "no such attribute") }) });
	connected k(srv);
	auto yes = k.c.compare({ .entry = jdoe, .attribute = "mail", .value = "jdoe@example.org" });
	REQUIRE(yes.has_value());
	CHECK(*yes);
	auto no = k.c.compare({ .entry = jdoe, .attribute = "cn", .value = "Jöhn" });
	REQUIRE(no.has_value());
	CHECK_FALSE(*no);
	auto missing = k.c.compare({ .entry = jdoe, .attribute = "pager", .value = "1" });
	REQUIRE_FALSE(missing.has_value());
	CHECK(missing.error().code == ldap::errc::no_such_attribute);
	CHECK(missing.error().code == ldap::cond::not_found);
	CHECK(missing.error().context == "compare uid=jdoe,ou=people,dc=example,dc=org");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 3);
	CHECK(got[0] == ldap::message{ 1, ldap::compare_request{ jdoe_str, { "mail", "jdoe@example.org" } } });
	CHECK(got[1] == ldap::message{ 2, ldap::compare_request{ jdoe_str, { "cn", "Jöhn" } } });
	CHECK(got[2] == ldap::message{ 3, ldap::compare_request{ jdoe_str, { "pager", "1" } } });
}

TEST_CASE("sync: extended", "[net][sync]")
{
	peer_server srv;
	srv.serve({ answer({ ldap::message{
				  1, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.4.5", std::string("\x04\x01x", 3) } } }),
	  answer({ ldap::message{
		2, ldap::extended_response{ ldap::ldap_result{ 2, "", "unsupported extended operation" } } } }) });
	connected k(srv);
	auto x = k.c.extended({ .name = "1.2.3.4", .value = std::string("\x30\x00", 2) });
	REQUIRE(x.has_value());
	CHECK(x->name == "1.2.3.4.5");
	CHECK(x->value == std::pmr::string("\x04\x01x", 3));
	auto unknown = k.c.extended({ .name = "1.9.9" });
	REQUIRE_FALSE(unknown.has_value());
	CHECK(unknown.error().code == ldap::errc::protocol_error);
	CHECK(unknown.error().context == "extended operation 1.9.9");
	CHECK(unknown.error().diagnostic == "unsupported extended operation");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(got[0] == ldap::message{ 1, ldap::extended_request{ "1.2.3.4", std::string("\x30\x00", 2) } });
	CHECK(got[1] == ldap::message{ 2, ldap::extended_request{ "1.9.9" } });
}

TEST_CASE("sync: extended with intermediate responses", "[net][sync][intermediate]")
{
	peer_server srv;
	srv.serve({ answer({ ldap::message{ 1, ldap::intermediate_response{ "1.2.3.6", "first" } },
	  ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 0 } } } }) });
	connected k(srv);
	auto x = k.c.extended({ .name = "1.2.3.4", .intermediate_responses = true });
	REQUIRE(x.has_value());
	REQUIRE(x->intermediates.size() == 1);
	CHECK(x->intermediates[0].response_name == "1.2.3.6");
	CHECK(x->intermediates[0].response_value == "first");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 1);
}

TEST_CASE("sync: password_modify", "[net][sync]")
{
	using namespace std::string_literals;
	peer_server srv;
	srv.serve({ answer({ ldap::message{
				  1, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "\x30\x07\x80\x05s3cr3"s } } }),
	  answer({ ldap::message{ 2, ldap::extended_response{ ldap::ldap_result{ 49, "", "old password wrong" } } } }) });
	connected k(srv);
	auto generated = ldap::sync::password_modify(k.c, { .user = std::string(jdoe_str) });
	REQUIRE(generated.has_value());
	CHECK(*generated == "s3cr3");
	auto refused =
	  ldap::sync::password_modify(k.c, { .user = "uid=jdoe", .old_password = "bad", .new_password = "new" });
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::errc::invalid_credentials);
	CHECK(refused.error().context == "password modify uid=jdoe");
	CHECK(refused.error().diagnostic == "old password wrong");
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	// SEQUENCE { [0] user }
	CHECK(
	  got[0]
	  == ldap::message{ 1,
		ldap::extended_request{ ldap::password_modify_oid, "\x30\x26\x80\x24uid=jdoe,ou=people,dc=example,dc=org"s } });
	// SEQUENCE { [0] user, [1] old, [2] new }
	CHECK(got[1]
		  == ldap::message{ 2,
			ldap::extended_request{ ldap::password_modify_oid,
			  "\x30\x14\x80\x08uid=jdoe\x81\x03"
			  "bad\x82\x03new"s } });
}

TEST_CASE("sync: transactions", "[net][sync][transaction]")
{
	const auto ext = [](std::int32_t id, std::optional<std::string_view> value = std::nullopt) {
		return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, value } };
	};
	peer_server srv;
	srv.serve({ answer({ ext(1, "t1") }),
	  answer({ result_msg<ldap::del_response>(2) }),
	  answer({ ext(3) }),
	  answer({ ext(4, "t2") }),
	  answer({ ext(5) }),// the destructor's abort, waited for
	  answer({ ext(6, "t3") }),
	  answer({ ext(7) }) });
	connected k(srv);
	auto t = k.c.begin_transaction();
	REQUIRE(t.has_value());
	// Moving the connection leaves its I/O thread where the transaction has it.
	ldap::sync::connection elsewhere = std::move(k.c);
	k.c = std::move(elsewhere);
	CHECK(t->identifier() == "t1");
	CHECK(t->is_open());
	auto d = t->del({ .entry = jdoe });
	REQUIRE(d.has_value());
	CHECK(d->message_id == 2);
	auto done = t->commit();
	REQUIRE(done.has_value());
	CHECK_FALSE(t->is_open());
	{
		auto open = k.c.begin_transaction();
		REQUIRE(open.has_value());
		ldap::sync::transaction moved = std::move(*open);
		CHECK_FALSE(open->is_open());
		CHECK(open->identifier().empty());
		CHECK(open->commit().error().code == ldap::client_errc::not_connected);
	}
	auto id = k.c.start_transaction();
	REQUIRE(id.has_value());
	CHECK(*id == "t3");
	REQUIRE(k.c.end_transaction(*id, false).has_value());
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 7);
	CHECK(got[1].controls
		  == std::pmr::vector<ldap::control>{ ldap::control{ ldap::transaction_specification_oid, true, "t1" } });
	const auto end_of = [](const ldap::message &m) {
		return ldap::decode_end_transaction_request(*std::get<ldap::extended_request>(m.op).request_value).value();
	};
	CHECK(end_of(got[2]) == ldap::end_transaction_request{ true, "t1" });
	CHECK(end_of(got[4]) == ldap::end_transaction_request{ false, "t2" });
	CHECK(end_of(got[6]) == ldap::end_transaction_request{ false, "t3" });
}

TEST_CASE("sync: a transaction's add, modify and modify DN, then abort", "[net][sync][transaction]")
{
	const auto ext = [](std::int32_t id, std::optional<std::string_view> value = std::nullopt) {
		return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, value } };
	};
	const ldap::dn group{ "cn=staff,ou=groups,dc=example,dc=org" };
	peer_server srv;
	srv.serve({ answer({ ext(1, "t1") }),
	  answer({ result_msg<ldap::add_response>(2) }),
	  answer({ result_msg<ldap::modify_response>(3, 50, "no write access") }),
	  answer({ result_msg<ldap::modify_dn_response>(4) }),
	  answer({ ext(5) }) });
	connected k(srv);
	auto t = k.c.begin_transaction();
	REQUIRE(t.has_value());
	auto a = t->add({ .entry = jdoe, .attributes = { { "uid", { "jdoe" } } } });
	REQUIRE(a.has_value());
	CHECK(a->message_id == 2);
	auto m = t->modify({ .object = group, .changes = { ldap::mod::add("member", { jdoe_str }) } });
	REQUIRE_FALSE(m.has_value());
	CHECK(m.error().code == ldap::errc::insufficient_access_rights);
	CHECK(m.error().diagnostic == "no write access");
	auto r = t->modify_dn({ .entry = jdoe, .new_rdn = ldap::rdn{ "uid=john" } });
	REQUIRE(r.has_value());
	CHECK(r->message_id == 4);
	REQUIRE(t->abort().has_value());
	CHECK_FALSE(t->is_open());
	// Settled: refused without a request, as ldap::transaction does.
	auto again = t->abort();
	REQUIRE_FALSE(again.has_value());
	CHECK(again.error().code == std::errc::invalid_argument);
	CHECK(again.error().context == "abort transaction: the transaction is already committed or aborted");
	auto late = t->add({ .entry = jdoe });
	REQUIRE_FALSE(late.has_value());
	CHECK(late.error().code == std::errc::invalid_argument);

	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 5);
	const std::pmr::vector<ldap::control> spec{ ldap::control{ ldap::transaction_specification_oid, true, "t1" } };
	CHECK(got[1].op == ldap::protocol_op{ ldap::add_request{ jdoe_str, { { "uid", { "jdoe" } } } } });
	CHECK(got[1].controls == spec);
	CHECK(got[2].op
		  == ldap::protocol_op{ ldap::modify_request{
			group.to_string(), { ldap::modify_change{ ldap::modify_operation::add, { "member", { jdoe_str } } } } } });
	CHECK(got[2].controls == spec);
	CHECK(got[3].op == ldap::protocol_op{ ldap::modify_dn_request{ jdoe_str, "uid=john" } });
	CHECK(got[3].controls == spec);
	CHECK(ldap::decode_end_transaction_request(*std::get<ldap::extended_request>(got[4].op).request_value).value()
		  == ldap::end_transaction_request{ false, "t1" });
}

TEST_CASE("sync: a move-assigned transaction aborts the one it replaces", "[net][sync][transaction]")
{
	const auto ext = [](std::int32_t id, std::optional<std::string_view> value = std::nullopt) {
		return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, value } };
	};
	peer_server srv;
	srv.serve({ answer({ ext(1, "t1") }),
	  answer({ ext(2, "t2") }),
	  answer({ ext(3) }),// t1's abort, waited for by the assignment
	  answer({ result_msg<ldap::del_response>(4) }),
	  answer({ ext(5) }) });// t2's commit
	connected k(srv);
	auto u = k.c.begin_transaction();
	REQUIRE(u.has_value());
	auto v = k.c.begin_transaction();
	REQUIRE(v.has_value());
	*u = std::move(*v);
	CHECK(u->identifier() == "t2");
	CHECK(u->is_open());
	CHECK(u->del({ .entry = jdoe }).has_value());
	// Every operation of the moved-from one is refused without a request.
	const auto refused = [](const ldap::error &e, std::string_view what) {
		CHECK(e.code == ldap::client_errc::not_connected);
		CHECK(std::string_view(e.context) == std::string(what) + ": no transaction (moved from)");
	};
	CHECK_FALSE(v->is_open());
	CHECK(v->identifier().empty());
	refused(v->add({ .entry = jdoe }).error(), "add");
	refused(v->modify({ .object = jdoe }).error(), "modify");
	refused(v->del({ .entry = jdoe }).error(), "delete");
	refused(v->modify_dn({ .entry = jdoe, .new_rdn = ldap::rdn{ "uid=john" } }).error(), "modify DN");
	refused(v->commit().error(), "commit transaction");
	refused(v->abort().error(), "abort transaction");
	// Assigning a moved-from one ends u's transaction too: t2 committed
	// first, so nothing is sent.
	REQUIRE(u->commit().has_value());
	*u = std::move(*v);
	CHECK_FALSE(u->is_open());

	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 5);
	const auto end_of = [](const ldap::message &m) {
		return ldap::decode_end_transaction_request(*std::get<ldap::extended_request>(m.op).request_value).value();
	};
	CHECK(end_of(got[2]) == ldap::end_transaction_request{ false, "t1" });
	CHECK(got[3].controls
		  == std::pmr::vector<ldap::control>{ ldap::control{ ldap::transaction_specification_oid, true, "t2" } });
	CHECK(end_of(got[4]) == ldap::end_transaction_request{ true, "t2" });
}

TEST_CASE("sync: a transaction's destructor waits for the abort's answer only so long", "[net][sync][transaction]")
{
	peer_server srv;
	srv.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "t1" } } }),
	  step{},// the abort, never answered
	  step{},// its abandon
	  step{} });// the abort queued again by the ldap::transaction's destructor
	auto opened = ldap::sync::connect(srv.url());// no default timeout
	REQUIRE(opened.has_value());
	auto &c = *opened;
	const auto started = std::chrono::steady_clock::now();
	{
		auto t = c.begin_transaction();
		REQUIRE(t.has_value());
	}
	CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds(30));
	const auto &got = hang_up(c, srv);
	REQUIRE(got.size() == 4);
	CHECK(std::holds_alternative<ldap::extended_request>(got[1].op));
	CHECK(std::holds_alternative<ldap::abandon_request>(got[2].op));
	CHECK(std::holds_alternative<ldap::extended_request>(got[3].op));
}

TEST_CASE("sync: change_password and reset_password", "[net][sync][password]")
{
	peer_server srv;
	srv.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 0 } } } }),
	  answer({ ldap::message{ 2, ldap::extended_response{ ldap::ldap_result{ 0 } } } }) });
	connected k(srv);
	CHECK(ldap::sync::change_password(k.c, jdoe, "old", "new").has_value());
	CHECK(ldap::sync::reset_password(k.c, jdoe, "next").has_value());
	// Active Directory's, on plain ldap://: refused before sending.
	CHECK(k.c.security_layer() == ldap::sasl_protection::none);
	auto refused = ldap::ad::reset_password(k.c, jdoe, "next");
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::client_errc::tls_required);
	auto no_dn = ldap::ad::change_password(k.c, {}, "old", "new");
	REQUIRE_FALSE(no_dn.has_value());
	CHECK(no_dn.error().code == ldap::client_errc::invalid_dn);
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 2);
	CHECK(std::holds_alternative<ldap::extended_request>(got[0].op));
	CHECK(std::holds_alternative<ldap::extended_request>(got[1].op));
}

TEST_CASE("sync: close without an UnbindRequest", "[net][sync]")
{
	{
		ldap::sync::connection never;
		never.close();// nothing to close
		CHECK_FALSE(never.is_open());
		CHECK_FALSE(never.is_tls());
	}
	peer_server srv;
	srv.serve({ answer({ bind_resp(1) }) });
	connected k(srv);
	REQUIRE(k.c.simple_bind(*ldap::dn::parse(admin), "secret").has_value());
	k.c.close();
	CHECK_FALSE(k.c.is_open());
	auto after = ldap::sync::who_am_i(k.c);
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == ldap::client_errc::not_sent);
	k.c.close();// again: nothing happens
	// The server saw the bind, then the connection end: an UnbindRequest
	// would show in the log and as an error (peer_server::serve).
	const auto &got = hang_up(k.c, srv);
	REQUIRE(got.size() == 1);
	CHECK(got[0] == bind_request_msg(1));
}

#ifdef JHETZ_LDAPSEARCH
// JHETZ_LDAPSEARCH is the CLI's $<TARGET_FILE>: the full path, with .exe on
// Windows. Commands go through platform.hpp's run_command (sh or cmd.exe).
TEST_CASE("jhetz-ldapsearch against the in-process server", "[net][cli]")
{
	server_thread srv;
	const std::string cli = shell_quote(JHETZ_LDAPSEARCH);
	const std::string url = std::string(srv.url().to_string());

	// status is -1 when popen failed or the command did not exit (a signal).
	{
		auto [status, out] =
		  run_command(cli + " -D cn=admin,dc=example,dc=org -w secret --page 5 "
					  + shell_quote(url + "/ou=people,dc=example,dc=org") + " " + shell_quote("(uid=*)") + " cn");
		INFO("search output: " << out);
		REQUIRE(status != -1);
		CHECK(status == 0);
		CHECK_THAT(out, Catch::Matchers::ContainsSubstring("dn: uid=x,ou=people,dc=example,dc=org\ncn: X\n"));
		CHECK_THAT(out, Catch::Matchers::ContainsSubstring("dn: uid=y,ou=people,dc=example,dc=org"));
		CHECK_THAT(out, Catch::Matchers::ContainsSubstring("# 2 entries in 1 pages"));
	}
	{
		auto [status, out] = run_command(cli + " -D cn=admin,dc=example,dc=org -w wrong " + shell_quote(url));
		INFO("wrong password output: " << out);
		REQUIRE(status != -1);
		CHECK(status == 1);
		CHECK_THAT(out, Catch::Matchers::ContainsSubstring("invalid credentials"));
	}
	{
		auto [status, out] = run_command(cli + " -Y PLAIN " + shell_quote(url));
		INFO("usage error output: " << out);
		REQUIRE(status != -1);
		CHECK(status == 2);
		CHECK_THAT(out, Catch::Matchers::ContainsSubstring("only -Y EXTERNAL is supported"));
	}
}
#endif
