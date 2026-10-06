// ldap::sync::client against an in-process LDAP server on loopback TCP that
// runs on its own thread and io_context and answers requests as they come.
#include "jhetz/ldap/sync.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <atomic>
#include <cstdio>
#include <future>
#include <string>
#include <thread>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;

namespace {

// Answers each request when it arrives: bind (49 for password "wrong"),
// search (two entries under its base, then done), extended (who am I),
// until the client unbinds or hangs up. Abandons are ignored.
capy::task<void> serve_session(net::transport t, std::atomic<int> &requests)
{
	net::read_buffer buf;
	while (true) {
		auto r = co_await net::read_message(t, buf, as_server);
		if (!r || std::holds_alternative<ldap::unbind_request>(r->op)) co_return;
		++requests;
		std::string out;
		if (const auto *b = std::get_if<ldap::bind_request>(&r->op)) {
			const auto *pw = std::get_if<ldap::simple_auth>(&b->authentication);
			out = bytes_of(bind_resp(r->id, pw != nullptr && pw->password == "wrong" ? 49 : 0));
		} else if (const auto *s = std::get_if<ldap::search_request>(&r->op)) {
			const std::string base(s->base_object);
			out = bytes_of(entry_msg(r->id, "uid=x," + base, "X")) + bytes_of(entry_msg(r->id, "uid=y," + base, "Y"))
				  + bytes_of(done_msg(r->id));
		} else if (std::holds_alternative<ldap::extended_request>(r->op)) {
			out = bytes_of(
			  ldap::message{ r->id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "dn:cn=me" } });
		} else {
			continue;
		}
		if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(out))); !w) co_return;
	}
}

capy::task<void> accept_loop(corosio::io_context &ioc, corosio::tcp_acceptor &acc, std::atomic<int> &requests)
{
	while (true) {
		auto [ec, peer] = co_await acc.accept();
		if (ec) co_return;
		capy::run_async(ioc.get_executor())(serve_session(net::transport::wrap(std::move(peer), "server"), requests));
	}
}

// The server, on its own thread.
struct server_thread
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 64 };
	std::atomic<int> requests{ 0 };
	std::thread thread;

	server_thread()
	{
		capy::run_async(ioc.get_executor())(accept_loop(ioc, acc, requests));
		thread = std::thread([this] { ioc.run(); });
	}
	// The accept loop ends when the acceptor closes (on the server thread);
	// sessions end when their client hangs up. Then run() returns.
	~server_thread()
	{
		capy::run_async(ioc.get_executor())([](corosio::tcp_acceptor &a) -> capy::task<void> {
			a.close();
			co_return;
		}(acc));
		thread.join();
	}
	ldap::url url() const
	{
		return *ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
	}
};

}// namespace

TEST_CASE("sync: connect, bind, search and unbind", "[net][sync]")
{
	server_thread srv;
	ldap::sync::client c({ .timeout = std::chrono::seconds(10) });
	CHECK_FALSE(c.is_open());
	REQUIRE(c.connect(srv.url()).has_value());
	CHECK(c.is_open());
	CHECK(c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret").has_value());
	auto bad = c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::cond::auth_failed);
	auto r = c.search({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } });
	REQUIRE(r.has_value());
	REQUIRE(r->size() == 2);
	CHECK((*r)[0].dn == "uid=x,ou=people,dc=example,dc=org");
	auto paged = c.search_paged({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } }, 10);
	REQUIRE(paged.has_value());
	CHECK(paged->size() == 2);
	CHECK(c.who_am_i() == "dn:cn=me");
	REQUIRE(c.unbind().has_value());
	CHECK_FALSE(c.is_open());
	auto after = c.search({});
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == ldap::client_errc::not_connected);
}

TEST_CASE("sync: many threads share one client", "[net][sync]")
{
	server_thread srv;
	ldap::sync::client c;
	REQUIRE(c.connect(srv.url()).has_value());
	constexpr int threads = 8, per_thread = 25;
	std::atomic<int> failures{ 0 };
	std::vector<std::thread> pool;
	for (int t = 0; t < threads; ++t) {
		pool.emplace_back([&c, &failures, t] {
			for (int i = 0; i < per_thread; ++i) {
				if (i % 2 == 0) {
					if (!c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")) ++failures;
					continue;
				}
				const std::string base = "ou=t" + std::to_string(t) + "i" + std::to_string(i) + ",dc=example,dc=org";
				auto r = c.search({ .base = *ldap::dn::parse(base) });
				if (!r || r->size() != 2 || !std::string_view((*r)[1].dn).ends_with(base)) ++failures;
			}
		});
	}
	for (auto &th : pool) th.join();
	CHECK(failures == 0);
	CHECK(srv.requests == threads * per_thread);
	CHECK(c.is_open());
}

TEST_CASE("sync: a blocking call from the I/O thread fails with would_deadlock", "[net][sync]")
{
	server_thread srv;
	ldap::sync::client c;
	REQUIRE(c.connect(srv.url()).has_value());
	std::promise<ldap::result<std::string>> got;
	capy::run_async(c.executor())(
	  [](ldap::sync::client &cl, std::promise<ldap::result<std::string>> &p) -> capy::task<void> {
		  p.set_value(cl.who_am_i());// blocking, on the I/O thread
		  co_return;
	  }(c, got));
	auto r = got.get_future().get();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::would_deadlock);
	// The client still works from other threads.
	CHECK(c.who_am_i() == "dn:cn=me");
}

TEST_CASE("sync: connect failures and destruction without unbind", "[net][sync]")
{
	std::uint16_t port = 0;
	{
		corosio::io_context ioc;
		corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
		port = acc.local_endpoint().port();
	}
	{
		ldap::sync::client c;
		auto r = c.connect(*ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::connection_refused);
	}
	server_thread srv;
	{
		ldap::sync::client c;
		REQUIRE(c.connect(srv.url()).has_value());
		REQUIRE(c.simple_bind(ldap::dn{}, "").has_value());
	}// destroyed while connected: closes and joins
	SUCCEED();
}

#ifdef JHETZ_LDAPSEARCH
#include <sys/wait.h>

namespace {

// Runs a command, returns its exit status and output (stdout and stderr).
std::pair<int, std::string> run_command(const std::string &command)
{
	std::string out;
	FILE *p = ::popen((command + " 2>&1").c_str(), "r");
	REQUIRE(p != nullptr);
	char buf[4096];
	while (std::size_t n = std::fread(buf, 1, sizeof buf, p)) out.append(buf, n);
	const int status = ::pclose(p);
	return { WIFEXITED(status) ? WEXITSTATUS(status) : -1, out };
}

}// namespace

TEST_CASE("jhetz-ldapsearch against the in-process server", "[net][cli]")
{
	server_thread srv;
	const std::string cli = JHETZ_LDAPSEARCH;
	const std::string url = std::string(srv.url().to_string());

	auto [status, out] = run_command(
	  cli + " -D cn=admin,dc=example,dc=org -w secret --page 5 '" + url + "/ou=people,dc=example,dc=org' '(uid=*)' cn");
	CHECK(status == 0);
	CHECK_THAT(out, Catch::Matchers::ContainsSubstring("dn: uid=x,ou=people,dc=example,dc=org\ncn: X\n"));
	CHECK_THAT(out, Catch::Matchers::ContainsSubstring("dn: uid=y,ou=people,dc=example,dc=org"));
	CHECK_THAT(out, Catch::Matchers::ContainsSubstring("# 2 entries in 1 pages"));

	auto [bad_status, bad_out] = run_command(cli + " -D cn=admin,dc=example,dc=org -w wrong " + url);
	CHECK(bad_status == 1);
	CHECK_THAT(bad_out, Catch::Matchers::ContainsSubstring("invalid credentials"));

	auto [usage_status, usage_out] = run_command(cli + " -Y PLAIN " + url);
	CHECK(usage_status == 2);
	CHECK_THAT(usage_out, Catch::Matchers::ContainsSubstring("only -Y EXTERNAL is supported"));
}
#endif
