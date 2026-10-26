// ldap::sync::client, the blocking pool, against in-process LDAP servers on
// loopback TCP running on their own thread and io_context: scripted ones
// (one script per accepted connection, mock_ldap.hpp's serve_script) and
// server_thread.hpp's, which answers whatever comes.
#include "jhetz/ldap/sync.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"
#include "server_thread.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_container_properties.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::IsEmpty;
using std::chrono::milliseconds;

namespace {

// Accepts connections one after another and runs the n-th script on the
// n-th, then stops accepting (a later connect is refused). stop() ends the
// sessions still running and joins the server's thread: only then may the
// test read the logs.
class threaded_script_server
{
  public:
	explicit threaded_script_server(std::vector<std::vector<step>> scripts) : scripts_(std::move(scripts))
	{
		capy::run_async(ioc_.get_executor())(accept_loop());
		thread_ = std::thread([this] { ioc_.run(); });
	}
	threaded_script_server(const threaded_script_server &) = delete;
	auto operator=(const threaded_script_server &) -> threaded_script_server & = delete;
	~threaded_script_server() { stop(); }

	[[nodiscard]] auto url() const -> ldap::url
	{
		return *ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port_));
	}
	[[nodiscard]] auto accepted() const -> std::size_t { return accepted_; }
	// After stop().
	[[nodiscard]] auto log(std::size_t n) -> server_log & { return logs_.at(n); }

	void stop()
	{
		if (!thread_.joinable()) {
			return;
		}
		capy::run_async(ioc_.get_executor())([](threaded_script_server &s) -> capy::task<void> {
			s.acc_.close();
			for (auto &p : s.peers_) {
				p.close();
			}
			co_return;
		}(*this));
		guard_.reset();
		thread_.join();
	}

  private:
	auto accept_loop() -> capy::task<void>
	{
		for (auto &script : scripts_) {
			auto &peer = peers_.emplace_back(ioc_);
			auto [ec] = co_await acc_.accept(peer);
			if (ec) {
				co_return;
			}
			auto &log = logs_.emplace_back();
			log.hang_up = [&peer] { peer.close(); };
			spawn(ioc_,
			  serve_script(net::transport::wrap(socket_ref{ &peer }, "server"), script, log),
			  sessions_.emplace_back());
			++accepted_;
		}
		acc_.close();
	}

	corosio::io_context ioc_{};
	// Keeps run() going until stop(), so that its task runs.
	std::optional<capy::work_guard<corosio::io_context::executor_type>> guard_{ ioc_.get_executor() };
	corosio::tcp_acceptor acc_{ ioc_, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8 };
	std::uint16_t port_ = acc_.local_endpoint().port();
	std::vector<std::vector<step>> scripts_;
	std::deque<corosio::tcp_socket> peers_{};
	std::deque<server_log> logs_{};
	std::deque<outcome<void>> sessions_{};
	std::atomic<std::size_t> accepted_{ 0 };
	std::thread thread_{};
};

// A URL nothing listens on: connects are refused at once.
auto refused_url() -> ldap::url
{
	std::uint16_t port = 0;
	{
		corosio::io_context ioc;
		corosio::tcp_acceptor a(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
		port = a.local_endpoint().port();
	}
	return *ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port));
}

auto text(const ldap::url &u) -> std::string { return std::string(std::string_view(u.to_string())); }

auto admin_setup() -> ldap::session_setup { return ldap::simple_bind_setup(*ldap::dn::parse(admin), "secret"); }

// The pool's options for `server`, with the admin bind as setup. The
// operation timeout fails a call the server never answers (a script too
// short) instead of hanging the test.
auto options_for(const ldap::url &server) -> ldap::client_options
{
	return {
		.servers = { server }, .connection = { .operation_timeout = std::chrono::seconds(10) }, .setup = admin_setup()
	};
}

auto whoami_msg(std::int32_t id) -> ldap::message
{
	return ldap::message{ id,
		ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "dn:" + std::string(admin) } };
}

auto compare_msg(std::int32_t id, std::int32_t code) -> ldap::message
{
	return ldap::message{ id, ldap::compare_response{ ldap::ldap_result{ code } } };
}

// Answers the setup's bind, reads one request and hangs up without an answer.
auto lost_after_bind() -> std::vector<step>
{
	return { answer({ bind_resp(1) }), step{ .read_request = true, .replies = {}, .close_after = true } };
}

// Reads one request (the UnbindRequest) and answers nothing.
auto unbind_read() -> step { return step{ .read_request = true, .replies = {} }; }

constexpr std::string_view jdoe = "uid=jdoe,ou=people,dc=example,dc=org";
const ldap::dn jdoe_dn{ "uid=jdoe,ou=people,dc=example,dc=org" };

}// namespace

TEST_CASE("sync client: acquire, then operations on the lease", "[net][sync][client]")
{
	threaded_script_server srv({ { answer({ bind_resp(1) }),
	  answer({ entry_msg(2, jdoe, "John"), done_msg(2) }),
	  answer({ whoami_msg(3) }),
	  unbind_read() } });
	{
		ldap::sync::client pool(options_for(srv.url()));
		CHECK(pool.connections() == 0);// opened lazily
		auto l = pool.acquire();
		REQUIRE(l.has_value());
		CHECK(static_cast<bool>(*l));
		CHECK(text(l->server()) == text(srv.url()));
		CHECK(l->is_open());
		CHECK_FALSE(l->is_tls());
		auto found = l->search(people_search());
		REQUIRE(found.has_value());
		REQUIRE(found->size() == 1);
		CHECK(found->front() == expected_entry(jdoe, "John"));
		CHECK(l->who_am_i() == "dn:" + std::string(admin));
		CHECK(pool.connections() == 1);
		ldap::sync::lease moved = std::move(*l);
		CHECK_FALSE(static_cast<bool>(*l));
		CHECK(l->server() == ldap::url{});
		CHECK_FALSE(l->is_open());
		auto none = l->who_am_i();
		REQUIRE_FALSE(none.has_value());
		CHECK(none.error().code == ldap::client_errc::not_connected);
		moved.release();
		CHECK_FALSE(static_cast<bool>(moved));
		moved.release();// again: nothing happens
		CHECK(pool.connections() == 1);// idle in the pool
	}// destroyed: the idle connection is unbound, then the thread joined
	srv.stop();
	const auto &got = srv.log(0);
	CHECK_THAT(got.error, IsEmpty());
	REQUIRE(got.received.size() == 4);
	CHECK(std::holds_alternative<ldap::search_request>(got.received[1].op));
	CHECK(std::holds_alternative<ldap::extended_request>(got.received[2].op));
	CHECK(std::holds_alternative<ldap::unbind_request>(got.received[3].op));
}

TEST_CASE("sync client: a transaction on an exclusive lease", "[net][sync][client][transaction]")
{
	const auto ext = [](std::int32_t id, std::optional<std::string_view> value = std::nullopt) {
		return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, value } };
	};
	threaded_script_server srv({ { answer({ bind_resp(1) }),
	  answer({ ext(2, "t1") }),
	  answer({ ldap::message{ 3, ldap::del_response{ ldap::ldap_result{ 0 } } } }),
	  answer({ ext(4) }),
	  unbind_read() } });
	{
		ldap::sync::client pool(options_for(srv.url()));
		auto l = pool.acquire({ .exclusive = true });
		REQUIRE(l.has_value());
		auto t = l->begin_transaction();
		REQUIRE(t.has_value());
		CHECK(t->identifier() == "t1");
		REQUIRE(t->del({ .entry = jdoe_dn }).has_value());
		REQUIRE(t->commit().has_value());
		CHECK_FALSE(t->is_open());
	}
	srv.stop();
	CHECK_THAT(srv.log(0).error, IsEmpty());
	CHECK(srv.log(0).received.size() == 5);
}

TEST_CASE("sync client: the read forwarders retry once on another connection", "[net][sync][client][retry]")
{
	SECTION("search(): the connection is lost")
	{
		threaded_script_server srv(
		  { lost_after_bind(), { answer({ bind_resp(1) }), answer({ entry_msg(2, jdoe, "John"), done_msg(2) }) } });
		ldap::sync::client pool(options_for(srv.url()));
		auto r = pool.search(people_search());
		REQUIRE(r.has_value());
		REQUIRE(r->size() == 1);
		CHECK(r->front() == expected_entry(jdoe, "John"));
		CHECK(srv.accepted() == 2);
		CHECK(pool.connections() == 1);
	}
	SECTION("compare(): the server is busy")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
		ldap::sync::client pool(options_for(srv.url()));
		auto r = pool.compare({ .entry = jdoe_dn, .attribute = "cn", .value = "John" });
		REQUIRE(r.has_value());
		CHECK(*r);
		CHECK(srv.accepted() == 2);
	}
	SECTION("who_am_i(): the connection is lost")
	{
		threaded_script_server srv({ lost_after_bind(), { answer({ bind_resp(1) }), answer({ whoami_msg(2) }) } });
		ldap::sync::client pool(options_for(srv.url()));
		CHECK(pool.who_am_i() == "dn:" + std::string(admin));
		CHECK(srv.accepted() == 2);
	}
	SECTION("search(): a result code that is not retried")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }), answer({ done_msg(2, 32) }) } });
		ldap::sync::client pool(options_for(srv.url()));
		auto r = pool.search(people_search());
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::no_such_object);
		CHECK(srv.accepted() == 1);
	}
}

TEST_CASE("sync client: a blocking call from the I/O thread fails with would_deadlock", "[net][sync][client]")
{
	server_thread srv;
	ldap::sync::client pool({ .servers = { srv.url() } });
	auto held = pool.acquire();
	REQUIRE(held.has_value());
	struct from_io_thread
	{
		ldap::result<ldap::sync::lease> acquired{};
		ldap::result<std::string> forwarded{};
		ldap::result<std::string> on_lease{};
		std::size_t connections = 1;
	};
	std::promise<from_io_thread> got;
	capy::run_async(pool.executor())(
	  [](ldap::sync::client &p, ldap::sync::lease &l, std::promise<from_io_thread> &out) -> capy::task<void> {
		  from_io_thread r;
		  r.acquired = p.acquire();// blocking, on the I/O thread
		  r.forwarded = p.who_am_i();
		  r.on_lease = l.who_am_i();
		  r.connections = p.connections();
		  out.set_value(std::move(r));
		  co_return;
	  }(pool, *held, got));
	auto r = got.get_future().get();
	REQUIRE_FALSE(r.acquired.has_value());
	REQUIRE_FALSE(r.forwarded.has_value());
	REQUIRE_FALSE(r.on_lease.has_value());
	for (const ldap::error *e : { &r.acquired.error(), &r.forwarded.error(), &r.on_lease.error() }) {
		CHECK(e->code == ldap::client_errc::would_deadlock);
		CHECK(e->context == "sync::client");
	}
	CHECK(r.connections == 0);
	// Everything still works from other threads.
	CHECK(pool.who_am_i() == "dn:cn=me");
	CHECK(held->who_am_i() == "dn:cn=me");
	CHECK(pool.connections() == 1);
}

namespace {

// Signals the first on_retry: an acquire() is then waiting out a backoff.
struct first_retry final : ldap::client_observer
{
	std::promise<void> seen{};
	std::atomic<bool> once{ false };

	void on_retry(const ldap::url &server, const ldap::error &failure, milliseconds delay) override
	{
		(void)server;
		(void)failure;
		(void)delay;
		if (!once.exchange(true)) {
			seen.set_value();
		}
	}
};

}// namespace

TEST_CASE("sync client: close() while another thread waits in acquire()", "[net][sync][client][close]")
{
	first_retry obs;
	ldap::sync::client pool({ .servers = { refused_url() },
	  .acquire_timeout = std::nullopt,// retries until close()
	  .backoff = { .initial = std::chrono::seconds(10), .max = std::chrono::seconds(10) },
	  .observer = &obs });
	std::optional<ldap::result<ldap::sync::lease>> got;
	std::thread waiter([&] { got = pool.acquire(); });
	obs.seen.get_future().wait();
	pool.close();
	waiter.join();
	REQUIRE(got.has_value());
	REQUIRE_FALSE(got->has_value());
	CHECK(got->error().code == ldap::client_errc::not_connected);
	auto later = pool.acquire();
	REQUIRE_FALSE(later.has_value());
	CHECK(later.error().code == ldap::client_errc::not_connected);
	pool.close();// again: nothing happens
}

TEST_CASE("sync client: close() from the I/O thread", "[net][sync][client][close]")
{
	server_thread srv;
	ldap::sync::client pool({ .servers = { srv.url() } });
	REQUIRE(pool.who_am_i().has_value());
	std::promise<void> closed;
	capy::run_async(pool.executor())([](ldap::sync::client &p, std::promise<void> &done) -> capy::task<void> {
		p.close();// at once, not would_deadlock
		done.set_value();
		co_return;
	}(pool, closed));
	closed.get_future().wait();
	auto after = pool.who_am_i();
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == ldap::client_errc::not_connected);
	CHECK(pool.connections() == 0);
}

TEST_CASE("sync client: destroyed while a lease is outstanding", "[net][sync][client][close]")
{
	threaded_script_server srv({ { answer({ bind_resp(1) }), client_hangs_up() } });
	ldap::sync::lease l;
	{
		ldap::sync::client pool(options_for(srv.url()));
		auto r = pool.acquire();
		REQUIRE(r.has_value());
		l = std::move(*r);
	}// closes the leased connection (no UnbindRequest); the lease keeps the I/O thread
	CHECK(static_cast<bool>(l));
	CHECK_FALSE(l.is_open());
	auto after = l.who_am_i();
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == ldap::cond::connection_lost);
	SECTION("released on this thread") { l.release(); }
	SECTION("destroyed on another thread")
	{
		std::thread([moved = std::move(l)] mutable { moved = ldap::sync::lease{}; }).join();
	}
	CHECK_FALSE(static_cast<bool>(l));// NOLINT(bugprone-use-after-move): moved-from is empty
	srv.stop();
	CHECK_THAT(srv.log(0).error, IsEmpty());
	CHECK(srv.log(0).received.size() == 1);// the bind only
}

TEST_CASE("sync client: many threads share the pool", "[net][sync][client]")
{
	server_thread srv;
	constexpr std::size_t max_connections = 3;
	ldap::sync::client pool({ .servers = { srv.url() }, .max_connections = max_connections });
	constexpr int threads = 8;
	constexpr int per_thread = 24;
	std::atomic<int> failures{ 0 };
	std::vector<std::thread> workers;
	workers.reserve(threads);
	for (int t = 0; t < threads; ++t) {
		workers.emplace_back([&pool, &failures, t] {
			for (int i = 0; i < per_thread; ++i) {
				const std::string base = "ou=t" + std::to_string(t) + "i" + std::to_string(i) + ",dc=example,dc=org";
				const auto ok = [&base](const ldap::result<std::pmr::vector<ldap::entry>> &r) {
					return r && r->size() == 2 && std::string_view((*r)[1].dn).ends_with(base);
				};
				bool good = false;
				switch (i % 3) {
				case 0:
					good = ok(pool.search({ .base = *ldap::dn::parse(base) }));
					break;
				case 1:
					good = pool.who_am_i() == "dn:cn=me";
					break;
				default: {
					auto l = pool.acquire();
					good = l && ok(l->search({ .base = *ldap::dn::parse(base) }));
					break;
				}
				}
				if (!good) {
					++failures;
				}
			}
		});
	}
	for (auto &w : workers) {
		w.join();
	}
	CHECK(failures == 0);
	CHECK(srv.requests == threads * per_thread);
	CHECK(pool.connections() >= 1);
	CHECK(pool.connections() <= max_connections);
}
