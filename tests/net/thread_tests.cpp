// A connection, a client and a store used from several threads at once:
// one io_context run by a thread pool, many operations in flight, against
// an in-process server that answers every request. Meant for TSan too
// (docs/DEVELOPMENT.md "ThreadSanitizer").
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/store.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/strand.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <latch>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;

namespace {

struct person
{
	std::string uid;
};

}// namespace

template<>
constexpr auto ldap::schema<person> =
  ldap::describe(ldap::object_class("inetOrgPerson"), ldap::field<&person::uid>("uid"));

namespace {

constexpr std::size_t threads = 4;
constexpr const char *hang_base = "ou=hang,dc=example,dc=org";

const ldap::dn people_base{ "ou=people,dc=example,dc=org" };

// Answers every request at once by its type: a search with two entries
// (under hang_base: nothing, until abandoned), the schema searches a store
// makes, success for the updates, binds and extended operations, compareTrue.
// Its coroutines run on a strand of their own.
class answering_server
{
  public:
	explicit answering_server(corosio::io_context &ioc)
	  : ioc_(ioc), strand_(ioc.get_executor()), acc_(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 64),
		port_(acc_.local_endpoint().port())
	{
		capy::run_async(strand_)(accept_loop());
	}
	answering_server(const answering_server &) = delete;
	auto operator=(const answering_server &) -> answering_server & = delete;
	~answering_server() = default;

	[[nodiscard]] auto url() const -> ldap::url
	{
		auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port_));
		REQUIRE(u.has_value());
		return *u;
	}
	// Searches under hang_base received, on any thread.
	[[nodiscard]] auto hanging() const noexcept -> std::size_t { return hanging_.load(); }
	[[nodiscard]] auto errors() const noexcept -> std::size_t { return errors_.load(); }

	// Closes the acceptor and every connection, on the server's strand.
	void stop()
	{
		capy::run_async(strand_)([](answering_server &s) -> capy::task<void> {
			s.acc_.close();
			for (auto &p : s.peers_) {
				p.close();
			}
			co_return;
		}(*this));
	}

  private:
	auto accept_loop() -> capy::task<void>
	{
		while (true) {
			auto &peer = peers_.emplace_back(ioc_);
			auto [ec] = co_await acc_.accept(peer);
			if (ec) {
				co_return;
			}
			capy::run_async(strand_)(session(net::transport::wrap(socket_ref{ &peer }, "server")));
		}
	}

	static auto entry(std::int32_t id, std::string_view uid) -> ldap::message
	{
		return ldap::message{ id,
			ldap::search_result_entry{ "uid=" + std::string(uid) + ",ou=people,dc=example,dc=org",
			  { { "uid", { uid } }, { "objectClass", { "inetOrgPerson" } } } } };
	}

	static auto answers(const ldap::message &m) -> std::vector<ldap::message>
	{
		const auto id = m.id;
		const ldap::ldap_result ok{ 0 };
		if (const auto *s = std::get_if<ldap::search_request>(&m.op)) {
			if (s->base_object.empty()) {
				return { ldap::message{
						   id, ldap::search_result_entry{ "", { { "subschemaSubentry", { "cn=Subschema" } } } } },
					done_msg(id) };
			}
			if (s->base_object == "cn=Subschema") {
				return {
					ldap::message{ id,
					  ldap::search_result_entry{ "cn=Subschema",
						{ { "attributeTypes",
							{ "( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )" } },
						  { "objectClasses", { "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' STRUCTURAL )" } } } } },
					done_msg(id)
				};
			}
			return { entry(id, "a"), entry(id, "b"), done_msg(id) };
		}
		if (std::holds_alternative<ldap::bind_request>(m.op)) {
			return { bind_resp(id) };
		}
		if (std::holds_alternative<ldap::add_request>(m.op)) {
			return { ldap::message{ id, ldap::add_response{ ok } } };
		}
		if (std::holds_alternative<ldap::modify_request>(m.op)) {
			return { ldap::message{ id, ldap::modify_response{ ok } } };
		}
		if (std::holds_alternative<ldap::del_request>(m.op)) {
			return { ldap::message{ id, ldap::del_response{ ok } } };
		}
		if (std::holds_alternative<ldap::modify_dn_request>(m.op)) {
			return { ldap::message{ id, ldap::modify_dn_response{ ok } } };
		}
		if (std::holds_alternative<ldap::compare_request>(m.op)) {
			return { ldap::message{ id, ldap::compare_response{ ldap::ldap_result{ 6 } } } };
		}
		if (std::holds_alternative<ldap::extended_request>(m.op)) {
			return { ldap::message{
			  id, ldap::extended_response{ ok, std::nullopt, "dn:cn=admin,dc=example,dc=org" } } };
		}
		return {};// abandon: nothing
	}

	auto session(net::transport t) -> capy::task<void>
	{
		net::read_buffer buf;
		while (true) {
			auto r = co_await net::read_message(t, buf, as_server);
			if (!r) {
				co_return;// the client hung up, or stop()
			}
			if (std::holds_alternative<ldap::unbind_request>(r->op)) {
				co_return;
			}
			if (const auto *s = std::get_if<ldap::search_request>(&r->op);
			  s != nullptr && s->base_object == hang_base) {
				++hanging_;
				continue;
			}
			for (const auto &m : answers(*r)) {
				const std::string bytes = bytes_of(m);
				if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
					co_return;
				}
			}
		}
	}

	corosio::io_context &ioc_;
	capy::strand<corosio::io_context::executor_type> strand_;
	corosio::tcp_acceptor acc_;
	std::uint16_t port_;
	std::deque<corosio::tcp_socket> peers_{};
	std::atomic<std::size_t> hanging_ = 0;
	std::atomic<std::size_t> errors_ = 0;
};

// An io_context run by `threads` threads until stop() (or the destructor).
class thread_pool
{
  public:
	explicit thread_pool(corosio::io_context &ioc) : ioc_(ioc), guard_(ioc.get_executor())
	{
		for (std::size_t i = 0; i < threads; ++i) {
			threads_.emplace_back([this] { ioc_.run(); });
		}
	}
	thread_pool(const thread_pool &) = delete;
	auto operator=(const thread_pool &) -> thread_pool & = delete;
	~thread_pool() { join(); }

	// Lets run() return once no work is left, and waits for the threads.
	void join()
	{
		guard_.reset();
		for (auto &t : threads_) {
			if (t.joinable()) {
				t.join();
			}
		}
	}

  private:
	corosio::io_context &ioc_;
	std::optional<capy::work_guard<corosio::io_context::executor_type>> guard_;
	std::vector<std::thread> threads_{};
};

// Counts the failures the tasks saw (checked on the test's thread).
struct tally
{
	std::atomic<std::size_t> ok = 0;
	std::atomic<std::size_t> failed = 0;
	std::atomic<std::size_t> in_progress = 0;// operation_in_progress from a concurrent next()
	std::atomic<std::size_t> lost = 0;// cond::connection_lost

	void check(bool good) { ++(good ? ok : failed); }
};

auto people_search(ldap::dn base = people_base) -> ldap::search_params
{
	return { .base = std::move(base), .scope = ldap::search_scope::single_level };
}

auto hang_search() -> ldap::search_params { return people_search(ldap::dn{ hang_base }); }

// Starts `t` on the io_context's executor (any of the pool's threads);
// counts `done` down when it ends.
void start(corosio::io_context &ioc, capy::task<void> t, std::latch &done)
{
	capy::run_async(
	  ioc.get_executor(), [&done] { done.count_down(); }, [&done](const std::exception_ptr &) { done.count_down(); })(
	  std::move(t));
}

// Every operation of a connection, `rounds` times, and its accessors.
auto connection_worker(ldap::connection &c, tally &t, int rounds) -> capy::task<void>
{
	for (int i = 0; i < rounds; ++i) {
		auto found = co_await c.search(people_search());
		t.check(found && found->entries.size() == 2);
		t.check((co_await c.add({ .entry = ldap::dn{ "uid=x,ou=people,dc=example,dc=org" } })).has_value());
		t.check((co_await c.modify({ .object = ldap::dn{ "uid=x,ou=people,dc=example,dc=org" },
				   .changes = { ldap::mod::replace("cn", { "x" }) } }))
			.has_value());
		auto same = co_await c.compare(
		  { .entry = ldap::dn{ "uid=x,ou=people,dc=example,dc=org" }, .attribute = "uid", .value = "x" });
		t.check(same && *same);
		t.check((co_await c.del({ .entry = ldap::dn{ "uid=x,ou=people,dc=example,dc=org" } })).has_value());
		auto me = co_await ldap::who_am_i(c);
		t.check(me && *me == "dn:cn=admin,dc=example,dc=org");
		auto s = co_await c.search_stream(people_search());
		std::size_t n = 0;
		if (s) {
			while (true) {
				auto e = co_await s->next();
				if (!e || !*e) {
					t.check(e.has_value());
					break;
				}
				++n;
			}
		}
		t.check(n == 2);
		auto p = co_await ldap::search_paged(c, people_search(), 1);
		t.check(p && (co_await p->next()).has_value());
		// Read on any thread.
		t.check(c.is_open() && !c.is_tls() && c.security_layer() == ldap::sasl_protection::none);
		(void)c.outstanding();
		(void)c.bind_count();
	}
}

// A next() while another runs on the same stream, from another thread:
// operation_in_progress, never two at once.
auto second_next(ldap::search_stream &s, tally &t) -> capy::task<void>
{
	auto e = co_await s.next();
	if (!e && e.error().code == ldap::client_errc::operation_in_progress) {
		++t.in_progress;
	}
}
auto second_page(ldap::paged_search &s, tally &t) -> capy::task<void>
{
	auto e = co_await s.next();
	if (!e && e.error().code == ldap::client_errc::operation_in_progress) {
		++t.in_progress;
	}
}

// An operation that the server never answers: it fails once the connection
// (or client) is gone.
template<class Source> auto hanging_search(Source &c, tally &t) -> capy::task<void>
{
	auto r = co_await c.search(hang_search());
	if (!r && r.error().code == ldap::cond::connection_lost) {
		++t.lost;
	} else {
		++t.failed;
	}
}

// Searches until the connection is closed: the strand keeps publishing
// its state meanwhile.
auto busy_search(ldap::connection &c) -> capy::task<void>
{
	while ((co_await c.search(people_search())).has_value()) {}
}

// Runs `t` on the pool and waits for its result on the test's thread.
template<class T> auto run_on_pool(corosio::io_context &ioc, capy::task<T> t) -> T
{
	outcome<T> out;
	std::latch done(1);
	capy::run_async(
	  ioc.get_executor(),
	  [&done, s = out.state](T v) {
		  s->value.emplace(std::move(v));
		  done.count_down();
	  },
	  [&done, s = out.state](std::exception_ptr e) {
		  s->error = std::move(e);
		  done.count_down();
	  })(std::move(t));
	done.wait();
	return std::move(out.get());
}

// Waits on the test's thread, at most io_limit.
template<class Pred> void wait_for(Pred done)
{
	const auto deadline = std::chrono::steady_clock::now() + io_limit;
	while (!done() && std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

// Every operation of a client (forwarders, leases, an exclusive lease
// bound again) and a store shared by every worker.
auto client_worker(ldap::client &pool, ldap::store<&person::uid, ldap::client> &people, tally &t, int rounds)
  -> capy::task<void>
{
	for (int i = 0; i < rounds; ++i) {
		auto found = co_await pool.search(people_search());
		t.check(found && found->entries.size() == 2);
		t.check((co_await pool.add({ .entry = ldap::dn{ "uid=y,ou=people,dc=example,dc=org" } })).has_value());
		auto same = co_await pool.compare(
		  { .entry = ldap::dn{ "uid=y,ou=people,dc=example,dc=org" }, .attribute = "uid", .value = "y" });
		t.check(same && same->value);
		t.check((co_await pool.del({ .entry = ldap::dn{ "uid=y,ou=people,dc=example,dc=org" } })).has_value());
		t.check((co_await ldap::who_am_i(pool)).has_value());
		t.check((co_await people.get("a")).has_value());
		t.check((co_await people.search()).has_value());
		{
			auto held = co_await pool.acquire();
			t.check(held.has_value());
			if (held) {
				t.check((co_await (*held)->search(people_search())).has_value());
			}
		}
		if (i % 4 == 0) {
			auto mine = co_await pool.acquire_exclusive();
			t.check(mine.has_value());
			if (mine) {
				// Bound again: retired from the pool once returned.
				t.check((co_await (*mine)->simple_bind(ldap::dn{ "cn=other,dc=example,dc=org" }, "pw")).has_value());
			}
		}
		auto s = co_await pool.search_stream(people_search());
		t.check(s && (co_await s->next()).has_value());
		(void)pool.connections();
	}
}

}// namespace

TEST_CASE("threads: one connection used from several threads", "[net][threads]")
{
	corosio::io_context ioc;
	answering_server server(ioc);
	auto c = finish(ioc, ldap::connect(ioc, server.url(), { .operation_timeout = std::chrono::seconds(30) }));
	REQUIRE(c.has_value());
	REQUIRE(finish(ioc, c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	tally t;
	{
		thread_pool pool(ioc);

		// Every operation, from many tasks on every thread.
		constexpr std::size_t workers = 16;
		constexpr int rounds = 20;
		std::latch done(workers);
		for (std::size_t i = 0; i < workers; ++i) {
			start(ioc, connection_worker(*c, t, rounds), done);
		}
		done.wait();
		CHECK(t.failed == 0);
		CHECK(t.ok == workers * rounds * 10);

		// A second next() on a stream, and on a paged search, while one runs.
		auto params = hang_search();
		params.timeout = std::chrono::seconds(5);
		auto s = run_on_pool(ioc, c->search_stream(params));
		auto p = run_on_pool(ioc, ldap::search_paged(*c, params, 10));
		REQUIRE(s.has_value());
		REQUIRE(p.has_value());
		std::latch firsts(2);
		std::latch seconds(2);
		start(ioc, second_next(*s, t), firsts);
		start(ioc, second_page(*p, t), firsts);
		wait_for([&server] { return server.hanging() == 2; });
		std::this_thread::sleep_for(std::chrono::milliseconds(50));// the first next()s wait for their responses
		start(ioc, second_next(*s, t), seconds);
		start(ioc, second_page(*p, t), seconds);
		seconds.wait();
		CHECK(t.in_progress == 2);

		// The connection destroyed while operations of other threads are
		// outstanding: they fail with not_connected (cond::connection_lost),
		// the first next()s too.
		constexpr std::size_t hung = 8;
		std::latch ended(hung);
		for (std::size_t i = 0; i < hung; ++i) {
			start(ioc, hanging_search(*c, t), ended);
		}
		wait_for([&server] { return server.hanging() == 2 + hung; });
		CHECK(c->outstanding() == 2 + hung);
		*c = ldap::connection{};// off the strand: the close is posted
		CHECK_FALSE(c->is_open());
		ended.wait();
		firsts.wait();
		CHECK(t.lost == hung);
		// Off the strand too: their cleanup is posted, and runs on the pool.
		*s = ldap::search_stream{};
		*p = ldap::paged_search{};
		server.stop();
	}
	CHECK(t.failed == 0);
}

TEST_CASE("threads: one client and one store used from several threads", "[net][threads][client]")
{
	corosio::io_context ioc;
	answering_server server(ioc);
	std::optional<ldap::client> pool(std::in_place,
	  ioc,
	  ldap::client_options{ .servers = { server.url() },
		.setup = ldap::simple_bind_setup(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"),
		.max_connections = 4 });
	ldap::store people(
	  *pool, people_base, ldap::named_by<&person::uid>, { .schema_check = ldap::schema_check::on_first_use });
	tally t;
	{
		thread_pool threads_running(ioc);

		constexpr std::size_t workers = 16;
		constexpr int rounds = 12;
		std::latch done(workers);
		for (std::size_t i = 0; i < workers; ++i) {
			start(ioc, client_worker(*pool, people, t, rounds), done);
		}
		done.wait();
		CHECK(t.failed == 0);
		CHECK(t.ok == (workers * rounds * 10) + (workers * ((rounds + 3) / 4) * 2));
		CHECK(pool->connections() <= 4 + workers);

		// The client destroyed while operations of other threads are
		// outstanding: they fail with not_connected (cond::connection_lost).
		constexpr std::size_t hung = 8;
		std::latch ended(hung);
		const std::size_t before = server.hanging();
		for (std::size_t i = 0; i < hung; ++i) {
			start(ioc, hanging_search(*pool, t), ended);
		}
		wait_for([&] { return server.hanging() == before + hung; });
		pool.reset();// off the strand: the close is posted
		ended.wait();
		CHECK(t.lost == hung);
		server.stop();
	}
	CHECK(t.failed == 0);
}

TEST_CASE("threads: a connection destroyed by a pool task after stop()", "[net][threads]")
{
	corosio::io_context ioc;
	answering_server server(ioc);
	auto c = finish(ioc, ldap::connect(ioc, server.url(), { .operation_timeout = std::chrono::seconds(30) }));
	REQUIRE(c.has_value());
	std::atomic<bool> closed = false;
	ldap::detail::set_close_hook(*c, [&closed] noexcept { closed = true; });
	tally t;
	constexpr std::size_t hung = 4;
	std::latch ended(hung);
	std::latch stopped(1);
	{
		thread_pool pool(ioc);
		for (std::size_t i = 0; i < hung; ++i) {
			start(ioc, hanging_search(*c, t), ended);
		}
		wait_for([&server] { return server.hanging() == hung; });
		REQUIRE(server.hanging() == hung);
		// Inside run() after stop(): the close is posted, not run while the
		// other threads may still be on the strand.
		start(
		  ioc,
		  [](corosio::io_context &io, ldap::connection &conn) -> capy::task<void> {
			  io.stop();
			  conn = ldap::connection{};
			  co_return;
		  }(ioc, *c),
		  stopped);
		pool.join();
	}
	CHECK(stopped.try_wait());
	CHECK_FALSE(c->is_open());
	CHECK_FALSE(closed);
	ioc.restart();
	drive_until(ioc, [&] { return closed && ended.try_wait(); });
	CHECK(closed);
	CHECK(ended.try_wait());
	CHECK(t.lost == hung);
	server.stop();
	drive(ioc);
	CHECK(t.failed == 0);
}

TEST_CASE("threads: close() from another thread reads as closed at once", "[net][threads]")
{
	corosio::io_context ioc;
	answering_server server(ioc);
	auto c = finish(ioc, ldap::connect(ioc, server.url(), { .operation_timeout = std::chrono::seconds(30) }));
	REQUIRE(c.has_value());
	tally t;
	constexpr std::size_t hung = 4;
	constexpr std::size_t busy = 8;
	std::latch ended(hung + busy);
	{
		thread_pool pool(ioc);
		for (std::size_t i = 0; i < hung; ++i) {
			start(ioc, hanging_search(*c, t), ended);
		}
		for (std::size_t i = 0; i < busy; ++i) {
			start(ioc, busy_search(*c), ended);
		}
		wait_for([&server] { return server.hanging() == hung; });
		REQUIRE(server.hanging() == hung);
		c->close();
		constexpr int reads = 2000;
		int stale = 0;
		for (int i = 0; i < reads; ++i) {
			if (c->is_open() || c->outstanding() != 0 || c->is_tls() || ldap::detail::accepts_requests(*c)
				|| c->security_layer() != ldap::sasl_protection::none) {
				++stale;
			}
		}
		CHECK(stale == 0);
		ended.wait();
		CHECK(t.lost == hung);
		server.stop();
	}
	CHECK(t.failed == 0);
}
