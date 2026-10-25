// ldap::client against scripted in-process LDAP servers on loopback TCP:
// each server accepts connections one after another and runs the n-th
// script on the n-th connection (mock_ldap.hpp's serve_script), then stops
// accepting, so a later connect is refused. Backoff runs on short real
// delays, with the jitter fixed by detail::set_jitter.
#include "jhetz/ldap/client.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/cond.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using std::chrono::milliseconds;

namespace {

// The server hangs up as soon as it accepts the connection.
auto hang_up_at_once() -> std::vector<step>
{
	return { step{ .read_request = false, .replies = {}, .close_after = true } };
}

// Answers the setup's simple bind (message id 1), then reads nothing more.
auto bind_ok() -> std::vector<step> { return { answer({ bind_resp(1) }) }; }

class ldap_server
{
  public:
	ldap_server(corosio::io_context &ioc, std::vector<std::vector<step>> scripts)
	  : ioc_(ioc), acc_(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8), scripts_(std::move(scripts)),
		port_(acc_.local_endpoint().port())
	{
		spawn(ioc_, accept_loop(), accepting_);
	}
	ldap_server(const ldap_server &) = delete;
	auto operator=(const ldap_server &) -> ldap_server & = delete;
	~ldap_server() { shut_down(); }

	[[nodiscard]] auto url() const -> ldap::url
	{
		auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port_));
		REQUIRE(u.has_value());
		return *u;
	}
	[[nodiscard]] auto accepted() const -> std::size_t { return logs_.size(); }
	[[nodiscard]] auto log(std::size_t n) -> server_log & { return logs_.at(n); }
	[[nodiscard]] auto session(std::size_t n) -> outcome<void> & { return sessions_.at(n); }
	// The server closes the n-th connection.
	void drop(std::size_t n) { peers_.at(n).close(); }
	void shut_down()
	{
		acc_.close();
		for (auto &p : peers_) {
			p.close();
		}
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
		}
		acc_.close();
	}

	corosio::io_context &ioc_;
	corosio::tcp_acceptor acc_;
	std::vector<std::vector<step>> scripts_;
	std::uint16_t port_;
	std::deque<corosio::tcp_socket> peers_{};
	std::deque<server_log> logs_{};
	std::deque<outcome<void>> sessions_{};
	outcome<void> accepting_{};
};

// A URL nothing listens on: connects are refused at once.
auto refused_url(corosio::io_context &ioc) -> ldap::url
{
	std::uint16_t port = 0;
	{
		corosio::tcp_acceptor a(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
		port = a.local_endpoint().port();
	}
	auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port));
	REQUIRE(u.has_value());
	return *u;
}

auto text(const ldap::url &u) -> std::string { return std::string(std::string_view(u.to_string())); }

auto reason_name(ldap::disconnect_reason r) -> std::string_view
{
	switch (r) {
	case ldap::disconnect_reason::closed:
		return "closed";
	case ldap::disconnect_reason::probe_failed:
		return "probe_failed";
	case ldap::disconnect_reason::max_lifetime:
		return "max_lifetime";
	case ldap::disconnect_reason::rebound:
		return "rebound";
	case ldap::disconnect_reason::failback:
		return "failback";
	case ldap::disconnect_reason::client_closed:
		return "client_closed";
	}
	return "?";
}

// Records the observer's calls as text: "connect <url> ok", "retry <url> 50ms", ...
struct recorder final : ldap::client_observer
{
	std::vector<std::string> events{};
	std::vector<milliseconds> waits{};

	void on_connect(const ldap::url &server, const ldap::result<void> &outcome) override
	{
		events.push_back("connect " + text(server) + (outcome ? " ok" : " failed"));
	}
	void on_disconnect(const ldap::url &server, ldap::disconnect_reason reason) override
	{
		events.push_back("disconnect " + text(server) + " " + std::string(reason_name(reason)));
	}
	void on_retry(const ldap::url &server, const ldap::error &, milliseconds delay) override
	{
		events.push_back("retry " + text(server) + " " + std::to_string(delay.count()) + "ms");
	}
	void on_probe(const ldap::url &server, const ldap::result<void> &outcome) override
	{
		events.push_back("probe " + text(server) + (outcome ? " ok" : " failed"));
	}
	void on_acquire_wait(milliseconds waited) override { waits.push_back(waited); }
};

auto admin_setup() -> ldap::session_setup
{
	return ldap::simple_bind_setup(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
}

auto sleep_for(milliseconds d) -> capy::task<void> { (void)co_await corosio::delay(d); }

// The servers, the client and the io_context they share. The client goes
// first, then the servers' sockets, then what is still running.
struct pool_fixture
{
	corosio::io_context ioc{};
	std::deque<ldap_server> servers{};
	std::optional<ldap::client> pool{};
	recorder obs{};

	pool_fixture() = default;
	pool_fixture(const pool_fixture &) = delete;
	auto operator=(const pool_fixture &) -> pool_fixture & = delete;
	~pool_fixture()
	{
		pool.reset();
		for (auto &s : servers) {
			s.shut_down();
		}
		drive(ioc);
	}

	auto server(std::vector<std::vector<step>> scripts) -> ldap_server &
	{
		return servers.emplace_back(ioc, std::move(scripts));
	}
	// The client, with the jitter fixed at 1 (each backoff is its cap).
	void make(ldap::client_options options)
	{
		pool.emplace(ioc, std::move(options));
		ldap::detail::set_jitter(*pool, [] { return 1.0; });
	}
	auto acquire() -> ldap::result<ldap::lease> { return finish(ioc, pool->acquire()); }
};

}// namespace

TEST_CASE("client: backoff delays", "[net][client][backoff]")
{
	const ldap::backoff_options b{ .initial = milliseconds(100), .max = milliseconds(1000), .multiplier = 2.0 };
	CHECK(ldap::detail::backoff_delay(b, 1, 1.0) == milliseconds(100));
	CHECK(ldap::detail::backoff_delay(b, 2, 1.0) == milliseconds(200));
	CHECK(ldap::detail::backoff_delay(b, 4, 1.0) == milliseconds(800));
	CHECK(ldap::detail::backoff_delay(b, 5, 1.0) == milliseconds(1000));// capped
	CHECK(ldap::detail::backoff_delay(b, 1'000'000, 1.0) == milliseconds(1000));
	CHECK(ldap::detail::backoff_delay(b, 3, 0.5) == milliseconds(200));// full jitter
	CHECK(ldap::detail::backoff_delay(b, 3, 0.0) == milliseconds(0));
	CHECK(ldap::detail::backoff_delay(b, 3, 7.0) == milliseconds(400));// unit clamped to 1
	const ldap::backoff_options flat{ .initial = milliseconds(50), .max = milliseconds(1000), .multiplier = 0.5 };
	CHECK(ldap::detail::backoff_delay(flat, 10, 1.0) == milliseconds(50));// a multiplier below 1 counts as 1
	const ldap::backoff_options over{ .initial = milliseconds(5000), .max = milliseconds(1000), .multiplier = 2.0 };
	CHECK(ldap::detail::backoff_delay(over, 1, 1.0) == milliseconds(1000));
}

TEST_CASE("client: options it cannot use", "[net][client]")
{
	pool_fixture f;
	f.make({});
	auto none = f.acquire();
	REQUIRE_FALSE(none.has_value());
	CHECK(none.error().code == ldap::client_errc::invalid_url);
	f.make({ .servers = { refused_url(f.ioc) }, .max_connections = 0 });
	auto zero = f.acquire();
	REQUIRE_FALSE(zero.has_value());
	CHECK(zero.error().code == std::errc::invalid_argument);
	ldap::client moved = std::move(*f.pool);
	auto from = f.acquire();
	REQUIRE_FALSE(from.has_value());
	CHECK(from.error().code == ldap::client_errc::not_connected);
}

TEST_CASE("client: fails over to the next server", "[net][client][failover]")
{
	pool_fixture f;
	const auto down = refused_url(f.ioc);
	auto &up = f.server({ bind_ok() });
	f.make({ .servers = { down, up.url() },
	  .setup = admin_setup(),
	  .backoff = { .initial = milliseconds(60'000), .max = milliseconds(60'000) },
	  .observer = &f.obs });
	auto l = f.acquire();
	REQUIRE(l.has_value());
	CHECK(text(l->server()) == text(up.url()));
	CHECK((*l)->is_open());
	CHECK(f.pool->connections() == 1);
	REQUIRE(up.accepted() == 1);
	REQUIRE(up.log(0).received.size() == 1);
	CHECK(std::get<ldap::bind_request>(up.log(0).received[0].op).name == admin);
	CHECK(
	  f.obs.events
	  == std::vector<std::string>{
		"connect " + text(down) + " failed", "retry " + text(down) + " 60000ms", "connect " + text(up.url()) + " ok" });
	CHECK(f.obs.waits.empty());

	// The lease works like a connection.
	l->release();
	CHECK_FALSE(static_cast<bool>(*l));
	CHECK(f.pool->connections() == 1);// pooled again
}

TEST_CASE("client: a failed server waits out its backoff", "[net][client][backoff]")
{
	SECTION("acquire() waits for the backoff, then tries again")
	{
		pool_fixture f;
		auto &s = f.server({ hang_up_at_once(), bind_ok() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .backoff = { .initial = milliseconds(50), .max = milliseconds(50) },
		  .observer = &f.obs });
		const auto start = std::chrono::steady_clock::now();
		auto l = f.acquire();
		const auto elapsed = std::chrono::steady_clock::now() - start;
		REQUIRE(l.has_value());
		CHECK(elapsed >= milliseconds(50));
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " failed",
				"retry " + text(s.url()) + " 50ms",
				"connect " + text(s.url()) + " ok" });
		REQUIRE(f.obs.waits.size() == 1);
		CHECK(f.obs.waits[0] >= milliseconds(45));
	}
	SECTION("a server in backoff is skipped by later acquires")
	{
		pool_fixture f;
		auto &a = f.server({ hang_up_at_once() });
		auto &b = f.server({ bind_ok(), bind_ok() });
		f.make({ .servers = { a.url(), b.url() },
		  .setup = admin_setup(),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto first = f.acquire();
		REQUIRE(first.has_value());
		CHECK(text(first->server()) == text(b.url()));
		(*first)->close();// its connection ends: the next acquire opens another
		first->release();
		CHECK(f.pool->connections() == 0);
		auto second = f.acquire();
		REQUIRE(second.has_value());
		CHECK(text(second->server()) == text(b.url()));
		CHECK(a.accepted() == 1);// not tried again
		CHECK(b.accepted() == 2);
	}
	SECTION("acquire() gives up when the backoff ends after acquire_timeout")
	{
		pool_fixture f;
		auto &s = f.server({ hang_up_at_once() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(100),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto first = f.acquire();
		REQUIRE_FALSE(first.has_value());
		CHECK(first.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(first.error().context), ContainsSubstring("acquire " + text(s.url())));
		auto second = f.acquire();// still backing off: not tried, the server's error again
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(second.error().context), ContainsSubstring("backing off"));
		CHECK(s.accepted() == 1);
	}
}

TEST_CASE("client: the session setup runs again on a new connection", "[net][client][setup]")
{
	pool_fixture f;
	auto &s = f.server({ bind_ok(), bind_ok() });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = std::nullopt, .observer = &f.obs });
	auto l = f.acquire();
	REQUIRE(l.has_value());
	l->release();
	s.drop(0);// the server drops the idle connection; the client cannot tell yet

	auto stale = f.acquire();// no idle check: handed out as is
	REQUIRE(stale.has_value());
	auto r = finish(f.ioc, (*stale)->search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::cond::connection_lost);
	stale->release();// closed: leaves the pool
	CHECK(f.pool->connections() == 0);

	auto fresh = f.acquire();
	REQUIRE(fresh.has_value());
	CHECK((*fresh)->is_open());
	REQUIRE(s.accepted() == 2);
	REQUIRE(s.log(1).received.size() == 1);
	CHECK(std::get<ldap::bind_request>(s.log(1).received[0].op).name == admin);
	CHECK(f.obs.events
		  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
			"disconnect " + text(s.url()) + " closed",
			"connect " + text(s.url()) + " ok" });
}

TEST_CASE("client: helpers building a session setup", "[net][client][setup]")
{
	SECTION("SASL: a fresh mechanism per connection")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok() });
		int made = 0;
		f.make({ .servers = { s.url() },
		  .setup = ldap::sasl_bind_setup([&made] {
			  ++made;
			  return std::make_unique<ldap::sasl_external>();
		  }),
		  .max_connections = 2 });
		auto a = f.acquire();
		auto b = f.acquire();
		REQUIRE(a.has_value());
		REQUIRE(b.has_value());
		CHECK(&a->get() != &b->get());
		CHECK(made == 2);
		REQUIRE(s.accepted() == 2);
		const auto &bind = std::get<ldap::bind_request>(s.log(1).received.at(0).op);
		CHECK(std::get<ldap::sasl_auth>(bind.authentication).mechanism == "EXTERNAL");
	}
	SECTION("a factory returning null fails the setup")
	{
		pool_fixture f;
		auto &s = f.server({ { step{ .read_request = false, .replies = {}, .close_after = false } } });
		f.make({ .servers = { s.url() },
		  .setup = ldap::sasl_bind_setup([] { return std::unique_ptr<ldap::sasl_mechanism>(); }) });
		auto l = f.acquire();
		REQUIRE_FALSE(l.has_value());
		CHECK(l.error().code == std::errc::invalid_argument);// invalid_input: not retried
		CHECK_THAT(std::string(l.error().context), ContainsSubstring("session setup"));
	}
}

TEST_CASE("client: an authentication failure stops reconnecting to that server", "[net][client][auth]")
{
	SECTION("one server")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1, 49, "bad password") }) } });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(10'000),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) },
		  .observer = &f.obs });
		auto first = f.acquire();// fails at once: no waiting for a backoff
		REQUIRE_FALSE(first.has_value());
		CHECK(first.error().code == ldap::errc::invalid_credentials);
		CHECK(first.error().code == ldap::cond::auth_failed);
		CHECK_THAT(std::string(first.error().context), ContainsSubstring("session setup"));
		CHECK(f.obs.waits.empty());
		// Within the backoff, a new acquire does not bind again: it waits
		// for the backoff (longer than acquire_timeout here) and fails with
		// the server's error.
		auto second = f.acquire();
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 1);
	}
	SECTION("every server refuses: acquire() fails once each was tried")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1, 49) }) } });
		auto &b = f.server({ { answer({ bind_resp(1, 49) }) } });
		f.make({ .servers = { a.url(), b.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = std::nullopt,// would wait forever for a retry
		  .backoff = { .initial = milliseconds(10), .max = milliseconds(10) } });
		auto l = f.acquire();
		REQUIRE_FALSE(l.has_value());
		CHECK(l.error().code == ldap::cond::auth_failed);
		CHECK_THAT(std::string(l.error().context), ContainsSubstring(text(b.url())));
		CHECK(a.accepted() == 1);
		CHECK(b.accepted() == 1);
	}
}

TEST_CASE("client: the idle check", "[net][client][probe]")
{
	SECTION("a dead connection is replaced")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = milliseconds(0), .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		const ldap::connection *first = &l->get();
		l->release();
		s.drop(0);
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK((*again)->is_open());
		CHECK(s.accepted() == 2);
		CHECK(f.pool->connections() == 1);
		(void)first;
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"probe " + text(s.url()) + " failed",
				"disconnect " + text(s.url()) + " probe_failed",
				"connect " + text(s.url()) + " ok" });
	}
	SECTION("a live connection answers a root DSE search for no attributes")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), answer({ done_msg(2) }) } });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = milliseconds(0), .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		const ldap::connection *first = &l->get();
		l->release();
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK(&again->get() == first);
		CHECK(s.accepted() == 1);
		REQUIRE(s.log(0).received.size() == 2);
		const auto &probe = std::get<ldap::search_request>(s.log(0).received[1].op);
		CHECK(probe.base_object.empty());
		CHECK(probe.scope == ldap::search_scope::base_object);
		REQUIRE(probe.attributes.size() == 1);
		CHECK(probe.attributes[0] == "1.1");
		CHECK(f.obs.events.back() == "probe " + text(s.url()) + " ok");
	}
	SECTION("a server error is an answer")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), answer({ done_msg(2, 50) }) } });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = milliseconds(0) });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		const ldap::connection *first = &l->get();
		l->release();
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK(&again->get() == first);
	}
	SECTION("a connection used recently is not probed")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = milliseconds(3'600'000) });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		l->release();
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK(s.log(0).received.size() == 1);
	}
}

TEST_CASE("client: max_connections", "[net][client][pool]")
{
	SECTION("leases share the connection by default")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto a = f.acquire();
		auto b = f.acquire();
		REQUIRE(a.has_value());
		REQUIRE(b.has_value());
		CHECK(&a->get() == &b->get());
		CHECK(s.accepted() == 1);
		CHECK(f.pool->connections() == 1);
	}
	SECTION("new connections before sharing, up to the limit; idle ones first")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok(), bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .max_connections = 2 });
		auto a = f.acquire();
		auto b = f.acquire();
		auto c = f.acquire();
		REQUIRE(a.has_value());
		REQUIRE(b.has_value());
		REQUIRE(c.has_value());
		CHECK(&a->get() != &b->get());
		CHECK((&c->get() == &a->get() || &c->get() == &b->get()));
		CHECK(s.accepted() == 2);
		CHECK(f.pool->connections() == 2);
		ldap::connection *idle = (&c->get() == &a->get()) ? &b->get() : &a->get();
		(&c->get() == &a->get() ? *b : *a).release();
		auto d = f.acquire();
		REQUIRE(d.has_value());
		CHECK(&d->get() == idle);
		CHECK(s.accepted() == 2);
	}
	SECTION("concurrent acquires wait for the connection being opened")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		outcome<ldap::result<ldap::lease>> a;
		outcome<ldap::result<ldap::lease>> b;
		spawn(f.ioc, f.pool->acquire(), a);
		spawn(f.ioc, f.pool->acquire(), b);
		drive_until(f.ioc, [&] { return a.done() && b.done(); });
		REQUIRE(a.get().has_value());
		REQUIRE(b.get().has_value());
		CHECK(&a.get()->get() == &b.get()->get());
		CHECK(s.accepted() == 1);
		CHECK(f.obs.waits.size() == 1);
	}
}

TEST_CASE("client: acquire_timeout", "[net][client][timeout]")
{
	pool_fixture f;
	auto &s = f.server({ { step{} } });// reads the bind, never answers
	f.make({ .servers = { s.url() },
	  .setup = admin_setup(),
	  .acquire_timeout = milliseconds(100),
	  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
	outcome<ldap::result<ldap::lease>> a;
	outcome<ldap::result<ldap::lease>> b;
	const auto start = std::chrono::steady_clock::now();
	spawn(f.ioc, f.pool->acquire(), a);
	spawn(f.ioc, f.pool->acquire(), b);// waits for the first's connection
	drive_until(f.ioc, [&] { return a.done() && b.done(); });
	CHECK(std::chrono::steady_clock::now() - start >= milliseconds(100));
	REQUIRE_FALSE(a.get().has_value());
	CHECK(a.get().error().code == ldap::cond::timeout);
	CHECK_THAT(std::string(a.get().error().context), ContainsSubstring("acquire_timeout"));
	REQUIRE_FALSE(b.get().has_value());
	CHECK(b.get().error().code == ldap::cond::timeout);
	CHECK(s.accepted() == 1);
}

TEST_CASE("client: connections are not pooled again after", "[net][client][pool]")
{
	SECTION("a lease bound them again")
	{
		pool_fixture f;
		auto &s =
		  f.server({ { answer({ bind_resp(1) }), answer({ bind_resp(2) }), step{}, client_hangs_up() }, bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		CHECK(l->get().bind_count() == 1);
		REQUIRE(finish(f.ioc, (*l)->simple_bind(ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" }, "pw")).has_value());
		CHECK(l->get().bind_count() == 2);
		l->release();
		CHECK(f.pool->connections() == 0);
		CHECK(f.obs.events.back() == "disconnect " + text(s.url()) + " rebound");
		// It is unbound, not just closed.
		drive_until(f.ioc, [&s] { return s.session(0).done(); });
		CHECK(s.log(0).error.empty());
		REQUIRE(s.log(0).received.size() == 3);
		CHECK(std::holds_alternative<ldap::unbind_request>(s.log(0).received[2].op));
		auto fresh = f.acquire();
		REQUIRE(fresh.has_value());
		CHECK(s.accepted() == 2);
	}
	SECTION("they are older than max_lifetime")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{}, client_hangs_up() }, bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .max_lifetime = milliseconds(0), .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		l->release();
		CHECK(f.pool->connections() == 0);
		CHECK(f.obs.events.back() == "disconnect " + text(s.url()) + " max_lifetime");
		drive_until(f.ioc, [&s] { return s.session(0).done(); });
		CHECK(s.log(0).error.empty());
		auto fresh = f.acquire();
		REQUIRE(fresh.has_value());
		CHECK(s.accepted() == 2);
	}
}

TEST_CASE("client: back to the primary after failback_after", "[net][client][failover]")
{
	pool_fixture f;
	auto &primary = f.server({ hang_up_at_once(), bind_ok() });
	auto &secondary = f.server({ bind_ok() });
	f.make({ .servers = { primary.url(), secondary.url() },
	  .setup = admin_setup(),
	  .idle_check = std::nullopt,
	  .backoff = { .initial = milliseconds(30), .max = milliseconds(30) },
	  .failback_after = milliseconds(0),
	  .observer = &f.obs });
	auto l = f.acquire();
	REQUIRE(l.has_value());
	CHECK(text(l->server()) == text(secondary.url()));
	l->release();
	finish(f.ioc, sleep_for(milliseconds(40)));// the primary's backoff ends
	auto back = f.acquire();
	REQUIRE(back.has_value());
	CHECK(text(back->server()) == text(primary.url()));
	CHECK(primary.accepted() == 2);
	CHECK(f.pool->connections() == 1);
	CHECK(f.obs.events
		  == std::vector<std::string>{ "connect " + text(primary.url()) + " failed",
			"retry " + text(primary.url()) + " 30ms",
			"connect " + text(secondary.url()) + " ok",
			"disconnect " + text(secondary.url()) + " failback",
			"connect " + text(primary.url()) + " ok" });
}

TEST_CASE("client: close()", "[net][client]")
{
	pool_fixture f;
	auto &s = f.server({ bind_ok() });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
	auto l = f.acquire();
	REQUIRE(l.has_value());
	f.pool->close();
	CHECK_FALSE((*l)->is_open());// leased connections are closed too
	CHECK(f.pool->connections() == 0);
	CHECK(f.obs.events.back() == "disconnect " + text(s.url()) + " client_closed");
	auto after = f.acquire();
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == ldap::client_errc::not_connected);
	l->release();// after close(): nothing to return it to
	f.pool->close();// idempotent
}

TEST_CASE("client: a lease outlives its client", "[net][client]")
{
	pool_fixture f;
	auto &s = f.server({ bind_ok() });
	f.make({ .servers = { s.url() }, .setup = admin_setup() });
	auto l = f.acquire();
	REQUIRE(l.has_value());
	ldap::lease kept = std::move(*l);
	CHECK_FALSE(static_cast<bool>(*l));
	f.pool.reset();
	CHECK(static_cast<bool>(kept));
	CHECK_FALSE(kept->is_open());
	CHECK(text(kept.server()) == text(s.url()));
}
