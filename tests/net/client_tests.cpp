// ldap::client against scripted in-process servers (the n-th script on the
// n-th connection), with the jitter fixed.
#include "../counting_resource.hpp"
#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/ad/dirsync.hpp"
#include "jhetz/ldap/ad/ranged_values.hpp"
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/repository.hpp"
#include "jhetz/ldap/schema.hpp"
#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/cond.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <initializer_list>
#include <memory>
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
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
	// socket_buffers::small: the accepted connections' receive buffer is
	// small_socket_buffer (mock_ldap.hpp).
	ldap_server(corosio::io_context &ioc,
	  std::vector<std::vector<step>> scripts,
	  socket_buffers buffers = socket_buffers::system)
	  : ioc_(ioc), acc_(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8), scripts_(std::move(scripts)),
		port_(acc_.local_endpoint().port())
	{
		if (buffers == socket_buffers::small) {
			REQUIRE_FALSE(acc_.set_option(corosio::socket_option::receive_buffer_size(small_socket_buffer)));
		}
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
	[[nodiscard]] auto endpoint() const -> corosio::endpoint { return { corosio::ipv4_address::loopback(), port_ }; }
	[[nodiscard]] auto accepted() const -> std::size_t { return logs_.size(); }
	// The SO_RCVBUF of the server's end of the n-th connection, as the
	// kernel reports it.
	[[nodiscard]] auto receive_buffer(std::size_t n) const -> std::size_t
	{
		const auto [ec, received] = peers_.at(n).get_option<corosio::socket_option::receive_buffer_size>();
		REQUIRE_FALSE(ec);
		return static_cast<std::size_t>(received.value());
	}
	[[nodiscard]] auto log(std::size_t n) -> server_log & { return logs_.at(n); }
	[[nodiscard]] auto session(std::size_t n) -> outcome<void> & { return sessions_.at(n); }
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
	case ldap::disconnect_reason::busy_or_unavailable:
		return "busy_or_unavailable";
	}
	return "?";
}

// Records the observer's calls as text: "connect <url> ok", "retry <url> 50ms", ...
struct recorder final : ldap::client_observer
{
	std::vector<std::string> events{};
	std::vector<milliseconds> waits{};
	std::vector<std::error_code> retry_failures{};// on_retry's `failure`

	void on_connect(const ldap::url &server, const ldap::result<void> &outcome) override
	{
		events.push_back("connect " + text(server) + (outcome ? " ok" : " failed"));
	}
	void on_disconnect(const ldap::url &server, ldap::disconnect_reason reason) override
	{
		events.push_back("disconnect " + text(server) + " " + std::string(reason_name(reason)));
	}
	void on_retry(const ldap::url &server, const ldap::error &failure, milliseconds delay) override
	{
		retry_failures.push_back(failure.code);
		events.push_back("retry " + text(server) + " " + std::to_string(delay.count()) + "ms");
	}
	void on_probe(const ldap::url &server, const ldap::result<void> &outcome) override
	{
		events.push_back("probe " + text(server) + (outcome ? " ok" : " failed"));
	}
	void on_acquire_wait(milliseconds waited) override { waits.push_back(waited); }
	void on_referral(const ldap::url &server, const ldap::referral_attempt &attempt) override
	{
		events.push_back(
		  "referral " + text(server) + " " + attempt.uri + " " + std::string(outcome_name(attempt.outcome)));
	}

	static auto outcome_name(ldap::referral_outcome o) -> std::string_view
	{
		switch (o) {
		case ldap::referral_outcome::followed:
			return "followed";
		case ldap::referral_outcome::skipped_policy:
			return "skipped_policy";
		case ldap::referral_outcome::skipped_loop:
			return "skipped_loop";
		case ldap::referral_outcome::limit_reached:
			return "limit_reached";
		case ldap::referral_outcome::unparseable:
			return "unparseable";
		case ldap::referral_outcome::failed:
			return "failed";
		}
		return "?";
	}
};

auto admin_setup() -> ldap::session_setup
{
	return ldap::simple_bind_setup(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
}

auto sleep_for(milliseconds d) -> capy::task<void> { (void)co_await corosio::delay(d); }

// Answers the setup's bind with invalidCredentials.
auto refuse() -> std::vector<step> { return { answer({ bind_resp(1, 49, "bad password") }) }; }

// Returns `held` and acquires at once, before any acquire() woken by the
// return runs (the wake-ups are posted).
auto release_then_acquire(ldap::client &pool, ldap::detail::lease_base &held) -> capy::task<ldap::result<ldap::lease>>
{
	held.release();
	co_return co_await pool.acquire();
}

// release_then_acquire(), stopping `stop` in between: an acquire() woken
// by the return is stopped before it resumes.
auto release_stop_then_acquire(ldap::client &pool, ldap::detail::lease_base &held, std::stop_source &stop)
  -> capy::task<ldap::result<ldap::lease>>
{
	held.release();
	stop.request_stop();
	co_return co_await pool.acquire();
}

auto retries(const recorder &r) -> std::ptrdiff_t
{
	return std::ranges::count_if(r.events, [](const std::string &e) { return e.starts_with("retry "); });
}

// The servers, the client and the io_context they share. The client goes
// first, then the servers' sockets, then what is still running.
struct pool_fixture
{
	corosio::io_context ioc{};
	std::deque<ldap_server> servers{};
	std::deque<refused_port> refused{};
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

	auto server(std::vector<std::vector<step>> scripts, socket_buffers buffers = socket_buffers::system)
	  -> ldap_server &
	{
		return servers.emplace_back(ioc, std::move(scripts), buffers);
	}
	// Connects are refused at once while the fixture lives.
	auto refused_url() -> ldap::url
	{
		auto u = ldap::url::parse(refused.emplace_back().url());
		REQUIRE(u.has_value());
		return *u;
	}
	// The jitter fixed at 1: each backoff is its cap.
	void make(ldap::client_options options)
	{
		options.connection.allow_cleartext_passwords = true;
		pool.emplace(ioc, std::move(options));
		ldap::detail::set_jitter(*pool, [] { return 1.0; });
	}
	auto acquire() -> ldap::result<ldap::lease> { return finish(ioc, pool->acquire()); }
	auto acquire_exclusive() -> ldap::result<ldap::exclusive_lease> { return finish(ioc, pool->acquire_exclusive()); }
	// Calls `f` on the client's strand, where a lease's release() and the
	// client's close() take effect at once.
	template<class F> void on_strand(F f) { run_on(ioc, pool->executor(), std::move(f)); }
	template<class Lease> void release(Lease &l)
	{
		on_strand([&l] { l.release(); });
	}
	void close()
	{
		on_strand([this] { pool->close(); });
	}
};

// The connection a lease is on, to tell connections apart.
auto conn_of(const ldap::lease &l) -> const ldap::connection * { return &*l; }
auto conn_of(const ldap::exclusive_lease &l) -> const ldap::connection * { return &*l; }

// The connection under a shared lease, for what changes the session for
// every lease (a bind, unbind(), close()), to see how the pool copes.
auto full(const ldap::lease &l) -> ldap::connection & { return *l; }

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
	f.make({ .servers = { f.refused_url() }, .max_connections = 0 });
	auto zero = f.acquire();
	REQUIRE_FALSE(zero.has_value());
	CHECK(zero.error().code == std::errc::invalid_argument);
	ldap::client moved = std::move(*f.pool);
	auto from = f.acquire();
	REQUIRE_FALSE(from.has_value());
	CHECK(from.error().code == ldap::client_errc::not_connected);
}

TEST_CASE("client: a server URL check_server() refuses fails every acquire() up front", "[net][client]")
{
	pool_fixture f;
	const auto with_dn = ldap::url::parse("ldap://127.0.0.1:1/dc=example,dc=org");
	REQUIRE(with_dn.has_value());
	f.make({ .servers = { f.refused_url(), *with_dn }, .observer = &f.obs });
	for (int i = 0; i < 2; ++i) {
		auto bad = f.acquire();
		REQUIRE_FALSE(bad.has_value());
		CHECK(bad.error().code == ldap::client_errc::invalid_url);
		CHECK(std::string_view(bad.error().context)
			  == "acquire: client_options::servers[1] ldap://127.0.0.1:1/dc=example,dc=org: a server URL names no DN, "
				 "attributes, scope or filter");
	}
	CHECK(f.obs.events.empty());// the first server is not tried either
}

TEST_CASE("client: fails over to the next server", "[net][client][failover]")
{
	pool_fixture f;
	const auto down = f.refused_url();
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
		full(*first).close();// its connection ends: the next acquire opens another
		f.release(*first);
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
		CHECK_THAT(std::string(second.error().context), ContainsSubstring("(backing off: acquire_timeout ends first)"));
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
	f.release(*stale);// closed: leaves the pool
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
		CHECK(conn_of(*a) != conn_of(*b));
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
	SECTION("no_bind_setup() succeeds without a request")
	{
		pool_fixture f;
		const auto &s = f.server({ { step{ .read_request = false, .replies = {}, .close_after = false } } });
		f.make({ .servers = { s.url() }, .setup = ldap::no_bind_setup() });
		auto l = f.acquire();
		CHECK(l.has_value());
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
		// Within the backoff, a new acquire does not bind again: it fails at
		// once with the stored error.
		auto second = f.acquire();
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == ldap::errc::invalid_credentials);
		CHECK_THAT(std::string(second.error().context), ContainsSubstring("authentication failure"));
		CHECK(f.obs.waits.empty());
		CHECK(s.accepted() == 1);
	}
	SECTION("every server refuses: acquire() fails once each was tried")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1, 49) }) } });
		auto &b = f.server({ { answer({ bind_resp(1, 49) }) } });
		f.make({ .servers = { a.url(), b.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = ldap::no_timeout,// would wait forever for a retry
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
		l->release();
		s.drop(0);
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK((*again)->is_open());
		CHECK(s.accepted() == 2);
		CHECK(f.pool->connections() == 1);
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
		const ldap::connection *first = conn_of(*l);
		l->release();
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK(conn_of(*again) == first);
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
		const ldap::connection *first = conn_of(*l);
		l->release();
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK(conn_of(*again) == first);
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
		CHECK(conn_of(*a) == conn_of(*b));
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
		CHECK(conn_of(*a) != conn_of(*b));
		CHECK((conn_of(*c) == conn_of(*a) || conn_of(*c) == conn_of(*b)));
		CHECK(s.accepted() == 2);
		CHECK(f.pool->connections() == 2);
		const ldap::connection *idle = (conn_of(*c) == conn_of(*a)) ? conn_of(*b) : conn_of(*a);
		(conn_of(*c) == conn_of(*a) ? *b : *a).release();
		auto d = f.acquire();
		REQUIRE(d.has_value());
		CHECK(conn_of(*d) == idle);
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
		CHECK(conn_of(*a.get()) == conn_of(*b.get()));
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
	CHECK_THAT(std::string(b.get().error().context), ContainsSubstring("acquire_timeout"));
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
		auto l = f.acquire_exclusive();
		REQUIRE(l.has_value());
		CHECK(l->get().bind_count() == 1);
		REQUIRE(finish(f.ioc, (*l)->simple_bind(ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" }, "pw")).has_value());
		CHECK(l->get().bind_count() == 2);
		f.release(*l);
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
		f.release(*l);
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
	f.close();
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
	f.on_strand([&f] { f.pool.reset(); });
	CHECK(static_cast<bool>(kept));
	CHECK_FALSE(kept->is_open());
	CHECK(text(kept.server()) == text(s.url()));
}

namespace {

// A client with one pooled idle connection, made through io_context::run(),
// which leaves the context stopped; the peer is `listener`'s backlog.
auto pool_after_run(corosio::io_context &ioc, const corosio::tcp_acceptor &listener, std::pmr::memory_resource *mr)
  -> std::optional<ldap::client>
{
	auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(listener.local_endpoint().port()));
	REQUIRE(u.has_value());
	std::optional<ldap::client> pool;
	pool.emplace(ioc, ldap::client_options{ .servers = { *u } }, mr);
	outcome<ldap::result<ldap::lease>> a;
	spawn(ioc, pool->acquire(), a);
	ioc.run();// no restart()
	REQUIRE(a.get().has_value());
	REQUIRE(ioc.stopped());
	return pool;// `a`'s lease returns the connection
}

}// namespace

TEST_CASE("client: destroyed after io_context::run() returned", "[net][client][close]")
{
	// It closes its idle connection; nothing is posted.
	counting_resource mr;
	corosio::io_context ioc;
	const corosio::tcp_acceptor listener(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8);
	auto pool = pool_after_run(ioc, listener, &mr);
	REQUIRE(pool->connections() == 1);
	pool.reset();
	CHECK(mr.outstanding() == 0);// freed now, not by a task
	ioc.restart();
	CHECK(ioc.poll() == 0);// no work left on the io_context
}

TEST_CASE("client: an unbind posted to an io_context that never runs again", "[net][client][close]")
{
	// restart()ed, so the unbind is posted; destroying the io_context
	// destroys the task, its connection and its socket.
	counting_resource mr;
	{
		corosio::io_context ioc;
		const corosio::tcp_acceptor listener(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8);
		auto pool = pool_after_run(ioc, listener, &mr);
		REQUIRE(pool->connections() == 1);
		ioc.restart();
		pool.reset();
		CHECK(mr.outstanding() != 0);// held by the posted task
	}
	CHECK(mr.outstanding() == 0);
}

TEST_CASE("client: a connection whose identity changed is not shared", "[net][client][identity]")
{
	const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
	SECTION("a bind in progress")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{} }, bind_ok() });// the second bind is never answered
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		outcome<ldap::result<void>> bound;
		spawn(f.ioc, full(*a).simple_bind(jdoe, "pw"), bound);
		drive_until(f.ioc, [&s] { return s.log(0).received.size() == 2; });
		auto b = f.acquire();
		REQUIRE(b.has_value());
		CHECK(conn_of(*b) != conn_of(*a));
		CHECK(s.accepted() == 2);
		f.pool->close();
		drive_until(f.ioc, [&bound] { return bound.done(); });
	}
	SECTION("a bind done")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), answer({ bind_resp(2) }) }, bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		REQUIRE(finish(f.ioc, full(*a).simple_bind(jdoe, "pw")).has_value());
		auto b = f.acquire();
		REQUIRE(b.has_value());
		CHECK(conn_of(*b) != conn_of(*a));
		CHECK(s.accepted() == 2);
	}
}

TEST_CASE("client: a dead leased connection does not hold its slot", "[net][client][pool]")
{
	pool_fixture f;
	auto &s = f.server({ bind_ok(), bind_ok() });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
	auto held = f.acquire();
	REQUIRE(held.has_value());
	s.drop(0);
	auto r = finish(f.ioc, (*held)->search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK_FALSE((*held)->is_open());
	auto other = f.acquire();// max_connections is 1, and `held` still holds the dead one
	REQUIRE(other.has_value());
	CHECK((*other)->is_open());
	CHECK(s.accepted() == 2);
}

TEST_CASE("client: a wrong password binds once for concurrent acquires", "[net][client][auth]")
{
	pool_fixture f;
	auto &s = f.server({ refuse(), refuse(), refuse(), refuse(), refuse(), refuse() });
	f.make({ .servers = { s.url() },
	  .setup = admin_setup(),
	  .acquire_timeout = milliseconds(10'000),
	  .backoff = { .initial = milliseconds(20), .max = milliseconds(20) } });
	constexpr std::size_t n = 5;
	std::vector<outcome<ldap::result<ldap::lease>>> out(n);
	for (auto &o : out) {
		spawn(f.ioc, f.pool->acquire(), o);
	}
	drive_until(f.ioc, [&out] { return std::ranges::all_of(out, [](const auto &o) { return o.done(); }); });
	for (auto &o : out) {
		REQUIRE_FALSE(o.get().has_value());
		CHECK(o.get().error().code == ldap::errc::invalid_credentials);
	}
	CHECK(s.accepted() == 1);
	finish(f.ioc, sleep_for(milliseconds(40)));// longer than the backoff's cap
	auto later = f.acquire();// still within the server's auth backoff: no new bind
	REQUIRE_FALSE(later.has_value());
	CHECK(later.error().code == ldap::errc::invalid_credentials);
	CHECK(s.accepted() == 1);
}

TEST_CASE("client: authentication failures back off", "[net][client][auth]")
{
	SECTION("at least auth_failure_min and half the cap, without jitter down to 0")
	{
		pool_fixture f;
		auto &s = f.server({ refuse() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .backoff = { .initial = milliseconds(100), .max = milliseconds(100), .auth_failure_min = milliseconds(70) },
		  .observer = &f.obs });
		ldap::detail::set_jitter(*f.pool, [] { return 0.0; });
		REQUIRE_FALSE(f.acquire().has_value());
		CHECK(f.obs.events.back() == "retry " + text(s.url()) + " 70ms");
		auto &t = f.server({ refuse() });
		f.make({ .servers = { t.url() },
		  .setup = admin_setup(),
		  .backoff = { .initial = milliseconds(400), .max = milliseconds(400), .auth_failure_min = milliseconds(70) },
		  .observer = &f.obs });
		ldap::detail::set_jitter(*f.pool, [] { return 0.0; });
		REQUIRE_FALSE(f.acquire().has_value());
		CHECK(f.obs.events.back() == "retry " + text(t.url()) + " 200ms");// half the cap
	}
	SECTION("concurrent attempts failing together count once")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), refuse(), refuse() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .max_connections = 3, .observer = &f.obs });
		constexpr std::size_t n = 3;
		std::vector<outcome<ldap::result<ldap::lease>>> out(n);
		for (auto &o : out) {
			spawn(f.ioc, f.pool->acquire(), o);
		}
		drive_until(f.ioc, [&out] { return std::ranges::all_of(out, [](const auto &o) { return o.done(); }); });
		for (auto &o : out) {
			REQUIRE_FALSE(o.get().has_value());
			CHECK(o.get().error().code == ldap::errc::invalid_credentials);
		}
		CHECK(s.accepted() == 3);// all in flight before the first failed
		CHECK(retries(f.obs) == 1);
	}
	SECTION("a bind is tried again once the backoff ends")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), bind_ok() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .backoff = { .initial = milliseconds(30), .max = milliseconds(30), .auth_failure_min = milliseconds(30) } });
		REQUIRE_FALSE(f.acquire().has_value());
		finish(f.ioc, sleep_for(milliseconds(40)));
		auto l = f.acquire();
		REQUIRE(l.has_value());
		CHECK(s.accepted() == 2);
	}
	SECTION("once the backoff ends, one bind for concurrent acquires")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), refuse(), refuse(), refuse() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .max_connections = 3,
		  .backoff = { .initial = milliseconds(30), .max = milliseconds(30), .auth_failure_min = milliseconds(30) } });
		REQUIRE_FALSE(f.acquire().has_value());
		finish(f.ioc, sleep_for(milliseconds(40)));// the backoff ends
		constexpr std::size_t n = 3;
		std::vector<outcome<ldap::result<ldap::lease>>> out(n);
		for (auto &o : out) {
			spawn(f.ioc, f.pool->acquire(), o);
		}
		drive_until(f.ioc, [&out] { return std::ranges::all_of(out, [](const auto &o) { return o.done(); }); });
		for (auto &o : out) {
			REQUIRE_FALSE(o.get().has_value());
			CHECK(o.get().error().code == ldap::errc::invalid_credentials);
		}
		CHECK(s.accepted() == 2);// one more bind, not one per acquire
	}
}

TEST_CASE("client: live connections are shared while no server can be tried", "[net][client][pool]")
{
	SECTION("the only server backs off")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), hang_up_at_once() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .max_connections = 2,
		  .acquire_timeout = milliseconds(5'000),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		auto b = f.acquire();// a second connection fails: shares the first
		REQUIRE(b.has_value());
		CHECK(conn_of(*b) == conn_of(*a));
		auto c = f.acquire();// the server still backs off: shares, tries nothing
		REQUIRE(c.has_value());
		CHECK(conn_of(*c) == conn_of(*a));
		CHECK(s.accepted() == 2);
	}
	SECTION("the password changed on the server")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), refuse() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .max_connections = 2 });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		auto b = f.acquire();// a new bind fails: the bound connection still serves
		REQUIRE(b.has_value());
		CHECK(conn_of(*b) == conn_of(*a));
		auto c = f.acquire();// within the auth backoff
		REQUIRE(c.has_value());
		CHECK(conn_of(*c) == conn_of(*a));
		CHECK(s.accepted() == 2);
	}
}

TEST_CASE("client: a waiting acquire() wakes when a leased connection leaves", "[net][client][pool]")
{
	SECTION("the connection closes")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
		auto e = f.acquire_exclusive();
		REQUIRE(e.has_value());
		outcome<ldap::result<ldap::lease>> b;
		spawn(f.ioc, f.pool->acquire(), b);
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK_FALSE(b.done());// waits: the only connection is held exclusively
		s.drop(0);
		REQUIRE_FALSE(finish(f.ioc, (*e)->search(people_search())).has_value());// the lease finds it closed
		drive_until(f.ioc, [&b] { return b.done(); });
		REQUIRE(b.get().has_value());
		CHECK(conn_of(*b.get()) != conn_of(*e));
		CHECK(s.accepted() == 2);
	}
	SECTION("the connection passes max_lifetime")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .max_lifetime = milliseconds(50),
		  .acquire_timeout = milliseconds(5'000) });
		const auto start = std::chrono::steady_clock::now();
		auto e = f.acquire_exclusive();
		REQUIRE(e.has_value());
		auto b = f.acquire();// waits until the held connection expires, then replaces it
		REQUIRE(b.has_value());
		CHECK(std::chrono::steady_clock::now() - start >= milliseconds(50));
		CHECK(conn_of(*b) != conn_of(*e));
		CHECK(s.accepted() == 2);
	}
}

TEST_CASE("client: a failure after a success is recorded", "[net][client][backoff]")
{
	pool_fixture f;
	auto &s = f.server({ { step{} }, hang_up_at_once(), bind_ok(), bind_ok() });
	f.make({ .servers = { s.url() },
	  .setup = admin_setup(),
	  .max_connections = 3,
	  .acquire_timeout = milliseconds(10'000),
	  .backoff = { .initial = milliseconds(0), .max = milliseconds(0) },
	  .observer = &f.obs });
	outcome<ldap::result<ldap::lease>> a;
	spawn(f.ioc, f.pool->acquire(), a);
	drive_until(f.ioc, [&s] { return s.accepted() == 1 && !s.log(0).received.empty(); });// its bind is out
	auto b = f.acquire();// fails once (recorded), then connects: the failures reset
	REQUIRE(b.has_value());
	CHECK(retries(f.obs) == 1);
	s.drop(0);// the attempt begun first fails after that success
	drive_until(f.ioc, [&a] { return a.done(); });
	REQUIRE(a.get().has_value());
	CHECK(retries(f.obs) == 2);
}

namespace {

// The operations that change the session for everyone sharing a connection.
template<class C>
concept has_simple_bind = requires(C &c) { c.simple_bind(ldap::dn{}, std::string{}); };
template<class C>
concept has_sasl_bind = requires(C &c, ldap::sasl_mechanism &m) { c.sasl_bind(m); };
template<class C>
concept has_start_tls = requires(C &c) { c.start_tls(); };
template<class C>
concept has_unbind = requires(C &c) { c.unbind(); };
template<class C>
concept has_close = requires(C &c) { c.close(); };
template<class C>
concept session_operations =
  has_simple_bind<C> && has_sasl_bind<C> && has_start_tls<C> && has_unbind<C> && has_close<C>;

template<class Lease> using leased_t = decltype(*std::declval<Lease &>());

static_assert(session_operations<ldap::connection>);
static_assert(std::same_as<leased_t<ldap::lease>, ldap::connection &>);
static_assert(std::same_as<leased_t<ldap::exclusive_lease>, ldap::connection &>);
static_assert(session_operations<ldap::sync::connection>);
static_assert(session_operations<ldap::sync::lease>);
static_assert(session_operations<ldap::sync::exclusive_lease>);

}// namespace

TEST_CASE("client: exclusive leases", "[net][client][exclusive]")
{
	SECTION("never shared while held")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .max_connections = 2 });
		auto e = f.acquire_exclusive();
		REQUIRE(e.has_value());
		auto a = f.acquire();
		auto b = f.acquire();
		REQUIRE(a.has_value());
		REQUIRE(b.has_value());
		CHECK(conn_of(*a) != conn_of(*e));
		CHECK(conn_of(*b) == conn_of(*a));// shares the shared one, not the exclusive one
		CHECK(s.accepted() == 2);
		e->release();
		auto c = f.acquire();// idle again: handed out first
		REQUIRE(c.has_value());
		CHECK(conn_of(*c) != conn_of(*a));
	}
	SECTION("an exclusive acquire does not take a shared connection")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		outcome<ldap::result<ldap::exclusive_lease>> e;
		spawn(f.ioc, f.pool->acquire_exclusive(), e);
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK_FALSE(e.done());// waits: the only connection is leased
		const ldap::connection *conn = conn_of(*a);
		a->release();
		drive_until(f.ioc, [&e] { return e.done(); });
		REQUIRE(e.get().has_value());
		CHECK(conn_of(*e.get()) == conn);
		CHECK(s.accepted() == 1);
	}
	SECTION("a shared acquire waits while the connection is held exclusively")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(50) });
		auto e = f.acquire_exclusive();
		REQUIRE(e.has_value());
		auto a = f.acquire();
		REQUIRE_FALSE(a.has_value());
		CHECK(a.error().code == ldap::cond::timeout);
		e->release();
		auto b = f.acquire();
		REQUIRE(b.has_value());
		CHECK(s.accepted() == 1);
	}
	SECTION("a waiting exclusive acquire is not starved by shared ones")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), bind_ok() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .max_connections = 2,
		  .acquire_timeout = milliseconds(5'000) });
		auto a = f.acquire();
		auto x = f.acquire_exclusive();
		REQUIRE(a.has_value());
		REQUIRE(x.has_value());
		outcome<ldap::result<ldap::exclusive_lease>> e;
		spawn(f.ioc, f.pool->acquire_exclusive(), e);
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK_FALSE(e.done());// waits: no idle connection, no free slot
		const ldap::connection *freed = conn_of(*x);
		auto b = finish(f.ioc, release_then_acquire(*f.pool, *x));
		REQUIRE(b.has_value());
		CHECK(conn_of(*b) == conn_of(*a));// shares, leaving the idle one to the waiter
		drive_until(f.ioc, [&e] { return e.done(); });
		REQUIRE(e.get().has_value());
		CHECK(conn_of(*e.get()) == freed);
		CHECK(s.accepted() == 2);
	}
	SECTION("a waiting exclusive acquire gets the only connection")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		outcome<ldap::result<ldap::exclusive_lease>> e;
		spawn(f.ioc, f.pool->acquire_exclusive(), e);
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK_FALSE(e.done());// waits: the only connection is shared
		const ldap::connection *conn = conn_of(*a);
		outcome<ldap::result<ldap::lease>> b;
		spawn(f.ioc, release_then_acquire(*f.pool, *a), b);// before the waiter resumes
		drive_until(f.ioc, [&e] { return e.done(); });
		REQUIRE(e.get().has_value());
		CHECK(conn_of(*e.get()) == conn);
		CHECK_FALSE(b.done());// left the idle connection to the waiter, waits for it
		e.get()->release();
		drive_until(f.ioc, [&b] { return b.done(); });
		REQUIRE(b.get().has_value());
		CHECK(conn_of(*b.get()) == conn);
		CHECK(s.accepted() == 1);
	}
	SECTION("a waiting exclusive acquire stopped before it takes the only connection leaves it to a shared one")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(5'000) });
		auto a = f.acquire();
		REQUIRE(a.has_value());
		std::stop_source stop;
		outcome<ldap::result<ldap::exclusive_lease>> e;
		spawn(f.ioc, stop.get_token(), f.pool->acquire_exclusive(), e);
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK_FALSE(e.done());
		const ldap::connection *conn = conn_of(*a);
		const auto start = std::chrono::steady_clock::now();
		outcome<ldap::result<ldap::lease>> b;
		spawn(f.ioc, release_stop_then_acquire(*f.pool, *a, stop), b);// b waits for the waiter
		drive_until(f.ioc, [&b, &e] { return b.done() && e.done(); });
		REQUIRE(e.done());
		REQUIRE_FALSE(e.get().has_value());
		CHECK(e.get().error().code == ldap::cond::canceled);
		REQUIRE(b.done());
		REQUIRE(b.get().has_value());
		CHECK(conn_of(*b.get()) == conn);
		CHECK(std::chrono::steady_clock::now() - start < milliseconds(2'500));// not at acquire_timeout
		CHECK(s.accepted() == 1);
	}
}

TEST_CASE("client: max_lifetime under load", "[net][client][pool]")
{
	pool_fixture f;
	auto &s = f.server({ { answer({ bind_resp(1) }), step{}, client_hangs_up() }, bind_ok() });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .max_lifetime = milliseconds(30), .observer = &f.obs });
	auto a = f.acquire();
	REQUIRE(a.has_value());
	finish(f.ioc, sleep_for(milliseconds(40)));
	auto b = f.acquire();// `a` still holds the expired one: not shared, replaced
	REQUIRE(b.has_value());
	CHECK(conn_of(*b) != conn_of(*a));
	CHECK(s.accepted() == 2);
	CHECK(f.pool->connections() == 2);// the old one drains
	f.release(*a);
	CHECK(f.pool->connections() == 1);
	CHECK(f.obs.events.back() == "disconnect " + text(s.url()) + " max_lifetime");
}

TEST_CASE("client: the probe's own bound", "[net][client][probe]")
{
	SECTION("a black-holed connection is replaced after probe_timeout")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{} }, bind_ok() });// reads the probe, never answers
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .idle_check = milliseconds(0),
		  .probe_timeout = milliseconds(50),
		  .acquire_timeout = milliseconds(10'000),
		  .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		l->release();
		const auto start = std::chrono::steady_clock::now();
		auto again = f.acquire();
		REQUIRE(again.has_value());
		CHECK(std::chrono::steady_clock::now() - start < milliseconds(5'000));
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"probe " + text(s.url()) + " failed",
				"disconnect " + text(s.url()) + " probe_failed",
				"connect " + text(s.url()) + " ok" });
	}
	SECTION("a probe begun late and cut short by acquire_timeout neither closes the connection nor tries a server")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{} }, bind_ok() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .idle_check = milliseconds(0),
		  .probe_timeout = milliseconds(5'000),
		  .acquire_timeout = milliseconds(200),
		  .observer = &f.obs });
		auto l = f.acquire_exclusive();
		REQUIRE(l.has_value());
		outcome<ldap::result<ldap::lease>> again;
		spawn(f.ioc, f.pool->acquire(), again);// waits for the exclusive lease
		finish(f.ioc, sleep_for(milliseconds(150)));
		l->release();// the probe begins with about 50 ms (under half) left
		drive_until(f.ioc, [&again] { return again.done(); });
		REQUIRE_FALSE(again.get().has_value());
		CHECK(again.get().error().code == ldap::cond::timeout);
		CHECK(s.accepted() == 1);
		CHECK(f.pool->connections() == 1);// unknown, not dead: it stays
		CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(s.url()) + " ok" });
	}
	SECTION("a probe that had most of acquire_timeout and got no answer fails")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{} } });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .idle_check = milliseconds(0),
		  .probe_timeout = milliseconds(5'000),
		  .acquire_timeout = milliseconds(400),
		  .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		l->release();
		REQUIRE_FALSE(f.acquire().has_value());// the probe begins at once
		CHECK(f.pool->connections() == 0);// replaced by the next acquire
		REQUIRE(f.obs.events.size() >= 3);
		CHECK(f.obs.events[1] == "probe " + text(s.url()) + " failed");
		CHECK(f.obs.events[2] == "disconnect " + text(s.url()) + " probe_failed");
	}
}

TEST_CASE("client: an attempt begun late and cut short by acquire_timeout is not the server's fault",
  "[net][client][timeout]")
{
	pool_fixture f;
	auto &s = f.server({ hang_up_at_once(), { step{} } });// then reads the bind, never answers
	f.make({ .servers = { s.url() },
	  .setup = admin_setup(),
	  .acquire_timeout = milliseconds(400),
	  .backoff = { .initial = milliseconds(250), .max = milliseconds(250) },
	  .observer = &f.obs });
	// Waits out the backoff, then begins with about 150 ms (under half) left:
	// excused if it begins before the deadline, at most 150 ms late.
	auto l = f.acquire();
	REQUIRE_FALSE(l.has_value());
	CHECK(l.error().code == ldap::cond::timeout);
	CHECK(s.accepted() == 2);
	// Only the first failure: no failed on_connect, no backoff for the second.
	CHECK(f.obs.events
		  == std::vector<std::string>{ "connect " + text(s.url()) + " failed", "retry " + text(s.url()) + " 250ms" });
}

TEST_CASE("client: an attempt that had most of acquire_timeout and did not finish fails", "[net][client][timeout]")
{
	SECTION("a server that never answers the bind: the next acquire fails over")
	{
		pool_fixture f;
		auto &hung = f.server({ { step{} }, { step{} } });// accepts, reads the bind, never answers
		auto &up = f.server({ bind_ok() });
		// The defaults' ratio: the connect timeout no shorter than
		// acquire_timeout, no operation_timeout.
		f.make({ .servers = { hung.url(), up.url() },
		  .connection = { .timeout = milliseconds(100) },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(100),
		  .backoff = { .initial = milliseconds(60'000), .max = milliseconds(60'000) },
		  .observer = &f.obs });
		auto first = f.acquire();
		REQUIRE_FALSE(first.has_value());
		CHECK(first.error().code == ldap::cond::timeout);
		CHECK(f.obs.events
			  == std::vector<std::string>{
				"connect " + text(hung.url()) + " failed", "retry " + text(hung.url()) + " 60000ms" });
		auto second = f.acquire();
		REQUIRE(second.has_value());
		CHECK(text(second->server()) == text(up.url()));
		CHECK(hung.accepted() == 1);
	}
	SECTION("acquire_timeout shorter than the connect timeout")
	{
		pool_fixture f;
		auto &hung = f.server({ { step{} }, { step{} } });
		auto &up = f.server({ bind_ok() });
		f.make({ .servers = { hung.url(), up.url() },
		  .connection = { .timeout = milliseconds(10'000), .operation_timeout = milliseconds(10'000) },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(60),
		  .backoff = { .initial = milliseconds(60'000), .max = milliseconds(60'000) } });
		REQUIRE_FALSE(f.acquire().has_value());
		auto second = f.acquire();
		REQUIRE(second.has_value());
		CHECK(text(second->server()) == text(up.url()));
		CHECK(hung.accepted() == 1);
	}
	SECTION("after a wrong password: the authentication backoff starts again, no bind per acquire")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), { step{} }, refuse() });// then slow to answer binds
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(100),
		  .backoff = { .initial = milliseconds(200), .max = milliseconds(200), .auth_failure_min = milliseconds(200) },
		  .observer = &f.obs });
		auto refused = f.acquire();
		REQUIRE_FALSE(refused.has_value());
		CHECK(refused.error().code == ldap::errc::invalid_credentials);
		finish(f.ioc, sleep_for(milliseconds(250)));// the backoff ends: one bind is let through
		REQUIRE_FALSE(f.acquire().has_value());// cut short
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events.back() == "retry " + text(s.url()) + " 200ms");
		CHECK(f.obs.retry_failures.back() == ldap::errc::invalid_credentials);
		auto later = f.acquire();// backing off again: fails at once, no bind
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
	}
}

TEST_CASE("client: the bind after an authentication backoff ends without a verdict: that backoff starts again",
  "[net][client][auth]")
{
	SECTION("begun late and cut short by acquire_timeout")
	{
		pool_fixture f;
		auto &hung = f.server({ { step{} }, { step{} } });// reads the bind, never answers
		auto &s = f.server({ refuse(), { step{} }, refuse() });// then slow to answer binds
		f.make({ .servers = { hung.url(), s.url() },
		  .connection = { .operation_timeout = milliseconds(250) },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(400),
		  .backoff = { .initial = milliseconds(300),
			.max = milliseconds(60'000),
			.multiplier = 10.0,
			.auth_failure_min = milliseconds(300) },
		  .observer = &f.obs });
		auto refused = f.acquire();// `hung` times out, then `s` refuses the password
		REQUIRE_FALSE(refused.has_value());
		CHECK(refused.error().code == ldap::errc::invalid_credentials);
		finish(f.ioc, sleep_for(milliseconds(350)));// both backoffs end
		// `hung` times out again, so the bind to `s` begins with under half the
		// time left and is cut short.
		auto cut = f.acquire();// fails with the stored error: `s` backs off again
		REQUIRE_FALSE(cut.has_value());
		CHECK(cut.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events.back() == "retry " + text(s.url()) + " 3000ms");// no on_connect
		CHECK(f.obs.retry_failures.back() == ldap::errc::invalid_credentials);// the stored error, not the timeout
		auto later = f.acquire();// backing off again: fails at once, no bind
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
	}
	SECTION("the acquire stopped by its stop token")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), { step{} }, refuse() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .backoff = { .initial = milliseconds(200), .max = milliseconds(200), .auth_failure_min = milliseconds(200) },
		  .observer = &f.obs });
		REQUIRE_FALSE(f.acquire().has_value());
		finish(f.ioc, sleep_for(milliseconds(250)));// the backoff ends: one bind is let through
		std::stop_source stop;
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, stop.get_token(), f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 2 && !s.log(1).received.empty(); });
		stop.request_stop();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::cond::canceled);
		CHECK(f.obs.events.back() == "retry " + text(s.url()) + " 200ms");// no on_connect
		CHECK(f.obs.retry_failures.back() == ldap::errc::invalid_credentials);// the stored error, not canceled
		auto later = f.acquire();
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
	}
	SECTION("another error: operation_timeout ends the bind")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), { step{} }, refuse() });
		f.make({ .servers = { s.url() },
		  .connection = { .operation_timeout = milliseconds(50) },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(5'000),
		  .backoff = { .initial = milliseconds(200), .max = milliseconds(200), .auth_failure_min = milliseconds(200) },
		  .observer = &f.obs });
		REQUIRE_FALSE(f.acquire().has_value());
		finish(f.ioc, sleep_for(milliseconds(250)));
		auto timed_out = f.acquire();// not the ordinary backoff: no bind again within this acquire
		REQUIRE_FALSE(timed_out.has_value());
		CHECK(timed_out.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events.back() == "retry " + text(s.url()) + " 200ms");
		CHECK(f.obs.retry_failures.back() == ldap::errc::invalid_credentials);
		auto later = f.acquire();
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
	}
	SECTION("recording that failure throws (the jitter source)")
	{
		pool_fixture f;
		auto &s = f.server({ refuse(), { step{} }, refuse() });
		f.make({ .servers = { s.url() },
		  .connection = { .operation_timeout = milliseconds(50) },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(5'000),
		  .backoff = {
			.initial = milliseconds(200), .max = milliseconds(200), .auth_failure_min = milliseconds(200) } });
		REQUIRE_FALSE(f.acquire().has_value());
		finish(f.ioc, sleep_for(milliseconds(250)));
		ldap::detail::set_jitter(*f.pool, [] -> double { throw std::runtime_error("no jitter"); });
		CHECK_THROWS_AS(f.acquire(), std::runtime_error);// server_failed() throws for the timed-out bind
		ldap::detail::set_jitter(*f.pool, [] { return 1.0; });
		auto later = f.acquire();// the backoff started again all the same: no bind
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::errc::invalid_credentials);
		CHECK(s.accepted() == 2);
	}
}

TEST_CASE("client: acquire() stopped by its stop token", "[net][client][cancel]")
{
	SECTION("while connecting")
	{
		pool_fixture f;
		auto &s = f.server({ { step{} } });// reads the bind, never answers
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		std::stop_source stop;
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, stop.get_token(), f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 1 && !s.log(0).received.empty(); });
		stop.request_stop();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::cond::canceled);
		CHECK(f.obs.events.empty());// not the server's fault: no backoff
	}
	SECTION("while probing")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{} } });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = milliseconds(0), .observer = &f.obs });
		auto l = f.acquire();
		REQUIRE(l.has_value());
		l->release();
		std::stop_source stop;
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, stop.get_token(), f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.log(0).received.size() == 2; });
		stop.request_stop();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::cond::canceled);
		CHECK(f.pool->connections() == 1);// the connection stays
		CHECK(f.obs.events.back() == "probe " + text(s.url()) + " failed");
	}
	SECTION("while waiting for a backoff")
	{
		pool_fixture f;
		auto &s = f.server({ hang_up_at_once() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = ldap::no_timeout,
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		std::stop_source stop;
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, stop.get_token(), f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 1; });
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK_FALSE(a.done());
		stop.request_stop();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::cond::canceled);
	}
}

TEST_CASE("client: closed during acquire()", "[net][client][close]")
{
	SECTION("close() while connecting")
	{
		pool_fixture f;
		auto &s = f.server({ { step{} } });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 1 && !s.log(0).received.empty(); });
		f.pool->close();// stops the attempt: the server need not answer or hang up
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::client_errc::not_connected);
	}
	SECTION("the client destroyed before acquire()'s task starts")
	{
		pool_fixture f;
		auto &s = f.server({ hang_up_at_once() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = ldap::no_timeout,
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		outcome<ldap::result<ldap::lease>> a;
		auto task = f.pool->acquire();
		f.pool.reset();// acquire() holds its own state, not the client
		spawn(f.ioc, std::move(task), a);
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::client_errc::not_connected);
		CHECK(s.accepted() == 0);
	}
	SECTION("the client destroyed while acquire() waits for a backoff")
	{
		pool_fixture f;
		auto &s = f.server({ hang_up_at_once() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = ldap::no_timeout,
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 1; });
		finish(f.ioc, sleep_for(milliseconds(20)));
		f.pool.reset();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::client_errc::not_connected);
	}
}

namespace {

// Closes the client from its first on_connect hook; records every call.
struct closing_recorder final : ldap::client_observer
{
	std::optional<ldap::client> *pool = nullptr;
	std::size_t calls = 0;

	void on_connect(const ldap::url &, const ldap::result<void> &) override
	{
		++calls;
		(*pool)->close();
	}
	void on_disconnect(const ldap::url &, ldap::disconnect_reason) override { ++calls; }
	void on_retry(const ldap::url &, const ldap::error &, milliseconds) override { ++calls; }
	void on_probe(const ldap::url &, const ldap::result<void> &) override { ++calls; }
	void on_acquire_wait(milliseconds) override { ++calls; }
};

}// namespace

TEST_CASE("client: no observer hook after close()", "[net][client][close]")
{
	SECTION("close() from a hook")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		closing_recorder obs;
		obs.pool = &f.pool;
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &obs });
		auto l = f.acquire();
		REQUIRE_FALSE(l.has_value());
		CHECK(l.error().code == ldap::client_errc::not_connected);
		CHECK(f.pool->connections() == 0);
		CHECK(obs.calls == 2);// on_connect, and close()'s on_disconnect
	}
	SECTION("a waiting acquire() ends after close() without calling on_acquire_wait")
	{
		pool_fixture f;
		auto &s = f.server({ hang_up_at_once() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = ldap::no_timeout,
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) },
		  .observer = &f.obs });
		outcome<ldap::result<ldap::lease>> a;
		spawn(f.ioc, f.pool->acquire(), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 1; });
		finish(f.ioc, sleep_for(milliseconds(20)));
		f.pool->close();
		const auto seen = f.obs.events.size();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(f.obs.events.size() == seen);
		CHECK(f.obs.waits.empty());
	}
}

namespace {

// Answers the setup's bind, reads one request and hangs up without an answer.
auto lost_after_bind() -> std::vector<step>
{
	return { answer({ bind_resp(1) }), step{ .read_request = true, .replies = {}, .close_after = true } };
}

// Answers the setup's bind, then the search with one entry.
auto found_after_bind() -> std::vector<step>
{
	return { answer({ bind_resp(1) }),
		answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"), done_msg(2) }) };
}

auto compare_msg(std::int32_t id, std::int32_t code) -> ldap::message
{
	return ldap::message{ id, ldap::compare_response{ ldap::ldap_result{ code } } };
}

// Answers the setup's bind, then the search with busy.
auto busy_search() -> std::vector<step>
{
	return { answer({ bind_resp(1) }), answer({ done_msg(2, 51, "", "too many operations") }) };
}

auto jdoe_compare() -> ldap::compare_params
{
	return { .entry = ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" }, .attribute = "cn", .value = "John" };
}

}// namespace

TEST_CASE("client: read forwarders retry once on another connection", "[net][client][retry]")
{
	SECTION("search(): the connection is lost")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		REQUIRE(r->entries.size() == 1);
		CHECK(r->entries.front() == expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "John"));
		REQUIRE(s.accepted() == 2);
		CHECK(s.log(0).received.size() == 2);// the bind, the search
		REQUIRE(s.log(1).received.size() == 2);
		CHECK(std::holds_alternative<ldap::search_request>(s.log(1).received[1].op));
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"disconnect " + text(s.url()) + " closed",
				"connect " + text(s.url()) + " ok" });
		CHECK(f.pool->connections() == 1);// the lease returned
	}
	SECTION("compare(): the server is busy")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(s.accepted() == 2);// another connection, although the first stayed open
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"disconnect " + text(s.url()) + " busy_or_unavailable",
				"connect " + text(s.url()) + " ok" });
	}
	SECTION("compare(): the response's diagnosticMessage and controls")
	{
		pool_fixture f;
		ldap::message answered{ 2, ldap::compare_response{ ldap::ldap_result{ 6, "", "cached" } } };
		answered.controls.emplace_back("1.2.3.4", false, "v");
		auto &s = f.server({ { answer({ bind_resp(1) }), answer({ answered }) } });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(r->diagnostic_message == "cached");
		REQUIRE(r->controls.size() == 1);
		CHECK(r->controls[0].type == "1.2.3.4");
		CHECK(r->referrals.empty());
	}
	SECTION("compare(): busy on the first server, the retry goes to the second")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) }, found_after_bind() });
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
		f.make({ .servers = { a.url(), b.url() }, .setup = admin_setup(), .max_connections = 2, .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(a.accepted() == 1);
		CHECK(b.accepted() == 1);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(a.url()) + " ok",
				"disconnect " + text(a.url()) + " busy_or_unavailable",
				"connect " + text(b.url()) + " ok" });// no backoff for the first server
		// Only the retry avoided it: with the connection to the second
		// server held, a new connection goes to the first again.
		auto held = f.acquire_exclusive();
		REQUIRE(held.has_value());
		CHECK(text(held->server()) == text(b.url()));
		auto next = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(next.has_value());
		CHECK(next->entries.size() == 1);
		CHECK(a.accepted() == 2);
	}
	SECTION("compare(): busy on the first server, the second down: back to the first")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
		const auto down = f.refused_url();
		f.make({ .servers = { a.url(), down }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(a.accepted() == 2);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(a.url()) + " ok",
				"disconnect " + text(a.url()) + " busy_or_unavailable",
				"connect " + text(down) + " failed",
				"retry " + text(down) + " 100ms",
				"connect " + text(a.url()) + " ok" });
	}
	SECTION("compare(): busy on the first server, the second down: a pooled connection to the first serves")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) } });
		const auto down = f.refused_url();
		f.make({ .servers = { a.url(), down },
		  .setup = admin_setup(),
		  .max_connections = 2,
		  .idle_check = std::nullopt,
		  .observer = &f.obs });
		auto first = f.acquire_exclusive();
		auto second = f.acquire_exclusive();
		REQUIRE(first.has_value());
		REQUIRE(second.has_value());
		first->release();
		finish(f.ioc, sleep_for(milliseconds(5)));
		second->release();// the most recently used: compare() takes it
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(a.accepted() == 2);// the retry took the idle first connection, opened none
		CHECK(a.log(0).received.size() == 2);// the bind, the compare
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(a.url()) + " ok",
				"connect " + text(a.url()) + " ok",
				"disconnect " + text(a.url()) + " busy_or_unavailable",
				"connect " + text(down) + " failed",
				"retry " + text(down) + " 100ms" });
	}
	SECTION("compare(): busy on the first server, the retry takes a pooled connection to the second")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) } });
		auto &b =
		  f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }), answer({ compare_msg(3, 6) }) } });
		f.make({ .servers = { a.url(), b.url() },
		  .setup = admin_setup(),
		  .max_connections = 3,
		  .idle_check = std::nullopt,
		  .observer = &f.obs });
		// The first compare() leaves an idle connection to the second server.
		REQUIRE(finish(f.ioc, f.pool->compare(jdoe_compare())).has_value());
		{
			auto to_b = f.acquire_exclusive();// the idle one
			auto to_a = f.acquire_exclusive();// a new one, to the first server
			REQUIRE(to_b.has_value());
			REQUIRE(to_a.has_value());
			CHECK(text(to_b->server()) == text(b.url()));
			CHECK(text(to_a->server()) == text(a.url()));
		}
		f.obs.events.clear();
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));// the first server's, preferred
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(a.accepted() == 2);
		CHECK(b.accepted() == 1);// no new connection
		CHECK(b.log(0).received.size() == 3);// the bind, both compares
		CHECK(f.obs.events == std::vector<std::string>{ "disconnect " + text(a.url()) + " busy_or_unavailable" });
	}
	SECTION("compare(): busy, the pool full: the retry shares a connection to the same server")
	{
		// The busy connection is already retired and the pool full: the retry
		// shares the other connection.
		pool_fixture f;
		const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
		auto &a = f.server({ { answer({ bind_resp(1) }),
							   step{},// reads the compare, answers it after the bind below
							   answer({ compare_msg(2, 51), bind_resp(3) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
		const auto other = f.refused_url();
		f.make(
		  { .servers = { a.url(), other }, .setup = admin_setup(), .idle_check = std::nullopt, .observer = &f.obs });
		auto mine = f.acquire();
		REQUIRE(mine.has_value());
		outcome<ldap::result<ldap::compare_result>> compared;
		spawn(f.ioc, f.pool->compare(jdoe_compare()), compared);// shares `mine`'s connection
		drive_until(f.ioc, [&a] { return a.log(0).received.size() == 2; });
		outcome<ldap::result<void>> bound;
		const auto binds = (*mine)->bind_count();
		spawn(f.ioc, full(*mine).simple_bind(jdoe, "pw"), bound);
		drive_until(f.ioc, [&] { return (*mine)->bind_count() != binds; });// binding: not handed out
		outcome<ldap::result<ldap::lease>> opener;
		spawn(f.ioc, f.pool->acquire(), opener);
		drive_until(f.ioc, [&] { return compared.done() && bound.done() && opener.done(); });
		REQUIRE(opener.get().has_value());
		CHECK(text(opener.get()->server()) == text(a.url()));
		REQUIRE(compared.get().has_value());
		CHECK(compared.get()->value);
		CHECK(a.accepted() == 2);
		CHECK(a.log(1).received.size() == 2);// the bind, the retried compare
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(a.url()) + " ok", "connect " + text(a.url()) + " ok" });
	}
	SECTION("compare(): busy on the second of three servers: the third, then the second")
	{
		pool_fixture f;
		auto &a = f.server({ hang_up_at_once(), hang_up_at_once() });
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 51) }) },
		  { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
		const auto c = f.refused_url();
		f.make({ .servers = { a.url(), b.url(), c },
		  .setup = admin_setup(),
		  .max_connections = 2,
		  .idle_check = std::nullopt,
		  .backoff = { .initial = milliseconds(50), .max = milliseconds(1000) },
		  .observer = &f.obs });
		REQUIRE(f.acquire().has_value());// the first server fails: to the second, then idle
		finish(f.ioc, sleep_for(milliseconds(100)));// the first server's backoff ends
		f.obs.events.clear();
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(a.accepted() == 2);
		CHECK(b.accepted() == 2);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "disconnect " + text(b.url()) + " busy_or_unavailable",
				"connect " + text(a.url()) + " failed",
				"retry " + text(a.url()) + " 100ms",
				"connect " + text(c) + " failed",
				"retry " + text(c) + " 50ms",
				"connect " + text(b.url()) + " ok" });
	}
	SECTION("search_stream(): lost before its first message")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(200) });
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());
		CHECK(s.accepted() == 2);
		// The stream holds its lease: an exclusive acquire() finds no
		// connection free.
		auto busy = f.acquire_exclusive();
		REQUIRE_FALSE(busy.has_value());
		CHECK(busy.error().code == ldap::cond::timeout);
		auto entries = finish(f.ioc, drain_stream(*stream));
		REQUIRE(entries.has_value());
		REQUIRE(entries->size() == 1);
		CHECK(entries->front() == expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "John"));
		stream = ldap::search_stream{};// returns the lease
		auto mine = f.acquire_exclusive();
		REQUIRE(mine.has_value());
		CHECK(s.accepted() == 2);
	}
	SECTION("search(): the server is busy")
	{
		pool_fixture f;
		auto &s = f.server({ busy_search(), found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		REQUIRE(r->entries.size() == 1);
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"disconnect " + text(s.url()) + " busy_or_unavailable",
				"connect " + text(s.url()) + " ok" });
	}
	SECTION("search_stream(): a SearchResultDone busy before any entry")
	{
		pool_fixture f;
		auto &s = f.server({ busy_search(), found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());
		auto entries = finish(f.ioc, drain_stream(*stream));
		REQUIRE(entries.has_value());
		REQUIRE(entries->size() == 1);
		CHECK(entries->front() == expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "John"));
		CHECK(s.accepted() == 2);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"disconnect " + text(s.url()) + " busy_or_unavailable",
				"connect " + text(s.url()) + " ok" });
	}
}

TEST_CASE("client: when read forwarders do not retry", "[net][client][retry]")
{
	SECTION("a stream after its first entry")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
							   answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John") }, true) },
		  found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());
		auto first = finish(f.ioc, stream->next());
		REQUIRE(first.has_value());
		CHECK(first->has_value());
		auto second = finish(f.ioc, stream->next());
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == ldap::cond::connection_lost);
		CHECK(s.accepted() == 1);
	}
	SECTION("a server result code")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
							   answer({ done_msg(2, 32, "", "no such entry") }),
							   answer({ done_msg(3, 32, "", "no such entry") }) },
		  found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::no_such_object);
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());// next() reports it, as connection::search_stream()
		auto e = finish(f.ioc, stream->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == ldap::errc::no_such_object);
		CHECK(s.accepted() == 1);
		CHECK(s.log(0).received.size() == 3);
	}
	SECTION("a limit code: the search_result")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
							   answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"),
								 done_msg(2, 4, "", "size limit") }) },
		  found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->result_code == 4);
		CHECK(r->entries.size() == 1);
		CHECK(s.accepted() == 1);
	}
	SECTION("only once")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), lost_after_bind(), found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK(s.accepted() == 2);
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));// the third connection
		REQUIRE(stream.has_value());
		CHECK(s.accepted() == 3);
	}
	SECTION("search_stream(): the retry fails before any message too: next() reports it")
	{
		pool_fixture f;
		auto &s = f.server({ busy_search(),
		  { answer({ bind_resp(1) }), answer({ done_msg(2, 52, "", "shutting down") }) },
		  found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());// the second error is the stream's
		auto e = finish(f.ioc, stream->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == ldap::errc::unavailable);
		CHECK(s.accepted() == 2);
	}
	SECTION("search_stream(): its deadline passes before any message")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{}, step{} }, found_after_bind() });// never answers
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto request = people_search();
		request.timeout = milliseconds(50);
		auto stream = finish(f.ioc, f.pool->search_stream(request));
		REQUIRE(stream.has_value());// not retried: next() reports the timeout
		auto e = finish(f.ioc, stream->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == ldap::cond::timeout);
		CHECK(s.accepted() == 1);
		drive_until(f.ioc, [&s] { return s.log(0).received.size() == 3; });
		REQUIRE(s.log(0).received.size() == 3);
		CHECK(std::holds_alternative<ldap::abandon_request>(s.log(0).received[2].op));
	}
	SECTION("search_stream(): the client destroyed while its stream is open")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
		  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John") }) } });// then nothing
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());
		f.pool.reset();// closes the stream's connection
		auto entries = finish(f.ioc, drain_stream(*stream));
		REQUIRE_FALSE(entries.has_value());
		CHECK(entries.error().code == ldap::cond::connection_lost);
		*stream = ldap::search_stream{};// returns its lease to a closed pool
		CHECK(s.accepted() == 1);
	}
	SECTION("acquire() fails: its error, not retried")
	{
		pool_fixture f;
		const auto down = f.refused_url();
		// An acquire_timeout above Winsock's retries of a refused SYN (about
		// a second before WSAECONNREFUSED; Linux refuses at once).
		f.make({ .servers = { down },
		  .acquire_timeout = milliseconds(10'000),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) },
		  .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::busy_or_unavailable);// connection refused
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("acquire " + text(down)));
		CHECK(retries(f.obs) == 1);
	}
	SECTION("stopped by the stop token")
	{
		pool_fixture f;
		auto &s =
		  f.server({ { answer({ bind_resp(1) }), step{}, step{} }, found_after_bind() });// never answers the search
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		std::stop_source stop;
		outcome<ldap::result<ldap::search_stream>> a;
		spawn(f.ioc, stop.get_token(), f.pool->search_stream(people_search()), a);
		drive_until(f.ioc, [&s] { return s.accepted() == 1 && s.log(0).received.size() == 2; });
		stop.request_stop();
		drive_until(f.ioc, [&a] { return a.done(); });
		REQUIRE_FALSE(a.get().has_value());
		CHECK(a.get().error().code == ldap::cond::canceled);
		drive_until(f.ioc, [&s] { return s.log(0).received.size() == 3; });
		REQUIRE(s.log(0).received.size() == 3);// the search was abandoned
		CHECK(std::holds_alternative<ldap::abandon_request>(s.log(0).received[2].op));
		auto mine = f.acquire_exclusive();// the lease came back
		REQUIRE(mine.has_value());
		CHECK(s.accepted() == 1);
	}
}

// ---------------------------------------------------------------- referrals

namespace {

// `srv`'s URL with `dn`, as a referral names it.
auto ref_to(const ldap_server &srv, std::string_view dn) -> std::pmr::string
{
	return std::pmr::string(text(srv.url()) + "/" + std::string(dn));
}

// The allow-list entry for `srv` (its port is not the default one).
auto domain_of(const ldap_server &srv) -> std::string
{
	return "127.0.0.1:" + std::to_string(srv.url().port_or_default());
}

auto search_referral(std::int32_t id, const std::pmr::string &uri) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_done{ ldap::ldap_result{ 10, "", "", { uri } } } };
}

auto compare_referral(std::int32_t id, const std::pmr::string &uri) -> ldap::message
{
	return ldap::message{ id, ldap::compare_response{ ldap::ldap_result{ 10, "", "", { uri } } } };
}

constexpr std::string_view b_dn = "uid=jdoe,ou=b,dc=example,dc=org";

}// namespace

TEST_CASE("client: referrals are not chased by default", "[net][client][referral]")
{
	pool_fixture f;
	auto &b = f.server({});
	auto &a = f.server({ { answer({ bind_resp(1) }),
	  answer({ search_referral(2, ref_to(b, "ou=b,dc=example,dc=org")) }),
	  answer({ entry_msg(3, "uid=jdoe,ou=people,dc=example,dc=org", "John"),
		ref_msg(3, { ref_to(b, "ou=b,dc=example,dc=org") }),
		done_msg(3) }),
	  answer({ entry_msg(4, "uid=jdoe,ou=people,dc=example,dc=org", "John"),
		ref_msg(4, { ref_to(b, "ou=b,dc=example,dc=org") }),
		done_msg(4) }) } });
	// An authorizer alone does not turn chasing on.
	f.make({ .servers = { a.url() },
	  .setup = admin_setup(),
	  .observer = &f.obs,
	  .referrals = { .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });

	auto referral = finish(f.ioc, f.pool->search(people_search()));
	REQUIRE_FALSE(referral.has_value());
	CHECK(referral.error().code == ldap::errc::referral);
	REQUIRE(referral.error().referrals.size() == 1);

	auto refs = finish(f.ioc, f.pool->search(people_search()));
	REQUIRE(refs.has_value());
	CHECK(refs->entries.size() == 1);
	CHECK(refs->references == ldap::string_list{ ref_to(b, "ou=b,dc=example,dc=org") });

	CHECK_FALSE(refs->is_complete());
	CHECK(refs->unlisted == 0);
	CHECK(refs->referrals.empty());

	// A request's follow_referrals turns chasing on for it: the reference
	// is counted (follow_references is off), not followed.
	auto request = people_search();
	request.follow_referrals = true;
	auto chased = finish(f.ioc, f.pool->search(request));
	REQUIRE(chased.has_value());
	CHECK(chased->entries.size() == 1);
	CHECK_FALSE(chased->is_complete());
	CHECK(chased->unlisted == 1);
	CHECK(chased->referrals.empty());

	CHECK(b.accepted() == 0);
	CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(a.url()) + " ok" });
}

TEST_CASE("client: following referral results", "[net][client][referral]")
{
	SECTION("search(): the referred server is bound with the client's setup")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ entry_msg(2, b_dn, "B"), done_msg(2) }) } });
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ search_referral(2, uri) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .observer = &f.obs,
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		REQUIRE(r->entries.size() == 1);
		CHECK(r->entries.front() == expected_entry(b_dn, "B"));
		REQUIRE(b.accepted() == 1);
		REQUIRE(b.log(0).received.size() == 2);
		const auto &bind = std::get<ldap::bind_request>(b.log(0).received[0].op);
		CHECK(bind.name == "cn=admin,dc=example,dc=org");
		const auto &sent = std::get<ldap::search_request>(b.log(0).received[1].op);
		CHECK(sent.base_object == "ou=b,dc=example,dc=org");
		CHECK(sent.filter == people_search().filter);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(a.url()) + " ok",
				"referral " + text(a.url()) + " " + std::string(uri) + " followed" });
		CHECK(f.pool->connections() == 1);// the referred connection is not pooled
	}
	SECTION("search(): the request's follow_referrals turns it off")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server(
		  { { answer({ bind_resp(1) }), answer({ search_referral(2, ref_to(b, "ou=b,dc=example,dc=org")) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto request = people_search();
		request.follow_referrals = false;
		auto r = finish(f.ioc, f.pool->search(request));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK(b.accepted() == 0);
	}
	SECTION("compare(): the request's follow_referrals turns it on")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ compare_msg(1, 6) }) } });
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer({ compare_referral(2, ref_to(b, "uid=jdoe,ou=b,dc=example,dc=org")) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .authorize = [](const ldap::referral_hop &) { return ldap::referral_binding::anonymous; } } });
		auto request = jdoe_compare();
		request.follow_referrals = true;
		auto r = finish(f.ioc, f.pool->compare(request));
		REQUIRE(r.has_value());
		CHECK(r->value);
		REQUIRE(r->referrals.size() == 1);
		CHECK(r->referrals[0].outcome == ldap::referral_outcome::followed);
		CHECK(b.accepted() == 1);
	}
	SECTION("compare(): the request's follow_referrals turns it off")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer({ compare_referral(2, ref_to(b, "uid=jdoe,ou=b,dc=example,dc=org")) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true,
			.authorize = [](const ldap::referral_hop &) { return ldap::referral_binding::anonymous; } } });
		auto request = jdoe_compare();
		request.follow_referrals = false;
		auto r = finish(f.ioc, f.pool->compare(request));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK(b.accepted() == 0);
	}
	SECTION("compare(): anonymous")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ compare_msg(1, 6) }) } });
		const auto uri = ref_to(b, "uid=jdoe,ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_referral(2, uri) }) } });
		std::vector<ldap::referral_hop> asked;
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true, .authorize = [&asked](const ldap::referral_hop &hop) {
							asked.push_back(hop);
							return ldap::referral_binding::anonymous;
						} } });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		REQUIRE(r->referrals.size() == 1);
		CHECK(r->referrals[0].outcome == ldap::referral_outcome::followed);
		REQUIRE(asked.size() == 1);
		CHECK(text(asked[0].origin) == text(a.url()));
		CHECK(asked[0].depth == 1);
		CHECK(asked[0].target.host() == "127.0.0.1");
		REQUIRE(b.log(0).received.size() == 1);// no bind
		CHECK(std::get<ldap::compare_request>(b.log(0).received[0].op).entry == "uid=jdoe,ou=b,dc=example,dc=org");
	}
	SECTION("refused: the referral is the error")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_referral(2, ref_to(b, "ou=b")) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .observer = &f.obs,
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ "example.org" }) } });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("1 skipped_policy"));
		CHECK(b.accepted() == 0);
		CHECK(f.obs.events.back()
			  == "referral " + text(a.url()) + " " + std::string(ref_to(b, "ou=b")) + " skipped_policy");
	}
	SECTION("without an authorizer nothing is contacted")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_referral(2, ref_to(b, "ou=b")) }) } });
		f.make({ .servers = { a.url() }, .setup = admin_setup(), .referrals = { .follow_referrals = true } });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK(b.accepted() == 0);
	}
	SECTION("ldapi:// is never asked about")
	{
		pool_fixture f;
		const std::pmr::string local = "ldapi://%2Fvar%2Frun%2Fslapd.sock/ou=b";
		auto &a = f.server({ { answer({ bind_resp(1) }), answer({ compare_referral(2, local) }) } });
		std::size_t asked = 0;
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true, .authorize = [&asked](const ldap::referral_hop &) {
							++asked;
							return ldap::referral_binding::same_setup;
						} } });
		auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK(asked == 0);
	}
}

TEST_CASE("client: following continuation references", "[net][client][referral]")
{
	SECTION("followed: every entry, complete")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ entry_msg(2, b_dn, "B"), done_msg(2) }) } });
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer(
			{ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"), ref_msg(2, { uri }), done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_references = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->is_complete());
		REQUIRE(r->entries.size() == 2);
		CHECK(r->entries[1] == expected_entry(b_dn, "B"));
		REQUIRE(r->referrals.size() == 1);
		CHECK(r->referrals[0].kind == ldap::reference_kind::continuation_reference);
	}
	SECTION("references only: a referral result stays an error")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server(
		  { { answer({ bind_resp(1) }), answer({ search_referral(2, ref_to(b, "ou=b,dc=example,dc=org")) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_references = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK(b.accepted() == 0);
	}
	SECTION("referral results only: a reference is counted, not followed")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"),
			ref_msg(2, { ref_to(b, "ou=b,dc=example,dc=org"), ref_to(b, "ou=c,dc=example,dc=org") }),
			done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 1);
		CHECK_FALSE(r->is_complete());
		CHECK(r->unlisted == 2);
		CHECK(r->references
			  == ldap::string_list{ ref_to(b, "ou=b,dc=example,dc=org"), ref_to(b, "ou=c,dc=example,dc=org") });
		CHECK(b.accepted() == 0);
	}
	SECTION("the request's follow_references false: the reference is not followed")
	{
		pool_fixture f;
		auto &b = f.server({});
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer(
			{ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"), ref_msg(2, { uri }), done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_references = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto request = people_search();
		request.follow_references = false;
		auto r = finish(f.ioc, f.pool->search(request));
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 1);
		CHECK_FALSE(r->is_complete());
		CHECK(r->references == ldap::string_list{ uri });
		CHECK(b.accepted() == 0);
	}
	SECTION("the request's follow_references true: followed though the client's is off")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ entry_msg(2, b_dn, "B"), done_msg(2) }) } });
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer(
			{ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"), ref_msg(2, { uri }), done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto request = people_search();
		request.follow_references = true;
		auto r = finish(f.ioc, f.pool->search(request));
		REQUIRE(r.has_value());
		CHECK(r->is_complete());
		REQUIRE(r->entries.size() == 2);
		CHECK(r->entries[1] == expected_entry(b_dn, "B"));
		CHECK(b.accepted() == 1);
	}
	SECTION("referral results only: search() returns the references, as without chasing")
	{
		pool_fixture f;
		auto &b = f.server({});
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer(
			{ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"), ref_msg(2, { uri }), done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 1);
		CHECK(r->references == ldap::string_list{ uri });
		CHECK(r->is_success());
		CHECK(b.accepted() == 0);
	}
	SECTION("a followed reference's limit code is search()'s result code")
	{
		pool_fixture f;
		auto &b = f.server(
		  { { answer({ bind_resp(1) }), answer({ entry_msg(2, b_dn, "B"), done_msg(2, 4, "", "size limit") }) } });
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer(
			{ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"), ref_msg(2, { uri }), done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_references = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 2);
		CHECK(r->references.empty());
		CHECK_FALSE(r->is_success());
		CHECK(r->result_code == 4);
		CHECK(r->diagnostic_message == "size limit");
	}
	SECTION("not followed: search() still returns the entries it got")
	{
		pool_fixture f;
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"),
			ref_msg(2, { "ldap://elsewhere.example/ou=b,dc=example,dc=org" }),
			done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .observer = &f.obs,
		  .referrals = { .follow_references = true, .authorize = ldap::same_setup_for_domains({ "example.org" }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 1);
		CHECK(r->references == ldap::string_list{ "ldap://elsewhere.example/ou=b,dc=example,dc=org" });
		CHECK(f.obs.events.back()
			  == "referral " + text(a.url()) + " ldap://elsewhere.example/ou=b,dc=example,dc=org skipped_policy");
	}
	SECTION("the limits apply")
	{
		pool_fixture f;
		auto &b = f.server({});
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer({ ref_msg(2, { ref_to(b, "ou=b,dc=example,dc=org") }), done_msg(2) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_references = true,
			.authorize = ldap::same_setup_for_domains({ domain_of(b) }),
			.limits = { .max_hops = 0 } } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->is_complete());
		REQUIRE(r->referrals.size() == 1);
		CHECK(r->referrals[0].outcome == ldap::referral_outcome::limit_reached);
		CHECK(b.accepted() == 0);
	}
}

TEST_CASE("client: referrals and the read forwarders' retry", "[net][client][referral][retry]")
{
	SECTION("the pooled connection's own failure is retried, the chase with it")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ entry_msg(2, b_dn, "B"), done_msg(2) }) } });
		const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
		auto &a = f.server({ lost_after_bind(), { answer({ bind_resp(1) }), answer({ search_referral(2, uri) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE(r.has_value());
		REQUIRE(r->entries.size() == 1);
		CHECK(r->entries.front() == expected_entry(b_dn, "B"));
		CHECK(a.accepted() == 2);
	}
	SECTION("a referred server's failure is not")
	{
		pool_fixture f;
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ done_msg(2, 51, "", "too many operations") }) } });
		auto &a = f.server(
		  { { answer({ bind_resp(1) }), answer({ search_referral(2, ref_to(b, "ou=b,dc=example,dc=org")) }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .observer = &f.obs,
		  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::busy_or_unavailable);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("1 failed"));
		CHECK(a.accepted() == 1);
		CHECK(b.accepted() == 1);
		CHECK(f.pool->connections() == 1);// not retired: it answered
		CHECK(f.obs.events.front() == "connect " + text(a.url()) + " ok");
		CHECK(std::ranges::none_of(f.obs.events, [](const std::string &e) { return e.starts_with("disconnect"); }));
	}
}

TEST_CASE("client: an authorizer's exception propagates", "[net][client][referral]")
{
	pool_fixture f;
	auto &b = f.server({});
	auto &a = f.server({ { answer({ bind_resp(1) }),
	  answer({ search_referral(2, ref_to(b, "ou=b,dc=example,dc=org")) }),
	  answer({ compare_msg(3, 6) }) } });
	f.make({ .servers = { a.url() },
	  .setup = admin_setup(),
	  .referrals = { .follow_referrals = true, .authorize = [](const ldap::referral_hop &) -> ldap::referral_binding {
						throw std::runtime_error("authorizer");
					} } });
	CHECK_THROWS_AS(finish(f.ioc, f.pool->search(people_search())), std::runtime_error);
	CHECK(b.accepted() == 0);
	// The lease came back, its connection still pooled and usable.
	auto r = finish(f.ioc, f.pool->compare(jdoe_compare()));
	REQUIRE(r.has_value());
	CHECK(r->value);
	CHECK(a.accepted() == 1);
	CHECK(f.pool->connections() == 1);
}

TEST_CASE("client: one referred connection per server and binding", "[net][client][referral]")
{
	pool_fixture f;
	// Two connections to b: anonymous for ou=b (searched twice), then bound
	// for ou=c.
	auto &b = f.server({ { answer({ entry_msg(1, b_dn, "B"), done_msg(1) }),
						   answer({ entry_msg(2, "uid=jdoe,ou=d,dc=example,dc=org", "D"), done_msg(2) }) },
	  { answer({ bind_resp(1) }), answer({ entry_msg(2, "uid=jdoe,ou=c,dc=example,dc=org", "C"), done_msg(2) }) } });
	auto &a = f.server({ { answer({ bind_resp(1) }),
	  answer({ ref_msg(2, { ref_to(b, "ou=b,dc=example,dc=org") }),
		ref_msg(2, { ref_to(b, "ou=c,dc=example,dc=org") }),
		ref_msg(2, { ref_to(b, "ou=d,dc=example,dc=org") }),
		done_msg(2) }) } });
	f.make({ .servers = { a.url() },
	  .setup = admin_setup(),
	  .referrals = { .follow_references = true, .authorize = [](const ldap::referral_hop &hop) {
						return hop.target.base_dn() == ldap::dn{ "ou=c,dc=example,dc=org" }
								 ? ldap::referral_binding::same_setup
								 : ldap::referral_binding::anonymous;
					} } });
	auto r = finish(f.ioc, f.pool->search(people_search()));
	REQUIRE(r.has_value());
	CHECK(r->is_complete());
	CHECK(r->entries.size() == 3);
	REQUIRE(b.accepted() == 2);
	REQUIRE(b.log(0).received.size() == 2);// anonymous: no bind, both searches
	CHECK(std::holds_alternative<ldap::search_request>(b.log(0).received[0].op));
	CHECK(std::holds_alternative<ldap::search_request>(b.log(0).received[1].op));
	REQUIRE(b.log(1).received.size() == 2);
	CHECK(std::get<ldap::bind_request>(b.log(1).received[0].op).name == "cn=admin,dc=example,dc=org");
}

TEST_CASE("client: close() stops a chase", "[net][client][referral][close]")
{
	pool_fixture f;
	auto &c = f.server({});
	auto &b = f.server({ { step{} } });// reads the bind, never answers
	auto &a = f.server({ { answer({ bind_resp(1) }),
	  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "John"),
		ref_msg(2, { ref_to(b, "ou=b,dc=example,dc=org") }),
		ref_msg(2, { ref_to(c, "ou=c,dc=example,dc=org") }),
		done_msg(2) }) } });
	std::size_t asked = 0;
	bool close_when_asked = false;
	f.make({ .servers = { a.url() },
	  .setup = admin_setup(),
	  .observer = &f.obs,
	  .referrals = {
		.follow_references = true, .authorize = [&f, &asked, &close_when_asked](const ldap::referral_hop &) {
			++asked;
			if (close_when_asked) {
				f.pool->close();
			}
			return ldap::referral_binding::same_setup;
		} } });
	outcome<ldap::result<ldap::search_result>> r;
	SECTION("while a referred server is being set up")
	{
		spawn(f.ioc, f.pool->search(people_search()), r);
		drive_until(f.ioc, [&b] { return b.accepted() == 1 && !b.log(0).received.empty(); });// the bind at b
		f.pool->close();
		drive_until(f.ioc, [&r] { return r.done(); });
	}
	SECTION("from the authorizer: the server it allowed is not contacted")
	{
		close_when_asked = true;
		spawn(f.ioc, f.pool->search(people_search()), r);
		drive_until(f.ioc, [&r] { return r.done(); });
		finish(f.ioc, sleep_for(milliseconds(20)));
		CHECK(b.accepted() == 0);
	}
	REQUIRE_FALSE(r.get().has_value());
	CHECK(r.get().error().code == ldap::client_errc::not_connected);
	CHECK(asked == 1);// not asked about c
	CHECK(c.accepted() == 0);
	CHECK(a.accepted() == 1);// not retried
	CHECK(std::ranges::none_of(f.obs.events, [](const std::string &e) { return e.starts_with("referral"); }));
}

TEST_CASE("client: same_setup_for_domains", "[net][client][referral]")
{
	const auto hop = [](std::string_view target, std::string_view origin) {
		auto t = ldap::url::parse(target);
		auto o = ldap::url::parse(origin);
		REQUIRE(t.has_value());
		REQUIRE(o.has_value());
		return ldap::referral_hop{ .target = *t, .origin = *o };
	};
	const auto authorize = ldap::same_setup_for_domains({ "example.org", "10.0.0.1:1389" });
	const auto same = ldap::referral_binding::same_setup;
	const auto refuse = ldap::referral_binding::refuse;
	CHECK(authorize(hop("ldap://example.org/ou=b", "ldap://a.example.org")) == same);
	CHECK(authorize(hop("ldaps://ldap.eu.example.org/ou=b", "ldap://a.example.org")) == same);
	CHECK(authorize(hop("ldap://badexample.org/ou=b", "ldap://a.example.org")) == refuse);
	CHECK(authorize(hop("ldap://b.example.org:1389/ou=b", "ldap://a.example.org")) == refuse);
	CHECK(authorize(hop("ldap://b.example.org:1389/ou=b", "ldap://a.example.org:1389")) == same);// the origin's port
	CHECK(authorize(hop("ldap://10.0.0.1:1389/ou=b", "ldap://a.example.org")) == same);
	CHECK(authorize(hop("ldap://10.0.0.2/ou=b", "ldap://a.example.org")) == refuse);
	CHECK(ldap::same_setup_for_domains({})(hop("ldap://example.org/ou=b", "ldap://a.example.org")) == refuse);
}

// ---------------------------------------------------------------- the rest of the API

TEST_CASE("client: move assignment, executor() and a moved-from client's reads", "[net][client]")
{
	pool_fixture f;
	auto &s = f.server({ bind_ok() });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
	CHECK(f.pool->executor().get_inner_executor() == f.ioc.get_executor());
	REQUIRE(f.acquire().has_value());// pooled, then returned
	ldap::client other(f.ioc, {});
	other = std::move(*f.pool);// takes the pool and its connection
	CHECK(other.executor().get_inner_executor() == f.ioc.get_executor());
	CHECK(other.connections() == 1);
	CHECK(f.pool->connections() == 0);

	// The moved-from client refuses every read without contacting anything.
	const auto refused = [](const ldap::error &e, std::string_view context) {
		CHECK(e.code == ldap::client_errc::not_connected);
		CHECK(std::string_view(e.context) == std::string(context) + ": client moved from");
	};
	const std::string search = "search ou=people,dc=example,dc=org";
	const std::string compare = "compare uid=jdoe,ou=people,dc=example,dc=org";
	refused(finish(f.ioc, f.pool->search(people_search())).error(), search);
	refused(finish(f.ioc, f.pool->search_stream(people_search())).error(), search);
	refused(finish(f.ioc, f.pool->compare(jdoe_compare())).error(), compare);
	refused(finish(f.ioc, ldap::who_am_i(*f.pool)).error(), "extended operation 1.3.6.1.4.1.4203.1.11.3");
	const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
	const std::string add = "add uid=jdoe,ou=people,dc=example,dc=org";
	const std::string modify = "modify uid=jdoe,ou=people,dc=example,dc=org";
	const std::string modify_dn = "modify DN uid=jdoe,ou=people,dc=example,dc=org";
	refused(finish(f.ioc, f.pool->add({ .entry = jdoe })).error(), add);
	refused(finish(f.ioc, f.pool->modify({ .object = jdoe })).error(), modify);
	refused(finish(f.ioc, f.pool->del({ .entry = jdoe })).error(), "delete uid=jdoe,ou=people,dc=example,dc=org");
	refused(finish(f.ioc, f.pool->modify_dn({ .entry = jdoe, .new_rdn = ldap::rdn{ "uid=j" } })).error(), modify_dn);
	refused(finish(f.ioc, f.pool->acquire()).error(), "acquire");
	f.pool->close();// nothing to close

	// The pool works from its new owner, on the same connection.
	auto l = finish(f.ioc, other.acquire());
	REQUIRE(l.has_value());
	CHECK(s.accepted() == 1);
	// Assigned over, a client is closed first, as by its destructor.
	run_on(f.ioc, other.executor(), [&] { other = ldap::client(f.ioc, {}); });
	CHECK_FALSE((*l)->is_open());
	CHECK(other.connections() == 0);
	CHECK(f.obs.events
		  == std::vector<std::string>{
			"connect " + text(s.url()) + " ok", "disconnect " + text(s.url()) + " client_closed" });
	l->release();
	drive_until(f.ioc, [&s] { return s.session(0).done(); });
	CHECK(s.log(0).received.size() == 1);// the bind only
}

TEST_CASE("client: a read fails as its acquire() does", "[net][client][retry]")
{
	pool_fixture f;
	f.make({ .servers = { f.refused_url() }, .max_connections = 0 });
	const auto unusable = [](const ldap::error &e) {
		CHECK(e.code == std::errc::invalid_argument);
		CHECK(std::string_view(e.context) == "acquire: client_options::max_connections is 0");
	};
	unusable(finish(f.ioc, f.pool->search(people_search())).error());
	unusable(finish(f.ioc, f.pool->search_stream(people_search())).error());
	unusable(finish(f.ioc, f.pool->compare(jdoe_compare())).error());
	unusable(finish(f.ioc, ldap::who_am_i(*f.pool)).error());
	unusable(finish(f.ioc, f.pool->del({ .entry = ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" } })).error());
}

TEST_CASE("client: a shared connection being unbound is not handed out", "[net][client]")
{
	// acquire() during another lease's unbind() opens a new connection.
	pool_fixture f;
	auto &s = f.server({ { answer({ bind_resp(1) }), step{ .read_request = true, .replies = {}, .close_after = true } },
	  found_after_bind() });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = std::nullopt, .observer = &f.obs });
	auto mine = f.acquire();
	REQUIRE(mine.has_value());
	outcome<ldap::result<void>> unbound;
	outcome<ldap::result<ldap::lease>> other;
	spawn(f.ioc, full(*mine).unbind(), unbound);
	REQUIRE((*mine)->is_open());// the UnbindRequest is not written yet
	spawn(f.ioc, f.pool->acquire(), other);
	drive_until(f.ioc, [&] { return unbound.done() && other.done(); });
	REQUIRE(unbound.get().has_value());
	REQUIRE(other.get().has_value());
	auto r = finish(f.ioc, (*other.get())->search(people_search()));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 1);
	CHECK(r->entries.front() == expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "John"));
	CHECK(s.accepted() == 2);
	REQUIRE(s.log(0).received.size() == 2);
	CHECK(std::holds_alternative<ldap::unbind_request>(s.log(0).received[1].op));
	f.release(*mine);
	CHECK(f.pool->connections() == 1);// the new one only
	CHECK(f.obs.events
		  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
			"connect " + text(s.url()) + " ok",
			"disconnect " + text(s.url()) + " closed" });
}

TEST_CASE("client: search_stream() failing before its first message", "[net][client][retry]")
{
	SECTION("not retried when retrying cannot help")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto p = people_search();
		p.time_limit = std::chrono::seconds(-1);
		auto r = finish(f.ioc, f.pool->search_stream(std::move(p)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK(s.accepted() == 1);
		CHECK(f.pool->connections() == 1);// still pooled
		CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(s.url()) + " ok" });
	}
	SECTION("retried on another connection when the idle one was reset by the server")
	{
		pool_fixture f;
		auto &s = f.server({ bind_ok(), found_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = std::nullopt, .observer = &f.obs });
		REQUIRE(f.acquire().has_value());// pooled, then returned
		s.reset(0);// the client cannot tell yet
		auto stream = finish(f.ioc, f.pool->search_stream(people_search()));
		REQUIRE(stream.has_value());
		auto entries = finish(f.ioc, drain_stream(*stream));
		REQUIRE(entries.has_value());
		REQUIRE(entries->size() == 1);
		CHECK(entries->front() == expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "John"));
		CHECK(s.accepted() == 2);
		REQUIRE(s.log(1).received.size() == 2);
		CHECK(std::holds_alternative<ldap::search_request>(s.log(1).received[1].op));
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"disconnect " + text(s.url()) + " closed",
				"connect " + text(s.url()) + " ok" });
	}
}

TEST_CASE("client: an observer overriding only on_connect", "[net][client][observer]")
{
	// The other hooks are client_observer's own no-ops, each run below.
	struct connects_only final : ldap::client_observer
	{
		std::vector<std::string> events{};
		void on_connect(const ldap::url &server, const ldap::result<void> &outcome) override
		{
			events.push_back("connect " + text(server) + (outcome ? " ok" : " failed"));
		}
	};
	pool_fixture f;
	const auto down = f.refused_url();
	auto &b = f.server({ { answer({ bind_resp(1) }), answer({ entry_msg(2, b_dn, "B"), done_msg(2) }) } });
	const auto uri = ref_to(b, "ou=b,dc=example,dc=org");
	auto &a = f.server({ { answer({ bind_resp(1) }), answer({ done_msg(2) }), answer({ search_referral(3, uri) }) } });
	connects_only obs;
	f.make({ .servers = { down, a.url() },
	  .setup = admin_setup(),
	  .idle_check = milliseconds(0),
	  .acquire_timeout = milliseconds(10'000),
	  .backoff = { .initial = milliseconds(60'000), .max = milliseconds(60'000) },
	  .observer = &obs,
	  .referrals = { .follow_referrals = true, .authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
	auto held = f.acquire_exclusive();// the first server refused: on_retry
	REQUIRE(held.has_value());
	CHECK(text(held->server()) == text(a.url()));
	outcome<ldap::result<ldap::lease>> waiting;
	spawn(f.ioc, f.pool->acquire(), waiting);// the only slot leased exclusively: it waits
	f.ioc.poll();
	f.ioc.restart();
	REQUIRE_FALSE(waiting.done());
	held->release();
	drive_until(f.ioc, [&waiting] { return waiting.done(); });
	REQUIRE(waiting.get().has_value());// on_acquire_wait; the idle connection probed (on_probe)
	// The search shares the leased connection and follows the referral
	// (on_referral).
	auto r = finish(f.ioc, f.pool->search(people_search()));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 1);
	CHECK(r->entries.front() == expected_entry(b_dn, "B"));
	f.release(*waiting.get());
	f.close();// on_disconnect
	CHECK(f.pool->connections() == 0);
	CHECK(obs.events
		  == std::vector<std::string>{ "connect " + text(down) + " failed", "connect " + text(a.url()) + " ok" });
	REQUIRE(a.log(0).received.size() == 3);
	CHECK(std::get<ldap::search_request>(a.log(0).received[1].op).base_object.empty());// the probe
	CHECK(b.accepted() == 1);
}

// ---------------------------------------------------------------- write forwarders

namespace {

constexpr std::string_view jdoe_text = "uid=jdoe,ou=people,dc=example,dc=org";

auto jdoe_dn() -> ldap::dn { return ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" }; }

auto jdoe_add() -> ldap::add_params
{
	return { .entry = jdoe_dn(), .attributes = { { "objectClass", { "person" } }, { "cn", { "John" } } } };
}

template<class Response>
auto written(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {}) -> ldap::message
{
	return ldap::message{ id, Response{ ldap::ldap_result{ code, "", diagnostic } } };
}

// connect_small_tcp() as a pooled connection's connector.
auto open_small(corosio::io_context &ioc,
  corosio::endpoint to,
  std::string name,
  ldap::connection_options options,
  std::size_t *send_buffer) -> capy::task<ldap::result<ldap::connection>>
{
	co_return co_await connect_small_tcp(ioc, to, std::move(name), std::move(options), send_buffer);
}

// Opens the pooled connections of `pool` with connect_small_tcp() to
// `server`; `send_buffer` receives their SO_SNDBUF.
void connect_small(const ldap::client &pool, const ldap_server &server, std::size_t *send_buffer)
{
	ldap::detail::set_connector(pool,
	  [to = server.endpoint(), send_buffer](corosio::io_context &ioc,
		const ldap::url &u,
		ldap::connection_options options,
		std::pmr::memory_resource * /*mr*/) {
		  return open_small(ioc, to, std::string(u.to_string()), std::move(options), send_buffer);
	  });
}

}// namespace

TEST_CASE("client: write forwarders run on a shared lease", "[net][client][write]")
{
	pool_fixture f;
	auto &s = f.server({ { answer({ bind_resp(1) }),
	  answer({ written<ldap::add_response>(2) }),
	  answer({ written<ldap::modify_response>(3) }),
	  answer({ written<ldap::del_response>(4) }),
	  answer({ written<ldap::modify_dn_response>(5) }),
	  answer({ ldap::message{ 6, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.5", "answer" } } }),
	  answer({ ldap::message{ 7, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "dn:cn=me" } } }) } });
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
	auto held = f.acquire();// shared with every write below
	REQUIRE(held.has_value());
	const auto added = finish(f.ioc, f.pool->add(jdoe_add()));
	REQUIRE(added.has_value());
	CHECK(added->message_id == 2);
	CHECK(finish(f.ioc, f.pool->modify({ .object = jdoe_dn(), .changes = { ldap::mod::replace("cn", { "Johnny" }) } }))
		.has_value());
	CHECK(finish(f.ioc, f.pool->del({ .entry = jdoe_dn() })).has_value());
	CHECK(finish(f.ioc, f.pool->modify_dn({ .entry = jdoe_dn(), .new_rdn = ldap::rdn{ "uid=j" } })).has_value());
	const auto x = finish(f.ioc, f.pool->extended({ .name = "1.2.3.4", .value = "question" }));
	REQUIRE(x.has_value());
	CHECK(x->name == "1.2.3.5");
	CHECK(x->value == "answer");
	CHECK(finish(f.ioc, ldap::who_am_i(*f.pool)) == "dn:cn=me");
	CHECK(s.accepted() == 1);
	CHECK(f.pool->connections() == 1);
	held->release();

	using op = ldap::modify_operation;
	const auto &got = s.log(0).received;
	REQUIRE(got.size() == 7);
	CHECK(
	  got[1]
	  == ldap::message{ 2, ldap::add_request{ jdoe_text, { { "objectClass", { "person" } }, { "cn", { "John" } } } } });
	CHECK(got[2] == ldap::message{ 3, ldap::modify_request{ jdoe_text, { { op::replace, { "cn", { "Johnny" } } } } } });
	CHECK(got[3] == ldap::message{ 4, ldap::del_request{ jdoe_text } });
	CHECK(got[4] == ldap::message{ 5, ldap::modify_dn_request{ jdoe_text, "uid=j", true, std::nullopt } });
	const auto &question = std::get<ldap::extended_request>(got[5].op);
	CHECK(question.request_name == "1.2.3.4");
	CHECK(question.request_value == "question");
	CHECK(std::get<ldap::extended_request>(got[6].op).request_name == "1.3.6.1.4.1.4203.1.11.3");
	CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(s.url()) + " ok" });
}

TEST_CASE("client: when write forwarders do not retry", "[net][client][write][retry]")
{
	SECTION("a server result code: the error, with its diagnostic")
	{
		pool_fixture f;
		auto &s = f.server(
		  { { answer({ bind_resp(1) }), answer({ written<ldap::add_response>(2, 68, "already there") }) }, bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->add(jdoe_add()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::entry_already_exists);
		CHECK(r.error().diagnostic == "already there");
		CHECK(std::string_view(r.error().context) == "add " + std::string(jdoe_text));
		CHECK(s.accepted() == 1);
		CHECK(f.pool->connections() == 1);// still pooled
		CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(s.url()) + " ok" });
	}
	SECTION("busy")
	{
		pool_fixture f;
		auto &s = f.server(
		  { { answer({ bind_resp(1) }), answer({ written<ldap::del_response>(2, 51, "too busy") }) }, bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->del({ .entry = jdoe_dn() }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::busy);
		CHECK(s.accepted() == 1);
		CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(s.url()) + " ok" });
	}
	SECTION("an extended operation (who_am_i) lost once sent is not retried either")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::who_am_i(*f.pool));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK(s.accepted() == 1);
		REQUIRE(s.log(0).received.size() == 2);
		CHECK(std::holds_alternative<ldap::extended_request>(s.log(0).received[1].op));
	}
	SECTION("the connection is lost once the request was sent: the server saw it once")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), bind_ok() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, f.pool->add(jdoe_add()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK(r.error().code != ldap::client_errc::not_sent);
		CHECK(s.accepted() == 1);
		REQUIRE(s.log(0).received.size() == 2);
		CHECK(std::holds_alternative<ldap::add_request>(s.log(0).received[1].op));
		CHECK(
		  f.obs.events
		  == std::vector<std::string>{ "connect " + text(s.url()) + " ok", "disconnect " + text(s.url()) + " closed" });
		CHECK(f.pool->connections() == 0);
	}
	SECTION("the operation times out")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{}, step{} }, bind_ok() });// never answers
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, f.pool->del({ .entry = jdoe_dn(), .timeout = milliseconds(50) }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(s.accepted() == 1);
	}
	SECTION("a referral result: the error, not chased even when reads chase")
	{
		pool_fixture f;
		auto &b = f.server({ bind_ok() });
		const auto uri = ref_to(b, jdoe_text);
		auto &a = f.server({ { answer({ bind_resp(1) }),
		  answer(
			{ ldap::message{ 2, ldap::modify_response{ ldap::ldap_result{ 10, "", "elsewhere", { uri } } } } }) } });
		f.make({ .servers = { a.url() },
		  .setup = admin_setup(),
		  .observer = &f.obs,
		  .referrals = { .follow_referrals = true,
			.follow_references = true,
			.authorize = ldap::same_setup_for_domains({ domain_of(b) }) } });
		auto r = finish(f.ioc, f.pool->modify({ .object = jdoe_dn() }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::referral);
		CHECK(r.error().referrals == ldap::string_list{ uri });
		CHECK(b.accepted() == 0);
		CHECK(a.accepted() == 1);
		CHECK(f.obs.events == std::vector<std::string>{ "connect " + text(a.url()) + " ok" });
	}
	SECTION("stopped by the stop token")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), step{}, step{} }, bind_ok() });// never answers
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		std::stop_source stop;
		outcome<ldap::result<ldap::response>> d;
		spawn(f.ioc, stop.get_token(), f.pool->del({ .entry = jdoe_dn() }), d);
		drive_until(f.ioc, [&s] { return s.accepted() == 1 && s.log(0).received.size() == 2; });
		stop.request_stop();
		drive_until(f.ioc, [&d] { return d.done(); });
		REQUIRE_FALSE(d.get().has_value());
		CHECK(d.get().error().code == ldap::cond::canceled);
		CHECK(s.accepted() == 1);
	}
}

TEST_CASE("client: a write never sent is retried once on another connection", "[net][client][write][retry]")
{
	pool_fixture f;
	// The first connection reads nothing after the bind.
	auto &s =
	  f.server({ bind_ok(), { answer({ bind_resp(1) }), answer({ written<ldap::add_response>(2) }) }, bind_ok() },
		socket_buffers::small);
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = std::nullopt, .observer = &f.obs });
	std::size_t send_buffer = 0;
	connect_small(*f.pool, s, &send_buffer);
	auto held = f.acquire();
	REQUIRE(held.has_value());
	REQUIRE(send_buffer + s.receive_buffer(0) < oversized_add_value);
	outcome<ldap::result<ldap::response>> big;
	outcome<ldap::result<ldap::response>> queued;
	spawn(f.ioc, (*held)->add(oversized_add()), big);
	spawn(f.ioc, f.pool->add(jdoe_add()), queued);// queued behind `big` on the same connection
	drive_until(f.ioc, [&held] { return (*held)->outstanding() == 2; });
	CHECK_FALSE(big.done());
	full(*held).close();
	drive_until(f.ioc, [&] { return big.done() && queued.done(); });
	REQUIRE_FALSE(big.get().has_value());
	CHECK(big.get().error().code == ldap::client_errc::not_connected);
	REQUIRE(queued.get().has_value());
	CHECK(queued.get()->message_id == 2);
	CHECK(s.accepted() == 2);
	REQUIRE(s.log(1).received.size() == 2);
	CHECK(
	  s.log(1).received[1]
	  == ldap::message{ 2, ldap::add_request{ jdoe_text, { { "objectClass", { "person" } }, { "cn", { "John" } } } } });
	f.release(*held);// the closed connection leaves the pool with its last lease
	CHECK(f.obs.events
		  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
			"connect " + text(s.url()) + " ok",
			"disconnect " + text(s.url()) + " closed" });
	CHECK(f.pool->connections() == 1);
}

TEST_CASE("client: an extended operation never sent is retried once on another connection",
  "[net][client][write][retry]")
{
	pool_fixture f;
	// The first connection reads nothing after the bind.
	auto &s = f.server(
	  { bind_ok(),
		{ answer({ bind_resp(1) }),
		  answer({ ldap::message{ 2, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.5", "answer" } } }) },
		bind_ok() },
	  socket_buffers::small);
	f.make({ .servers = { s.url() }, .setup = admin_setup(), .idle_check = std::nullopt, .observer = &f.obs });
	std::size_t send_buffer = 0;
	connect_small(*f.pool, s, &send_buffer);
	auto held = f.acquire();
	REQUIRE(held.has_value());
	REQUIRE(send_buffer + s.receive_buffer(0) < oversized_add_value);
	outcome<ldap::result<ldap::response>> big;
	outcome<ldap::result<ldap::extended_result>> queued;
	spawn(f.ioc, (*held)->add(oversized_add()), big);
	spawn(f.ioc,
	  f.pool->extended({ .name = "1.2.3.4", .value = "question" }),
	  queued);// queued behind `big` on the same connection
	drive_until(f.ioc, [&held] { return (*held)->outstanding() == 2; });
	CHECK_FALSE(big.done());
	full(*held).close();
	drive_until(f.ioc, [&] { return big.done() && queued.done(); });
	REQUIRE_FALSE(big.get().has_value());
	CHECK(big.get().error().code == ldap::client_errc::not_connected);
	REQUIRE(queued.get().has_value());
	CHECK(queued.get()->value == "answer");
	CHECK(s.accepted() == 2);
	REQUIRE(s.log(1).received.size() == 2);
	CHECK(s.log(1).received[1].id == 2);
	const auto &resent = std::get<ldap::extended_request>(s.log(1).received[1].op);
	CHECK(resent.request_name == "1.2.3.4");
	CHECK(resent.request_value == "question");
	f.release(*held);// the closed connection leaves the pool with its last lease
	CHECK(f.obs.events
		  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
			"connect " + text(s.url()) + " ok",
			"disconnect " + text(s.url()) + " closed" });
	CHECK(f.pool->connections() == 1);
}

namespace {

struct card
{
	std::string cn;
};

}// namespace

template<>
constexpr auto ldap::schema<card> = ldap::describe(ldap::object_class("person"), ldap::field<&card::cn>("cn"));

namespace {

auto root_dse_msg(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_entry{ "", { { "subschemaSubentry", { "cn=Subschema" } } } } };
}

auto subschema_msg(std::int32_t id) -> ldap::message
{
	return ldap::message{ id,
		ldap::search_result_entry{ "cn=Subschema",
		  { { "attributeTypes", { "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )" } },
			{ "objectClasses", { "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )" } } } } };
}

// Answers the setup's bind, the root DSE and the subschema searches, then
// reads the unbind.
auto schema_after_bind() -> std::vector<step>
{
	return { answer({ bind_resp(1) }),
		answer({ root_dse_msg(2), done_msg(2) }),
		answer({ subschema_msg(3), done_msg(3) }),
		step{},
		client_hangs_up() };
}

auto search_base(const ldap::message &received) -> std::string
{
	return std::string(std::string_view(std::get<ldap::search_request>(received.op).base_object));
}

}// namespace

TEST_CASE("client: load_schema runs both searches on one lease", "[net][client][schema]")
{
	SECTION("a two-server pool where each acquire() opens a new connection")
	{
		pool_fixture f;
		// max_lifetime 0: a released connection is not handed out again.
		auto &a = f.server({ schema_after_bind() });
		auto &b = f.server({ { answer({ bind_resp(1) }), answer({ subschema_msg(2), done_msg(2) }) } });
		f.make({ .servers = { a.url(), b.url() }, .setup = admin_setup(), .max_lifetime = milliseconds(0) });
		auto s = finish(f.ioc, ldap::load_schema(*f.pool));
		REQUIRE(s.has_value());
		CHECK(ldap::validate<card>(*s).ok());
		CHECK(a.accepted() == 1);
		CHECK(b.accepted() == 0);
		REQUIRE(a.log(0).received.size() >= 3);
		CHECK(search_base(a.log(0).received[1]).empty());
		CHECK(search_base(a.log(0).received[2]) == "cn=Subschema");
	}
	SECTION("a repository over the client checks the schema the same way")
	{
		pool_fixture f;
		auto &a = f.server({ schema_after_bind(),
		  { answer({ bind_resp(1) }),
			answer({ card_msg(2, "cn=a,ou=people,dc=example,dc=org", "a"), done_msg(2) }),
			step{},
			client_hangs_up() } });
		f.make({ .servers = { a.url() }, .setup = admin_setup(), .max_lifetime = milliseconds(0) });
		ldap::repository cards(*f.pool,
		  ldap::dn{ "ou=people,dc=example,dc=org" },
		  ldap::named_by<&card::cn>,
		  { .schema_check = ldap::schema_check::on_first_use });
		auto r = finish(f.ioc, cards.get("a"));
		REQUIRE(r.has_value());
		REQUIRE(r->has_value());
		CHECK((*r)->cn == "a");
		CHECK(a.accepted() == 2);
		REQUIRE(a.log(0).received.size() >= 3);
		CHECK(search_base(a.log(0).received[2]) == "cn=Subschema");
	}
	SECTION("a lost connection: both searches again on a new lease")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
							   answer({ root_dse_msg(2), done_msg(2) }),
							   step{ .read_request = true, .replies = {}, .close_after = true } },
		  schema_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, ldap::load_schema(*f.pool));
		REQUIRE(r.has_value());
		CHECK(ldap::validate<card>(*r).ok());
		REQUIRE(s.accepted() == 2);
		CHECK(s.log(0).received.size() == 3);
		REQUIRE(s.log(1).received.size() >= 3);
		CHECK(search_base(s.log(1).received[1]).empty());
		CHECK(search_base(s.log(1).received[2]) == "cn=Subschema");
	}
	SECTION("lost twice: the retry's error")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), lost_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::load_schema(*f.pool));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("load schema: "));
		CHECK(s.accepted() == 2);
	}
	SECTION("busy is not retried")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }), answer({ done_msg(2, 51, "", "too many operations") }) },
		  schema_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::load_schema(*f.pool));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::busy);
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("load schema: "));
		CHECK(s.accepted() == 1);
	}
	SECTION("an acquire() failure")
	{
		pool_fixture f;
		f.make({ .servers = { f.refused_url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(50),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto r = finish(f.ioc, ldap::load_schema(*f.pool));
		REQUIRE_FALSE(r.has_value());
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("load schema: acquire "));
	}
}

namespace {

const ldap::dn staff{ "cn=staff,dc=example,dc=org" };

// The entry `staff` with the attribute `name` holding `values`.
auto staff_msg(std::int32_t id, std::string_view name, std::initializer_list<std::string_view> values) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_entry{ "cn=staff,dc=example,dc=org", { { name, values } } } };
}

auto attributes_asked(const ldap::message &received) -> std::string
{
	const auto &attributes = std::get<ldap::search_request>(received.op).attributes;
	REQUIRE(attributes.size() == 1);
	return std::string(attributes[0]);
}

}// namespace

TEST_CASE("client: ad::read_all_values starts over on a new lease after a lost connection",
  "[net][client][ad][range][retry]")
{
	SECTION("the values of the lost lease are dropped")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
							   answer({ staff_msg(2, "member;range=0-1", { "m0", "m1" }), done_msg(2) }),
							   step{ .read_request = true, .replies = {}, .close_after = true } },
		  { answer({ bind_resp(1) }),
			answer({ staff_msg(2, "member;range=0-*", { "m0", "m1", "m2" }), done_msg(2) }),
			step{},
			client_hangs_up() } });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::ad::read_all_values(*f.pool, staff, "member"));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(std::vector<std::string>(r->begin(), r->end()) == std::vector<std::string>{ "m0", "m1", "m2" });
		REQUIRE(s.accepted() == 2);
		REQUIRE(s.log(0).received.size() == 3);
		CHECK(attributes_asked(s.log(0).received[2]) == "member;range=2-*");
		REQUIRE(s.log(1).received.size() >= 2);
		CHECK(attributes_asked(s.log(1).received[1]) == "member");
	}
	SECTION("lost twice: the retry's error")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), lost_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::ad::read_all_values(*f.pool, staff, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("read all values of member "));
		CHECK(s.accepted() == 2);
	}
	SECTION("the retry's acquire() failure is returned as is")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(50),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto r = finish(f.ioc, ldap::ad::read_all_values(*f.pool, staff, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK_FALSE(r.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("acquire "));
		CHECK(s.accepted() == 1);
	}
}

namespace {

const ldap::dn domain_root{ "dc=example,dc=org" };

// One entry `dn` (when not empty), then a SearchResultDone with a DirSync
// response control.
auto dirsync_page(std::int32_t id, std::string_view dn, bool more, std::string_view cookie) -> step
{
	step out;
	if (!dn.empty()) {
		out.replies.push_back(bytes_of(entry_msg(id, dn, "x")));
	}
	ldap::message done = done_msg(id);
	done.controls.push_back(
	  ldap::testing::ad::encode_dirsync_response({ .more_results = more, .cookie_server = std::string(cookie) }));
	out.replies.push_back(bytes_of(done));
	return out;
}

auto dirsync_cookie_sent(const ldap::message &received) -> std::string
{
	REQUIRE(received.controls.size() == 1);
	auto r = ldap::testing::ad::decode_dirsync_request(received.controls[0]);
	REQUIRE(r.has_value());
	return r->cookie;
}

}// namespace

TEST_CASE("client: ad::dirsync starts over from the caller's cookie after a lost connection",
  "[net][client][ad][dirsync][retry]")
{
	const ldap::search_params users{ .base = domain_root, .filter = ldap::filters::attr("objectClass") == "user" };
	SECTION("the entries of the lost lease are dropped")
	{
		pool_fixture f;
		auto &s = f.server({ { answer({ bind_resp(1) }),
							   dirsync_page(2, "cn=a,dc=example,dc=org", true, "c1"),
							   step{ .read_request = true, .replies = {}, .close_after = true } },
		  { answer({ bind_resp(1) }),
			dirsync_page(2, "cn=b,dc=example,dc=org", false, "c9"),
			step{},
			client_hangs_up() } });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::ad::dirsync(*f.pool, users, { .cookie = "c0" }));
		if (!r) {
			FAIL(r.error().message());
		}
		REQUIRE(r->entries.size() == 1);
		CHECK(r->entries[0].dn == "cn=b,dc=example,dc=org");
		CHECK(r->cookie == "c9");
		REQUIRE(s.accepted() == 2);
		REQUIRE(s.log(0).received.size() == 3);
		CHECK(dirsync_cookie_sent(s.log(0).received[1]) == "c0");
		CHECK(dirsync_cookie_sent(s.log(0).received[2]) == "c1");
		REQUIRE(s.log(1).received.size() >= 2);
		CHECK(dirsync_cookie_sent(s.log(1).received[1]) == "c0");
	}
	SECTION("lost twice: the retry's error")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(), lost_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto r = finish(f.ioc, ldap::ad::dirsync(*f.pool, users));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("DirSync dc=example,dc=org"));
		CHECK(s.accepted() == 2);
	}
	SECTION("the retry's acquire() failure is returned as is")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind() });
		f.make({ .servers = { s.url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(50),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto r = finish(f.ioc, ldap::ad::dirsync(*f.pool, users));
		REQUIRE_FALSE(r.has_value());
		CHECK_FALSE(r.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(r.error().context), Catch::Matchers::StartsWith("acquire "));
		CHECK(s.accepted() == 1);
	}
}

TEST_CASE("client: the AD helpers retire the lost connection before the retry", "[net][client][ad][retry]")
{
	pool_fixture f;
	const auto retried = [&f](const ldap::url &u) {
		CHECK(f.obs.events
			  == std::vector<std::string>{
				"connect " + text(u) + " ok", "disconnect " + text(u) + " closed", "connect " + text(u) + " ok" });
		CHECK(f.pool->connections() == 1);
	};
	SECTION("ad::read_all_values")
	{
		auto &s = f.server({ lost_after_bind(),
		  { answer({ bind_resp(1) }),
			answer({ staff_msg(2, "member;range=0-*", { "m0" }), done_msg(2) }),
			step{},
			client_hangs_up() } });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc, ldap::ad::read_all_values(*f.pool, staff, "member"));
		REQUIRE(r.has_value());
		CHECK(s.accepted() == 2);
		retried(s.url());
	}
	SECTION("ad::dirsync")
	{
		auto &s = f.server({ lost_after_bind(),
		  { answer({ bind_resp(1) }),
			dirsync_page(2, "cn=b,dc=example,dc=org", false, "c9"),
			step{},
			client_hangs_up() } });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto r = finish(f.ioc,
		  ldap::ad::dirsync(*f.pool,
			{ .base = domain_root, .filter = ldap::filters::attr("objectClass") == "user" },
			{ .cookie = "c0" }));
		REQUIRE(r.has_value());
		CHECK(s.accepted() == 2);
		retried(s.url());
	}
}

TEST_CASE("client: ad::dirsync honours max_rounds", "[net][client][ad][dirsync]")
{
	const ldap::search_params users{ .base = domain_root, .filter = ldap::filters::attr("objectClass") == "user" };
	pool_fixture f;
	auto &s = f.server({ { answer({ bind_resp(1) }),
	  dirsync_page(2, "cn=a,dc=example,dc=org", true, "c1"),
	  dirsync_page(3, "cn=b,dc=example,dc=org", true, "c2"),
	  step{},
	  client_hangs_up() } });
	f.make({ .servers = { s.url() }, .setup = admin_setup() });
	auto r = finish(f.ioc, ldap::ad::dirsync(*f.pool, users, { .cookie = "c0" }, 2));
	if (!r) {
		FAIL(r.error().message());
	}
	CHECK(r->entries.size() == 2);
	CHECK(r->cookie == "c2");
	CHECK(r->more_results);
	REQUIRE(s.accepted() == 1);
	CHECK(s.log(0).received.size() >= 3);
}

namespace {

auto paged_page(std::int32_t id, std::string_view cookie) -> ldap::message
{
	ldap::message m = done_msg(id);
	m.controls.push_back(*ldap::encode_paged_results({ 0, cookie }));
	return m;
}

// Answers the setup's bind, then two pages of one entry each.
auto two_pages_after_bind() -> std::vector<step>
{
	return { answer({ bind_resp(1) }),
		answer({ entry_msg(2, "uid=a,ou=people,dc=example,dc=org", "A"), paged_page(2, "page2") }),
		answer({ entry_msg(3, "uid=b,ou=people,dc=example,dc=org", "B"), paged_page(3, "") }) };
}

auto drain_pages(ldap::paged_search &s) -> capy::task<ldap::result<std::vector<std::string>>>
{
	std::vector<std::string> dns;
	while (true) {
		auto e = co_await s.next();
		if (!e) {
			co_return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			co_return dns;
		}
		dns.emplace_back((*e)->dn);
	}
}

}// namespace

TEST_CASE("client: search_paged on one lease", "[net][client][paged]")
{
	const std::vector<std::string> both{ "uid=a,ou=people,dc=example,dc=org", "uid=b,ou=people,dc=example,dc=org" };
	SECTION("the pages follow the cookie on the lease it holds")
	{
		pool_fixture f;
		auto &s = f.server({ two_pages_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .acquire_timeout = milliseconds(200) });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE(pages.has_value());
		// The paged_search holds its lease: an exclusive acquire() finds no
		// connection free.
		auto busy = f.acquire_exclusive();
		REQUIRE_FALSE(busy.has_value());
		CHECK(busy.error().code == ldap::cond::timeout);
		auto dns = finish(f.ioc, drain_pages(*pages));
		REQUIRE(dns.has_value());
		CHECK(*dns == both);
		CHECK(pages->pages() == 2);
		REQUIRE(s.log(0).received.size() == 3);
		const auto &second = s.log(0).received[2];
		auto cookie = ldap::find_paged(second.controls);
		REQUIRE(cookie.has_value());
		REQUIRE(cookie->has_value());
		CHECK((*cookie)->cookie == "page2");
		run_on(f.ioc, (**f.acquire()).executor(), [&pages] { *pages = ldap::paged_search{}; });// returns the lease
		auto mine = f.acquire_exclusive();
		REQUIRE(mine.has_value());
		CHECK(s.accepted() == 1);
	}
	SECTION("lost before the first page's first message: requested again on a new lease")
	{
		pool_fixture f;
		auto &s = f.server({ lost_after_bind(),
		  { answer({ bind_resp(1) }),
			answer({ entry_msg(2, "uid=a,ou=people,dc=example,dc=org", "A"), paged_page(2, "") }) } });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE(pages.has_value());
		CHECK(s.accepted() == 2);
		auto dns = finish(f.ioc, drain_pages(*pages));
		REQUIRE(dns.has_value());
		CHECK(*dns == std::vector<std::string>{ "uid=a,ou=people,dc=example,dc=org" });
	}
	SECTION("busy before the first page's first message: set aside, requested again on a new lease")
	{
		pool_fixture f;
		auto &s = f.server({ busy_search(), two_pages_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup(), .observer = &f.obs });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE(pages.has_value());
		auto dns = finish(f.ioc, drain_pages(*pages));
		REQUIRE(dns.has_value());
		CHECK(*dns == both);
		CHECK(s.accepted() == 2);
		REQUIRE(s.log(1).received.size() == 3);// the bind and both pages, on the new connection
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(s.url()) + " ok",
				"disconnect " + text(s.url()) + " busy_or_unavailable",
				"connect " + text(s.url()) + " ok" });
	}
	SECTION("busy on the first server: the first page is requested again on the second")
	{
		pool_fixture f;
		auto &a = f.server({ busy_search(), two_pages_after_bind() });
		auto &b = f.server({ two_pages_after_bind() });
		f.make({ .servers = { a.url(), b.url() }, .setup = admin_setup(), .max_connections = 2, .observer = &f.obs });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE(pages.has_value());
		auto dns = finish(f.ioc, drain_pages(*pages));
		REQUIRE(dns.has_value());
		CHECK(*dns == both);
		CHECK(a.accepted() == 1);
		CHECK(b.accepted() == 1);
		REQUIRE(b.log(0).received.size() == 3);
		CHECK(f.obs.events
			  == std::vector<std::string>{ "connect " + text(a.url()) + " ok",
				"disconnect " + text(a.url()) + " busy_or_unavailable",
				"connect " + text(b.url()) + " ok" });
	}
	SECTION("requested again only once: the retry's error is reported by next()")
	{
		pool_fixture f;
		auto &s = f.server({ busy_search(),
		  { answer({ bind_resp(1) }), answer({ done_msg(2, 52, "", "shutting down") }) },
		  two_pages_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE(pages.has_value());
		auto dns = finish(f.ioc, drain_pages(*pages));
		REQUIRE_FALSE(dns.has_value());
		CHECK(dns.error().code == ldap::errc::unavailable);
		CHECK(s.accepted() == 2);
	}
	SECTION("a page size that is not positive: nothing is opened")
	{
		pool_fixture f;
		auto &s = f.server({ two_pages_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 0));
		REQUIRE_FALSE(pages.has_value());
		CHECK(pages.error().code == ldap::client_errc::encode_error);
		drive(f.ioc);
		CHECK(s.accepted() == 0);
		CHECK(f.pool->connections() == 0);
	}
	SECTION("a max_pages of 0: nothing is opened")
	{
		pool_fixture f;
		auto &s = f.server({ two_pages_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1, 0));
		REQUIRE_FALSE(pages.has_value());
		CHECK(pages.error().code == std::errc::invalid_argument);
		CHECK(pages.error().context == "search ou=people,dc=example,dc=org: max_pages is 0");
		drive(f.ioc);
		CHECK(s.accepted() == 0);
		CHECK(f.pool->connections() == 0);
	}
	SECTION("an acquire() failure")
	{
		pool_fixture f;
		f.make({ .servers = { f.refused_url() },
		  .setup = admin_setup(),
		  .acquire_timeout = milliseconds(50),
		  .backoff = { .initial = milliseconds(3'600'000), .max = milliseconds(3'600'000) } });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE_FALSE(pages.has_value());
		CHECK_THAT(std::string(pages.error().context), ContainsSubstring("acquire "));
	}
	SECTION("it outlives its client")
	{
		pool_fixture f;
		auto &s = f.server({ two_pages_after_bind() });
		f.make({ .servers = { s.url() }, .setup = admin_setup() });
		auto pages = finish(f.ioc, ldap::search_paged(*f.pool, people_search(), 1));
		REQUIRE(pages.has_value());
		f.pool.reset();// closes the leased connection
		auto dns = finish(f.ioc, drain_pages(*pages));
		REQUIRE_FALSE(dns.has_value());
		CHECK(dns.error().code == ldap::cond::connection_lost);
		*pages = ldap::paged_search{};
		drive(f.ioc);
	}
}
