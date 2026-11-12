// ldap::sync::client, the blocking pool, against in-process LDAP servers on
// loopback TCP running on their own thread and io_context: scripted ones
// (one script per accepted connection, mock_ldap.hpp's serve_script) and
// server_thread.hpp's, which answers whatever comes.
#include "jhetz/ldap/ad/sync.hpp"
#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/sync_extended_operations.hpp"
#include "jhetz/ldap/sync_repository.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"
#include "server_thread.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <memory_resource>
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

// The operations that change the session for everyone sharing a connection.
template<class C>
concept all_session_operations = requires(C &c, ldap::sasl_mechanism &m) {
	c.simple_bind(ldap::dn{}, std::string{});
	c.sasl_bind(m);
	c.start_tls();
	c.unbind();
	c.close();
};

static_assert(all_session_operations<ldap::sync::connection>);
static_assert(all_session_operations<ldap::sync::lease>);
static_assert(all_session_operations<ldap::sync::exclusive_lease>);

auto pki() -> test_pki &
{
	static test_pki instance("jhetz-ldap sync client test CA");
	return instance;
}

auto server_context() -> corosio::tls_context
{
	static const auto leaf = pki().issue("localhost", "DNS:localhost,IP:127.0.0.1");
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(leaf.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(leaf.key_pem, corosio::tls_file_format::pem));
	return ctx;
}

// Whether threaded_script_server's sessions run over TLS from the start
// (ldaps://).
enum class served { clear, tls };

// Accepts connections one after another and runs the n-th script on the
// n-th, then stops accepting (a later connect is refused). stop() lets the
// sessions finish (the client, gone by then, may have written its last
// request, the UnbindRequest of a detached unbind(), without the server
// having read it yet), ends those still running after session_grace, and
// joins the server's thread: only then may the test read the logs.
class threaded_script_server
{
  public:
	explicit threaded_script_server(std::vector<std::vector<step>> scripts, served how = served::clear)
	  : scripts_(std::move(scripts))
	{
		if (how == served::tls) {
			tls_.emplace(server_context());
		}
		capy::run_async(ioc_.get_executor())(accept_loop());
		thread_ = std::thread([this] { ioc_.run(); });
	}
	threaded_script_server(const threaded_script_server &) = delete;
	auto operator=(const threaded_script_server &) -> threaded_script_server & = delete;
	~threaded_script_server() { stop(); }

	[[nodiscard]] auto url() const -> ldap::url
	{
		return *ldap::url::parse((tls_ ? "ldaps://127.0.0.1:" : "ldap://127.0.0.1:") + std::to_string(port_));
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
			const auto give_up = std::chrono::steady_clock::now() + session_grace;
			while (!std::ranges::all_of(s.sessions_, [](const outcome<void> &o) { return o.done(); })
				   && std::chrono::steady_clock::now() < give_up) {
				(void)co_await corosio::delay(milliseconds(1));
			}
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
	// How long stop() waits for the sessions to end by themselves.
	static constexpr milliseconds session_grace{ 5'000 };

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
			// Counted first: the session may run its whole script before
			// spawn() returns, and the client thread check accepted() then.
			++accepted_;
			spawn(ioc_, session(peer, script, log), sessions_.emplace_back());
		}
		acc_.close();
	}

	auto session(corosio::tcp_socket &peer, std::vector<step> script, server_log &log) -> capy::task<void>
	{
		if (!tls_) {
			co_await serve_script(net::transport::wrap(socket_ref{ &peer }, "server"), std::move(script), log);
			co_return;
		}
		corosio::openssl_stream tls(&peer, *tls_);
		auto [ec] = co_await tls.handshake(corosio::tls_role::server);
		if (ec) {
			log.error = "server handshake: " + ec.message();
			co_return;
		}
		co_await serve_script(net::transport::wrap(socket_ref{ &tls }, "server tls"), std::move(script), log);
	}

	corosio::io_context ioc_{};
	// Keeps run() going until stop(), so that its task runs.
	std::optional<capy::work_guard<corosio::io_context::executor_type>> guard_{ ioc_.get_executor() };
	corosio::tcp_acceptor acc_{ ioc_, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8 };
	std::uint16_t port_ = acc_.local_endpoint().port();
	std::vector<std::vector<step>> scripts_;
	std::optional<corosio::tls_context> tls_{};
	std::deque<corosio::tcp_socket> peers_{};
	std::deque<server_log> logs_{};
	std::deque<outcome<void>> sessions_{};
	std::atomic<std::size_t> accepted_{ 0 };
	std::thread thread_{};
};

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
		REQUIRE(found->entries.size() == 1);
		CHECK(found->entries.front() == expected_entry(jdoe, "John"));
		CHECK(ldap::sync::who_am_i(*l) == "dn:" + std::string(admin));
		CHECK(pool.connections() == 1);
		ldap::sync::lease moved = std::move(*l);
		CHECK_FALSE(static_cast<bool>(*l));
		CHECK(l->server() == ldap::url{});
		CHECK_FALSE(l->is_open());
		auto none = ldap::sync::who_am_i(*l);
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

TEST_CASE("sync: a search ending with a limit code returns its entries", "[net][sync][client]")
{
	SECTION("sync::connection: search and search_paged")
	{
		threaded_script_server srv({ { answer({ entry_msg(1, jdoe, "John"), done_msg(1, 4, "", "size limit") }),
		  answer({ entry_msg(2, jdoe, "John"), done_msg(2, 11, "", "admin limit") }),
		  unbind_read() } });
		{
			auto opened = ldap::sync::connect(srv.url(), { .timeout = std::chrono::seconds(10) });
			REQUIRE(opened.has_value());
			auto &c = *opened;
			auto r = c.search(people_search());
			REQUIRE(r.has_value());
			CHECK(r->result_code == 4);
			CHECK_FALSE(r->is_success());
			CHECK(r->diagnostic_message == "size limit");
			REQUIRE(r->entries.size() == 1);
			CHECK(r->entries.front() == expected_entry(jdoe, "John"));
			auto paged = ldap::sync::search_paged(c, people_search(), 10);
			REQUIRE(paged.has_value());
			CHECK(paged->result_code == 11);
			CHECK(paged->entries.size() == 1);
			CHECK(c.unbind().has_value());
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		CHECK(srv.log(0).received.size() == 3);
	}
	SECTION("sync::client and sync::lease")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }),
		  answer({ entry_msg(2, jdoe, "John"), done_msg(2, 3, "", "time limit") }),
		  answer({ entry_msg(3, jdoe, "John"), done_msg(3, 4) }),
		  unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			auto r = pool.search(people_search());
			REQUIRE(r.has_value());
			CHECK(r->result_code == 3);
			CHECK(r->diagnostic_message == "time limit");
			CHECK(r->entries.size() == 1);
			auto l = pool.acquire();
			REQUIRE(l.has_value());
			auto on_lease = l->search(people_search());
			REQUIRE(on_lease.has_value());
			CHECK(on_lease->result_code == 4);
			CHECK(on_lease->entries.size() == 1);
			CHECK(pool.connections() == 1);// not retried
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		CHECK(srv.accepted() == 1);
		CHECK(srv.log(0).received.size() == 4);
	}
}

TEST_CASE("sync: search_paged on a sync::client and a sync::lease", "[net][sync][client][paged]")
{
	const auto page = [](std::int32_t id, std::string_view cookie) {
		ldap::message m = done_msg(id);
		m.controls.push_back(*ldap::encode_paged_results({ 0, cookie }));
		return m;
	};
	threaded_script_server srv({ { answer({ bind_resp(1) }),
	  answer({ entry_msg(2, jdoe, "John"), page(2, "next") }),
	  answer({ entry_msg(3, "uid=jane,ou=people,dc=example,dc=org", "Jane"), page(3, "") }),
	  answer({ entry_msg(4, jdoe, "John"), page(4, "") }),
	  unbind_read() } });
	{
		ldap::sync::client pool(options_for(srv.url()));
		auto all = ldap::sync::search_paged(pool, people_search(), 1);
		REQUIRE(all.has_value());
		REQUIRE(all->entries.size() == 2);
		CHECK(all->entries[0] == expected_entry(jdoe, "John"));
		CHECK(all->entries[1] == expected_entry("uid=jane,ou=people,dc=example,dc=org", "Jane"));
		CHECK(all->is_success());
		auto l = pool.acquire();
		REQUIRE(l.has_value());
		auto on_lease = ldap::sync::search_paged(*l, people_search(), 1);
		REQUIRE(on_lease.has_value());
		CHECK(on_lease->entries.size() == 1);
		CHECK(pool.connections() == 1);
	}
	srv.stop();
	CHECK_THAT(srv.log(0).error, IsEmpty());
	CHECK(srv.accepted() == 1);
	REQUIRE(srv.log(0).received.size() == 5);
	auto cookie = ldap::find_paged(srv.log(0).received[2].controls);
	REQUIRE(cookie.has_value());
	REQUIRE(cookie->has_value());
	CHECK((*cookie)->cookie == "next");
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
		auto l = pool.acquire_exclusive();
		REQUIRE(l.has_value());
		auto t = ldap::sync::transaction::begin(*l);
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
		REQUIRE(r->entries.size() == 1);
		CHECK(r->entries.front() == expected_entry(jdoe, "John"));
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
		CHECK(r->value);
		CHECK(srv.accepted() == 2);
	}
	SECTION("who_am_i() through extended(): a write forwarder, not retried once sent")
	{
		threaded_script_server srv({ lost_after_bind(), { answer({ bind_resp(1) }), answer({ whoami_msg(2) }) } });
		ldap::sync::client pool(options_for(srv.url()));
		auto r = ldap::sync::who_am_i(pool);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK(srv.accepted() == 1);
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

TEST_CASE("sync client: the write forwarders", "[net][sync][client][write]")
{
	const auto ok = [](std::int32_t id, auto response) { return ldap::message{ id, std::move(response) }; };
	SECTION("each runs on a shared lease")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }),
		  answer({ ok(2, ldap::add_response{ ldap::ldap_result{ 0 } }) }),
		  answer({ ok(3, ldap::modify_response{ ldap::ldap_result{ 0 } }) }),
		  answer({ ok(4, ldap::del_response{ ldap::ldap_result{ 0 } }) }),
		  answer({ ok(5, ldap::modify_dn_response{ ldap::ldap_result{ 0 } }) }),
		  unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			const auto added = pool.add({ .entry = jdoe_dn, .attributes = { { "cn", { "John" } } } });
			REQUIRE(added.has_value());
			CHECK(added->message_id == 2);
			CHECK(pool.modify({ .object = jdoe_dn, .changes = { ldap::mod::replace("cn", { "J" }) } }).has_value());
			CHECK(pool.del({ .entry = jdoe_dn }).has_value());
			CHECK(pool.modify_dn({ .entry = jdoe_dn, .new_rdn = ldap::rdn{ "uid=j" } }).has_value());
			CHECK(pool.connections() == 1);
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		const auto &got = srv.log(0).received;
		REQUIRE(got.size() == 6);
		CHECK(std::holds_alternative<ldap::add_request>(got[1].op));
		CHECK(std::holds_alternative<ldap::modify_request>(got[2].op));
		CHECK(got[3] == ldap::message{ 4, ldap::del_request{ jdoe } });
	}
	SECTION("a server result code, with its diagnostic")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }),
		  answer({ ok(2, ldap::del_response{ ldap::ldap_result{ 32, "", "gone" } }) }) } });
		ldap::sync::client pool(options_for(srv.url()));
		auto r = pool.del({ .entry = jdoe_dn });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::no_such_object);
		CHECK(r.error().diagnostic == "gone");
		CHECK(srv.accepted() == 1);
	}
	SECTION("the connection is lost once the request was sent: not retried")
	{
		threaded_script_server srv({ lost_after_bind(), { answer({ bind_resp(1) }) } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			auto r = pool.add({ .entry = jdoe_dn, .attributes = { { "cn", { "John" } } } });
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::cond::connection_lost);
			CHECK(r.error().code != ldap::client_errc::not_sent);
			CHECK(srv.accepted() == 1);
		}
		srv.stop();
		REQUIRE(srv.log(0).received.size() == 2);
		CHECK(std::holds_alternative<ldap::add_request>(srv.log(0).received[1].op));
	}
}

TEST_CASE("sync client: Active Directory passwords on a lease and on the client", "[net][sync][client][ad]")
{
	const auto modified = [](std::int32_t id) {
		return ldap::message{ id, ldap::modify_response{ ldap::ldap_result{ 0 } } };
	};
	// The unicodePwd modify ad::reset_password (one replace) or
	// ad::change_password (a delete and an add) sends for jdoe.
	const auto unicode_pwd = [](const ldap::message &m) -> std::vector<ldap::modify_operation> {
		const auto *r = std::get_if<ldap::modify_request>(&m.op);
		REQUIRE(r != nullptr);
		CHECK(std::string_view(r->object) == jdoe);
		std::vector<ldap::modify_operation> ops;
		for (const auto &c : r->changes) {
			CHECK(c.modification.type == "unicodePwd");
			ops.push_back(c.operation);
		}
		return ops;
	};
	using op = ldap::modify_operation;
	SECTION("over TLS")
	{
		threaded_script_server srv(
		  { { answer({ bind_resp(1) }), answer({ modified(2) }), answer({ modified(3) }), unbind_read() } },
		  served::tls);
		{
			auto o = options_for(srv.url());
			o.connection.tls.ca_pem = std::pmr::string(pki().ca_pem());
			ldap::sync::client pool(std::move(o));
			auto l = pool.acquire();
			REQUIRE(l.has_value());
			CHECK(l->is_tls());
			CHECK(ldap::ad::reset_password(*l, jdoe_dn, "N3w-S3cret").has_value());
			l->release();
			CHECK(ldap::ad::change_password(pool, jdoe_dn, "0ld-S3cret", "N3w-S3cret").has_value());
			CHECK(pool.connections() == 1);
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		const auto &got = srv.log(0).received;
		REQUIRE(got.size() == 4);
		CHECK(unicode_pwd(got[1]) == std::vector{ op::replace });
		CHECK(unicode_pwd(got[2]) == std::vector{ op::delete_, op::add });
	}
	SECTION("without TLS: refused before sending")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }), unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			auto l = pool.acquire();
			REQUIRE(l.has_value());
			auto on_lease = ldap::ad::reset_password(*l, jdoe_dn, "N3w-S3cret");
			REQUIRE_FALSE(on_lease.has_value());
			CHECK(on_lease.error().code == ldap::client_errc::tls_required);
			l->release();
			auto on_pool = ldap::ad::change_password(pool, jdoe_dn, "0ld-S3cret", "N3w-S3cret");
			REQUIRE_FALSE(on_pool.has_value());
			CHECK(on_pool.error().code == ldap::client_errc::tls_required);
			CHECK(srv.accepted() == 1);
		}
		srv.stop();
		const auto &got = srv.log(0).received;
		REQUIRE(got.size() == 2);
		CHECK(std::holds_alternative<ldap::unbind_request>(got[1].op));
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
		ldap::result<ldap::response> written{};
		ldap::result<std::string> on_lease{};
		ldap::result<ldap::server_schema> schema{};
		std::size_t connections = 0;
	};
	std::promise<from_io_thread> got;
	capy::run_async(pool.executor())(
	  [](ldap::sync::client &p, ldap::sync::lease &l, std::promise<from_io_thread> &out) -> capy::task<void> {
		  from_io_thread r;
		  r.acquired = p.acquire();// blocking, on the I/O thread
		  r.forwarded = ldap::sync::who_am_i(p);
		  r.written = p.del({ .entry = ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" } });
		  r.on_lease = ldap::sync::who_am_i(l);
		  r.schema = ldap::sync::load_schema(p);
		  r.connections = p.connections();
		  out.set_value(std::move(r));
		  co_return;
	  }(pool, *held, got));
	auto r = got.get_future().get();
	REQUIRE_FALSE(r.acquired.has_value());
	REQUIRE_FALSE(r.forwarded.has_value());
	REQUIRE_FALSE(r.written.has_value());
	REQUIRE_FALSE(r.on_lease.has_value());
	for (const ldap::error *e :
	  { &r.acquired.error(), &r.forwarded.error(), &r.written.error(), &r.on_lease.error() }) {
		CHECK(e->code == ldap::client_errc::would_deadlock);
		CHECK(e->context == "sync::client");
	}
	REQUIRE_FALSE(r.schema.has_value());
	CHECK(r.schema.error().code == ldap::client_errc::would_deadlock);
	CHECK(r.schema.error().context == "load schema: sync::client");
	CHECK(r.connections == 1);// read at once on the I/O thread
	// Everything still works from other threads.
	CHECK(ldap::sync::who_am_i(pool) == "dn:cn=me");
	CHECK(ldap::sync::who_am_i(*held) == "dn:cn=me");
	CHECK(ldap::sync::run(pool, [](ldap::client &a) { return ldap::who_am_i(a); }) == "dn:cn=me");
	CHECK(ldap::sync::run(*held, [](ldap::connection &a) { return ldap::who_am_i(a); }) == "dn:cn=me");
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
	const refused_port down;
	ldap::sync::client pool({ .servers = { *ldap::url::parse(down.url()) },
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
	REQUIRE(ldap::sync::who_am_i(pool).has_value());
	std::promise<void> closed;
	capy::run_async(pool.executor())([](ldap::sync::client &p, std::promise<void> &done) -> capy::task<void> {
		p.close();// at once, not would_deadlock
		done.set_value();
		co_return;
	}(pool, closed));
	closed.get_future().wait();
	auto after = ldap::sync::who_am_i(pool);
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
	auto after = ldap::sync::who_am_i(l);
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

TEST_CASE("sync client: a lease released or destroyed on the I/O thread", "[net][sync][client]")
{
	server_thread srv;
	ldap::sync::client pool({ .servers = { srv.url() }, .max_connections = 1 });
	auto held = pool.acquire_exclusive();
	REQUIRE(held.has_value());
	REQUIRE(ldap::sync::who_am_i(*held).has_value());
	std::promise<void> released;
	SECTION("released")
	{
		capy::run_async(pool.executor())(
		  [](ldap::sync::exclusive_lease &l, std::promise<void> &done) -> capy::task<void> {
			  l.release();// not the last owner: returns the connection without waiting
			  done.set_value();
			  co_return;
		  }(*held, released));
		released.get_future().wait();
	}
	SECTION("moved into a coroutine and destroyed there")
	{
		capy::run_async(pool.executor())(
		  [](ldap::sync::exclusive_lease l, std::promise<void> &done) -> capy::task<void> {
			  {
				  auto gone = std::move(l);// its destructor runs here, on the I/O thread
			  }
			  done.set_value();
			  co_return;
		  }(std::move(*held), released));
		released.get_future().wait();
	}
	CHECK_FALSE(static_cast<bool>(*held));
	CHECK(pool.connections() == 1);
	// The only connection is back in the pool: an exclusive lease gets it.
	auto again = pool.acquire_exclusive();
	REQUIRE(again.has_value());
	CHECK(ldap::sync::who_am_i(*again) == "dn:cn=me");
	CHECK(pool.connections() == 1);
}

TEST_CASE("sync client: a transaction outlives its temporary lease and the client", "[net][sync][client][transaction]")
{
	server_thread srv;
	std::optional<ldap::sync::transaction> t;
	{
		ldap::sync::client pool({ .servers = { srv.url() } });
		// The lease is released first; the transaction shares the client's
		// core, so it keeps the I/O thread.
		{
			auto l = pool.acquire();
			REQUIRE(l.has_value());
			auto made = ldap::sync::transaction::begin(*l);
			REQUIRE(made.has_value());
			t.emplace(std::move(*made));
		}
		CHECK(t->is_open());
	}// closes the connection; the transaction keeps the I/O thread
	auto after = t->commit();
	REQUIRE_FALSE(after.has_value());
	t.reset();// the I/O thread's last owner: ends the transaction there, then joins it
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
				const auto ok = [&base](const ldap::result<ldap::search_result> &r) {
					return r && r->entries.size() == 2 && std::string_view(r->entries[1].dn).ends_with(base);
				};
				bool good = false;
				switch (i % 3) {
				case 0:
					good = ok(pool.search({ .base = *ldap::dn::parse(base) }));
					break;
				case 1:
					good = ldap::sync::who_am_i(pool) == "dn:cn=me";
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

TEST_CASE("sync client: chasing referrals", "[net][sync][client][referral]")
{
	threaded_script_server b({ { answer({ bind_resp(1) }), answer({ entry_msg(2, jdoe, "B"), done_msg(2) }) },
	  { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
	const std::pmr::string search_uri(text(b.url()) + "/ou=b,dc=example,dc=org");
	const std::pmr::string compare_uri(text(b.url()) + "/" + std::string(jdoe));
	threaded_script_server a({ { answer({ bind_resp(1) }),
	  answer({ ref_msg(2, { search_uri }), done_msg(2) }),
	  answer({ ldap::message{ 3, ldap::compare_response{ ldap::ldap_result{ 10, "", "", { compare_uri } } } } }),
	  unbind_read() } });
	{
		auto options = options_for(a.url());
		options.referrals = { .follow_referrals = true,
			.follow_references = true,
			.authorize = ldap::same_setup_for_domains({ "127.0.0.1:" + std::to_string(b.url().port_or_default()) }) };
		ldap::sync::client pool(std::move(options));
		auto found = pool.search(people_search());
		REQUIRE(found.has_value());
		CHECK(found->is_complete());
		REQUIRE(found->entries.size() == 1);
		CHECK(found->entries.front() == expected_entry(jdoe, "B"));
		auto same = pool.compare({ .entry = jdoe_dn, .attribute = "cn", .value = "B" });
		REQUIRE(same.has_value());
		CHECK(same->value);
		REQUIRE(same->referrals.size() == 1);
		CHECK(same->referrals[0].outcome == ldap::referral_outcome::followed);
	}
	a.stop();
	b.stop();
	CHECK_THAT(a.log(0).error, IsEmpty());
	CHECK_THAT(b.log(0).error, IsEmpty());
	CHECK_THAT(b.log(1).error, IsEmpty());
	CHECK(b.accepted() == 2);// a connection per chase
}

TEST_CASE("sync client: a compare's follow_referrals overrides the client's", "[net][sync][client][referral]")
{
	threaded_script_server b({ { answer({ bind_resp(1) }), answer({ compare_msg(2, 6) }) } });
	const std::pmr::string compare_uri(text(b.url()) + "/" + std::string(jdoe));
	const auto referral =
	  ldap::message{ 2, ldap::compare_response{ ldap::ldap_result{ 10, "", "", { compare_uri } } } };
	threaded_script_server a({ { answer({ bind_resp(1) }), answer({ referral }), unbind_read() },
	  { answer({ bind_resp(1) }), answer({ referral }), unbind_read() } });
	const auto authorize = ldap::same_setup_for_domains({ "127.0.0.1:" + std::to_string(b.url().port_or_default()) });
	{
		auto options = options_for(a.url());
		options.referrals = { .authorize = authorize };
		ldap::sync::client pool(std::move(options));
		auto chased = pool.compare({ .entry = jdoe_dn, .attribute = "cn", .value = "B", .follow_referrals = true });
		REQUIRE(chased.has_value());
		CHECK(chased->value);
		REQUIRE(chased->referrals.size() == 1);
		CHECK(chased->referrals[0].outcome == ldap::referral_outcome::followed);
	}
	{
		auto options = options_for(a.url());
		options.referrals = { .follow_referrals = true, .authorize = authorize };
		ldap::sync::client pool(std::move(options));
		auto refused = pool.compare({ .entry = jdoe_dn, .attribute = "cn", .value = "B", .follow_referrals = false });
		REQUIRE_FALSE(refused.has_value());
		CHECK(refused.error().code == ldap::errc::referral);
	}
	a.stop();
	b.stop();
	CHECK_THAT(a.log(0).error, IsEmpty());
	CHECK_THAT(a.log(1).error, IsEmpty());
	CHECK_THAT(b.log(0).error, IsEmpty());
	CHECK(b.accepted() == 1);
}

namespace {

struct card
{
	std::string cn;
};

struct badly_typed_card
{
	std::int64_t cn = 0;// cn is a DirectoryString: syntax error
};

}// namespace

template<>
constexpr auto ldap::schema<card> = ldap::describe(ldap::object_class("person"), ldap::field<&card::cn>("cn"));
template<>
constexpr auto ldap::schema<badly_typed_card> =
  ldap::describe(ldap::object_class("person"), ldap::field<&badly_typed_card::cn>("cn"));

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

const ldap::dn cards_base{ "ou=people,dc=example,dc=org" };
constexpr std::string_view card_a = "cn=a,ou=people,dc=example,dc=org";

}// namespace

TEST_CASE("sync load_schema: on a sync::connection and a sync::client", "[net][sync][schema]")
{
	SECTION("sync::connection")
	{
		threaded_script_server srv(
		  { { answer({ root_dse_msg(1), done_msg(1) }), answer({ subschema_msg(2), done_msg(2) }), unbind_read() } });
		{
			auto opened = ldap::sync::connect(srv.url(), { .timeout = std::chrono::seconds(10) });
			REQUIRE(opened.has_value());
			auto &c = *opened;
			auto s = ldap::sync::load_schema(c);
			REQUIRE(s.has_value());
			CHECK(s->attribute_count() == 1);
			CHECK(s->object_class_count() == 1);
			CHECK(ldap::validate<card>(*s).ok());
			CHECK(c.unbind().has_value());
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		REQUIRE(srv.log(0).received.size() == 3);
		CHECK(std::get<ldap::search_request>(srv.log(0).received[1].op).base_object == "cn=Subschema");
	}
	SECTION("sync::client: both searches on one lease of a two-server pool")
	{
		threaded_script_server a({ { answer({ bind_resp(1) }),
		  answer({ root_dse_msg(2), done_msg(2) }),
		  answer({ subschema_msg(3), done_msg(3) }),
		  unbind_read() } });
		threaded_script_server b({ { answer({ bind_resp(1) }), answer({ subschema_msg(2), done_msg(2) }) } });
		{
			auto options = options_for(a.url());
			options.servers.push_back(b.url());
			// A released connection is not handed out again.
			options.max_lifetime = std::chrono::milliseconds(0);
			ldap::sync::client pool(std::move(options));
			auto s = ldap::sync::load_schema(pool);
			REQUIRE(s.has_value());
			CHECK(ldap::validate<card>(*s).ok());
		}
		a.stop();
		b.stop();
		CHECK_THAT(a.log(0).error, IsEmpty());
		REQUIRE(a.log(0).received.size() == 4);
		CHECK(std::get<ldap::search_request>(a.log(0).received[2].op).base_object == "cn=Subschema");
		CHECK(b.accepted() == 0);
	}
	SECTION("sync::client: a failing root DSE read")
	{
		threaded_script_server srv(
		  { { answer({ bind_resp(1) }), answer({ done_msg(2, 50, "", "no access") }), unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			auto s = ldap::sync::load_schema(pool);
			REQUIRE_FALSE(s.has_value());
			CHECK(s.error().code == ldap::errc::insufficient_access_rights);
			CHECK_THAT(std::string(s.error().context), Catch::Matchers::StartsWith("load schema: "));
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
	}
}

TEST_CASE("sync repository: schema_check::on_first_use", "[net][sync][repository][schema]")
{
	SECTION("checked once, then every operation runs")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }),
		  answer({ root_dse_msg(2), done_msg(2) }),
		  answer({ subschema_msg(3), done_msg(3) }),
		  answer({ card_msg(4, card_a, "a"), done_msg(4) }),
		  answer({ card_msg(5, card_a, "a"), done_msg(5) }),
		  unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			ldap::sync::repository cards(
			  pool, cards_base, ldap::named_by<&card::cn>, { .schema_check = ldap::schema_check::on_first_use });
			for (int i = 0; i < 2; ++i) {
				auto r = cards.get("a");
				REQUIRE(r.has_value());
				REQUIRE(r->has_value());
				CHECK((*r)->cn == "a");
			}
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		CHECK(srv.log(0).received.size() == 6);
	}
	SECTION("a mismatch fails every operation, loaded once")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }),
		  answer({ root_dse_msg(2), done_msg(2) }),
		  answer({ subschema_msg(3), done_msg(3) }),
		  unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			ldap::sync::repository cards(pool,
			  cards_base,
			  ldap::named_by<&badly_typed_card::cn>,
			  { .schema_check = ldap::schema_check::on_first_use });
			for (int i = 0; i < 2; ++i) {
				auto r = cards.add(badly_typed_card{ .cn = 7 });
				REQUIRE_FALSE(r.has_value());
				CHECK(r.error().code == ldap::client_errc::schema_mismatch);
				CHECK_THAT(
				  std::string(r.error().context), Catch::Matchers::ContainsSubstring("error: attribute cn: syntax"));
			}
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		CHECK(srv.log(0).received.size() == 4);
	}
	SECTION("a schema that does not load is tried again")
	{
		threaded_script_server srv({ { answer({ bind_resp(1) }),
		  answer({ done_msg(2, 50, "", "no access") }),
		  answer({ root_dse_msg(3), done_msg(3) }),
		  answer({ subschema_msg(4), done_msg(4) }),
		  answer({ ldap::message{ 5, ldap::del_response{ ldap::ldap_result{ 0 } } } }),
		  unbind_read() } });
		{
			ldap::sync::client pool(options_for(srv.url()));
			ldap::sync::repository cards(
			  pool, cards_base, ldap::named_by<&card::cn>, { .schema_check = ldap::schema_check::on_first_use });
			auto first = cards.remove("a");
			REQUIRE_FALSE(first.has_value());
			CHECK(first.error().code == ldap::errc::insufficient_access_rights);
			CHECK_THAT(std::string(first.error().context), Catch::Matchers::StartsWith("load schema: "));
			CHECK(cards.remove("a").has_value());
		}
		srv.stop();
		CHECK_THAT(srv.log(0).error, IsEmpty());
		REQUIRE(srv.log(0).received.size() == 6);
		CHECK(std::holds_alternative<ldap::del_request>(srv.log(0).received[4].op));
	}
}
