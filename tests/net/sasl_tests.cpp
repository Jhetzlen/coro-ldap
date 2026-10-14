// SASL binds (connection::sasl_bind) against the scripted mock server.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/sasl_scram.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"
#include "scram_test_access.hpp"

#include <boost/corosio/delay.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <semaphore>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;

namespace {

auto sasl_resp(std::int32_t id, std::int32_t code, std::optional<std::string_view> creds = {}) -> ldap::message
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ code }, creds } };
}

auto sasl_req(std::int32_t id, std::string_view mech, std::optional<std::string_view> creds) -> ldap::message
{
	return ldap::message{ id, ldap::bind_request{ 3, "", ldap::sasl_auth{ mech, creds } } };
}

// The anonymous simple bind that aborts a SASL exchange (RFC 4511 section 4.2.1).
auto abort_req(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::bind_request{ 3, "", ldap::simple_auth{ "" } } };
}

// A made-up multi-step mechanism: sends "hello", then answers each
// challenge with "re:<challenge>", and records the final server creds.
class echo_mechanism final : public ldap::sasl_mechanism
{
  public:
	std::vector<std::string> challenges;
	std::optional<std::string> final_creds;
	bool reject_final = false;
	bool fail_start = false;
	std::vector<std::string> hosts;// prepare()'s, then "start" at each start()

	auto name() const noexcept -> std::string_view override { return "X-ECHO"; }
	void prepare(const ldap::sasl_bind_context &context) override { hosts.emplace_back(context.host); }
	auto start() -> ldap::result<std::optional<std::string>> override
	{
		hosts.emplace_back("start");
		challenges.clear();
		if (fail_start) {
			return ldap::fail(ldap::client_errc::decode_error, "no credentials");
		}
		return std::optional<std::string>("hello");
	}
	auto step(std::optional<std::string_view> c) -> ldap::result<std::optional<std::string>> override
	{
		challenges.emplace_back(c.value_or("<none>"));
		if (c == "bad") {
			return ldap::fail(ldap::client_errc::decode_error, "bad challenge");
		}
		return std::optional<std::string>("re:" + std::string(c.value_or("")));
	}
	auto complete(std::optional<std::string_view> c) -> ldap::result<void> override
	{
		if (c) {
			final_creds.emplace(*c);
		}
		if (reject_final) {
			return ldap::fail(ldap::client_errc::decode_error, "server signature mismatch");
		}
		return {};
	}
};

// What the offloaded steps of offload_mechanism share with the test (and
// not with the mechanism, which may be gone while they run): each step
// waits for a permit, on the thread sasl_bind gives it.
struct offload_gate
{
	std::atomic<int> permits{ 0 };
	std::atomic<int> started{ 0 };
	std::atomic<int> finished{ 0 };
	std::mutex mutex;
	std::vector<std::thread::id> threads;

	// Lets the first `n` steps through.
	void allow(int n)
	{
		permits.store(n);
		permits.notify_all();
	}
	void enter()
	{
		const int index = started.fetch_add(1);
		{
			const std::lock_guard lock(mutex);
			threads.push_back(std::this_thread::get_id());
		}
		for (int n = permits.load(); n <= index; n = permits.load()) {
			permits.wait(n);
		}
	}
};

// Lets every step through at the end of a test, before the mock server
// (declared earlier) runs its io_context out of work.
struct open_at_exit
{
	std::shared_ptr<offload_gate> gate;
	explicit open_at_exit(std::shared_ptr<offload_gate> g) noexcept : gate(std::move(g)) {}
	open_at_exit(const open_at_exit &) = delete;
	auto operator=(const open_at_exit &) -> open_at_exit & = delete;
	~open_at_exit() { gate->allow(1000); }
};

// Steps that may block (sasl_mechanism::offload_start, offload_step), as
// GSSAPI's: "hello", then "re:<challenge>", each once the gate allows it.
class offload_mechanism final : public ldap::sasl_mechanism
{
  public:
	std::shared_ptr<offload_gate> gate = std::make_shared<offload_gate>();

	auto name() const noexcept -> std::string_view override { return "X-SLOW"; }
	auto start() -> ldap::result<std::optional<std::string>> override
	{
		return ldap::fail(ldap::client_errc::unexpected_response, "start() called");
	}
	auto step(std::optional<std::string_view>) -> ldap::result<std::optional<std::string>> override
	{
		return ldap::fail(ldap::client_errc::unexpected_response, "step() called");
	}
	auto offload_start() -> ldap::sasl_work override
	{
		return [g = gate]() -> ldap::result<std::optional<std::string>> {
			g->enter();
			g->finished.fetch_add(1);
			return std::optional<std::string>("hello");
		};
	}
	auto offload_step(std::optional<std::string_view> c) -> ldap::sasl_work override
	{
		return [g = gate, c = std::string(c.value_or(""))]() -> ldap::result<std::optional<std::string>> {
			g->enter();
			g->finished.fetch_add(1);
			return std::optional<std::string>("re:" + c);
		};
	}
};

// Runs `ioc` until `done()` holds, at most io_limit: for conditions another
// thread makes true, which drive_until() would sleep through (run_one()
// waits for a handler).
template<class Pred> void poll_until(corosio::io_context &ioc, Pred done)
{
	const auto deadline = std::chrono::steady_clock::now() + io_limit;
	while (!done() && std::chrono::steady_clock::now() < deadline) {
		ioc.run_one_for(std::chrono::milliseconds(1));
		ioc.restart();
	}
}

}// namespace

TEST_CASE("sasl: EXTERNAL in one step", "[net][sasl]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 0) }), answer({ sasl_resp(2, 0) }) });
	ldap::sasl_external plain;
	REQUIRE(m.run(m.conn.sasl_bind(plain)).has_value());
	ldap::sasl_external as_other("dn:uid=jdoe,ou=people,dc=example,dc=org");
	REQUIRE(m.run(m.conn.sasl_bind(as_other)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0] == sasl_req(1, "EXTERNAL", ""));
	CHECK(m.log.received[1] == sasl_req(2, "EXTERNAL", "dn:uid=jdoe,ou=people,dc=example,dc=org"));
}

TEST_CASE("sasl: prepare() gets the URL's host before each start()", "[net][sasl]")
{
	SECTION("a wrapped transport has none")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 0) }) });
		echo_mechanism mech;
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		CHECK(mech.hosts == std::vector<std::string>{ "", "start" });
	}
	SECTION("ldap:// has the URL's")
	{
		tcp_mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 0) }), answer({ sasl_resp(2, 0) }) });
		echo_mechanism mech;
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		CHECK(mech.hosts == std::vector<std::string>{ "127.0.0.1", "start", "127.0.0.1", "start" });
	}
}

TEST_CASE("sasl: failure codes keep the connection usable", "[net][sasl]")
{
	mock_ldap m;
	m.serve(
	  { answer({ ldap::message{ 1, ldap::bind_response{ ldap::ldap_result{ 48, "", "no client certificate" } } } }),
		answer({ sasl_resp(2, 7) }),
		answer({ bind_resp(3) }) });
	ldap::sasl_external mech;
	auto r = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::inappropriate_authentication);
	CHECK(r.error().code == ldap::cond::auth_failed);
	CHECK(r.error().diagnostic == "no client certificate");
	CHECK(r.error().context == "sasl bind EXTERNAL");
	auto unsupported = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(unsupported.has_value());
	CHECK(unsupported.error().code == ldap::errc::auth_method_not_supported);
	CHECK(m.conn.is_open());
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
}

TEST_CASE("sasl: a multi-step exchange with server credentials", "[net][sasl]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "c1") }),
	  answer({ sasl_resp(2, 14) }),
	  answer({ sasl_resp(3, 0, "server-final") }) });
	echo_mechanism mech;
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	CHECK(mech.challenges == std::vector<std::string>{ "c1", "<none>" });
	CHECK(mech.final_creds == "server-final");
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
	CHECK(m.log.received[1] == sasl_req(2, "X-ECHO", "re:c1"));
	CHECK(m.log.received[2] == sasl_req(3, "X-ECHO", "re:"));
}

TEST_CASE("sasl: mechanism errors abort the bind", "[net][sasl]")
{
	SECTION("a challenge the mechanism rejects")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "bad") }), answer({ bind_resp(2) }) });
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind X-ECHO: bad challenge");
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
	SECTION("a server that refuses the abort")
	{
		// Any BindResponse ends the exchange (RFC 4511 section 4.2.1), even a
		// refusal from a server that disallows anonymous binds: the
		// connection stays open (anonymous), the held search then goes out,
		// and the mechanism's error is still the result.
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "bad") }),
		  answer({ bind_resp(3, 48, "anonymous bind disallowed") }),
		  answer({ done_msg(2) }) });
		echo_mechanism mech;
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
		spawn(m.ioc, m.conn.sasl_bind(mech), bind);
		spawn(m.ioc, m.conn.search({}), search);// id 2, held
		drive_until(m.ioc, [&] { return bind.done() && search.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().context == "sasl bind X-ECHO: bad challenge");
		CHECK(search.get().has_value());
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[1] == abort_req(3));
		CHECK(m.log.received[2].id == 2);
	}
	SECTION("a server that answers the abort with saslBindInProgress")
	{
		// Not an answer to a simple bind (RFC 4511 section 4.2.2): the
		// server may still be in the exchange, so the connection is closed
		// and the held search fails with that error, without being sent.
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "bad") }), answer({ bind_resp(3, 14) }), client_hangs_up() });
		echo_mechanism mech;
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
		spawn(m.ioc, m.conn.sasl_bind(mech), bind);
		spawn(m.ioc, m.conn.search({}), search);// id 2, held
		drive_until(m.ioc, [&] { return bind.done() && search.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().context == "sasl bind X-ECHO: bad challenge");
		CHECK_FALSE(m.conn.is_open());
		REQUIRE_FALSE(search.get().has_value());
		CHECK(search.get().error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(search.get().error().context), ContainsSubstring("could not be aborted"));
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(3));
	}
	SECTION("final server credentials the mechanism rejects")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 0, "forged") }) });
		echo_mechanism mech;
		mech.reject_final = true;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("server signature mismatch"));
		// The server considers the connection bound: it is closed, and later
		// operations name the reason.
		CHECK_FALSE(m.conn.is_open());
		auto later = m.run(m.conn.who_am_i());
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::client_errc::not_connected);
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("server signature mismatch"));
	}
	SECTION("EXTERNAL given a challenge")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "what?") }), answer({ bind_resp(2) }) });
		ldap::sasl_external mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK(r.error().context == "sasl bind EXTERNAL: the server sent a challenge to a single-step mechanism");
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
	SECTION("a server that never finishes")
	{
		mock_ldap m;
		std::vector<step> script;
		for (std::int32_t id = 1; id <= 32; ++id) {
			script.push_back(answer({ sasl_resp(id, 14, "more") }));
		}
		script.push_back(answer({ bind_resp(33) }));
		m.serve(script);
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("still in progress after 32 steps"));
		m.check_server();
		REQUIRE(m.log.received.size() == 33);
		CHECK(m.log.received[32] == abort_req(33));
	}
}

// RFC 4511 section 4.2.1: nothing is sent while a BindRequest is outstanding.
// A request started during a SASL exchange waits for all of its steps.
TEST_CASE("sasl: requests started during the exchange wait for its end", "[net][sasl][rfc]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "c1") }),
	  answer({ sasl_resp(3, 14) }),
	  answer({ sasl_resp(4, 0, "server-final") }),
	  answer({ done_msg(2) }) });
	echo_mechanism mech;
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.sasl_bind(mech), bind);
	spawn(m.ioc, m.conn.search({}), search);// id 2, held
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	CHECK(bind.get().has_value());
	CHECK(search.get().has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
	CHECK(m.log.received[1] == sasl_req(3, "X-ECHO", "re:c1"));
	CHECK(m.log.received[2] == sasl_req(4, "X-ECHO", "re:"));
	CHECK(m.log.received[3].id == 2);
}

// RFC 4511 section 4.2.1: a client that gives up on a SASL exchange the
// server still considers in progress aborts it with another bind before
// anything else is sent (coro-ldap-f1e).
TEST_CASE("sasl: a failed exchange is aborted before held requests are sent", "[net][sasl][rfc]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "bad") }), answer({ bind_resp(3) }), answer({ done_msg(2) }) });
	echo_mechanism mech;
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.sasl_bind(mech), bind);
	spawn(m.ioc, m.conn.search({}), search);// id 2, held
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	CHECK(bind.get().error().context == "sasl bind X-ECHO: bad challenge");
	CHECK(search.get().has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
	CHECK(m.log.received[1] == abort_req(3));
	CHECK(m.log.received[2].id == 2);
}

// A bind cannot be abandoned: an abort that gets no answer closes the
// connection, and the requests it held fail without being sent.
TEST_CASE("sasl: an abort without an answer closes the connection", "[net][sasl]")
{
	// The server reads the abort, answers nothing, and then sees the
	// client hang up: nothing else is sent.
	auto check = [](mock_ldap &m,
				   outcome<ldap::result<void>> &bind,
				   outcome<ldap::result<std::pmr::vector<ldap::entry>>> &search) {
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().context == "sasl bind X-ECHO: bad challenge");
		CHECK_FALSE(m.conn.is_open());
		REQUIRE_FALSE(search.get().has_value());
		CHECK(search.get().error().code == ldap::client_errc::not_connected);
		CHECK_THAT(std::string(search.get().error().context), ContainsSubstring("cannot be abandoned"));
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
		CHECK(m.log.received[1] == abort_req(3));
	};
	echo_mechanism mech;
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	SECTION("timeout")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(100) });
		m.serve({ answer({ sasl_resp(1, 14, "bad") }), step{}, client_hangs_up() });
		spawn(m.ioc, m.conn.sasl_bind(mech), bind);
		// id 2, held; its own timeout is longer, so the abort's ends it.
		spawn(m.ioc, m.conn.search({ .timeout = std::chrono::seconds(10) }), search);
		drive_until(m.ioc, [&] { return bind.done() && search.done(); });
		check(m, bind, search);
	}
	SECTION("cancellation")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "bad") }), step{}, client_hangs_up() });
		std::stop_source stop;
		spawn(m.ioc, stop.get_token(), m.conn.sasl_bind(mech), bind);
		spawn(m.ioc, m.conn.search({}), search);// id 2, held
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		CHECK_FALSE(bind.done());
		stop.request_stop();
		drive_until(m.ioc, [&] { return bind.done() && search.done(); });
		check(m, bind, search);
	}
}

// Before the first request the server knows of no exchange: a mechanism
// that fails to start sends nothing, not even an abort.
TEST_CASE("sasl: a mechanism that fails to start sends nothing", "[net][sasl]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });
	echo_mechanism mech;
	mech.fail_start = true;
	auto r = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().context == "sasl bind X-ECHO: no credentials");
	CHECK(m.conn.is_open());
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(std::holds_alternative<ldap::search_request>(m.log.received[0].op));
}

// SCRAM-SHA-256 with the RFC 7677 section 3 test vector (the mechanism's
// own tests are in sasl_scram_tests.cpp).
TEST_CASE("sasl: SCRAM-SHA-256 with the RFC 7677 test vector", "[net][sasl][scram][rfc]")
{
	constexpr std::string_view client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
	constexpr std::string_view server_first =
	  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
	constexpr std::string_view client_final =
	  "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
	constexpr std::string_view server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
	auto mech = ldap::detail::scram_test_access::with_nonce("user", "pencil", "", "rOprNGfwEbeRWgbNEkqO");

	SECTION("server-final-message with the success result")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }), answer({ sasl_resp(2, 0, server_final) }) });
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[0] == sasl_req(1, "SCRAM-SHA-256", client_first));
		CHECK(m.log.received[1] == sasl_req(2, "SCRAM-SHA-256", client_final));
	}
	SECTION("server-final-message as a last challenge")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }),
		  answer({ sasl_resp(2, 14, server_final) }),
		  answer({ sasl_resp(3, 0) }) });
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[2] == sasl_req(3, "SCRAM-SHA-256", ""));
	}
	SECTION("a server that does not prove it knows the password")
	{
		// Each time the server reported success: the connection is closed.
		auto refused = [&](std::vector<step> script, std::string_view why) {
			mock_ldap m;
			m.serve(std::move(script));
			auto r = m.run(m.conn.sasl_bind(mech));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::unexpected_response);
			CHECK(std::string(r.error().context) == "sasl bind SCRAM-SHA-256: " + std::string(why));
			CHECK_FALSE(m.conn.is_open());
			m.check_server();
		};
		refused({ answer({ sasl_resp(1, 14, server_first) }), answer({ sasl_resp(2, 0) }) },
		  "the server reported success without a server signature (v=)");
		refused({ answer({ sasl_resp(1, 14, server_first) }),
				  answer({ sasl_resp(2, 0, "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=") }) },
		  "wrong server signature: the server could not be authenticated");
		refused({ answer({ sasl_resp(1, 0) }) },
		  "the server reported success before the exchange was complete (no server signature)");
	}
	SECTION("a wrong server signature as a challenge")
	{
		// The server has not reported success yet: the bind fails, the
		// connection is not closed.
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }),
		  answer({ sasl_resp(2, 14, "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=") }),
		  answer({ bind_resp(3) }) });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context
			  == "sasl bind SCRAM-SHA-256: wrong server signature: the server could not be authenticated");
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[2] == abort_req(3));
	}
	SECTION("the server refuses the proof")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }),
		  answer({ ldap::message{ 2, ldap::bind_response{ ldap::ldap_result{ 49 }, "e=invalid-proof" } } }) });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK(m.conn.is_open());
	}
	SECTION("a server nonce that does not extend the client's")
	{
		mock_ldap m;
		m.serve(
		  { answer({ sasl_resp(1, 14, "r=forged,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") }), answer({ bind_resp(2) }) });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("does not start with the client nonce"));
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
}

// A mechanism's blocking steps run on a thread of their own (offload_start,
// offload_step), and the bind's timeout and cancellation apply to the wait
// (coro-ldap-2px.1).
TEST_CASE("sasl: offloaded steps run off the I/O thread", "[net][sasl][offload]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "c1") }), answer({ sasl_resp(2, 0) }) });
	offload_mechanism mech;
	mech.gate->allow(2);
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0] == sasl_req(1, "X-SLOW", "hello"));
	CHECK(m.log.received[1] == sasl_req(2, "X-SLOW", "re:c1"));
	CHECK(mech.gate->finished == 2);
	const std::lock_guard lock(mech.gate->mutex);
	REQUIRE(mech.gate->threads.size() == 2);
	for (auto id : mech.gate->threads) {
		CHECK(id != std::this_thread::get_id());
	}
}

TEST_CASE("sasl: a timeout or cancellation gives up on an offloaded step", "[net][sasl][offload][cancel][timeout]")
{
	SECTION("timeout before the first request: nothing sent, the connection stays usable")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(100) });
		m.serve({ answer({ done_msg(1) }) });
		auto mech = std::make_unique<offload_mechanism>();
		const auto gate = mech->gate;
		const open_at_exit opener{ gate };
		auto r = m.run(m.conn.sasl_bind(*mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(r.error().context == "sasl bind X-SLOW: gave up on the mechanism's step (it runs on, on its own thread)");
		CHECK(m.conn.is_open());
		// The step still runs, with what it owns: the mechanism can go.
		mech.reset();
		CHECK(gate->finished == 0);
		CHECK(m.run(m.conn.search({})).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::search_request>(m.log.received[0].op));
		// The io_context keeps running until the step is over (its wakeup
		// then reaches nobody): run() returns after it, never before.
		std::jthread later([gate] {
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			gate->allow(1);
		});
		m.sockets.client.close();
		m.sockets.server.close();
		drive(m.ioc);
		CHECK(gate->finished == 1);
	}
	SECTION("cancellation before the first request: nothing sent, the connection stays usable")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 0) }) });
		offload_mechanism mech;
		const open_at_exit opener{ mech.gate };
		std::stop_source stop;
		outcome<ldap::result<void>> bind;
		spawn(m.ioc, stop.get_token(), m.conn.sasl_bind(mech), bind);
		poll_until(m.ioc, [&] { return mech.gate->started == 1; });
		REQUIRE(mech.gate->started == 1);
		CHECK_FALSE(bind.done());
		stop.request_stop();
		drive_until(m.ioc, [&] { return bind.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code == ldap::cond::canceled);
		CHECK(m.conn.is_open());
		// Another bind with the same mechanism, while the first step runs on.
		mech.gate->allow(2);
		CHECK(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(m.log.received[0] == sasl_req(1, "X-SLOW", "hello"));
	}
	SECTION("timeout during the exchange: aborted as for a mechanism error")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(100) });
		m.serve({ answer({ sasl_resp(1, 14, "c1") }), answer({ bind_resp(2) }) });
		offload_mechanism mech;
		const open_at_exit opener{ mech.gate };
		mech.gate->allow(1);// start, not the step
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[0] == sasl_req(1, "X-SLOW", "hello"));
		CHECK(m.log.received[1] == abort_req(2));
	}
	SECTION("cancellation during the exchange: the abort is cancelled too, the connection closed")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "c1") }), step{}, client_hangs_up() });
		offload_mechanism mech;
		const open_at_exit opener{ mech.gate };
		mech.gate->allow(1);
		std::stop_source stop;
		outcome<ldap::result<void>> bind;
		spawn(m.ioc, stop.get_token(), m.conn.sasl_bind(mech), bind);
		poll_until(m.ioc, [&] { return mech.gate->started == 2; });
		REQUIRE(mech.gate->started == 2);
		stop.request_stop();
		drive_until(m.ioc, [&] { return bind.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code == ldap::cond::canceled);
		CHECK_FALSE(m.conn.is_open());
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
}

// The io_context's destructor joins the thread of a step still running, so
// nothing of it outlives the scheduler it wakes and releases its work on
// (coro-ldap-2px.1.1: a detached thread could still be in the scheduler's
// stop() when the io_context was destroyed).
TEST_CASE("sasl: destroying the io_context waits for an offloaded step", "[net][sasl][offload]")
{
	// The step is let through only once the scope has checked it is still
	// blocked (armed), shortly before the io_context is destroyed. If the
	// scope exits early (a failed REQUIRE), the opener lets it through after
	// 2 s anyway, so the io_context's destructor waits for it, not forever.
	const auto gate = std::make_shared<offload_gate>();
	std::binary_semaphore armed{ 0 };
	const std::jthread opener([gate, &armed] {
		(void)armed.try_acquire_for(std::chrono::seconds(2));
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		gate->allow(1);
	});
	{
		corosio::io_context ioc;
		socket_pair sockets{ ioc };
		ldap::connection conn(ioc,
		  ldap::net::transport::wrap(socket_ref{ &sockets.client }, "mock"),
		  { .operation_timeout = std::chrono::milliseconds(100) });
		offload_mechanism mech;
		mech.gate = gate;
		auto r = finish(ioc, conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(gate->started == 1);
		conn.close();
		sockets.client.close();
		sockets.server.close();
		ioc.poll();// what is ready, not the step: it still holds work
		CHECK(gate->finished == 0);
		armed.release();
	}
	CHECK(gate->finished == 1);
}

// The thread of an offloaded step posts to the io_context from outside, so
// it needs Corosio's locking_mode::safe: under unsafe the step fails before
// anything is sent, as Corosio's resolver does (coro-ldap-2px.1.3).
TEST_CASE("sasl: an offloaded step needs locking_mode::safe", "[net][sasl][offload]")
{
	mock_ldap m(corosio::io_context_options{ .locking = corosio::locking_mode::unsafe });
	m.serve({ answer({ done_msg(1) }) });
	offload_mechanism mech;
	mech.gate->allow(2);
	auto r = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == std::errc::operation_not_supported);
	CHECK_THAT(std::string(r.error().context), ContainsSubstring("locking_mode::safe"));
	CHECK(mech.gate->started == 0);
	CHECK(m.conn.is_open());
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(std::holds_alternative<ldap::search_request>(m.log.received[0].op));
}

// A high iteration count runs PBKDF2 on a thread of its own, so the
// io_context goes on meanwhile: a 1 ms timer ticks between the server's
// first message and the client's final one (inline, PBKDF2 would block the
// event loop for that whole time, ~0.1 s here). coro-ldap-zzz.
TEST_CASE("sasl: SCRAM-SHA-256 runs a costly PBKDF2 off the I/O thread", "[net][sasl][scram][offload]")
{
	constexpr std::string_view server_first = "r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=300000";
	// The expected client-final-message, from step() on the calling thread.
	auto direct = ldap::detail::scram_test_access::with_nonce("user", "pencil", "", "fixednonce");
	REQUIRE(direct.start().has_value());
	auto expected = direct.step(server_first);
	REQUIRE(expected.has_value());
	REQUIRE(expected->has_value());

	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, server_first) }), answer({ sasl_resp(2, 49) }) });
	auto mech = ldap::detail::scram_test_access::with_nonce("user", "pencil", "", "fixednonce");
	outcome<ldap::result<void>> bind;
	spawn(m.ioc, m.conn.sasl_bind(mech), bind);
	int ticks = 0;// while the server waits for the client-final-message
	auto ticker = [](const server_log &log, const outcome<ldap::result<void>> &b, int &n) -> capy::task<void> {
		while (!b.done()) {
			(void)co_await corosio::delay(1ms);
			if (log.received.size() == 1) {
				++n;
			}
		}
	};
	outcome<void> ticked;
	spawn(m.ioc, ticker(m.log, bind, ticks), ticked);
	drive_until(m.ioc, [&] { return bind.done() && ticked.done(); });
	REQUIRE(bind.done());
	REQUIRE_FALSE(bind.get().has_value());
	CHECK(bind.get().error().code == ldap::errc::invalid_credentials);
	CHECK(ticks >= 5);
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == sasl_req(2, "SCRAM-SHA-256", **expected));
}

// Under locking_mode::unsafe, where an offloaded step cannot run, SCRAM
// runs PBKDF2 inline whatever the count.
TEST_CASE("sasl: SCRAM-SHA-256 under locking_mode::unsafe", "[net][sasl][scram][offload]")
{
	constexpr std::string_view server_first =
	  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
	constexpr std::string_view server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
	mock_ldap m(corosio::io_context_options{ .locking = corosio::locking_mode::unsafe });
	m.serve({ answer({ sasl_resp(1, 14, server_first) }), answer({ sasl_resp(2, 0, server_final) }) });
	auto mech = ldap::detail::scram_test_access::with_nonce(
	  "user", "pencil", ldap::sasl_scram_options{ .offload_above_iterations = 0 }, "rOprNGfwEbeRWgbNEkqO");
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
}

// With offloading allowed, the same exchange goes through the offloaded
// step, and a rebind with the same salt and count uses the cache.
TEST_CASE("sasl: SCRAM-SHA-256 offloaded, then cached", "[net][sasl][scram][offload]")
{
	constexpr std::string_view client_final =
	  "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
	constexpr std::string_view server_first =
	  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
	constexpr std::string_view server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, server_first) }),
	  answer({ sasl_resp(2, 0, server_final) }),
	  answer({ sasl_resp(3, 14, server_first) }),
	  answer({ sasl_resp(4, 0, server_final) }) });
	auto mech = ldap::detail::scram_test_access::with_nonce(
	  "user", "pencil", ldap::sasl_scram_options{ .offload_above_iterations = 0 }, "rOprNGfwEbeRWgbNEkqO");
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	CHECK(ldap::detail::scram_test_access::cached_iterations(mech) == 4096);
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[1] == sasl_req(2, "SCRAM-SHA-256", client_final));
	CHECK(m.log.received[3] == sasl_req(4, "SCRAM-SHA-256", client_final));
}
