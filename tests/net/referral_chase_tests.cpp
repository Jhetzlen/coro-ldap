// chase_search and chase_compare (referral_chase.hpp) against several
// scripted in-process servers on one io_context (mock_ldap.hpp's
// serve_script over socket pairs), with a test connector that maps a URL's
// host to one of them.
#include "jhetz/ldap/referral_chase.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <boost/corosio/delay.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using ldap::errc;
using ldap::reference_kind;
using ldap::referral_outcome;

namespace {

template<class Response>
auto result_msg(std::int32_t id, std::int32_t code = 0, std::string_view diagnostic = {}) -> ldap::message
{
	return ldap::message{ id, Response{ ldap::ldap_result{ code, "", diagnostic } } };
}

auto referral_compare(std::int32_t id, std::initializer_list<std::string_view> uris) -> ldap::message
{
	return ldap::message{ id, ldap::compare_response{ ldap::ldap_result{ 10, "", "", uris } } };
}

// One scripted server and the connection to it.
struct server
{
	socket_pair sockets;
	ldap::connection conn;
	server_log log{};
	outcome<void> done{};
	bool serving = false;

	server(corosio::io_context &ioc, std::string_view name)
	  : sockets(ioc), conn(ioc, net::transport::wrap(socket_ref{ &sockets.client }, name))
	{
		log.hang_up = [this] { sockets.server.close(); };
	}
	server(const server &) = delete;
	auto operator=(const server &) -> server & = delete;
	~server()
	{
		sockets.client.close();
		sockets.server.close();
	}

	auto server_end() -> net::transport { return net::transport::wrap(socket_ref{ &sockets.server }, "server"); }

	// The search requests it received.
	auto searches() const -> std::vector<ldap::search_request>
	{
		std::vector<ldap::search_request> out;
		for (const auto &m : log.received) {
			if (const auto *s = std::get_if<ldap::search_request>(&m.op)) {
				out.push_back(*s);
			}
		}
		return out;
	}
};

// The origin ("ldap://a.example") and the referral targets, keyed by host.
struct world
{
	corosio::io_context ioc{};
	std::map<std::string, std::unique_ptr<server>, std::less<>> servers{};
	server &origin;
	// Every connector call: host and depth.
	std::vector<std::pair<std::string, std::size_t>> asked{};
	// Hosts the connector refuses (returns null for).
	std::vector<std::string> refused{};
	// Hosts the connector fails for.
	std::vector<std::string> unreachable{};
	// Hosts the connector works on until it is cancelled.
	std::vector<std::string> hanging{};
	// Runs at each connector call.
	std::function<void()> on_ask{};

	world() : origin(add("a.example", "ldap://a.example")) {}
	world(const world &) = delete;
	auto operator=(const world &) -> world & = delete;
	~world()
	{
		// Wake whatever still waits, so no coroutine is left suspended.
		for (auto &[host, s] : servers) {
			s->sockets.client.close();
			s->sockets.server.close();
		}
		drive(ioc);
	}

	auto add(const std::string &host, std::string_view name = "mock") -> server &
	{
		auto [it, inserted] = servers.emplace(host, std::make_unique<server>(ioc, name));
		REQUIRE(inserted);
		return *it->second;
	}

	// `host`'s server runs `script`.
	void serve(std::string_view host, std::vector<step> script)
	{
		auto &s = *servers.find(host)->second;
		s.serving = true;
		spawn(ioc, serve_script(s.server_end(), std::move(script), s.log), s.done);
	}

	auto lookup(std::string host, std::size_t depth) -> capy::task<ldap::result<ldap::connection *>>
	{
		asked.emplace_back(host, depth);
		if (on_ask) {
			on_ask();
		}
		if (std::ranges::find(hanging, host) != hanging.end()) {
			auto [ec] = co_await corosio::delay(std::chrono::minutes(1));
			co_return ldap::fail(ec ? ec : make_error_code(std::errc::timed_out), "hanging " + host);
		}
		if (std::ranges::find(unreachable, host) != unreachable.end()) {
			co_return ldap::fail(make_error_code(std::errc::connection_refused), "connect " + host);
		}
		const auto it = servers.find(host);
		if (it == servers.end() || std::ranges::find(refused, host) != refused.end()) {
			co_return nullptr;
		}
		co_return &it->second->conn;
	}

	auto connector() -> ldap::referral_connector
	{
		return [this](const ldap::url &u, std::size_t depth) { return lookup(std::string(u.host()), depth); };
	}

	template<class T> auto run(capy::task<T> t) -> T { return finish(ioc, std::move(t)); }

	// Every server given a script ran it to its end without errors.
	void check_servers()
	{
		for (auto &[host, s] : servers) {
			if (!s->serving) {
				continue;
			}
			INFO(host);
			drive_until(ioc, [&s] { return s->done.done(); });
			CHECK(s->log.error.empty());
			CHECK(s->done.done());
		}
	}
};

auto search() -> ldap::search_params
{
	return {
		.base = ldap::dn{ "dc=example,dc=org" },
		.filter = ldap::filters::attr("uid") == "jdoe",
		.attributes = { "cn" },
	};
}

auto dns(const ldap::chased_search &r) -> std::vector<std::string>
{
	std::vector<std::string> out;
	for (const auto &e : r.entries) {
		out.emplace_back(e.dn);
	}
	return out;
}

auto outcomes(const std::vector<ldap::referral_attempt> &attempts) -> std::vector<referral_outcome>
{
	std::vector<referral_outcome> out;
	out.reserve(attempts.size());
	for (const auto &a : attempts) {
		out.push_back(a.outcome);
	}
	return out;
}

}// namespace

TEST_CASE("chase_search: continuation references are followed", "[net][referral]")
{
	world w;
	w.add("b.example");
	w.add("c.example");
	w.serve("a.example",
	  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
		ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
		ref_msg(1, { "ldap://c.example/ou=c,dc=example,dc=org??one?(uid=other)" }),
		done_msg(1) }) });
	w.serve("b.example", { answer({ entry_msg(1, "uid=jdoe,ou=b,dc=example,dc=org", "B"), done_msg(1) }) });
	w.serve("c.example", { answer({ entry_msg(1, "uid=other,ou=c,dc=example,dc=org", "C"), done_msg(1) }) });

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
	REQUIRE(r.has_value());
	CHECK(r->complete);
	CHECK(dns(*r)
		  == std::vector<std::string>{
			"uid=jdoe,ou=a,dc=example,dc=org", "uid=jdoe,ou=b,dc=example,dc=org", "uid=other,ou=c,dc=example,dc=org" });
	REQUIRE(r->referrals.size() == 2);
	CHECK(r->referrals[0].uri == "ldap://b.example/ou=b,dc=example,dc=org");
	CHECK(r->referrals[0].kind == reference_kind::continuation_reference);
	CHECK(r->referrals[0].depth == 1);
	CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::followed, referral_outcome::followed });
	CHECK(w.asked == std::vector<std::pair<std::string, std::size_t>>{ { "b.example", 1 }, { "c.example", 1 } });
	w.check_servers();

	// The requests sent there: the URL's DN, scope and filter, else the
	// original's; the original's attributes.
	const auto b = w.servers["b.example"]->searches();
	REQUIRE(b.size() == 1);
	CHECK(b[0].base_object == "ou=b,dc=example,dc=org");
	CHECK(b[0].scope == ldap::search_scope::whole_subtree);
	CHECK(b[0].filter == search().filter);
	CHECK(b[0].attributes == ldap::string_list{ "cn" });
	const auto c = w.servers["c.example"]->searches();
	REQUIRE(c.size() == 1);
	CHECK(c[0].scope == ldap::search_scope::single_level);
	CHECK(c[0].filter == (ldap::filters::attr("uid") == "other"));
}

TEST_CASE("chase_search: nested references, one hop deeper each", "[net][referral]")
{
	world w;
	w.add("b.example");
	w.add("c.example");
	w.serve("a.example", { answer({ ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }), done_msg(1) }) });
	w.serve("b.example",
	  { answer({ entry_msg(1, "uid=jdoe,ou=b,dc=example,dc=org", "B"),
		ref_msg(1, { "ldap://c.example/ou=c,ou=b,dc=example,dc=org" }),
		done_msg(1) }) });

	SECTION("followed")
	{
		w.serve("c.example", { answer({ entry_msg(1, "uid=jdoe,ou=c,ou=b,dc=example,dc=org", "C"), done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE(r.has_value());
		CHECK(r->complete);
		CHECK(dns(*r)
			  == std::vector<std::string>{ "uid=jdoe,ou=b,dc=example,dc=org", "uid=jdoe,ou=c,ou=b,dc=example,dc=org" });
		CHECK(w.asked == std::vector<std::pair<std::string, std::size_t>>{ { "b.example", 1 }, { "c.example", 2 } });
		REQUIRE(r->referrals.size() == 2);
		CHECK(r->referrals[1].depth == 2);
	}
	SECTION("over max_hops: partial")
	{
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_hops = 1 }));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->complete);
		CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=b,dc=example,dc=org" });
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::followed, referral_outcome::limit_reached });
		CHECK(w.asked.size() == 1);
	}
	SECTION("over max_targets: partial, the rest counted, not examined")
	{
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_targets = 1 }));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->complete);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::followed });
		CHECK(r->unlisted == 1);
		CHECK(w.asked.size() == 1);
	}
	w.check_servers();
}

TEST_CASE("chase_search: many references cost little once the limits are reached", "[net][referral]")
{
	world w;
	constexpr int references = 1000;
	step s;
	for (const auto *bad : { "https://x.example/", "not a url", "ldap://x.example" }) {
		s.replies.push_back(bytes_of(ref_msg(1, { bad })));
	}
	for (int i = 0; i < references; ++i) {
		s.replies.push_back(bytes_of(ref_msg(1, { "ldap://no.example/ou=n" + std::pmr::string(std::to_string(i)) })));
	}
	s.replies.push_back(bytes_of(done_msg(1)));
	w.serve("a.example", { std::move(s) });
	w.refused = { "no.example" };

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_targets = 2, .max_attempts = 4 }));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	// Three unparseable and one skipped listed; the second skipped one
	// counted over max_attempts, the other references once max_targets
	// was reached.
	CHECK(outcomes(r->referrals)
		  == std::vector{ referral_outcome::unparseable,
			referral_outcome::unparseable,
			referral_outcome::unparseable,
			referral_outcome::skipped_policy });
	CHECK(r->unlisted == 1 + (references - 2));
	CHECK(w.asked.size() == 2);
	w.check_servers();
}

TEST_CASE("chase_search: over max_hops, one entry per reference, nothing parsed", "[net][referral]")
{
	world w;
	w.serve("a.example",
	  { answer({ ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org", "ldap://c.example/ou=c,dc=example,dc=org" }),
		ref_msg(1, { "not a url", "ldap://c.example/ou=c,dc=example,dc=org" }),
		done_msg(1) }) });
	auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_hops = 0 }));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	REQUIRE(r->referrals.size() == 2);
	CHECK(r->referrals[0].uri == "ldap://b.example/ou=b,dc=example,dc=org");
	CHECK(r->referrals[0].outcome == referral_outcome::limit_reached);
	// Not unparseable: over max_hops the URI is not parsed.
	CHECK(r->referrals[1].uri == "not a url");
	CHECK(r->referrals[1].outcome == referral_outcome::limit_reached);
	CHECK(w.asked.empty());
	w.check_servers();
}

TEST_CASE("chase_search: max_hops 0 follows nothing", "[net][referral]")
{
	world w;
	w.add("b.example");
	w.serve("a.example",
	  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
		ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
		done_msg(1) }) });
	auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_hops = 0 }));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=a,dc=example,dc=org" });
	CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::limit_reached });
	CHECK(w.asked.empty());
	w.check_servers();
}

TEST_CASE("chase_search: a reference's URIs are alternatives", "[net][referral]")
{
	world w;
	w.add("skip.example");
	w.add("b.example");
	w.add("unused.example");
	w.serve("a.example",
	  { answer({ ref_msg(1,
				   { "https://b.example/",
					 "ldap://b.example/ou=b,dc=example,dc=org???\?!x-unknown",
					 "ldap://down.example/ou=b,dc=example,dc=org",
					 "ldap://skip.example/ou=b,dc=example,dc=org",
					 "ldap://b.example/ou=b,dc=example,dc=org",
					 "ldap://unused.example/ou=b,dc=example,dc=org" }),
		done_msg(1) }) });
	w.serve("b.example", { answer({ entry_msg(1, "uid=jdoe,ou=b,dc=example,dc=org", "B"), done_msg(1) }) });
	w.refused = { "skip.example" };
	w.unreachable = { "down.example" };

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
	REQUIRE(r.has_value());
	CHECK(r->complete);
	CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=b,dc=example,dc=org" });
	CHECK(outcomes(r->referrals)
		  == std::vector{ referral_outcome::unparseable,
			referral_outcome::unparseable,
			referral_outcome::failed,
			referral_outcome::skipped_policy,
			referral_outcome::followed });
	REQUIRE(r->referrals[1].failure);
	CHECK(r->referrals[1].failure->code == ldap::client_errc::invalid_url);
	REQUIRE(r->referrals[2].failure);
	CHECK(r->referrals[2].failure->code == std::errc::connection_refused);
	// The critical extension is refused before the connector is asked.
	CHECK(w.asked
		  == std::vector<std::pair<std::string, std::size_t>>{
			{ "down.example", 1 }, { "skip.example", 1 }, { "b.example", 1 } });
	w.check_servers();
}

TEST_CASE("chase_search: references that cannot be followed leave the search partial", "[net][referral]")
{
	world w;
	w.add("b.example");
	w.add("c.example");
	w.serve("a.example",
	  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
		ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
		ref_msg(1, { "ldap://c.example/ou=c,dc=example,dc=org" }),
		ref_msg(1, { "ldap://c.example" }),// no DN: cannot be followed
		done_msg(1) }) });
	w.serve("b.example", { answer({ done_msg(1, 32, "", "no such object") }) });
	w.refused = { "c.example" };

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=a,dc=example,dc=org" });
	CHECK(outcomes(r->referrals)
		  == std::vector{ referral_outcome::failed, referral_outcome::skipped_policy, referral_outcome::unparseable });
	REQUIRE(r->referrals[0].failure);
	CHECK(r->referrals[0].failure->code == errc::no_such_object);
	w.check_servers();
}

TEST_CASE("chase_search: without a connector nothing is followed", "[net][referral]")
{
	world w;
	w.serve("a.example",
	  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
		ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
		done_msg(1) }) });
	auto r = w.run(ldap::chase_search(w.origin.conn, search(), ldap::referral_connector{}));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::skipped_policy });
	w.check_servers();
}

TEST_CASE("chase_search: loops are not followed", "[net][referral]")
{
	world w;
	w.add("b.example");

	SECTION("a reference back to the origin with the same search")
	{
		// The same server (host case and default port aside), DN (by
		// distinguishedNameMatch), scope and filter as the origin's request.
		w.serve("a.example",
		  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
			ref_msg(1, { "ldap://A.Example:389/DC=Example,DC=Org??sub?(uid=jdoe)" }),
			done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE(r.has_value());
		CHECK(r->complete);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::skipped_loop });
		CHECK(w.asked.empty());
	}
	SECTION("between two servers")
	{
		w.serve("a.example", { answer({ ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }), done_msg(1) }) });
		w.serve("b.example",
		  { answer({ entry_msg(1, "uid=jdoe,ou=b,dc=example,dc=org", "B"),
			ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
			done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE(r.has_value());
		CHECK(r->complete);
		CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=b,dc=example,dc=org" });
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::followed, referral_outcome::skipped_loop });
		CHECK(w.asked.size() == 1);
	}
	w.check_servers();
}

TEST_CASE("chase_search: a loop is recognized before max_targets, not over max_hops", "[net][referral]")
{
	world w;
	// The origin's own search, as a reference back to it.
	const std::pmr::string loop = "ldap://a.example/dc=example,dc=org??sub?(uid=jdoe)";

	SECTION("max_targets reached within the reference")
	{
		w.serve("a.example",
		  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
			ref_msg(1, { "ldap://down.example/ou=d,dc=example,dc=org", loop }),
			done_msg(1) }) });
		w.unreachable = { "down.example" };
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_targets = 1 }));
		REQUIRE(r.has_value());
		CHECK(r->complete);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::failed, referral_outcome::skipped_loop });
	}
	SECTION("over max_hops: not parsed, so not known to be a loop")
	{
		w.serve("a.example", { answer({ ref_msg(1, { loop }), done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_hops = 0 }));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->complete);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::limit_reached });
	}
	w.check_servers();
}

TEST_CASE("chase_search: referral results", "[net][referral]")
{
	world w;
	w.add("b.example");
	w.add("c.example");

	SECTION("followed, with the target's references")
	{
		w.serve(
		  "a.example", { answer({ done_msg(1, 10, "", "", { "ldap://b.example/ou=people,dc=example,dc=org" }) }) });
		w.serve("b.example",
		  { answer({ entry_msg(1, "uid=jdoe,ou=people,dc=example,dc=org", "B"),
			ref_msg(1, { "ldap://c.example/ou=c,ou=people,dc=example,dc=org" }),
			done_msg(1) }) });
		w.serve(
		  "c.example", { answer({ entry_msg(1, "uid=jdoe,ou=c,ou=people,dc=example,dc=org", "C"), done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE(r.has_value());
		CHECK(r->complete);
		CHECK(dns(*r)
			  == std::vector<std::string>{
				"uid=jdoe,ou=people,dc=example,dc=org", "uid=jdoe,ou=c,ou=people,dc=example,dc=org" });
		REQUIRE(r->referrals.size() == 2);
		CHECK(r->referrals[0].kind == reference_kind::referral);
		CHECK(r->referrals[1].kind == reference_kind::continuation_reference);
		CHECK(r->referrals[1].depth == 2);
		CHECK(w.servers["b.example"]->searches().at(0).base_object == "ou=people,dc=example,dc=org");
	}
	SECTION("a referral from the target is chased one hop deeper")
	{
		w.serve(
		  "a.example", { answer({ done_msg(1, 10, "", "", { "ldap://b.example/ou=people,dc=example,dc=org" }) }) });
		w.serve("b.example", { answer({ done_msg(1, 10, "", "", { "ldap://c.example" }) }) });
		w.serve("c.example", { answer({ entry_msg(1, "uid=jdoe,ou=people,dc=example,dc=org", "C"), done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE(r.has_value());
		CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=people,dc=example,dc=org" });
		CHECK(w.asked == std::vector<std::pair<std::string, std::size_t>>{ { "b.example", 1 }, { "c.example", 2 } });
		// No DN in the second URL: the DN of the request that got it.
		CHECK(w.servers["c.example"]->searches().at(0).base_object == "ou=people,dc=example,dc=org");
	}
	SECTION("an alternative after a failed one")
	{
		w.serve("a.example",
		  { answer({ done_msg(1,
			10,
			"",
			"",
			{ "ldap://b.example/ou=people,dc=example,dc=org", "ldap://c.example/ou=people,dc=example,dc=org" }) }) });
		w.serve("b.example", { answer({ done_msg(1, 51, "", "busy") }) });
		w.serve("c.example", { answer({ entry_msg(1, "uid=jdoe,ou=people,dc=example,dc=org", "C"), done_msg(1) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE(r.has_value());
		CHECK(r->complete);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::failed, referral_outcome::followed });
	}
	SECTION("none followed: the last failure")
	{
		w.serve("a.example",
		  { answer({ done_msg(1,
			10,
			"",
			"",
			{ "ldap://b.example/ou=people,dc=example,dc=org", "ldap://c.example/ou=people,dc=example,dc=org" }) }) });
		w.serve("b.example", { answer({ done_msg(1, 32, "", "no such object") }) });
		w.refused = { "c.example" };
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::no_such_object);
		// The attempts are counted in the context.
		CHECK(r.error().context.starts_with("referral chase (URIs: 1 skipped_policy, 1 failed)"));
	}
	SECTION("none followed and none failed: the referral")
	{
		w.serve(
		  "a.example", { answer({ done_msg(1, 10, "", "", { "ldap://c.example/ou=people,dc=example,dc=org" }) }) });
		w.refused = { "c.example" };
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::referral);
		CHECK(r.error().referrals.size() == 1);
	}
	SECTION("a loop back to the origin: the target's referral")
	{
		w.serve("a.example", { answer({ done_msg(1, 10, "", "", { "ldap://b.example" }) }) });
		w.serve("b.example", { answer({ done_msg(1, 10, "", "", { "ldap://a.example" }) }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::referral);
		CHECK(r.error().referrals == std::pmr::vector<std::pmr::string>{ "ldap://a.example" });
		CHECK(w.asked.size() == 1);
	}
	SECTION("other errors are returned as they are")
	{
		w.serve("a.example", { answer({ done_msg(1, 50, "", "denied") }) });
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::insufficient_access_rights);
		CHECK(w.asked.empty());
	}
	w.check_servers();
}

TEST_CASE("chase_compare: referral results", "[net][referral]")
{
	world w;
	w.add("b.example");
	const ldap::compare_params request{
		.entry = ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" }, .attribute = "mail", .value = "jdoe@example.org"
	};

	SECTION("answered by the origin")
	{
		w.serve("a.example", { answer({ result_msg<ldap::compare_response>(1, 6) }) });
		auto r = w.run(ldap::chase_compare(w.origin.conn, request, w.connector()));
		REQUIRE(r.has_value());
		CHECK(r->value);
		CHECK(r->referrals.empty());
	}
	SECTION("followed")
	{
		w.serve(
		  "a.example", { answer({ referral_compare(1, { "ldap://b.example/uid=jdoe,ou=moved,dc=example,dc=org" }) }) });
		w.serve("b.example", { answer({ result_msg<ldap::compare_response>(1, 5) }) });
		auto r = w.run(ldap::chase_compare(w.origin.conn, request, w.connector()));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->value);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::followed });
		REQUIRE(w.servers["b.example"]->log.received.size() == 1);
		const auto &sent = std::get<ldap::compare_request>(w.servers["b.example"]->log.received[0].op);
		CHECK(sent.entry == "uid=jdoe,ou=moved,dc=example,dc=org");
		CHECK(sent.ava.attribute_desc == "mail");
		CHECK(sent.ava.assertion_value == "jdoe@example.org");
	}
	SECTION("skipped: the referral")
	{
		w.serve(
		  "a.example", { answer({ referral_compare(1, { "ldap://b.example/uid=jdoe,ou=moved,dc=example,dc=org" }) }) });
		w.refused = { "b.example" };
		auto r = w.run(ldap::chase_compare(w.origin.conn, request, w.connector()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::referral);
	}
	w.check_servers();
}

TEST_CASE("chase_search: a cancellation stops the chase", "[net][referral]")
{
	world w;
	w.add("b.example");
	w.add("c.example");
	w.serve("a.example",
	  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
		ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
		ref_msg(1, { "ldap://c.example/ou=c,dc=example,dc=org" }),
		done_msg(1) }) });
	std::stop_source stop;
	w.on_ask = [&stop] { stop.request_stop(); };
	outcome<ldap::result<ldap::chased_search>> out;
	spawn(w.ioc, stop.get_token(), ldap::chase_search(w.origin.conn, search(), w.connector()), out);
	drive_until(w.ioc, [&out] { return out.done(); });
	auto &r = out.get();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::cond::canceled);
	// Stopped before the request to b was sent, and c never asked for.
	CHECK(w.asked == std::vector<std::pair<std::string, std::size_t>>{ { "b.example", 1 } });
	CHECK(w.servers["b.example"]->log.received.empty());
	w.check_servers();
}

TEST_CASE("chase_search: the timeout bounds the whole chase, the connector included", "[net][referral]")
{
	using std::chrono::steady_clock;
	world w;
	w.add("b.example");
	auto request = search();
	// Long enough for the origin's search even on a loaded machine.
	request.timeout = std::chrono::seconds(1);

	SECTION("a connector still working when it is spent is cancelled")
	{
		w.serve("a.example",
		  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
			ref_msg(1, { "ldap://slow.example/ou=s,dc=example,dc=org" }),
			ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org" }),
			done_msg(1) }) });
		w.hanging = { "slow.example" };
		const auto start = steady_clock::now();
		auto r = w.run(ldap::chase_search(w.origin.conn, request, w.connector()));
		CHECK(steady_clock::now() - start < std::chrono::seconds(30));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->complete);
		CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=a,dc=example,dc=org" });
		// b's reference is left unexamined: the chase stopped.
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::failed });
		CHECK(r->unlisted == 1);
		REQUIRE(r->referrals[0].failure);
		CHECK(r->referrals[0].failure->code == ldap::cond::timeout);
		CHECK(w.asked == std::vector<std::pair<std::string, std::size_t>>{ { "slow.example", 1 } });
	}
	SECTION("a connector that returns after it is spent: nothing is sent, the reference stops")
	{
		w.add("c.example");
		w.serve("a.example",
		  { answer({ entry_msg(1, "uid=jdoe,ou=a,dc=example,dc=org", "A"),
			ref_msg(1, { "ldap://b.example/ou=b,dc=example,dc=org", "ldap://c.example/ou=c,dc=example,dc=org" }),
			done_msg(1) }) });
		// Blocks the thread: the deadline cannot cancel it.
		w.on_ask = [] { std::this_thread::sleep_for(std::chrono::milliseconds(1100)); };
		auto r = w.run(ldap::chase_search(w.origin.conn, request, w.connector()));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->complete);
		// One limit_reached entry: c, the reference's other URI, is not
		// looked at.
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::limit_reached });
		CHECK(r->unlisted == 0);
		CHECK(w.asked.size() == 1);
		CHECK(w.servers["b.example"]->log.received.empty());
	}
	w.check_servers();
}

// ---------------------------------------------------------------- make_same_policy_connector

namespace {

auto plan(std::string_view target,
  std::vector<std::string> allowed,
  bool origin_tls = false,
  const ldap::connection_options &options = {},
  std::optional<std::uint16_t> origin_port = std::nullopt) -> std::optional<ldap::detail::referral_connect_plan>
{
	auto u = ldap::url::parse(target);
	INFO(target);
	REQUIRE(u.has_value());
	return ldap::detail::same_policy_plan(*u, origin_tls, options, allowed, origin_port);
}

}// namespace

TEST_CASE("make_same_policy_connector: the host allow-list", "[net][referral]")
{
	const std::vector<std::string> example{ "example.org" };
	SECTION("a name and its subdomains, in ASCII case-insensitively")
	{
		CHECK(plan("ldap://example.org", example));
		CHECK(plan("ldap://ldap.eu.example.org/dc=x", example));
		CHECK(plan("ldap://LDAP.Example.ORG./dc=x", example));
		CHECK(plan("ldap://ldap.example.org", { ".Example.org." }));
		CHECK_FALSE(plan("ldap://badexample.org", example));
		CHECK_FALSE(plan("ldap://example.org.evil.test", example));
		CHECK_FALSE(plan("ldap://org", example));
	}
	SECTION("empty: everything is refused") { CHECK_FALSE(plan("ldap://example.org", {})); }
	SECTION("internationalized names compare in their ASCII form (RFC 4513 section 3.1.3.1)")
	{
		auto p = plan("ldap://B%C3%9CCHER.example:1389/dc=x", { "xn--bcher-kva.example:1389" });
		REQUIRE(p);
		// Connected to under the ASCII name, the port kept.
		CHECK(p->server.host() == "xn--bcher-kva.example");
		CHECK(p->server.port_or_default() == 1389);
		CHECK(plan("ldap://ldap.xn--bcher-kva.example", { "bücher.example" }));
		CHECK_FALSE(plan("ldap://b%C3%BCcher.example", { "bucher.example" }));
		// A name IDNA refuses (a label with a leading hyphen and non-ASCII) is refused.
		CHECK_FALSE(plan("ldap://-b%C3%BCcher.example", { "example" }));
	}
	SECTION("IP addresses match only themselves")
	{
		CHECK(plan("ldap://10.0.0.1", { "10.0.0.1" }));
		CHECK_FALSE(plan("ldap://10.0.0.1", { "0.0.1" }));
		CHECK_FALSE(plan("ldap://10.0.0.1", { "10.0.0.10" }));
		CHECK(plan("ldap://[::1]:389", { "::1" }));
		CHECK(plan("ldap://[FE80::1]", { "[fe80::1]" }));
		CHECK_FALSE(plan("ldap://[::1]", { "1" }));
	}
	SECTION("bytes no host name has are refused, whatever the suffix")
	{
		CHECK(plan("ldap://_ldap.example.org", example));
		for (const auto *text : { "ldap://evil.test%00.example.org",
			   "ldap://evil.test%2F.example.org",
			   "ldap://evil.test%20.example.org",
			   "ldap://evil.test%25.example.org",
			   "ldap://evil.test%3A1.example.org",
			   "ldap://evil.test%0A.example.org" }) {
			CHECK_FALSE(plan(text, example));
		}
	}
	SECTION("ldapi and URLs without a host are refused")
	{
		CHECK_FALSE(
		  plan("ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi", { "%2Fvar%2Frun%2Fslapd%2Fldapi", "/var/run/slapd/ldapi" }));
		CHECK_FALSE(plan("ldap:///dc=example,dc=org", { "" }));
	}
}

TEST_CASE("make_same_policy_connector: ports", "[net][referral]")
{
	const std::vector<std::string> example{ "example.org" };
	SECTION("the scheme's default port")
	{
		CHECK(plan("ldap://b.example.org:389", example));
		CHECK(plan("ldaps://b.example.org", example));
		CHECK(plan("ldaps://b.example.org:636", example));
		CHECK_FALSE(plan("ldaps://b.example.org:389", example));
		CHECK_FALSE(plan("ldap://b.example.org:1389", example));
	}
	SECTION("the origin's port")
	{
		CHECK(plan("ldap://b.example.org:1389", example, false, {}, 1389));
		CHECK_FALSE(plan("ldap://b.example.org:1390", example, false, {}, 1389));
	}
	SECTION("a port an entry names, on top of the usual ones")
	{
		const std::vector<std::string> with_port{ "example.org:1389" };
		CHECK(plan("ldap://b.example.org:1389", with_port));
		CHECK(plan("ldap://b.example.org", with_port));
		CHECK_FALSE(plan("ldap://b.example.org:1390", with_port));
		CHECK_FALSE(plan("ldap://b.other.test:1389", with_port));
		CHECK(plan("ldap://10.0.0.1:1389", { "10.0.0.1:1389" }));
		CHECK(plan("ldap://[::1]:1389", { "[::1]:1389" }));
		CHECK_FALSE(plan("ldap://[::1]:1389", { "::1" }));
		CHECK(plan("ldap://[::1]", { "::1" }));
	}
	SECTION("an entry that cannot be read allows nothing")
	{
		for (const auto *entry :
		  { "example.org:", "example.org:x", "example.org:0", "example.org:65536", "[::1", "[::1]x" }) {
			INFO(entry);
			CHECK_FALSE(plan("ldap://b.example.org", { entry }));
			CHECK_FALSE(plan("ldap://[::1]", { entry }));
		}
	}
}

TEST_CASE("make_same_policy_connector: no TLS downgrade, the referred host checked", "[net][referral]")
{
	ldap::connection_options options;
	options.tls.server_name = "origin.example.org";
	const std::vector<std::string> example{ "example.org" };

	SECTION("a TLS origin: ldap:// targets get StartTLS")
	{
		auto p = plan("ldap://b.example.org", example, true, options);
		REQUIRE(p);
		CHECK(p->options.start_tls);
		CHECK(p->options.tls.server_name.empty());
		auto s = plan("ldaps://b.example.org", example, true, options);
		REQUIRE(s);
		CHECK(s->server.scheme() == ldap::url_scheme::ldaps);
		CHECK_FALSE(s->options.start_tls);
		CHECK(s->options.tls.server_name.empty());
	}
	SECTION("a plain origin: the options as given")
	{
		auto p = plan("ldap://b.example.org", example, false, options);
		REQUIRE(p);
		CHECK_FALSE(p->options.start_tls);
		options.start_tls = true;
		auto q = plan("ldap://b.example.org", example, false, options);
		REQUIRE(q);
		CHECK(q->options.start_tls);
		auto s = plan("ldaps://b.example.org", example, false, options);
		REQUIRE(s);
		CHECK_FALSE(s->options.start_tls);
	}
}

TEST_CASE("make_same_policy_connector: connects, sets up once, reuses", "[net][referral]")
{
	world w;
	corosio::tcp_acceptor acc{ w.ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
	corosio::tcp_socket peer{ w.ioc };
	server_log log;
	log.hang_up = [&peer] { peer.close(); };
	// Accepts one connection and runs the script on it: the bind of the
	// setup, then both searches.
	outcome<void> served;
	spawn(
	  w.ioc,
	  [](corosio::tcp_acceptor &a, corosio::tcp_socket &p, server_log &l) -> capy::task<void> {
		  auto [ec] = co_await a.accept(p);
		  if (ec) {
			  throw std::system_error(ec, "accept");
		  }
		  co_await serve_script(net::transport::wrap(socket_ref{ &p }, "peer"),
			{ answer({ bind_resp(1) }),
			  answer({ entry_msg(2, "uid=jdoe,ou=b,dc=example,dc=org", "B"), done_msg(2) }),
			  answer({ entry_msg(3, "uid=jdoe,ou=c,dc=example,dc=org", "C"), done_msg(3) }) },
			l);
	  }(acc, peer, log),
	  served);
	const std::pmr::string target = "ldap://127.0.0.1:" + std::pmr::string(std::to_string(acc.local_endpoint().port()));
	w.serve("a.example",
	  { answer({ ref_msg(1, { target + "/ou=b,dc=example,dc=org" }),
		ref_msg(1, { "ldap://elsewhere.test/ou=x,dc=example,dc=org" }),
		ref_msg(1, { target + "/ou=c,dc=example,dc=org" }),
		done_msg(1) }) });

	ldap::connection_options options;
	options.operation_timeout = std::chrono::seconds(5);
	auto connector = ldap::make_same_policy_connector(w.ioc,
	  w.origin.conn,
	  options,
	  { "127.0.0.1:" + std::to_string(acc.local_endpoint().port()) },
	  ldap::simple_bind_setup(ldap::dn{ "cn=reader,dc=example,dc=org" }, "secret"));

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), connector));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);// elsewhere.test is not allowed
	CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=b,dc=example,dc=org", "uid=jdoe,ou=c,dc=example,dc=org" });
	CHECK(outcomes(r->referrals)
		  == std::vector{ referral_outcome::followed, referral_outcome::skipped_policy, referral_outcome::followed });
	drive_until(w.ioc, [&served] { return served.done(); });
	served.get();
	CHECK(log.error.empty());
	// One bind (the setup), then both searches on the same connection.
	REQUIRE(log.received.size() == 3);
	CHECK(std::get<ldap::bind_request>(log.received[0].op).name == "cn=reader,dc=example,dc=org");
	CHECK(std::get<ldap::search_request>(log.received[1].op).base_object == "ou=b,dc=example,dc=org");
	CHECK(std::get<ldap::search_request>(log.received[2].op).base_object == "ou=c,dc=example,dc=org");
	w.check_servers();
	connector = {};// closes the connection it opened
	peer.close();
	acc.close();
	drive(w.ioc);
}

namespace {

// Loopback TCP servers for make_same_policy_connector: accepts connections
// one after another, running the next script on each.
struct tcp_targets
{
	corosio::io_context &ioc;
	corosio::tcp_acceptor acc;
	std::deque<corosio::tcp_socket> peers{};
	std::deque<server_log> logs{};
	outcome<void> served{};

	tcp_targets(corosio::io_context &io, std::vector<std::vector<step>> scripts)
	  : ioc(io), acc{ io, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 }
	{
		for (std::size_t i = 0; i < scripts.size(); ++i) {
			auto &p = peers.emplace_back(ioc);
			logs.emplace_back().hang_up = [&p] { p.close(); };
		}
		spawn(ioc, serve_all(std::move(scripts)), served);
	}
	tcp_targets(const tcp_targets &) = delete;
	auto operator=(const tcp_targets &) -> tcp_targets & = delete;
	~tcp_targets()
	{
		for (auto &p : peers) {
			p.close();
		}
		acc.close();
		drive(ioc);
	}

	auto serve_all(std::vector<std::vector<step>> scripts) -> capy::task<void>
	{
		for (std::size_t i = 0; i < scripts.size(); ++i) {
			auto [ec] = co_await acc.accept(peers[i]);
			if (ec) {
				throw std::system_error(ec, "accept");
			}
			co_await serve_script(
			  net::transport::wrap(socket_ref{ &peers[i] }, "peer"), std::move(scripts[i]), logs[i]);
		}
	}

	auto port() const -> std::uint16_t { return acc.local_endpoint().port(); }
	auto url(std::string_view dn) const -> std::pmr::string
	{
		return std::pmr::string("ldap://127.0.0.1:" + std::to_string(port()) + "/") + std::pmr::string(dn);
	}
	auto allowed() const -> std::vector<std::string> { return { "127.0.0.1:" + std::to_string(port()) }; }

	// Every script ran to its end without errors.
	void check()
	{
		drive_until(ioc, [this] { return served.done(); });
		served.get();
		for (const auto &l : logs) {
			CHECK(l.error.empty());
		}
	}
};

auto extended_msg(std::int32_t id, std::int32_t code) -> ldap::message
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ code }, std::nullopt, std::nullopt } };
}

auto reader_setup() -> ldap::session_setup
{
	return ldap::simple_bind_setup(ldap::dn{ "cn=reader,dc=example,dc=org" }, "secret");
}

auto with_timeout() -> ldap::connection_options
{
	ldap::connection_options options;
	options.timeout = std::chrono::seconds(10);
	options.operation_timeout = std::chrono::seconds(10);
	return options;
}

}// namespace

TEST_CASE("make_same_policy_connector: a refused StartTLS fails the URI", "[net][referral]")
{
	world w;
	// The server can only refuse StartTLS (it does not speak TLS).
	tcp_targets t(w.ioc, { { answer({ extended_msg(1, 2) }) } });
	w.serve("a.example", { answer({ ref_msg(1, { t.url("ou=b,dc=example,dc=org") }), done_msg(1) }) });
	auto options = with_timeout();
	options.start_tls = true;// what a TLS origin sets for an ldap:// target
	auto connector = ldap::make_same_policy_connector(w.ioc, w.origin.conn, options, t.allowed(), reader_setup());

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), connector));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::failed });
	CHECK(r->referrals[0].failure.has_value());
	// Only the StartTLS request: no bind, no search in the clear.
	t.check();
	REQUIRE(t.logs[0].received.size() == 1);
	CHECK(std::holds_alternative<ldap::extended_request>(t.logs[0].received[0].op));
	w.check_servers();
	connector = {};
}

TEST_CASE("make_same_policy_connector: a failed setup fails the URI", "[net][referral]")
{
	world w;
	tcp_targets t(w.ioc, { { answer({ bind_resp(1, 49, "bad password") }) } });
	w.serve("a.example", { answer({ ref_msg(1, { t.url("ou=b,dc=example,dc=org") }), done_msg(1) }) });
	auto connector =
	  ldap::make_same_policy_connector(w.ioc, w.origin.conn, with_timeout(), t.allowed(), reader_setup());

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), connector));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::failed });
	REQUIRE(r->referrals[0].failure);
	CHECK(r->referrals[0].failure->code == errc::invalid_credentials);
	t.check();
	REQUIRE(t.logs[0].received.size() == 1);
	CHECK(std::holds_alternative<ldap::bind_request>(t.logs[0].received[0].op));
	w.check_servers();
	connector = {};
}

TEST_CASE("make_same_policy_connector: a failed connect fails the URI", "[net][referral]")
{
	world w;
	// A port nothing listens on: bound, then closed.
	std::uint16_t port = 0;
	{
		corosio::tcp_acceptor closed{ w.ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
		port = closed.local_endpoint().port();
		closed.close();
	}
	const std::string server = "127.0.0.1:" + std::to_string(port);
	w.serve("a.example",
	  { answer({ ref_msg(1, { std::pmr::string("ldap://" + server + "/ou=b,dc=example,dc=org") }), done_msg(1) }) });
	auto connector = ldap::make_same_policy_connector(w.ioc, w.origin.conn, with_timeout(), { server });

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), connector));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::failed });
	REQUIRE(r->referrals[0].failure);
	CHECK(r->referrals[0].failure->code == std::errc::connection_refused);
	w.check_servers();
	connector = {};
}

TEST_CASE("make_same_policy_connector: a closed connection is reopened", "[net][referral]")
{
	world w;
	// The first connection answers one search, then hangs up on the next
	// one (c's: it was still open when c was sent, whatever the order the
	// chase and the reader run in); the second one is opened (and set up)
	// for the URI after the one that found it closed.
	tcp_targets t(w.ioc,
	  { { answer({ bind_resp(1) }),
		  answer({ entry_msg(2, "uid=jdoe,ou=b,dc=example,dc=org", "B"), done_msg(2) }),
		  answer({}, true) },
		{ answer({ bind_resp(1) }), answer({ entry_msg(2, "uid=jdoe,ou=d,dc=example,dc=org", "D"), done_msg(2) }) } });
	w.serve("a.example",
	  { answer({ ref_msg(1, { t.url("ou=b,dc=example,dc=org") }),
		ref_msg(1, { t.url("ou=c,dc=example,dc=org") }),
		ref_msg(1, { t.url("ou=d,dc=example,dc=org") }),
		done_msg(1) }) });
	auto connector =
	  ldap::make_same_policy_connector(w.ioc, w.origin.conn, with_timeout(), t.allowed(), reader_setup());

	auto r = w.run(ldap::chase_search(w.origin.conn, search(), connector));
	REQUIRE(r.has_value());
	CHECK_FALSE(r->complete);
	CHECK(dns(*r) == std::vector<std::string>{ "uid=jdoe,ou=b,dc=example,dc=org", "uid=jdoe,ou=d,dc=example,dc=org" });
	// c's search went to the closed connection and failed with it.
	CHECK(outcomes(r->referrals)
		  == std::vector{ referral_outcome::followed, referral_outcome::failed, referral_outcome::followed });
	t.check();
	REQUIRE(t.logs[0].received.size() == 3);
	CHECK(std::get<ldap::search_request>(t.logs[0].received[2].op).base_object == "ou=c,dc=example,dc=org");
	REQUIRE(t.logs[1].received.size() == 2);
	CHECK(std::holds_alternative<ldap::bind_request>(t.logs[1].received[0].op));
	CHECK(std::get<ldap::search_request>(t.logs[1].received[1].op).base_object == "ou=d,dc=example,dc=org");
	w.check_servers();
	connector = {};
}
