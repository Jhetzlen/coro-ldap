// chase_search and chase_compare (referral_chase.hpp) against several
// scripted in-process servers on one io_context (mock_ldap.hpp's
// serve_script over socket pairs), with a test connector that maps a URL's
// host to one of them.
#include "jhetz/ldap/referral_chase.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
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
	SECTION("over max_targets: partial")
	{
		auto r = w.run(ldap::chase_search(w.origin.conn, search(), w.connector(), { .max_targets = 1 }));
		REQUIRE(r.has_value());
		CHECK_FALSE(r->complete);
		CHECK(outcomes(r->referrals) == std::vector{ referral_outcome::followed, referral_outcome::limit_reached });
		CHECK(w.asked.size() == 1);
	}
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
