// ldap::connection against a scripted in-process LDAP server: the server end
// decodes requests with origin::client and answers with encoded responses
// from a script, over a Unix socket pair (and once over loopback TCP,
// through ldap::connect).
//
// Not capy::test::stream: at the pinned Capy commit its wake() posts the
// parked continuation by reference and then clears the handle while it is
// still queued, so a reader woken by the peer resumes a null handle. Its
// provide()-before-read use in message_io_tests.cpp never parks a reader.
#include "../counting_resource.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using ldap::client_errc;
using ldap::errc;


// ---------------------------------------------------------------- bind

TEST_CASE("connection: simple bind", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }) });
	auto r = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	REQUIRE(r.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == bind_request_msg(1));// version 3, simple auth, id 1
	CHECK(m.conn.is_open());
	CHECK(m.conn.name() == "mock");
}

TEST_CASE("connection: bind errors keep the connection usable", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1, 49, "bad password") }), answer({ bind_resp(2) }) });
	auto bad = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == errc::invalid_credentials);
	CHECK(bad.error().code == ldap::cond::auth_failed);
	CHECK(bad.error().diagnostic == "bad password");
	CHECK(bad.error().context == "bind cn=admin,dc=example,dc=org");
	CHECK(m.conn.is_open());

	auto good = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	CHECK(good.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1].id == 2);
}

TEST_CASE("connection: anonymous and unauthenticated binds", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }) });
	// A name without a password is refused before anything is sent.
	auto unauth = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, ""));
	REQUIRE_FALSE(unauth.has_value());
	CHECK(unauth.error().code == client_errc::unauthenticated_bind);
	CHECK(unauth.error().code == ldap::cond::auth_failed);
	CHECK(m.log.received.empty());
	CHECK(m.conn.is_open());

	auto anon = m.run(m.conn.simple_bind(ldap::dn{}, ""));
	REQUIRE(anon.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == ldap::message{ 1, ldap::bind_request{ 3, "", ldap::simple_auth{ "" } } });
}

// ---------------------------------------------------------------- search

TEST_CASE("connection: search sends the request and collects the entries", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
	  ref_msg(1, { "ldap://other.example.org/ou=people,dc=example,dc=org" }),
	  entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
	  done_msg(1) }) });

	auto r = m.run(m.conn.search({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .scope = ldap::search_scope::single_level,
	  .filter = ldap::filters::attr("objectClass") == "person" && ldap::filters::attr("uid").present(),
	  .attributes = { "cn", "mail" },
	  .deref = ldap::deref_aliases::always,
	  .size_limit = 10,
	  .time_limit = std::chrono::seconds(5),
	  .types_only = false,
	  .controls = { ldap::control{ "1.2.3.4", true, "v" } },
	}));
	REQUIRE(r.has_value());
	REQUIRE(r->size() == 2);
	CHECK((*r)[0] == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
	CHECK((*r)[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
	m.check_server();

	ldap::search_request wire{ people,
		ldap::search_scope::single_level,
		ldap::filter::raw("(&(objectClass=person)(uid=*))").value(),
		{ "cn", "mail" } };
	wire.deref = ldap::deref_aliases::always;
	wire.size_limit = 10;
	wire.time_limit = 5;
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == ldap::message{ 1, wire, { ldap::control{ "1.2.3.4", true, "v" } } });
}

TEST_CASE("connection: search defaults", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });
	auto r = m.run(m.conn.search({}));
	REQUIRE(r.has_value());
	CHECK(r->empty());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	// Root DSE base, subtree, (objectClass=*), all user attributes, no limits.
	CHECK(
	  m.log.received[0]
	  == ldap::message{ 1,
		ldap::search_request{ "", ldap::search_scope::whole_subtree, ldap::filters::attr("objectClass").present() } });
}

TEST_CASE("connection: search result errors", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1, 32, "dc=example,dc=org", "no such entry") }),
	  answer({ done_msg(2, 10, "", "go elsewhere", { "ldap://b.example.org/ou=missing,dc=example,dc=org" }) }),
	  answer({ done_msg(3) }) });

	auto r = m.run(m.conn.search({ .base = ldap::dn{ "ou=missing,dc=example,dc=org" } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == errc::no_such_object);
	CHECK(r.error().code == ldap::cond::not_found);
	CHECK(r.error().matched_dn == "dc=example,dc=org");
	CHECK(r.error().diagnostic == "no such entry");
	CHECK(r.error().context == "search ou=missing,dc=example,dc=org");
	CHECK(m.conn.is_open());

	auto referral = m.run(m.conn.search({ .base = ldap::dn{ "ou=missing,dc=example,dc=org" } }));
	REQUIRE_FALSE(referral.has_value());
	CHECK(referral.error().code == errc::referral);
	CHECK(referral.error().referrals == ldap::string_list{ "ldap://b.example.org/ou=missing,dc=example,dc=org" });
	CHECK_FALSE(referral.error().matched_dn.has_value());

	// Still usable.
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
}

TEST_CASE("connection: requests that cannot be encoded are not sent", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });

	auto negative = m.run(m.conn.search({ .size_limit = -1 }));
	REQUIRE_FALSE(negative.has_value());
	CHECK(negative.error().code == client_errc::encode_error);

	auto too_long = m.run(m.conn.search({ .time_limit = std::chrono::seconds(std::int64_t{ 1 } << 31) }));
	REQUIRE_FALSE(too_long.has_value());
	CHECK(too_long.error().code == client_errc::encode_error);
	CHECK_THAT(std::string(too_long.error().context), StartsWith("search \"\": time_limit"));

	auto empty_filter = m.run(m.conn.search({ .filter = ldap::filter{} }));
	REQUIRE_FALSE(empty_filter.has_value());
	CHECK(empty_filter.error().code == client_errc::invalid_filter);

	CHECK(m.conn.is_open());
	CHECK(m.log.received.empty());
	// Failed encodes do not use up message ids: the next request gets 1.
	CHECK(m.run(m.conn.search({})).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0].id == 1);
}

// ---------------------------------------------------------------- streaming

TEST_CASE("connection: search_stream yields entries one at a time", "[net][connection]")
{
	mock_ldap m;
	ldap::message done = done_msg(1);
	done.controls.push_back(*ldap::encode_paged_results({ 0, "cookie" }));
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
	  ref_msg(1, { "ldap://r1.example.org/", "ldap://r2.example.org/" }),
	  entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
	  done }) });

	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	CHECK_FALSE(s->done());

	auto a = m.run(s->next());
	REQUIRE(a.has_value());
	REQUIRE(a->has_value());
	CHECK(**a == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
	CHECK(s->references().empty());

	auto b = m.run(s->next());
	REQUIRE(b.has_value());
	REQUIRE(b->has_value());
	CHECK(**b == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
	CHECK(s->references() == ldap::string_list{ "ldap://r1.example.org/", "ldap://r2.example.org/" });

	auto end = m.run(s->next());
	REQUIRE(end.has_value());
	CHECK_FALSE(end->has_value());
	CHECK(s->done());
	REQUIRE(s->controls().size() == 1);
	CHECK(ldap::decode_paged_results(s->controls()[0])->cookie == "cookie");

	// The end repeats without I/O.
	auto again = m.run(s->next());
	REQUIRE(again.has_value());
	CHECK_FALSE(again->has_value());
	m.check_server();
}

TEST_CASE("connection: search_stream keeps the entries before an error", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1, 4, "", "limit") }),
	  answer({ bind_resp(2) }) });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	auto entries = m.run(drain_stream(*s));
	REQUIRE_FALSE(entries.has_value());
	CHECK(entries.error().code == errc::size_limit_exceeded);
	CHECK(s->done());
	auto a = m.run(s->next());// the error repeats
	REQUIRE_FALSE(a.has_value());
	CHECK(a.error().code == errc::size_limit_exceeded);

	// The search is over, so the connection is free again.
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
}

TEST_CASE("connection: other operations run while a stream is open", "[net][connection]")
{
	mock_ldap m;
	// The bind is answered while the search is still going on.
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }),
	  answer({ bind_resp(2), entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"), done_msg(1) }) });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	auto a = m.run(s->next());
	REQUIRE(a.has_value());
	REQUIRE(a->has_value());

	auto bound = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	CHECK(bound.has_value());
	CHECK_FALSE(s->done());// its last entry and done may be queued already, not yet taken

	auto rest = m.run(drain_stream(*s));
	REQUIRE(rest.has_value());
	REQUIRE(rest->size() == 1);
	CHECK((*rest)[0] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
	CHECK(m.conn.outstanding() == 0);
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == bind_request_msg(2));
}

TEST_CASE("connection: a stream destroyed early abandons its search", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }),
	  // The server reads the AbandonRequest, but the rest of the search was
	  // already on its way: those late responses must be dropped.
	  answer({ entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
		ref_msg(1, { "ldap://r.example.org/" }),
		done_msg(1, 4) }),
	  answer({ bind_resp(3) }) });
	{
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		auto a = m.run(s->next());
		REQUIRE(a.has_value());
		REQUIRE(a->has_value());
		CHECK(m.conn.outstanding() == 1);
	}
	CHECK(m.conn.outstanding() == 0);
	auto b = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	CHECK(b.has_value());
	CHECK(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
	CHECK(m.log.received[2] == bind_request_msg(3));
}

TEST_CASE("connection: a second next() on the same stream is refused", "[net][connection]")
{
	mock_ldap m;
	m.serve({ step{} });// reads the search, does not answer
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	outcome<ldap::result<std::optional<ldap::entry>>> first;
	spawn(m.ioc, s->next(), first);
	drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
	CHECK_FALSE(first.done());
	auto second = m.run(s->next());
	REQUIRE_FALSE(second.has_value());
	CHECK(second.error().code == client_errc::operation_in_progress);
	CHECK(
	  second.error().context == "search ou=people,dc=example,dc=org during an earlier next() on this search_stream");
	m.conn.close();
	drive_until(m.ioc, [&first] { return first.done(); });
	REQUIRE_FALSE(first.get().has_value());
	CHECK(first.get().error().code == client_errc::not_connected);
}

TEST_CASE("connection: moving connections and streams", "[net][connection]")
{
	SECTION("a stream survives moves of itself and its connection")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		ldap::connection moved = std::move(m.conn);
		CHECK_FALSE(m.conn.is_open());
		ldap::search_stream s2 = std::move(*s);
		ldap::search_stream s3;
		s3 = std::move(s2);
		auto entries = m.run(drain_stream(s3));
		REQUIRE(entries.has_value());
		CHECK(entries->size() == 1);
		m.check_server();
		// A default or moved-from stream and connection.
		ldap::search_stream empty;
		auto e = m.run(empty.next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == client_errc::not_connected);
		CHECK(e.error().context == "search");
		auto nc = m.run(m.conn.search({}));
		REQUIRE_FALSE(nc.has_value());
		CHECK(nc.error().code == client_errc::not_connected);
		CHECK(nc.error().context == "search \"\"");
		auto tls = m.run(m.conn.start_tls());
		REQUIRE_FALSE(tls.has_value());
		CHECK(tls.error().code == client_errc::not_connected);
		CHECK(tls.error().context == "start tls");
	}
	SECTION("a stream outliving its connection")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		m.conn = ldap::connection{};
		auto e = m.run(s->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == client_errc::not_connected);
		CHECK(s->done());
	}
}

// ---------------------------------------------------------------- unbind

TEST_CASE("connection: unbind", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }), step{} });
	REQUIRE(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	auto u = m.run(m.conn.unbind());
	REQUIRE(u.has_value());
	CHECK_FALSE(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::unbind_request{} });

	auto after = m.run(m.conn.search({}));
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == client_errc::not_connected);
	CHECK(after.error().context == "search \"\": connection closed");
	auto twice = m.run(m.conn.unbind());
	REQUIRE_FALSE(twice.has_value());
	CHECK(twice.error().code == client_errc::not_connected);
	m.conn.close();// idempotent
}

TEST_CASE("connection: unbind with a stream open ends the stream", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }), step{} });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	REQUIRE(m.run(s->next()).has_value());
	REQUIRE(m.run(m.conn.unbind()).has_value());
	auto e = m.run(s->next());
	REQUIRE_FALSE(e.has_value());
	CHECK(e.error().code == client_errc::not_connected);
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(std::holds_alternative<ldap::unbind_request>(m.log.received[1].op));
}

TEST_CASE("connection: message ids increase per request", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }),
	  answer({ done_msg(2) }),
	  answer({ entry_msg(3, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(3) }),
	  answer({ bind_resp(4) }),
	  step{} });
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	CHECK(m.run(m.conn.search({})).has_value());
	CHECK(m.run(m.conn.search(people_search())).has_value());
	CHECK(m.run(m.conn.simple_bind(ldap::dn{}, "")).has_value());
	CHECK(m.run(m.conn.unbind()).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 5);
	for (std::size_t i = 0; i < m.log.received.size(); ++i)
		CHECK(m.log.received[i].id == static_cast<std::int32_t>(i + 1));
}

// ---------------------------------------------------------------- server misbehaving

TEST_CASE("connection: protocol violations close the connection", "[net][connection]")
{
	struct case_t
	{
		const char *name;
		std::vector<std::string> replies;
		std::error_code code;
		const char *context;
	};
	const std::vector<case_t> cases{
		{ "wrong message id",
		  { bytes_of(bind_resp(7)) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: read mock: message with id 7, which matches no outstanding request" },
		{ "wrong operation",
		  { bytes_of(done_msg(1)) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: read mock: SearchResultDone with message id 1 in response to a "
		  "BindRequest" },
		{ "entry for a bind",
		  { bytes_of(entry_msg(1, "cn=x", "x")) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: read mock: SearchResultEntry with message id 1 in response to a "
		  "BindRequest" },
		{ "request operation from the server",
		  { bytes_of(bind_request_msg(1)) },
		  client_errc::unsupported_operation,
		  nullptr },
		{ "id 0 that is not a notification",
		  { bytes_of(bind_resp(0)) },
		  client_errc::unexpected_response,
		  "bind cn=admin,dc=example,dc=org: read mock: BindResponse with message id 0" },
		{ "not a PDU", { std::string("\x04\x01\x00", 3) }, client_errc::decode_error, nullptr },
	};
	for (const auto &c : cases) {
		DYNAMIC_SECTION(c.name)
		{
			mock_ldap m;
			step s;
			s.replies = c.replies;
			m.serve({ s });
			auto r = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == c.code);
			CHECK(r.error().code == ldap::cond::protocol_error);
			if (c.context != nullptr) CHECK(r.error().context == c.context);
			CHECK_FALSE(m.conn.is_open());
			m.check_server();

			auto later = m.run(m.conn.search({}));
			REQUIRE_FALSE(later.has_value());
			CHECK(later.error().code == client_errc::not_connected);
			CHECK_THAT(
			  std::string(later.error().context), StartsWith("search \"\": connection closed by an earlier error: "));
		}
	}
}

TEST_CASE("connection: wrong operation inside a search", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), bind_resp(1) }) });
	auto r = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::unexpected_response);
	CHECK(
	  r.error().context
	  == "search ou=people,dc=example,dc=org: read mock: BindResponse with message id 1 in response to a "
		 "SearchRequest");
	CHECK_FALSE(m.conn.is_open());
}

TEST_CASE("connection: oversized responses are rejected from the header", "[net][connection]")
{
	mock_ldap m({ .max_message_size = 1024 });
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", std::string(2000, 'x')), done_msg(1) }) });
	auto r = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::message_too_large);
	CHECK_THAT(std::string(r.error().context), StartsWith("search ou=people,dc=example,dc=org: read mock"));
	CHECK_FALSE(m.conn.is_open());
}

TEST_CASE("connection: max_elements applies to responses", "[net][connection]")
{
	// The entry decodes to 6 strings (name, two types, three values).
	mock_ldap m({ .max_elements = 2 });
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
	auto r = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::message_too_large);
	CHECK_THAT(std::string(r.error().context), ContainsSubstring("more than 2 elements"));
	CHECK_FALSE(m.conn.is_open());
}

TEST_CASE("connection: server closing mid-search", "[net][connection]")
{
	SECTION("between PDUs")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }, true) });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::eof);
		CHECK(r.error().code == ldap::cond::connection_lost);
		CHECK(r.error().context == "search ou=people,dc=example,dc=org: read mock: connection closed");
		CHECK_FALSE(m.conn.is_open());
		m.check_server();
	}
	SECTION("inside a PDU, streaming")
	{
		mock_ldap m;
		const auto second = bytes_of(entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"));
		step s = answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }, true);
		s.replies.push_back(second.substr(0, 10));
		m.serve({ s });
		auto st = m.run(m.conn.search_stream(people_search()));
		REQUIRE(st.has_value());
		auto a = m.run(st->next());
		REQUIRE(a.has_value());
		REQUIRE(a->has_value());
		auto b = m.run(st->next());
		REQUIRE_FALSE(b.has_value());
		CHECK(b.error().code == capy::cond::eof);
		CHECK_THAT(std::string(b.error().context), ContainsSubstring("connection closed after 10 of"));
		CHECK(st->done());
		auto later = m.run(m.conn.simple_bind(ldap::dn{}, ""));
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == client_errc::not_connected);
		CHECK(later.error().code == ldap::cond::connection_lost);
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("connection closed after 10 of"));
	}
}

TEST_CASE("connection: unsolicited notifications and intermediate responses", "[net][connection]")
{
	SECTION("notice of disconnection")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 0,
		  ldap::extended_response{
			ldap::ldap_result{ 52, "", "shutting down" }, std::string(ldap::notice_of_disconnection_oid) } } }) });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);
		CHECK(r.error().code == ldap::cond::busy_or_unavailable);
		CHECK(r.error().diagnostic == "shutting down");
		CHECK(r.error().context == "search ou=people,dc=example,dc=org: notice of disconnection");
		CHECK_FALSE(m.conn.is_open());
	}
	SECTION("notice of disconnection claiming success")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{
		  0, ldap::extended_response{ ldap::ldap_result{ 0 }, std::string(ldap::notice_of_disconnection_oid) } } }) });
		auto r = m.run(m.conn.simple_bind(ldap::dn{}, ""));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == errc::unavailable);
		CHECK_FALSE(m.conn.is_open());
	}
	SECTION("other notifications and intermediate responses are skipped")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 0, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.4" } },
		  ldap::message{ 1, ldap::intermediate_response{ "1.2.3.5", "x" } },
		  entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
		  ldap::message{ 1, ldap::intermediate_response{} },
		  done_msg(1) }) });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE(r.has_value());
		CHECK(r->size() == 1);
		CHECK(m.conn.is_open());
		m.check_server();
	}
}

TEST_CASE("connection: a cancelled search is abandoned", "[net][connection]")
{
	mock_ldap m;
	// Reads the search and answers nothing; then reads the AbandonRequest
	// and sends a late entry and done anyway; then answers a bind.
	m.serve({ step{},
	  answer({ entry_msg(1, "uid=late,ou=people,dc=example,dc=org", "L"), done_msg(1) }),
	  answer({ bind_resp(3) }) });
	std::stop_source stop;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> out;
	spawn(m.ioc, stop.get_token(), m.conn.search({}), out);
	drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
	REQUIRE(m.log.received.size() == 1);
	CHECK_FALSE(out.done());
	CHECK(m.conn.outstanding() == 1);
	stop.request_stop();
	drive_until(m.ioc, [&out] { return out.done(); });
	auto &r = out.get();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == capy::cond::canceled);
	CHECK(r.error().code == ldap::cond::canceled);
	CHECK(r.error().context == "search \"\" (abandoned)");
	CHECK(m.conn.is_open());
	CHECK(m.conn.outstanding() == 0);

	// The late entry and done are dropped; the connection still works.
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
}

// ---------------------------------------------------------------- raceable, with_stop

namespace {

using entries = ldap::result<std::pmr::vector<ldap::entry>>;
using event_race = std::variant<std::error_code, entries, std::tuple<>>;

// A search raced against `event`.
capy::task<event_race> search_or(ldap::connection &c, capy::async_event &event)
{
	co_return co_await capy::when_any(ldap::raceable(c.search({})), event.wait());
}

// A search raced against a timer.
capy::task<event_race> search_or_delay(ldap::connection &c, std::chrono::milliseconds d)
{
	co_return co_await capy::when_any(ldap::raceable(c.search({})), corosio::delay(d));
}

using bind_race = std::variant<std::error_code, ldap::result<void>, std::tuple<>>;

// A simple bind raced against a timer.
capy::task<bind_race> bind_or_delay(ldap::connection &c, std::chrono::milliseconds d)
{
	co_return co_await capy::when_any(
	  ldap::raceable(c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")), corosio::delay(d));
}

// The search was abandoned (AbandonRequest for message 1, sent as message
// 2) and the connection still works: a bind (message 3) is answered.
void check_abandoned_and_usable(mock_ldap &m)
{
	CHECK(m.conn.is_open());
	CHECK(m.conn.outstanding() == 0);
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
}

// A bind given up on closed the connection (RFC 4511 section 4.11).
void check_bind_closed(mock_ldap &m, const ldap::result<void> &r)
{
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::cond::canceled);
	CHECK(r.error().context == "bind cn=admin,dc=example,dc=org (connection closed)");
	CHECK_FALSE(m.conn.is_open());
	REQUIRE(m.log.received.size() == 1);
	CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
}

}// namespace

TEST_CASE("raceable: an operation raced with capy::when_any", "[net][connection][cancel]")
{
	mock_ldap m;
	capy::async_event event;
	outcome<event_race> out;

	SECTION("completes first: the operation wins, the other waiter is cancelled")
	{
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		spawn(m.ioc, search_or(m.conn, event), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().index() == 1);
		auto &r = std::get<1>(out.get());
		REQUIRE(r.has_value());
		CHECK(r->size() == 1);
		// The other event after completion: nothing more happens.
		event.set();
		m.check_server();
		CHECK(m.log.received.size() == 1);
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("a server error also completes the operation, and wins")
	{
		m.serve({ answer({ done_msg(1, 32) }) });
		spawn(m.ioc, search_or(m.conn, event), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().index() == 1);
		REQUIRE_FALSE(std::get<1>(out.get()).has_value());
		CHECK(std::get<1>(out.get()).error().code == errc::no_such_object);
		m.check_server();
	}
	SECTION("the other event first: it wins, the operation is abandoned")
	{
		// Reads the search and the abandon, answers nothing; then a bind.
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		spawn(m.ioc, search_or(m.conn, event), out);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		CHECK_FALSE(out.done());
		event.set();
		drive_until(m.ioc, [&out] { return out.done(); });
		CHECK(out.get().index() == 2);
		check_abandoned_and_usable(m);
	}
	SECTION("stopping the awaiting task cancels both: nothing wins")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		std::stop_source stop;
		spawn(m.ioc, stop.get_token(), search_or(m.conn, event), out);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		stop.request_stop();
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().index() == 0);
		CHECK(std::get<0>(out.get()) == ldap::cond::canceled);
		check_abandoned_and_usable(m);
	}
	SECTION("the awaiting task stopped before the race starts: nothing wins, the search is abandoned at once")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		std::stop_source stop;
		stop.request_stop();
		spawn(m.ioc, stop.get_token(), search_or(m.conn, event), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().index() == 0);
		CHECK(std::get<0>(out.get()) == ldap::cond::canceled);
		check_abandoned_and_usable(m);
	}
}

TEST_CASE("raceable: an operation raced with a timer", "[net][connection][cancel][timeout]")
{
	mock_ldap m;
	outcome<event_race> out;

	SECTION("the timer fires first: the operation is abandoned")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		spawn(m.ioc, search_or_delay(m.conn, std::chrono::milliseconds(50)), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		CHECK(out.get().index() == 2);
		check_abandoned_and_usable(m);
	}
	SECTION("the operation completes first: the timer is cancelled, the race ends at once")
	{
		m.serve({ answer({ done_msg(1) }) });
		const auto start = std::chrono::steady_clock::now();
		spawn(m.ioc, search_or_delay(m.conn, std::chrono::hours(1)), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
		REQUIRE(out.get().index() == 1);
		CHECK(std::get<1>(out.get()).has_value());
		m.check_server();
		CHECK(m.log.received.size() == 1);
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("a bind that loses closes the connection")
	{
		m.serve({ step{}, step{} });// reads the bind, then sees EOF
		outcome<bind_race> bind;
		spawn(m.ioc, bind_or_delay(m.conn, std::chrono::milliseconds(50)), bind);
		drive_until(m.ioc, [&bind] { return bind.done(); });
		CHECK(bind.get().index() == 2);
		CHECK_FALSE(m.conn.is_open());
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&m] { return m.server.done(); });
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
	}
}

TEST_CASE("with_stop: an operation cancelled from a stop source of one's own", "[net][connection][cancel]")
{
	mock_ldap m;
	std::stop_source cancel;
	outcome<entries> out;

	SECTION("completes normally; a stop requested afterwards has no effect")
	{
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		spawn(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.search({})), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().has_value());
		CHECK(out.get()->size() == 1);
		cancel.request_stop();
		m.check_server();
		CHECK(out.get().has_value());
		CHECK(m.log.received.size() == 1);
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("stopped mid-operation: the operation is abandoned")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		spawn(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.search({})), out);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		CHECK_FALSE(out.done());
		cancel.request_stop();
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE_FALSE(out.get().has_value());
		CHECK(out.get().error().code == ldap::cond::canceled);
		CHECK(out.get().error().context == "search \"\" (abandoned)");
		CHECK(out.get().error().message() == "search \"\" (abandoned): operation canceled [boost.capy:2]");
		check_abandoned_and_usable(m);
	}
	SECTION("stopped from another thread")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		spawn(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.search({})), out);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		std::thread([&cancel] { cancel.request_stop(); }).join();
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE_FALSE(out.get().has_value());
		CHECK(out.get().error().code == ldap::cond::canceled);
		check_abandoned_and_usable(m);
	}
	SECTION("stop requested before it starts")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		cancel.request_stop();
		auto r = m.run(ldap::with_stop(cancel.get_token(), m.conn.search({})));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::canceled);
		CHECK(r.error().context == "search \"\" (abandoned)");
		check_abandoned_and_usable(m);
	}
	SECTION("a bind stopped before it starts is not sent: the connection stays open")
	{
		m.serve({ answer({ done_msg(1) }) });
		cancel.request_stop();
		auto r = m.run(
		  ldap::with_stop(cancel.get_token(), m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::canceled);
		CHECK(r.error().context == "bind cn=admin,dc=example,dc=org");
		CHECK(m.conn.is_open());
		CHECK(m.run(m.conn.search({})).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::search_request>(m.log.received[0].op));
	}
	SECTION("the awaiting task's own stop token still cancels it")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		std::stop_source outer;
		spawn(m.ioc, outer.get_token(), ldap::with_stop(cancel.get_token(), m.conn.search({})), out);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		outer.request_stop();
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE_FALSE(out.get().has_value());
		CHECK(out.get().error().code == ldap::cond::canceled);
		check_abandoned_and_usable(m);
	}
	SECTION("a bind stopped mid-exchange closes the connection")
	{
		m.serve({ step{}, step{} });
		outcome<ldap::result<void>> bind;
		spawn(m.ioc,
		  ldap::with_stop(cancel.get_token(), m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")),
		  bind);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		cancel.request_stop();
		drive_until(m.ioc, [&bind] { return bind.done(); });
		check_bind_closed(m, bind.get());
	}
}

// ---------------------------------------------------------------- multiplexing

TEST_CASE("connection: concurrent searches with interleaved responses", "[net][connection][mux]")
{
	mock_ldap m;
	m.serve({ step{},// reads the first search
	  answer({ entry_msg(1, "uid=a1,ou=people,dc=example,dc=org", "A1"),
		entry_msg(2, "uid=b1,ou=groups,dc=example,dc=org", "B1"),
		entry_msg(1, "uid=a2,ou=people,dc=example,dc=org", "A2"),
		done_msg(2),
		entry_msg(1, "uid=a3,ou=people,dc=example,dc=org", "A3"),
		done_msg(1) }) });
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> a, b;
	spawn(m.ioc, m.conn.search(people_search()), a);
	spawn(m.ioc, m.conn.search({ .base = ldap::dn{ "ou=groups,dc=example,dc=org" } }), b);
	drive_until(m.ioc, [&] { return a.done() && b.done(); });
	REQUIRE(a.get().has_value());
	REQUIRE(b.get().has_value());
	REQUIRE(a.get()->size() == 3);
	CHECK((*a.get())[0] == expected_entry("uid=a1,ou=people,dc=example,dc=org", "A1"));
	CHECK((*a.get())[2] == expected_entry("uid=a3,ou=people,dc=example,dc=org", "A3"));
	REQUIRE(b.get()->size() == 1);
	CHECK((*b.get())[0] == expected_entry("uid=b1,ou=groups,dc=example,dc=org", "B1"));
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0].id == 1);
	CHECK(m.log.received[1].id == 2);
	CHECK(m.conn.outstanding() == 0);
}

TEST_CASE("connection: timeouts abandon the operation", "[net][connection][mux][timeout]")
{
	SECTION("search_params::timeout")
	{
		mock_ldap m;
		m.serve({ step{}, step{} });// reads the search and the abandon, answers nothing
		const auto start = std::chrono::steady_clock::now();
		auto r = m.run(m.conn.search({ .timeout = std::chrono::milliseconds(100) }));
		const auto elapsed = std::chrono::steady_clock::now() - start;
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::timeout);
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(r.error().context == "search \"\" (abandoned)");
		CHECK(elapsed >= std::chrono::milliseconds(80));
		CHECK(elapsed < std::chrono::seconds(10));
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
	}
	SECTION("connection_options::operation_timeout")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(100) });
		m.serve({ step{}, step{}, answer({ done_msg(3) }) });
		auto r = m.run(m.conn.del({ .entry = ldap::dn{ "cn=x,dc=example,dc=org" } }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::timeout);
		CHECK(r.error().context == "delete cn=x,dc=example,dc=org (abandoned)");
		// A search that is answered in time is unaffected.
		CHECK(m.run(m.conn.search({})).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
	}
}

TEST_CASE("connection: a disconnect fails every outstanding operation once", "[net][connection][mux]")
{
	mock_ldap m;
	// Reads the bind, then hangs up; the search, held while the bind is
	// outstanding, is never sent.
	m.serve({ step{ true, {}, true } });
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
	spawn(m.ioc, m.conn.search(people_search()), search);
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	REQUIRE_FALSE(search.get().has_value());
	CHECK(bind.get().error().code == ldap::cond::connection_lost);
	CHECK(bind.get().error().context == "bind cn=admin,dc=example,dc=org: read mock: connection closed");
	CHECK(search.get().error().code == ldap::cond::connection_lost);
	CHECK(search.get().error().context == "search ou=people,dc=example,dc=org: read mock: connection closed");
	CHECK_FALSE(m.conn.is_open());
	CHECK(m.conn.outstanding() == 0);
	m.check_server();
	CHECK(m.log.received.size() == 1);
}

TEST_CASE("connection: a notice of disconnection fails every outstanding operation", "[net][connection][mux]")
{
	mock_ldap m;
	// Reads the bind (the search is held behind it), then sends the notice.
	m.serve({ answer({ ldap::message{ 0,
	  ldap::extended_response{
		ldap::ldap_result{ 51, "", "too busy" }, std::string(ldap::notice_of_disconnection_oid) } } }) });
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
	spawn(m.ioc, m.conn.search(people_search()), search);
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	REQUIRE_FALSE(search.get().has_value());
	CHECK(bind.get().error().code == errc::busy);
	CHECK(bind.get().error().diagnostic == "too busy");
	CHECK(bind.get().error().context == "bind cn=admin,dc=example,dc=org: notice of disconnection");
	CHECK(search.get().error().code == errc::busy);
	CHECK(search.get().error().context == "search ou=people,dc=example,dc=org: notice of disconnection");
	CHECK_FALSE(m.conn.is_open());
	auto later = m.run(m.conn.search({}));
	REQUIRE_FALSE(later.has_value());
	CHECK(later.error().code == client_errc::not_connected);
	CHECK_THAT(std::string(later.error().context), ContainsSubstring("notice of disconnection"));
}

TEST_CASE("connection: an idle connection leaves the io_context free to stop", "[net][connection][mux]")
{
	mock_ldap m;
	m.serve({ answer({ bind_resp(1) }) });
	REQUIRE(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
	// No read is pending once nothing is outstanding: run() returns at once.
	const auto start = std::chrono::steady_clock::now();
	drive(m.ioc);
	CHECK(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
	CHECK(m.conn.is_open());
}

TEST_CASE("connection: destroying the connection fails its outstanding operations", "[net][connection][mux]")
{
	mock_ldap m;
	m.serve({ step{} });
	outcome<ldap::result<void>> bind;
	spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
	drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
	m.conn = ldap::connection{};
	drive_until(m.ioc, [&bind] { return bind.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	CHECK(bind.get().error().code == client_errc::not_connected);
	CHECK(bind.get().error().context == "bind cn=admin,dc=example,dc=org: connection closed");
}

namespace {

// Reads `n` searches (skipping AbandonRequests, which may come in
// between), then answers them all with their responses interleaved at
// random (each search's own responses stay in order): two entries under
// its base DN and a SearchResultDone. Abandoned requests are answered too:
// the client must drop those late responses.
capy::task<void> serve_shuffled(net::transport t, std::size_t n, std::uint64_t seed, server_log &log)
{
	net::read_buffer buf;
	std::vector<std::vector<std::string>> queues;
	while (queues.size() < n) {
		auto r = co_await net::read_message(t, buf, as_server);
		if (!r) {
			log.error = "server read: " + std::string(r.error().message());
			co_return;
		}
		if (std::holds_alternative<ldap::abandon_request>(r->op)) continue;
		const auto *sr = std::get_if<ldap::search_request>(&r->op);
		if (sr == nullptr) {
			log.error = "server: expected a SearchRequest";
			co_return;
		}
		const std::string base(sr->base_object);
		std::vector<std::string> q{ bytes_of(entry_msg(r->id, "uid=x," + base, "X")),
			bytes_of(entry_msg(r->id, "uid=y," + base, "Y")),
			bytes_of(done_msg(r->id)) };
		std::reverse(q.begin(), q.end());// popped from the back
		queues.push_back(std::move(q));
		log.received.push_back(std::move(*r));
	}
	std::uint64_t state = seed;
	auto next = [&state](std::size_t bound) {
		state = state * 6364136223846793005u + 1442695040888963407u;
		return static_cast<std::size_t>((state >> 33) % bound);
	};
	std::vector<std::size_t> live(n);
	for (std::size_t i = 0; i < n; ++i) live[i] = i;
	while (!live.empty()) {
		const std::size_t pick = next(live.size());
		auto &q = queues[live[pick]];
		const std::string bytes = std::move(q.back());
		q.pop_back();
		if (q.empty()) {
			live[pick] = live.back();
			live.pop_back();
		}
		if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(bytes))); !w) {
			log.error = "server write: " + std::string(w.error().message());
			co_return;
		}
	}
}

// A search whose entries must all lie under its own base.
capy::task<std::string> checked_search(ldap::connection &c, std::string base)
{
	auto d = ldap::dn::parse(base);
	if (!d) co_return "bad base";
	auto r = co_await c.search({ .base = std::move(*d) });
	if (!r) co_return std::string(r.error().message());
	if (r->size() != 2) co_return "expected 2 entries, got " + std::to_string(r->size());
	for (const auto &e : *r)
		if (!std::string_view(e.dn).ends_with("," + base))
			co_return "entry " + std::string(e.dn) + " not under " + base;
	co_return "";
}

}// namespace

// Many concurrent searches, responses interleaved at random, some
// cancelled while outstanding; 20 rounds (run under ASan in CI). Binds
// cannot run concurrently with anything (RFC 4511 section 4.2.1).
TEST_CASE("connection: stress with many concurrent operations", "[net][connection][mux]")
{
	constexpr std::size_t ops = 64;
	for (std::uint64_t round = 0; round < 20; ++round) {
		INFO("round " << round);
		mock_ldap m;
		spawn(m.ioc,
		  serve_shuffled(net::transport::wrap(socket_ref{ &m.sockets.server }, "server"), ops, 0x51ed + round, m.log),
		  m.server);
		std::vector<std::stop_source> stops(ops);
		std::vector<outcome<std::string>> results(ops);
		for (std::size_t i = 0; i < ops; ++i)
			spawn(m.ioc,
			  stops[i].get_token(),
			  checked_search(m.conn, "ou=" + std::to_string(i) + ",dc=example,dc=org"),
			  results[i]);
		// Cancel every 7th operation before the server answers anything.
		for (std::size_t i = 0; i < ops; i += 7) stops[i].request_stop();
		drive_until(
		  m.ioc, [&] { return std::all_of(results.begin(), results.end(), [](const auto &r) { return r.done(); }); });
		for (std::size_t i = 0; i < ops; ++i) {
			INFO("operation " << i);
			if (i % 7 == 0)
				CHECK_THAT(results[i].get(), ContainsSubstring("canceled"));
			else
				CHECK(results[i].get() == "");
		}
		m.check_server();
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		// Every late response for a cancelled operation was dropped; the
		// connection still works.
		CHECK(m.log.received.size() == ops);
	}
}

// Deterministic fuzzing of the response path: a valid search answer with
// bytes flipped, dropped, inserted or cut off. The client must finish every
// time (the server hangs up at the end), with entries or an error; a
// transport or protocol error closes the connection, a server result error
// does not.
TEST_CASE("connection: mutated server responses", "[net][connection]")
{
	std::string wire;
	for (const auto &msg : { entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
		   ref_msg(1, { "ldap://r.example.org/" }),
		   ldap::message{ 1, ldap::intermediate_response{ "1.2.3" } },
		   entry_msg(1, "uid=b,ou=people,dc=example,dc=org", std::string(300, 'b')),
		   done_msg(1, 0, "dc=example,dc=org", "ok") })
		wire += bytes_of(msg);

	std::uint64_t state = 0x9e3779b97f4a7c15u;
	auto next = [&state](std::size_t bound) {
		state = state * 6364136223846793005u + 1442695040888963407u;
		return static_cast<std::size_t>((state >> 33) % bound);
	};
	std::size_t ok = 0, server_error = 0, broken = 0;
	corosio::io_context ioc;
	for (int i = 0; i < 1500; ++i) {
		std::string bytes = wire;
		const std::size_t edits = 1 + next(4);
		for (std::size_t e = 0; e < edits && !bytes.empty(); ++e) {
			const std::size_t at = next(bytes.size());
			switch (next(4)) {
			case 0:
				bytes[at] = static_cast<char>(next(256));
				break;
			case 1:
				bytes.erase(at, 1 + next(8));
				break;
			case 2:
				bytes.insert(at, 1, static_cast<char>(next(256)));
				break;
			default:
				bytes.resize(at);
				break;
			}
		}
		socket_pair sp(ioc);
		server_log log;
		log.hang_up = [&sp] { sp.server.close(); };
		ldap::connection conn(ioc, net::transport::wrap(socket_ref{ &sp.client }, "mock"));
		step s;
		s.replies.push_back(bytes);
		s.close_after = true;
		outcome<void> server;
		spawn(ioc, serve_script(net::transport::wrap(socket_ref{ &sp.server }, "server"), { s }, log), server);
		auto r = run(ioc, conn.search(people_search()));
		if (r) {
			++ok;
		} else if (&r.error().code.category() == &ldap::result_category()) {
			++server_error;
			CHECK(conn.is_open());
		} else {
			++broken;
			CHECK_FALSE(conn.is_open());
		}
		sp.client.close();
		sp.server.close();
		drive(ioc);
		CHECK(server.done());
	}
	WARN("ok " << ok << " server_error " << server_error << " broken " << broken);
	CHECK(ok + server_error + broken == 1500);
	CHECK(broken > 0);
}

// ---------------------------------------------------------------- memory

TEST_CASE("connection: entries live on the resource given to search", "[net][connection][pmr]")
{
	counting_resource conn_mr;
	counting_resource results;
	{
		mock_ldap m({}, &conn_mr);
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
					entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
					done_msg(1) }),
		  answer({ entry_msg(2, "uid=c,ou=people,dc=example,dc=org", "C"), done_msg(2) }) });
		CHECK(conn_mr.allocations() > 0);// the connection's state

		auto r = m.run(m.conn.search(people_search(), &results));
		REQUIRE(r.has_value());
		REQUIRE(r->size() == 2);
		CHECK(r->get_allocator().resource() == &results);
		for (const auto &e : *r) {
			CHECK(e.get_allocator().resource() == &results);
			CHECK(e.attributes.get_allocator().resource() == &results);
			CHECK(e.attributes[0].values[0].get_allocator().resource() == &results);
		}
		CHECK((*r)[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));

		std::pmr::monotonic_buffer_resource arena;
		auto s = m.run(m.conn.search_stream(people_search(), &arena));
		REQUIRE(s.has_value());
		auto c = m.run(s->next());
		REQUIRE(c.has_value());
		REQUIRE(c->has_value());
		CHECK((*c)->get_allocator().resource() == &arena);
		CHECK(m.run(s->next()).has_value());
		m.check_server();
	}
	CHECK(conn_mr.outstanding() == 0);
	CHECK(results.outstanding() == 0);
}

// ---------------------------------------------------------------- over TCP

namespace {

capy::task<void> accept_and_serve(corosio::tcp_acceptor &acc, std::vector<step> script, server_log &log)
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		log.error = "accept: " + ec.message();
		co_return;
	}
	net::transport t = net::transport::wrap(std::move(peer), "server");
	co_await serve_script(std::move(t), std::move(script), log);
}

capy::task<std::string> tcp_session(corosio::io_context &ioc, std::string text)
{
	auto u = ldap::url::parse(text);
	if (!u) co_return "url: " + std::string(u.error().message());
	auto c = co_await ldap::connect(ioc, *u, { .timeout = std::chrono::seconds(10) });
	if (!c) co_return "connect: " + std::string(c.error().message());
	if (!c->is_open() || c->name() != text) co_return "unexpected connection state";
	if (auto b = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !b)
		co_return "bind: " + std::string(b.error().message());
	auto r = co_await c->search(people_search());
	if (!r) co_return "search: " + std::string(r.error().message());
	if (r->size() != 1 || (*r)[0] != expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "J"))
		co_return "unexpected entries";
	if (auto u2 = co_await c->unbind(); !u2) co_return "unbind: " + std::string(u2.error().message());
	co_return "";
}

}// namespace

TEST_CASE("connection: ldap::connect, bind, search and unbind over TCP", "[net][connection]")
{
	corosio::io_context ioc;
	corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 16);
	const std::string url = "ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port());

	server_log log;
	log.hang_up = [] {};
	outcome<void> server;
	spawn(ioc,
	  accept_and_serve(acc,
		{ answer({ bind_resp(1) }),
		  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "J"), done_msg(2) }),
		  step{} },
		log),
	  server);
	CHECK(run(ioc, tcp_session(ioc, url)) == "");
	CHECK(log.error == "");
	CHECK(server.done());
	REQUIRE(log.received.size() == 3);
	CHECK(std::holds_alternative<ldap::unbind_request>(log.received[2].op));
}

TEST_CASE("connection: ldap::connect failures", "[net][connection]")
{
	corosio::io_context ioc;
	std::uint16_t port = 0;
	{
		corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
		port = acc.local_endpoint().port();
	}// closed: nothing listens there now
	auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(port));
	REQUIRE(u.has_value());
	auto c = run(ioc, ldap::connect(ioc, *u));
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == std::errc::connection_refused);
	CHECK(c.error().code == ldap::cond::busy_or_unavailable);
	CHECK_THAT(std::string(c.error().context), StartsWith("connect ldap://127.0.0.1:"));

	auto bad = ldap::url::parse("ldap://127.0.0.1:1/??sub?(cn=x)?!unknown-ext");
	REQUIRE(bad.has_value());
	auto refused = run(ioc, ldap::connect(ioc, *bad));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == client_errc::invalid_url);
}

// ---------------------------------------------------------------- RFC conformance

// RFC 4511 section 4.11: "Abandon, Bind, Unbind, and StartTLS operations
// cannot be abandoned." Giving up on a bind closes the connection instead.
TEST_CASE("RFC 4511 4.11: a bind that is given up on is not abandoned", "[net][connection][rfc][timeout]")
{
	auto check = [](mock_ldap &m, const ldap::result<void> &r) {
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "bind cn=admin,dc=example,dc=org (connection closed)");
		CHECK_FALSE(m.conn.is_open());
		// Nothing more can be sent: the server's second read sees EOF.
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&m] { return m.server.done(); });
		CHECK_THAT(m.log.error, StartsWith("server read: "));
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
		auto later = m.run(m.conn.search({}));
		REQUIRE_FALSE(later.has_value());
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("cannot be abandoned"));
	};
	SECTION("timeout")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(100) });
		m.serve({ step{}, step{} });// reads the bind and whatever comes next, answers nothing
		auto r = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
		CHECK(r.error().code == ldap::cond::timeout);
		check(m, r);
	}
	SECTION("cancellation")
	{
		mock_ldap m;
		m.serve({ step{}, step{} });
		std::stop_source stop;
		outcome<ldap::result<void>> bind;
		spawn(m.ioc, stop.get_token(), m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		stop.request_stop();
		drive_until(m.ioc, [&bind] { return bind.done(); });
		CHECK(bind.get().error().code == ldap::cond::canceled);
		check(m, bind.get());
	}
}

// RFC 4511 section 4.2.1: "After sending a BindRequest, clients MUST NOT send
// further LDAP PDUs until receiving the BindResponse."
TEST_CASE("RFC 4511 4.2.1: nothing is sent while a bind is outstanding", "[net][connection][rfc]")
{
	// The server never answers the bind; its timeout closes the connection.
	mock_ldap m({ .operation_timeout = std::chrono::milliseconds(200) });
	m.serve({ step{}, step{} });
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
	spawn(m.ioc, m.conn.search(people_search()), search);
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	CHECK_FALSE(bind.get().has_value());
	REQUIRE_FALSE(search.get().has_value());
	CHECK_THAT(std::string(search.get().error().context), ContainsSubstring("cannot be abandoned"));
	// No BindResponse came, so the BindRequest is all the server got.
	drive_until(m.ioc, [&m] { return m.server.done(); });
	REQUIRE(m.log.received.size() == 1);
	CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
}

TEST_CASE("RFC 4511 4.2.1: requests started during a bind go out after its response", "[net][connection][rfc]")
{
	SECTION("in order, once the bind is answered")
	{
		mock_ldap m;
		m.serve({ answer({ bind_resp(1) }), answer({ done_msg(2) }), answer({ done_msg(3) }) });
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<std::pmr::vector<ldap::entry>>> first, second;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		spawn(m.ioc, m.conn.search(people_search()), first);
		spawn(m.ioc, m.conn.search({}), second);
		drive_until(m.ioc, [&] { return bind.done() && first.done() && second.done(); });
		CHECK(bind.get().has_value());
		CHECK(first.get().has_value());
		CHECK(second.get().has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
		CHECK(m.log.received[1].id == 2);
		CHECK(m.log.received[2].id == 3);
	}
	SECTION("a held request that is cancelled is never sent, nor abandoned")
	{
		mock_ldap m;
		m.serve({ answer({ bind_resp(1) }), answer({ done_msg(3) }) });
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<std::pmr::vector<ldap::entry>>> cancelled;
		std::stop_source stop;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		spawn(m.ioc, stop.get_token(), m.conn.search(people_search()), cancelled);
		stop.request_stop();
		drive_until(m.ioc, [&] { return bind.done() && cancelled.done(); });
		CHECK(bind.get().has_value());
		REQUIRE_FALSE(cancelled.get().has_value());
		CHECK(cancelled.get().error().code == ldap::cond::canceled);
		CHECK(m.run(m.conn.search({})).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
		CHECK(m.log.received[1].id == 3);
		CHECK(std::holds_alternative<ldap::search_request>(m.log.received[1].op));
	}
	SECTION("a second bind waits for the first")
	{
		mock_ldap m;
		m.serve({ answer({ bind_resp(1) }), answer({ bind_resp(2) }) });
		outcome<ldap::result<void>> first, second;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), first);
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{}, ""), second);
		drive_until(m.ioc, [&] { return first.done() && second.done(); });
		CHECK(first.get().has_value());
		CHECK(second.get().has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::get<ldap::bind_request>(m.log.received[0].op).name == "cn=admin,dc=example,dc=org");
		CHECK(std::get<ldap::bind_request>(m.log.received[1].op).name == "");
	}
	SECTION("a bind cancelled while waiting for the first")
	{
		mock_ldap m;
		m.serve({ step{}, step{} });// reads the first bind, never answers
		outcome<ldap::result<void>> first, second;
		std::stop_source stop;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), first);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		spawn(m.ioc, stop.get_token(), m.conn.simple_bind(ldap::dn{}, ""), second);
		CHECK_FALSE(second.done());
		stop.request_stop();
		drive_until(m.ioc, [&second] { return second.done(); });
		REQUIRE_FALSE(second.get().has_value());
		CHECK(second.get().error().code == ldap::cond::canceled);
		CHECK(second.get().error().context == "bind \"\"");
		CHECK(m.log.received.size() == 1);// the waiting bind was never sent
		m.conn.close();
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&] { return first.done() && m.server.done(); });
	}
	SECTION("unbind during a bind closes without an UnbindRequest")
	{
		mock_ldap m;
		m.serve({ step{}, step{} });
		outcome<ldap::result<void>> bind;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		CHECK(m.run(m.conn.unbind()).has_value());
		CHECK_FALSE(m.conn.is_open());
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&] { return bind.done() && m.server.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code == client_errc::not_connected);
		CHECK(m.log.received.size() == 1);
		CHECK_THAT(m.log.error, StartsWith("server read: "));
	}
}

// RFC 4511 section 4.1.1: a client "MUST NOT send a request with the same
// messageID as an earlier request in the same LDAP session unless it can be
// determined that the server is no longer servicing the earlier request".
TEST_CASE("RFC 4511 4.1.1: ids still in use are skipped after wrapping", "[net][connection][rfc]")
{
	auto del_resp = [](std::int32_t id) { return ldap::message{ id, ldap::del_response{ ldap::ldap_result{ 0 } } }; };
	const ldap::dn x{ "cn=x,dc=example,dc=org" };
	SECTION("an outstanding search keeps its id")
	{
		mock_ldap m;
		// Reads the search (id 1) and leaves it open; answers two deletes,
		// then ends the search.
		m.serve({ step{}, answer({ del_resp(ldap::max_int) }), answer({ del_resp(2), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream({}));
		REQUIRE(s.has_value());
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		ldap::detail::set_next_message_id(m.conn, ldap::max_int);
		CHECK(m.run(m.conn.del({ .entry = x })).has_value());// max_int
		CHECK(m.run(m.conn.del({ .entry = x })).has_value());// 2: 1 is the search's
		auto rest = m.run(drain_stream(*s));
		CHECK(rest.has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[1].id == ldap::max_int);
		CHECK(m.log.received[2].id == 2);
		CHECK(m.conn.is_open());
	}
	SECTION("an abandoned request keeps its id")
	{
		mock_ldap m;
		// Reads the search (id 1), its AbandonRequest (id 2), then answers
		// a delete: it must not reuse 1, which the server may still serve.
		m.serve({ step{}, step{}, answer({ del_resp(ldap::max_int) }), answer({ del_resp(2) }) });
		std::stop_source stop;
		outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
		spawn(m.ioc, stop.get_token(), m.conn.search({}), search);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		stop.request_stop();
		drive_until(m.ioc, [&] { return search.done() && m.log.received.size() == 2; });
		ldap::detail::set_next_message_id(m.conn, ldap::max_int);
		CHECK(m.run(m.conn.del({ .entry = x })).has_value());// max_int
		CHECK(m.run(m.conn.del({ .entry = x })).has_value());// 2: 1 was abandoned (2, the AbandonRequest's, is free)
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
		CHECK(m.log.received[3].id == 2);
	}
}
