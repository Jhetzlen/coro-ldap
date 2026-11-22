// ldap::connection against a scripted in-process LDAP server
// (mock_ldap.hpp), and once over loopback TCP.
#include "../counting_resource.hpp"
#include "../value_semantics.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/testing/message_io.hpp"
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
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <latch>
#include <limits>
#include <memory_resource>
#include <numeric>
#include <optional>
#include <semaphore>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
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
using Catch::Matchers::IsEmpty;
using Catch::Matchers::StartsWith;
using ldap::client_errc;
using ldap::errc;


TEST_CASE("connection: search_entry and search_reference value semantics", "[net][connection][value_semantics]")
{
	const std::string_view long_value = "a value long enough to allocate";
	ldap::entry e;
	e.dn = "uid=a-user-with-a-long-name,ou=people,dc=example,dc=org";
	e.attributes.push_back(ldap::attribute_values(ldap::attribute("description"), { long_value }));
	check_value_semantics(ldap::search_entry{ e, { ldap::control{ "1.2.840.113556.1.4.319", true, long_value } } },
	  [](const ldap::search_entry &x) { return resources{ mr(x.dn), mr(x.controls.at(0).value.value()) }; });
	check_value_semantics(
	  ldap::search_reference{ ldap::search_result_reference{ ldap::string_list{ "ldap://a-long-host.example.org/" } },
		{ ldap::control{ "1.2.840.113556.1.4.319", true, long_value } } },
	  [](const ldap::search_reference &x) { return resources{ mr(x.uris.at(0)), mr(x.controls.at(0).type) }; });
}

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
	REQUIRE(r->entries.size() == 2);
	CHECK(r->entries[0] == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
	CHECK(r->entries[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
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
	auto r = m.run(m.conn.search({ .base = ldap::dn{} }));
	REQUIRE(r.has_value());
	CHECK(r->entries.empty());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	// The empty DN, subtree, (objectClass=*), all user attributes, no limits.
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
	CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
	m.check_server();
}

TEST_CASE("connection: search returns a search_result on the limit codes", "[net][connection]")
{
	mock_ldap m;
	ldap::message size_limit = done_msg(1, 4, "ou=people,dc=example,dc=org", "size limit");
	size_limit.controls.emplace_back("1.2.3.4", false, "v");
	ldap::message ok = done_msg(5, 0, "", "all there");
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
				ref_msg(1, { "ldap://b.example.org/ou=b,dc=example,dc=org" }),
				entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
				size_limit }),
	  answer({ entry_msg(2, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(2, 3) }),
	  answer({ done_msg(3, 11, "", "admin limit") }),
	  answer({ entry_msg(4, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(4, 53, "", "unwilling") }),
	  answer({ entry_msg(5, "uid=a,ou=people,dc=example,dc=org", "A"), ok }) });

	auto size = m.run(m.conn.search(people_search()));
	REQUIRE(size.has_value());
	CHECK_FALSE(size->is_success());
	CHECK(size->result_code == 4);
	REQUIRE(size->entries.size() == 2);
	CHECK(size->entries[0] == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
	CHECK(size->entries[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
	CHECK(size->references == ldap::string_list{ "ldap://b.example.org/ou=b,dc=example,dc=org" });
	CHECK(size->matched_dn == "ou=people,dc=example,dc=org");
	CHECK(size->diagnostic_message == "size limit");
	CHECK(size->controls == std::pmr::vector<ldap::control>{ ldap::control{ "1.2.3.4", false, "v" } });

	auto time = m.run(m.conn.search(people_search()));
	REQUIRE(time.has_value());
	CHECK(time->result_code == 3);
	CHECK(time->entries.size() == 1);

	auto admin_limit = m.run(m.conn.search(people_search()));
	REQUIRE(admin_limit.has_value());
	CHECK(admin_limit->result_code == 11);
	CHECK(admin_limit->entries.empty());
	CHECK(admin_limit->diagnostic_message == "admin limit");

	auto unwilling = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(unwilling.has_value());
	CHECK(unwilling.error().code == errc::unwilling_to_perform);
	CHECK(unwilling.error().diagnostic == "unwilling");

	auto all = m.run(m.conn.search(people_search()));
	REQUIRE(all.has_value());
	CHECK(all->is_success());
	CHECK(all->entries.size() == 1);
	CHECK(all->references.empty());
	CHECK(all->diagnostic_message == "all there");
	m.check_server();
}

TEST_CASE("connection: requests that cannot be encoded are not sent", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1) }) });

	auto negative = m.run(m.conn.search({ .base = ldap::dn{}, .size_limit = -1 }));
	REQUIRE_FALSE(negative.has_value());
	CHECK(negative.error().code == client_errc::encode_error);

	auto too_long = m.run(m.conn.search({ .base = ldap::dn{},
	  .time_limit = std::chrono::seconds(std::int64_t{ std::numeric_limits<std::int32_t>::max() } + 1) }));
	REQUIRE_FALSE(too_long.has_value());
	CHECK(too_long.error().code == client_errc::encode_error);
	CHECK_THAT(std::string(too_long.error().context), StartsWith("search \"\": time_limit"));

	auto negative_time = m.run(m.conn.search({ .base = ldap::dn{}, .time_limit = std::chrono::seconds(-1) }));
	REQUIRE_FALSE(negative_time.has_value());
	CHECK(negative_time.error().code == client_errc::encode_error);

	auto empty_filter = m.run(m.conn.search({ .base = ldap::dn{}, .filter = ldap::filter{} }));
	REQUIRE_FALSE(empty_filter.has_value());
	CHECK(empty_filter.error().code == client_errc::invalid_filter);

	CHECK(m.conn.is_open());
	CHECK(m.log.received.empty());
	// Failed encodes do not use up message ids: the next request gets 1.
	CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
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

TEST_CASE("connection: search_stream yields intermediate responses when asked", "[net][connection][intermediate]")
{
	// IntermediateResponses with a value, with controls, or with neither.
	ldap::message with_control{ 1, ldap::intermediate_response{ "1.2.3.6" } };
	with_control.controls.emplace_back("1.2.3.7", true, "c");
	auto entry_b = entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B");
	entry_b.controls.emplace_back("1.2.3.8", false, "state");
	auto ref = ref_msg(1, { "ldap://r1.example.org/" });
	ref.controls.emplace_back("1.2.3.9", false, std::nullopt);
	auto script = [&] {
		return answer(
		  { ldap::message{ 1, ldap::intermediate_response{ "1.3.6.1.4.1.4203.1.9.1.4", std::string("\xa0\x00", 2) } },
			entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
			ldap::message{ 1, ldap::intermediate_response{} },
			ref,
			with_control,
			entry_b,
			ldap::message{ 1, ldap::intermediate_response{ std::nullopt, "v" } },
			ref_msg(1, { "ldap://r2.example.org/", "ldap://r3.example.org/" }),
			done_msg(1) });
	};
	const auto drain_items = [](mock_ldap &m, ldap::search_stream &s) {
		std::vector<ldap::search_stream::item> items;
		while (true) {
			auto i = m.run(s.next_item());
			REQUIRE(i.has_value());
			if (!*i) {
				break;
			}
			items.push_back(std::move(**i));
		}
		return items;
	};
	const ldap::string_list all_refs{ "ldap://r1.example.org/", "ldap://r2.example.org/", "ldap://r3.example.org/" };

	SECTION("next_item() returns every message in order, with its controls")
	{
		std::pmr::monotonic_buffer_resource arena;// outlives the stream's posted cleanup
		mock_ldap m;
		m.serve({ script() });
		auto params = people_search();
		params.intermediate_responses = true;
		auto s = m.run(m.conn.search_stream(std::move(params), &arena));
		REQUIRE(s.has_value());
		const auto items = drain_items(m, *s);
		CHECK(s->done());
		CHECK(s->references() == all_refs);// next_item() keeps them there too
		REQUIRE(items.size() == 8);

		// Decoded into the stream's resource, controls included.
		const auto &sync_info = std::get<ldap::intermediate>(items[0]);
		CHECK(sync_info.response_name == "1.3.6.1.4.1.4203.1.9.1.4");
		CHECK(sync_info.response_value == std::pmr::string("\xa0\x00", 2));
		CHECK(sync_info.controls.empty());
		CHECK(sync_info.get_allocator().resource() == &arena);
		CHECK(sync_info.response_value->get_allocator().resource() == &arena);
		CHECK(sync_info.controls.get_allocator().resource() == &arena);

		const auto &a = std::get<ldap::search_entry>(items[1]);
		CHECK(static_cast<const ldap::entry &>(a) == expected_entry("uid=a,ou=people,dc=example,dc=org", "A"));
		CHECK(a.controls.empty());
		CHECK(a.get_allocator().resource() == &arena);

		const auto &empty = std::get<ldap::intermediate>(items[2]);
		CHECK_FALSE(empty.response_name.has_value());
		CHECK_FALSE(empty.response_value.has_value());
		CHECK(empty.controls.empty());

		const auto &r1 = std::get<ldap::search_reference>(items[3]);
		CHECK(r1.uris == ldap::string_list{ "ldap://r1.example.org/" });
		CHECK(r1.controls == std::pmr::vector<ldap::control>{ ldap::control{ "1.2.3.9" } });
		CHECK(r1.uris.get_allocator().resource() == &arena);
		CHECK(r1.controls[0].get_allocator().resource() == &arena);

		const auto &controlled = std::get<ldap::intermediate>(items[4]);
		CHECK(controlled.response_name == "1.2.3.6");
		CHECK_FALSE(controlled.response_value.has_value());
		REQUIRE(controlled.controls.size() == 1);
		CHECK(controlled.controls[0] == ldap::control{ "1.2.3.7", true, "c" });
		CHECK(controlled.controls[0].get_allocator().resource() == &arena);

		const auto &b = std::get<ldap::search_entry>(items[5]);
		CHECK(static_cast<const ldap::entry &>(b) == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));
		REQUIRE(b.controls.size() == 1);
		CHECK(b.controls[0] == ldap::control{ "1.2.3.8", false, "state" });
		CHECK(b.controls[0].get_allocator().resource() == &arena);
		CHECK(b.find("cn") != nullptr);// an entry, with entry's accessors

		// Allocator-aware: a plain copy is on the default resource, the
		// allocator-extended one on the given one.
		std::pmr::monotonic_buffer_resource other;
		const ldap::search_entry b_copy(b, &other);
		CHECK(b_copy == b);
		CHECK(b_copy.dn.get_allocator().resource() == &other);
		CHECK(b_copy.controls[0].get_allocator().resource() == &other);
		const ldap::search_entry b_plain(b);
		CHECK(b_plain.controls[0].get_allocator().resource() == std::pmr::get_default_resource());
		const ldap::search_reference r1_copy(r1, &other);
		CHECK(r1_copy == r1);
		CHECK(r1_copy.uris[0].get_allocator().resource() == &other);
		const ldap::intermediate i_copy(controlled, &other);
		CHECK(i_copy == controlled);
		CHECK(i_copy.response_name->get_allocator().resource() == &other);
		CHECK(i_copy.controls[0].get_allocator().resource() == &other);

		const auto &value_only = std::get<ldap::intermediate>(items[6]);
		CHECK_FALSE(value_only.response_name.has_value());
		CHECK(value_only.response_value == "v");

		const auto &r2 = std::get<ldap::search_reference>(items[7]);
		CHECK(r2.uris == ldap::string_list{ "ldap://r2.example.org/", "ldap://r3.example.org/" });
		CHECK(r2.controls.empty());

		auto again = m.run(s->next_item());// the end repeats without I/O
		REQUIRE(again.has_value());
		CHECK_FALSE(again->has_value());
		m.check_server();
	}
	SECTION("next() drops them on a stream that asked for them")
	{
		mock_ldap m;
		m.serve({ script() });
		auto params = people_search();
		params.intermediate_responses = true;
		auto s = m.run(m.conn.search_stream(std::move(params)));
		REQUIRE(s.has_value());
		auto entries = m.run(drain_stream(*s));
		REQUIRE(entries.has_value());
		CHECK(*entries
			  == std::vector{ expected_entry("uid=a,ou=people,dc=example,dc=org", "A"),
				expected_entry("uid=b,ou=people,dc=example,dc=org", "B") });
		CHECK(s->references() == all_refs);
		m.check_server();
	}
	SECTION("next() and next_item() mixed: each reads the next message")
	{
		mock_ldap m;
		m.serve({ script() });
		auto params = people_search();
		params.intermediate_responses = true;
		auto s = m.run(m.conn.search_stream(std::move(params)));
		REQUIRE(s.has_value());
		auto first = m.run(s->next_item());
		REQUIRE(first.has_value());
		REQUIRE(first->has_value());
		CHECK(std::holds_alternative<ldap::intermediate>(**first));
		auto a = m.run(s->next());// entry A
		REQUIRE(a.has_value());
		REQUIRE(a->has_value());
		CHECK((*a)->dn == "uid=a,ou=people,dc=example,dc=org");
		auto b = m.run(s->next());// skips an intermediate, r1, an intermediate
		REQUIRE(b.has_value());
		REQUIRE(b->has_value());
		CHECK((*b)->dn == "uid=b,ou=people,dc=example,dc=org");
		CHECK(s->references() == ldap::string_list{ "ldap://r1.example.org/" });
		auto rest = drain_items(m, *s);
		REQUIRE(rest.size() == 2);
		CHECK(std::holds_alternative<ldap::intermediate>(rest[0]));
		CHECK(std::holds_alternative<ldap::search_reference>(rest[1]));
		CHECK(s->references() == all_refs);
		m.check_server();
	}
	SECTION("without intermediate_responses they are skipped, next_item() included")
	{
		mock_ldap m;
		m.serve({ script() });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		const auto items = drain_items(m, *s);
		REQUIRE(items.size() == 4);
		CHECK(std::get<ldap::search_entry>(items[0]).dn == "uid=a,ou=people,dc=example,dc=org");
		CHECK(std::get<ldap::search_reference>(items[1]).uris == ldap::string_list{ "ldap://r1.example.org/" });
		CHECK(std::get<ldap::search_entry>(items[2]).controls.size() == 1);
		CHECK(std::get<ldap::search_reference>(items[3]).uris.size() == 2);
		CHECK(m.conn.is_open());
		m.check_server();
	}
	SECTION("search() skips them either way")
	{
		mock_ldap m;
		m.serve({ script() });
		auto params = people_search();
		params.intermediate_responses = true;
		auto r = m.run(m.conn.search(std::move(params)));
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 2);
		m.check_server();
	}
}

TEST_CASE("connection: search items move with an allocator", "[net][connection][intermediate]")
{
	// Long enough to be off the small-string buffer, so a steal keeps data().
	const std::string long_value(64, 'v');
	const std::string long_oid = "1.3.6.1.4.1.4203.1.9.1.2." + std::string(32, '7');
	std::pmr::monotonic_buffer_resource a;
	std::pmr::monotonic_buffer_resource b;

	SECTION("search_entry")
	{
		const auto make = [&] {
			ldap::search_entry e(&a);
			e.dn = "uid=someone-with-a-long-name,ou=people,dc=example,dc=org";
			e.attributes.emplace_back(
			  ldap::attribute{ "description" }, std::initializer_list<std::string_view>{ long_value });
			e.controls.emplace_back(long_oid, true, long_value);
			return e;
		};
		const auto expected = make();

		auto same = make();
		const auto *dn = same.dn.data();
		const auto *value = same.attributes[0].values[0].data();
		const auto *control_type = same.controls[0].type.data();
		const auto *control_value = same.controls[0].value->data();
		const ldap::search_entry stolen(std::move(same), &a);
		CHECK(stolen == expected);
		CHECK(stolen.dn.data() == dn);
		CHECK(stolen.attributes[0].values[0].data() == value);
		CHECK(stolen.controls[0].type.data() == control_type);
		CHECK(stolen.controls[0].value->data() == control_value);

		const ldap::search_entry copied(make(), &b);
		CHECK(copied == expected);
		CHECK(copied.get_allocator().resource() == &b);
		CHECK(copied.dn.get_allocator().resource() == &b);
		CHECK(copied.attributes.get_allocator().resource() == &b);
		CHECK(copied.attributes[0].values[0].get_allocator().resource() == &b);
		CHECK(copied.controls.get_allocator().resource() == &b);
		CHECK(copied.controls[0].type.get_allocator().resource() == &b);
		CHECK(copied.controls[0].value->get_allocator().resource() == &b);
	}
	SECTION("search_reference")
	{
		const auto make = [&] {
			ldap::search_reference r(&a);
			r.uris.emplace_back("ldap://referral.example.org/ou=people,dc=example,dc=org");
			r.controls.emplace_back(long_oid, false, long_value);
			return r;
		};
		const auto expected = make();

		auto same = make();
		const auto *uri = same.uris[0].data();
		const auto *control_value = same.controls[0].value->data();
		const ldap::search_reference stolen(std::move(same), &a);
		CHECK(stolen == expected);
		CHECK(stolen.uris[0].data() == uri);
		CHECK(stolen.controls[0].value->data() == control_value);

		const ldap::search_reference copied(make(), &b);
		CHECK(copied == expected);
		CHECK(copied.uris.get_allocator().resource() == &b);
		CHECK(copied.uris[0].get_allocator().resource() == &b);
		CHECK(copied.controls.get_allocator().resource() == &b);
		CHECK(copied.controls[0].type.get_allocator().resource() == &b);
		CHECK(copied.controls[0].value->get_allocator().resource() == &b);
	}
	SECTION("intermediate")
	{
		const auto make = [&] {
			ldap::intermediate i(&a);
			i.response_name.emplace(long_oid, &a);
			i.response_value.emplace(long_value, &a);
			i.controls.emplace_back(long_oid, true, long_value);
			return i;
		};
		const auto expected = make();

		auto same = make();
		const auto *name = same.response_name->data();
		const auto *value = same.response_value->data();
		const auto *control_value = same.controls[0].value->data();
		const ldap::intermediate stolen(std::move(same), &a);
		CHECK(stolen == expected);
		CHECK(stolen.response_name->data() == name);
		CHECK(stolen.response_value->data() == value);
		CHECK(stolen.controls[0].value->data() == control_value);

		const ldap::intermediate copied(make(), &b);
		CHECK(copied == expected);
		CHECK(copied.get_allocator().resource() == &b);
		CHECK(copied.response_name->get_allocator().resource() == &b);
		CHECK(copied.response_value->get_allocator().resource() == &b);
		CHECK(copied.controls.get_allocator().resource() == &b);
		CHECK(copied.controls[0].type.get_allocator().resource() == &b);
		CHECK(copied.controls[0].value->get_allocator().resource() == &b);
	}
	SECTION("a std::pmr::vector<intermediate> keeps its resource on its elements")
	{
		// extended_result::intermediates relies on uses-allocator construction.
		std::pmr::vector<ldap::intermediate> v(&a);
		v.emplace_back(ldap::intermediate_response{ long_oid, long_value },
		  std::pmr::vector<ldap::control>{ ldap::control{ long_oid, false, long_value } });
		const auto capacity = v.capacity();
		while (v.capacity() == capacity) {// until it reallocates
			v.emplace_back(ldap::intermediate{ ldap::intermediate_response{ std::nullopt, long_value }, {} });
		}
		for (const auto &i : v) {
			CHECK(i.get_allocator().resource() == &a);
			CHECK(i.response_value->get_allocator().resource() == &a);
			CHECK(i.controls.get_allocator().resource() == &a);
		}
		CHECK(v[0].response_name->get_allocator().resource() == &a);
		REQUIRE(v[0].controls.size() == 1);
		CHECK(v[0].controls[0] == ldap::control{ long_oid, false, long_value });
		CHECK(v[0].controls[0].value->get_allocator().resource() == &a);
	}
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
	  // Late responses after the AbandonRequest are dropped.
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
		run_on(m.ioc, m.conn.executor(), [&s] { *s = ldap::search_stream{}; });
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

TEST_CASE("connection: off the strand, a stream's destructor and close() take effect when the io_context runs",
  "[net][connection][pmr]")
{
	SECTION("a stream destroyed off the strand")
	{
		counting_resource arena;// outlives the posted abandon, which frees the stream's queue on it
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
					entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B") }),
		  step{} });// reads the AbandonRequest
		{
			auto s = m.run(m.conn.search_stream(people_search(), &arena));
			REQUIRE(s.has_value());
			auto a = m.run(s->next());
			REQUIRE(a.has_value());
			REQUIRE(a->has_value());
			drive_until(m.ioc, [&arena] { return arena.outstanding() > 0; });// B queued on the arena
		}
		CHECK(m.conn.outstanding() == 1);// not abandoned yet
		CHECK(arena.outstanding() > 0);
		CHECK(m.log.received.size() == 1);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
		CHECK(m.conn.outstanding() == 0);
		CHECK(arena.outstanding() == 0);
		CHECK(m.conn.is_open());
	}
	SECTION("close() off the strand")
	{
		mock_ldap m;
		m.serve({ step{}, client_hangs_up() });// reads the search, never answers
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		drive_until(m.ioc, [&m] { return m.log.received.size() == 1; });
		m.conn.close();
		CHECK_FALSE(m.conn.is_open());// at once
		CHECK(m.conn.outstanding() == 0);
		CHECK_FALSE(m.server.done());// the socket is closed by the posted work
		m.sockets.client.close();// a wrapped transport leaves the socket open
		auto e = m.run(s->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == ldap::client_errc::not_connected);
		m.check_server();
	}
	SECTION("once the io_context is stopped, at once")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }), step{} });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		m.ioc.stop();
		*s = ldap::search_stream{};
		CHECK(m.conn.outstanding() == 0);
		m.ioc.restart();
		drive_until(m.ioc, [&m] { return m.log.received.size() == 2; });
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
	}
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
	CHECK(second.error().context
		  == "search ou=people,dc=example,dc=org during an earlier next() or next_item() on this search_stream");
	m.conn.close();
	drive_until(m.ioc, [&first] { return first.done(); });
	REQUIRE_FALSE(first.get().has_value());
	CHECK(first.get().error().code == client_errc::not_connected);
}

TEST_CASE("connection: next() and next_item() refuse each other while suspended", "[net][connection][intermediate]")
{
	const std::string_view busy =
	  "search ou=people,dc=example,dc=org during an earlier next() or next_item() on this search_stream";
	mock_ldap m;
	m.serve({ step{} });// reads the search, does not answer
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());

	SECTION("next_item() during next()")
	{
		outcome<ldap::result<std::optional<ldap::entry>>> first;
		spawn(m.ioc, s->next(), first);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		CHECK_FALSE(first.done());
		auto second = m.run(s->next_item());
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == client_errc::operation_in_progress);
		CHECK(second.error().context == busy);
		m.conn.close();
		drive_until(m.ioc, [&first] { return first.done(); });
		REQUIRE_FALSE(first.get().has_value());
		CHECK(first.get().error().code == client_errc::not_connected);
	}
	SECTION("next() during next_item()")
	{
		outcome<ldap::result<std::optional<ldap::search_stream::item>>> first;
		spawn(m.ioc, s->next_item(), first);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		CHECK_FALSE(first.done());
		auto second = m.run(s->next());
		REQUIRE_FALSE(second.has_value());
		CHECK(second.error().code == client_errc::operation_in_progress);
		CHECK(second.error().context == busy);
		m.conn.close();
		drive_until(m.ioc, [&first] { return first.done(); });
		REQUIRE_FALSE(first.get().has_value());
		CHECK(first.get().error().code == client_errc::not_connected);
	}
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
		auto nc = m.run(m.conn.search({ .base = ldap::dn{} }));
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
	SECTION("a live connection move-assigned over one with an open stream closes it")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		socket_pair other(m.ioc);
		m.conn = ldap::connection(m.ioc, net::transport::wrap(socket_ref{ &other.client }, "other"));
		CHECK(m.conn.is_open());
		auto e = m.run(s->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == client_errc::not_connected);
		m.conn.close();
		other.client.close();
		other.server.close();
		drive(m.ioc);
	}
	SECTION("a task created before a move completes")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 1, ldap::add_response{ ldap::ldap_result{ 0 } } } }) });
		auto added = m.conn.add({ .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" } });
		ldap::connection moved = std::move(m.conn);
		CHECK(moved.is_open());
		auto r = m.run(std::move(added));
		REQUIRE(r.has_value());
		m.check_server();
	}
}

TEST_CASE("connection: copies are handles on one session", "[net][connection]")
{
	static_assert(std::is_nothrow_copy_constructible_v<ldap::connection>);
	static_assert(std::is_nothrow_copy_assignable_v<ldap::connection>);

	SECTION("a copy keeps the session when the original is destroyed")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 1, ldap::add_response{ ldap::ldap_result{ 0 } } } }) });
		std::optional<ldap::connection> copy(m.conn);
		CHECK(copy->name() == m.conn.name());
		m.conn = ldap::connection{};
		CHECK(copy->is_open());
		auto r = m.run(copy->add({ .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" } }));
		REQUIRE(r.has_value());
		m.check_server();
		bool closed = false;
		ldap::detail::set_close_hook(*copy, [&closed] noexcept { closed = true; });
		drive(m.ioc);
		copy.reset();
		drive(m.ioc);
		CHECK(closed);
	}
	SECTION("a stream outlives every handle; the last one closes the connection")
	{
		mock_ldap m;
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A") }), step{} });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		ldap::connection copy = m.conn;
		m.conn = ldap::connection{};
		CHECK(copy.is_open());
		REQUIRE(m.run(s->next()).has_value());
		copy = ldap::connection{};
		auto e = m.run(s->next());
		REQUIRE_FALSE(e.has_value());
		CHECK(e.error().code == client_errc::not_connected);
		CHECK(s->done());
	}
	SECTION("close() through one copy ends the session for every copy")
	{
		mock_ldap m;
		m.serve({});
		const ldap::connection copy = m.conn;
		ldap::connection other = copy;
		other.close();
		CHECK_FALSE(m.conn.is_open());
		CHECK_FALSE(copy.is_open());
		auto r = m.run(m.conn.add({ .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" } }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::not_sent);
		CHECK(r.error().code == ldap::cond::connection_lost);
		auto u = m.run(m.conn.unbind());
		REQUIRE_FALSE(u.has_value());
		CHECK(u.error().code == client_errc::not_connected);
		CHECK(m.log.received.empty());
	}
	SECTION("unbind() through one copy ends the session for every copy")
	{
		mock_ldap m;
		m.serve({ step{} });
		ldap::connection copy = m.conn;
		REQUIRE(m.run(copy.unbind()).has_value());
		CHECK_FALSE(m.conn.is_open());
		auto r = m.run(m.conn.search({ .base = ldap::dn{} }));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::not_sent);
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::unbind_request>(m.log.received[0].op));
	}
	SECTION("assigning over a handle releases it; over the last one closes it")
	{
		mock_ldap m;
		m.serve({});
		socket_pair sockets(m.ioc);
		ldap::connection a(m.ioc, net::transport::wrap(socket_ref{ &sockets.client }, "other"));
		bool closed = false;
		ldap::detail::set_close_hook(a, [&closed] noexcept { closed = true; });
		ldap::connection b = a;
		auto &self = a;
		a = self;
		CHECK(a.is_open());
		a = m.conn;
		CHECK(a.name() == "mock");
		CHECK(b.is_open());
		drive(m.ioc);
		CHECK_FALSE(closed);
		b = std::move(a);
		CHECK(b.name() == "mock");
		drive(m.ioc);
		CHECK(closed);
		CHECK(m.conn.is_open());
		sockets.client.close();
		sockets.server.close();
		drive(m.ioc);
	}
}

// Every operation of a moved-from connection fails at once with
// not_connected, and its accessors answer as for a closed one.
TEST_CASE("connection: operations on a moved-from connection", "[net][connection]")
{
	mock_ldap m;
	m.serve({});
	const ldap::connection moved = std::move(m.conn);
	CHECK(moved.executor().get_inner_executor() == m.ioc.get_executor());
	ldap::connection &c = m.conn;
	CHECK_FALSE(c.is_open());
	CHECK(c.name().empty());
	CHECK(c.outstanding() == 0);
	CHECK(c.bind_count() == 0);
	CHECK_FALSE(c.is_tls());
	CHECK(c.peer_certificate().empty());
	CHECK(c.channel_bindings().tls_server_end_point.empty());
	c.close();// does nothing

	const ldap::dn who{ "uid=jdoe,ou=people,dc=example,dc=org" };
	const auto refused = [](const auto &r, std::string_view context) {
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::not_connected);
		CHECK(std::string_view(r.error().context) == context);
	};
	refused(m.run(c.simple_bind(who, "secret")), "bind uid=jdoe,ou=people,dc=example,dc=org");
	ldap::sasl_external external;
	refused(m.run(c.sasl_bind(external)), "sasl bind EXTERNAL");
	refused(m.run(c.unbind()), "unbind");
	auto schema = m.run(ldap::load_schema(c));
	REQUIRE_FALSE(schema.has_value());
	CHECK(schema.error().code == client_errc::not_connected);
	CHECK(std::string_view(schema.error().context) == "load schema: search \"\"");
	refused(m.run(c.add({ .entry = who })), "add uid=jdoe,ou=people,dc=example,dc=org");
	refused(m.run(c.modify({ .object = who })), "modify uid=jdoe,ou=people,dc=example,dc=org");
	refused(m.run(c.del({ .entry = who })), "delete uid=jdoe,ou=people,dc=example,dc=org");
	refused(m.run(c.modify_dn({ .entry = who, .new_rdn = ldap::rdn{ "uid=j" } })),
	  "modify DN uid=jdoe,ou=people,dc=example,dc=org");
	refused(m.run(c.compare({ .entry = who, .attribute = "uid", .value = "jdoe" })),
	  "compare uid=jdoe,ou=people,dc=example,dc=org");
	refused(m.run(c.extended({ .name = "1.2.3" })), "extended operation 1.2.3");
	refused(m.run(c.search_stream({ .base = ldap::dn{} })), "search \"\"");
	refused(m.run(ldap::search_paged(c, { .base = ldap::dn{} }, 10)), "search \"\"");
	refused(m.run(c.start_transaction()), "start transaction");
	refused(m.run(c.end_transaction(std::string("txn"))), "end transaction");
	refused(m.run(ldap::transaction::begin(c)), "start transaction");
	refused(m.run(ldap::reset_password(c, who, "new")),
	  "reset password uid=jdoe,ou=people,dc=example,dc=org: password modify (RFC 3062)");
	refused(m.run(ldap::password_modify(c, {})), "password modify");
	auto change = m.run(ldap::change_password(c, who, "old", "new"));
	REQUIRE_FALSE(change.has_value());
	CHECK(change.error().code == client_errc::not_connected);
	auto who_am_i = m.run(ldap::who_am_i(c));
	REQUIRE_FALSE(who_am_i.has_value());
	CHECK(who_am_i.error().code == client_errc::not_connected);
	CHECK(m.log.received.empty());
}

// A closed connection refuses what starts with a search or a bind: not
// sent.
TEST_CASE("connection: load_schema and sasl_bind on a closed connection", "[net][connection]")
{
	mock_ldap m;
	m.serve({});
	m.conn.close();
	auto s = m.run(ldap::load_schema(m.conn));
	REQUIRE_FALSE(s.has_value());
	CHECK(s.error().code == client_errc::not_sent);
	CHECK_THAT(std::string(s.error().context), StartsWith("load schema"));
	ldap::sasl_external external;
	auto b = m.run(m.conn.sasl_bind(external));
	REQUIRE_FALSE(b.has_value());
	CHECK(b.error().code == client_errc::not_sent);
	CHECK(m.log.received.empty());
}

// The search_stream and paged_search accessors of a default (moved-from)
// object, and a self move-assignment, which keeps the search.
TEST_CASE("connection: default and self-assigned streams", "[net][connection]")
{
	ldap::search_stream none;
	CHECK(none.done());
	CHECK(none.references().empty());
	CHECK(none.controls().empty());
	CHECK(none.reference_urls().empty());
	corosio::io_context ioc;
	auto item = finish(ioc, none.next_item());
	REQUIRE_FALSE(item.has_value());
	CHECK(item.error().code == client_errc::not_connected);

	ldap::paged_search no_pages;
	CHECK(no_pages.done());
	CHECK(no_pages.pages() == 0);
	CHECK(no_pages.references().empty());
	CHECK(no_pages.reference_urls().empty());
	CHECK(no_pages.controls().empty());
	auto page = finish(ioc, no_pages.next());
	REQUIRE_FALSE(page.has_value());
	CHECK(page.error().code == client_errc::not_connected);

	mock_ldap m;
	m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"), done_msg(1) }) });
	auto s = m.run(m.conn.search_stream(people_search()));
	REQUIRE(s.has_value());
	ldap::search_stream &alias = *s;
	*s = std::move(alias);
	auto entries = m.run(drain_stream(*s));
	REQUIRE(entries.has_value());
	CHECK(entries->size() == 1);
	m.check_server();
}

// A stream that ended with an error repeats it; one that ended with
// references gives them as URLs.
TEST_CASE("connection: search_stream after its end", "[net][connection]")
{
	SECTION("an error is returned again by every next()")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1, 32, "dc=example,dc=org", "no such entry") }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		auto first = m.run(s->next());
		REQUIRE_FALSE(first.has_value());
		CHECK(first.error().code == errc::no_such_object);
		CHECK(s->done());
		auto again = m.run(s->next_item());
		REQUIRE_FALSE(again.has_value());
		CHECK(again.error().code == errc::no_such_object);
		m.check_server();
	}
	SECTION("references as URLs, an invalid one left out")
	{
		mock_ldap m;
		m.serve({ answer({ ref_msg(1, { "ldap://a.example.org/dc=example,dc=org", "not a url" }), done_msg(1) }) });
		auto s = m.run(m.conn.search_stream(people_search()));
		REQUIRE(s.has_value());
		auto entries = m.run(drain_stream(*s));
		REQUIRE(entries.has_value());
		CHECK(entries->empty());
		CHECK(s->references().size() == 2);
		const auto urls = s->reference_urls();
		REQUIRE(urls.size() == 1);
		CHECK(urls[0].host() == "a.example.org");
		m.check_server();
	}
}

// Requests whose controls do not encode are not sent (an assertion with
// the empty filter), and do not use up a message id.
TEST_CASE("connection: update and compare requests whose controls do not encode", "[net][connection]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1, ldap::del_response{ ldap::ldap_result{ 0, "", "" } } } }) });
	const ldap::dn who{ "uid=jdoe,ou=people,dc=example,dc=org" };
	const auto not_encoded = [](const auto &r) {
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::invalid_filter);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("assertion"));
	};
	not_encoded(m.run(m.conn.add({ .entry = who, .controls = { ldap::assertion{} } })));
	not_encoded(m.run(m.conn.modify({ .object = who, .controls = { ldap::assertion{} } })));
	not_encoded(m.run(m.conn.del({ .entry = who, .controls = { ldap::assertion{} } })));
	not_encoded(
	  m.run(m.conn.modify_dn({ .entry = who, .new_rdn = ldap::rdn{ "uid=j" }, .controls = { ldap::assertion{} } })));
	not_encoded(
	  m.run(m.conn.compare({ .entry = who, .attribute = "uid", .value = "jdoe", .controls = { ldap::assertion{} } })));
	CHECK(m.log.received.empty());
	CHECK(m.run(m.conn.del({ .entry = who })).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0].id == 1);
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

	auto after = m.run(m.conn.search({ .base = ldap::dn{} }));
	REQUIRE_FALSE(after.has_value());
	CHECK(after.error().code == client_errc::not_sent);
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

TEST_CASE("RFC 4511 4.3: requests started while unbind waits for the writer are refused", "[net][connection][rfc]")
{
	tcp_mock_ldap m({}, socket_buffers::small);// over TCP, so StartTLS gets past its transport check
	REQUIRE(m.buffered_at_most() < oversized_add_value);
	outcome<ldap::result<ldap::response>> add;
	spawn(m.ioc, m.conn.add(oversized_add()), add);
	outcome<ldap::result<void>> unbind;
	spawn(m.ioc, m.conn.unbind(), unbind);
	drive_until(m.ioc, [&add] { return add.done(); });// abandoned by the unbind
	REQUIRE_FALSE(add.get().has_value());
	CHECK(add.get().error().code == client_errc::not_connected);
	REQUIRE_FALSE(unbind.done());
	CHECK(m.conn.is_open());

	auto s = m.run(m.conn.search(people_search()));
	REQUIRE_FALSE(s.has_value());
	CHECK(s.error().code == client_errc::not_sent);
	CHECK(s.error().context == "search ou=people,dc=example,dc=org: connection closing (unbind)");
	auto t = m.run(m.conn.start_tls());
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == client_errc::not_sent);
	CHECK(t.error().context == "start tls: connection closing (unbind)");
	auto u = m.run(m.conn.unbind());
	REQUIRE_FALSE(u.has_value());
	CHECK(u.error().code == client_errc::not_connected);
	CHECK_FALSE(unbind.done());

	// The server reads: the AddRequest, the UnbindRequest, then the close.
	m.serve({ step{}, step{}, client_hangs_up() });
	drive_until(m.ioc, [&unbind] { return unbind.done(); });
	CHECK(unbind.get().has_value());
	CHECK_FALSE(m.conn.is_open());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(std::holds_alternative<ldap::add_request>(m.log.received[0].op));
	CHECK(m.log.received[1] == ldap::message{ 2, ldap::unbind_request{} });
}

// Each frame allocation unbind() makes behind the busy writer fails in
// turn: unbind() rethrows and the connection is closed.
TEST_CASE("connection: a failed allocation in unbind closes the connection", "[net][connection][oom]")
{
	// True if the failing-th allocation threw, false if unbind() waited.
	auto fail_one = [](std::size_t failing, bool other) {
		failing_frames frames;// outlives the io_context's coroutines
		const clear_frame_allocator clear;
		outcome<ldap::result<ldap::response>> add;// outlive `m`: what still waits ends with it
		outcome<ldap::result<void>> unbind;
		tcp_mock_ldap m({}, socket_buffers::small);
		REQUIRE(m.buffered_at_most() < oversized_add_value);
		m.ioc.set_frame_allocator(&frames);
		spawn(m.ioc, m.conn.add(oversized_add()), add);
		while (m.ioc.poll() != 0) {}// the writer parks on its write
		m.ioc.restart();
		spawn(m.ioc, m.conn.unbind(), unbind);
		frames.fail_at(failing, other);
		while (m.ioc.poll() != 0) {}
		m.ioc.restart();
		const std::size_t tried = frames.count();
		const bool failed = unbind.done();
		frames.fail_at(0);
		if (!failed) {
			CHECK(m.conn.is_open());// waiting for the writer
			m.serve({ step{}, step{}, client_hangs_up() });
			drive_until(m.ioc, [&unbind] { return unbind.done(); });
			CHECK(unbind.get().has_value());
			CHECK_FALSE(m.conn.is_open());
			return false;
		}
		CHECK(tried == failing);
		if (other) {
			CHECK_THROWS_AS(unbind.get(), std::runtime_error);
		} else {
			CHECK_THROWS_AS(unbind.get(), std::bad_alloc);
		}
		CHECK_FALSE(m.conn.is_open());
		REQUIRE(add.done());// abandoned by the unbind
		CHECK_FALSE(add.get().has_value());
		auto later = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == client_errc::not_sent);
		CHECK_THAT(std::string(later.error().context),
		  ContainsSubstring(other ? ": connection closed by an earlier error: connection closed: unbind aborted"
								  : ": connection closed by an earlier error: "));
		CHECK_THAT(std::string(later.error().context), !ContainsSubstring("unbind)"));
		auto again = m.run(m.conn.unbind());
		REQUIRE_FALSE(again.has_value());
		CHECK(again.error().code == client_errc::not_connected);
		return true;
	};
	for (const bool other : { false, true }) {
		CAPTURE(other);
		std::size_t failing = 1;
		while (fail_one(failing, other)) {
			++failing;
		}
		CHECK(failing > 2);// finish_unbind's, wait_write_idle's, its lambda's
	}
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
	CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
	CHECK(m.run(m.conn.search(people_search())).has_value());
	CHECK(m.run(m.conn.simple_bind(ldap::dn{}, "")).has_value());
	CHECK(m.run(m.conn.unbind()).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 5);
	std::int32_t id = 0;
	for (const auto &msg : m.log.received) {
		CHECK(msg.id == ++id);
	}
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
		{ .name = "wrong message id",
		  .replies = { bytes_of(bind_resp(7)) },
		  .code = client_errc::unexpected_response,
		  .context =
			"bind cn=admin,dc=example,dc=org: read mock: message with id 7, which matches no outstanding request" },
		{ .name = "wrong operation",
		  .replies = { bytes_of(done_msg(1)) },
		  .code = client_errc::unexpected_response,
		  .context = "bind cn=admin,dc=example,dc=org: read mock: SearchResultDone with message id 1 in response to a "
					 "BindRequest" },
		{ .name = "entry for a bind",
		  .replies = { bytes_of(entry_msg(1, "cn=x", "x")) },
		  .code = client_errc::unexpected_response,
		  .context = "bind cn=admin,dc=example,dc=org: read mock: SearchResultEntry with message id 1 in response to a "
					 "BindRequest" },
		{ .name = "request operation from the server",
		  .replies = { bytes_of(bind_request_msg(1)) },
		  .code = client_errc::unsupported_operation,
		  .context = nullptr },
		{ .name = "id 0 that is not a notification",
		  .replies = { bytes_of(bind_resp(0)) },
		  .code = client_errc::unexpected_response,
		  .context = "bind cn=admin,dc=example,dc=org: read mock: BindResponse with message id 0" },
		{ .name = "not a PDU",
		  .replies = { std::string("\x04\x01\x00", 3) },
		  .code = client_errc::decode_error,
		  .context = nullptr },
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
			if (c.context != nullptr) {
				CHECK(r.error().context == c.context);
			}
			CHECK_FALSE(m.conn.is_open());
			m.check_server();

			auto later = m.run(m.conn.search({ .base = ldap::dn{} }));
			REQUIRE_FALSE(later.has_value());
			CHECK(later.error().code == client_errc::not_sent);
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
		CHECK(later.error().code == client_errc::not_sent);
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
		CHECK(r->entries.size() == 1);
		CHECK(m.conn.is_open());
		m.check_server();
	}
	SECTION("a notification that does not decode closes the connection, naming the transport")
	{
		mock_ldap m;
		// An LDAPMessage with id 0 whose protocolOp is an OCTET STRING.
		m.serve({ step{ .replies = { std::string("\x30\x05\x02\x01\x00\x04\x00", 7) } } });
		auto r = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unsupported_operation);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("read mock"));
		CHECK_FALSE(m.conn.is_open());
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
	outcome<ldap::result<ldap::search_result>> out;
	spawn(m.ioc, stop.get_token(), m.conn.search({ .base = ldap::dn{} }), out);
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

using entries = ldap::result<ldap::search_result>;
using event_race = std::variant<std::error_code, entries, std::tuple<>>;

// A search raced against `event`.
auto search_or(ldap::connection &c, capy::async_event &event) -> capy::task<event_race>
{
	co_return co_await capy::when_any(ldap::raceable(c.search({ .base = ldap::dn{} })), event.wait());
}

// A search raced against a timer.
auto search_or_delay(ldap::connection &c, std::chrono::milliseconds d) -> capy::task<event_race>
{
	co_return co_await capy::when_any(ldap::raceable(c.search({ .base = ldap::dn{} })), corosio::delay(d));
}

using bind_race = std::variant<std::error_code, ldap::result<void>, std::tuple<>>;

// A simple bind raced against a timer.
auto bind_or_delay(ldap::connection &c, std::chrono::milliseconds d) -> capy::task<bind_race>
{
	co_return co_await capy::when_any(
	  ldap::raceable(c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")), corosio::delay(d));
}

// The search was abandoned and the connection still works.
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
		CHECK(r->entries.size() == 1);
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
	SECTION("the awaiting task stopped before the race starts: nothing wins, the search is not sent")
	{
		m.serve({ answer({ bind_resp(1) }) });
		std::stop_source stop;
		stop.request_stop();
		spawn(m.ioc, stop.get_token(), search_or(m.conn, event), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().index() == 0);
		CHECK(std::get<0>(out.get()) == ldap::cond::canceled);
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
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
		spawn(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.search({ .base = ldap::dn{} })), out);
		drive_until(m.ioc, [&out] { return out.done(); });
		REQUIRE(out.get().has_value());
		CHECK(out.get()->entries.size() == 1);
		cancel.request_stop();
		m.check_server();
		CHECK(out.get().has_value());
		CHECK(m.log.received.size() == 1);
		CHECK(m.conn.outstanding() == 0);
	}
	SECTION("stopped mid-operation: the operation is abandoned")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		spawn(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.search({ .base = ldap::dn{} })), out);
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
	SECTION("a search stopped before it starts is not sent: the connection stays open")
	{
		m.serve({ answer({ bind_resp(1) }) });
		cancel.request_stop();
		auto r = m.run(ldap::with_stop(cancel.get_token(), m.conn.search({ .base = ldap::dn{} })));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::canceled);
		CHECK(r.error().context == "search \"\"");
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
	}
	SECTION("a paged search stopped before it starts is not sent")
	{
		m.serve({ answer({ bind_resp(1) }) });
		cancel.request_stop();
		auto r = m.run(ldap::with_stop(cancel.get_token(), ldap::search_paged(m.conn, { .base = ldap::dn{} }, 10)));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::canceled);
		CHECK(r.error().context == "search \"\"");
		CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
	}
	SECTION("an update stopped before it starts is not sent, so it cannot be applied")
	{
		m.serve({ answer({ bind_resp(1) }) });
		cancel.request_stop();
		auto add = m.run(ldap::with_stop(cancel.get_token(),
		  m.conn.add({ .entry = ldap::dn{ "cn=x,dc=example,dc=org" }, .attributes = { { "cn", { "x" } } } })));
		REQUIRE_FALSE(add.has_value());
		CHECK(add.error().code == ldap::cond::canceled);
		CHECK(add.error().context == "add cn=x,dc=example,dc=org");
		auto mod = m.run(ldap::with_stop(cancel.get_token(),
		  m.conn.modify(
			{ .object = ldap::dn{ "cn=x,dc=example,dc=org" }, .changes = { ldap::mod::replace("cn", { "y" }) } })));
		REQUIRE_FALSE(mod.has_value());
		CHECK(mod.error().code == ldap::cond::canceled);
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
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
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::search_request>(m.log.received[0].op));
	}
	SECTION("the awaiting task's own stop token still cancels it")
	{
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		std::stop_source outer;
		spawn(
		  m.ioc, outer.get_token(), ldap::with_stop(cancel.get_token(), m.conn.search({ .base = ldap::dn{} })), out);
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

namespace {

// Awaits `op`, then stops `ioc`.
auto then_stop_ioc(corosio::io_context &ioc, capy::task<entries> op) -> capy::task<entries>
{
	auto r = co_await std::move(op);
	ioc.stop();
	co_return r;
}

}// namespace

// The stop is requested from the test thread while run() executes on a
// worker; assertions after the join.
TEST_CASE("with_stop: stopped from another thread while the io_context runs", "[net][connection][cancel]")
{
	const auto stopped_while_running = [](const ldap::connection_options &options) {
		std::stop_source cancel;
		outcome<entries> out;
		mock_ldap m(options);
		m.serve({ step{}, step{}, answer({ bind_resp(3) }) });
		spawn(
		  m.ioc, then_stop_ioc(m.ioc, ldap::with_stop(cancel.get_token(), m.conn.search({ .base = ldap::dn{} }))), out);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		REQUIRE_FALSE(out.done());

		std::latch running{ 1 };
		capy::run_async(m.ioc.get_executor())([](std::latch &l) -> capy::task<void> {
			l.count_down();
			co_return;
		}(running));
		std::thread io([&m] { m.ioc.run_for(io_limit); });
		running.wait();
		cancel.request_stop();
		io.join();
		m.ioc.restart();

		REQUIRE(out.done());
		REQUIRE_FALSE(out.get().has_value());
		CHECK(out.get().error().code == ldap::cond::canceled);
		CHECK(out.get().error().context == "search \"\" (abandoned)");
		check_abandoned_and_usable(m);
	};

	SECTION("waiting for the response") { stopped_while_running({}); }
	SECTION("with a timeout: the stop also cancels the timer")
	{
		stopped_while_running({ .operation_timeout = std::chrono::hours(1) });
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
	outcome<ldap::result<ldap::search_result>> a;
	outcome<ldap::result<ldap::search_result>> b;
	spawn(m.ioc, m.conn.search(people_search()), a);
	spawn(m.ioc, m.conn.search({ .base = ldap::dn{ "ou=groups,dc=example,dc=org" } }), b);
	drive_until(m.ioc, [&] { return a.done() && b.done(); });
	REQUIRE(a.get().has_value());
	REQUIRE(b.get().has_value());
	REQUIRE(a.get()->entries.size() == 3);
	CHECK(a.get()->entries[0] == expected_entry("uid=a1,ou=people,dc=example,dc=org", "A1"));
	CHECK(a.get()->entries[2] == expected_entry("uid=a3,ou=people,dc=example,dc=org", "A3"));
	REQUIRE(b.get()->entries.size() == 1);
	CHECK(b.get()->entries[0] == expected_entry("uid=b1,ou=groups,dc=example,dc=org", "B1"));
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
		auto r = m.run(m.conn.search({ .base = ldap::dn{}, .timeout = std::chrono::milliseconds(100) }));
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
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
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
	m.serve({ step{ .read_request = true, .replies = {}, .close_after = true } });
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<ldap::search_result>> search;
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

TEST_CASE("connection: requests the writer never took fail with not_sent", "[net][connection][not_sent]")
{
	SECTION("the connection is closed before the request is submitted")
	{
		mock_ldap m;
		m.conn.close();
		auto s = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == client_errc::not_sent);
		CHECK(s.error().code == ldap::cond::connection_lost);
		CHECK(s.error().context == "search ou=people,dc=example,dc=org: connection closed");
		auto d = m.run(m.conn.del({ .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" } }));
		REQUIRE_FALSE(d.has_value());
		CHECK(d.error().code == client_errc::not_sent);
		auto b = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
		REQUIRE_FALSE(b.has_value());
		CHECK(b.error().code == client_errc::not_sent);
		auto st = m.run(m.conn.search_stream(people_search()));
		REQUIRE_FALSE(st.has_value());
		CHECK(st.error().code == client_errc::not_sent);
	}
	SECTION("after a failure closed the connection, the failure is named")
	{
		mock_ldap m;
		m.serve({ step{ .read_request = true, .replies = {}, .close_after = true } });
		auto first = m.run(m.conn.search(people_search()));
		REQUIRE_FALSE(first.has_value());
		CHECK(first.error().code != client_errc::not_sent);// it was sent
		CHECK(first.error().code == ldap::cond::connection_lost);
		auto later = m.run(m.conn.modify({ .object = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" } }));
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == client_errc::not_sent);
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("connection closed by an earlier error"));
		m.check_server();
		CHECK(m.log.received.size() == 1);
	}
	SECTION("a request held behind a bind that fails by losing the connection")
	{
		mock_ldap m;
		// Reads the bind, then hangs up: the update held behind it is never sent.
		m.serve({ step{ .read_request = true, .replies = {}, .close_after = true } });
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<ldap::response>> held;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		spawn(m.ioc, m.conn.del({ .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" } }), held);
		drive_until(m.ioc, [&] { return bind.done() && held.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code != client_errc::not_sent);
		CHECK(bind.get().error().code == ldap::cond::connection_lost);
		REQUIRE_FALSE(held.get().has_value());
		CHECK(held.get().error().code == client_errc::not_sent);
		CHECK(held.get().error().code == ldap::cond::connection_lost);
		// The context still says what closed the connection.
		CHECK(held.get().error().context == "delete uid=a,ou=people,dc=example,dc=org: read mock: connection closed");
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
	}
	SECTION("a request held behind a bind given up on (timeout closes the connection)")
	{
		mock_ldap m({ .operation_timeout = std::chrono::milliseconds(50) });
		m.serve({ step{}, step{} });// reads the bind, never answers
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<ldap::response>> held;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		spawn(m.ioc,
		  m.conn.add({ .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" }, .attributes = { { "cn", { "a" } } } }),
		  held);
		drive_until(m.ioc, [&] { return bind.done() && held.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code == ldap::cond::timeout);
		REQUIRE_FALSE(held.get().has_value());
		CHECK(held.get().error().code == client_errc::not_sent);
		m.sockets.client.close();// closing a wrapped transport leaves the socket open
		drive_until(m.ioc, [&m] { return m.server.done(); });
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
	}
	SECTION("a request queued behind a PDU the writer is still writing")
	{
		tcp_mock_ldap m({}, socket_buffers::small);
		REQUIRE(m.buffered_at_most() < oversized_add_value);
		outcome<ldap::result<ldap::response>> add;
		outcome<ldap::result<ldap::search_result>> queued;
		spawn(m.ioc, m.conn.add(oversized_add()), add);
		spawn(m.ioc, m.conn.search(people_search()), queued);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 2; });
		m.conn.close();
		drive_until(m.ioc, [&] { return add.done() && queued.done(); });
		REQUIRE_FALSE(add.get().has_value());
		CHECK(add.get().error().code == client_errc::not_connected);// the writer had it: maybe seen
		REQUIRE_FALSE(queued.get().has_value());
		CHECK(queued.get().error().code == client_errc::not_sent);
	}
}

TEST_CASE("connection: a notice of disconnection fails every outstanding operation", "[net][connection][mux]")
{
	mock_ldap m;
	// Reads the bind (the search is held behind it), then sends the notice.
	m.serve({ answer({ ldap::message{ 0,
	  ldap::extended_response{
		ldap::ldap_result{ 51, "", "too busy" }, std::string(ldap::notice_of_disconnection_oid) } } }) });
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<ldap::search_result>> search;
	spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
	spawn(m.ioc, m.conn.search(people_search()), search);
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	REQUIRE_FALSE(search.get().has_value());
	CHECK(bind.get().error().code == errc::busy);
	CHECK(bind.get().error().diagnostic == "too busy");
	CHECK(bind.get().error().context == "bind cn=admin,dc=example,dc=org: notice of disconnection");
	CHECK(search.get().error().code == client_errc::not_sent);// held behind the bind
	CHECK(search.get().error().diagnostic == "too busy");
	CHECK(search.get().error().context == "search ou=people,dc=example,dc=org: notice of disconnection");
	CHECK_FALSE(m.conn.is_open());
	auto later = m.run(m.conn.search({ .base = ldap::dn{} }));
	REQUIRE_FALSE(later.has_value());
	CHECK(later.error().code == client_errc::not_sent);
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

// Reads `n` searches, then answers them interleaved at random (each
// search's responses in order), abandoned ones included.
auto serve_shuffled(net::transport t, std::size_t n, std::uint64_t seed, server_log &log) -> capy::task<void>
{
	net::read_buffer buf;
	std::vector<std::vector<std::string>> queues;
	while (queues.size() < n) {
		auto r = co_await ldap::testing::read_message(t, buf, as_server);
		if (!r) {
			log.error = "server read: " + std::string(r.error().message());
			co_return;
		}
		if (std::holds_alternative<ldap::abandon_request>(r->op)) {
			continue;
		}
		const auto *sr = std::get_if<ldap::search_request>(&r->op);
		if (sr == nullptr) {
			log.error = "server: expected a SearchRequest";
			co_return;
		}
		const std::string base(sr->base_object);
		std::vector<std::string> q{ bytes_of(entry_msg(r->id, "uid=x," + base, "X")),
			bytes_of(entry_msg(r->id, "uid=y," + base, "Y")),
			bytes_of(done_msg(r->id)) };
		std::ranges::reverse(q);// popped from the back
		queues.push_back(std::move(q));
		log.received.push_back(std::move(*r));
	}
	std::uint64_t state = seed;
	auto next = [&state](std::size_t bound) {
		state = (state * 6364136223846793005u) + 1442695040888963407u;
		return static_cast<std::size_t>((state >> 33) % bound);
	};
	std::vector<std::size_t> live(n);
	std::ranges::iota(live, std::size_t{ 0 });
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
auto checked_search(ldap::connection &c, std::string base) -> capy::task<std::string>
{
	auto d = ldap::dn::parse(base);
	if (!d) {
		co_return "bad base";
	}
	auto r = co_await c.search({ .base = std::move(*d) });
	if (!r) {
		co_return std::string(r.error().message());
	}
	if (r->entries.size() != 2) {
		co_return "expected 2 entries, got " + std::to_string(r->entries.size());
	}
	for (const auto &e : r->entries) {
		if (!std::string_view(e.dn).ends_with("," + base)) {
			co_return "entry " + std::string(e.dn) + " not under " + base;
		}
	}
	co_return "";
}

}// namespace

// Many concurrent searches with interleaved responses, some cancelled.
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
		for (std::size_t i = 0; i < ops; ++i) {
			spawn(m.ioc,
			  stops[i].get_token(),
			  checked_search(m.conn, "ou=" + std::to_string(i) + ",dc=example,dc=org"),
			  results[i]);
		}
		// Cancel every 7th operation once all are sent, before the server
		// answers anything (one stopped before it starts would not be sent).
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == ops; });
		for (std::size_t i = 0; i < ops; i += 7) {
			stops[i].request_stop();
		}
		drive_until(m.ioc, [&] { return std::ranges::all_of(results, [](const auto &r) { return r.done(); }); });
		for (std::size_t i = 0; i < ops; ++i) {
			INFO("operation " << i);
			if (i % 7 == 0) {
				CHECK_THAT(results[i].get(), ContainsSubstring("canceled"));
			} else {
				CHECK_THAT(results[i].get(), IsEmpty());
			}
		}
		m.check_server();
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		// Late responses were dropped; the connection still works.
		CHECK(m.log.received.size() == ops);
	}
}

// A valid search answer with bytes flipped, dropped, inserted or cut: the
// client always finishes, closing on transport or protocol errors only.
TEST_CASE("connection: mutated server responses", "[net][connection]")
{
	std::string wire;
	for (const auto &msg : { entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
		   ref_msg(1, { "ldap://r.example.org/" }),
		   ldap::message{ 1, ldap::intermediate_response{ "1.2.3" } },
		   entry_msg(1, "uid=b,ou=people,dc=example,dc=org", std::string(300, 'b')),
		   done_msg(1, 0, "dc=example,dc=org", "ok") }) {
		wire += bytes_of(msg);
	}

	std::uint64_t state = 0x9e3779b97f4a7c15u;
	auto next = [&state](std::size_t bound) {
		state = (state * 6364136223846793005u) + 1442695040888963407u;
		return static_cast<std::size_t>((state >> 33) % bound);
	};
	std::size_t ok = 0;
	std::size_t server_error = 0;
	std::size_t broken = 0;
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
		auto r = run_task(ioc, conn.search(people_search()));
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
	// Outlives the mock: the stream's search is abandoned on the strand, by
	// work its destructor posts, after the stream is gone.
	std::pmr::monotonic_buffer_resource arena;
	{
		mock_ldap m({}, &conn_mr);
		m.serve({ answer({ entry_msg(1, "uid=a,ou=people,dc=example,dc=org", "A"),
					entry_msg(1, "uid=b,ou=people,dc=example,dc=org", "B"),
					done_msg(1) }),
		  answer({ entry_msg(2, "uid=c,ou=people,dc=example,dc=org", "C"), done_msg(2) }) });
		CHECK(conn_mr.allocations() > 0);// the connection's state

		auto r = m.run(m.conn.search(people_search(), &results));
		REQUIRE(r.has_value());
		REQUIRE(r->entries.size() == 2);
		CHECK(r->entries.get_allocator().resource() == &results);
		for (const auto &e : r->entries) {
			CHECK(e.get_allocator().resource() == &results);
			CHECK(e.attributes.get_allocator().resource() == &results);
			CHECK(e.attributes[0].values[0].get_allocator().resource() == &results);
		}
		CHECK(r->entries[1] == expected_entry("uid=b,ou=people,dc=example,dc=org", "B"));

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

TEST_CASE("connection: ldap::connect, bind, search and unbind over TCP", "[net][connection]")
{
	tcp_mock_ldap m({ .timeout = std::chrono::seconds(10) });
	m.serve({ answer({ bind_resp(1) }),
	  answer({ entry_msg(2, "uid=jdoe,ou=people,dc=example,dc=org", "J"), done_msg(2) }),
	  step{} });
	CHECK(m.conn.is_open());
	CHECK(m.conn.name() == m.url());
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	auto r = m.run(m.conn.search(people_search()));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 1);
	CHECK(r->entries[0] == expected_entry("uid=jdoe,ou=people,dc=example,dc=org", "J"));
	CHECK(m.run(m.conn.unbind()).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(std::holds_alternative<ldap::unbind_request>(m.log.received[2].op));
}

TEST_CASE("connection: a password is not sent in clear over TCP unless allowed", "[net][connection][bind]")
{
	tcp_mock_ldap m({}, socket_buffers::system, false);
	m.serve({ answer({ bind_resp(1) }), step{} });
	auto refused = m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::client_errc::tls_required);
	CHECK_THAT(std::string(refused.error().context), ContainsSubstring("allow_cleartext_passwords"));
	// An anonymous bind carries no password.
	CHECK(m.run(m.conn.simple_bind(ldap::dn{}, "")).has_value());
	CHECK(m.run(m.conn.unbind()).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
}

TEST_CASE("connection: ldap::connect failures", "[net][connection]")
{
	corosio::io_context ioc;
	const refused_port closed;// nothing listens there
	auto u = ldap::url::parse(closed.url());
	REQUIRE(u.has_value());
	auto c = run_task(ioc, ldap::connect(ioc, *u));
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == std::errc::connection_refused);
	CHECK(c.error().code == ldap::cond::busy_or_unavailable);
	CHECK_THAT(std::string(c.error().context), StartsWith("connect ldap://127.0.0.1:"));

	auto bad = ldap::url::parse("ldap://127.0.0.1:1/??sub?(cn=x)?!unknown-ext");
	REQUIRE(bad.has_value());
	auto refused = run_task(ioc, ldap::connect(ioc, *bad));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == client_errc::invalid_url);
}

namespace {

auto echo_length(corosio::io_context &, const std::string &text) -> capy::task<std::size_t> { co_return text.size(); }

}// namespace

TEST_CASE("ldap::run(f, args...) returns the task's value or rethrows its exception", "[net][run]")
{
	CHECK(ldap::run([](corosio::io_context &) -> capy::task<int> { co_return 7; }) == 7);
	bool ran = false;
	ldap::run(
	  [](corosio::io_context &, bool &r) -> capy::task<void> {
		  r = true;
		  co_return;
	  },
	  ran);
	CHECK(ran);
	CHECK_THROWS_AS(ldap::run([](corosio::io_context &) -> capy::task<int> {
		throw std::runtime_error("thrown");
		co_return 0;
	}),
	  std::runtime_error);
	// A condition the optimizer cannot fold, or MSVC finds run()'s return unreachable (C4702).
	CHECK_THROWS_AS(ldap::run([](corosio::io_context &ioc) -> capy::task<int> {
		if (!ioc.stopped()) {
			throw std::logic_error("from f");
		}
		return []() -> capy::task<int> { co_return 0; }();
	}),
	  std::logic_error);
	// The std::string made from the const char * lives until the run ends.
	CHECK(ldap::run(echo_length, "a temporary string longer than the small-string buffer") == 54);

	const refused_port closed;
	auto u = ldap::url::parse(closed.url());
	REQUIRE(u.has_value());
	const auto code = ldap::run(
	  [](corosio::io_context &ioc, const ldap::url &to) -> capy::task<std::error_code> {
		  auto c = co_await ldap::connect(ioc, to);
		  co_return c ? std::error_code{} : c.error().code;
	  },
	  *u);
	CHECK(code == std::errc::connection_refused);

	corosio::io_context ioc;
	auto c = ldap::run(ioc, ldap::connect(ioc, *u));
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == std::errc::connection_refused);
	CHECK(ldap::run(ioc, []() -> capy::task<int> { co_return 8; }()) == 8);
}

namespace user_code {
template<class T> auto run(corosio::io_context &ioc, capy::task<T> t) -> T { return ldap::run(ioc, std::move(t)); }

auto connect_with_own_run(corosio::io_context &ioc, const ldap::url &u) -> ldap::result<ldap::connection>
{
	return run(ioc, ldap::connect(ioc, u));
}
}// namespace user_code

TEST_CASE("ldap::run leaves a user's own unqualified run(ioc, task) unambiguous", "[net][run]")
{
	corosio::io_context ioc;
	const refused_port closed;
	auto u = ldap::url::parse(closed.url());
	REQUIRE(u.has_value());
	auto c = user_code::connect_with_own_run(ioc, *u);
	REQUIRE_FALSE(c.has_value());
	CHECK(c.error().code == std::errc::connection_refused);
}

TEST_CASE("ldap::run throws canceled when the io_context stops before the task ends", "[net][run]")
{
	corosio::io_context ioc;
	capy::async_event resume;
	try {
		(void)ldap::run(ioc, [](corosio::io_context &io, capy::async_event &e) -> capy::task<int> {
			io.stop();
			(void)co_await e.wait();
			co_return 1;
		}(ioc, resume));
		FAIL("ldap::run returned");
	} catch (const std::system_error &e) {
		CHECK(e.code() == capy::cond::canceled);
	}
	// Run again: the stopped context is restarted, and the first task ends too.
	CHECK(ldap::run(ioc,
			[](capy::async_event &e) -> capy::task<int> {
				e.set();
				co_return 2;
			}(resume))
		  == 2);
}

TEST_CASE("connection: ldap::connect with the URL as text", "[net][connection][connect]")
{
	corosio::io_context ioc;
	corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
	const std::string where = "ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port());
	// A connection the kernel completed and the acceptor has not taken.
	auto pending = [&acc] { return poll_readable(acc.native_handle()); };

	SECTION("a bad URL fails with url::parse's error before connecting")
	{
		const std::string text = where + "/??sub?(cn=x";
		auto parsed = ldap::url::parse(text);
		REQUIRE_FALSE(parsed.has_value());
		auto c = finish(ioc, ldap::connect(ioc, text));
		REQUIRE_FALSE(c.has_value());
		CHECK(c.error().code == client_errc::invalid_url);
		CHECK(c.error() == parsed.error());
		CHECK_FALSE(pending());
	}
	SECTION("a good URL connects; the text need not outlive the call")
	{
		// NOLINTNEXTLINE(performance-string-view-conversions): the temporary string is the point of the test
		auto task = ldap::connect(ioc, std::string(where), { .timeout = std::chrono::seconds(10) });
		auto c = finish(ioc, std::move(task));
		REQUIRE(c.has_value());
		CHECK(c->is_open());
		CHECK(c->name() == where);
		CHECK(pending());
		c->close();
		drive(ioc);
	}
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
		auto later = m.run(m.conn.search({ .base = ldap::dn{} }));
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
	outcome<ldap::result<ldap::search_result>> search;
	spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
	spawn(m.ioc, m.conn.search(people_search()), search);
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	CHECK_FALSE(bind.get().has_value());
	REQUIRE_FALSE(search.get().has_value());
	CHECK_THAT(std::string(search.get().error().context), ContainsSubstring("cannot be abandoned"));
	// No BindResponse came, so the BindRequest is all the server got.
	m.sockets.client.close();// closing a wrapped transport leaves the socket open
	drive_until(m.ioc, [&m] { return m.server.done(); });
	REQUIRE(m.server.done());
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
		outcome<ldap::result<ldap::search_result>> first;
		outcome<ldap::result<ldap::search_result>> second;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		spawn(m.ioc, m.conn.search(people_search()), first);
		spawn(m.ioc, m.conn.search({ .base = ldap::dn{} }), second);
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
		outcome<ldap::result<ldap::search_result>> cancelled;
		std::stop_source stop;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), bind);
		spawn(m.ioc, stop.get_token(), m.conn.search(people_search()), cancelled);
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 2; });// the search is held
		stop.request_stop();
		drive_until(m.ioc, [&] { return bind.done() && cancelled.done(); });
		CHECK(bind.get().has_value());
		REQUIRE_FALSE(cancelled.get().has_value());
		CHECK(cancelled.get().error().code == ldap::cond::canceled);
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
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
		outcome<ldap::result<void>> first;
		outcome<ldap::result<void>> second;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"), first);
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{}, ""), second);
		drive_until(m.ioc, [&] { return first.done() && second.done(); });
		CHECK(first.get().has_value());
		CHECK(second.get().has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::get<ldap::bind_request>(m.log.received[0].op).name == "cn=admin,dc=example,dc=org");
		CHECK(std::get<ldap::bind_request>(m.log.received[1].op).name.empty());
	}
	SECTION("a bind cancelled while waiting for the first")
	{
		mock_ldap m;
		m.serve({ step{}, step{} });// reads the first bind, never answers
		outcome<ldap::result<void>> first;
		outcome<ldap::result<void>> second;
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
	SECTION("a bind stopped after the first ends, before it resumes, is not sent")
	{
		// The stop comes after bind_idle.set() claimed the waiter, before it
		// resumes.
		mock_ldap m;
		m.serve({ answer({ bind_resp(1) }), answer({ done_msg(2) }) });
		outcome<ldap::result<void>> first;
		outcome<ldap::result<void>> second;
		std::stop_source stop;
		capy::run_async(
		  m.conn.executor(),
		  [s = first.state, &stop](ldap::result<void> v) {
			  s->value.emplace(std::move(v));
			  stop.request_stop();
		  },
		  [s = first.state](std::exception_ptr e) { s->error = std::move(e); })(
		  m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"));
		spawn(m.ioc, stop.get_token(), m.conn.simple_bind(ldap::dn{}, ""), second);
		drive_until(m.ioc, [&] { return first.done() && second.done(); });
		CHECK(first.get().has_value());
		REQUIRE_FALSE(second.get().has_value());
		CHECK(second.get().error().code == ldap::cond::canceled);
		CHECK(second.get().error().context == "bind \"\"");
		CHECK(m.conn.is_open());
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);// the stopped bind was never sent
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
		CHECK(m.log.received[1].id == 2);
		CHECK(std::holds_alternative<ldap::search_request>(m.log.received[1].op));
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

namespace {

// A mechanism whose first step, run on a thread of its own, fails without
// anything being sent once release() is called.
class refused_offload final : public ldap::sasl_mechanism
{
  public:
	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "X-REFUSED"; }
	auto start() -> ldap::result<std::optional<std::string>> override { return std::nullopt; }
	auto step(std::optional<std::string_view>) -> ldap::result<std::optional<std::string>> override
	{
		return std::nullopt;
	}
	auto offload_start() -> ldap::sasl_work override
	{
		return [this] -> ldap::result<std::optional<std::string>> {
			(void)gate_.try_acquire_for(std::chrono::seconds(10));
			return ldap::fail(client_errc::tls_required, "refused before sending");
		};
	}
	void release() { gate_.release(); }

  private:
	std::binary_semaphore gate_{ 0 };
};

// A mechanism whose second step throws.
class throwing_step final : public ldap::sasl_mechanism
{
  public:
	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "X-THROW"; }
	auto start() -> ldap::result<std::optional<std::string>> override { return std::optional<std::string>("hello"); }
	auto step(std::optional<std::string_view>) -> ldap::result<std::optional<std::string>> override
	{
		throw std::runtime_error("mechanism failure");
	}
};

}// namespace

TEST_CASE("requests held behind a failed bind fail without being sent", "[net][connection]")
{
	SECTION("a bind that fails before sending anything: the connection stays open")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(2) }) });
		refused_offload mech;
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<ldap::search_result>> held;
		spawn(m.ioc, m.conn.sasl_bind(mech), bind);
		spawn(m.ioc, m.conn.search({ .base = ldap::dn{} }), held);// id 1
		while (m.ioc.poll() != 0) {}// the bind waits on its step, the search is held
		m.ioc.restart();
		CHECK_FALSE(held.done());
		mech.release();
		drive_until(m.ioc, [&] { return bind.done() && held.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code == client_errc::tls_required);
		REQUIRE_FALSE(held.get().has_value());
		CHECK(held.get().error().code == client_errc::bind_failed);
		CHECK_THAT(std::string(held.get().error().context), ContainsSubstring("held behind a failed bind: sasl bind"));
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());// id 2
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(m.log.received[0].id == 2);
	}
	SECTION("a bind that does not complete (the exchange throws)")
	{
		mock_ldap m;
		m.serve({ answer({ bind_resp(1, 14) }) });
		throwing_step mech;
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<ldap::search_result>> held;
		spawn(m.ioc, m.conn.sasl_bind(mech), bind);
		spawn(m.ioc, m.conn.search({ .base = ldap::dn{} }), held);// id 2
		drive_until(m.ioc, [&] { return bind.done() && held.done(); });
		CHECK_THROWS_AS(bind.get(), std::runtime_error);
		REQUIRE_FALSE(held.get().has_value());
		CHECK(held.get().error().code == client_errc::bind_failed);
		CHECK_THAT(
		  std::string(held.get().error().context), ContainsSubstring("held behind a bind that did not complete"));
		m.check_server();
		REQUIRE(m.log.received.size() == 1);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
	}
	SECTION("a bind the server refuses")
	{
		mock_ldap m;
		m.serve({ answer({ bind_resp(1, 49, "bad password") }), answer({ done_msg(4) }) });
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<ldap::search_result>> first;
		outcome<ldap::result<ldap::search_result>> second;
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong"), bind);
		spawn(m.ioc, m.conn.search(people_search()), first);
		spawn(m.ioc, m.conn.search({ .base = ldap::dn{} }), second);
		drive_until(m.ioc, [&] { return bind.done() && first.done() && second.done(); });
		REQUIRE_FALSE(bind.get().has_value());
		CHECK(bind.get().error().code == ldap::errc::invalid_credentials);
		for (auto *held : { &first, &second }) {
			REQUIRE_FALSE(held->get().has_value());
			const auto &e = held->get().error();
			CHECK(e.code == client_errc::bind_failed);
			CHECK(e.code == ldap::cond::auth_failed);
			CHECK_THAT(std::string(e.context), ContainsSubstring("held behind a failed bind: bind cn=admin"));
			CHECK_THAT(std::string(e.context), ContainsSubstring("bad password"));
		}
		CHECK(m.conn.is_open());
		CHECK(m.conn.outstanding() == 0);
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());// id 4
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[0].op));
		CHECK(m.log.received[1].id == 4);
	}
	SECTION("an AbandonRequest held behind the bind is still sent")
	{
		mock_ldap m;
		// Reads the search (id 1) and leaves it open, then the bind (2), the
		// AbandonRequest for the search (4) and a later search (5).
		m.serve({ step{}, answer({ bind_resp(2, 49) }), step{}, answer({ done_msg(5) }) });
		std::stop_source stop;
		outcome<ldap::result<ldap::search_result>> early;
		outcome<ldap::result<void>> bind;
		outcome<ldap::result<ldap::search_result>> held;
		spawn(m.ioc, stop.get_token(), m.conn.search(people_search()), early);
		drive_until(m.ioc, [&m] { return m.log.received.size() == 1; });
		spawn(m.ioc, m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "wrong"), bind);
		spawn(m.ioc, m.conn.search({ .base = ldap::dn{} }), held);// id 3
		drive_until(m.ioc, [&m] { return m.conn.outstanding() == 3; });// the search is held
		stop.request_stop();
		drive_until(m.ioc, [&] { return early.done() && bind.done() && held.done(); });
		CHECK(early.get().error().code == ldap::cond::canceled);
		CHECK(held.get().error().code == client_errc::bind_failed);
		CHECK(m.run(m.conn.search({ .base = ldap::dn{} })).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(std::holds_alternative<ldap::bind_request>(m.log.received[1].op));
		CHECK(m.log.received[2] == ldap::message{ 4, ldap::abandon_request{ 1 } });
		CHECK(m.log.received[3].id == 5);
	}
}

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
		auto s = m.run(m.conn.search_stream({ .base = ldap::dn{} }));
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
		outcome<ldap::result<ldap::search_result>> search;
		spawn(m.ioc, stop.get_token(), m.conn.search({ .base = ldap::dn{} }), search);
		drive_until(m.ioc, [&m] { return !m.log.received.empty(); });
		stop.request_stop();
		drive_until(m.ioc, [&] { return search.done() && m.log.received.size() == 2; });
		ldap::detail::set_next_message_id(m.conn, ldap::max_int);
		CHECK(m.run(m.conn.del({ .entry = x })).has_value());// max_int
		CHECK(m.run(m.conn.del({ .entry = x })).has_value());// 2: 1 was abandoned
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(m.log.received[1] == ldap::message{ 2, ldap::abandon_request{ 1 } });
		CHECK(m.log.received[3].id == 2);
	}
}
