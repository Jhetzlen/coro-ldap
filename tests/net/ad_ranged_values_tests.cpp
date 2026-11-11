// ad::read_all_values against the scripted mock server: the windows it
// asks for, with and without a step, and the answers it refuses.
#include "jhetz/ldap/ad/ranged_values.hpp"
#include "jhetz/ldap/connection.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using ldap::client_errc;

namespace {

const ldap::dn group{ "cn=staff,dc=example,dc=org" };

auto values(std::uint32_t from, std::uint32_t to) -> std::vector<std::string>
{
	std::vector<std::string> out;
	for (std::uint32_t i = from; i <= to; ++i) {
		out.push_back("cn=m" + std::to_string(i));
	}
	return out;
}

// One entry for `group` with the attribute `name` holding `vals`, then the
// SearchResultDone.
auto window(std::int32_t id, std::string_view name, const std::vector<std::string> &vals) -> step
{
	ldap::partial_attribute a{ name, {} };
	for (const auto &v : vals) {
		a.values.emplace_back(v);
	}
	step s;
	s.replies.push_back(
	  bytes_of(ldap::message{ id, ldap::search_result_entry{ "cn=staff,dc=example,dc=org", { std::move(a) } } }));
	s.replies.push_back(bytes_of(done_msg(id)));
	return s;
}

// One entry for `group` without attributes, then the SearchResultDone.
auto bare(std::int32_t id) -> step
{
	step s;
	s.replies.push_back(bytes_of(ldap::message{ id, ldap::search_result_entry{ "cn=staff,dc=example,dc=org", {} } }));
	s.replies.push_back(bytes_of(done_msg(id)));
	return s;
}

// One entry for `group` with the attributes `attrs`, then the
// SearchResultDone.
auto entry_with(std::int32_t id, std::vector<ldap::partial_attribute> attrs) -> step
{
	ldap::search_result_entry e{ "cn=staff,dc=example,dc=org" };
	e.attributes.assign(std::make_move_iterator(attrs.begin()), std::make_move_iterator(attrs.end()));
	step s;
	s.replies.push_back(bytes_of(ldap::message{ id, std::move(e) }));
	s.replies.push_back(bytes_of(done_msg(id)));
	return s;
}

auto attr(std::string_view name, const std::vector<std::string> &vals) -> ldap::partial_attribute
{
	ldap::partial_attribute a{ name, {} };
	for (const auto &v : vals) {
		a.values.emplace_back(v);
	}
	return a;
}

auto asked_for(const ldap::message &m) -> std::string
{
	const auto *s = std::get_if<ldap::search_request>(&m.op);
	REQUIRE(s != nullptr);
	CHECK(s->scope == ldap::search_scope::base_object);
	REQUIRE(s->attributes.size() == 1);
	return std::string(s->attributes[0]);
}

auto as_strings(const ldap::string_list &l) -> std::vector<std::string> { return { l.begin(), l.end() }; }

auto concat(std::initializer_list<std::vector<std::string>> parts) -> std::vector<std::string>
{
	std::vector<std::string> out;
	for (const auto &p : parts) {
		out.insert(out.end(), p.begin(), p.end());
	}
	return out;
}

}// namespace

TEST_CASE("ad::read_all_values: follows the server's windows", "[net][ad][range]")
{
	mock_ldap m;
	m.serve({ window(1, "member;range=0-2", values(0, 2)),
	  window(2, "member;range=3-5", values(3, 5)),
	  window(3, "member;range=6-*", values(6, 7)) });
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
	if (!r) {
		FAIL(r.error().message());
	}
	CHECK(as_strings(*r) == values(0, 7));
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(asked_for(m.log.received[0]) == "member");
	CHECK(asked_for(m.log.received[1]) == "member;range=3-*");
	CHECK(asked_for(m.log.received[2]) == "member;range=6-*");
}

TEST_CASE("ad::read_all_values: the plain attribute is every value", "[net][ad][range]")
{
	mock_ldap m;
	m.serve({ window(1, "Member", values(0, 3)) });
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
	REQUIRE(r.has_value());
	CHECK(as_strings(*r) == values(0, 3));
	m.check_server();
}

TEST_CASE("ad::read_all_values: no such attribute is no values", "[net][ad][range]")
{
	mock_ldap m;
	m.serve({ bare(1) });
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
	REQUIRE(r.has_value());
	CHECK(r->empty());
	m.check_server();
}

TEST_CASE("ad::read_all_values: the server names the attribute its own way", "[net][ad][range]")
{
	mock_ldap m;
	SECTION("an OID answered as the plain attribute")
	{
		m.serve({ window(1, "member", values(0, 3)) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "2.5.4.31"));
		REQUIRE(r.has_value());
		CHECK(as_strings(*r) == values(0, 3));
		REQUIRE(m.log.received.size() == 1);
		CHECK(asked_for(m.log.received[0]) == "2.5.4.31");
	}
	SECTION("an OID answered in windows: the next ones under the server's name")
	{
		m.serve({ window(1, "member;range=0-2", values(0, 2)), window(2, "member;range=3-*", values(3, 4)) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "2.5.4.31"));
		REQUIRE(r.has_value());
		CHECK(as_strings(*r) == values(0, 4));
		REQUIRE(m.log.received.size() == 2);
		CHECK(asked_for(m.log.received[1]) == "member;range=3-*");
	}
	SECTION("an alias with a step")
	{
		m.serve({ window(1, "cn;range=0-1", { "a", "b" }), window(2, "cn;range=2-*", { "c" }) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "commonName", { .step = 2 }));
		REQUIRE(r.has_value());
		CHECK(as_strings(*r) == std::vector<std::string>{ "a", "b", "c" });
		REQUIRE(m.log.received.size() == 2);
		CHECK(asked_for(m.log.received[0]) == "commonName;range=0-1");
		CHECK(asked_for(m.log.received[1]) == "cn;range=2-3");
	}
	SECTION("several attributes, none of them the one asked for")
	{
		step s;
		s.replies.push_back(bytes_of(ldap::message{ 1,
		  ldap::search_result_entry{ "cn=staff,dc=example,dc=org",
			{ ldap::partial_attribute{ "cn", { "x" } }, ldap::partial_attribute{ "sn", { "y" } } } } }));
		s.replies.push_back(bytes_of(done_msg(1)));
		m.serve({ std::move(s) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "name"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("none of the attributes returned is name"));
	}
	m.check_server();
}

TEST_CASE("ad::read_all_values: an empty plain attribute next to the first window", "[net][ad][range]")
{
	const bool plain_first = GENERATE(true, false);
	const std::string requested = GENERATE(std::string("member"), std::string("2.5.4.31"));
	CAPTURE(plain_first, requested);
	std::vector<ldap::partial_attribute> first;
	first.push_back(attr("member", {}));
	first.push_back(attr("member;range=0-2", values(0, 2)));
	if (!plain_first) {
		std::swap(first[0], first[1]);
	}
	mock_ldap m;
	m.serve({ entry_with(1, std::move(first)), window(2, "member;range=3-*", values(3, 4)) });
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, requested));
	if (!r) {
		FAIL(r.error().message());
	}
	CHECK(as_strings(*r) == values(0, 4));
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(asked_for(m.log.received[1]) == "member;range=3-*");
}

TEST_CASE("ad::read_all_values: several answers for the attribute", "[net][ad][range]")
{
	mock_ldap m;
	SECTION("two ranged forms")
	{
		m.serve({ entry_with(1, { attr("member;range=0-2", values(0, 2)), attr("member;range=3-5", values(3, 5)) }) });
	}
	SECTION("a plain attribute with values next to a ranged one")
	{
		m.serve({ entry_with(1, { attr("member", values(0, 5)), attr("member;range=0-2", values(0, 2)) }) });
	}
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::unexpected_response);
	CHECK_THAT(std::string(r.error().context), ContainsSubstring("several attributes returned answer member"));
	m.check_server();
}

TEST_CASE("ad::read_all_values: a step asks for windows of that size", "[net][ad][range]")
{
	mock_ldap m;
	// The server shortens the second window; the last one asked for is
	// past the end, so the attribute is absent.
	m.serve({ window(1, "member;range=0-3", values(0, 3)),
	  window(2, "member;range=4-5", values(4, 5)),
	  window(3, "member;range=6-9", values(6, 9)),
	  bare(4) });
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member", { .step = 4 }));
	REQUIRE(r.has_value());
	CHECK(as_strings(*r) == concat({ values(0, 3), values(4, 5), values(6, 9) }));
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(asked_for(m.log.received[0]) == "member;range=0-3");
	CHECK(asked_for(m.log.received[1]) == "member;range=4-7");
	CHECK(asked_for(m.log.received[2]) == "member;range=6-9");
	CHECK(asked_for(m.log.received[3]) == "member;range=10-13");
}

TEST_CASE("ad::read_all_values: a step near 2^32 does not wrap", "[net][ad][range]")
{
	mock_ldap m;
	m.serve({ window(1, "member;range=0-*", values(0, 1)) });
	auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member", { .step = 4294967295U }));
	REQUIRE(r.has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(asked_for(m.log.received[0]) == "member;range=0-4294967294");
}

TEST_CASE("ad::read_all_values: answers refused", "[net][ad][range]")
{
	mock_ldap m;
	SECTION("a window that does not continue the previous one")
	{
		m.serve({ window(1, "member;range=0-2", values(0, 2)), window(2, "member;range=4-*", values(4, 5)) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context),
		  ContainsSubstring("read all values of member cn=staff,dc=example,dc=org: asked for the values from 3"));
	}
	SECTION("the plain attribute after a window")
	{
		m.serve({ window(1, "member;range=0-2", values(0, 2)), window(2, "member", values(0, 5)) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unexpected_response);
	}
	SECTION("a malformed range")
	{
		m.serve({ window(1, "member;range=2-1", values(0, 2)) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::decode_error);
	}
	SECTION("no entry")
	{
		m.serve({ answer({ done_msg(1) }) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unexpected_response);
	}
	SECTION("the server's error")
	{
		m.serve({ answer({ done_msg(1, 32, "dc=example,dc=org") }) });
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, "member"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::no_such_object);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("read all values of member"));
	}
	m.check_server();
	CHECK(m.conn.is_open());
}

TEST_CASE("ad::read_all_values: refused before sending", "[net][ad][range]")
{
	mock_ldap m;
	m.serve({});
	for (const char *attribute : { "", "member;range=0-*" }) {
		CAPTURE(attribute);
		auto r = m.run(ldap::ad::read_all_values(m.conn, group, attribute));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == std::errc::invalid_argument);
	}
	m.check_server();
	CHECK(m.log.received.empty());
}
