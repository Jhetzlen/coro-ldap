// ad::dirsync against the scripted mock server: the DirSync control it
// sends with each cookie, MoreResults followed, and the answers refused.
#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/ad/dirsync.hpp"
#include "jhetz/ldap/connection.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;
using namespace jhetz::ldap::test;
using ldap::client_errc;

namespace {

const ldap::dn domain{ "dc=example,dc=org" };

auto users() -> ldap::search_params
{
	return { .base = domain, .filter = ldap::filters::attr("objectClass") == "user", .attributes = { "description" } };
}

// One entry (when `dn` is not empty), then a SearchResultDone carrying
// `control`, or no control.
auto page(std::int32_t id, std::string_view dn, std::optional<ldap::control> control) -> step
{
	step s;
	if (!dn.empty()) {
		s.replies.push_back(bytes_of(entry_msg(id, dn, "x")));
	}
	ldap::message done = done_msg(id);
	if (control) {
		done.controls.push_back(*control);
	}
	s.replies.push_back(bytes_of(done));
	return s;
}

auto response(bool more, std::string_view cookie) -> ldap::control
{
	return ad::encode_dirsync_response({ .more_results = more, .cookie_server = std::string(cookie) });
}

// The DirSync request control of a logged search.
auto sent(const ldap::message &m) -> ad::dirsync_request
{
	REQUIRE(std::holds_alternative<ldap::search_request>(m.op));
	REQUIRE(m.controls.size() == 1);
	auto r = ad::decode_dirsync_request(m.controls[0]);
	REQUIRE(r.has_value());
	return *r;
}

}// namespace

TEST_CASE("ad::dirsync: follows MoreResults with each new cookie", "[net][ad][dirsync]")
{
	mock_ldap m;
	m.serve({ page(1, "cn=a,dc=example,dc=org", response(true, "c1")),
	  page(2, "cn=b,dc=example,dc=org", response(true, "c2")),
	  page(3, "", response(false, "c3")) });
	auto r = m.run(ad::dirsync(m.conn, users(), { .flags = ad::dirsync_flags::object_security, .cookie = "c0" }));
	if (!r) {
		FAIL(r.error().message());
	}
	REQUIRE(r->entries.size() == 2);
	CHECK(r->entries[0].dn == "cn=a,dc=example,dc=org");
	CHECK(r->entries[1].dn == "cn=b,dc=example,dc=org");
	CHECK(r->cookie == "c3");
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(
	  sent(m.log.received[0]) == ad::dirsync_request{ .flags = ad::dirsync_flags::object_security, .cookie = "c0" });
	CHECK(sent(m.log.received[1]).cookie == "c1");
	CHECK(sent(m.log.received[2]).cookie == "c2");
	CHECK(sent(m.log.received[2]).flags == ad::dirsync_flags::object_security);
}

TEST_CASE("ad::dirsync: one search without MoreResults", "[net][ad][dirsync]")
{
	mock_ldap m;
	m.serve({ page(1, "", response(false, "next")) });
	auto r = m.run(ad::dirsync(m.conn, users()));
	REQUIRE(r.has_value());
	CHECK(r->entries.empty());
	CHECK(r->cookie == "next");
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(sent(m.log.received[0]) == ad::dirsync_request{});
}

TEST_CASE("ad::dirsync: answers refused", "[net][ad][dirsync]")
{
	mock_ldap m;
	SECTION("no DirSync control")
	{
		m.serve({ page(1, "cn=a,dc=example,dc=org", std::nullopt) });
		auto r = m.run(ad::dirsync(m.conn, users()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unexpected_response);
		CHECK(
		  std::string(r.error().context) == "DirSync dc=example,dc=org: no DirSync control in the SearchResultDone");
	}
	SECTION("more results without a new cookie")
	{
		m.serve({ page(1, "", response(true, "c1")), page(2, "", response(true, "c1")) });
		auto r = m.run(ad::dirsync(m.conn, users()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::unexpected_response);
	}
	SECTION("a malformed control")
	{
		m.serve({ page(1, "", ldap::control{ ad::dirsync_oid, false, "\x30\x00" }) });
		auto r = m.run(ad::dirsync(m.conn, users()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::decode_error);
	}
	SECTION("the server's refusal")
	{
		m.serve({ answer({ done_msg(1, 50, "", "00002098: insufficient access") }) });
		auto r = m.run(ad::dirsync(m.conn, users()));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::insufficient_access_rights);
	}
	m.check_server();
	CHECK(m.conn.is_open());
}
