// Typed operations (search_as, modify<T>, add(dn, T)) against the scripted
// mock server (mock_ldap.hpp).
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;

namespace {

struct account
{
	std::string uid;
	std::optional<std::string> mail;
	std::vector<ldap::dn> groups;
	std::int64_t uid_number = 0;
	std::chrono::sys_seconds modified{};
};

}// namespace

template<>
constexpr auto ldap::schema<account> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&account::uid>("uid"),
  ldap::field<&account::mail>("mail"),
  ldap::field<&account::groups>("memberOf"),
  ldap::field<&account::uid_number>("uidNumber"),
  ldap::field<&account::modified>("modifyTimestamp", ldap::read_only));

namespace {

ldap::message account_entry(std::int32_t id, std::string_view uid, std::string_view number)
{
	return ldap::message{ id,
		ldap::search_result_entry{ "uid=" + std::string(uid) + ",ou=people,dc=example,dc=org",
		  { { "uid", { uid } },
			{ "memberOf", { "cn=staff,ou=groups,dc=example,dc=org" } },
			{ "uidNumber", { number } },
			{ "modifyTimestamp", { "20250101000000Z" } } } } };
}

}// namespace

TEST_CASE("typed: search_as requests the descriptor's attributes and object classes", "[net][mapping]")
{
	mock_ldap m;
	m.serve({ answer({ account_entry(1, "a", "1000"), account_entry(1, "b", "1001"), done_msg(1) }) });
	auto r = m.run(m.conn.search_as<account>({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter = ldap::filters::field<&account::uid_number>() >= 1000,
	  .attributes = { "ignored" },
	}));
	REQUIRE(r.has_value());
	REQUIRE(r->size() == 2);
	CHECK((*r)[0].uid == "a");
	CHECK((*r)[1].uid_number == 1001);
	CHECK((*r)[1].groups.front() == ldap::dn{ "cn=staff,ou=groups,dc=example,dc=org" });
	CHECK_FALSE((*r)[0].mail.has_value());
	m.check_server();

	REQUIRE(m.log.received.size() == 1);
	const auto &sr = std::get<ldap::search_request>(m.log.received[0].op);
	CHECK(sr.attributes == ldap::string_list{ "uid", "mail", "memberOf", "uidNumber", "modifyTimestamp" });
	CHECK(sr.filter.to_string() == "(&(objectClass=inetOrgPerson)(uidNumber>=1000))");
}

TEST_CASE("typed: an entry that does not decode fails search_as", "[net][mapping]")
{
	mock_ldap m;
	m.serve({ answer({ account_entry(1, "a", "1000"), account_entry(1, "b", "x"), done_msg(1) }) });
	auto r = m.run(m.conn.search_as<account>({ .base = ldap::dn{ "ou=people,dc=example,dc=org" } }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::conversion_failed);
	CHECK(r.error().context
		  == "search ou=people,dc=example,dc=org: entry uid=b,ou=people,dc=example,dc=org: attribute uidNumber: not an integer: \"x\"");
	CHECK(m.conn.is_open());// a mapping error is not a connection error
}

TEST_CASE("typed: modify<T> and add(dn, T)", "[net][mapping]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1, ldap::modify_response{ ldap::ldap_result{ 0 } } } }),
	  answer({ ldap::message{ 2, ldap::add_response{ ldap::ldap_result{ 0 } } } }) });
	const ldap::dn who{ "uid=jdoe,ou=people,dc=example,dc=org" };
	REQUIRE(m.run(m.conn.modify<account>(who,
					{ ldap::replace<&account::mail>("jdoe@example.org"),
					  ldap::add<&account::groups>(ldap::dn{ "cn=admins,ou=groups,dc=example,dc=org" }),
					  ldap::replace<&account::uid_number>(std::int64_t{ 2000 }) }))
			  .has_value());
	REQUIRE(m.run(m.conn.add(who, account{ .uid = "jdoe", .mail = std::nullopt, .groups = {}, .uid_number = 2000 }))
			  .has_value());
	m.check_server();

	using op = ldap::modify_operation;
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0]
		  == ldap::message{ 1,
			ldap::modify_request{ "uid=jdoe,ou=people,dc=example,dc=org",
			  { { op::replace, { "mail", { "jdoe@example.org" } } },
				{ op::add, { "memberOf", { "cn=admins,ou=groups,dc=example,dc=org" } } },
				{ op::replace, { "uidNumber", { "2000" } } } } } });
	// objectClass from the descriptor; no read_only, no empty members.
	CHECK(m.log.received[1]
		  == ldap::message{ 2,
			ldap::add_request{ "uid=jdoe,ou=people,dc=example,dc=org",
			  { { "objectClass", { "inetOrgPerson" } }, { "uid", { "jdoe" } }, { "uidNumber", { "2000" } } } } });
}
