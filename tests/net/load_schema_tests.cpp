// ldap::load_schema over a directory, against the scripted mock server
// (mock_ldap.hpp).
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/schema.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
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

auto root_dse(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::search_result_entry{ "", { { "subschemaSubentry", { "cn=Subschema" } } } } };
}

auto subschema(std::int32_t id) -> ldap::message
{
	return ldap::message{ id,
		ldap::search_result_entry{ "cn=Subschema",
		  { { "attributeTypes",
			  { "( 0.9.2342.19200300.100.1.1 NAME 'uid' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )",
				"( 0.9.2342.19200300.100.1.3 NAME 'mail' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
				"( 1.2.840.113556.1.2.102 NAME 'memberOf' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
				"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
				// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
				"( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE "
				"NO-USER-MODIFICATION )",
				"not a definition" } },
			{ "objectClasses", { "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' STRUCTURAL )" } } } } };
}

}// namespace

TEST_CASE("load_schema: reads the subschema named by the root DSE", "[net][schema]")
{
	mock_ldap m;
	m.serve({ answer({ root_dse(1), done_msg(1) }), answer({ subschema(2), done_msg(2) }) });
	auto s = m.run(ldap::load_schema(m.conn));
	REQUIRE(s.has_value());
	CHECK(s->attribute_count() == 5);
	CHECK(s->skipped() == 1);
	CHECK(ldap::validate<account>(*s).ok());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	const auto &root = std::get<ldap::search_request>(m.log.received[0].op);
	CHECK(root.base_object.empty());
	CHECK(root.scope == ldap::search_scope::base_object);
	CHECK(root.attributes == ldap::string_list{ "subschemaSubentry" });
	const auto &sub = std::get<ldap::search_request>(m.log.received[1].op);
	CHECK(sub.base_object == "cn=Subschema");
	CHECK(sub.filter.to_string() == "(objectClass=subschema)");
	CHECK(sub.attributes == ldap::string_list{ "attributeTypes", "objectClasses", "dITContentRules" });
}

// The root DSE's subschemaSubentry is the server's text: quoted in the
// context sanitized (valid UTF-8 kept, controls, bidi controls and
// U+2028 shown as U+FFFD) and cut at 256 bytes.
TEST_CASE("load_schema: quotes the subschemaSubentry sanitized", "[net][schema]")
{
	const std::string fffd = "\xEF\xBF\xBD";
	auto root_naming = [](std::string where) {
		return answer(
		  { ldap::message{ 1, ldap::search_result_entry{ "", { { "subschemaSubentry", { where } } } } }, done_msg(1) });
	};

	SECTION("not a DN")
	{
		mock_ldap m;
		// 27 bytes, then x up to the cut.
		m.serve(
		  { root_naming("Subschema\r\n\x1b[31m\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC\xE2\x80\xAE" + std::string(300, 'x')) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::client_errc::invalid_dn);
		CHECK(std::string(s.error().context)
			  == "load schema: the root DSE names an invalid subschemaSubentry: Subschema" + fffd + fffd + fffd
				   + "[31m\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC" + fffd + std::string(256 - 27, 'x') + "...");
		m.check_server();
	}
	SECTION("a DN with no subschema entry")
	{
		mock_ldap m;
		// 19 bytes: U+0085 (C1) and U+2028, then y up to the cut.
		m.serve({ root_naming("cn=sub\xC2\x85\xE2\x80\xA8\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC" + std::string(300, 'y')),
		  answer({ done_msg(2) }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::no_such_object);
		CHECK(std::string(s.error().context)
			  == "load schema: no subschema entry at cn=sub" + fffd + fffd + "\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC"
				   + std::string(256 - 19, 'y') + "...");
		m.check_server();
	}
}

TEST_CASE("load_schema: without a subschemaSubentry, or failing", "[net][schema]")
{
	SECTION("the root DSE search fails")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1, 50, "", "no access") }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::insufficient_access_rights);
		CHECK_THAT(std::string(s.error().context), Catch::Matchers::StartsWith("load schema: "));
		m.check_server();
	}
	SECTION("no root DSE entry: cn=Subschema, whose search fails")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1) }), answer({ done_msg(2, 32, "", "no subschema") }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::no_such_object);
		CHECK_THAT(std::string(s.error().context), Catch::Matchers::StartsWith("load schema: "));
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::get<ldap::search_request>(m.log.received[1].op).base_object == "cn=Subschema");
	}
	SECTION("a root DSE without subschemaSubentry, a subschema entry without definitions")
	{
		mock_ldap m;
		m.serve({ answer({ ldap::message{ 1, ldap::search_result_entry{ "", { { "namingContexts", { "dc=x" } } } } },
					done_msg(1) }),
		  answer({ ldap::message{ 2, ldap::search_result_entry{ "cn=Subschema", { { "cn", { "Subschema" } } } } },
			done_msg(2) }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE(s.has_value());
		CHECK(s->attribute_count() == 0);
		CHECK(s->object_class_count() == 0);
		CHECK(s->skipped() == 0);
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::get<ldap::search_request>(m.log.received[1].op).base_object == "cn=Subschema");
	}
}

TEST_CASE("load_schema: a limit code with no entry is an error", "[net][schema]")
{
	SECTION("on the root DSE")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1, 3, "", "time limit") }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::time_limit_exceeded);
		CHECK(s.error().diagnostic == "time limit");
		CHECK(std::string(s.error().context) == "load schema: search \"\"");
		m.check_server();
		CHECK(m.log.received.size() == 1);
	}
	SECTION("on the subschema entry")
	{
		mock_ldap m;
		m.serve({ answer({ root_dse(1), done_msg(1) }), answer({ done_msg(2, 11, "", "admin limit") }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::admin_limit_exceeded);
		CHECK(std::string(s.error().context) == "load schema: search cn=Subschema");
		m.check_server();
	}
	SECTION("an entry that came back is used")
	{
		mock_ldap m;
		m.serve({ answer({ root_dse(1), done_msg(1, 3) }), answer({ subschema(2), done_msg(2, 11) }) });
		auto s = m.run(ldap::load_schema(m.conn));
		REQUIRE(s.has_value());
		CHECK(s->attribute_count() == 5);
		m.check_server();
	}
}
