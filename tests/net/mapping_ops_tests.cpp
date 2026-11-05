// Typed operations (search_as, modify<T>, add(dn, T)) against the scripted
// mock server (mock_ldap.hpp).
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

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

auto account_entry(std::int32_t id, std::string_view uid, std::string_view number) -> ldap::message
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

// The base is often a DN the server returned: sanitized in the context
// (valid UTF-8 kept, U+2028 shown as U+FFFD) and cut at 256 bytes, as the
// entry's DN.
TEST_CASE("typed: search_as quotes its base sanitized", "[net][mapping]")
{
	mock_ldap m;
	m.serve({ answer({ account_entry(1, "b", "x"), done_msg(1) }) });
	// 13 bytes: U+2028 and accents; then o up to the cut.
	auto base = ldap::dn::parse("ou=\xE2\x80\xA8p\xC3\xA9pl\xC3\xA9" + std::string(400, 'o') + ",dc=example,dc=org");
	REQUIRE(base.has_value());
	auto r = m.run(m.conn.search_as<account>({ .base = std::move(*base) }));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::conversion_failed);
	CHECK(std::string(r.error().context)
		  == "search ou=\xEF\xBF\xBDp\xC3\xA9pl\xC3\xA9" + std::string(256 - 13, 'o')
			   + "...: entry uid=b,ou=people,dc=example,dc=org: attribute uidNumber: not an integer: \"x\"");
}

TEST_CASE("typed: modify<T> and add(dn, T)", "[net][mapping]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1, ldap::modify_response{ ldap::ldap_result{ 0 } } } }),
	  answer({ ldap::message{ 2, ldap::add_response{ ldap::ldap_result{ 0 } } } }) });
	const ldap::dn who{ "uid=jdoe,ou=people,dc=example,dc=org" };
	REQUIRE(
	  m.run(m.conn.modify<account>(who,
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

// A value that does not encode fails modify<T> and add(dn, T) before
// anything is sent, the schema check included.
TEST_CASE("typed: modify<T>, add(dn, T) and search_as fail before sending on a value that does not encode",
  "[net][mapping]")
{
	mock_ldap m({ .schema_check = ldap::schema_check::on_first_use });
	m.serve({});
	const ldap::dn who{ "uid=jdoe,ou=people,dc=example,dc=org" };

	auto mod = m.run(m.conn.modify<account>(who,
	  { ldap::replace<&account::uid_number>(std::int64_t{ 2000 }),
		ldap::replace<&account::mail>("jdoe\xFF@example.org"),
		ldap::replace<&account::uid>("j\xC3") }));
	REQUIRE_FALSE(mod.has_value());
	CHECK(mod.error().code == ldap::client_errc::encode_error);
	CHECK(
	  std::string(mod.error().context)
	  == "modify uid=jdoe,ou=people,dc=example,dc=org: replace mail: not valid UTF-8 (ill-formed sequence at offset "
		 "4)");

	auto add = m.run(m.conn.add(who, account{ .uid = "jdoe\xED\xA0\x80", .mail = std::nullopt, .groups = {} }));
	REQUIRE_FALSE(add.has_value());
	CHECK(add.error().code == ldap::client_errc::encode_error);
	CHECK(
	  std::string(add.error().context)
	  == "add uid=jdoe,ou=people,dc=example,dc=org: attribute uid: not valid UTF-8 (ill-formed sequence at offset 4)");

	// A typed filter on a value that does not encode is the empty (poison)
	// filter: search_as rejects it before the schema load.
	auto found = m.run(m.conn.search_as<account>({ .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .filter =
		ldap::filters::field<&account::uid>() == std::string("j\xC3") && ldap::filters::attr("mail").present() }));
	REQUIRE_FALSE(found.has_value());
	CHECK(found.error().code == ldap::client_errc::invalid_filter);
	CHECK(std::string(found.error().context) == "search ou=people,dc=example,dc=org: filter: empty");

	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());
}

// ---------------------------------------------------------------- schema

namespace {

struct mismatched
{
	std::int64_t uid = 0;// uid is a DirectoryString: syntax error
};

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

template<> constexpr auto ldap::schema<mismatched> = ldap::describe(ldap::field<&mismatched::uid>("uid"));

TEST_CASE("typed: load_schema reads the subschema named by the root DSE", "[net][mapping][schema]")
{
	mock_ldap m;
	m.serve({ answer({ root_dse(1), done_msg(1) }), answer({ subschema(2), done_msg(2) }) });
	auto s = m.run(m.conn.load_schema());
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
	CHECK(sub.attributes == ldap::string_list{ "attributeTypes", "objectClasses" });
}

// The root DSE's subschemaSubentry is the server's text: quoted in the
// context sanitized (valid UTF-8 kept, controls, bidi controls and
// U+2028 shown as U+FFFD) and cut at 256 bytes.
TEST_CASE("typed: load_schema quotes the subschemaSubentry sanitized", "[net][mapping][schema]")
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
		auto s = m.run(m.conn.load_schema());
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
		auto s = m.run(m.conn.load_schema());
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::no_such_object);
		CHECK(std::string(s.error().context)
			  == "load schema: no subschema entry at cn=sub" + fffd + fffd + "\xC3\xA9\xE6\x97\xA5\xE6\x9C\xAC"
				   + std::string(256 - 19, 'y') + "...");
		m.check_server();
	}
}

TEST_CASE("typed: schema_check::on_first_use", "[net][mapping][schema]")
{
	mock_ldap m({ .schema_check = ldap::schema_check::on_first_use });
	m.serve({ answer({ root_dse(1), done_msg(1) }),
	  answer({ subschema(2), done_msg(2) }),
	  answer({ account_entry(3, "a", "1000"), done_msg(3) }),
	  answer({ done_msg(4) }) });
	// The first typed search loads and checks the schema, then runs.
	auto first = m.run(m.conn.search_as<account>({ .base = ldap::dn{} }));
	REQUIRE(first.has_value());
	CHECK(first->size() == 1);
	// The second one does neither again.
	CHECK(m.run(m.conn.search_as<account>({ .base = ldap::dn{} })).has_value());
	// A type that does not match fails before anything is sent.
	auto bad = m.run(m.conn.search_as<mismatched>({ .base = ldap::dn{} }));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::schema_mismatch);
	CHECK_THAT(std::string(bad.error().context), Catch::Matchers::ContainsSubstring("error: attribute uid: syntax"));
	m.check_server();
	CHECK(m.log.received.size() == 4);
}

TEST_CASE("typed: load_schema without a subschemaSubentry, or failing", "[net][mapping][schema]")
{
	SECTION("the root DSE search fails")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1, 50, "", "no access") }) });
		auto s = m.run(m.conn.load_schema());
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::errc::insufficient_access_rights);
		CHECK_THAT(std::string(s.error().context), Catch::Matchers::StartsWith("load schema: "));
		m.check_server();
	}
	SECTION("no root DSE entry: cn=Subschema, whose search fails")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1) }), answer({ done_msg(2, 32, "", "no subschema") }) });
		auto s = m.run(m.conn.load_schema());
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
		auto s = m.run(m.conn.load_schema());
		REQUIRE(s.has_value());
		CHECK(s->attribute_count() == 0);
		CHECK(s->object_class_count() == 0);
		CHECK(s->skipped() == 0);
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(std::get<ldap::search_request>(m.log.received[1].op).base_object == "cn=Subschema");
	}
}

namespace {

struct mismatched_entry
{
	std::int64_t uid = 0;// uid is a DirectoryString: syntax error
};

}// namespace

template<>
constexpr auto ldap::schema<mismatched_entry> =
  ldap::describe(ldap::object_class("inetOrgPerson"), ldap::field<&mismatched_entry::uid>("uid"));

// schema_check::on_first_use: a schema that cannot be loaded, or a type
// that does not match it, fails modify<T> and add(dn, T) before they are
// sent.
TEST_CASE("typed: modify<T> and add(dn, T) with schema_check::on_first_use", "[net][mapping][schema]")
{
	const ldap::dn who{ "uid=jdoe,ou=people,dc=example,dc=org" };
	SECTION("the schema does not load")
	{
		mock_ldap m({ .schema_check = ldap::schema_check::on_first_use });
		m.serve({ answer({ done_msg(1, 50) }) });
		auto mod = m.run(m.conn.modify<account>(who, { ldap::replace<&account::mail>("j@example.org") }));
		REQUIRE_FALSE(mod.has_value());
		CHECK(mod.error().code == ldap::errc::insufficient_access_rights);
		m.check_server();
		CHECK(m.log.received.size() == 1);
	}
	SECTION("the type does not match")
	{
		mock_ldap m({ .schema_check = ldap::schema_check::on_first_use });
		m.serve({ answer({ root_dse(1), done_msg(1) }), answer({ subschema(2), done_msg(2) }) });
		auto mod = m.run(m.conn.modify<mismatched>(who, { ldap::replace<&mismatched::uid>(std::int64_t{ 7 }) }));
		REQUIRE_FALSE(mod.has_value());
		CHECK(mod.error().code == ldap::client_errc::schema_mismatch);
		auto add = m.run(m.conn.add(who, mismatched_entry{ .uid = 7 }));
		REQUIRE_FALSE(add.has_value());
		CHECK(add.error().code == ldap::client_errc::schema_mismatch);
		m.check_server();
		CHECK(m.log.received.size() == 2);// the schema, loaded once
	}
	SECTION("a moved-from connection: no schema to check, not connected")
	{
		mock_ldap m({ .schema_check = ldap::schema_check::on_first_use });
		m.serve({});
		const ldap::connection moved = std::move(m.conn);
		auto add = m.run(m.conn.add(who, account{ .uid = "jdoe", .mail = std::nullopt, .groups = {} }));
		REQUIRE_FALSE(add.has_value());
		CHECK(add.error().code == ldap::client_errc::not_connected);
		CHECK(m.log.received.empty());
	}
}
