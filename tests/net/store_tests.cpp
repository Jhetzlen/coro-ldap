// ldap::store and sync::store against the scripted mock server
// (mock_ldap.hpp) and the threaded one (server_thread.hpp).
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/store.hpp"
#include "jhetz/ldap/sync_extended_operations.hpp"
#include "jhetz/ldap/sync_store.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"
#include "server_thread.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;

namespace {

struct person
{
	std::string uid;
	std::optional<std::string> mail;
	std::int64_t uid_number = 0;
	std::chrono::sys_seconds modified{};
};

struct badly_typed
{
	std::int64_t uid = 0;// uid is a DirectoryString: syntax error
};

struct card
{
	std::string cn;
};

}// namespace

template<>
constexpr auto ldap::schema<person> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::mail>("mail"),
  ldap::field<&person::uid_number>("uidNumber"),
  ldap::field<&person::modified>("modifyTimestamp", ldap::read_only));

template<>
constexpr auto ldap::schema<badly_typed> =
  ldap::describe(ldap::object_class("inetOrgPerson"), ldap::field<&badly_typed::uid>("uid"));

template<>
constexpr auto ldap::schema<card> = ldap::describe(ldap::object_class("person"), ldap::field<&card::cn>("cn"));

static_assert(ldap::directory<ldap::connection>);
static_assert(ldap::directory<ldap::client>);
static_assert(ldap::directory<const ldap::shared_connection>);
static_assert(ldap::sync::directory<ldap::sync::connection>);
static_assert(ldap::sync::directory<ldap::sync::client>);
static_assert(ldap::sync::directory<ldap::sync::lease>);
static_assert(ldap::sync::directory<ldap::sync::exclusive_lease>);
static_assert(ldap::extended_directory<ldap::connection>);
static_assert(ldap::extended_directory<ldap::client>);
static_assert(ldap::extended_directory<const ldap::shared_connection>);
static_assert(ldap::sync::extended_directory<ldap::sync::connection>);
static_assert(ldap::sync::extended_directory<ldap::sync::client>);
static_assert(ldap::sync::extended_directory<ldap::sync::lease>);
static_assert(ldap::sync::extended_directory<ldap::sync::exclusive_lease>);

namespace {

const ldap::dn people_base{ "ou=people,dc=example,dc=org" };

auto person_entry(std::int32_t id, std::string_view uid, std::string_view number) -> ldap::message
{
	return ldap::message{ id,
		ldap::search_result_entry{ "uid=" + std::string(uid) + ",ou=people,dc=example,dc=org",
		  { { "uid", { uid } }, { "uidNumber", { number } }, { "modifyTimestamp", { "20250101000000Z" } } } } };
}

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
				"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
				// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
				"( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE "
				"NO-USER-MODIFICATION )" } },
			{ "objectClasses", { "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' STRUCTURAL )" } } } } };
}

auto ok(std::int32_t id, const auto &response) -> ldap::message
{
	return ldap::message{ id, std::remove_cvref_t<decltype(response)>{ ldap::ldap_result{ 0 } } };
}

}// namespace

TEST_CASE("store: dn_of escapes the naming value under the base", "[net][store]")
{
	mock_ldap m;
	const ldap::store s(m.conn, people_base, ldap::named_by<&person::uid>);
	auto d = s.dn_of("a,b+c \xC3\xA9");
	REQUIRE(d.has_value());
	CHECK(d->to_string() == "uid=a\\,b\\+c \xC3\xA9,ou=people,dc=example,dc=org");
	CHECK(d->parent() == people_base);

	auto bad = s.dn_of("j\xC3");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::encode_error);
	CHECK_THAT(std::string(bad.error().context), Catch::Matchers::StartsWith("attribute uid: "));
}

TEST_CASE("store: get reads one entry with a base-object search", "[net][store]")
{
	mock_ldap m;
	m.serve({ answer({ person_entry(1, "jdoe", "1000"), done_msg(1) }),
	  answer({ done_msg(2, 32, "ou=people,dc=example,dc=org", "no such entry") }),
	  answer({ done_msg(3) }) });
	ldap::store s(m.conn, people_base, ldap::named_by<&person::uid>);

	auto found = m.run(s.get("jdoe"));
	REQUIRE(found.has_value());
	REQUIRE(found->has_value());
	CHECK((*found)->uid == "jdoe");
	CHECK((*found)->uid_number == 1000);

	// noSuchObject, or an entry that is not of T's object classes: nullopt.
	auto missing = m.run(s.get("nobody"));
	REQUIRE(missing.has_value());
	CHECK_FALSE(missing->has_value());
	auto other = m.run(s.get_at(ldap::dn{ "cn=config" }));
	REQUIRE(other.has_value());
	CHECK_FALSE(other->has_value());
	m.check_server();

	REQUIRE(m.log.received.size() == 3);
	const auto &sr = std::get<ldap::search_request>(m.log.received[0].op);
	CHECK(sr.base_object == "uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(sr.scope == ldap::search_scope::base_object);
	CHECK(sr.filter.to_string() == "(&(objectClass=inetOrgPerson)(objectClass=*))");
	CHECK(sr.attributes == ldap::string_list{ "uid", "mail", "uidNumber", "modifyTimestamp" });
	CHECK(std::get<ldap::search_request>(m.log.received[2].op).base_object == "cn=config");
}

TEST_CASE("store: get returns the other errors and decode failures", "[net][store]")
{
	mock_ldap m;
	m.serve({ answer({ done_msg(1, 50, "", "no access") }), answer({ person_entry(2, "jdoe", "x"), done_msg(2) }) });
	ldap::store s(m.conn, people_base, ldap::named_by<&person::uid>);
	auto denied = m.run(s.get("jdoe"));
	REQUIRE_FALSE(denied.has_value());
	CHECK(denied.error().code == ldap::errc::insufficient_access_rights);
	auto bad = m.run(s.get("jdoe"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::conversion_failed);
	CHECK(std::string(bad.error().context)
		  == "search uid=jdoe,ou=people,dc=example,dc=org: entry uid=jdoe,ou=people,dc=example,dc=org: attribute "
			 "uidNumber: not an integer: \"x\"");
	m.check_server();
}

TEST_CASE("store: add, modify and remove name the entry from the key", "[net][store]")
{
	mock_ldap m;
	m.serve({ answer({ ok(1, ldap::add_response{}) }),
	  answer({ ok(2, ldap::modify_response{}) }),
	  answer({ ok(3, ldap::modify_response{}) }),
	  answer({ ok(4, ldap::del_response{}) }),
	  answer({ ok(5, ldap::del_response{}) }) });
	ldap::store s(m.conn, people_base, ldap::named_by<&person::uid>);
	const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };

	REQUIRE(m.run(s.add(person{ .uid = "jdoe", .mail = "j@example.org", .uid_number = 1000 })).has_value());
	REQUIRE(m.run(s.modify("jdoe", { ldap::replace<&person::mail>("john@example.org") })).has_value());
	REQUIRE(m.run(s.modify_at(ldap::dn{ "cn=jdoe,ou=other,dc=example,dc=org" }, { ldap::remove<&person::mail>() }))
		.has_value());
	REQUIRE(m.run(s.remove("jdoe")).has_value());
	REQUIRE(m.run(s.remove_at(ldap::dn{ "cn=jdoe,ou=other,dc=example,dc=org" })).has_value());
	m.check_server();

	using op = ldap::modify_operation;
	REQUIRE(m.log.received.size() == 5);
	CHECK(m.log.received[0]
		  == ldap::message{ 1,
			ldap::add_request{ jdoe.to_string(),
			  { { "objectClass", { "inetOrgPerson" } },
				{ "uid", { "jdoe" } },
				{ "mail", { "j@example.org" } },
				{ "uidNumber", { "1000" } } } } });
	CHECK(m.log.received[1]
		  == ldap::message{
			2, ldap::modify_request{ jdoe.to_string(), { { op::replace, { "mail", { "john@example.org" } } } } } });
	CHECK(m.log.received[2]
		  == ldap::message{
			3, ldap::modify_request{ "cn=jdoe,ou=other,dc=example,dc=org", { { op::delete_, { "mail", {} } } } } });
	CHECK(m.log.received[3] == ldap::message{ 4, ldap::del_request{ jdoe.to_string() } });
	CHECK(m.log.received[4] == ldap::message{ 5, ldap::del_request{ "cn=jdoe,ou=other,dc=example,dc=org" } });
}

TEST_CASE("store: a value that does not encode fails before anything is sent", "[net][store]")
{
	mock_ldap m;
	m.serve({});
	ldap::store s(
	  m.conn, people_base, ldap::named_by<&person::uid>, { .schema_check = ldap::schema_check::on_first_use });

	auto add_key = m.run(s.add(person{ .uid = "j\xC3", .mail = std::nullopt }));
	REQUIRE_FALSE(add_key.has_value());
	CHECK(add_key.error().code == ldap::client_errc::encode_error);
	CHECK_THAT(std::string(add_key.error().context), Catch::Matchers::StartsWith("add: attribute uid: "));

	auto add_value = m.run(s.add(person{ .uid = "jdoe", .mail = "j\xFF" }));
	REQUIRE_FALSE(add_value.has_value());
	CHECK_THAT(std::string(add_value.error().context),
	  Catch::Matchers::StartsWith("add uid=jdoe,ou=people,dc=example,dc=org: attribute mail: "));

	auto mod = m.run(s.modify("jdoe", { ldap::replace<&person::mail>("j\xFF") }));
	REQUIRE_FALSE(mod.has_value());
	CHECK_THAT(std::string(mod.error().context),
	  Catch::Matchers::StartsWith("modify uid=jdoe,ou=people,dc=example,dc=org: replace mail: "));

	auto found = m.run(s.search(ldap::filters::field<&person::uid>() == std::string("j\xC3")));
	REQUIRE_FALSE(found.has_value());
	CHECK(found.error().code == ldap::client_errc::invalid_filter);
	CHECK(std::string(found.error().context) == "search ou=people,dc=example,dc=org: filter: empty");

	auto got = m.run(s.get("j\xC3"));
	REQUIRE_FALSE(got.has_value());
	CHECK_THAT(std::string(got.error().context), Catch::Matchers::StartsWith("search: attribute uid: "));
	m.check_server();
	CHECK(m.log.received.empty());
}

TEST_CASE("store: search returns records under the base, on the limit codes too", "[net][store]")
{
	mock_ldap m;
	m.serve(
	  { answer({ person_entry(1, "a", "1000"),
		  ldap::message{ 1,
			ldap::search_result_entry{ "cn=b,ou=people,dc=example,dc=org",
			  { { "uid", { "b" } }, { "uidNumber", { "1001" } }, { "modifyTimestamp", { "20250101000000Z" } } } } },
		  done_msg(1, 4, "", "size limit") }),
		answer({ person_entry(2, "c", "x"), done_msg(2) }) });
	ldap::store s(m.conn, people_base, ldap::named_by<&person::uid>);

	auto r = m.run(s.search(ldap::filters::field<&person::uid_number>() >= 1000));
	REQUIRE(r.has_value());
	CHECK(r->result_code == 4);
	CHECK(r->diagnostic_message == "size limit");
	REQUIRE(r->entries.size() == 2);
	CHECK(r->entries[0].dn == ldap::dn{ "uid=a,ou=people,dc=example,dc=org" });
	CHECK(r->entries[0].value.uid == "a");
	CHECK(r->entries[1].dn == ldap::dn{ "cn=b,ou=people,dc=example,dc=org" });// named otherwise
	CHECK(r->entries[1].value.uid_number == 1001);

	auto bad = m.run(s.search());
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::conversion_failed);
	m.check_server();

	REQUIRE(m.log.received.size() == 2);
	const auto &first = std::get<ldap::search_request>(m.log.received[0].op);
	CHECK(first.base_object == "ou=people,dc=example,dc=org");
	CHECK(first.scope == ldap::search_scope::single_level);
	CHECK(first.filter.to_string() == "(&(objectClass=inetOrgPerson)(uidNumber>=1000))");
	CHECK(first.attributes == ldap::string_list{ "uid", "mail", "uidNumber", "modifyTimestamp" });
	CHECK(std::get<ldap::search_request>(m.log.received[1].op).filter.to_string()
		  == "(&(objectClass=inetOrgPerson)(objectClass=*))");
}

// The base is often a DN the server returned: sanitized in the context
// (valid UTF-8 kept, U+2028 shown as U+FFFD) and cut at 256 bytes, as the
// entry's DN.
TEST_CASE("store: search quotes its base sanitized", "[net][store]")
{
	mock_ldap m;
	m.serve({ answer({ person_entry(1, "b", "x"), done_msg(1) }) });
	// 13 bytes: U+2028 and accents; then o up to the cut.
	auto base = ldap::dn::parse("ou=\xE2\x80\xA8p\xC3\xA9pl\xC3\xA9" + std::string(400, 'o') + ",dc=example,dc=org");
	REQUIRE(base.has_value());
	ldap::store s(m.conn, std::move(*base), ldap::named_by<&person::uid>);
	auto r = m.run(s.search());
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::conversion_failed);
	CHECK(std::string(r.error().context)
		  == "search ou=\xEF\xBF\xBDp\xC3\xA9pl\xC3\xA9" + std::string(256 - 13, 'o')
			   + "...: entry uid=b,ou=people,dc=example,dc=org: attribute uidNumber: not an integer: \"x\"");
	CHECK(m.conn.is_open());// a mapping error is not a connection error
}

TEST_CASE("store: schema_check::on_first_use", "[net][store][schema]")
{
	SECTION("checked once, then every operation runs")
	{
		mock_ldap m;
		m.serve({ answer({ root_dse(1), done_msg(1) }),
		  answer({ subschema(2), done_msg(2) }),
		  answer({ person_entry(3, "a", "1000"), done_msg(3) }),
		  answer({ ok(4, ldap::del_response{}) }) });
		ldap::store s(
		  m.conn, people_base, ldap::named_by<&person::uid>, { .schema_check = ldap::schema_check::on_first_use });
		CHECK(m.run(s.get("a")).has_value());
		CHECK(m.run(s.remove("a")).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 4);
		CHECK(
		  std::get<ldap::search_request>(m.log.received[0].op).attributes == ldap::string_list{ "subschemaSubentry" });
		CHECK(std::get<ldap::search_request>(m.log.received[1].op).base_object == "cn=Subschema");
	}
	SECTION("a mismatch fails every operation, loaded once")
	{
		mock_ldap m;
		m.serve({ answer({ root_dse(1), done_msg(1) }), answer({ subschema(2), done_msg(2) }) });
		ldap::store s(
		  m.conn, people_base, ldap::named_by<&badly_typed::uid>, { .schema_check = ldap::schema_check::on_first_use });
		for (int i = 0; i < 2; ++i) {
			auto r = m.run(s.add(badly_typed{ .uid = 7 }));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::schema_mismatch);
			CHECK_THAT(
			  std::string(r.error().context), Catch::Matchers::ContainsSubstring("error: attribute uid: syntax"));
		}
		m.check_server();
		CHECK(m.log.received.size() == 2);
	}
	SECTION("a schema that does not load is tried again")
	{
		mock_ldap m;
		m.serve({ answer({ done_msg(1, 50, "", "no access") }),
		  answer({ root_dse(2), done_msg(2) }),
		  answer({ subschema(3), done_msg(3) }),
		  answer({ ok(4, ldap::del_response{}) }) });
		ldap::store s(
		  m.conn, people_base, ldap::named_by<&person::uid>, { .schema_check = ldap::schema_check::on_first_use });
		auto first = m.run(s.remove("a"));
		REQUIRE_FALSE(first.has_value());
		CHECK(first.error().code == ldap::errc::insufficient_access_rights);
		CHECK_THAT(std::string(first.error().context), Catch::Matchers::StartsWith("load schema: "));
		CHECK(m.run(s.remove("a")).has_value());
		m.check_server();
		CHECK(m.log.received.size() == 4);
	}
}

TEST_CASE("store: over a shared lease's connection", "[net][store]")
{
	mock_ldap m;
	m.serve({ answer({ person_entry(1, "a", "1000"), done_msg(1) }) });
	const ldap::shared_connection shared(m.conn);
	ldap::store s(shared, people_base, ldap::named_by<&person::uid>);
	static_assert(std::same_as<decltype(s)::source_type, const ldap::shared_connection>);
	auto r = m.run(s.search());
	REQUIRE(r.has_value());
	CHECK(r->entries.size() == 1);
	m.check_server();
}

TEST_CASE("sync store: the same operations, blocking", "[net][store][sync]")
{
	server_thread srv;
	ldap::sync::connection c;
	REQUIRE(c.connect(srv.url()).has_value());
	ldap::sync::store s(c, people_base, ldap::named_by<&card::cn>);

	auto all = s.search();
	REQUIRE(all.has_value());
	REQUIRE(all->entries.size() == 2);
	CHECK(all->entries[0].dn == ldap::dn{ "uid=x,ou=people,dc=example,dc=org" });
	CHECK(all->entries[1].value.cn == "Y");
	auto one = s.get("X");
	REQUIRE(one.has_value());
	REQUIRE(one->has_value());
	CHECK((*one)->cn == "X");
	CHECK(s.add(card{ .cn = "Z" }).has_value());
	CHECK(s.modify("Z", { ldap::replace<&card::cn>("Z") }).has_value());
	CHECK(s.remove("Z").has_value());
	CHECK(srv.requests == 5);

	auto bad = s.add(card{ .cn = "\xC3" });
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::encode_error);
	CHECK(srv.requests == 5);
}
