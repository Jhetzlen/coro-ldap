#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/entry.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <map>
#include <string>
#include <unordered_set>

namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using namespace std::string_literals;

static_assert(ldap::detail::is_attribute_description("cn"));
static_assert(ldap::detail::is_attribute_description("userCertificate;binary"));
static_assert(ldap::detail::is_attribute_description("2.5.4.3;lang-en;x-1"));
static_assert(!ldap::detail::is_attribute_description("cn;"));
static_assert(!ldap::detail::is_attribute_description("1cn"));

TEST_CASE("valid attribute descriptions", "[attribute]")
{
	const std::string good = GENERATE(as<std::string>{},
	  "cn",
	  "objectClass",
	  "x-custom-attr",
	  "cn;lang-en",
	  "cn;lang-en;phonetic",
	  "2.5.4.3",
	  "1.3.6.1.4.1.1466.115.121.1.15",
	  "0.0",
	  "10.20;x");
	INFO(good);
	auto a = ldap::attribute::parse(good);
	REQUIRE(a);
	CHECK(a->name() == good);
}

TEST_CASE("invalid attribute descriptions", "[attribute]")
{
	const std::string bad = GENERATE(as<std::string>{},
	  "",
	  "1",
	  "1.",
	  ".1",
	  "1..2",
	  "01.2",
	  "1.02",
	  "-cn",
	  "c n",
	  "c_n",
	  "cn;",
	  "cn;;x",
	  "cn;a_b",
	  ";x",
	  "cn=x",
	  "member;range=0-1499");
	INFO(bad);
	auto b = ldap::attribute::parse(bad);
	REQUIRE_FALSE(b);
	CHECK(b.error().code == client_errc::invalid_attribute);
}

TEST_CASE("attribute comparison and hashing ignore case", "[attribute]")
{
	const ldap::attribute a{ "objectClass" };
	const ldap::attribute b = *ldap::attribute::parse("OBJECTCLASS");
	CHECK(a == b);
	CHECK(a.name() == "objectClass");// spelling kept
	CHECK(std::hash<ldap::attribute>{}(a) == std::hash<ldap::attribute>{}(b));
	CHECK(a != ldap::attribute{ "objectClasses" });
	CHECK(ldap::attribute{ "cn;LANG-EN" } == ldap::attribute{ "CN;lang-en" });
	CHECK(ldap::attribute{ "cn" } != ldap::attribute{ "cn;lang-en" });

	CHECK(ldap::attribute{ "a" } < ldap::attribute{ "B" });
	CHECK(ldap::attribute{ "B" } > ldap::attribute{ "a" });
	CHECK(ldap::attribute{ "cn" } < ldap::attribute{ "cn;x" });
	CHECK((ldap::attribute{ "CN" } <=> ldap::attribute{ "cn" }) == 0);

	std::unordered_set<ldap::attribute> set{
		ldap::attribute{ "mail" }, ldap::attribute{ "MAIL" }, ldap::attribute{ "cn" }
	};
	CHECK(set.size() == 2);
	std::map<ldap::attribute, int> ordered{ { ldap::attribute{ "Mail" }, 1 } };
	CHECK(ordered.count(ldap::attribute{ "mail" }) == 1);

	// Server-supplied names are kept as sent.
	const auto range = ldap::attribute::unchecked("member;range=0-1499");
	CHECK(range.name() == "member;range=0-1499");
	CHECK(range == ldap::attribute::unchecked("MEMBER;RANGE=0-1499"));
}

TEST_CASE("entry from a search result entry", "[entry]")
{
	ldap::search_result_entry e{ .object_name = "uid=jdoe,dc=example,dc=org",
		.attributes = { { "cn", { "John", "Johnny" } },
		  { "objectClass", { "top", "person" } },
		  { "jpegPhoto", { "\xff\xd8\0\x01"s } },
		  { "CN", { "J" } },
		  { "member;range=0-1499", { "a" } },
		  { "noValues", {} } } };
	const auto x = ldap::entry::from(e);
	CHECK(x.dn == "uid=jdoe,dc=example,dc=org");
	REQUIRE(x.attributes.size() == 5);
	CHECK(x.attributes[0].type.name() == "cn");
	CHECK(x.attributes[1].type.name() == "objectClass");

	const auto *cn = x.find("CN");
	REQUIRE(cn != nullptr);
	CHECK(*cn == std::vector<std::string>{ "John", "Johnny", "J" });
	CHECK(x.find(ldap::attribute{ "OBJECTCLASS" }) == &x.attributes[1].values);
	CHECK(x.find("jpegphoto")->front() == "\xff\xd8\0\x01"s);
	CHECK(x.find("member;range=0-1499") != nullptr);
	CHECK(x.find("member") == nullptr);
	CHECK(x.find("mail") == nullptr);
	REQUIRE(x.find("novalues") != nullptr);
	CHECK(x.find("novalues")->empty());
	CHECK(ldap::entry::from(e) == x);
}
