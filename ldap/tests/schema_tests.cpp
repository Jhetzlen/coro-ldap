#include "jhetz/ldap/schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;
using Catch::Matchers::ContainsSubstring;

namespace {

// As OpenLDAP 2.6 serves them from cn=Subschema (core, cosine, nis,
// inetorgperson, memberof overlay).
const std::pmr::vector<std::pmr::string> openldap_types{
	"( 2.5.4.41 NAME 'name' DESC 'RFC4519: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR "
	"caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
	"( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )",
	"( 2.5.4.4 NAME ( 'sn' 'surname' ) DESC 'RFC2256: last (family) name(s) for which the entity is known by' SUP name "
	")",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) DESC 'RFC4519: user identifier' EQUALITY caseIgnoreMatch "
	"SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
	"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) DESC 'RFC1274: RFC822 Mailbox' EQUALITY "
	"caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
	"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' DESC 'RFC2307: An integer uniquely identifying a user in an administrative "
	"domain' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	"( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC4512: time which object was created' EQUALITY generalizedTimeMatch "
	"ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION "
	"USAGE directoryOperation )",
	"( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group that the entry belongs to' SYNTAX "
	"'1.3.6.1.4.1.1466.115.121.1.12' EQUALITY distinguishedNameMatch USAGE dSAOperation NO-USER-MODIFICATION "
	"X-ORIGIN 'iPlanet Delegated Administrator' )",
	"( 2.5.4.35 NAME 'userPassword' DESC 'RFC4519/2307: password of user' EQUALITY octetStringMatch SYNTAX "
	"1.3.6.1.4.1.1466.115.121.1.40{128} )",
	"( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'pwdAttribute' EQUALITY objectIdentifierMatch SYNTAX "
	"1.3.6.1.4.1.1466.115.121.1.38 SINGLE-VALUE X-ORIGIN ( 'draft-behera-ldap-password-policy' 'OpenLDAP' ) )",
};
const std::pmr::vector<std::pmr::string> openldap_classes{
	"( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
	"( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ "
	"telephoneNumber $ seeAlso $ description ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP "
	"organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense $ mail $ uid ) )",
};

// As Active Directory serves them (CN=Aggregate,CN=Schema,CN=Configuration):
// quoted OIDs, no space after '('.
const std::pmr::vector<std::pmr::string> ad_types{
	"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.656 NAME 'userPrincipalName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",
	"( 1.2.840.113556.1.2.102 NAME 'memberOf' SYNTAX '1.3.6.1.4.1.1466.115.121.1.12' NO-USER-MODIFICATION )",
	"( 2.5.18.1 NAME 'createTimeStamp' SYNTAX '1.3.6.1.4.1.1466.115.121.1.24' SINGLE-VALUE NO-USER-MODIFICATION )",
};
const std::pmr::vector<std::pmr::string> ad_classes{
	"( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL MUST (objectClass ) MAY (o $ "
	"businessCategory $ userCertificate ) )",
	"( 2.5.6.0 NAME 'top' ABSTRACT MUST (objectClass $ objectCategory ) )",
};

}// namespace

TEST_CASE("schema: parse OpenLDAP definitions", "[schema]")
{
	const auto s = ldap::server_schema::parse(openldap_types, openldap_classes);
	CHECK(s.skipped() == 0);
	CHECK(s.attribute_count() == openldap_types.size());
	CHECK(s.object_class_count() == 3);

	const auto *cn = s.find_attribute("commonName");
	REQUIRE(cn != nullptr);
	CHECK(cn->oid == "2.5.4.3");
	CHECK(cn->names == std::vector<std::string>{ "cn", "commonName" });
	CHECK(cn->sup == "name");
	CHECK_FALSE(cn->syntax.has_value());
	CHECK(s.syntax_of(*cn) == ldap::syntax::directory_string);// inherited from name, {32768} removed
	CHECK(s.find_attribute("CN") == cn);
	CHECK(s.find_attribute("cn;lang-en") == cn);
	CHECK(s.find_attribute("2.5.4.3") == cn);

	const auto *ts = s.find_attribute("createTimestamp");
	REQUIRE(ts != nullptr);
	CHECK(ts->single_value);
	CHECK(ts->no_user_modification);
	const auto *member_of = s.find_attribute("memberOf");
	REQUIRE(member_of != nullptr);
	CHECK(member_of->syntax == ldap::syntax::dn);// quoted
	CHECK_FALSE(member_of->single_value);
	CHECK(s.find_attribute("pwdAttribute") != nullptr);// list-valued extension
	CHECK(s.find_object_class("inetorgperson") != nullptr);
	CHECK(s.find_object_class("2.5.6.6")->names == std::vector<std::string>{ "person" });
	CHECK(s.find_attribute("nope") == nullptr);
}

TEST_CASE("schema: parse Active Directory definitions", "[schema]")
{
	const auto s = ldap::server_schema::parse(ad_types, ad_classes);
	CHECK(s.skipped() == 0);
	CHECK(s.find_attribute("samaccountname")->syntax == ldap::syntax::directory_string);
	CHECK(s.find_attribute("userAccountControl")->single_value);
	CHECK(s.find_object_class("user") != nullptr);
	CHECK(s.find_object_class("top") != nullptr);
}

TEST_CASE("schema: unparseable definitions are skipped", "[schema]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.3 NAME 'ok' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"",
		"1.2.3 NAME 'no parenthesis'",
		"( 1.2.4 NAME 'unterminated )",
		"( 1.2.5 NAME ( 'a' 'b' )",
		"( 1.2.6 NAME 'x' ) trailing",
		"( 1.2.7 NAME 'bad\\zz' )",
		"( )",
		"( 1.2.8 'not a keyword' )",
		"( 1.2.9 SUP )",
	};
	const auto s = ldap::server_schema::parse(types, {});
	CHECK(s.attribute_count() == 1);
	CHECK(s.skipped() == types.size() - 1);
	CHECK(s.find_attribute("ok") != nullptr);

	auto bad = ldap::parse_attribute_type("( 1.2.4 NAME 'unterminated )");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::decode_error);
	// Escapes are decoded; "it's" is not a valid descriptor, so the NAME is dropped.
	auto escaped = ldap::parse_attribute_type("( 1.2 NAME 'it\\27s' DESC 'a\\5cb' )");
	REQUIRE(escaped.has_value());
	CHECK(escaped->names.empty());
	CHECK(ldap::parse_attribute_type("( 1.2 NAME ( 'ok' 'not;ok' '' ) )")->names == std::vector<std::string>{ "ok" });
	CHECK_FALSE(ldap::parse_attribute_type("( not-an-oid! NAME 'x' )").has_value());
	CHECK(ldap::parse_attribute_type("(1.2 NAME 'tight' SINGLE-VALUE)")->single_value);
	CHECK(ldap::parse_attribute_type("( 1.2 name 'lower' single-value )")->single_value);
}

TEST_CASE("schema: SUP cycles do not loop", "[schema]")
{
	const std::pmr::vector<std::pmr::string> types{ "( 1.1 NAME 'a' SUP b )", "( 1.2 NAME 'b' SUP a )" };
	const auto s = ldap::server_schema::parse(types, {});
	CHECK_FALSE(s.syntax_of(*s.find_attribute("a")).has_value());
}

// ---------------------------------------------------------------- validate

namespace {

struct good_person
{
	std::string uid;
	std::vector<std::string> cn;
	std::optional<std::int64_t> uid_number;
	std::vector<ldap::dn> member_of;
	std::chrono::sys_seconds created{};
};

struct bad_person
{
	std::string uid;// fine (uid is multi-valued: a warning)
	std::string cn;// single member on multi-valued cn: warning
	std::int64_t mail = 0;// int on IA5String: syntax error
	std::vector<std::string> no_such;// unknown attribute
	std::chrono::sys_seconds created{};// writable NO-USER-MODIFICATION: error
	bool user_password = false;// bool on octet string: syntax error
};

}// namespace

template<>
constexpr auto ldap::schema<good_person> = ldap::describe(ldap::object_class("inetOrgPerson", "person"),
  ldap::field<&good_person::uid>("uid"),
  ldap::field<&good_person::cn>("commonName"),
  ldap::field<&good_person::uid_number>("uidNumber"),
  ldap::field<&good_person::member_of>("memberOf", ldap::read_only),
  ldap::field<&good_person::created>("createTimestamp", ldap::read_only));

template<>
constexpr auto ldap::schema<bad_person> = ldap::describe(ldap::object_class("inetOrgPerson", "posixAccount"),
  ldap::field<&bad_person::uid>("uid"),
  ldap::field<&bad_person::cn>("cn"),
  ldap::field<&bad_person::mail>("mail"),
  ldap::field<&bad_person::no_such>("x-noSuchAttribute"),
  ldap::field<&bad_person::created>("createTimestamp"),
  ldap::field<&bad_person::user_password>("userPassword"));

TEST_CASE("schema: validate a matching descriptor", "[schema][validate]")
{
	const auto s = ldap::server_schema::parse(openldap_types, openldap_classes);
	const auto rep = ldap::validate<good_person>(s);
	CHECK(rep.ok());
	// uid is multi-valued on the server but a single member here: a warning only.
	REQUIRE(rep.issues.size() == 1);
	CHECK(rep.issues[0].what == ldap::schema_issue::kind::single_member_multi_valued);
	CHECK(rep.issues[0].name == "uid");
	CHECK_FALSE(rep.issues[0].is_error());
}

TEST_CASE("schema: validate lists every issue", "[schema][validate]")
{
	const auto s = ldap::server_schema::parse(openldap_types, openldap_classes);
	const auto rep = ldap::validate<bad_person>(s);
	CHECK_FALSE(rep.ok());
	using k = ldap::schema_issue::kind;
	auto has = [&](k what, std::string_view name) {
		for (const auto &i : rep.issues)
			if (i.what == what && i.name == name) return true;
		return false;
	};
	CHECK(has(k::unknown_object_class, "posixAccount"));
	CHECK(has(k::single_member_multi_valued, "uid"));
	CHECK(has(k::single_member_multi_valued, "cn"));
	CHECK(has(k::syntax_mismatch, "mail"));
	CHECK(has(k::unknown_attribute, "x-noSuchAttribute"));
	CHECK(has(k::writable_but_no_user_modification, "createTimestamp"));
	CHECK(has(k::syntax_mismatch, "userPassword"));
	// mail and userPassword are single members on multi-valued attributes too.
	CHECK(has(k::single_member_multi_valued, "mail"));
	CHECK(has(k::single_member_multi_valued, "userPassword"));
	CHECK(rep.issues.size() == 9);
	const std::string text = rep.to_string();
	CHECK_THAT(text, ContainsSubstring("error: object class posixAccount: not defined on the server"));
	CHECK_THAT(text, ContainsSubstring("error: attribute mail: syntax 1.3.6.1.4.1.1466.115.121.1.26 is not one"));
	CHECK_THAT(text, ContainsSubstring("warning: attribute cn: single-valued member"));
	CHECK_THAT(text, ContainsSubstring("mark the member ldap::read_only"));
}
