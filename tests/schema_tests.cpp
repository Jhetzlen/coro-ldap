#include "jhetz/ldap/schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
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
	REQUIRE(s.syntax_of(*cn) != nullptr);
	CHECK(*s.syntax_of(*cn) == ldap::syntax::directory_string);// inherited from name, {32768} removed
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

// RFC 4512 section 4.1.2: SYNTAX is a noidlen, a numericoid with an
// optional {len}. Anything else is the server's own text (it could never
// match a syntax the mapping knows): the definition is skipped, and the
// error does not quote it.
TEST_CASE("schema: a SYNTAX that is not a numeric OID skips the definition", "[schema]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.1 NAME 'accented' DESC '\\5C caf\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC' SYNTAX "
		"'1.3.6.1.4.1.1466.115.121.1.15{64}' )",
		"( 1.2.2 NAME 'forged' SYNTAX '1.2\x1b[31m\\5C\r\nerror: forged' )",
		"( 1.2.3 NAME 'bidi' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15\xE2\x80\xAE )",
		"( 1.2.4 NAME 'named' SYNTAX directoryString )",
		"( 1.2.5 NAME 'accentedSyntax' SYNTAX 1.2.\xC3\xA9 )",
		"( 1.2.6 NAME 'lengthOnly' SYNTAX {64} )",
		"( 1.2.7 NAME 'leadingZero' SYNTAX 1.02 )",
	};
	const auto s = ldap::server_schema::parse(types, {});
	CHECK(s.attribute_count() == 1);
	CHECK(s.skipped() == types.size() - 1);
	const auto *accented = s.find_attribute("accented");
	REQUIRE(accented != nullptr);
	CHECK(accented->syntax == ldap::syntax::directory_string);

	auto forged = ldap::parse_attribute_type(types[1]);
	REQUIRE_FALSE(forged.has_value());
	CHECK(forged.error().code == ldap::client_errc::decode_error);
	CHECK(forged.error().context == "schema: SYNTAX is not a numeric OID");
	// An object class has no SYNTAX: not checked there.
	CHECK(ldap::parse_object_class(types[1]).has_value());
}

// noidlen's {len} is "{" 1*DIGIT "}" right after the OID (no space). A
// spaced "{256}" is not a keyword: it fails the definition, which is
// skipped and counted, instead of being read as a keyword that takes
// SINGLE-VALUE as its value (single_value false, silently). Any other word
// where a keyword goes fails the same way; X- extension names may hold '_'.
TEST_CASE("schema: SYNTAX lengths are {digits} attached to the OID; other words are not keywords", "[schema]")
{
	const std::string desc = " DESC 'caf\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \xF0\x9F\x94\x91'";
	auto def = [&](std::string_view oid, std::string_view rest) {
		return std::pmr::string("( " + std::string(oid) + " NAME 'n" + std::string(oid.substr(4)) + "'" + desc + " "
								+ std::string(rest) + " )");
	};
	const std::pmr::vector<std::pmr::string> good{
		def("1.2.1", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE"),
		def("1.2.2", "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{64}' SINGLE-VALUE"),
		def("1.2.3", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{0} X-NDS_SYNTAX '3' X-ORIGIN 'caf\xC3\xA9'"),
	};
	const auto ok = ldap::server_schema::parse(good, {});
	CHECK(ok.skipped() == 0);
	REQUIRE(ok.attribute_count() == good.size());
	for (const char *n : { "n1", "n2" }) {
		const auto *a = ok.find_attribute(n);
		REQUIRE(a != nullptr);
		CHECK(a->syntax == ldap::syntax::directory_string);
		CHECK(a->single_value);
	}
	CHECK(ok.find_attribute("n3")->syntax == ldap::syntax::directory_string);

	const std::pmr::vector<std::pmr::string> bad{
		def("1.2.4", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 {256} SINGLE-VALUE"),
		def("1.2.5", "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{\r\nforged'"),
		def("1.2.6", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64"),
		def("1.2.7", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{}"),
		def("1.2.8", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{6a}"),
		def("1.2.9", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64}x"),
		def("1.2.10", "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64}{64}"),
		def("1.2.11", "$ SINGLE-VALUE"),
		def("1.2.12", "1.2.3 SINGLE-VALUE"),
		def("1.2.13", "-X SINGLE-VALUE"),
		def("1.2.14", "SINGLE-VALUE caf\xC3\xA9 'x'"),
	};
	const auto s = ldap::server_schema::parse(bad, bad);
	CHECK(s.attribute_count() == 0);
	CHECK(s.skipped() == 2 * bad.size() - 6);// the SYNTAX failures are not the object class grammar's
	CHECK(s.object_class_count() == 6);
	CHECK(s.skipped_for_syntax("n5"));
	CHECK_FALSE(s.skipped_for_syntax("n4"));// failed as a keyword: not a SYNTAX failure

	auto spaced = ldap::parse_attribute_type(bad[0]);
	REQUIRE_FALSE(spaced.has_value());
	CHECK(spaced.error().code == ldap::client_errc::decode_error);
	CHECK(spaced.error().context == "schema: expected a keyword");
	auto junk = ldap::parse_attribute_type(bad[1]);
	REQUIRE_FALSE(junk.has_value());
	CHECK(junk.error().context == "schema: SYNTAX is not a numeric OID");
}

TEST_CASE("schema: SUP cycles do not loop", "[schema]")
{
	const std::pmr::vector<std::pmr::string> types{ "( 1.1 NAME 'a' SUP b )", "( 1.2 NAME 'b' SUP a )" };
	const auto s = ldap::server_schema::parse(types, {});
	CHECK(s.syntax_of(*s.find_attribute("a")) == nullptr);
}

TEST_CASE("schema: lookups fold ASCII case only", "[schema]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.1 NAME 'fooBar' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.2 NAME ( 'FOOBAR' 'other' ) )",// differs from 1.1's NAME only in case: 1.1 keeps it
		"( 1.3 NAME ( 'zz' 'ZZ' ) SUP FOOBAR )",
	};
	const std::pmr::vector<std::pmr::string> classes{
		"( 2.1 NAME 'Person' )",
		"( 2.2 NAME 'PERSON' )",
	};
	const auto s = ldap::server_schema::parse(types, classes);
	REQUIRE(s.attribute_count() == 3);

	const auto *foo = s.find_attribute("foobar");
	REQUIRE(foo != nullptr);
	CHECK(foo->oid == "1.1");
	for (const char *n : { "fooBar", "FOOBAR", "fOoBaR", "FooBar;Lang-EN", "1.1" }) CHECK(s.find_attribute(n) == foo);
	CHECK(s.find_attribute("OTHER")->oid == "1.2");
	CHECK(s.find_attribute("1.2")->oid == "1.2");
	CHECK(s.find_attribute("Zz")->oid == "1.3");
	REQUIRE(s.syntax_of(*s.find_attribute("zz")) != nullptr);
	CHECK(*s.syntax_of(*s.find_attribute("zz")) == ldap::syntax::directory_string);// SUP looked up in any case
	CHECK(s.find_object_class("person")->oid == "2.1");
	CHECK(s.find_object_class("PERSON")->oid == "2.1");
	CHECK(s.find_object_class("2.2")->oid == "2.2");

	// Only A-Z fold: bytes >= 0x80 compare as they are (0xC1 is 'A' | 0x80,
	// 0xC1 / 0xE1 are Latin-1 A / a acute, C3 81 is UTF-8 U+00C1).
	CHECK(s.find_attribute("foob\xC1r") == nullptr);
	CHECK(s.find_attribute("foob\xE1r") == nullptr);
	CHECK(s.find_attribute("foob\xC3\x81r") == nullptr);
	CHECK(s.find_attribute("") == nullptr);
	CHECK(s.find_attribute("fooba") == nullptr);
	CHECK(s.find_object_class("pers\xCFn") == nullptr);// 0xCF is 'O' | 0x80
	CHECK(ldap::detail::ci_equal{}("\xC1", "\xC1"));
	CHECK_FALSE(ldap::detail::ci_equal{}("\xC1", "\xE1"));
	CHECK_FALSE(ldap::detail::ci_equal{}("\xC1", "A"));
	CHECK(ldap::detail::ci_hash{}("FooBar") == ldap::detail::ci_hash{}("fOObAR"));

	STATIC_REQUIRE(noexcept(s.find_attribute("x")));
	STATIC_REQUIRE(noexcept(s.find_object_class("x")));
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

namespace {

struct long_syntax
{
	std::int64_t n = 0;
};

}// namespace

template<>
constexpr auto ldap::schema<long_syntax> =
  ldap::describe(ldap::object_class("top"), ldap::field<&long_syntax::n>("longSyntax"));

// The SYNTAX is a numeric OID (checked when parsed), but of any length: the
// report cuts it at 64 bytes. Both definitions carry a UTF-8 DESC (accents,
// CJK, an emoji): the cut applies to the SYNTAX only, and the rest of the
// definition is accepted.
TEST_CASE("schema: a syntax mismatch quotes the server's SYNTAX cut", "[schema][validate]")
{
	std::string oid = "1";
	for (int i = 0; i < 100; ++i) oid += ".2";
	const std::string desc = "DESC 'caf\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \xF0\x9F\x94\x91'";
	const std::pmr::vector<std::pmr::string> types{ std::pmr::string(
	  "( 1.2.1 NAME 'longSyntax' " + desc + " SYNTAX " + oid + " SINGLE-VALUE )") };
	const std::pmr::vector<std::pmr::string> classes{ std::pmr::string(
	  "( 2.5.6.0 NAME 'top' " + desc + " ABSTRACT )") };
	const auto rep = ldap::validate<long_syntax>(ldap::server_schema::parse(types, classes));
	REQUIRE(rep.issues.size() == 1);
	CHECK(rep.issues[0].what == ldap::schema_issue::kind::syntax_mismatch);
	CHECK(rep.issues[0].detail
		  == "syntax " + oid.substr(0, 64) + "... is not one the member's type reads (" + ldap::syntax::integer + ", "
			   + ldap::syntax::numeric_string + ", " + ldap::syntax::ad_large_integer + ")");
}

namespace {

struct broken_sup
{
	std::vector<std::int64_t> child;
	std::vector<std::int64_t> orphan;
	std::vector<std::int64_t> parent;
	std::vector<std::string> child_text;// strings read any syntax: not checked
};

}// namespace

template<>
constexpr auto ldap::schema<broken_sup> = ldap::describe(ldap::object_class("top"),
  ldap::field<&broken_sup::child>("childAttr"),
  ldap::field<&broken_sup::orphan>("orphanAttr"),
  ldap::field<&broken_sup::parent>("parentAttr"),
  ldap::field<&broken_sup::child_text>("childAttr"));

// A subtype without a SYNTAX of its own whose SUP was skipped (its SYNTAX is
// not a numeric OID) or is not defined at all has no syntax_of: the syntax
// cannot be checked, which is an error, not ok(). The member mapped to the
// skipped definition itself is told why it is missing. The SUP is server
// text: quoted sanitized (U+202E becomes U+FFFD). Definitions carry UTF-8.
TEST_CASE("schema: a SUP that is missing or skipped for its SYNTAX is reported", "[schema][validate]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.4 NAME 'parentAttr' DESC 'caf\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC' SYNTAX 'Directory String' )",
		"( 1.2.5 NAME 'childAttr' DESC 'na\xC3\xAFve \xE5\xAD\x90' SUP parentAttr )",
		"( 1.2.6 NAME 'orphanAttr' DESC '\xC3\xA9t\xC3\xA9 \xE5\xAD\xA4' SUP 'no\xE2\x80\xAEsuch' )",
	};
	const std::pmr::vector<std::pmr::string> classes{ "( 2.5.6.0 NAME 'top' ABSTRACT )" };
	const auto s = ldap::server_schema::parse(types, classes);
	CHECK(s.skipped() == 1);
	CHECK(s.find_attribute("parentAttr") == nullptr);
	CHECK(s.skipped_for_syntax("PARENTATTR;lang-en"));
	CHECK(s.skipped_for_syntax("1.2.4"));
	CHECK_FALSE(s.skipped_for_syntax("childAttr"));
	CHECK_FALSE(s.skipped_for_syntax("nope"));
	REQUIRE(s.find_attribute("childAttr") != nullptr);
	CHECK(s.syntax_of(*s.find_attribute("childAttr")) == nullptr);

	const auto rep = ldap::validate<broken_sup>(s);
	CHECK_FALSE(rep.ok());
	using k = ldap::schema_issue::kind;
	REQUIRE(rep.issues.size() == 3);
	CHECK(rep.issues[0].what == k::syntax_mismatch);
	CHECK(rep.issues[0].name == "childAttr");
	CHECK(rep.issues[0].detail
		  == "syntax unknown: SUP parentAttr is defined on the server, but skipped: its SYNTAX is not a numeric OID");
	CHECK(rep.issues[1].what == k::syntax_mismatch);
	CHECK(rep.issues[1].name == "orphanAttr");
	CHECK(rep.issues[1].detail == "syntax unknown: SUP no\xEF\xBF\xBDsuch is not defined on the server");
	CHECK(rep.issues[2].what == k::unknown_attribute);
	CHECK(rep.issues[2].name == "parentAttr");
	CHECK(rep.issues[2].detail == "defined on the server, but skipped: its SYNTAX is not a numeric OID");
}

namespace {

struct no_syntax
{
	std::vector<std::int64_t> bare;
	std::vector<std::int64_t> child;
	std::vector<std::string> bare_text;// strings read any syntax: not checked
};

}// namespace

template<>
constexpr auto ldap::schema<no_syntax> = ldap::describe(ldap::object_class("top"),
  ldap::field<&no_syntax::bare>("bareAttr"),
  ldap::field<&no_syntax::child>("bareChild"),
  ldap::field<&no_syntax::bare_text>("bareAttr"));

// RFC 4512 4.1.2 requires a SYNTAX or a SUP; a definition with neither (or a
// chain ending in one) still parses, but its syntax cannot be checked: an
// error, not ok(). Definitions carry UTF-8.
TEST_CASE("schema: an attribute type with neither SYNTAX nor SUP is reported", "[schema][validate]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.7 NAME 'bareAttr' DESC 'caf\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \xF0\x9F\x93\x9C' )",
		"( 1.2.8 NAME 'bareChild' DESC 'na\xC3\xAFve \xE5\xAD\x90' SUP bareAttr )",
	};
	const std::pmr::vector<std::pmr::string> classes{ "( 2.5.6.0 NAME 'top' ABSTRACT )" };
	const auto s = ldap::server_schema::parse(types, classes);
	CHECK(s.skipped() == 0);
	REQUIRE(s.find_attribute("bareAttr") != nullptr);
	CHECK(s.syntax_of(*s.find_attribute("bareAttr")) == nullptr);

	const auto rep = ldap::validate<no_syntax>(s);
	CHECK_FALSE(rep.ok());
	REQUIRE(rep.issues.size() == 2);
	CHECK(rep.issues[0].what == ldap::schema_issue::kind::syntax_mismatch);
	CHECK(rep.issues[0].name == "bareAttr");
	CHECK(rep.issues[0].detail == "syntax unknown: the server declares no SYNTAX and no SUP for it");
	CHECK(rep.issues[1].what == ldap::schema_issue::kind::syntax_mismatch);
	CHECK(rep.issues[1].name == "bareChild");
	CHECK(rep.issues[1].detail == "syntax unknown: the server declares no SYNTAX for it or its supertypes");
}

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
