#include "jhetz/ldap/schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
using Catch::Matchers::ContainsSubstring;

namespace {

// As OpenLDAP 2.6 serves them from cn=Subschema (core, cosine, nis,
// inetorgperson, memberof overlay).
const std::pmr::vector<std::pmr::string> openldap_types{
	// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
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
	"( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( "
	"title $ x121Address $ registeredAddress $ destinationIndicator $ ou $ st $ l ) )",
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
	CHECK(s.object_class_count() == 4);

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

// RFC 4512 qdstrings (NAME, DESC) are UTF-8 (QUTF8) and the rest of the
// grammar is ASCII: a definition that is not well-formed UTF-8 is skipped
// like any other that does not parse, the rest of the schema kept.
TEST_CASE("schema: a definition that is not UTF-8 is skipped", "[schema][rfc]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.3 NAME 'ok' DESC 'Größe, 日本' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.2.4 NAME 'badDesc' DESC 'caf\xE9' )",// Latin-1, not UTF-8
		"( 1.2.5 NAME 'overlong' DESC '\xC0\xAF' )",
		"( 1.2.6 NAME 'surrogate' DESC '\xED\xA0\x80' )",
		"( 1.2.7 NAME 'truncated' DESC '\xE6\x97' )",
		"( 1.2.8 NAME 'bad\xFFname' )",
		"( 1.2.9 NAME 'badSup' SUP cn\x80 )",
	};
	const std::pmr::vector<std::pmr::string> classes{
		"( 2.5.6.0 NAME 'top' DESC 'top \xE2\x80\x94 the root' ABSTRACT )",
		"( 1.2.10 NAME 'badClass' DESC '\xF5\x80\x80\x80' )",
	};
	const auto s = ldap::server_schema::parse(types, classes);
	CHECK(s.attribute_count() == 1);
	CHECK(s.find_attribute("ok") != nullptr);
	CHECK(s.find_attribute("badDesc") == nullptr);
	CHECK(s.find_object_class("top") != nullptr);
	CHECK(s.find_object_class("badClass") == nullptr);
	CHECK(s.skipped() == 7);

	const auto bad = ldap::parse_attribute_type("( 1.2.4 NAME 'badDesc' DESC 'caf\xE9' )");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::decode_error);
	CHECK(bad.error().context == "schema: not valid UTF-8 (ill-formed sequence at offset 32)");
	CHECK_FALSE(ldap::parse_object_class("( 1.2.10 NAME 'x' DESC '\xF5\x80\x80\x80' )").has_value());
}

// RFC 4512 section 4.1.2: SYNTAX is a noidlen, a numericoid with an
// optional {len}. Anything else is the server's own text (it could never
// match a syntax the mapping knows): the definition is skipped, and the
// error does not quote it.
TEST_CASE("schema: a SYNTAX that is not a numeric OID skips the definition", "[schema]")
{
	const std::pmr::vector<std::pmr::string> types{
		// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
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
	CHECK(s.skipped() == (2 * bad.size()) - 6);// the SYNTAX failures are not the object class grammar's
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

namespace {

struct on_cycle
{
	std::vector<std::int64_t> a;
};

}// namespace

template<>
constexpr auto ldap::schema<on_cycle> = ldap::describe(ldap::object_class("top"), ldap::field<&on_cycle::a>("a"));

TEST_CASE("schema: a SUP cycle is reported as a chain too long", "[schema][validate]")
{
	const std::pmr::vector<std::pmr::string> types{ "( 1.1 NAME 'a' SUP b )", "( 1.2 NAME 'b' SUP a )" };
	const std::pmr::vector<std::pmr::string> classes{ "( 2.5.6.0 NAME 'top' ABSTRACT )" };
	const auto rep = ldap::validate<on_cycle>(ldap::server_schema::parse(types, classes));
	REQUIRE(rep.issues.size() == 1);
	CHECK(rep.issues[0].what == ldap::schema_issue::kind::syntax_mismatch);
	CHECK(rep.issues[0].detail == "syntax unknown: the SUP chain is longer than 32 (a cycle?)");
}

TEST_CASE("schema: lists and fields are bounded", "[schema]")
{
	const auto context = [](const auto &r) {
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
		return std::string(r.error().context);
	};
	std::string names;
	for (int i = 0; i < 4096; ++i) {
		names += " 'n" + std::to_string(i) + "'";
	}
	CHECK(ldap::parse_attribute_type("( 1.2 NAME (" + names + " ) )").has_value());
	CHECK(context(ldap::parse_attribute_type("( 1.2 NAME (" + names + " 'one-more' ) )")) == "schema: list too long");

	std::string oids = "a0";
	for (int i = 1; i < 4096; ++i) {
		oids += "$a" + std::to_string(i);
	}
	CHECK(ldap::parse_object_class("( 1.2 MAY " + oids + " )").has_value());
	CHECK(context(ldap::parse_object_class("( 1.2 MAY " + oids + "$extra )")) == "schema: list too long");

	std::string fields;
	for (int i = 0; i < 256; ++i) {
		fields += " SINGLE-VALUE";
	}
	CHECK(ldap::parse_attribute_type("( 1.2" + fields + " )").has_value());
	CHECK(context(ldap::parse_attribute_type("( 1.2" + fields + " SINGLE-VALUE )")) == "schema: too many fields");
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
	for (const char *n : { "fooBar", "FOOBAR", "fOoBaR", "FooBar;Lang-EN", "1.1" }) {
		CHECK(s.find_attribute(n) == foo);
	}
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
	for (int i = 0; i < 100; ++i) {
		oid += ".2";
	}
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
	std::vector<std::string> child_text;// a string's unknown syntax: not reported
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
	std::vector<std::string> bare_text;// a string's unknown syntax: not reported
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
	// uid is multi-valued on the server but a single member here, person's
	// sn is not mapped and its cn is a vector: warnings only.
	REQUIRE(rep.issues.size() == 3);
	CHECK(rep.issues[0].what == ldap::schema_issue::kind::single_member_multi_valued);
	CHECK(rep.issues[0].name == "uid");
	CHECK(rep.issues[1].what == ldap::schema_issue::kind::must_attribute_not_mapped);
	CHECK(rep.issues[1].name == "sn");
	CHECK(rep.issues[2].what == ldap::schema_issue::kind::must_attribute_not_required);
	CHECK(rep.issues[2].name == "cn");
	CHECK(std::ranges::none_of(rep.issues, &ldap::schema_issue::is_error));
}

TEST_CASE("schema: validate lists every issue", "[schema][validate]")
{
	const auto s = ldap::server_schema::parse(openldap_types, openldap_classes);
	const auto rep = ldap::validate<bad_person>(s);
	CHECK_FALSE(rep.ok());
	using k = ldap::schema_issue::kind;
	auto has = [&](k what, std::string_view name) {
		return std::ranges::any_of(rep.issues, [&](const auto &i) { return i.what == what && i.name == name; });
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
	CHECK(has(k::must_attribute_not_mapped, "sn"));// person's, through organizationalPerson
	CHECK(rep.issues.size() == 10);
	const std::string text = rep.to_string();
	CHECK_THAT(text, ContainsSubstring("error: object class posixAccount: not defined on the server"));
	CHECK_THAT(text, ContainsSubstring("error: attribute mail: syntax 1.3.6.1.4.1.1466.115.121.1.26 is not one"));
	CHECK_THAT(text, ContainsSubstring("warning: attribute cn: single-valued member"));
	CHECK_THAT(text, ContainsSubstring("mark the member ldap::read_only"));
}

namespace {

// String members on the binary syntaxes, which they refuse; a string on
// Directory String passes.
struct binary_as_text
{
	std::optional<std::string> password;// userPassword: Octet String
	std::vector<std::pmr::string> photo;// jpegPhoto: JPEG
	std::string certificate;// userCertificate: Certificate
	std::optional<std::string> revocation;// certificateRevocationList: Certificate List
	std::optional<std::string> pair;// crossCertificatePair: Certificate Pair
	std::optional<std::string> fax;// x-fax: Fax
	std::optional<std::string> sound;// audio: Audio
	std::optional<std::string> blob;// x-blob: Binary
	std::optional<std::string> description;// description: Directory String
};

struct binary_as_binary
{
	std::optional<ldap::binary> password;
	std::vector<ldap::binary> photo;
	ldap::binary certificate;
};

}// namespace

template<>
constexpr auto ldap::schema<binary_as_text> = ldap::describe(ldap::object_class("top"),
  ldap::field<&binary_as_text::password>("userPassword"),
  ldap::field<&binary_as_text::photo>("jpegPhoto"),
  ldap::field<&binary_as_text::certificate>("userCertificate"),
  ldap::field<&binary_as_text::revocation>("certificateRevocationList"),
  ldap::field<&binary_as_text::pair>("crossCertificatePair"),
  ldap::field<&binary_as_text::fax>("x-fax"),
  ldap::field<&binary_as_text::sound>("audio"),
  ldap::field<&binary_as_text::blob>("x-blob"),
  ldap::field<&binary_as_text::description>("description"));

template<>
constexpr auto ldap::schema<binary_as_binary> = ldap::describe(ldap::object_class("top"),
  ldap::field<&binary_as_binary::password>("userPassword"),
  ldap::field<&binary_as_binary::photo>("jpegPhoto"),
  ldap::field<&binary_as_binary::certificate>("userCertificate"));

// The binary syntaxes (RFC 4517, RFC 4523, RFC 2252) hold octets, not UTF-8
// text: a std::string or std::pmr::string member on one is a
// syntax_mismatch (it would fail to decode), whatever its shape; ldap::binary
// members pass. Definitions carry UTF-8 descriptions.
TEST_CASE("schema: a string member on a binary syntax is a syntax mismatch", "[schema][validate]")
{
	const std::pmr::vector<std::pmr::string> types{
		// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
		"( 2.5.4.35 NAME 'userPassword' DESC 'mot de passe \xC3\xA0 v\xC3\xA9rifier' EQUALITY octetStringMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
		"( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' DESC '\xE5\x86\x99\xE7\x9C\x9F' SYNTAX "
		"1.3.6.1.4.1.1466.115.121.1.28 )",
		"( 2.5.4.36 NAME 'userCertificate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )",
		"( 2.5.4.39 NAME 'certificateRevocationList' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )",
		"( 2.5.4.40 NAME 'crossCertificatePair' SYNTAX 1.3.6.1.4.1.1466.115.121.1.10 )",
		"( 1.2.9 NAME 'x-fax' SYNTAX 1.3.6.1.4.1.1466.115.121.1.23 )",
		"( 0.9.2342.19200300.100.1.55 NAME 'audio' SYNTAX 1.3.6.1.4.1.1466.115.121.1.4{250000} )",
		"( 1.2.10 NAME 'x-blob' SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 )",
		"( 2.5.4.13 NAME 'description' DESC 'caf\xC3\xA9' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )",
	};
	const std::pmr::vector<std::pmr::string> classes{ "( 2.5.6.0 NAME 'top' ABSTRACT )" };
	const auto s = ldap::server_schema::parse(types, classes);
	REQUIRE(s.skipped() == 0);

	const auto rep = ldap::validate<binary_as_text>(s);
	CHECK_FALSE(rep.ok());
	using k = ldap::schema_issue::kind;
	auto mismatch = [&](std::string_view name) -> const ldap::schema_issue * {
		const auto it = std::ranges::find_if(
		  rep.issues, [&](const auto &i) { return i.what == k::syntax_mismatch && i.name == name; });
		return it == rep.issues.end() ? nullptr : &*it;
	};
	const std::vector<std::pair<std::string_view, const char *>> refused{
		{ "userPassword", ldap::syntax::octet_string },
		{ "jpegPhoto", ldap::syntax::jpeg },
		{ "userCertificate", ldap::syntax::certificate },
		{ "certificateRevocationList", ldap::syntax::certificate_list },
		{ "crossCertificatePair", ldap::syntax::certificate_pair },
		{ "x-fax", ldap::syntax::fax },
		{ "audio", ldap::syntax::audio },
		{ "x-blob", ldap::syntax::binary },
	};
	for (const auto &[name, oid] : refused) {
		INFO(name);
		const auto *issue = mismatch(name);
		REQUIRE(issue != nullptr);
		CHECK(issue->detail
			  == std::string("syntax ") + oid
				   + " is one the member's type refuses: its values are binary, map the member to ldap::binary");
	}
	CHECK(mismatch("description") == nullptr);
	// The single members on multi-valued attributes are warnings only.
	const auto errors = std::ranges::count_if(rep.issues, [](const auto &i) { return i.is_error(); });
	CHECK(static_cast<std::size_t>(errors) == refused.size());
	CHECK_THAT(rep.to_string(),
	  ContainsSubstring("error: attribute userPassword: syntax 1.3.6.1.4.1.1466.115.121.1.40 is one the member's "
						"type refuses"));

	const auto binary = ldap::validate<binary_as_binary>(s);
	CHECK(binary.ok());
	CHECK(std::ranges::none_of(binary.issues, [](const auto &i) { return i.what == k::syntax_mismatch; }));
}

// ---------------------------------------------------------------- MUST / MAY

namespace {

// OpenLDAP's core.schema, nis.schema and inetorgperson.schema, as
// cn=Subschema serves them (MAY lists cut).
const std::pmr::vector<std::pmr::string> core_types{
	// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
	"( 2.5.4.0 NAME 'objectClass' DESC 'RFC4512: object classes of the entity' EQUALITY objectIdentifierMatch "
	"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
	"( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
	"( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
	"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
	"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
	// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
	"( 2.5.18.1 NAME 'createTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION "
	"USAGE directoryOperation )",
};
const std::pmr::vector<std::pmr::string> core_classes{
	"( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
	// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
	"( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ "
	"telephoneNumber $ seeAlso $ description ) )",
	"( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( "
	"title $ ou $ st $ l ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP "
	"organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense $ mail $ uid ) )",
	"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' DESC 'Abstraction of an account with POSIX attributes' SUP top AUXILIARY "
	"MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ "
	"description ) )",
	"( 2.5.6.9 NAME 'groupOfNames' DESC 'RFC2256: a group of names (DNs)' SUP top STRUCTURAL MUST ( member $ cn ) "
	"MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
};

auto core_schema() -> ldap::server_schema { return ldap::server_schema::parse(core_types, core_classes); }

// The MUST issues of a report, as (kind, name) in report order.
auto must_issues(const ldap::schema_report &rep) -> std::vector<std::pair<ldap::schema_issue::kind, std::string>>
{
	std::vector<std::pair<ldap::schema_issue::kind, std::string>> out;
	for (const auto &i : rep.issues) {
		if (i.what == ldap::schema_issue::kind::must_attribute_not_mapped
			|| i.what == ldap::schema_issue::kind::must_attribute_not_required
			|| i.what == ldap::schema_issue::kind::unknown_superclass) {
			out.emplace_back(i.what, i.name);
		}
	}
	return out;
}

// Every MUST of inetOrgPerson and posixAccount (and their superclasses)
// mapped by a required member: sn by its alias, cn with an option.
struct posix_user
{
	std::string uid;
	std::string cn;
	std::string sn;
	std::int64_t uid_number = 0;
	std::int64_t gid_number = 0;
	std::string home;
	std::optional<std::string> mail;
	std::chrono::sys_seconds created{};
};

// person's sn not mapped, cn optional, uidNumber read_only, gidNumber a
// vector; homeDirectory only by its OID.
struct partial_user
{
	std::string uid;
	std::optional<std::string> cn;
	std::int64_t uid_number = 0;
	std::vector<std::int64_t> gid_number;
	std::string home;
};

// No object class declared: nothing to check MUSTs against.
struct no_classes
{
	std::string cn;
};

// A subtype does not map its supertype: name is not mapped by cn.
struct named_thing
{
	std::string cn;
};

}// namespace

template<>
constexpr auto ldap::schema<posix_user> = ldap::describe(ldap::object_class("inetOrgPerson", "posixAccount"),
  ldap::field<&posix_user::uid>("uid"),
  ldap::field<&posix_user::cn>("cn;lang-en"),
  ldap::field<&posix_user::sn>("surname"),
  ldap::field<&posix_user::uid_number>("uidNumber"),
  ldap::field<&posix_user::gid_number>("gidNumber"),
  ldap::field<&posix_user::home>("homeDirectory"),
  ldap::field<&posix_user::mail>("mail"),
  ldap::field<&posix_user::created>("createTimestamp", ldap::read_only));

template<>
constexpr auto ldap::schema<partial_user> = ldap::describe(ldap::object_class("inetOrgPerson", "posixAccount"),
  ldap::field<&partial_user::uid>("uid"),
  ldap::field<&partial_user::cn>("cn"),
  ldap::field<&partial_user::uid_number>("uidNumber", ldap::read_only),
  ldap::field<&partial_user::gid_number>("gidNumber"),
  ldap::field<&partial_user::home>("1.3.6.1.1.1.1.3"));

template<> constexpr auto ldap::schema<no_classes> = ldap::describe(ldap::field<&no_classes::cn>("cn"));

template<>
constexpr auto ldap::schema<named_thing> =
  ldap::describe(ldap::object_class("namedThing"), ldap::field<&named_thing::cn>("cn"));

TEST_CASE("schema: object class SUP, kind, MUST and MAY", "[schema]")
{
	const auto s = core_schema();
	CHECK(s.skipped() == 0);

	const auto *top = s.find_object_class("top");
	REQUIRE(top != nullptr);
	CHECK(top->sup.empty());
	CHECK(top->kind == ldap::object_class_kind::abstract);
	CHECK(top->must == std::vector<std::string>{ "objectClass" });
	CHECK(top->may.empty());

	const auto *person = s.find_object_class("person");
	REQUIRE(person != nullptr);
	CHECK(person->sup == std::vector<std::string>{ "top" });
	CHECK(person->kind == ldap::object_class_kind::structural);
	CHECK(person->must == std::vector<std::string>{ "sn", "cn" });
	CHECK(person->may == std::vector<std::string>{ "userPassword", "telephoneNumber", "seeAlso", "description" });

	const auto *posix = s.find_object_class("posixAccount");
	REQUIRE(posix != nullptr);
	CHECK(posix->kind == ldap::object_class_kind::auxiliary);
	CHECK(posix->must == std::vector<std::string>{ "cn", "uid", "uidNumber", "gidNumber", "homeDirectory" });

	// No kind: STRUCTURAL (RFC 4512 4.1.1). Several superclasses, numeric
	// OIDs, keywords in any case, no space before ')' (as AD writes them).
	// Entries that are not oids are dropped.
	auto c = ldap::parse_object_class(
	  "( 1.2.3 NAME 'mixed' sup ( top $ 2.5.6.6 ) must (cn $ 2.5.4.4 $ 'bad name' $ 1.2.) may 'x-y')");
	REQUIRE(c.has_value());
	CHECK(c->kind == ldap::object_class_kind::structural);
	CHECK(c->sup == std::vector<std::string>{ "top", "2.5.6.6" });
	CHECK(c->must == std::vector<std::string>{ "cn", "2.5.4.4" });
	CHECK(c->may == std::vector<std::string>{ "x-y" });
	// Several kinds (against the grammar): the first wins.
	auto twice = ldap::parse_object_class("( 1.2.4 AUXILIARY ABSTRACT )");
	REQUIRE(twice.has_value());
	CHECK(twice->kind == ldap::object_class_kind::auxiliary);
	// MUST without a value is malformed, like any keyword.
	CHECK_FALSE(ldap::parse_object_class("( 1.2.5 MUST )").has_value());
}

TEST_CASE("schema: an oidlist's '$' needs no spaces (RFC 4512 1.4)", "[schema]")
{
	// oidlist = oid *( WSP DOLLAR WSP oid ), WSP = 0*SPACE.
	for (const char *text : { "( 1.1 NAME 'x' SUP (top$2.5.6.6) MUST (sn$cn) MAY (a$b$c) )",
		   "( 1.1 NAME 'x' SUP ( top $2.5.6.6 ) MUST ( sn $cn ) MAY ( a $b $c ) )",
		   "( 1.1 NAME 'x' SUP ( top$ 2.5.6.6 ) MUST ( sn$ cn ) MAY ( a$ b$ c ) )",
		   "( 1.1 NAME 'x' SUP(top $ 2.5.6.6)MUST(sn $ cn)MAY(a $ b$c))" }) {
		INFO(text);
		auto c = ldap::parse_object_class(text);
		REQUIRE(c.has_value());
		CHECK(c->sup == std::vector<std::string>{ "top", "2.5.6.6" });
		CHECK(c->must == std::vector<std::string>{ "sn", "cn" });
		CHECK(c->may == std::vector<std::string>{ "a", "b", "c" });
	}
	// In a quoted string, '$' is text.
	auto a = ldap::parse_attribute_type("( 1.2 NAME ( 'y' 'z' ) DESC 'costs $5 (a$b)' SUP name X-X ( 'p$q' ) )");
	REQUIRE(a.has_value());
	CHECK(a->names == std::vector<std::string>{ "y", "z" });
	CHECK(a->sup == "name");
	// An object class's SUP, MUST and MAY without parentheses: "a$b" (or
	// "a $ b") is read as the list "( a $ b )".
	for (const char *text : { "( 1.1 NAME 'x' SUP top$2.5.6.6 MUST sn$cn MAY a$b$c )",
		   "( 1.1 NAME 'x' SUP top $ 2.5.6.6 MUST sn $cn MAY a$ b $ 'c' )",
		   "( 1.1 NAME 'x' SUP top$2.5.6.6 MUST sn$cn MAY a$b$c)" }) {
		INFO(text);
		auto c = ldap::parse_object_class(text);
		REQUIRE(c.has_value());
		CHECK(c->sup == std::vector<std::string>{ "top", "2.5.6.6" });
		CHECK(c->must == std::vector<std::string>{ "sn", "cn" });
		CHECK(c->may == std::vector<std::string>{ "a", "b", "c" });
		CHECK(c->kind == ldap::object_class_kind::structural);
	}
	// Elsewhere, '$' outside a list is no value and no keyword: the
	// definition is skipped, not cut short. So is an unparenthesised list
	// with a '$' that no oid follows.
	const std::pmr::vector<std::pmr::string> bad{ "( 1.3 NAME 'b1' MUST cn$ )",
		"( 1.4 NAME 'b2' MUST $ )",
		"( 1.5 NAME 'b3' MUST ( sn ) $ )",
		"( 1.6 NAME x$y )",
		"( 1.7 NAME 'b7' X-FOO bar$baz )",
		"( 1.8 NAME 'b8' MUST cn $ $ sn )",
		"( 1.9 NAME 'b9' MAY cn$(sn) )" };
	CHECK_FALSE(ldap::parse_attribute_type("( 1.3 NAME 'at' SUP name$cn )").has_value());
	CHECK_FALSE(ldap::parse_attribute_type("( 1.3 NAME 'at' X-A b$c )").has_value());
	const auto s = ldap::server_schema::parse({}, bad);
	CHECK(s.skipped() == bad.size());
	CHECK(s.object_class_count() == 0);
	// A schema with no spaces around '$': validate<T> sees every MUST.
	const std::pmr::vector<std::pmr::string> classes{ "( 1.9 NAME 'namedThing' SUP (top$base) MUST (sn$cn) )",
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 1.10 NAME 'base' MUST (description$name) )" };
	using k = ldap::schema_issue::kind;
	CHECK(must_issues(ldap::validate<named_thing>(ldap::server_schema::parse(core_types, classes)))
		  == std::vector<std::pair<k, std::string>>{ { k::must_attribute_not_mapped, "sn" },
			{ k::must_attribute_not_mapped, "description" },
			{ k::must_attribute_not_mapped, "name" } });
}

TEST_CASE("schema: MUST attributes mapped by required members", "[schema][validate]")
{
	const auto s = core_schema();
	const auto rep = ldap::validate<posix_user>(s);
	INFO(rep.to_string());
	CHECK(rep.ok());
	// objectClass (top's MUST) is what add sends from the declared classes;
	// cn and sn are mapped through an option and an alias.
	CHECK(must_issues(rep).empty());
	// Only the multi-valued warnings are left (uid, cn, sn, mail, home).
	CHECK(std::ranges::all_of(
	  rep.issues, [](const auto &i) { return i.what == ldap::schema_issue::kind::single_member_multi_valued; }));
}

TEST_CASE("schema: MUST attributes not mapped, or mapped by members add may leave out", "[schema][validate]")
{
	const auto s = core_schema();
	const auto rep = ldap::validate<partial_user>(s);
	INFO(rep.to_string());
	// Warnings: the RDN or the server may supply them, and a read
	// projection does not add entries.
	CHECK(rep.ok());
	using k = ldap::schema_issue::kind;
	// Each attribute once, the declared classes first, then their
	// superclasses (breadth first): cn, required by posixAccount and
	// person, is reported for posixAccount.
	CHECK(must_issues(rep)
		  == std::vector<std::pair<k, std::string>>{ { k::must_attribute_not_required, "cn" },
			{ k::must_attribute_not_required, "uidNumber" },
			{ k::must_attribute_not_required, "gidNumber" },
			{ k::must_attribute_not_mapped, "sn" } });
	const std::string text = rep.to_string();
	CHECK_THAT(text,
	  ContainsSubstring("warning: attribute sn: required (MUST) by object class person (a superclass of "
						"inetOrgPerson), but no member maps it: add(dn, T) fails unless the entry's RDN or the server "
						"supplies it"));
	CHECK_THAT(text,
	  ContainsSubstring("warning: attribute cn: required (MUST) by object class posixAccount, but its member is a "
						"std::optional: add(dn, T) sends nothing when it is empty"));
	CHECK_THAT(text,
	  ContainsSubstring("warning: attribute uidNumber: required (MUST) by object class posixAccount, but its member "
						"is read_only: add(dn, T) never sends it"));
	CHECK_THAT(text,
	  ContainsSubstring("warning: attribute gidNumber: required (MUST) by object class posixAccount, but its member "
						"is a std::vector: add(dn, T) sends nothing when it is empty"));
}

TEST_CASE("schema: MUST checks follow the RFC 4512 rules", "[schema][validate]")
{
	using k = ldap::schema_issue::kind;

	SECTION("no declared object class: nothing to check")
	{
		CHECK(must_issues(ldap::validate<no_classes>(core_schema())).empty());
	}
	SECTION("a subtype does not map its supertype")
	{
		const std::pmr::vector<std::pmr::string> classes{ "( 1.9 NAME 'namedThing' MUST name )" };
		const auto rep = ldap::validate<named_thing>(ldap::server_schema::parse(core_types, classes));
		CHECK(must_issues(rep) == std::vector<std::pair<k, std::string>>{ { k::must_attribute_not_mapped, "name" } });
	}
	SECTION("a NO-USER-MODIFICATION MUST is the server's; objectClass is sent")
	{
		const std::pmr::vector<std::pmr::string> classes{
			"( 1.9 NAME 'namedThing' MUST ( createTimestamp $ objectClass $ 2.5.4.3 ) )"
		};
		CHECK(must_issues(ldap::validate<named_thing>(ldap::server_schema::parse(core_types, classes))).empty());
	}
	SECTION("objectClass is sent whatever its spelling: OID or another NAME")
	{
		std::pmr::vector<std::pmr::string> types = core_types;
		types.front() = "( 2.5.4.0 NAME ( 'objectClass' 'oc' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )";
		const std::pmr::vector<std::pmr::string> classes{
			"( 1.9 NAME 'namedThing' SUP top MUST ( 2.5.4.0 $ OC ) )",
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST 2.5.4.0 )",
		};
		CHECK(must_issues(ldap::validate<named_thing>(ldap::server_schema::parse(types, classes))).empty());
		// Not defined on the server: its OID and RFC 4512 name still are it,
		// an alias is not known.
		CHECK(must_issues(ldap::validate<named_thing>(ldap::server_schema::parse({}, classes)))
			  == std::vector<std::pair<k, std::string>>{ { k::must_attribute_not_mapped, "OC" } });
	}
	SECTION("a MUST the server does not define is matched by name, once")
	{
		const std::pmr::vector<std::pmr::string> classes{
			"( 1.9 NAME 'namedThing' SUP ( other $ third ) MUST ( cn $ x-Unknown ) )",
			"( 1.10 NAME 'other' MUST X-UNKNOWN )",
			"( 1.11 NAME 'third' MUST ( x-unknown $ cn ) )",
		};
		const auto rep = ldap::validate<named_thing>(ldap::server_schema::parse(core_types, classes));
		CHECK(
		  must_issues(rep) == std::vector<std::pair<k, std::string>>{ { k::must_attribute_not_mapped, "x-Unknown" } });
	}
	SECTION("superclasses: a cycle ends, an unknown one is reported once")
	{
		const std::pmr::vector<std::pmr::string> classes{
			"( 1.9 NAME 'namedThing' SUP ( loopA $ missing ) )",
			"( 1.10 NAME 'loopA' SUP ( loopB $ missing ) )",
			"( 1.11 NAME 'loopB' SUP ( loopA $ namedThing ) MUST sn )",
		};
		const auto rep = ldap::validate<named_thing>(ldap::server_schema::parse(core_types, classes));
		CHECK(rep.ok());
		CHECK(must_issues(rep)
			  == std::vector<std::pair<k, std::string>>{
				{ k::unknown_superclass, "missing" }, { k::must_attribute_not_mapped, "sn" } });
		const std::string text = rep.to_string();
		CHECK_THAT(text,
		  ContainsSubstring("warning: object class missing: a superclass of namedThing not defined on the server: "
							"the MUST attributes it would add are not checked"));
		CHECK_THAT(text, ContainsSubstring("by object class loopB (a superclass of namedThing)"));
	}
	SECTION("an undefined declared class is an error, with no MUST to check")
	{
		const auto rep = ldap::validate<named_thing>(core_schema());
		CHECK_FALSE(rep.ok());
		CHECK(rep.issues[0].what == k::unknown_object_class);
		CHECK(must_issues(rep).empty());
	}
}

TEST_CASE("schema: MUST checks scale with long SUP chains and MUST lists", "[schema][validate]")
{
	// A server schema is the server's: 20000 classes chained by SUP, each
	// with a MUST the members map (cn) and one of 4000 the server does
	// not define, all also in the declared class's MUST list. Linear
	// lookups made this seconds (minutes under ASan).
	constexpr std::size_t chain = 20'000;
	constexpr std::size_t names = 4'000;
	std::pmr::vector<std::pmr::string> classes;
	std::string list = "( 1.9 NAME 'namedThing' SUP c1 MUST ( cn";
	for (std::size_t i = 0; i < names; ++i) {
		list += " $ m" + std::to_string(i);
	}
	classes.emplace_back(list + " ) )");
	for (std::size_t i = 1; i < chain; ++i) {
		classes.emplace_back("( 1.10." + std::to_string(i) + " NAME 'c" + std::to_string(i) + "' SUP ( c"
							 + std::to_string(i + 1) + " $ namedThing ) MUST ( cn $ M" + std::to_string(i % names)
							 + " ) )");
	}
	const auto s = ldap::server_schema::parse(core_types, classes);
	REQUIRE(s.object_class_count() == chain);
	const auto start = std::chrono::steady_clock::now();
	const auto issues = must_issues(ldap::validate<named_thing>(s));
	const auto took = std::chrono::steady_clock::now() - start;
	using k = ldap::schema_issue::kind;
	// c<chain> is not defined, then each m<i> is reported once, for
	// namedThing.
	REQUIRE(issues.size() == names + 1);
	CHECK(issues.front() == std::pair<k, std::string>{ k::unknown_superclass, "c" + std::to_string(chain) });
	CHECK(issues[1] == std::pair<k, std::string>{ k::must_attribute_not_mapped, "m0" });
	CHECK(issues.back() == std::pair<k, std::string>{ k::must_attribute_not_mapped, "m" + std::to_string(names - 1) });
	CHECK(took < std::chrono::seconds(10));
}
