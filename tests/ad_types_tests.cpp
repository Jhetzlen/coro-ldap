#include "jhetz/ldap/ad/guid.hpp"
#include "jhetz/ldap/ad/sid.hpp"
#include "jhetz/ldap/ad/user_account_control.hpp"
#include "jhetz/ldap/schema.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;
using Catch::Matchers::ContainsSubstring;
using namespace std::string_literals;
using namespace std::string_view_literals;

namespace {

static_assert(ldap::mapped_value<ad::sid>);
static_assert(ldap::mapped_value<ad::guid>);
static_assert(ldap::mapped_value<ad::user_account_control>);

auto bytes(std::initializer_list<unsigned> octets) -> std::string
{
	std::string out;
	for (const unsigned o : octets) {
		out += static_cast<char>(o);
	}
	return out;
}

}// namespace

// ---------------------------------------------------------------- SID

TEST_CASE("ad::sid: known binary and string forms (MS-DTYP 2.4.2)", "[ad][sid]")
{
	struct known
	{
		std::string_view text;
		std::string binary;
	};
	const std::array vectors{
		// Everyone, BUILTIN\Administrators, Local System.
		known{ .text = "S-1-1-0", .binary = bytes({ 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }) },
		known{ .text = "S-1-5-32-544", .binary = bytes({ 1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0 }) },
		known{ .text = "S-1-5-18", .binary = bytes({ 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 }) },
		// A domain user: S-1-5-21 and three sub-authorities, then the RID.
		known{ .text = "S-1-5-21-2127521184-1604012920-1887927527-72713",
		  .binary =
			"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xA0\x65\xCF\x7E\x78\x4B\x9B\x5F\xE7\x7C\x87\x70\x09\x1C\x01\x00"s },
		// No sub-authority.
		known{ .text = "S-1-0", .binary = bytes({ 1, 0, 0, 0, 0, 0, 0, 0 }) },
		// Authority 2^32 and above: hex, 12 digits.
		known{ .text = "S-1-0x123456789ABC-4294967295",
		  .binary = bytes({ 1, 1, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xFF, 0xFF, 0xFF, 0xFF }) },
		known{ .text = "S-1-4294967295-1", .binary = bytes({ 1, 1, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0 }) },
	};
	for (const auto &[text, binary] : vectors) {
		CAPTURE(text);
		auto from_text = ad::sid::parse(text);
		REQUIRE(from_text.has_value());
		CHECK(from_text->to_binary() == binary);
		CHECK(from_text->to_string() == text);
		auto from_binary = ad::sid::from_binary(binary);
		REQUIRE(from_binary.has_value());
		CHECK(*from_binary == *from_text);
		CHECK(from_binary->to_string() == text);
	}

	auto user = ad::sid::parse("S-1-5-21-2127521184-1604012920-1887927527-72713");
	REQUIRE(user.has_value());
	CHECK(user->identifier_authority() == 5);
	CHECK(std::vector(user->sub_authorities().begin(), user->sub_authorities().end())
		  == std::vector<std::uint32_t>{ 21, 2127521184, 1604012920, 1887927527, 72713 });
	CHECK(ad::sid{}.to_string() == "S-1-0");
}

TEST_CASE("ad::sid: parse accepts", "[ad][sid]")
{
	CHECK(ad::sid::parse("s-1-5-18")->to_string() == "S-1-5-18");
	// The hex form below 2^32 too, digits in either case; to_string() writes decimal.
	CHECK(ad::sid::parse("S-1-0x000000000005-18")->to_string() == "S-1-5-18");
	CHECK(ad::sid::parse("S-1-0X123456789abc-1")->to_string() == "S-1-0x123456789ABC-1");
	CHECK(ad::sid::parse("S-1-5-0018")->to_string() == "S-1-5-18");
	CHECK(ad::sid::parse("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15")->sub_authorities().size() == 15);
}

TEST_CASE("ad::sid: parse refuses", "[ad][sid]")
{
	for (const std::string_view text : { ""sv,
		   "S"sv,
		   "S-1"sv,
		   "S-1-"sv,
		   "S-2-5-18"sv,
		   "X-1-5-18"sv,
		   "S-1-5-"sv,
		   "S-1-5--18"sv,
		   "S-1-5-18-"sv,
		   "S-1--5"sv,
		   "S-1-+5-18"sv,
		   "S-1-5--1"sv,
		   "S-1-5-4294967296"sv,
		   "S-1-4294967296-1"sv,
		   "S-1-0x12345678-1"sv,
		   "S-1-0x123456789ABCD-1"sv,
		   "S-1-0x12345678G0BC-1"sv,
		   "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16"sv,
		   "S-1-5-18 "sv,
		   " S-1-5-18"sv,
		   "S-1-5-1 8"sv }) {
		CAPTURE(text);
		auto s = ad::sid::parse(text);
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::client_errc::conversion_failed);
		CHECK_THAT(std::string(s.error().message()), ContainsSubstring("not a SID"));
	}
}

TEST_CASE("ad::sid: from_binary refuses", "[ad][sid]")
{
	const std::string ok = bytes({ 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 });
	REQUIRE(ad::sid::from_binary(ok).has_value());
	for (const std::string &raw : { std::string(),
		   ok.substr(0, 7),
		   ok.substr(0, 11),
		   ok + '\0',
		   bytes({ 2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 }),
		   bytes({ 0, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 }),
		   bytes({ 1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 }),
		   bytes({ 1, 16, 0, 0, 0, 0, 0, 5 }) + std::string(64, '\0') }) {
		CAPTURE(raw.size());
		auto s = ad::sid::from_binary(raw);
		REQUIRE_FALSE(s.has_value());
		CHECK(s.error().code == ldap::client_errc::conversion_failed);
		CHECK_THAT(std::string(s.error().message()), ContainsSubstring("not a binary SID"));
	}
	// 15 sub-authorities is the most.
	CHECK(ad::sid::from_binary(bytes({ 1, 15, 0, 0, 0, 0, 0, 5 }) + std::string(60, '\0')).has_value());
}

TEST_CASE("ad::sid: make", "[ad][sid]")
{
	const std::array<std::uint32_t, 2> builtin_admins{ 32, 544 };
	auto s = ad::sid::make(5, builtin_admins);
	REQUIRE(s.has_value());
	CHECK(s->to_string() == "S-1-5-32-544");
	CHECK(*s == *ad::sid::parse("S-1-5-32-544"));
	CHECK(ad::sid::make(ad::sid::max_identifier_authority, {})->to_string() == "S-1-0xFFFFFFFFFFFF");

	auto wide = ad::sid::make(ad::sid::max_identifier_authority + 1, builtin_admins);
	REQUIRE_FALSE(wide.has_value());
	CHECK(wide.error().code == std::errc::invalid_argument);
	const std::vector<std::uint32_t> sixteen(16, 1);
	auto many = ad::sid::make(5, sixteen);
	REQUIRE_FALSE(many.has_value());
	CHECK(many.error().code == std::errc::invalid_argument);
}

TEST_CASE("ad::sid: comparison", "[ad][sid]")
{
	const auto s = [](std::string_view t) { return *ad::sid::parse(t); };
	CHECK(s("S-1-5-21") == s("S-1-5-21"));
	CHECK(s("S-1-5-21") != s("S-1-5-21-0"));
	CHECK(s("S-1-5-21") < s("S-1-5-21-0"));
	CHECK(s("S-1-5-21-5") < s("S-1-5-22"));
	CHECK(s("S-1-1-0") < s("S-1-5-18"));
}

// ---------------------------------------------------------------- GUID

TEST_CASE("ad::guid: binary and string forms (MS-DTYP 2.3.4)", "[ad][guid]")
{
	// Data1, Data2 and Data3 little-endian, Data4 as is: .NET's
	// Guid("00010203-0405-0607-0809-0a0b0c0d0e0f").ToByteArray().
	const std::string raw = bytes({ 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 });
	auto g = ad::guid::from_binary(raw);
	REQUIRE(g.has_value());
	CHECK(g->data1 == 0x00010203);
	CHECK(g->data2 == 0x0405);
	CHECK(g->data3 == 0x0607);
	CHECK(g->data4 == std::array<std::uint8_t, 8>{ 8, 9, 10, 11, 12, 13, 14, 15 });
	CHECK(g->to_string() == "00010203-0405-0607-0809-0a0b0c0d0e0f");
	CHECK(g->to_binary() == raw);
	CHECK(ad::guid::parse("00010203-0405-0607-0809-0a0b0c0d0e0f") == *g);

	const std::string high =
	  bytes({ 0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
	auto h = ad::guid::from_binary(high);
	REQUIRE(h.has_value());
	CHECK(h->to_string() == "00112233-4455-6677-8899-aabbccddeeff");
	CHECK(ad::guid::parse("{00112233-4455-6677-8899-AABBCCDDEEFF}")->to_binary() == high);
	CHECK(ad::guid::parse("00112233-4455-6677-8899-AabBccDdeEfF") == *h);

	CHECK(ad::guid{}.to_string() == "00000000-0000-0000-0000-000000000000");
	CHECK(ad::guid{}.to_binary() == std::string(16, '\0'));
	CHECK(ad::guid{ .data1 = 1 } < ad::guid{ .data1 = 2 });
}

TEST_CASE("ad::guid: refusals", "[ad][guid]")
{
	for (const std::string_view text : { ""sv,
		   "00010203-0405-0607-0809-0a0b0c0d0e0"sv,
		   "00010203-0405-0607-0809-0a0b0c0d0e0f0"sv,
		   "000102030405-0607-0809-0a0b0c0d0e0f-"sv,
		   "00010203-0405-0607-08090a0b0c0d0e0f-"sv,
		   "0001020g-0405-0607-0809-0a0b0c0d0e0f"sv,
		   "{00010203-0405-0607-0809-0a0b0c0d0e0f"sv,
		   "00010203-0405-0607-0809-0a0b0c0d0e0f}"sv,
		   "(00010203-0405-0607-0809-0a0b0c0d0e0f)"sv,
		   "00010203-0405-0607-0809-0a0b0c0d0e0 "sv,
		   "00010203-+405-0607-0809-0a0b0c0d0e0f"sv }) {
		CAPTURE(text);
		auto g = ad::guid::parse(text);
		REQUIRE_FALSE(g.has_value());
		CHECK(g.error().code == ldap::client_errc::conversion_failed);
	}
	for (const std::size_t n : { 0U, 15U, 17U }) {
		auto g = ad::guid::from_binary(std::string(n, '\0'));
		REQUIRE_FALSE(g.has_value());
		CHECK(g.error().code == ldap::client_errc::conversion_failed);
		CHECK_THAT(std::string(g.error().message()), ContainsSubstring("not a 16-octet GUID"));
	}
}

// ---------------------------------------------------------------- userAccountControl

TEST_CASE("ad::user_account_control: values and bitmask operators (MS-ADTS 2.2.16)", "[ad][uac]")
{
	using enum ad::user_account_control;
	static_assert(std::to_underlying(account_disable) == 0x2);
	static_assert(std::to_underlying(normal_account) == 0x200);
	static_assert(std::to_underlying(workstation_trust_account) == 0x1000);
	static_assert(std::to_underlying(server_trust_account) == 0x2000);
	static_assert(std::to_underlying(dont_expire_passwd) == 0x10000);
	static_assert(std::to_underlying(trusted_for_delegation) == 0x80000);
	static_assert(std::to_underlying(use_aes_keys) == 0x8000000);

	constexpr auto disabled_user = normal_account | account_disable;
	static_assert(std::to_underlying(disabled_user) == 514);
	static_assert(has(disabled_user, account_disable));
	static_assert(has(disabled_user, normal_account | account_disable));
	static_assert(!has(disabled_user, normal_account | dont_expire_passwd));
	static_assert(has(disabled_user, none));
	static_assert((disabled_user & ~account_disable) == normal_account);
	static_assert((disabled_user ^ account_disable) == normal_account);

	auto v = normal_account;
	v |= account_disable;
	CHECK(v == disabled_user);
	v &= ~account_disable;
	CHECK(v == normal_account);
	v ^= dont_expire_passwd;
	CHECK(std::to_underlying(v) == 66048);
}

TEST_CASE("ad::user_account_control: value_traits", "[ad][uac]")
{
	using traits = ldap::value_traits<ad::user_account_control>;
	using enum ad::user_account_control;
	CHECK(traits::decode("512") == normal_account);
	CHECK(traits::decode("514") == (normal_account | account_disable));
	CHECK(traits::decode("532480") == (server_trust_account | trusted_for_delegation));
	CHECK(traits::decode("0") == none);
	// Bits not named here are kept.
	CHECK(std::to_underlying(*traits::decode("1073742336")) == 0x40000200U);
	// AD's INTEGER is a signed 32-bit number: bit 31 is negative.
	CHECK(std::to_underlying(*traits::decode("-2147483648")) == 0x80000000U);
	CHECK(std::to_underlying(*traits::decode("4294967295")) == 0xFFFFFFFFU);
	CHECK(traits::encode(normal_account | account_disable) == "514");
	CHECK(traits::encode(ad::user_account_control(0x80000200U)) == "-2147483136");
	CHECK(traits::encode(ad::user_account_control(0xFFFFFFFFU)) == "-1");

	for (const std::string_view raw : { "4294967296"sv, "-2147483649"sv, "abc"sv, ""sv, "0x200"sv }) {
		CAPTURE(raw);
		auto v = traits::decode(raw);
		REQUIRE_FALSE(v.has_value());
		CHECK(v.error().code == ldap::client_errc::conversion_failed);
	}
}

// ---------------------------------------------------------------- mapping

namespace {

struct ad_account
{
	std::string sam_account_name;
	ad::sid object_sid;
	ad::guid object_guid;
	ad::user_account_control user_account_control{};
	std::vector<ad::sid> sid_history;
};

}// namespace

template<>
constexpr auto ldap::schema<ad_account> = ldap::describe(ldap::object_class("user"),
  ldap::field<&ad_account::sam_account_name>("sAMAccountName"),
  ldap::field<&ad_account::object_sid>("objectSid", ldap::read_only),
  ldap::field<&ad_account::object_guid>("objectGUID", ldap::read_only),
  ldap::field<&ad_account::user_account_control>("userAccountControl"),
  ldap::field<&ad_account::sid_history>("sIDHistory"));

TEST_CASE("ad types in the typed mapping", "[ad][mapping]")
{
	const std::string sid_raw = ad::sid::parse("S-1-5-21-1-2-3-1104")->to_binary();
	const std::string old_sid_raw = ad::sid::parse("S-1-5-21-4-5-6-1104")->to_binary();
	const std::string guid_raw = bytes({ 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 });
	auto a = ldap::decode<ad_account>(ldap::entry::from(ldap::search_result_entry("CN=jdoe,CN=Users,DC=example,DC=org",
	  { { "sAMAccountName", { "jdoe" } },
		{ "objectSid", { sid_raw } },
		{ "objectGUID", { guid_raw } },
		{ "userAccountControl", { "66050" } },
		{ "sIDHistory", { old_sid_raw } } })));
	REQUIRE(a.has_value());
	CHECK(a->object_sid.to_string() == "S-1-5-21-1-2-3-1104");
	CHECK(a->object_guid.to_string() == "00010203-0405-0607-0809-0a0b0c0d0e0f");
	CHECK(has(a->user_account_control, ad::user_account_control::account_disable));
	REQUIRE(a->sid_history.size() == 1);
	CHECK(a->sid_history[0].to_string() == "S-1-5-21-4-5-6-1104");

	auto bad = ldap::decode<ad_account>(ldap::entry::from(ldap::search_result_entry("CN=x,DC=example,DC=org",
	  { { "sAMAccountName", { "x" } },
		{ "objectSid", { "S-1-5-18" } },
		{ "objectGUID", { guid_raw } },
		{ "userAccountControl", { "512" } } })));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::conversion_failed);
	CHECK_THAT(std::string(bad.error().message()), ContainsSubstring("objectSid"));

	// Filters and modifications carry the binary form and the integer.
	const auto f = ldap::filters::field<&ad_account::object_guid>() == a->object_guid;
	CHECK(std::string(f.to_string())
		  == "(objectGUID=" + bytes({ 3, 2, 1 }) + "\\00" + bytes({ 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 }) + ")");
	using op = ldap::modify_operation;
	CHECK(ldap::replace<&ad_account::user_account_control>(ad::user_account_control::normal_account).wire
		  == ldap::modify_change{ op::replace, { "userAccountControl", { "512" } } });
}

TEST_CASE("ad types in validate<T>: Octet String and INTEGER", "[ad][schema]")
{
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.146 NAME 'objectSid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.2 NAME 'objectGUID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.609 NAME 'sIDHistory' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' )",
	};
	const std::pmr::vector<std::pmr::string> classes{
		"( 2.5.6.0 NAME 'top' ABSTRACT )",
		"( 1.2.840.113556.1.5.9 NAME 'user' SUP top STRUCTURAL MAY ( sAMAccountName $ userAccountControl ) )",
	};
	const auto s = ldap::server_schema::parse(types, classes);
	REQUIRE(s.skipped() == 0);
	const auto rep = ldap::validate<ad_account>(s);
	INFO(rep.to_string());
	CHECK(rep.ok());
	CHECK(rep.issues.empty());

	// On an INTEGER attribute a SID member is a syntax_mismatch.
	const std::pmr::vector<std::pmr::string> wrong{
		"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.146 NAME 'objectSid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.2 NAME 'objectGUID' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' SINGLE-VALUE )",
		"( 1.2.840.113556.1.4.609 NAME 'sIDHistory' SYNTAX '1.3.6.1.4.1.1466.115.121.1.40' )",
	};
	const auto bad = ldap::validate<ad_account>(ldap::server_schema::parse(wrong, classes));
	REQUIRE(bad.issues.size() == 2);
	CHECK(bad.issues[0].name == "objectSid");
	CHECK(bad.issues[0].what == ldap::schema_issue::kind::syntax_mismatch);
	CHECK(bad.issues[1].name == "userAccountControl");
	CHECK(bad.issues[1].what == ldap::schema_issue::kind::syntax_mismatch);
}
