#include "jhetz/ldap/mapping.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
using Catch::Matchers::ContainsSubstring;
using namespace std::chrono;
using namespace std::string_view_literals;

namespace {

enum class status { active, locked, retired };

struct person
{
	std::string uid;
	std::string cn;
	std::optional<std::string> mail;
	std::vector<ldap::dn> member_of;
	std::int32_t uid_number = 0;
	std::optional<bool> disabled;
	ldap::binary photo;
	std::vector<std::string> telephone;
	sys_seconds created{};
	std::optional<status> state;
};

struct account
{
	std::string uid;
	std::int64_t uid_number = 0;
};

// A struct without declared object classes maps objectClass itself.
struct device
{
	std::vector<std::string> object_class;
	std::string cn;
};

struct album
{
	std::vector<ldap::binary> photos;
};

}// namespace

template<>
constexpr auto ldap::enum_names<status> = std::to_array<std::pair<status, std::string_view>>(
  { { status::active, "active" }, { status::locked, "locked" }, { status::retired, "retired" } });

template<>
constexpr auto ldap::schema<person> = ldap::describe(ldap::object_class("inetOrgPerson", "posixAccount"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::cn>("cn"),
  ldap::field<&person::mail>("mail"),
  ldap::field<&person::member_of>("memberOf"),
  ldap::field<&person::uid_number>("uidNumber"),
  ldap::field<&person::disabled>("x-disabled"),
  ldap::field<&person::photo>("jpegPhoto"),
  ldap::field<&person::telephone>("telephoneNumber"),
  ldap::field<&person::created>("createTimestamp", ldap::read_only),
  ldap::field<&person::state>("x-status"));

template<>
constexpr auto ldap::schema<account> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::auxiliary_class("posixAccount", "shadowAccount"),
  ldap::field<&account::uid>("uid"),
  ldap::field<&account::uid_number>("uidNumber"));

template<>
constexpr auto ldap::schema<device> =
  ldap::describe(ldap::field<&device::object_class>("objectClass"), ldap::field<&device::cn>("cn"));

template<> constexpr auto ldap::schema<album> = ldap::describe(ldap::field<&album::photos>("jpegPhoto"));

namespace {

auto make_entry(std::string_view dn, std::initializer_list<ldap::partial_attribute> attrs) -> ldap::entry
{
	return ldap::entry::from(ldap::search_result_entry(dn, attrs));
}

auto full_entry() -> ldap::entry
{
	return make_entry("uid=jdoe,ou=people,dc=example,dc=org",
	  { { "uid", { "jdoe" } },
		{ "CN", { "John Doe" } },// attribute names match case-insensitively
		{ "mail", { "jdoe@example.org" } },
		{ "memberOf", { "cn=admins,ou=groups,dc=example,dc=org", "cn=staff,ou=groups,dc=example,dc=org" } },
		{ "uidNumber", { "1000" } },
		{ "x-disabled", { "FALSE" } },
		{ "jpegPhoto", { std::string_view("\xff\xd8\x00\x01", 4) } },
		{ "telephoneNumber", { "+1 555 0100", "+1 555 0101" } },
		{ "createTimestamp", { "20240229123456Z" } },
		{ "x-status", { "locked" } } });
}

}// namespace

// ---------------------------------------------------------------- value_traits

TEST_CASE("value_traits for integers", "[mapping][traits]")
{
	using T = ldap::value_traits<std::int32_t>;
	CHECK(T::decode("0") == 0);
	CHECK(T::decode("-42") == -42);
	CHECK(T::decode("2147483647") == 2147483647);
	CHECK(T::encode(-7) == "-7");
	for (const auto *bad : { "", "+1", " 1", "1 ", "12a", "0x10", "2147483648", "1.5" }) {
		INFO(bad);
		auto r = T::decode(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::conversion_failed);
	}
	CHECK(ldap::value_traits<std::uint8_t>::decode("255") == std::uint8_t{ 255 });
	CHECK_FALSE(ldap::value_traits<std::uint8_t>::decode("256").has_value());
	CHECK_FALSE(ldap::value_traits<std::uint32_t>::decode("-1").has_value());
	CHECK(ldap::value_traits<std::int64_t>::decode("-9223372036854775808") == INT64_MIN);
}

TEST_CASE("value_traits for bool, strings, DNs and binary", "[mapping][traits]")
{
	CHECK(ldap::value_traits<bool>::decode("TRUE") == true);
	CHECK(ldap::value_traits<bool>::decode("FALSE") == false);
	CHECK_FALSE(ldap::value_traits<bool>::decode("true").has_value());
	CHECK_FALSE(ldap::value_traits<bool>::decode("1").has_value());
	CHECK(ldap::value_traits<bool>::encode(true) == "TRUE");

	CHECK(ldap::value_traits<std::string>::decode(std::string_view("a\0b", 3)) == std::string("a\0b", 3));
	CHECK(ldap::value_traits<std::pmr::string>::encode(std::pmr::string("x")) == "x");

	auto d = ldap::value_traits<ldap::dn>::decode("CN=Admins,DC=example,DC=org");
	REQUIRE(d.has_value());
	CHECK(*d == ldap::dn{ "cn=Admins,dc=example,dc=org" });
	auto bad_dn = ldap::value_traits<ldap::dn>::decode("not a dn");
	REQUIRE_FALSE(bad_dn.has_value());
	CHECK(bad_dn.error().code == ldap::client_errc::conversion_failed);
	CHECK_THAT(std::string(bad_dn.error().context), ContainsSubstring("not a distinguished name: \"not a dn\""));

	const ldap::binary raw{ std::byte{ 0 }, std::byte{ 0xff } };
	CHECK(ldap::value_traits<ldap::binary>::decode(std::string_view("\x00\xff", 2)) == raw);
	CHECK(ldap::value_traits<ldap::binary>::encode(raw) == std::string("\x00\xff", 2));
	// Binary takes any octets, ill-formed UTF-8 included.
	std::string all_octets;
	for (int i = 0; i < 256; ++i) {
		all_octets += static_cast<char>(i);
	}
	const auto all = ldap::value_traits<ldap::binary>::decode(all_octets);
	REQUIRE(all.has_value());
	REQUIRE(all->size() == 256);
	CHECK(std::to_integer<int>((*all)[255]) == 255);
	CHECK(ldap::value_traits<ldap::binary>::encode(*all) == all_octets);
}

TEST_CASE("string value_traits take only well-formed UTF-8", "[mapping][traits][utf8]")
{
	// Well-formed: ASCII, 2-, 3- and 4-octet sequences, the extremes of
	// each length, and long values that cross the 8-octet ASCII fast path.
	for (std::string_view good : { ""sv,
		   "plain ascii"sv,
		   "J\xC3\xBCrgen M\xC3\xBCller"sv,// Jürgen Müller
		   "\xE6\x9D\xB1\xE4\xBA\xAC"sv,// 東京
		   "\xF0\x9F\x98\x80"sv,// U+1F600
		   "\xC2\x80\xDF\xBF\xE0\xA0\x80\xED\x9F\xBF\xEE\x80\x80\xEF\xBF\xBF\xF0\x90\x80\x80\xF4\x8F\xBF\xBF"sv,
		   "0123456789abcdef\xC3\xA9"
		   "0123456789abcdef"sv }) {
		INFO(good.size());
		const auto s = ldap::value_traits<std::string>::decode(good);
		REQUIRE(s.has_value());
		CHECK(*s == good);
		const auto p = ldap::value_traits<std::pmr::string>::decode(good);
		REQUIRE(p.has_value());
		CHECK(*p == good);
	}

	struct bad_t
	{
		const char *name;
		std::string_view raw;
		std::size_t offset;
	};
	const std::string long_prefix(20, 'a');
	const std::string long_bad = long_prefix + "\xFF" + long_prefix;
	for (const bad_t &bad :
	  std::initializer_list<bad_t>{ { .name = "overlong 2-octet", .raw = "\xC0\x80"sv, .offset = 0 },
		{ .name = "overlong 3-octet", .raw = "ab\xE0\x80\xAF"sv, .offset = 2 },
		{ .name = "overlong 4-octet", .raw = "\xF0\x80\x80\xAF"sv, .offset = 0 },
		{ .name = "surrogate", .raw = "x\xED\xA0\x80"sv, .offset = 1 },
		{ .name = "above U+10FFFF", .raw = "\xF4\x90\x80\x80"sv, .offset = 0 },
		{ .name = "truncated 2-octet", .raw = "J\xC3"sv, .offset = 1 },
		{ .name = "truncated 4-octet", .raw = "\xF0\x9F\x98"sv, .offset = 0 },
		{ .name = "truncated before ASCII", .raw = "\xE6\x9Dz"sv, .offset = 0 },
		{ .name = "stray continuation", .raw = "abc\x80"sv, .offset = 3 },
		{ .name = "0xFF", .raw = "\xFF"sv, .offset = 0 },
		{ .name = "after a long ASCII run", .raw = long_bad, .offset = 20 } }) {
		DYNAMIC_SECTION(bad.name)
		{
			const std::string expected =
			  "not valid UTF-8 (ill-formed sequence at offset " + std::to_string(bad.offset) + ")";
			const auto s = ldap::value_traits<std::string>::decode(bad.raw);
			REQUIRE_FALSE(s.has_value());
			CHECK(s.error().code == ldap::client_errc::conversion_failed);
			CHECK(std::string_view(s.error().context) == expected);
			const auto p = ldap::value_traits<std::pmr::string>::decode(bad.raw);
			REQUIRE_FALSE(p.has_value());
			CHECK(p.error().code == ldap::client_errc::conversion_failed);
			CHECK(std::string_view(p.error().context) == expected);
			CHECK(ldap::detail::invalid_utf8_offset(bad.raw) == bad.offset);
			CHECK_FALSE(ldap::detail::is_valid_utf8(bad.raw));
			// Encoding checks the same, as encode_error.
			const auto es = ldap::value_traits<std::string>::encode(std::string(bad.raw));
			REQUIRE_FALSE(es.has_value());
			CHECK(es.error().code == ldap::client_errc::encode_error);
			CHECK(std::string_view(es.error().context) == expected);
			const auto ep = ldap::value_traits<std::pmr::string>::encode(std::pmr::string(bad.raw));
			REQUIRE_FALSE(ep.has_value());
			CHECK(ep.error().code == ldap::client_errc::encode_error);
			CHECK(std::string_view(ep.error().context) == expected);
		}
	}
	CHECK(ldap::value_traits<std::string>::encode("caf\xC3\xA9") == "caf\xC3\xA9");
}

TEST_CASE("value_traits for enums with a name table", "[mapping][traits]")
{
	CHECK(ldap::value_traits<status>::decode("retired") == status::retired);
	CHECK_FALSE(ldap::value_traits<status>::decode("Retired").has_value());
	CHECK(ldap::value_traits<status>::encode(status::locked) == "locked");
	// A value without a name: decode could not read it back.
	auto unknown = ldap::value_traits<status>::encode(static_cast<status>(9));
	REQUIRE_FALSE(unknown.has_value());
	CHECK(unknown.error().code == ldap::client_errc::encode_error);
	CHECK(std::string_view(unknown.error().context) == "value 9 is not in ldap::enum_names");
}

TEST_CASE("GeneralizedTime", "[mapping][traits][time]")
{
	const sys_seconds noon = sys_days(2024y / February / 29) + 12h;
	struct case_t
	{
		const char *text{};
		sys_seconds expected;
	};
	const case_t cases[] = {
		{ .text = "2024022912Z", .expected = noon },
		{ .text = "202402291230Z", .expected = noon + 30min },
		{ .text = "20240229123045Z", .expected = noon + 30min + 45s },
		{ .text = "20240229123045.999Z", .expected = noon + 30min + 45s },// fractions of a second truncated
		{ .text = "20240229123045,5Z", .expected = noon + 30min + 45s },
		{ .text = "2024022912.5Z", .expected = noon + 30min },// fraction of an hour
		{ .text = "202402291230.25Z", .expected = noon + 30min + 15s },// fraction of a minute
		{ .text = "20240229140000+0200", .expected = noon },
		{ .text = "20240229070000-05", .expected = noon },
		{ .text = "20240229123060Z", .expected = noon + 31min },// leap second rolls over
		{ .text = "19700101000000Z", .expected = sys_seconds{} },
		{ .text = "99991231235959Z", .expected = sys_days(9999y / December / 31) + 23h + 59min + 59s },
	};
	for (const auto &c : cases) {
		INFO(c.text);
		auto t = ldap::parse_generalized_time(c.text);
		REQUIRE(t.has_value());
		CHECK(*t == c.expected);
	}
	for (const auto *bad : { "",
		   "2024",
		   "20240229",
		   "2024022912",
		   "20240230120000Z",
		   "20241301120000Z",
		   "20240229240000Z",
		   "20240229126000Z",
		   "20240229123061Z",
		   "20240229123045.Z",
		   "20240229123045+2400",
		   "20240229123045+0260",
		   "20240229123045Zx",
		   "20240229123045 Z",
		   "2024022912304Z",
		   "20240229123045+1" }) {
		INFO(bad);
		auto t = ldap::parse_generalized_time(bad);
		REQUIRE_FALSE(t.has_value());
		CHECK(t.error().code == ldap::client_errc::conversion_failed);
	}
	CHECK(ldap::format_generalized_time(noon + 5min + 7s) == "20240229120507Z");
	CHECK(ldap::format_generalized_time(sys_seconds{}) == "19700101000000Z");
	CHECK_FALSE(ldap::format_generalized_time(sys_days(10000y / January / 1)).has_value());
	// Out of range is encode_error, no exception.
	auto far = ldap::value_traits<sys_seconds>::encode(sys_days(10000y / January / 1));
	REQUIRE_FALSE(far.has_value());
	CHECK(far.error().code == ldap::client_errc::encode_error);
	CHECK(std::string_view(far.error().context) == "GeneralizedTime: year 10000 outside 0000-9999");
	CHECK_FALSE(ldap::value_traits<sys_seconds>::encode(sys_days(-1y / December / 31)).has_value());
	CHECK(ldap::value_traits<sys_seconds>::encode(sys_seconds{}) == "19700101000000Z");
	// Round trip.
	const sys_seconds t = sys_days(1999y / December / 31) + 23h + 59min + 58s;
	CHECK(ldap::parse_generalized_time(*ldap::format_generalized_time(t)) == t);
}

// ---------------------------------------------------------------- decode

TEST_CASE("decode maps every member shape", "[mapping][decode]")
{
	auto p = ldap::decode<person>(full_entry());
	REQUIRE(p.has_value());
	CHECK(p->uid == "jdoe");
	CHECK(p->cn == "John Doe");
	CHECK(p->mail == "jdoe@example.org");
	REQUIRE(p->member_of.size() == 2);
	CHECK(p->member_of[1] == ldap::dn{ "cn=staff,ou=groups,dc=example,dc=org" });
	CHECK(p->uid_number == 1000);
	CHECK(p->disabled == false);
	CHECK(p->photo == ldap::binary{ std::byte{ 0xff }, std::byte{ 0xd8 }, std::byte{ 0 }, std::byte{ 1 } });
	CHECK(p->telephone == std::vector<std::string>{ "+1 555 0100", "+1 555 0101" });
	CHECK(p->created == sys_days(2024y / February / 29) + 12h + 34min + 56s);
	CHECK(p->state == status::locked);

	// Absent optional and multi-valued members.
	auto minimal = ldap::decode<person>(make_entry("uid=x,dc=example,dc=org",
	  { { "uid", { "x" } },
		{ "cn", { "X" } },
		{ "uidNumber", { "1" } },
		{ "jpegPhoto", { "" } },
		{ "createTimestamp", { "20240101000000Z" } } }));
	REQUIRE(minimal.has_value());
	CHECK_FALSE(minimal->mail.has_value());
	CHECK(minimal->member_of.empty());
	CHECK_FALSE(minimal->disabled.has_value());
	CHECK(minimal->photo.empty());
	CHECK_FALSE(minimal->state.has_value());
}

TEST_CASE("decode errors name the entry and the attribute", "[mapping][decode]")
{
	struct case_t
	{
		const char *name;
		std::string_view attribute;
		std::vector<std::string_view> values;// empty: attribute removed
		std::error_code code;
		const char *context;
	};
	const std::vector<case_t> cases{
		{ .name = "missing required",
		  .attribute = "uid",
		  .values = {},
		  .code = ldap::client_errc::missing_attribute,
		  .context = "entry uid=jdoe,ou=people,dc=example,dc=org: attribute uid" },
		{ .name = "two values for a required member",
		  .attribute = "cn",
		  .values = { "a", "b" },
		  .code = ldap::client_errc::too_many_values,
		  .context = "entry uid=jdoe,ou=people,dc=example,dc=org: attribute cn: 2 values" },
		{ .name = "two values for an optional member",
		  .attribute = "mail",
		  .values = { "a", "b" },
		  .code = ldap::client_errc::too_many_values,
		  .context = nullptr },
		{ .name = "bad integer",
		  .attribute = "uidNumber",
		  .values = { "12a" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = "entry uid=jdoe,ou=people,dc=example,dc=org: attribute uidNumber: not an integer: \"12a\"" },
		{ .name = "bad element of a vector",
		  .attribute = "memberOf",
		  .values = { "cn=ok,dc=example,dc=org", "bad" },
		  .code = ldap::client_errc::conversion_failed,
		  .context =
			"entry uid=jdoe,ou=people,dc=example,dc=org: attribute memberOf: not a distinguished name: \"bad\"" },
		{ .name = "bad boolean",
		  .attribute = "x-disabled",
		  .values = { "yes" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = nullptr },
		{ .name = "bad time",
		  .attribute = "createTimestamp",
		  .values = { "yesterday" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = nullptr },
		{ .name = "ill-formed UTF-8 in a required string",
		  .attribute = "cn",
		  .values = { "J\xC3" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = "entry uid=jdoe,ou=people,dc=example,dc=org: attribute cn: not valid UTF-8 (ill-formed "
					 "sequence at offset 1)" },
		{ .name = "ill-formed UTF-8 in an optional string",
		  .attribute = "mail",
		  .values = { "\xC0\xAF@example.org" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = "entry uid=jdoe,ou=people,dc=example,dc=org: attribute mail: not valid UTF-8 (ill-formed "
					 "sequence at offset 0)" },
		{ .name = "ill-formed UTF-8 in an element of a string vector",
		  .attribute = "telephoneNumber",
		  .values = { "+1 555 0100", "+1 \x80 0101" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = "entry uid=jdoe,ou=people,dc=example,dc=org: attribute telephoneNumber: not valid UTF-8 "
					 "(ill-formed sequence at offset 3)" },
		{ .name = "unknown enum name",
		  .attribute = "x-status",
		  .values = { "gone" },
		  .code = ldap::client_errc::conversion_failed,
		  .context = nullptr },
	};
	for (const auto &c : cases) {
		DYNAMIC_SECTION(c.name)
		{
			ldap::entry e = full_entry();
			const ldap::attribute type = ldap::attribute::parse(c.attribute).value();
			std::erase_if(e.attributes, [&](const ldap::attribute_values &a) { return a.type == type; });
			if (!c.values.empty()) {
				ldap::attribute_values a;
				a.type = type;
				for (auto v : c.values) {
					a.values.emplace_back(v);
				}
				e.attributes.push_back(std::move(a));
			}
			auto p = ldap::decode<person>(e);
			REQUIRE_FALSE(p.has_value());
			CHECK(p.error().code == c.code);
			if (c.context != nullptr) {
				CHECK(p.error().context == c.context);
			}
			// The code's text appears once in message(), after the context.
			const std::string message(p.error().message());
			const std::string code_text = c.code.message();
			const auto first = message.find(code_text);
			REQUIRE(first != std::string::npos);
			CHECK(message.find(code_text, first + 1) == std::string::npos);
		}
	}
}

TEST_CASE("a mapping error message names the code once", "[mapping][decode]")
{
	ldap::entry e = full_entry();
	const ldap::attribute uid{ "uid" };
	std::erase_if(e.attributes, [&](const ldap::attribute_values &a) { return a.type == uid; });
	auto p = ldap::decode<person>(e);
	REQUIRE_FALSE(p.has_value());
	CHECK(std::string(p.error().message())
		  == "entry uid=jdoe,ou=people,dc=example,dc=org: attribute uid: required attribute missing [ldap.client:"
			   + std::to_string(std::to_underlying(ldap::client_errc::missing_attribute)) + "]");
}

TEST_CASE("a conversion error shows the value and the DN sanitized", "[mapping][decode]")
{
	const std::string fffd = "\xEF\xBF\xBD";// U+FFFD
	const auto context = [](std::string_view raw) {
		auto r = ldap::value_traits<int>::decode(raw);
		REQUIRE_FALSE(r.has_value());
		return std::string(r.error().context);
	};
	// Valid UTF-8 is kept; controls, bidi controls and ill-formed bytes become U+FFFD.
	CHECK(context("\xC3\xA9t\xC3\xA9 \xF0\x9F\x98\x80") == "not an integer: \"\xC3\xA9t\xC3\xA9 \xF0\x9F\x98\x80\"");
	CHECK(context("1\r\n\x1B[0m\xE2\x80\xAE\xFF")
		  == "not an integer: \"1" + fffd + fffd + fffd + "[0m" + fffd + fffd + "\"");
	// At most 64 bytes, never half a character: a 2-byte character
	// straddling byte 64 is left out with what follows.
	const std::string straddling = std::string(63, '1') + "\xC3\xA9" + "1";
	CHECK(context(straddling) == "not an integer: \"" + std::string(63, '1') + "...\"");
	CHECK(context(std::string(62, '1') + "\xC3\xA9") == "not an integer: \"" + std::string(62, '1') + "\xC3\xA9\"");
	CHECK(context(std::string(65, '1')) == "not an integer: \"" + std::string(64, '1') + "...\"");

	// The entry's DN (the server's text) too.
	ldap::entry e = full_entry();
	e.dn = "uid=x\n2026-01-01 forged,dc=example";
	const ldap::attribute uid{ "uid" };
	std::erase_if(e.attributes, [&](const ldap::attribute_values &a) { return a.type == uid; });
	auto p = ldap::decode<person>(e);
	REQUIRE_FALSE(p.has_value());
	CHECK(std::string(p.error().context) == "entry uid=x" + fffd + "2026-01-01 forged,dc=example: attribute uid");
	// An empty DN is quoted.
	e.dn = "";
	auto root = ldap::decode<person>(e);
	REQUIRE_FALSE(root.has_value());
	CHECK(std::string(root.error().context) == "entry \"\": attribute uid");
}

TEST_CASE("a change's context names its RFC 4511 operation", "[mapping][encode]")
{
	using ldap::modify_operation;
	CHECK(ldap::detail::change_context(modify_operation::add, "mail") == "add mail");
	CHECK(ldap::detail::change_context(modify_operation::delete_, "mail") == "delete mail");
	CHECK(ldap::detail::change_context(modify_operation::replace, "mail") == "replace mail");
	CHECK(ldap::detail::change_context(modify_operation::increment, "uidNumber") == "increment uidNumber");
}

// ---------------------------------------------------------------- encode / descriptor

TEST_CASE("to_attributes writes objectClass and skips read_only and empty members", "[mapping][encode]")
{
	auto p = *ldap::decode<person>(full_entry());
	p.mail.reset();
	p.member_of.clear();
	const auto encoded = ldap::to_attributes(p);
	REQUIRE(encoded.has_value());
	const auto &attrs = *encoded;
	std::vector<std::string> names;
	names.reserve(attrs.size());
	for (const auto &a : attrs) {
		names.emplace_back(a.type);
	}
	CHECK(names
		  == std::vector<std::string>{
			"objectClass", "uid", "cn", "uidNumber", "x-disabled", "jpegPhoto", "telephoneNumber", "x-status" });
	CHECK(attrs[0] == ldap::partial_attribute{ "objectClass", { "inetOrgPerson", "posixAccount" } });
	CHECK(attrs[3] == ldap::partial_attribute{ "uidNumber", { "1000" } });
	CHECK(attrs[4] == ldap::partial_attribute{ "x-disabled", { "FALSE" } });
	CHECK(attrs[6] == ldap::partial_attribute{ "telephoneNumber", { "+1 555 0100", "+1 555 0101" } });
	CHECK(attrs[7] == ldap::partial_attribute{ "x-status", { "locked" } });

	// decode(entry built from to_attributes) gives the value back (but the
	// read_only member).
	ldap::search_result_entry wire("uid=jdoe,ou=people,dc=example,dc=org");
	wire.attributes.assign(attrs.begin(), attrs.end());
	wire.attributes.push_back({ "createTimestamp", { "20240229123456Z" } });
	auto back = ldap::decode<person>(ldap::entry::from(std::move(wire)));
	REQUIRE(back.has_value());
	CHECK(back->uid == p.uid);
	CHECK(back->photo == p.photo);
	CHECK(back->state == p.state);

	const auto dev = ldap::to_attributes(device{ .object_class = { "top", "device" }, .cn = "printer" });
	REQUIRE(dev.has_value());
	REQUIRE(dev->size() == 2);
	CHECK((*dev)[0] == ldap::partial_attribute{ "objectClass", { "top", "device" } });
}

TEST_CASE("to_attributes fails on a member that does not encode", "[mapping][encode]")
{
	auto p = *ldap::decode<person>(full_entry());
	SECTION("invalid UTF-8 in a required string")
	{
		p.cn = "Jos\xC3";
		auto attrs = ldap::to_attributes(p);
		REQUIRE_FALSE(attrs.has_value());
		CHECK(attrs.error().code == ldap::client_errc::encode_error);
		CHECK(
		  std::string_view(attrs.error().context) == "attribute cn: not valid UTF-8 (ill-formed sequence at offset 3)");
	}
	SECTION("invalid UTF-8 in an optional string")
	{
		p.mail = "\xFF@example.org";
		auto attrs = ldap::to_attributes(p);
		REQUIRE_FALSE(attrs.has_value());
		CHECK(std::string_view(attrs.error().context)
			  == "attribute mail: not valid UTF-8 (ill-formed sequence at offset 0)");
	}
	SECTION("invalid UTF-8 in one value of a multi-valued string")
	{
		p.telephone = { "1", "2\xED\xA0\x80" };// a surrogate
		auto attrs = ldap::to_attributes(p);
		REQUIRE_FALSE(attrs.has_value());
		CHECK(std::string_view(attrs.error().context)
			  == "attribute telephoneNumber: not valid UTF-8 (ill-formed sequence at offset 1)");
	}
	SECTION("an enum value without a name")
	{
		p.state = static_cast<status>(7);
		auto attrs = ldap::to_attributes(p);
		REQUIRE_FALSE(attrs.has_value());
		CHECK(attrs.error().code == ldap::client_errc::encode_error);
		CHECK(std::string_view(attrs.error().context) == "attribute x-status: value 7 is not in ldap::enum_names");
	}
	SECTION("a read_only member is not encoded")
	{
		p.created = sys_days(10000y / January / 1);
		CHECK(ldap::to_attributes(p).has_value());
	}
}

TEST_CASE("auxiliary classes are written on add, not ANDed into the filter", "[mapping][auxiliary]")
{
	CHECK(std::ranges::equal(ldap::object_classes_of<account>(), std::array{ "inetOrgPerson"sv }));
	CHECK(std::ranges::equal(ldap::auxiliary_classes_of<account>(), std::array{ "posixAccount"sv, "shadowAccount"sv }));
	CHECK(ldap::auxiliary_classes_of<person>().empty());

	auto a = ldap::to_attributes(account{ .uid = "jdoe", .uid_number = 1000 });
	REQUIRE(a.has_value());
	REQUIRE(a->size() == 3);
	CHECK((*a)[0] == ldap::partial_attribute{ "objectClass", { "inetOrgPerson", "posixAccount", "shadowAccount" } });
	CHECK((*a)[1] == ldap::partial_attribute{ "uid", { "jdoe" } });

	CHECK(ldap::narrow_filter<account>(ldap::filters::attr("uid") == "jdoe").to_string()
		  == "(&(objectClass=inetOrgPerson)(uid=jdoe))");
}

TEST_CASE("descriptor helpers", "[mapping]")
{
	CHECK(ldap::attribute_names<device>() == ldap::string_list{ "objectClass", "cn" });
	CHECK(ldap::attribute_names<person>().size() == 10);
	CHECK(ldap::object_classes_of<person>().size() == 2);
	CHECK(ldap::object_classes_of<device>().empty());
	STATIC_REQUIRE(ldap::described<person>);
	STATIC_REQUIRE_FALSE(ldap::described<int>);
}

// ---------------------------------------------------------------- changes and filters

TEST_CASE("typed changes encode with the member's value_traits", "[mapping][modify]")
{
	using op = ldap::modify_operation;
	const ldap::dn admins{ "cn=admins,dc=example,dc=org" };
	CHECK(ldap::replace<&person::mail>("new@example.org").wire
		  == ldap::modify_change{ op::replace, { "mail", { "new@example.org" } } });
	CHECK(ldap::replace<&person::mail>(std::optional<std::string>{}).wire
		  == ldap::modify_change{ op::replace, { "mail", {} } });
	CHECK(
	  ldap::replace<&person::uid_number>(1001).wire == ldap::modify_change{ op::replace, { "uidNumber", { "1001" } } });
	CHECK(
	  ldap::replace<&person::disabled>(true).wire == ldap::modify_change{ op::replace, { "x-disabled", { "TRUE" } } });
	CHECK(ldap::replace<&person::state>(status::retired).wire
		  == ldap::modify_change{ op::replace, { "x-status", { "retired" } } });
	CHECK(ldap::add<&person::member_of>(admins).wire
		  == ldap::modify_change{ op::add, { "memberOf", { "cn=admins,dc=example,dc=org" } } });
	CHECK(ldap::replace<&person::telephone>(std::vector<std::string>{ "1", "2" }).wire
		  == ldap::modify_change{ op::replace, { "telephoneNumber", { "1", "2" } } });
	CHECK(ldap::remove<&person::telephone>().wire == ldap::modify_change{ op::delete_, { "telephoneNumber", {} } });
	CHECK(ldap::remove<&person::member_of>(admins).wire
		  == ldap::modify_change{ op::delete_, { "memberOf", { "cn=admins,dc=example,dc=org" } } });
}

TEST_CASE("a typed change carries the encode error of its value", "[mapping][modify]")
{
	const auto check_failed = [](const ldap::change<person> &c, std::string_view context) {
		REQUIRE_FALSE(c.wire.has_value());
		CHECK(c.wire.error().code == ldap::client_errc::encode_error);
		CHECK(std::string_view(c.wire.error().context) == context);
	};
	check_failed(
	  ldap::replace<&person::cn>("\xC0\xAF"), "replace cn: not valid UTF-8 (ill-formed sequence at offset 0)");
	check_failed(ldap::replace<&person::mail>(std::optional<std::string>("a\xFF")),
	  "replace mail: not valid UTF-8 (ill-formed sequence at offset 1)");
	check_failed(ldap::add<&person::telephone>(std::vector<std::string>{ "1", "\xF8" }),
	  "add telephoneNumber: not valid UTF-8 (ill-formed sequence at offset 0)");
	check_failed(ldap::add<&person::telephone>(std::string("x\xE2\x82")),
	  "add telephoneNumber: not valid UTF-8 (ill-formed sequence at offset 1)");
	check_failed(ldap::remove<&person::telephone>(std::string("\x80")),
	  "delete telephoneNumber: not valid UTF-8 (ill-formed sequence at offset 0)");
	check_failed(
	  ldap::replace<&person::state>(static_cast<status>(5)), "replace x-status: value 5 is not in ldap::enum_names");
	// Full UTF-8 goes through.
	CHECK(ldap::replace<&person::cn>("Jos\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \xF0\x9F\x98\x80").wire
		  == ldap::modify_change{
			ldap::modify_operation::replace, { "cn", { "Jos\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \xF0\x9F\x98\x80" } } });
}

TEST_CASE("unchanged_filter: the original's values as a filter", "[mapping][unchanged_filter]")
{
	const person original{ .uid = "jdoe",
		.cn = "John",
		.mail = std::nullopt,
		.member_of = {},
		.uid_number = 1000,
		.disabled = false,
		.photo = { std::byte{ 0x28 } },
		.telephone = { "1", "2" },
		.created = sys_seconds{ seconds{ 5 } },
		.state = std::nullopt };

	auto all = ldap::unchanged_filter(original);
	REQUIRE(all.has_value());
	CHECK(all->to_string()
		  == "(&(uid=jdoe)(cn=John)(uidNumber=1000)(x-disabled=FALSE)(jpegPhoto=\\28)"
			 "(telephoneNumber=1)(telephoneNumber=2))");

	auto version = ldap::unchanged_filter<&person::created>(original);
	REQUIRE(version.has_value());
	CHECK(version->to_string() == "(createTimestamp=19700101000005Z)");
	auto optional_version = ldap::unchanged_filter<&person::disabled>(original);
	REQUIRE(optional_version.has_value());
	CHECK(optional_version->to_string() == "(x-disabled=FALSE)");

	auto missing = ldap::unchanged_filter<&person::mail>(original);
	REQUIRE_FALSE(missing.has_value());
	CHECK(missing.error().code == ldap::client_errc::missing_attribute);
	CHECK(std::string(missing.error().context) == "attribute mail");

	person bad = original;
	bad.cn = "j\xFF";
	auto not_encoded = ldap::unchanged_filter(bad);
	REQUIRE_FALSE(not_encoded.has_value());
	CHECK(not_encoded.error().code == ldap::client_errc::encode_error);
	CHECK_THAT(std::string(not_encoded.error().context), ContainsSubstring("attribute cn"));
	auto bad_version = ldap::unchanged_filter<&person::cn>(bad);
	REQUIRE_FALSE(bad_version.has_value());
	CHECK(bad_version.error().code == ldap::client_errc::encode_error);
}

TEST_CASE("diff: the changes turning one value into another", "[mapping][diff]")
{
	using op = ldap::modify_operation;
	const auto wires = [](const ldap::result<std::vector<ldap::change<person>>> &r) {
		REQUIRE(r.has_value());
		std::vector<ldap::modify_change> out;
		for (const auto &c : *r) {
			REQUIRE(c.wire.has_value());
			out.push_back(*c.wire);
		}
		return out;
	};
	const person before{ .uid = "jdoe",
		.cn = "John Doe",
		.mail = "jdoe@example.org",
		.member_of = { ldap::dn{ "cn=admins,dc=example,dc=org" }, ldap::dn{ "cn=staff,dc=example,dc=org" } },
		.uid_number = 1000,
		.disabled = std::nullopt,
		.photo = {},
		.telephone = { "1", "2" },
		.created = sys_seconds{ seconds{ 1 } },
		.state = std::nullopt };

	CHECK(wires(ldap::diff(before, before)).empty());

	SECTION("single-valued members: add when empty, replace, or delete once empty")
	{
		person after = before;
		after.cn = "J\xC3\xBCrgen Doe";
		after.mail.reset();
		after.disabled = true;
		after.uid_number = 1001;
		after.created = sys_seconds{ seconds{ 2 } };// read_only: never written
		CHECK(wires(ldap::diff(before, after))
			  == std::vector<ldap::modify_change>{ { op::replace, { "cn", { "J\xC3\xBCrgen Doe" } } },
				{ op::delete_, { "mail", {} } },
				{ op::replace, { "uidNumber", { "1001" } } },
				{ op::add, { "x-disabled", { "TRUE" } } } });

		person refilled = after;
		refilled.disabled = false;
		CHECK(wires(ldap::diff(after, refilled))
			  == std::vector<ldap::modify_change>{ { op::replace, { "x-disabled", { "FALSE" } } } });
	}

	SECTION("multi-valued members: delete the lost values, then add the new ones")
	{
		person after = before;
		after.member_of = { ldap::dn{ "cn=staff,dc=example,dc=org" },
			ldap::dn{ "cn=ops,dc=example,dc=org" },
			ldap::dn{ "cn=ops,dc=example,dc=org" } };
		after.telephone = { "2", "1" };// the same values: no change
		after.photo = { std::byte{ 0xff } };
		CHECK(wires(ldap::diff(before, after))
			  == std::vector<ldap::modify_change>{ { op::delete_, { "memberOf", { "cn=admins,dc=example,dc=org" } } },
				{ op::add, { "memberOf", { "cn=ops,dc=example,dc=org" } } },
				{ op::replace, { "jpegPhoto", { "\xff" } } } });

		after = before;
		after.telephone.clear();
		const ldap::dn ops{ "cn=ops,dc=example,dc=org" };
		after.member_of.push_back(ops);
		CHECK(wires(ldap::diff(before, after))
			  == std::vector<ldap::modify_change>{ { op::add, { "memberOf", { "cn=ops,dc=example,dc=org" } } },
				{ op::delete_, { "telephoneNumber", { "1", "2" } } } });
	}

	SECTION("a value that does not encode fails the diff")
	{
		person after = before;
		after.telephone.emplace_back("\xFF");
		auto r = ldap::diff(before, after);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK(std::string_view(r.error().context)
			  == "attribute telephoneNumber: not valid UTF-8 (ill-formed sequence at offset 0)");
	}
}

TEST_CASE("diff: a multi-valued binary member is replaced, or added when empty", "[mapping][diff]")
{
	using op = ldap::modify_operation;
	const auto wires = [](const ldap::result<std::vector<ldap::change<album>>> &r) {
		REQUIRE(r.has_value());
		std::vector<ldap::modify_change> out;
		for (const auto &c : *r) {
			REQUIRE(c.wire.has_value());
			out.push_back(*c.wire);
		}
		return out;
	};
	const ldap::binary a{ std::byte{ 'a' } };
	const ldap::binary b{ std::byte{ 'b' } };
	const ldap::binary c{ std::byte{ 'c' } };
	const album before{ .photos = { a, b } };

	CHECK(wires(ldap::diff(before, album{ .photos = { b, a } })).empty());
	CHECK(wires(ldap::diff(before, album{ .photos = { b, c, c } }))
		  == std::vector<ldap::modify_change>{ { op::replace, { "jpegPhoto", { "b", "c" } } } });
	CHECK(wires(ldap::diff(before, album{ .photos = {} }))
		  == std::vector<ldap::modify_change>{ { op::replace, { "jpegPhoto", {} } } });
	CHECK(wires(ldap::diff(album{}, album{ .photos = { a, b, a } }))
		  == std::vector<ldap::modify_change>{ { op::add, { "jpegPhoto", { "a", "b" } } } });
}

TEST_CASE("typed filters and object class narrowing", "[mapping][filter]")
{
	CHECK((ldap::filters::field<&person::uid>() == "jdoe").to_string() == "(uid=jdoe)");
	CHECK((ldap::filters::field<&person::uid_number>() >= 1000).to_string() == "(uidNumber>=1000)");
	CHECK((ldap::filters::field<&person::disabled>() == true).to_string() == "(x-disabled=TRUE)");
	CHECK((ldap::filters::field<&person::state>() == status::active).to_string() == "(x-status=active)");
	CHECK(ldap::filters::field<&person::mail>().present().to_string() == "(mail=*)");
	CHECK((ldap::filters::field<&person::uid>() == "a*b").to_string() == "(uid=a\\2ab)");// values are escaped
	CHECK((ldap::filters::field<&person::cn>() == "Jos\xC3\xA9").to_string() == "(cn=Jos\xC3\xA9)");

	const auto f = ldap::narrow_filter<person>(ldap::filters::attr("uid") == "jdoe");
	CHECK(f.to_string() == "(&(objectClass=inetOrgPerson)(objectClass=posixAccount)(uid=jdoe))");
	CHECK(ldap::narrow_filter<device>(ldap::filters::attr("cn") == "x").to_string() == "(cn=x)");
}

TEST_CASE("a typed filter on a value that does not encode is the empty filter", "[mapping][filter]")
{
	using ldap::filters::field;
	const ldap::filter bad[] = {
		field<&person::uid>() == "\xFF",
		field<&person::cn>() >= "a\xC3",
		field<&person::cn>() <= "\xED\xA0\x80",
		field<&person::cn>().approx("\x80"),
		field<&person::state>() == static_cast<status>(9),
	};
	for (const auto &f : bad) {
		CHECK(f.empty());
		// It stays empty through && || !, and does not encode.
		const auto combined = !(f && (field<&person::uid>() == "jdoe")) || (field<&person::uid>() == "x");
		CHECK(combined.empty());
		ldap::ber::writer w;
		const auto r = ldap::encode_filter(w, combined);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::invalid_filter);
	}
}

// ---------------------------------------------------------------- custom value_traits

namespace {

// A trait whose encode cannot fail returns std::string.
struct celsius
{
	int degrees = 0;
};

// A trait whose encode can fail returns result<std::string>.
struct even
{
	int value = 0;
};

struct reading
{
	celsius temperature;
	std::optional<even> count;
};

}// namespace

template<> struct ldap::value_traits<celsius>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> ldap::result<celsius>
	{
		auto v = ldap::value_traits<int>::decode(raw);
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		return celsius{ *v };
	}
	[[nodiscard]] static auto encode(const celsius &c) -> std::string { return std::to_string(c.degrees); }
};

template<> struct ldap::value_traits<even>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> ldap::result<even>
	{
		auto v = ldap::value_traits<int>::decode(raw);
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		return even{ *v };
	}
	[[nodiscard]] static auto encode(const even &e) -> ldap::result<std::string>
	{
		if (e.value % 2 != 0) {
			return ldap::fail(ldap::client_errc::encode_error, "odd");
		}
		return std::to_string(e.value);
	}
};

template<>
constexpr auto ldap::schema<reading> = ldap::describe(ldap::object_class("device"),
  ldap::field<&reading::temperature>("x-temperature"),
  ldap::field<&reading::count>("x-count"));

TEST_CASE("custom value_traits may return std::string or result<std::string>", "[mapping][traits]")
{
	STATIC_REQUIRE(ldap::mapped_value<celsius>);
	STATIC_REQUIRE(ldap::mapped_value<even>);
	CHECK(ldap::detail::encode_value(celsius{ -5 }) == "-5");
	CHECK(ldap::detail::encode_value(even{ 4 }) == "4");
	REQUIRE_FALSE(ldap::detail::encode_value(even{ 3 }).has_value());

	using op = ldap::modify_operation;
	CHECK(ldap::replace<&reading::temperature>(celsius{ 21 }).wire
		  == ldap::modify_change{ op::replace, { "x-temperature", { "21" } } });
	CHECK(ldap::replace<&reading::count>(even{ 2 }).wire == ldap::modify_change{ op::replace, { "x-count", { "2" } } });
	const auto odd = ldap::replace<&reading::count>(even{ 3 });
	REQUIRE_FALSE(odd.wire.has_value());
	CHECK(std::string_view(odd.wire.error().context) == "replace x-count: odd");

	CHECK((ldap::filters::field<&reading::temperature>() >= celsius{ 30 }).to_string() == "(x-temperature>=30)");
	CHECK((ldap::filters::field<&reading::count>() == even{ 1 }).empty());

	const auto ok = ldap::to_attributes(reading{ .temperature = { 7 }, .count = even{ 8 } });
	REQUIRE(ok.has_value());
	CHECK(*ok
		  == std::pmr::vector<ldap::partial_attribute>{
			{ "objectClass", { "device" } }, { "x-temperature", { "7" } }, { "x-count", { "8" } } });
	const auto failed = ldap::to_attributes(reading{ .temperature = { 7 }, .count = even{ 9 } });
	REQUIRE_FALSE(failed.has_value());
	CHECK(failed.error().code == ldap::client_errc::encode_error);
	CHECK(std::string_view(failed.error().context) == "attribute x-count: odd");
}
