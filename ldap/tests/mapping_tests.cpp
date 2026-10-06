#include "jhetz/ldap/mapping.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
using Catch::Matchers::ContainsSubstring;
using namespace std::chrono;

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

// A struct without declared object classes maps objectClass itself.
struct device
{
	std::vector<std::string> object_class;
	std::string cn;
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
constexpr auto ldap::schema<device> =
  ldap::describe(ldap::field<&device::object_class>("objectClass"), ldap::field<&device::cn>("cn"));

namespace {

ldap::entry make_entry(std::string_view dn, std::initializer_list<ldap::partial_attribute> attrs)
{
	return ldap::entry::from(ldap::search_result_entry(dn, attrs));
}

ldap::entry full_entry()
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
	for (auto bad : { "", "+1", " 1", "1 ", "12a", "0x10", "2147483648", "1.5" }) {
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
}

TEST_CASE("value_traits for enums with a name table", "[mapping][traits]")
{
	CHECK(ldap::value_traits<status>::decode("retired") == status::retired);
	CHECK_FALSE(ldap::value_traits<status>::decode("Retired").has_value());
	CHECK(ldap::value_traits<status>::encode(status::locked) == "locked");
	CHECK(ldap::value_traits<status>::encode(static_cast<status>(9)) == "9");
}

TEST_CASE("GeneralizedTime", "[mapping][traits][time]")
{
	const sys_seconds noon = sys_days(2024y / February / 29) + 12h;
	struct case_t
	{
		const char *text;
		sys_seconds expected;
	};
	const case_t cases[] = {
		{ "2024022912Z", noon },
		{ "202402291230Z", noon + 30min },
		{ "20240229123045Z", noon + 30min + 45s },
		{ "20240229123045.999Z", noon + 30min + 45s },// fractions of a second truncated
		{ "20240229123045,5Z", noon + 30min + 45s },
		{ "2024022912.5Z", noon + 30min },// fraction of an hour
		{ "202402291230.25Z", noon + 30min + 15s },// fraction of a minute
		{ "20240229140000+0200", noon },
		{ "20240229070000-05", noon },
		{ "20240229123060Z", noon + 31min },// leap second rolls over
		{ "19700101000000Z", sys_seconds{} },
		{ "99991231235959Z", sys_days(9999y / December / 31) + 23h + 59min + 59s },
	};
	for (const auto &c : cases) {
		INFO(c.text);
		auto t = ldap::parse_generalized_time(c.text);
		REQUIRE(t.has_value());
		CHECK(*t == c.expected);
	}
	for (auto bad : { "",
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
	CHECK_THROWS_AS(ldap::value_traits<sys_seconds>::encode(sys_days(10000y / January / 1)), std::out_of_range);
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
		{ "missing required",
		  "uid",
		  {},
		  ldap::client_errc::missing_attribute,
		  "entry uid=jdoe,ou=people,dc=example,dc=org: attribute uid: required attribute missing" },
		{ "two values for a required member",
		  "cn",
		  { "a", "b" },
		  ldap::client_errc::too_many_values,
		  "entry uid=jdoe,ou=people,dc=example,dc=org: attribute cn: 2 values for a single-valued member" },
		{ "two values for an optional member", "mail", { "a", "b" }, ldap::client_errc::too_many_values, nullptr },
		{ "bad integer",
		  "uidNumber",
		  { "12a" },
		  ldap::client_errc::conversion_failed,
		  "entry uid=jdoe,ou=people,dc=example,dc=org: attribute uidNumber: not an integer: \"12a\"" },
		{ "bad element of a vector",
		  "memberOf",
		  { "cn=ok,dc=example,dc=org", "bad" },
		  ldap::client_errc::conversion_failed,
		  "entry uid=jdoe,ou=people,dc=example,dc=org: attribute memberOf: not a distinguished name: \"bad\"" },
		{ "bad boolean", "x-disabled", { "yes" }, ldap::client_errc::conversion_failed, nullptr },
		{ "bad time", "createTimestamp", { "yesterday" }, ldap::client_errc::conversion_failed, nullptr },
		{ "unknown enum name", "x-status", { "gone" }, ldap::client_errc::conversion_failed, nullptr },
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
				for (auto v : c.values) a.values.emplace_back(v);
				e.attributes.push_back(std::move(a));
			}
			auto p = ldap::decode<person>(e);
			REQUIRE_FALSE(p.has_value());
			CHECK(p.error().code == c.code);
			if (c.context != nullptr) CHECK(p.error().context == c.context);
		}
	}
}

// ---------------------------------------------------------------- encode / descriptor

TEST_CASE("to_attributes writes objectClass and skips read_only and empty members", "[mapping][encode]")
{
	auto p = *ldap::decode<person>(full_entry());
	p.mail.reset();
	p.member_of.clear();
	const auto attrs = ldap::to_attributes(p);
	std::vector<std::string> names;
	for (const auto &a : attrs) names.emplace_back(a.type);
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

	const auto dev = ldap::to_attributes(device{ { "top", "device" }, "printer" });
	REQUIRE(dev.size() == 2);
	CHECK(dev[0] == ldap::partial_attribute{ "objectClass", { "top", "device" } });
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

TEST_CASE("typed filters and object class narrowing", "[mapping][filter]")
{
	CHECK((ldap::filters::field<&person::uid>() == "jdoe").to_string() == "(uid=jdoe)");
	CHECK((ldap::filters::field<&person::uid_number>() >= 1000).to_string() == "(uidNumber>=1000)");
	CHECK((ldap::filters::field<&person::disabled>() == true).to_string() == "(x-disabled=TRUE)");
	CHECK((ldap::filters::field<&person::state>() == status::active).to_string() == "(x-status=active)");
	CHECK(ldap::filters::field<&person::mail>().present().to_string() == "(mail=*)");
	CHECK((ldap::filters::field<&person::uid>() == "a*b").to_string() == "(uid=a\\2ab)");// values are escaped

	const auto f = ldap::narrow_filter<person>(ldap::filters::attr("uid") == "jdoe");
	CHECK(f.to_string() == "(&(objectClass=inetOrgPerson)(objectClass=posixAccount)(uid=jdoe))");
	CHECK(ldap::narrow_filter<device>(ldap::filters::attr("cn") == "x").to_string() == "(cn=x)");
}
