#include "jhetz/ldap/ad/filetime.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <ratio>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;
using Catch::Matchers::ContainsSubstring;
using namespace std::chrono;

namespace {

using filetime = ad::filetime_clock::time_point;
using ticks = ad::filetime_clock::duration;
using traits = ldap::value_traits<filetime>;
using interval_traits = ldap::value_traits<ticks>;

static_assert(is_clock_v<ad::filetime_clock>);
static_assert(std::same_as<ad::filetime_clock::period, std::ratio<1, 10'000'000>>);
static_assert(!ad::filetime_clock::is_steady);
static_assert(ldap::mapped_value<filetime>);
static_assert(ldap::mapped_value<ticks>);

// 2024-01-01 00:00:00.1234567 UTC as AD writes it (lastLogonTimestamp).
constexpr std::int64_t new_year_2024 = 133'485'408'001'234'567;

}// namespace

TEST_CASE("filetime_clock: epoch and the Unix epoch", "[ad][clock]")
{
	CHECK(clock_cast<system_clock>(filetime{}) == sys_days(1601y / January / 1));
	CHECK(ad::filetime_clock::to_sys(filetime{}) == sys_days(1601y / January / 1));
	CHECK(clock_cast<ad::filetime_clock>(sys_days(1970y / January / 1)).time_since_epoch().count()
		  == 116'444'736'000'000'000);
	CHECK(ad::filetime_clock::unix_epoch_offset == days(134'774));
	// Constant-evaluable both ways.
	static_assert(ad::filetime_clock::from_sys(sys_seconds{}) == filetime(ad::filetime_clock::unix_epoch_offset));
	static_assert(ad::filetime_clock::to_sys(filetime(ad::filetime_clock::unix_epoch_offset)) == sys_seconds{});
}

TEST_CASE("filetime_clock: a known AD value, round trips and now()", "[ad][clock]")
{
	const filetime t{ ticks{ new_year_2024 } };
	const sys_time<ticks> s = clock_cast<system_clock>(t);
	CHECK(s == sys_days(2024y / January / 1) + ticks{ 1'234'567 });
	CHECK(floor<seconds>(s) == sys_days(2024y / January / 1));
	CHECK(clock_cast<ad::filetime_clock>(s) == t);

	// Nanoseconds round down to the 100 ns tick.
	const sys_time<nanoseconds> ns = sys_days(2024y / January / 1) + nanoseconds{ 123'456'789 };
	CHECK(clock_cast<ad::filetime_clock>(ns).time_since_epoch().count() == 133'485'408'001'234'567);
	// Before 1970 (and before 1601) work too.
	CHECK(clock_cast<ad::filetime_clock>(sys_days(1601y / January / 2)).time_since_epoch() == days(1));
	CHECK(clock_cast<ad::filetime_clock>(sys_days(1600y / December / 31)).time_since_epoch() == -days(1));

	const auto before = floor<ticks>(system_clock::now());
	const filetime now = ad::filetime_clock::now();
	const auto after = system_clock::now();
	CHECK(clock_cast<system_clock>(now) >= before);
	CHECK(clock_cast<system_clock>(now) <= after);
}

TEST_CASE("filetime_clock: conversions at the limits", "[ad][clock]")
{
	using ft = ad::filetime_clock;
	constexpr ticks offset = ft::unix_epoch_offset;
	// The lowest date to_sys converts, and the highest from_sys produces.
	static_assert(ft::to_sys(filetime::min() + offset) == sys_time<ticks>::min());
	static_assert(ft::from_sys(sys_time<ticks>::min()) == filetime::min() + offset);
	static_assert(ft::from_sys(sys_time<ticks>::max() - offset) == ad::never);
	// ad::never converts without overflow, to year 30828 (no real date).
	static_assert(ft::to_sys(ad::never) == sys_time<ticks>(ticks::max() - offset));
	CHECK(year_month_day(floor<days>(clock_cast<system_clock>(ad::never))).year() == 30828y);
	CHECK(clock_cast<ad::filetime_clock>(clock_cast<system_clock>(ad::never)) == ad::never);
	// The decodable extremes: -1 (ad::pwd_set_now) and tick 0.
	CHECK(clock_cast<system_clock>(*traits::decode("-1")) == sys_days(1601y / January / 1) - ticks{ 1 });
	CHECK(clock_cast<system_clock>(*traits::decode("0")) == sys_days(1601y / January / 1));
	CHECK(clock_cast<ad::filetime_clock>(clock_cast<system_clock>(ad::pwd_set_now)) == ad::pwd_set_now);
	// from_sys' domain ends at sys_time<ticks>::max() - offset whatever
	// system_clock's period. With nanoseconds (libstdc++) every
	// system_clock::time_point is in it; with MSVC's 100 ns ticks or
	// libc++'s microseconds only those up to that bound are.
	if constexpr (std::ratio_less_equal_v<system_clock::period, std::nano>) {
		CHECK(clock_cast<ad::filetime_clock>(system_clock::time_point::max())
			  == filetime(floor<ticks>(system_clock::duration::max()) + offset));
		CHECK(clock_cast<ad::filetime_clock>(system_clock::time_point::min())
			  == filetime(floor<ticks>(system_clock::duration::min()) + offset));
	} else {
		const auto top = floor<system_clock::duration>(sys_time<ticks>::max() - offset);
		CHECK(clock_cast<ad::filetime_clock>(top) == filetime(floor<ticks>(top.time_since_epoch()) + offset));
	}
}

TEST_CASE("filetime_clock: utc_clock and zoned_time", "[ad][clock]")
{
	const filetime t{ ticks{ new_year_2024 } };
	CHECK(clock_cast<utc_clock>(t) == clock_cast<utc_clock>(sys_days(2024y / January / 1) + ticks{ 1'234'567 }));
	// The toolchain's tzdb (libstdc++ reads the system's zoneinfo).
	const zoned_time paris{ "Europe/Paris", clock_cast<system_clock>(t) };
	CHECK(floor<seconds>(paris.get_local_time()) == local_days(2024y / January / 1) + 1h);
	// The offset, not the abbreviation: "CET" in the IANA data, but other
	// tzdb sources (MSVC's, through ICU) may spell it "GMT+1".
	CHECK(paris.get_info().offset == 1h);
}

TEST_CASE("filetime value_traits: ticks, sentinels and errors", "[ad][traits]")
{
	CHECK(traits::decode("133485408001234567") == filetime{ ticks{ new_year_2024 } });
	CHECK(traits::encode(filetime{ ticks{ new_year_2024 } }) == "133485408001234567");
	CHECK(traits::decode("1") == filetime{ ticks{ 1 } });

	// The maximum is ad::never; 0 is tick 0 (1601-01-01), before every date.
	CHECK(ad::never == filetime::max());
	CHECK(traits::decode("9223372036854775807") == ad::never);
	CHECK(traits::encode(ad::never) == "9223372036854775807");
	CHECK(ad::never != filetime{ ticks{ new_year_2024 } });
	CHECK(traits::decode("0") == filetime{});
	CHECK(traits::encode(filetime{}) == "0");
	CHECK(*traits::decode("0") < filetime{ ticks{ 1 } });

	// accountExpires "never expires": either spelling.
	static_assert(ad::is_never(filetime{}));
	static_assert(ad::is_never(ad::never));
	static_assert(noexcept(ad::is_never(ad::never)));
	CHECK(ad::is_never(*traits::decode("0")));
	CHECK(ad::is_never(*traits::decode("9223372036854775807")));
	CHECK_FALSE(ad::is_never(*traits::decode("1")));
	CHECK_FALSE(ad::is_never(*traits::decode("-1")));
	CHECK_FALSE(ad::is_never(filetime{ ticks{ new_year_2024 } }));
	CHECK_FALSE(ad::is_never(filetime::max() - ticks{ 1 }));

	// pwdLastSet: 0 forces a change at the next logon, -1 sets it to now.
	CHECK(traits::encode(ad::pwd_must_change) == "0");
	CHECK(traits::encode(ad::pwd_set_now) == "-1");
	CHECK(traits::decode("-1") == ad::pwd_set_now);
	CHECK(traits::decode("0") == ad::pwd_must_change);// read back

	for (const char *bad : { "", "x", "1.5", "+1", "9223372036854775808", "-9223372036854775809", " 1" }) {
		const auto r = traits::decode(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::conversion_failed);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("not an integer"));
	}
	// Below -1: no AD date, and where to_sys would overflow.
	for (const char *bad : { "-2", "-116444736000000000", "-9223372036854775808" }) {
		const auto r = traits::decode(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::conversion_failed);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("FILETIME date before -1"));
	}
	// Intervals keep the full range.
	CHECK(interval_traits::decode("-2") == ticks{ -2 });
}

TEST_CASE("interval value_traits keep AD's negative intervals", "[ad][traits]")
{
	// maxPwdAge 42 days, lockoutDuration 30 minutes.
	CHECK(interval_traits::decode("-36288000000000") == -days(42));
	CHECK(interval_traits::decode("-18000000000") == -minutes(30));
	CHECK(abs(*interval_traits::decode("-18000000000")) == 30min);
	CHECK(interval_traits::encode(-days(42)) == "-36288000000000");
	CHECK(interval_traits::encode(ticks{ 5 }) == "5");
	// "Never expires" / "until unlocked".
	CHECK(interval_traits::decode("-9223372036854775808") == ad::forever);
	CHECK(interval_traits::encode(ad::forever) == "-9223372036854775808");
	CHECK_FALSE(interval_traits::decode("-1d").has_value());
}

// ---------------------------------------------------------------- mapping

namespace {

struct ad_user
{
	std::string sam_account_name;
	std::optional<filetime> account_expires;
	std::optional<filetime> pwd_last_set;
	std::optional<filetime> last_logon_timestamp;
};

struct ad_user_raw
{
	std::string sam_account_name;
	std::int64_t account_expires = 0;
	std::optional<std::int64_t> usn_changed;
};

struct ad_user_narrow
{
	std::int32_t account_expires = 0;
	std::uint64_t usn_changed = 0;
	ticks bad_interval{};// an interval on an INTEGER attribute
	filetime bad_date{};// a date on an INTEGER attribute
};

struct ad_domain
{
	ticks max_pwd_age{};
	std::optional<ticks> lockout_duration;
	std::optional<ticks> lockout_observation_window;
};

}// namespace

template<>
constexpr auto ldap::schema<ad_user> = ldap::describe(ldap::object_class("user"),
  ldap::field<&ad_user::sam_account_name>("sAMAccountName"),
  ldap::field<&ad_user::account_expires>("accountExpires"),
  ldap::field<&ad_user::pwd_last_set>("pwdLastSet"),
  ldap::field<&ad_user::last_logon_timestamp>("lastLogonTimestamp", ldap::read_only));

template<>
constexpr auto ldap::schema<ad_user_raw> = ldap::describe(ldap::object_class("user"),
  ldap::field<&ad_user_raw::sam_account_name>("sAMAccountName"),
  ldap::field<&ad_user_raw::account_expires>("accountExpires"),
  ldap::field<&ad_user_raw::usn_changed>("uSNChanged", ldap::read_only));

template<>
constexpr auto ldap::schema<ad_user_narrow> = ldap::describe(ldap::object_class("user"),
  ldap::field<&ad_user_narrow::account_expires>("accountExpires"),
  ldap::field<&ad_user_narrow::usn_changed>("uSNChanged", ldap::read_only),
  ldap::field<&ad_user_narrow::bad_interval>("userAccountControl"),
  ldap::field<&ad_user_narrow::bad_date>("userAccountControl"));

template<>
constexpr auto ldap::schema<ad_domain> = ldap::describe(ldap::object_class("domainDNS"),
  ldap::field<&ad_domain::max_pwd_age>("maxPwdAge"),
  ldap::field<&ad_domain::lockout_duration>("lockoutDuration"),
  ldap::field<&ad_domain::lockout_observation_window>("lockOutObservationWindow"));

namespace {

// As Active Directory serves them (CN=Aggregate): quoted OIDs, 906 syntax.
const std::pmr::vector<std::pmr::string> ad_types{
	"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.8 NAME 'userAccountControl' SYNTAX '1.3.6.1.4.1.1466.115.121.1.27' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.159 NAME 'accountExpires' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.96 NAME 'pwdLastSet' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.1696 NAME 'lastLogonTimestamp' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )",
	// NOLINTNEXTLINE(bugprone-suspicious-missing-comma): one definition, wrapped at the column limit
	"( 1.2.840.113556.1.2.120 NAME 'uSNChanged' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE "
	"NO-USER-MODIFICATION )",
	"( 1.2.840.113556.1.4.74 NAME 'maxPwdAge' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.60 NAME 'lockoutDuration' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )",
	"( 1.2.840.113556.1.4.61 NAME 'lockOutObservationWindow' SYNTAX '1.2.840.113556.1.4.906' SINGLE-VALUE )",
};
// MAY lists cut; AD's top requires attributes the server fills in itself.
const std::pmr::vector<std::pmr::string> ad_classes{
	"( 2.5.6.0 NAME 'top' ABSTRACT MUST (objectClass $ instanceType $ nTSecurityDescriptor $ objectCategory ) )",
	"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST (cn ) MAY (sn $ userPassword ) )",
	"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY (c $ l ) )",
	"( 1.2.840.113556.1.5.9 NAME 'user' SUP organizationalPerson STRUCTURAL MAY (accountExpires $ pwdLastSet ) )",
	"( 1.2.840.113556.1.5.67 NAME 'domainDNS' SUP top STRUCTURAL MAY (maxPwdAge ) )",
};

// The issues but the MUST warnings (validate<T> reports the MUSTs of the
// declared classes and their superclasses that no required member maps).
auto without_must(const ldap::schema_report &rep) -> std::vector<ldap::schema_issue>
{
	std::vector<ldap::schema_issue> out;
	for (const auto &i : rep.issues) {
		if (i.what != ldap::schema_issue::kind::must_attribute_not_mapped
			&& i.what != ldap::schema_issue::kind::must_attribute_not_required) {
			out.push_back(i);
		}
	}
	return out;
}

// The names of the MUST warnings, in report order.
auto must_names(const ldap::schema_report &rep) -> std::vector<std::string>
{
	std::vector<std::string> out;
	for (const auto &i : rep.issues) {
		if (i.what == ldap::schema_issue::kind::must_attribute_not_mapped) {
			out.push_back(i.name);
		}
	}
	return out;
}

auto make_entry(std::string_view dn, std::initializer_list<ldap::partial_attribute> attrs) -> ldap::entry
{
	return ldap::entry::from(ldap::search_result_entry(dn, attrs));
}

}// namespace

TEST_CASE("schema: AD Large Integer validates for int64, filetime and interval members", "[ad][schema]")
{
	const auto s = ldap::server_schema::parse(ad_types, ad_classes);
	REQUIRE(s.skipped() == 0);
	REQUIRE(s.find_attribute("accountExpires") != nullptr);
	CHECK(*s.find_attribute("accountExpires")->syntax == ldap::ad::large_integer_syntax);

	const auto raw = ldap::validate<ad_user_raw>(s);
	CHECK(raw.ok());
	CHECK(without_must(raw).empty());
	const auto user = ldap::validate<ad_user>(s);
	CHECK(user.ok());
	CHECK(without_must(user).empty());
	// person's cn (the RDN supplies it), and top's attributes AD fills in
	// itself: warnings only.
	CHECK(
	  must_names(user) == std::vector<std::string>{ "cn", "instanceType", "nTSecurityDescriptor", "objectCategory" });
	const auto domain = ldap::validate<ad_domain>(s);
	CHECK(domain.ok());
	CHECK(without_must(domain).empty());
	CHECK(must_names(domain) == std::vector<std::string>{ "instanceType", "nTSecurityDescriptor", "objectCategory" });

	// int32 and unsigned members cannot hold 906 values (dates, negative
	// intervals); the filetime types read 906 only.
	const auto narrow_report = ldap::validate<ad_user_narrow>(s);
	const auto narrow = without_must(narrow_report);
	REQUIRE(narrow.size() == 4);
	for (const auto &issue : narrow) {
		CHECK(issue.what == ldap::schema_issue::kind::syntax_mismatch);
	}
	CHECK(narrow[0].name == "accountExpires");
	CHECK(narrow[1].name == "uSNChanged");
	CHECK(narrow[2].detail
		  == std::string("syntax 1.3.6.1.4.1.1466.115.121.1.27 is not one the member's type reads (")
			   + ldap::ad::large_integer_syntax + ")");
	CHECK(narrow[3].name == "userAccountControl");
}

TEST_CASE("mapping AD users and domain policy", "[ad][mapping]")
{
	auto u = ldap::decode<ad_user>(make_entry("CN=jdoe,CN=Users,DC=example,DC=org",
	  { { "sAMAccountName", { "jdoe" } },
		{ "accountExpires", { "9223372036854775807" } },
		{ "pwdLastSet", { "0" } },
		{ "lastLogonTimestamp", { "133485408001234567" } } }));
	REQUIRE(u.has_value());
	CHECK(u->account_expires == ad::never);
	CHECK(ad::is_never(*u->account_expires));
	CHECK(u->pwd_last_set == ad::pwd_must_change);
	CHECK(u->last_logon_timestamp == filetime{ ticks{ new_year_2024 } });

	// 0: accountExpires never expires; lastLogonTimestamp never happened, so
	// it sorts before any cutoff (a stale-account check includes it).
	auto fresh = ldap::decode<ad_user>(make_entry("CN=new,CN=Users,DC=example,DC=org",
	  { { "sAMAccountName", { "new" } }, { "accountExpires", { "0" } }, { "lastLogonTimestamp", { "0" } } }));
	REQUIRE(fresh.has_value());
	CHECK(fresh->account_expires == filetime{});
	CHECK(ad::is_never(*fresh->account_expires));
	CHECK(fresh->last_logon_timestamp == filetime{});
	CHECK(*fresh->last_logon_timestamp < clock_cast<ad::filetime_clock>(sys_days(2024y / January / 1)) - days(90));

	auto raw = ldap::decode<ad_user_raw>(make_entry("CN=jdoe,CN=Users,DC=example,DC=org",
	  { { "sAMAccountName", { "jdoe" } }, { "accountExpires", { "9223372036854775807" } } }));
	REQUIRE(raw.has_value());
	CHECK(raw->account_expires == std::numeric_limits<std::int64_t>::max());

	auto d = ldap::decode<ad_domain>(make_entry("DC=example,DC=org",
	  { { "maxPwdAge", { "-36288000000000" } }, { "lockoutDuration", { "-9223372036854775808" } } }));
	REQUIRE(d.has_value());
	CHECK(d->max_pwd_age == -days(42));
	CHECK(d->lockout_duration == ad::forever);
	CHECK_FALSE(d->lockout_observation_window.has_value());

	using op = ldap::modify_operation;
	CHECK(ldap::replace<&ad_user::pwd_last_set>(ad::pwd_must_change).wire
		  == ldap::modify_change{ op::replace, { "pwdLastSet", { "0" } } });
	CHECK(ldap::replace<&ad_user::pwd_last_set>(ad::pwd_set_now).wire
		  == ldap::modify_change{ op::replace, { "pwdLastSet", { "-1" } } });
	CHECK(ldap::replace<&ad_user::account_expires>(ad::never).wire
		  == ldap::modify_change{ op::replace, { "accountExpires", { "9223372036854775807" } } });
	const filetime expiry = clock_cast<ad::filetime_clock>(sys_days(2024y / January / 1));
	CHECK(ldap::replace<&ad_user::account_expires>(expiry).wire
		  == ldap::modify_change{ op::replace, { "accountExpires", { "133485408000000000" } } });
}

TEST_CASE("filters on AD times", "[ad][filter]")
{
	const filetime t = clock_cast<ad::filetime_clock>(sys_days(2024y / January / 1));
	CHECK(
	  (ldap::filters::field<&ad_user::account_expires>() <= t).to_string() == "(accountExpires<=133485408000000000)");
	// Expired accounts: 0 ("never") sorts below every date, so exclude it.
	const auto expired = ldap::filters::field<&ad_user::account_expires>() >= filetime{ ticks{ 1 } }
						 && ldap::filters::field<&ad_user::account_expires>() <= t;
	CHECK(expired.to_string() == "(&(accountExpires>=1)(accountExpires<=133485408000000000))");
	// "Never expires": equality on ad::never matches 9223372036854775807
	// only, so ask for 0 too.
	const auto expires = ldap::filters::field<&ad_user::account_expires>();
	CHECK((expires == ad::never).to_string() == "(accountExpires=9223372036854775807)");
	CHECK((expires == ad::never || expires == filetime{}).to_string()
		  == "(|(accountExpires=9223372036854775807)(accountExpires=0))");
	// Untyped: encode the value.
	CHECK((ldap::filters::attr("lastLogonTimestamp") >= traits::encode(t)).to_string()
		  == "(lastLogonTimestamp>=133485408000000000)");
}
