// Active Directory's Large Integer syntax (1.2.840.113556.1.4.906) as
// std::chrono types. AD stores dates as FILETIME, a signed 64-bit count of
// 100 ns ticks since 1601-01-01 00:00:00 UTC, written in decimal
// (accountExpires, pwdLastSet, lastLogonTimestamp, lastLogon,
// badPasswordTime, lockoutTime), and intervals as negative tick counts
// (maxPwdAge, minPwdAge, lockoutDuration, lockOutObservationWindow).
//
//   struct ad_user {
//       std::string                                  sam_account_name;
//       std::optional<ldap::ad::filetime_clock::time_point> account_expires;
//       std::optional<ldap::ad::filetime_clock::time_point> pwd_last_set;
//   };
//   struct ad_domain {
//       ldap::ad::filetime_clock::duration max_pwd_age{};   // negative
//   };
//
//   if (u.account_expires && *u.account_expires != ldap::ad::never) {
//       auto utc = std::chrono::clock_cast<std::chrono::system_clock>(*u.account_expires);
//   }
//   auto f = ldap::filters::field<&ad_user::account_expires>() <= ldap::ad::filetime_clock::now();
//
// The schema cannot tell a date from a counter (uSNChanged is 906 too): the
// member's type decides. std::int64_t members read every 906 attribute as
// the raw number; the time_point and duration below read 906 only.
//
// Sentinels:
//   ad::never          accountExpires (and lastLogonTimestamp, ...) 0 or
//                      9223372036854775807 decode to it: "no date". It is
//                      time_point::max() and encodes as 9223372036854775807
//                      (AD's "never expires"). Compare against it before
//                      converting: as a date it is in year 30828.
//   ad::pwd_must_change  pwdLastSet 0: written, the user must change the
//                      password at the next logon. On read, pwdLastSet 0
//                      decodes to ad::never (no date set), like any 0.
//   ad::pwd_set_now    pwdLastSet -1: written, AD sets pwdLastSet to now.
//   ad::forever        an interval of -9223372036854775808 ticks
//                      (duration::min()): maxPwdAge "passwords never
//                      expire", lockoutDuration "until an administrator
//                      unlocks". Negating it overflows: test for it first.
//
// Filters: a typed filter on a mapped member encodes the value
// (filters::field<&T::m>() <= t). On an untyped attribute, encode it:
// filters::attr("accountExpires") <= ldap::value_traits<ad::filetime_clock::time_point>::encode(t).
// AD compares the numbers, so 0 ("never") is below every date:
// "accounts that expired" is (&(accountExpires>=1)(accountExpires<=now)).
#pragma once

#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/schema.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <ratio>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace jhetz::ldap::ad {

// A C++20 Clock for FILETIME: 100 ns ticks since 1601-01-01 00:00:00 UTC.
// std::chrono::file_clock is not this clock: its epoch and period are
// implementation-defined (libstdc++: 2174-01-01, nanoseconds).
// std::chrono::clock_cast converts to and from system_clock (and so to
// zoned_time, utc_clock, ...) through to_sys / from_sys. Leap seconds are
// not counted, as in FILETIME and system_clock.
struct filetime_clock
{
	using rep = std::int64_t;
	using period = std::ratio<1, 10'000'000>;
	using duration = std::chrono::duration<rep, period>;
	using time_point = std::chrono::time_point<filetime_clock>;
	static constexpr bool is_steady = false;

	// From 1601-01-01 to 1970-01-01 (the Unix epoch): 134774 days.
	static constexpr std::chrono::seconds unix_epoch_offset{ 11'644'473'600 };

	[[nodiscard]] static time_point now() noexcept { return from_sys(std::chrono::system_clock::now()); }

	template<class D>
	[[nodiscard]] static constexpr std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>> to_sys(
	  const std::chrono::time_point<filetime_clock, D> &t)
	{
		return std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>(
		  t.time_since_epoch() - unix_epoch_offset);
	}

	// Rounds down to a tick (a system_clock::time_point has nanoseconds, and
	// FILETIME dates in nanoseconds would overflow 64 bits after 1893).
	template<class D> [[nodiscard]] static constexpr time_point from_sys(const std::chrono::sys_time<D> &t)
	{
		return time_point(std::chrono::floor<duration>(t.time_since_epoch()) + unix_epoch_offset);
	}
};

inline constexpr filetime_clock::time_point never = filetime_clock::time_point::max();
inline constexpr filetime_clock::time_point pwd_must_change{ filetime_clock::duration{ 0 } };
inline constexpr filetime_clock::time_point pwd_set_now{ filetime_clock::duration{ -1 } };
inline constexpr filetime_clock::duration forever = filetime_clock::duration::min();

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// A FILETIME date: decimal ticks. 0 and 9223372036854775807 decode to
// ad::never; any other value (negative ones included) is that many ticks
// from 1601-01-01. Encodes the tick count (ad::never: 9223372036854775807).
template<> struct value_traits<ad::filetime_clock::time_point>
{
	static constexpr std::array syntaxes{ syntax::ad_large_integer };

	[[nodiscard]] static result<ad::filetime_clock::time_point> decode(std::string_view raw)
	{
		auto ticks = value_traits<std::int64_t>::decode(raw);
		if (!ticks) return std::unexpected(std::move(ticks.error()));
		if (*ticks == 0) return ad::never;
		return ad::filetime_clock::time_point(ad::filetime_clock::duration(*ticks));
	}
	[[nodiscard]] static std::string encode(ad::filetime_clock::time_point v)
	{
		return std::to_string(v.time_since_epoch().count());
	}
};

// A Large Integer interval: decimal ticks, sign kept (AD writes intervals
// as negative values: maxPwdAge -36288000000000 is 42 days).
template<> struct value_traits<ad::filetime_clock::duration>
{
	static constexpr std::array syntaxes{ syntax::ad_large_integer };

	[[nodiscard]] static result<ad::filetime_clock::duration> decode(std::string_view raw)
	{
		auto ticks = value_traits<std::int64_t>::decode(raw);
		if (!ticks) return std::unexpected(std::move(ticks.error()));
		return ad::filetime_clock::duration(*ticks);
	}
	[[nodiscard]] static std::string encode(ad::filetime_clock::duration v) { return std::to_string(v.count()); }
};

}// namespace jhetz::ldap
