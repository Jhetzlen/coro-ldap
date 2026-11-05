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
//   if (u.account_expires && !ldap::ad::is_never(*u.account_expires)) {
//       auto utc = std::chrono::clock_cast<std::chrono::system_clock>(*u.account_expires);
//   }
//   // Expired accounts. AD compares the numbers, and 0 ("never expires")
//   // is below every date: ">= 1" leaves it out.
//   using ft = ldap::ad::filetime_clock;
//   auto expires = ldap::filters::field<&ad_user::account_expires>();
//   auto f = expires >= ft::time_point{ ft::duration{ 1 } } && expires <= ft::now();
//
// The schema cannot tell a date from a counter (uSNChanged is 906 too): the
// member's type decides. std::int64_t members read every 906 attribute as
// the raw number; the time_point and duration below read 906 only.
//
// Sentinels:
//   ad::never          9223372036854775807, time_point::max(): accountExpires
//                      "never expires". Decodes from and encodes as
//                      9223372036854775807. As a date it is in year 30828:
//                      test for it before converting or doing arithmetic.
//                      Arithmetic on any decoded date near the top of the
//                      range can overflow too, like any std::chrono value:
//                      an untrusted lockoutTime 9223372036854775806 minus a
//                      30-minute lockoutDuration is undefined. Check
//                      ad::is_never / ad::forever first, and keep the
//                      result in range.
//   0                  decodes to tick 0 (time_point{}, 1601-01-01, never a
//                      real AD date), which sorts before every date and
//                      encodes as 0 again. What it means depends on the
//                      attribute:
//                      - accountExpires: "never expires", like ad::never.
//                        ad::is_never(t) is true for both.
//                      - lastLogon, lastLogonTimestamp, badPasswordTime:
//                        "never happened". Being before every date,
//                        `last_logon < cutoff` includes accounts that never
//                        logged on (test != time_point{} to skip them).
//                      - lockoutTime: "not currently locked out". AD writes
//                        0 when an account is unlocked, so it does not mean
//                        the account was never locked out.
//                      - pwdLastSet: equals ad::pwd_must_change (the user
//                        must change the password at the next logon).
//   ad::pwd_must_change  pwdLastSet 0 (time_point{}): written, the user must
//                      change the password at the next logon; read back,
//                      pwdLastSet 0 compares equal to it.
//   ad::pwd_set_now    pwdLastSet -1: written, AD sets pwdLastSet to now.
//   ad::forever        an interval of -9223372036854775808 ticks
//                      (duration::min()): maxPwdAge "passwords never
//                      expire", lockoutDuration "until an administrator
//                      unlocks". Negating it overflows: test for it first.
//
// Filters: a typed filter on a mapped member encodes the value
// (filters::field<&T::m>() <= t). On an untyped attribute, encode it; the
// two FILETIME traits return a plain std::string, as every value encodes
// (the string, enum and sys_seconds traits return result<std::string>):
// filters::attr("accountExpires") <= ldap::value_traits<ad::filetime_clock::time_point>::encode(t).
// AD compares the numbers, so 0 ("never") is below every date:
// "accounts that expired" is (&(accountExpires>=1)(accountExpires<=now)).
// An equality filter on ad::never encodes 9223372036854775807 only and
// misses accounts stored as 0; "never expires" takes both spellings:
// expires == ad::never || expires == ft::time_point{}, that is
// (|(accountExpires=9223372036854775807)(accountExpires=0)).
#pragma once

#include "jhetz/ldap/ad/syntax.hpp"
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
// std::chrono::clock_cast converts to and from system_clock (and so
// utc_clock, ...) through to_sys / from_sys; a zoned_time is then built
// from the sys_time it returns. Leap seconds are not counted, as in
// FILETIME and system_clock.
struct filetime_clock
{
	using rep = std::int64_t;
	using period = std::ratio_divide<std::micro, std::ratio<10>>;// 100 ns
	using duration = std::chrono::duration<rep, period>;
	using time_point = std::chrono::time_point<filetime_clock>;
	static constexpr bool is_steady = false;

	// From 1601-01-01 to 1970-01-01 (the Unix epoch): 134774 days.
	static constexpr std::chrono::seconds unix_epoch_offset{ 11'644'473'600 };

	[[nodiscard]] static auto now() noexcept -> time_point { return from_sys(std::chrono::system_clock::now()); }

	// Defined for t >= time_point::min() + unix_epoch_offset (about year
	// -27258, sys_time::min()); below, the subtraction overflows. Every
	// decoded value is in range (decode rejects dates below -1). ad::never
	// converts without overflow, to a sys_time in year 30828 that is no real
	// date: test ad::is_never (or == ad::never) before converting.
	// Converting is defined for every decoded date, but arithmetic on a date
	// near the top of the range (t + days(n), t - lockout_duration) can
	// overflow, like on any std::chrono value. The result keeps the 100 ns
	// ticks; assigning it to a system_clock::time_point may not fit (with
	// libstdc++'s nanoseconds it overflows after 2262, ad::never included),
	// so keep the ticks or floor to seconds.
	template<class D>
	[[nodiscard]] static constexpr auto to_sys(const std::chrono::time_point<filetime_clock, D> &t)
	  -> std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>
	{
		return std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>(
		  t.time_since_epoch() - unix_epoch_offset);
	}

	// Rounds down to a tick (system_clock's period is implementation-
	// defined: nanoseconds in libstdc++, microseconds in libc++, 100 ns in
	// MSVC's STL). Defined for t <= time_point::max() - unix_epoch_offset
	// (as a sys_time in ticks, year 30828: the result is then at most
	// ad::never) and t >= the lowest sys_time in ticks (about year -27258),
	// whatever D is; beyond, the result or the conversion of t to ticks
	// overflows. The mirror of to_sys' domain. Whether every
	// system_clock::time_point is in range depends on the period: yes with
	// nanoseconds (years 1677-2262), no with MSVC's 100 ns ticks or libc++'s
	// microseconds, whose time_point::max() is beyond year 30828.
	template<class D> [[nodiscard]] static constexpr auto from_sys(const std::chrono::sys_time<D> &t) -> time_point
	{
		return time_point(std::chrono::floor<duration>(t.time_since_epoch()) + unix_epoch_offset);
	}
};

inline constexpr filetime_clock::time_point never = filetime_clock::time_point::max();
inline constexpr filetime_clock::time_point pwd_must_change{ filetime_clock::duration{ 0 } };
inline constexpr filetime_clock::time_point pwd_set_now{ filetime_clock::duration{ -1 } };
inline constexpr filetime_clock::duration forever = filetime_clock::duration::min();

// accountExpires "never expires": true for both of AD's spellings, 0 (tick 0)
// and 9223372036854775807 (ad::never).
[[nodiscard]] constexpr auto is_never(filetime_clock::time_point t) noexcept -> bool
{
	return t == filetime_clock::time_point{} || t == never;
}

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// A FILETIME date: decimal ticks from 1601-01-01, decoded and encoded as
// the plain tick count: 0 is time_point{} (ad::pwd_must_change) and
// 9223372036854775807 is ad::never. Values below -1 are rejected
// (conversion_failed): AD writes no date before 1601, -1 is the
// ad::pwd_set_now command (kept so that every constant here decodes back),
// and the rejected range is where to_sys would overflow.
template<> struct value_traits<ad::filetime_clock::time_point>
{
	static constexpr std::array syntaxes{ ad::large_integer_syntax };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::filetime_clock::time_point>
	{
		auto ticks = value_traits<std::int64_t>::decode(raw);
		if (!ticks) {
			return std::unexpected(std::move(ticks.error()));
		}
		if (*ticks < -1) {
			return std::unexpected(detail::conversion_error("FILETIME date before -1", raw));
		}
		return ad::filetime_clock::time_point(ad::filetime_clock::duration(*ticks));
	}
	[[nodiscard]] static auto encode(ad::filetime_clock::time_point v) -> std::string
	{
		return std::to_string(v.time_since_epoch().count());
	}
};

// A Large Integer interval: decimal ticks, sign kept (AD writes intervals
// as negative values: maxPwdAge -36288000000000 is 42 days).
template<> struct value_traits<ad::filetime_clock::duration>
{
	static constexpr std::array syntaxes{ ad::large_integer_syntax };

	[[nodiscard]] static auto decode(std::string_view raw) -> result<ad::filetime_clock::duration>
	{
		auto ticks = value_traits<std::int64_t>::decode(raw);
		if (!ticks) {
			return std::unexpected(std::move(ticks.error()));
		}
		return ad::filetime_clock::duration(*ticks);
	}
	[[nodiscard]] static auto encode(ad::filetime_clock::duration v) -> std::string
	{
		return std::to_string(v.count());
	}
};

}// namespace jhetz::ldap
