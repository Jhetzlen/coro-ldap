// Active Directory's Large Integer syntax (1.2.840.113556.1.4.906) as
// std::chrono types: dates as FILETIME, a signed 64-bit count of 100 ns
// ticks since 1601-01-01 00:00:00 UTC in decimal (accountExpires,
// pwdLastSet, lastLogonTimestamp, lastLogon, badPasswordTime, lockoutTime),
// intervals as negative tick counts (maxPwdAge, minPwdAge, lockoutDuration,
// lockOutObservationWindow).
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
//   // Expired accounts: 0 ("never expires") is below every date, ">= 1" leaves it out.
//   using ft = ldap::ad::filetime_clock;
//   auto expires = ldap::filters::field<&ad_user::account_expires>();
//   auto f = expires >= ft::time_point{ ft::duration{ 1 } } && expires <= ft::now();
//
// The member's type decides how a 906 attribute reads (uSNChanged is 906
// too): std::int64_t reads any 906 attribute as the raw number; the
// time_point and duration below read 906 only.
//
// Sentinels:
//   ad::never          9223372036854775807 (time_point::max()): accountExpires
//                      "never expires", year 30828 as a date. Test for it
//                      (ad::is_never) before converting or doing arithmetic;
//                      arithmetic near the top of the range can overflow.
//   0                  tick 0 (time_point{}), before every date. accountExpires:
//                      "never expires" (ad::is_never is true). lastLogon,
//                      lastLogonTimestamp, badPasswordTime: "never happened"
//                      (`last_logon < cutoff` includes it). lockoutTime: not
//                      currently locked out. pwdLastSet: ad::pwd_must_change.
//   ad::pwd_must_change  pwdLastSet 0: the user must change the password at
//                      the next logon.
//   ad::pwd_set_now    pwdLastSet -1: written, AD sets pwdLastSet to now.
//   ad::forever        -9223372036854775808 ticks (duration::min()): maxPwdAge
//                      "never expire", lockoutDuration "until an
//                      administrator unlocks". Negating it overflows.
//
// Filters: a typed filter on a mapped member encodes the value; on an
// untyped attribute use the trait, which returns a plain std::string:
// filters::attr("accountExpires") <= ldap::value_traits<ad::filetime_clock::time_point>::encode(t).
// Equality on ad::never misses accounts stored as 0: "never expires" is
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

// A C++20 Clock for FILETIME: 100 ns ticks since 1601-01-01 00:00:00 UTC
// (not std::chrono::file_clock, whose epoch and period are
// implementation-defined). clock_cast converts to and from system_clock
// through to_sys / from_sys. Leap seconds are not counted.
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
	// -27258), so for every decoded value. ad::never converts to year 30828:
	// test ad::is_never first. Arithmetic near the top of the range can
	// overflow. The result keeps 100 ns ticks and may not fit a
	// system_clock::time_point (libstdc++'s nanoseconds overflow after 2262):
	// keep the ticks or floor to seconds.
	template<class D>
	[[nodiscard]] static constexpr auto to_sys(const std::chrono::time_point<filetime_clock, D> &t)
	  -> std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>
	{
		return std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>(
		  t.time_since_epoch() - unix_epoch_offset);
	}

	// Rounds down to a tick. Defined for t from about year -27258 to
	// time_point::max() - unix_epoch_offset (year 30828, at most ad::never);
	// beyond, it overflows. Not every system_clock::time_point is in range
	// with libc++'s microseconds or MSVC's 100 ns ticks; all are with
	// nanoseconds.
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
