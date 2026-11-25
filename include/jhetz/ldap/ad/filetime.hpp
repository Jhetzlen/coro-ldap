// Active Directory's Large Integer syntax (1.2.840.113556.1.4.906) as
// std::chrono types: FILETIME dates and negative tick intervals, with AD's
// sentinels (docs/API.md, "jhetz/ldap/ad/filetime.hpp").
#pragma once

#include "jhetz/ldap/ad/syntax.hpp"
#include "jhetz/ldap/mapping.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <ratio>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace jhetz::ldap::ad {

// A C++20 Clock for FILETIME: 100 ns ticks since 1601-01-01 00:00:00 UTC,
// leap seconds not counted.
struct filetime_clock
{
	using rep = std::int64_t;
	using period = std::ratio_divide<std::micro, std::ratio<10>>;// 100 ns
	using duration = std::chrono::duration<rep, period>;
	using time_point = std::chrono::time_point<filetime_clock>;
	static constexpr bool is_steady = false;

	// From 1601-01-01 to 1970-01-01: 134774 days.
	static constexpr std::chrono::seconds unix_epoch_offset{ 11'644'473'600 };

	[[nodiscard]] static auto now() noexcept -> time_point { return from_sys(std::chrono::system_clock::now()); }

	// Defined for every decoded value; test ad::is_never first.
	template<class D>
	[[nodiscard]] static constexpr auto to_sys(const std::chrono::time_point<filetime_clock, D> &t)
	  -> std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>
	{
		return std::chrono::sys_time<std::common_type_t<D, std::chrono::seconds>>(
		  t.time_since_epoch() - unix_epoch_offset);
	}

	// Rounds down to a tick; overflows past year 30828.
	template<class D> [[nodiscard]] static constexpr auto from_sys(const std::chrono::sys_time<D> &t) -> time_point
	{
		return time_point(std::chrono::floor<duration>(t.time_since_epoch()) + unix_epoch_offset);
	}
};

inline constexpr filetime_clock::time_point never = filetime_clock::time_point::max();
inline constexpr filetime_clock::time_point pwd_must_change{ filetime_clock::duration{ 0 } };
inline constexpr filetime_clock::time_point pwd_set_now{ filetime_clock::duration{ -1 } };
inline constexpr filetime_clock::duration forever = filetime_clock::duration::min();

// accountExpires "never expires": 0 or ad::never.
[[nodiscard]] constexpr auto is_never(filetime_clock::time_point t) noexcept -> bool
{
	return t == filetime_clock::time_point{} || t == never;
}

}// namespace jhetz::ldap::ad

namespace jhetz::ldap {

// Decimal ticks; values below -1 are conversion_failed.
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

// Decimal ticks, sign kept (AD's intervals are negative).
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
