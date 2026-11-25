// libFuzzer target for the typed mapping's value conversions: rejected
// input is conversion_failed, accepted input round-trips.
#include "jhetz/ldap/ad/filetime.hpp"
#include "jhetz/ldap/ad/guid.hpp"
#include "jhetz/ldap/ad/sid.hpp"
#include "jhetz/ldap/ad/user_account_control.hpp"
#include "jhetz/ldap/mapping.hpp"

#include "check.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <memory_resource>
#include <string>
#include <string_view>
#include <utility>

constexpr jhetz::ldap::fuzz::checker check{ "value_fuzz" };

namespace ldap = jhetz::ldap;

namespace {

template<class T> void round_trip(std::string_view text)
{
	auto v = ldap::value_traits<T>::decode(text);
	if (!v) {
		check(v.error().code == ldap::client_errc::conversion_failed,
		  "v.error().code == ldap::client_errc::conversion_failed");
		return;
	}
	// What decodes encodes, except sys_seconds.
	const auto encoded = ldap::detail::encode_value(*v);
	check(encoded.has_value(), "encoded.has_value()");
	auto again = ldap::value_traits<T>::decode(*encoded);
	check(again.has_value(), "again.has_value()");
	check(*again == *v, "*again == *v");
}

void filetime_checks(std::string_view text)
{
	namespace ad = ldap::ad;
	const auto t = ldap::value_traits<ad::filetime_clock::time_point>::decode(text);
	const auto n = ldap::value_traits<std::int64_t>::decode(text);
	check(t.has_value() == (n.has_value() && *n >= -1), "t.has_value() == (n.has_value() && *n >= -1)");
	if (!t) {
		check(t.error().code == ldap::client_errc::conversion_failed,
		  "t.error().code == ldap::client_errc::conversion_failed");
		return;
	}
	check(t->time_since_epoch().count() == *n, "t->time_since_epoch().count() == *n");
	check(ldap::value_traits<ad::filetime_clock::time_point>::encode(*t) == std::to_string(*n),
	  "ldap::value_traits<ad::filetime_clock::time_point>::encode(*t) == std::to_string(*n)");
	check(ad::is_never(*t) == (*n == 0 || *n == std::numeric_limits<std::int64_t>::max()),
	  "ad::is_never(*t) == (*n == 0 || *n == std::numeric_limits<std::int64_t>::max())");
	if (*t == ad::never) {
		return;
	}
	const auto sys = std::chrono::clock_cast<std::chrono::system_clock>(*t);
	check(
	  std::chrono::clock_cast<ad::filetime_clock>(sys) == *t, "std::chrono::clock_cast<ad::filetime_clock>(sys) == *t");
}

template<class T> void binary_and_text_checks(std::string_view text)
{
	if (auto v = T::from_binary(text)) {
		check(v->to_binary() == text, "v->to_binary() == text");
		auto back = T::parse(v->to_string());
		check(back.has_value() && *back == *v, "back.has_value() && *back == *v");
	} else {
		check(v.error().code == ldap::client_errc::conversion_failed,
		  "v.error().code == ldap::client_errc::conversion_failed");
	}
	if (auto v = T::parse(text)) {
		auto back = T::parse(v->to_string());
		check(back.has_value() && *back == *v, "back.has_value() && *back == *v");
		auto raw = T::from_binary(v->to_binary());
		check(raw.has_value() && *raw == *v, "raw.has_value() && *raw == *v");
	} else {
		check(v.error().code == ldap::client_errc::conversion_failed,
		  "v.error().code == ldap::client_errc::conversion_failed");
	}
}

void user_account_control_checks(std::string_view text)
{
	const auto u = ldap::value_traits<ldap::ad::user_account_control>::decode(text);
	const auto n = ldap::value_traits<std::int64_t>::decode(text);
	const bool in_range = n.has_value() && std::cmp_greater_equal(*n, std::numeric_limits<std::int32_t>::min())
						  && std::cmp_less_equal(*n, std::numeric_limits<std::uint32_t>::max());
	check(u.has_value() == in_range, "u.has_value() == in_range");
	if (u) {
		check(std::to_underlying(*u) == static_cast<std::uint32_t>(*n),
		  "std::to_underlying(*u) == static_cast<std::uint32_t>(*n)");
	}
}

}// namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);

	auto t = ldap::parse_generalized_time(text);
	if (!t) {
		check(t.error().code == ldap::client_errc::conversion_failed,
		  "t.error().code == ldap::client_errc::conversion_failed");
	} else if (auto s = ldap::format_generalized_time(*t)) {
		// Offsets can move a time out of years 0000-9999; inside, it round-trips.
		auto back = ldap::parse_generalized_time(*s);
		check(back.has_value() && *back == *t, "back.has_value() && *back == *t");
		check(ldap::format_generalized_time(*back) == *s, "ldap::format_generalized_time(*back) == *s");
	} else {
		check(s.error().code == ldap::client_errc::encode_error, "s.error().code == ldap::client_errc::encode_error");
	}

	round_trip<std::string>(text);
	round_trip<std::pmr::string>(text);
	round_trip<std::int64_t>(text);
	round_trip<std::uint8_t>(text);
	round_trip<bool>(text);
	round_trip<ldap::dn>(text);
	round_trip<ldap::ad::filetime_clock::time_point>(text);
	round_trip<ldap::ad::filetime_clock::duration>(text);
	filetime_checks(text);
	round_trip<ldap::ad::sid>(text);
	round_trip<ldap::ad::guid>(text);
	round_trip<ldap::ad::user_account_control>(text);
	binary_and_text_checks<ldap::ad::sid>(text);
	binary_and_text_checks<ldap::ad::guid>(text);
	user_account_control_checks(text);
	return 0;
}
