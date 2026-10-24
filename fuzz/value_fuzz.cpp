// libFuzzer target for the value conversions of the typed mapping
// (mapping.hpp), which read untrusted attribute values (also driven by
// value_fuzz_replay).
//
// For any input it must not crash, and for each decoder (GeneralizedTime,
// integers, bool, dn, AD FILETIME dates and intervals):
// - rejected input fails with conversion_failed;
// - accepted input encodes to text that decodes to the same value, and
//   GeneralizedTime re-encodes to the same text (encoding is canonical).
// AD FILETIME dates decode to the plain tick count (0 is tick 0, only the
// maximum is ad::never), accept what int64 accepts from -1 up and encode
// the same text; every decoded date other than ad::never clock_casts to
// system_clock and back unchanged (UBSan catches an overflow).
#include "jhetz/ldap/ad.hpp"
#include "jhetz/ldap/mapping.hpp"

#include "check.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

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
	// What decodes encodes (decode and encode take the same UTF-8, names and
	// years).
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

	round_trip<std::int64_t>(text);
	round_trip<std::uint8_t>(text);
	round_trip<bool>(text);
	round_trip<ldap::dn>(text);
	round_trip<ldap::ad::filetime_clock::time_point>(text);
	round_trip<ldap::ad::filetime_clock::duration>(text);
	filetime_checks(text);
	return 0;
}
