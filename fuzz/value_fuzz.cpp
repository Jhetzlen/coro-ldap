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
// maximum is ad::never), so they accept what int64 accepts and encode the
// same text.
#include "jhetz/ldap/ad.hpp"
#include "jhetz/ldap/mapping.hpp"

#define FUZZ_TARGET "value_fuzz"
#include "check.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;

namespace {

template<class T> void round_trip(std::string_view text)
{
	auto v = ldap::value_traits<T>::decode(text);
	if (!v) {
		LDAP_FUZZ_CHECK(v.error().code == ldap::client_errc::conversion_failed);
		return;
	}
	const std::string encoded = ldap::value_traits<T>::encode(*v);
	auto again = ldap::value_traits<T>::decode(encoded);
	LDAP_FUZZ_CHECK(again.has_value());
	LDAP_FUZZ_CHECK(*again == *v);
}

void filetime_checks(std::string_view text)
{
	namespace ad = ldap::ad;
	const auto t = ldap::value_traits<ad::filetime_clock::time_point>::decode(text);
	const auto n = ldap::value_traits<std::int64_t>::decode(text);
	LDAP_FUZZ_CHECK(t.has_value() == n.has_value());
	if (!t) return;
	LDAP_FUZZ_CHECK(t->time_since_epoch().count() == *n);
	LDAP_FUZZ_CHECK(ldap::value_traits<ad::filetime_clock::time_point>::encode(*t) == std::to_string(*n));
	LDAP_FUZZ_CHECK(ad::is_never(*t) == (*n == 0 || *n == std::numeric_limits<std::int64_t>::max()));
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);

	auto t = ldap::parse_generalized_time(text);
	if (!t) {
		LDAP_FUZZ_CHECK(t.error().code == ldap::client_errc::conversion_failed);
	} else if (auto s = ldap::format_generalized_time(*t)) {
		// Offsets can move a time out of years 0000-9999; inside, it round-trips.
		auto back = ldap::parse_generalized_time(*s);
		LDAP_FUZZ_CHECK(back.has_value() && *back == *t);
		LDAP_FUZZ_CHECK(ldap::format_generalized_time(*back) == *s);
	} else {
		LDAP_FUZZ_CHECK(s.error().code == ldap::client_errc::encode_error);
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
