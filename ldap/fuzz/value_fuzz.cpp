// libFuzzer target for the value conversions of the typed mapping
// (mapping.hpp), which read untrusted attribute values (also driven by
// value_fuzz_replay).
//
// For any input it must not crash, and for each decoder (GeneralizedTime,
// integers, bool, dn):
// - rejected input fails with conversion_failed;
// - accepted input encodes to text that decodes to the same value, and
//   GeneralizedTime re-encodes to the same text (encoding is canonical).
#include "jhetz/ldap/mapping.hpp"

#define FUZZ_TARGET "value_fuzz"
#include "check.hpp"

#include <cstdint>
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
	return 0;
}
