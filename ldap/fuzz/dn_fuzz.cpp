// libFuzzer target for RFC 4514 DN parsing (also driven by dn_fuzz_replay).
//
// For any input it must not crash, and:
// - the constexpr literal validator agrees with parse();
// - a parsed DN prints as text that parses to an equal DN and prints the
//   same again; parent() walks up in rdns().size() steps;
// - rejected input fails with invalid_dn.
#include "jhetz/ldap/dn.hpp"

#define FUZZ_TARGET "dn_fuzz"
#include "check.hpp"

#include <cstdint>
#include <string_view>

namespace ldap = jhetz::ldap;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	auto d = ldap::dn::parse(text);
	LDAP_FUZZ_CHECK(ldap::detail::is_dn(text) == d.has_value());
	if (!d) {
		LDAP_FUZZ_CHECK(d.error().code == ldap::client_errc::invalid_dn);
		return 0;
	}
	const auto printed = d->to_string();
	auto back = ldap::dn::parse(printed);
	LDAP_FUZZ_CHECK(back.has_value());
	LDAP_FUZZ_CHECK(*back == *d);
	LDAP_FUZZ_CHECK(back->to_string() == printed);

	std::size_t steps = 0;
	for (auto p = *d; !p.empty(); p = p.parent()) ++steps;
	LDAP_FUZZ_CHECK(steps == d->rdns().size());
	return 0;
}
