// libFuzzer target for RFC 4514 DN parsing (also driven by dn_fuzz_replay).
//
// For any input it must not crash, and:
// - the constexpr literal validator agrees with parse();
// - a parsed DN prints as text that parses to an equal DN and prints the
//   same again; parent() walks up in rdns().size() steps;
// - rdn::parse() accepts exactly the one-RDN DNs, and each RDN of a DN prints
//   as text that parses back to it;
// - child() rebuilds the DN from its parts: parent().child(first RDN), and
//   the empty DN's child(dn);
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
	auto r = ldap::rdn::parse(text);
	LDAP_FUZZ_CHECK(ldap::detail::is_rdn(text) == r.has_value());
	LDAP_FUZZ_CHECK(r.has_value() == (d.has_value() && d->rdns().size() == 1));
	if (!r) LDAP_FUZZ_CHECK(r.error().code == ldap::client_errc::invalid_dn);
	if (!d) {
		LDAP_FUZZ_CHECK(d.error().code == ldap::client_errc::invalid_dn);
		return 0;
	}
	if (r) LDAP_FUZZ_CHECK(*r == d->rdns().front());
	const auto printed = d->to_string();
	auto back = ldap::dn::parse(printed);
	LDAP_FUZZ_CHECK(back.has_value());
	LDAP_FUZZ_CHECK(*back == *d);
	LDAP_FUZZ_CHECK(back->to_string() == printed);

	std::size_t steps = 0;
	for (auto p = *d; !p.empty(); p = p.parent()) ++steps;
	LDAP_FUZZ_CHECK(steps == d->rdns().size());

	for (const auto &part : d->rdns()) {
		auto again = ldap::rdn::parse(part.to_string());
		LDAP_FUZZ_CHECK(again.has_value());
		LDAP_FUZZ_CHECK(*again == part);
	}
	if (!d->empty()) LDAP_FUZZ_CHECK(d->parent().child(d->rdns().front()) == *d);
	LDAP_FUZZ_CHECK(ldap::dn{}.child(*d) == *d);
	LDAP_FUZZ_CHECK(d->child(ldap::dn{}) == *d);
	return 0;
}
