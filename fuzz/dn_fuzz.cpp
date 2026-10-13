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

#include "check.hpp"

#include <cstdint>
#include <string_view>

constexpr jhetz::ldap::fuzz::checker check{ "dn_fuzz" };

namespace ldap = jhetz::ldap;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	auto d = ldap::dn::parse(text);
	check(ldap::detail::is_dn(text) == d.has_value(), "ldap::detail::is_dn(text) == d.has_value()");
	auto r = ldap::rdn::parse(text);
	check(ldap::detail::is_rdn(text) == r.has_value(), "ldap::detail::is_rdn(text) == r.has_value()");
	check(r.has_value() == (d.has_value() && d->rdns().size() == 1),
	  "r.has_value() == (d.has_value() && d->rdns().size() == 1)");
	if (!r) check(r.error().code == ldap::client_errc::invalid_dn, "r.error().code == ldap::client_errc::invalid_dn");
	if (!d) {
		check(d.error().code == ldap::client_errc::invalid_dn, "d.error().code == ldap::client_errc::invalid_dn");
		return 0;
	}
	if (r) check(*r == d->rdns().front(), "*r == d->rdns().front()");
	const auto printed = d->to_string();
	auto back = ldap::dn::parse(printed);
	check(back.has_value(), "back.has_value()");
	check(*back == *d, "*back == *d");
	check(back->to_string() == printed, "back->to_string() == printed");

	std::size_t steps = 0;
	for (auto p = *d; !p.empty(); p = p.parent()) ++steps;
	check(steps == d->rdns().size(), "steps == d->rdns().size()");

	for (const auto &part : d->rdns()) {
		auto again = ldap::rdn::parse(part.to_string());
		check(again.has_value(), "again.has_value()");
		check(*again == part, "*again == part");
	}
	if (!d->empty()) check(d->parent().child(d->rdns().front()) == *d, "d->parent().child(d->rdns().front()) == *d");
	check(ldap::dn{}.child(*d) == *d, "ldap::dn{}.child(*d) == *d");
	check(d->child(ldap::dn{}) == *d, "d->child(ldap::dn{}) == *d");
	return 0;
}
