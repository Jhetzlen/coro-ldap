// libFuzzer target for RFC 4516 URL parsing: URLs round-trip canonically,
// printed fully encoded, and referred_request agrees.
#include "jhetz/ldap/referral.hpp"
#include "jhetz/ldap/url.hpp"

#include "check.hpp"

#include <cstdint>
#include <string>
#include <string_view>

constexpr jhetz::ldap::fuzz::checker check{ "url_fuzz" };

namespace ldap = jhetz::ldap;

namespace {

auto is_uri_char(char c) -> bool
{
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
		return true;
	}
	return std::string_view("-._~!$&'()*+,;=:@/?%[]").contains(c);
}

}// namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	auto u = ldap::url::parse(text);
	if (!u) {
		check(u.error().code == ldap::client_errc::invalid_url, "u.error().code == ldap::client_errc::invalid_url");
		check(u.error().context.starts_with("url: "), "u.error().context.starts_with(\"url: \")");
		return 0;
	}
	const auto printed = u->to_string();
	for (const char c : printed) {
		check(is_uri_char(c), "is_uri_char(c)");
	}
	auto back = ldap::url::parse(printed);
	check(back.has_value(), "back.has_value()");
	check(*back == *u, "*back == *u");
	check(back->to_string() == printed, "back->to_string() == printed");

	if (u->port()) {
		std::string prefix(ldap::to_string(u->scheme()));
		prefix += "://";
		prefix += u->authority();
		check(printed.starts_with(prefix), "printed.starts_with(prefix)");
	}
	if (u->scheme() == ldap::url_scheme::ldapi) {
		check(!u->port() && !u->host_is_ipv6(), "!u->port() && !u->host_is_ipv6()");
	}

	const bool has_dn = u->base_dn() && !u->base_dn()->empty();
	for (const auto kind : { ldap::reference_kind::referral, ldap::reference_kind::continuation_reference }) {
		const auto t = ldap::referred_request(*u, ldap::search_params{ .base = ldap::dn{} }, kind);
		const bool refused =
		  u->has_critical_extension() || (kind == ldap::reference_kind::continuation_reference && !has_dn);
		check(t.has_value() != refused, "t.has_value() != refused");
		if (t && has_dn) {
			check(t->base == *u->base_dn(), "t->base == *u->base_dn()");
		}
	}
	return 0;
}
