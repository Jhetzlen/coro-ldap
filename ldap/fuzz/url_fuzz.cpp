// libFuzzer target for RFC 4516 URL parsing (also driven by url_fuzz_replay).
//
// For any input it must not crash, and:
// - rejected input fails with invalid_url and a "url: " context;
// - an accepted URL prints as text that parses to an equal URL and prints
//   the same again (to_string is canonical);
// - the printed text contains no byte outside RFC 3986 (no space, control,
//   non-ASCII, '#', '"', '\\', ...): it is always fully encoded;
// - authority() is a prefix of what follows "://" when the port is explicit.
#include "jhetz/ldap/url.hpp"

#define FUZZ_TARGET "url_fuzz"
#include "check.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;

namespace {

bool is_uri_char(char c)
{
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return true;
	return std::string_view("-._~!$&'()*+,;=:@/?%[]").find(c) != std::string_view::npos;
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const std::string_view text(reinterpret_cast<const char *>(data), size);
	auto u = ldap::url::parse(text);
	if (!u) {
		LDAP_FUZZ_CHECK(u.error().code == ldap::client_errc::invalid_url);
		LDAP_FUZZ_CHECK(u.error().context.starts_with("url: "));
		return 0;
	}
	const auto printed = u->to_string();
	for (char c : printed) LDAP_FUZZ_CHECK(is_uri_char(c));
	auto back = ldap::url::parse(printed);
	LDAP_FUZZ_CHECK(back.has_value());
	LDAP_FUZZ_CHECK(*back == *u);
	LDAP_FUZZ_CHECK(back->to_string() == printed);

	if (u->port()) {
		std::string prefix(ldap::to_string(u->scheme()));
		prefix += "://";
		prefix += u->authority();
		LDAP_FUZZ_CHECK(printed.starts_with(prefix));
	}
	if (u->scheme() == ldap::url_scheme::ldapi) LDAP_FUZZ_CHECK(!u->port() && !u->host_is_ipv6());
	return 0;
}
