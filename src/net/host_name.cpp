#include "host_name.hpp"

#include "../idna_util.hpp"
#include "jhetz/ldap/attribute.hpp"

#include <unicode/uidna.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace jhetz::ldap::net::detail {
namespace {

	// A DNS name is at most 253 octets in text form (RFC 1035 section 2.3.4);
	// the ASCII form of a longer one is not a usable host name either.
	constexpr std::size_t max_ascii_name = 253;

	constexpr unsigned char first_non_ascii = 0x80;

	// RFC 4513 section 3.1.3.1: ToASCII with UseSTD3ASCIIRules, transitional.
	constexpr auto idna_options = static_cast<std::uint32_t>(UIDNA_USE_STD3_RULES)
								  | static_cast<std::uint32_t>(UIDNA_CHECK_BIDI)
								  | static_cast<std::uint32_t>(UIDNA_CHECK_CONTEXTJ);

	auto lowered(std::string_view s) -> std::string
	{
		std::string out(s);
		std::ranges::transform(out, out.begin(), ldap::detail::ascii_lower);
		return out;
	}

}// namespace

auto is_ascii(std::string_view s) noexcept -> bool
{
	return std::ranges::all_of(s, [](char c) { return static_cast<unsigned char>(c) < first_non_ascii; });
}

auto ascii_host_name(std::string_view host) -> std::optional<std::string>
{
	if (host.ends_with('.')) {
		host.remove_suffix(1);
	}
	if (is_ascii(host)) {
		return lowered(host);
	}
	auto ascii = ldap::detail::idna_to_ascii(host, idna_options, max_ascii_name);
	if (!ascii) {
		return std::nullopt;
	}
	return lowered(*ascii);
}

}// namespace jhetz::ldap::net::detail
