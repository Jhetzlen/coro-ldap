#include "host_name.hpp"

#include "../icu_util.hpp"
#include "jhetz/ldap/attribute.hpp"

#include <unicode/uidna.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::net::detail {
namespace {

	struct idna_closer
	{
		void operator()(UIDNA *p) const noexcept { uidna_close(p); }
	};

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

	auto to_ascii(std::string_view name) -> std::optional<std::string>
	{
		if (name.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
			return std::nullopt;
		}
		UErrorCode status = U_ZERO_ERROR;
		const std::unique_ptr<UIDNA, idna_closer> idna(uidna_openUTS46(idna_options, &status));
		if (ldap::detail::icu_failed(status)) {
			return std::nullopt;
		}
		std::string out(max_ascii_name + 1, '\0');
		UIDNAInfo info = UIDNA_INFO_INITIALIZER;
		const std::int32_t length = uidna_nameToASCII_UTF8(idna.get(),
		  name.data(),
		  static_cast<std::int32_t>(name.size()),
		  out.data(),
		  static_cast<std::int32_t>(out.size()),
		  &info,
		  &status);
		if (ldap::detail::icu_failed(status) || info.errors != 0 || length <= 0
			|| std::cmp_greater(length, max_ascii_name)) {
			return std::nullopt;
		}
		out.resize(static_cast<std::size_t>(length));
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
	auto ascii = to_ascii(host);
	if (!ascii) {
		return std::nullopt;
	}
	return lowered(*ascii);
}

}// namespace jhetz::ldap::net::detail
