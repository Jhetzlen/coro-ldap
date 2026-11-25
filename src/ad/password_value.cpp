#include "jhetz/ldap/ad/password_value.hpp"

#include "../icu_util.hpp"
#include "../scope_util.hpp"
#include "../wipe_util.hpp"

#include <unicode/utypes.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::ad {

using detail::icu_failed;

auto password_value(std::string_view password) -> result<std::string>
{
	constexpr std::string_view context = "Active Directory password value";
	if (password.size() > static_cast<std::size_t>(INT32_MAX / 2) - 2) {
		return fail(client_errc::encode_error, std::string(context) + ": the password is too long");
	}

	std::vector<UChar> units;
	const detail::scope_exit wipe{ [&units] noexcept { detail::wipe_vector(units); } };
	const UErrorCode status = detail::to_utf16(password, units);
	if (detail::is_invalid_utf8(status)) {
		return fail(client_errc::encode_error, std::string(context) + ": the password is not valid UTF-8");
	}
	if (icu_failed(status)) {
		return fail(client_errc::internal_error,
		  std::string(context) + ": UTF-16 conversion failed (ICU " + u_errorName(status) + ")");
	}

	// '"' password '"', each UTF-16 code unit little-endian.
	std::string out;
	out.reserve((units.size() + 2) * 2);
	const auto put = [&out](char16_t u) {
		out.push_back(static_cast<char>(u & 0xFF));
		out.push_back(static_cast<char>(u >> 8));
	};
	put(u'"');
	for (const UChar u : units) {
		put(static_cast<char16_t>(u));
	}
	put(u'"');
	return out;
}

}// namespace jhetz::ldap::ad
