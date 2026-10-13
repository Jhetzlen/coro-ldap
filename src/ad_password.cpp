#include "jhetz/ldap/connection.hpp"

#include <openssl/crypto.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

result<std::string> ad_password_value(std::string_view password)
{
	constexpr std::string_view context = "Active Directory password value";
	if (password.size() > static_cast<std::size_t>(INT32_MAX / 2) - 2)
		return fail(client_errc::encode_error, std::string(context) + ": the password is too long");

	// UTF-8 -> UTF-16 (ICU's native order). u_strFromUTF8 refuses ill-formed
	// UTF-8: overlong forms, surrogates, code points above U+10FFFF,
	// truncated sequences.
	UErrorCode status = U_ZERO_ERROR;
	int32_t n = 0;
	u_strFromUTF8(nullptr, 0, &n, password.data(), static_cast<int32_t>(password.size()), &status);
	if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status))
		return fail(client_errc::encode_error, std::string(context) + ": the password is not valid UTF-8");
	std::vector<UChar> units(static_cast<std::size_t>(n));
	status = U_ZERO_ERROR;
	if (n != 0) u_strFromUTF8(units.data(), n, &n, password.data(), static_cast<int32_t>(password.size()), &status);
	if (U_FAILURE(status)) {
		OPENSSL_cleanse(units.data(), units.size() * sizeof(UChar));
		return fail(client_errc::encode_error, std::string(context) + ": the password is not valid UTF-8");
	}

	// '"' password '"', each UTF-16 code unit little-endian.
	std::string out;
	out.reserve((units.size() + 2) * 2);
	const auto put = [&out](char16_t u) {
		out.push_back(static_cast<char>(u & 0xFF));
		out.push_back(static_cast<char>(u >> 8));
	};
	put(u'"');
	for (const UChar u : units) put(static_cast<char16_t>(u));
	put(u'"');
	OPENSSL_cleanse(units.data(), units.size() * sizeof(UChar));
	return out;
}

}// namespace jhetz::ldap
