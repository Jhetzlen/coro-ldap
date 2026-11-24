#include "jhetz/ldap/ad/diagnostic.hpp"

#include <charconv>
#include <cstddef>
#include <string_view>
#include <system_error>

namespace jhetz::ldap::ad {

namespace {

	enum class win32_error : unsigned {
		access_denied = 0x5,// ERROR_ACCESS_DENIED
		invalid_password = 0x56,// ERROR_INVALID_PASSWORD
		password_restriction = 0x52D,// ERROR_PASSWORD_RESTRICTION
		account_locked_out = 0x775,// ERROR_ACCOUNT_LOCKED_OUT
	};

}// namespace

auto explain(const error &e) noexcept -> std::string_view
{
	const std::string_view diagnostic = e.diagnostic_message;
	constexpr std::size_t code_digits = 8;
	if (diagnostic.size() <= code_digits || diagnostic[code_digits] != ':') {
		return {};
	}
	unsigned code = 0;
	// NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): bounded to 8 chars, no terminator read
	const auto [end, ec] = std::from_chars(diagnostic.data(), diagnostic.data() + code_digits, code, 16);
	if (ec != std::errc{} || end != diagnostic.data() + code_digits) {
		return {};
	}
	switch (static_cast<win32_error>(code)) {
	case win32_error::access_denied:
		return "not allowed to set this user's password";
	case win32_error::invalid_password:
		return "the old password is wrong";
	case win32_error::password_restriction:
		return "the new password does not meet the password policy (length, complexity, history or minimum age)";
	case win32_error::account_locked_out:
		return "the account is locked out";
	default:
		return {};
	}
}

}// namespace jhetz::ldap::ad
