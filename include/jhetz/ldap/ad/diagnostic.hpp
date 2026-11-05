// Active Directory's diagnosticMessage: the Win32 error code it starts with,
// explained.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <string_view>

namespace jhetz::ldap::ad {

// The explanation of the Win32 error code in eight hex digits and a colon
// that starts an AD diagnosticMessage ("0000052D: Constraint violation -
// ..."), for the codes a password change commonly fails with:
// 00000005 (ERROR_ACCESS_DENIED), 00000056 (ERROR_INVALID_PASSWORD),
// 0000052D (ERROR_PASSWORD_RESTRICTION) and 00000775
// (ERROR_ACCOUNT_LOCKED_OUT). Empty for any other code or diagnostic. A
// view of static text.
[[nodiscard]] auto explain(const error &e) noexcept -> std::string_view;

}// namespace jhetz::ldap::ad
