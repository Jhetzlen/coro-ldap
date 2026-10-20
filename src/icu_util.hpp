// Internal: ICU helpers shared by the translation units that call ICU.
#pragma once

#include <unicode/utypes.h>

namespace jhetz::ldap::detail {

// ICU's U_FAILURE as a bool (it yields UBool, an integer type).
constexpr auto icu_failed(UErrorCode status) noexcept -> bool { return U_FAILURE(status) != 0; }

}// namespace jhetz::ldap::detail
