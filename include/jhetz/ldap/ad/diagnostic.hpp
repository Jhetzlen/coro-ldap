#pragma once

#include "jhetz/ldap/error.hpp"

#include <string_view>

namespace jhetz::ldap::ad {

// The explanation of the Win32 code starting an AD diagnosticMessage, for
// 00000005, 00000056, 0000052D and 00000775; empty otherwise.
[[nodiscard]] auto explain(const error &e) noexcept -> std::string_view;

}// namespace jhetz::ldap::ad
