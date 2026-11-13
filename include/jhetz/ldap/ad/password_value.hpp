#pragma once

#include "jhetz/ldap/error.hpp"

#include <string>
#include <string_view>

namespace jhetz::ldap::ad {

// The unicodePwd value (MS-ADTS 3.1.1.3.1.5): the quoted password as
// UTF-16LE; encode_error for ill-formed UTF-8. Not wiped.
[[nodiscard]] auto password_value(std::string_view password) -> result<std::string>;

}// namespace jhetz::ldap::ad
