// The unicodePwd value Active Directory sets passwords with.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <string>
#include <string_view>

namespace jhetz::ldap::ad {

// The unicodePwd value (MS-ADTS 3.1.1.3.1.5): the password in double
// quotes, encoded UTF-16LE, characters outside the BMP as surrogate pairs.
// `password` is UTF-8; ill-formed UTF-8 fails with
// client_errc::encode_error, any other ICU failure (e.g. out of memory)
// with client_errc::internal_error (the context never quotes the
// password). For a ModifyRequest built by hand: replace unicodePwd with it
// to reset a password, or delete the old value and add the new one in one
// modify to change it (ad::change_password and ad::reset_password do so).
// Neither the result nor the scratch buffers are wiped.
[[nodiscard]] auto password_value(std::string_view password) -> result<std::string>;

}// namespace jhetz::ldap::ad
