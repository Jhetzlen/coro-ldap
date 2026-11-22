// Internal: UTS #46 ToASCII, shared by jhetz::ldap_net and jhetz::ldap_ad.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace jhetz::ldap::detail {

// `name` (UTF-8) as A-labels, by uidna_nameToASCII_UTF8 with `options`
// (UIDNA_*): internal_error if ICU fails, string_prep_failed if `name` is
// refused or its ASCII form is empty or longer than `max_length`.
[[nodiscard]] auto idna_to_ascii(std::string_view name, std::uint32_t options, std::size_t max_length)
  -> result<std::string>;

}// namespace jhetz::ldap::detail
