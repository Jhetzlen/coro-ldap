// Blocking counterparts of the ldap::ad operations, run with sync::run.
#pragma once

#include "jhetz/ldap/ad/dirsync.hpp"
#include "jhetz/ldap/ad/password.hpp"
#include "jhetz/ldap/ad/ranged_values.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/sync.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::ad {

template<sync::directory D>
[[nodiscard]] auto change_password(D &d, dn user, std::string_view old_password, std::string_view new_password)
  -> result<void>
{
	return sync::run(d, [&](auto &a) { return ad::change_password(a, std::move(user), old_password, new_password); });
}
template<sync::directory D>
[[nodiscard]] auto reset_password(D &d, dn user, std::string_view new_password) -> result<void>
{
	return sync::run(d, [&](auto &a) { return ad::reset_password(a, std::move(user), new_password); });
}

// Values on the default resource.
template<sync::directory D>
[[nodiscard]] auto read_all_values(D &d, dn object, std::string attribute, range_options options = {})
  -> result<string_list>
{
	return sync::run(
	  d, [&](auto &a) { return ad::read_all_values(a, std::move(object), std::move(attribute), options); });
}

// Entries on the default resource.
template<sync::directory D>
[[nodiscard]] auto dirsync(D &d,
  search_params request,
  dirsync_request options = {},
  std::size_t max_rounds = dirsync_default_max_rounds) -> result<dirsync_result>
{
	return sync::run(d, [&](auto &a) { return ad::dirsync(a, std::move(request), std::move(options), max_rounds); });
}

}// namespace jhetz::ldap::ad
