// The free extended operations for the blocking facades, run with
// sync::run.
#pragma once

#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sync.hpp"

#include <optional>
#include <string>
#include <utility>

namespace jhetz::ldap::sync {

template<directory D> [[nodiscard]] auto who_am_i(D &d, extended_controls controls = {}) -> result<std::string>
{
	return sync::run(d, [&](auto &a) { return ldap::who_am_i(a, std::move(controls)); });
}

template<directory D>
[[nodiscard]] auto password_modify(D &d, password_modify_params request) -> result<std::optional<std::string>>
{
	return sync::run(d, [&](auto &a) { return ldap::password_modify(a, std::move(request)); });
}

template<directory D>
[[nodiscard]] auto change_password(D &d, const dn &user, std::string old_password, std::string new_password)
  -> result<void>
{
	return sync::run(
	  d, [&](auto &a) { return ldap::change_password(a, user, std::move(old_password), std::move(new_password)); });
}
template<directory D> [[nodiscard]] auto reset_password(D &d, const dn &user, std::string new_password) -> result<void>
{
	return sync::run(d, [&](auto &a) { return ldap::reset_password(a, user, std::move(new_password)); });
}

}// namespace jhetz::ldap::sync
