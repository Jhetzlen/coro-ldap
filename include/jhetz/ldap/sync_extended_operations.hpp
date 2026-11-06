// The free extended operations (extended_operations.hpp) for the blocking
// facade: the same calls on a sync::connection, a sync::client or a sync
// lease, blocking the calling thread.
//
//   ldap::result<std::string> me = ldap::sync::who_am_i(c);
#pragma once

#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sync.hpp"

#include <concepts>
#include <optional>
#include <string>
#include <utility>

namespace jhetz::ldap::sync {

// ldap::extended_directory, blocking.
template<class D>
concept extended_directory = requires(D &d, extended_params x) {
	{ d.extended(std::move(x)) } -> std::same_as<result<extended_result>>;
};

template<extended_directory D> [[nodiscard]] auto who_am_i(D &d, extended_controls controls = {}) -> result<std::string>
{
	return ldap::detail::who_am_i_result(d.extended(ldap::detail::who_am_i_request(std::move(controls))));
}

template<extended_directory D>
[[nodiscard]] auto password_modify(D &d, password_modify_params request) -> result<std::optional<std::string>>
{
	auto call = ldap::detail::password_modify_request(std::move(request));
	return ldap::detail::password_modify_result(d.extended(std::move(call.request)), call.context);
}

template<extended_directory D>
[[nodiscard]] auto change_password(D &d, const dn &user, std::string old_password, std::string new_password)
  -> result<void>
{
	auto call =
	  ldap::detail::set_password_request("change password", user, std::move(old_password), std::move(new_password));
	if (!call) {
		return std::unexpected(std::move(call.error()));
	}
	return ldap::detail::set_password_result(d.extended(std::move(call->request)), call->context);
}
template<extended_directory D>
[[nodiscard]] auto reset_password(D &d, const dn &user, std::string new_password) -> result<void>
{
	auto call = ldap::detail::set_password_request("reset password", user, std::nullopt, std::move(new_password));
	if (!call) {
		return std::unexpected(std::move(call.error()));
	}
	return ldap::detail::set_password_result(d.extended(std::move(call->request)), call->context);
}

}// namespace jhetz::ldap::sync
