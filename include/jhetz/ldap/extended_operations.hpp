// Who am I? (RFC 4532) and Password Modify (RFC 3062) as free functions over
// any source with extended(). The tasks refer to `d`, which must outlive
// them.
#pragma once

#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <concepts>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

template<class D>
concept extended_directory = requires(D &d, extended_params x) {
	{ d.extended(std::move(x)) } -> std::same_as<boost::capy::task<result<extended_result>>>;
};

namespace detail {
	// The requests and results, without the I/O.
	[[nodiscard]] auto who_am_i_request(extended_controls controls) -> extended_params;
	[[nodiscard]] auto who_am_i_result(result<extended_result> r) -> result<std::string>;

	struct password_modify_call
	{
		extended_params request;
		std::string context;
	};
	[[nodiscard]] auto password_modify_request(password_modify_params request) -> password_modify_call;
	[[nodiscard]] auto password_modify_result(result<extended_result> r, std::string_view context)
	  -> result<std::optional<std::string>>;
	// std::errc::invalid_argument on an empty new or old password.
	[[nodiscard]] auto set_password_request(std::string_view op,
	  const dn &user,
	  std::optional<std::string> old_password,
	  std::string new_password) -> result<password_modify_call>;
	[[nodiscard]] auto set_password_result(result<extended_result> r, std::string_view context) -> result<void>;
}// namespace detail

// The authorization identity of `d`'s session: "dn:<dn>", "u:<user>", or ""
// when anonymous.
template<extended_directory D>
auto who_am_i(D &d, extended_controls controls = {}) -> boost::capy::task<result<std::string>>
{
	co_return detail::who_am_i_result(co_await d.extended(detail::who_am_i_request(std::move(controls))));
}

// Password Modify (RFC 3062); returns the generated password when
// new_password was not given.
template<extended_directory D>
auto password_modify(D &d, password_modify_params request) -> boost::capy::task<result<std::optional<std::string>>>
{
	auto call = detail::password_modify_request(std::move(request));
	co_return detail::password_modify_result(co_await d.extended(std::move(call.request)), call.context);
}

// Password Modify with `user` as userIdentity (empty: the bound user):
// change_password needs the old password, reset_password does not.
template<extended_directory D>
auto change_password(D &d, dn user, std::string old_password, std::string new_password)
  -> boost::capy::task<result<void>>
{
	auto call = detail::set_password_request("change password", user, std::move(old_password), std::move(new_password));
	if (!call) {
		co_return std::unexpected(std::move(call.error()));
	}
	co_return detail::set_password_result(co_await d.extended(std::move(call->request)), call->context);
}
template<extended_directory D>
auto reset_password(D &d, dn user, std::string new_password) -> boost::capy::task<result<void>>
{
	auto call = detail::set_password_request("reset password", user, std::nullopt, std::move(new_password));
	if (!call) {
		co_return std::unexpected(std::move(call.error()));
	}
	co_return detail::set_password_result(co_await d.extended(std::move(call->request)), call->context);
}

}// namespace jhetz::ldap
