// Standard extended operations as free functions over any source with
// extended() (an ldap::connection, an ldap::client, a shared lease's
// ldap::shared_connection): Who am I? (RFC 4532) and Password Modify
// (RFC 3062), with change_password / reset_password over it.
//
//   ldap::result<std::string> me = co_await ldap::who_am_i(conn);
//   co_await ldap::reset_password(pool, ldap::dn{"uid=jdoe,ou=people,dc=example,dc=org"}, new_password);
//
// Password memory is not wiped, here or in simple binds: the password
// passes through std::string copies (the arguments, the request's values,
// the encoded PDU in the connection's buffers) that the library cannot
// wipe all of. Only sasl_scram_sha256 and sasl_ntlm wipe what they hold.
// Passwords never appear in error contexts.
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

// A source of extended operations, with connection's extended().
template<class D>
concept extended_directory = requires(D &d, extended_params x) {
	{ d.extended(std::move(x)) } -> std::same_as<boost::capy::task<result<extended_result>>>;
};

namespace detail {
	// The requests and results, without the I/O: shared by the async forms
	// below and the blocking ones (sync_extended_operations.hpp).
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
	// change_password (`old_password` set) and reset_password; fails with
	// std::errc::invalid_argument on an empty new or old password.
	[[nodiscard]] auto set_password_request(std::string_view op,
	  const dn &user,
	  std::optional<std::string> old_password,
	  std::string new_password) -> result<password_modify_call>;
	[[nodiscard]] auto set_password_result(result<extended_result> r, std::string_view context) -> result<void>;
}// namespace detail

// The authorization identity of `d`'s session (RFC 4532): "dn:<dn>",
// "u:<user>", or "" when anonymous. An authzId that is not well-formed
// UTF-8 (an LDAPString, RFC 4511 section 4.1.2) fails with
// conversion_failed, as a mapped string value does. On an ldap::client,
// the session of the pooled connection it ran on.
template<extended_directory D>
auto who_am_i(D &d, extended_controls controls = {}) -> boost::capy::task<result<std::string>>
{
	co_return detail::who_am_i_result(co_await d.extended(detail::who_am_i_request(std::move(controls))));
}

// Changes a password (RFC 3062). Returns the password the server
// generated (genPasswd) when new_password was not given, else nullopt.
// Errors have the context "password modify <user>".
template<extended_directory D>
auto password_modify(D &d, password_modify_params request) -> boost::capy::task<result<std::optional<std::string>>>
{
	auto call = detail::password_modify_request(std::move(request));
	co_return detail::password_modify_result(co_await d.extended(std::move(call.request)), call.context);
}

// Password changes with Password Modify, `user` as userIdentity (left out
// if `user` is empty: the bound user). change_password is a user's own
// change, which needs the old password; reset_password is an
// administrator's, without it. Both need a new password (only
// password_modify() has the server generate one) and the old one too for
// a change, else they fail with std::errc::invalid_argument before
// anything is sent. Active Directory has no RFC 3062: see
// ad::change_password and ad::reset_password (ad/password.hpp).
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
