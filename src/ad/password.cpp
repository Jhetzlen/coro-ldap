#include "jhetz/ldap/ad/password.hpp"

#include "jhetz/ldap/ad/diagnostic.hpp"
#include "jhetz/ldap/ad/password_value.hpp"
#include "jhetz/ldap/operations.hpp"

#include "../scope_util.hpp"
#include "../wipe_util.hpp"

#include <boost/capy/task.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap::ad {

namespace {

	// The ModifyRequest of a change or a reset, and its error context; the
	// values are wiped when destroyed.
	struct prepared
	{
		std::string context;
		modify_params request;

		prepared(std::string c, modify_params r) : context(std::move(c)), request(std::move(r)) {}
		prepared(const prepared &) = delete;
		prepared(prepared &&) = default;
		auto operator=(const prepared &) -> prepared & = delete;
		auto operator=(prepared &&) -> prepared & = delete;
		~prepared()
		{
			for (auto &c : request.changes) {
				for (auto &v : c.modification.values) {
					detail::wipe_string(v);
				}
			}
		}
	};

	auto
	  prepare(std::string_view op, dn user, std::optional<std::string_view> old_password, std::string_view new_password)
		-> result<prepared>
	{
		std::string context = detail::op_context(op, user);
		if (new_password.empty()) {
			return fail(std::make_error_code(std::errc::invalid_argument), context + ": empty new password");
		}
		if (old_password && old_password->empty()) {
			return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": empty old password (reset_password() sets one without it)");
		}
		if (user.empty()) {
			return fail(client_errc::invalid_dn, context + ": Active Directory needs the user's DN");
		}
		auto new_value = password_value(new_password);
		if (!new_value) {
			return std::unexpected(detail::with_context(std::move(new_value.error()), context));
		}
		const detail::scope_exit wipe_new{ [&new_value] noexcept { detail::wipe_string(*new_value); } };
		prepared out(std::move(context), modify_params{ .object = std::move(user) });
		auto &changes = out.request.changes;
		if (old_password) {
			auto old_value = password_value(*old_password);
			if (!old_value) {
				return std::unexpected(detail::with_context(std::move(old_value.error()), out.context));
			}
			const detail::scope_exit wipe_old{ [&old_value] noexcept { detail::wipe_string(*old_value); } };
			changes.push_back(mod::remove("unicodePwd", { *old_value }));
			changes.push_back(mod::add("unicodePwd", { *new_value }));
		} else {
			changes.push_back(mod::replace("unicodePwd", { *new_value }));
		}
		return out;
	}

	// The refusal of an open connection neither TLS nor a SASL
	// confidentiality layer protects.
	auto check_protection(bool open, bool tls, sasl_protection layer, const prepared &p) -> result<void>
	{
		if (open && !tls && layer != sasl_protection::confidentiality) {
			return fail(client_errc::tls_required,
			  p.context
				+ ": Active Directory sets unicodePwd only over an encrypted connection (ldaps://, start_tls() or a "
				  "SASL confidentiality layer)");
		}
		return {};
	}

	// The modify's outcome, its error in the change's context.
	auto settle(result<update_result> r, const prepared &p) -> result<void>
	{
		if (r) {
			return {};
		}
		error e = std::move(r.error());
		const std::string modify = detail::op_context("modify", p.request.object);
		const std::string replacement = p.context + ": modify unicodePwd";
		if (std::string_view(e.context).starts_with(modify)) {
			e.context.replace(0, modify.size(), replacement);
		} else {
			e = detail::with_context(std::move(e), replacement);
		}
		if (const auto text = explain(e); !text.empty()) {
			e.context.append(": ").append(text).append(" (Active Directory error ");
			e.context.append(std::string_view(e.diagnostic_message).substr(0, 8)).append(")");
		}
		return std::unexpected(std::move(e));
	}

	auto send(connection &c, const prepared &p) -> capy::task<result<void>>
	{
		if (auto ok = check_protection(c.is_open(), c.is_tls(), c.security_layer(), p); !ok) {
			co_return ok;
		}
		co_return settle(co_await c.modify(p.request), p);
	}

	auto run(connection &c, result<prepared> p) -> capy::task<result<void>>
	{
		if (!p) {
			co_return std::unexpected(std::move(p.error()));
		}
		co_return co_await send(c, *p);
	}

	// `first` and `retry` are acquire() tasks of the same client: `retry`
	// runs only after client_errc::not_sent on the first lease.
	auto run(capy::task<result<lease>> first, capy::task<result<lease>> retry, result<prepared> p)
	  -> capy::task<result<void>>
	{
		if (!p) {
			co_return std::unexpected(std::move(p.error()));
		}
		{
			auto l = co_await std::move(first);
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			auto r = co_await send(l->get(), *p);
			if (r || r.error().code != client_errc::not_sent) {
				co_return r;
			}
		}
		auto l = co_await std::move(retry);
		if (!l) {
			co_return std::unexpected(std::move(l.error()));
		}
		co_return co_await send(l->get(), *p);
	}

	auto run(client &pool, result<prepared> p) -> capy::task<result<void>>
	{
		return run(pool.acquire(), pool.acquire(), std::move(p));
	}

	constexpr std::string_view change_op = "change password";
	constexpr std::string_view reset_op = "reset password";

}// namespace

auto change_password(connection &c, dn user, std::string_view old_password, std::string_view new_password)
  -> capy::task<result<void>>
{
	return run(c, prepare(change_op, std::move(user), old_password, new_password));
}

auto reset_password(connection &c, dn user, std::string_view new_password) -> capy::task<result<void>>
{
	return run(c, prepare(reset_op, std::move(user), std::nullopt, new_password));
}

auto change_password(client &pool, dn user, std::string_view old_password, std::string_view new_password)
  -> capy::task<result<void>>
{
	return run(pool, prepare(change_op, std::move(user), old_password, new_password));
}

auto reset_password(client &pool, dn user, std::string_view new_password) -> capy::task<result<void>>
{
	return run(pool, prepare(reset_op, std::move(user), std::nullopt, new_password));
}

}// namespace jhetz::ldap::ad
