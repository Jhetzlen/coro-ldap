#include "jhetz/ldap/ad/password.hpp"

#include "jhetz/ldap/ad/password_value.hpp"
#include "jhetz/ldap/ad/sync.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <charconv>
#include <cstddef>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap::ad {

namespace {

	// The ModifyRequest of a change or a reset, and its error context.
	struct prepared
	{
		std::string context;
		modify_params request;
	};

	auto prepare(std::string_view op, dn user, const std::string *old_password, const std::string &new_password)
	  -> result<prepared>
	{
		std::string context = detail::op_context(op, user);
		if (new_password.empty()) {
			return fail(std::make_error_code(std::errc::invalid_argument), context + ": empty new password");
		}
		if (old_password != nullptr && old_password->empty()) {
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
		modify_params request{ .object = std::move(user) };
		if (old_password != nullptr) {
			auto old_value = password_value(*old_password);
			if (!old_value) {
				return std::unexpected(detail::with_context(std::move(old_value.error()), context));
			}
			request.changes.push_back(mod::remove("unicodePwd", { *old_value }));
			request.changes.push_back(mod::add("unicodePwd", { *new_value }));
		} else {
			request.changes.push_back(mod::replace("unicodePwd", { *new_value }));
		}
		return prepared{ .context = std::move(context), .request = std::move(request) };
	}

	// The refusal of an open connection AD would not take a password over.
	auto check_protection(bool open, bool tls, const prepared &p) -> result<void>
	{
		if (open && !tls) {
			return fail(client_errc::tls_required,
			  p.context + ": Active Directory sets unicodePwd only over TLS (ldaps:// or start_tls())");
		}
		return {};
	}

	// The Win32 error codes of a failed password change.
	enum class win32_error : unsigned {
		access_denied = 0x5,// ERROR_ACCESS_DENIED
		invalid_password = 0x56,// ERROR_INVALID_PASSWORD
		password_restriction = 0x52D,// ERROR_PASSWORD_RESTRICTION
		account_locked_out = 0x775,// ERROR_ACCOUNT_LOCKED_OUT
	};

	// The explanation of the Win32 error in hex that starts an AD
	// diagnosticMessage ("0000052D: Constraint violation - ..."), "" for
	// the others.
	auto explanation(std::string_view diagnostic) -> std::string_view
	{
		constexpr std::size_t code_digits = 8;
		if (diagnostic.size() <= code_digits || diagnostic[code_digits] != ':') {
			return {};
		}
		unsigned code = 0;
		// NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): bounded to 8 chars, no terminator read
		const auto [end, ec] = std::from_chars(diagnostic.data(), diagnostic.data() + code_digits, code, 16);
		if (ec != std::errc{} || end != diagnostic.data() + code_digits) {
			return {};
		}
		switch (static_cast<win32_error>(code)) {
		case win32_error::access_denied:
			return "not allowed to set this user's password";
		case win32_error::invalid_password:
			return "the old password is wrong";
		case win32_error::password_restriction:
			return "the new password does not meet the password policy (length, complexity, history or minimum "
				   "age)";
		case win32_error::account_locked_out:
			return "the account is locked out";
		default:
			return {};
		}
	}

	// The modify's outcome, its error in the change's context.
	auto settle(result<response> r, const prepared &p) -> result<void>
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
		if (const auto text = explanation(e.diagnostic); !text.empty()) {
			e.context.append(": ").append(text).append(" (Active Directory error ");
			e.context.append(std::string_view(e.diagnostic).substr(0, 8)).append(")");
		}
		return std::unexpected(std::move(e));
	}

	auto send(connection &c, const prepared &p) -> capy::task<result<void>>
	{
		if (auto ok = check_protection(c.is_open(), c.is_tls(), p); !ok) {
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

	auto run(client &pool, result<prepared> p) -> capy::task<result<void>>
	{
		if (!p) {
			co_return std::unexpected(std::move(p.error()));
		}
		for (int attempt = 0;; ++attempt) {
			auto l = co_await pool.acquire();
			if (!l) {
				co_return std::unexpected(std::move(l.error()));
			}
			auto r = co_await send(l->get(), *p);
			if (r || attempt != 0 || r.error().code != client_errc::not_sent) {
				co_return r;
			}
		}
	}

	template<class C> auto send_sync(C &c, const prepared &p) -> result<void>
	{
		if (auto ok = check_protection(c.is_open(), c.is_tls(), p); !ok) {
			return ok;
		}
		return settle(c.modify(p.request), p);
	}

	template<class C> auto run_sync(C &c, result<prepared> p) -> result<void>
	{
		if (!p) {
			return std::unexpected(std::move(p.error()));
		}
		return send_sync(c, *p);
	}

	auto run_sync(sync::client &pool, result<prepared> p) -> result<void>
	{
		if (!p) {
			return std::unexpected(std::move(p.error()));
		}
		for (int attempt = 0;; ++attempt) {
			auto l = pool.acquire();
			if (!l) {
				return std::unexpected(std::move(l.error()));
			}
			auto r = send_sync(*l, *p);
			if (r || attempt != 0 || r.error().code != client_errc::not_sent) {
				return r;
			}
		}
	}

	constexpr std::string_view change_op = "change password";
	constexpr std::string_view reset_op = "reset password";

}// namespace

auto change_password(connection &c, dn user, std::string old_password, std::string new_password)
  -> capy::task<result<void>>
{
	return run(c, prepare(change_op, std::move(user), &old_password, new_password));
}

auto reset_password(connection &c, dn user, std::string new_password) -> capy::task<result<void>>
{
	return run(c, prepare(reset_op, std::move(user), nullptr, new_password));
}

auto change_password(client &pool, dn user, std::string old_password, std::string new_password)
  -> capy::task<result<void>>
{
	return run(pool, prepare(change_op, std::move(user), &old_password, new_password));
}

auto reset_password(client &pool, dn user, std::string new_password) -> capy::task<result<void>>
{
	return run(pool, prepare(reset_op, std::move(user), nullptr, new_password));
}

auto change_password(sync::connection &c, dn user, std::string old_password, std::string new_password) -> result<void>
{
	return run_sync(c, prepare(change_op, std::move(user), &old_password, new_password));
}

auto reset_password(sync::connection &c, dn user, std::string new_password) -> result<void>
{
	return run_sync(c, prepare(reset_op, std::move(user), nullptr, new_password));
}

auto change_password(sync::lease &c, dn user, std::string old_password, std::string new_password) -> result<void>
{
	return run_sync(c, prepare(change_op, std::move(user), &old_password, new_password));
}

auto reset_password(sync::lease &c, dn user, std::string new_password) -> result<void>
{
	return run_sync(c, prepare(reset_op, std::move(user), nullptr, new_password));
}

auto change_password(sync::client &pool, dn user, std::string old_password, std::string new_password) -> result<void>
{
	return run_sync(pool, prepare(change_op, std::move(user), &old_password, new_password));
}

auto reset_password(sync::client &pool, dn user, std::string new_password) -> result<void>
{
	return run_sync(pool, prepare(reset_op, std::move(user), nullptr, new_password));
}

}// namespace jhetz::ldap::ad
