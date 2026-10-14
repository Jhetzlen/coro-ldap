#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"
#include "search.hpp"

#include <unicode/ustring.h>
#include <unicode/utypes.h>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::impl_ref;
using detail::no_connection;
using detail::op_context;

auto ad_password_value(std::string_view password) -> result<std::string>
{
	constexpr std::string_view context = "Active Directory password value";
	if (password.size() > static_cast<std::size_t>(INT32_MAX / 2) - 2) {
		return fail(client_errc::encode_error, std::string(context) + ": the password is too long");
	}

	// UTF-8 -> UTF-16 (ICU's native order). u_strFromUTF8 refuses ill-formed
	// UTF-8: overlong forms, surrogates, code points above U+10FFFF,
	// truncated sequences.
	// Any other ICU status is ICU's failure, not the password's.
	const auto failed = [&](UErrorCode status) {
		if (status == U_INVALID_CHAR_FOUND || status == U_ILLEGAL_CHAR_FOUND) {
			return fail(client_errc::encode_error, std::string(context) + ": the password is not valid UTF-8");
		}
		return fail(client_errc::internal_error,
		  std::string(context) + ": UTF-16 conversion failed (ICU " + u_errorName(status) + ")");
	};
	UErrorCode status = U_ZERO_ERROR;
	int32_t n = 0;
	u_strFromUTF8(nullptr, 0, &n, password.data(), static_cast<int32_t>(password.size()), &status);
	if (status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status)) {
		return failed(status);
	}
	std::vector<UChar> units(static_cast<std::size_t>(n));
	status = U_ZERO_ERROR;
	if (n != 0) {
		u_strFromUTF8(units.data(), n, &n, password.data(), static_cast<int32_t>(password.size()), &status);
	}
	if (U_FAILURE(status)) {
		return failed(status);
	}

	// '"' password '"', each UTF-16 code unit little-endian.
	std::string out;
	out.reserve((units.size() + 2) * 2);
	const auto put = [&out](char16_t u) {
		out.push_back(static_cast<char>(u & 0xFF));
		out.push_back(static_cast<char>(u >> 8));
	};
	put(u'"');
	for (const UChar u : units) {
		put(static_cast<char16_t>(u));
	}
	put(u'"');
	return out;
}


namespace {

	// PasswdModifyRequestValue ::= SEQUENCE { userIdentity [0], oldPasswd [1],
	// newPasswd [2] } (all OCTET STRING OPTIONAL). nullopt when all are
	// absent: the requestValue is then left out (RFC 3062 section 2).
	auto encode_password_modify(const password_modify_params &p) -> std::optional<std::string>
	{
		if (!p.user && !p.old_password && !p.new_password) {
			return std::nullopt;
		}
		ber::writer w;
		w.constructed(ber::tags::sequence, [&](ber::writer &s) {
			if (p.user) {
				s.octet_string(*p.user, ber::context(0));
			}
			if (p.old_password) {
				s.octet_string(*p.old_password, ber::context(1));
			}
			if (p.new_password) {
				s.octet_string(*p.new_password, ber::context(2));
			}
		});
		return std::string(detail::as_text(w.bytes()));
	}

	// PasswdModifyResponseValue ::= SEQUENCE { genPasswd [0] OCTET STRING
	// OPTIONAL }; unknown trailing elements are ignored.
	auto decode_password_modify(std::string_view value) -> result<std::optional<std::string>>
	{
		ber::reader r(std::as_bytes(std::span(value)));
		auto s = r.enter();
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		if (auto end = r.expect_end(); !end) {
			return std::unexpected(std::move(end.error()));
		}
		std::optional<std::string> generated;
		if (!s->empty()) {
			auto t = s->peek_tag();
			if (t && t->cls == ber::tag_class::context && t->number == 0) {
				auto g = s->read_octet_string(ber::context(0));
				if (!g) {
					return std::unexpected(std::move(g.error()));
				}
				generated.emplace(detail::as_text(*g));
			}
		}
		return generated;
	}

}// namespace

namespace detail {

	auto password_modify_impl(impl_ref self, password_modify_params p, std::string context)
	  -> capy::task<result<std::optional<std::string>>>
	{
		extended_params request{ .name = std::string(password_modify_oid),
			.value = encode_password_modify(p),
			.controls = std::move(p.controls),
			.timeout = p.timeout };
		auto r = co_await extended_impl(std::move(self), std::move(request));
		if (!r) {
			error e = std::move(r.error());
			const std::string generic = detail::format("extended operation {}", password_modify_oid);
			if (std::string_view(e.context).starts_with(generic)) {
				e.context.replace(0, generic.size(), context);
			}
			co_return std::unexpected(std::move(e));
		}
		if (!r->value) {
			co_return std::optional<std::string>{};
		}
		auto generated = decode_password_modify(*r->value);
		if (!generated) {
			co_return std::unexpected(detail::with_context(std::move(generated.error()), context + ": response value"));
		}
		co_return std::move(*generated);
	}

}// namespace detail

using detail::password_modify_impl;

auto connection::password_modify(password_modify_params p) -> capy::task<result<std::optional<std::string>>>
{
	std::string context = "password modify";
	if (p.user) {// usually a DN, often the server's: as op_context
		context += ' ';
		detail::append_sanitized(context, *p.user, 256);
	}
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await password_modify_impl(impl_ref(impl_), std::move(p), std::move(context));
}

using detail::read_one;

// ---------------------------------------------------------------- password changes

namespace {

	// How to choose the method when the root DSE does not tell.
	constexpr std::string_view choose_password_method =
	  "choose the method with connection_options::password_method or the method argument "
	  "(ldap::password_method::rfc3062 or active_directory)";

	// password_method::automatic: what the root DSE advertises, RFC 3062
	// first. Errors are prefixed with `context`.
	auto advertised_password_method(impl_ref self, const std::string &context)
	  -> capy::task<result<ldap::password_method>>
	{
		auto root = co_await read_one(self,
		  { .scope = search_scope::base_object, .attributes = { "supportedExtension", "supportedCapabilities" } });
		if (!root) {
			co_return std::unexpected(detail::with_context(std::move(root.error()),
			  detail::format("{}: reading the root DSE to pick the method failed ({} to skip it)",
				context,
				choose_password_method)));
		}
		const auto lists = [&root](std::string_view type, std::string_view oid) {
			const auto *values = *root ? (*root)->find(type) : nullptr;
			return values != nullptr && std::ranges::contains(*values, oid);
		};
		if (lists("supportedExtension", password_modify_oid)) {
			co_return ldap::password_method::rfc3062;
		}
		if (lists("supportedCapabilities", active_directory_capability_oid)) {
			co_return ldap::password_method::active_directory;
		}
		co_return fail(client_errc::no_password_method,
		  detail::format("{}: the root DSE advertises neither the RFC 3062 password modify extension nor Active "
						 "Directory (it may be hidden by access controls): {}, or call password_modify()",
			context,
			choose_password_method));
	}

	// Active Directory starts its diagnosticMessage with the Win32 error in
	// hex ("0000052D: Constraint violation - ..."): the common ones of a
	// password change, explained ("" for the others).
	auto ad_password_explanation(std::string_view diagnostic) -> std::string_view
	{
		if (diagnostic.size() < 9 || diagnostic[8] != ':') {
			return {};
		}
		unsigned code = 0;
		const auto [end, ec] = std::from_chars(diagnostic.data(), diagnostic.data() + 8, code, 16);
		if (ec != std::errc{} || end != diagnostic.data() + 8) {
			return {};
		}
		switch (code) {
		case 0x5:// ERROR_ACCESS_DENIED
			return "not allowed to set this user's password";
		case 0x56:// ERROR_INVALID_PASSWORD
			return "the old password is wrong";
		case 0x52D:// ERROR_PASSWORD_RESTRICTION
			return "the new password does not meet the password policy (length, complexity, history or minimum "
				   "age)";
		case 0x775:// ERROR_ACCOUNT_LOCKED_OUT
			return "the account is locked out";
		default:
			return {};
		}
	}

	// password_method::active_directory: a ModifyRequest of unicodePwd.
	auto ad_set_password(impl_ref self,
	  const dn &user,
	  const std::optional<std::string> &old_password,
	  const std::string &new_password,
	  const std::string &context) -> capy::task<result<void>>
	{
		if (user.empty()) {
			co_return fail(client_errc::invalid_dn, context + ": Active Directory needs the user's DN");
		}
		// A closed connection fails with not_connected below.
		if (self->is_open() && !self->is_tls()) {
			co_return fail(client_errc::tls_required,
			  context + ": Active Directory sets unicodePwd only over TLS (ldaps:// or start_tls())");
		}
		auto new_value = ad_password_value(new_password);
		if (!new_value) {
			co_return std::unexpected(detail::with_context(std::move(new_value.error()), context));
		}
		modify_params p{ .object = user };
		if (old_password) {
			auto old_value = ad_password_value(*old_password);
			if (!old_value) {
				co_return std::unexpected(detail::with_context(std::move(old_value.error()), context));
			}
			p.changes.push_back(mod::remove("unicodePwd", { *old_value }));
			p.changes.push_back(mod::add("unicodePwd", { *new_value }));
		} else {
			p.changes.push_back(mod::replace("unicodePwd", { *new_value }));
		}
		auto r = co_await modify_impl(std::move(self), std::move(p), context + ": modify unicodePwd");
		if (r) {
			co_return result<void>{};
		}
		error e = std::move(r.error());
		if (const auto text = ad_password_explanation(e.diagnostic); !text.empty()) {
			e.context +=
			  detail::format(": {} (Active Directory error {})", text, std::string_view(e.diagnostic).substr(0, 8));
		}
		co_return std::unexpected(std::move(e));
	}

	// change_password (with `old_password`) and reset_password.
	auto set_password(impl_ref self,
	  std::string context,
	  dn user,
	  std::optional<std::string> old_password,
	  std::string new_password,
	  std::optional<ldap::password_method> method) -> capy::task<result<void>>
	{
		if (new_password.empty()) {
			co_return fail(std::make_error_code(std::errc::invalid_argument), context + ": empty new password");
		}
		if (old_password && old_password->empty()) {
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": empty old password (reset_password() sets one without it)");
		}
		ldap::password_method m = method.value_or(self->knowledge().password_mode);
		if (m == ldap::password_method::automatic) {
			if (const auto &known = self->knowledge().advertised_password_method) {
				m = *known;
			} else {
				auto found = co_await advertised_password_method(self, context);
				if (!found) {
					co_return std::unexpected(std::move(found.error()));
				}
				self->knowledge().advertised_password_method = *found;
				m = *found;
			}
		}
		if (m == ldap::password_method::active_directory) {
			co_return co_await ad_set_password(std::move(self), user, old_password, new_password, context);
		}
		password_modify_params p{ .old_password = std::move(old_password), .new_password = std::move(new_password) };
		if (!user.empty()) {
			p.user = std::string(user.to_string());
		}
		auto r = co_await password_modify_impl(std::move(self), std::move(p), context + ": password modify (RFC 3062)");
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return result<void>{};
	}

}// namespace

auto connection::change_password(dn user,
  std::string old_password,
  std::string new_password,
  std::optional<ldap::password_method> method) -> capy::task<result<void>>
{
	std::string context = op_context("change password", user);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await set_password(
	  impl_ref(impl_), std::move(context), std::move(user), std::move(old_password), std::move(new_password), method);
}

auto connection::reset_password(dn user, std::string new_password, std::optional<ldap::password_method> method)
  -> capy::task<result<void>>
{
	std::string context = op_context("reset password", user);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await set_password(
	  impl_ref(impl_), std::move(context), std::move(user), std::nullopt, std::move(new_password), method);
}

}// namespace jhetz::ldap
