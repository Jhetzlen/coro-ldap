#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::impl_ref;
using detail::no_connection;
using detail::op_context;

namespace {

	// PasswdModifyRequestValue ::= SEQUENCE { userIdentity [0], oldPasswd [1],
	// newPasswd [2] } (all OCTET STRING OPTIONAL). nullopt when all are
	// absent: the requestValue is then left out (RFC 3062 section 2).
	auto encode_password_modify(const password_modify_params &request) -> std::optional<std::string>
	{
		if (!request.user && !request.old_password && !request.new_password) {
			return std::nullopt;
		}
		ber::writer w;
		w.constructed(ber::tags::sequence, [&](ber::writer &s) {
			if (request.user) {
				s.octet_string(*request.user, ber::context(0));
			}
			if (request.old_password) {
				s.octet_string(*request.old_password, ber::context(1));
			}
			if (request.new_password) {
				s.octet_string(*request.new_password, ber::context(2));
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

	auto password_modify_impl(impl_ref self, password_modify_params request, std::string context)
	  -> capy::task<result<std::optional<std::string>>>
	{
		extended_params extended{ .name = std::string(password_modify_oid),
			.value = encode_password_modify(request),
			.controls = std::move(request.controls),
			.timeout = request.timeout };
		auto r = co_await extended_impl(std::move(self), std::move(extended));
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

auto connection::password_modify(password_modify_params request) -> capy::task<result<std::optional<std::string>>>
{
	std::string context = "password modify";
	if (request.user) {// usually a DN, often the server's: as op_context
		context += ' ';
		detail::append_sanitized(context, *request.user, 256);
	}
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await password_modify_impl(impl_ref(impl_), std::move(request), std::move(context));
}

// ---------------------------------------------------------------- password changes

namespace {

	// change_password (with `old_password`) and reset_password.
	auto set_password(impl_ref self,
	  std::string context,
	  dn user,
	  std::optional<std::string> old_password,
	  std::string new_password) -> capy::task<result<void>>
	{
		if (new_password.empty()) {
			co_return fail(std::make_error_code(std::errc::invalid_argument), context + ": empty new password");
		}
		if (old_password && old_password->empty()) {
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": empty old password (reset_password() sets one without it)");
		}
		password_modify_params request{ .old_password = std::move(old_password),
			.new_password = std::move(new_password) };
		if (!user.empty()) {
			request.user = std::string(user.to_string());
		}
		auto r =
		  co_await password_modify_impl(std::move(self), std::move(request), context + ": password modify (RFC 3062)");
		if (!r) {
			co_return std::unexpected(std::move(r.error()));
		}
		co_return result<void>{};
	}

}// namespace

auto connection::change_password(dn user, std::string old_password, std::string new_password)
  -> capy::task<result<void>>
{
	std::string context = op_context("change password", user);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await set_password(
	  impl_ref(impl_), std::move(context), std::move(user), std::move(old_password), std::move(new_password));
}

auto connection::reset_password(dn user, std::string new_password) -> capy::task<result<void>>
{
	std::string context = op_context("reset password", user);
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	co_return co_await set_password(
	  impl_ref(impl_), std::move(context), std::move(user), std::nullopt, std::move(new_password));
}

}// namespace jhetz::ldap
