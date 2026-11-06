#include "jhetz/ldap/extended_operations.hpp"

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/mapping.hpp"

#include "format_util.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace jhetz::ldap {

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

auto detail::who_am_i_request(extended_controls controls) -> extended_params
{
	return { .name = std::string(who_am_i_oid), .controls = std::move(controls) };
}

auto detail::who_am_i_result(result<extended_result> r) -> result<std::string>
{
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	if (!r->value) {
		return std::string();
	}
	// The authzId is an LDAPString (RFC 4532 section 2.2, RFC 4511 section
	// 4.1.2): UTF-8, checked as the mapping checks a decoded string.
	if (const std::size_t bad = detail::invalid_utf8_offset(*r->value); bad != std::string_view::npos) {
		error e = detail::utf8_conversion_error(bad);
		e.context.insert(0, "who_am_i authzId: ");
		return std::unexpected(std::move(e));
	}
	return std::string(*r->value);
}

auto detail::password_modify_request(password_modify_params request) -> password_modify_call
{
	std::string context = "password modify";
	if (request.user) {// usually a DN, often the server's: as op_context
		context += ' ';
		detail::append_sanitized(context, *request.user, 256);
	}
	extended_params x{ .name = std::string(password_modify_oid),
		.value = encode_password_modify(request),
		.controls = std::move(request.controls),
		.timeout = request.timeout };
	return { .request = std::move(x), .context = std::move(context) };
}

auto detail::password_modify_result(result<extended_result> r, std::string_view context)
  -> result<std::optional<std::string>>
{
	if (!r) {
		// The extended operation's context names the OID: name the operation.
		error e = std::move(r.error());
		const std::string generic = detail::format("extended operation {}", password_modify_oid);
		if (std::string_view(e.context).starts_with(generic)) {
			e.context.replace(0, generic.size(), context);
		}
		return std::unexpected(std::move(e));
	}
	if (!r->value) {
		return std::optional<std::string>{};
	}
	auto generated = decode_password_modify(*r->value);
	if (!generated) {
		return std::unexpected(
		  detail::with_context(std::move(generated.error()), std::string(context) + ": response value"));
	}
	return std::move(*generated);
}

auto detail::set_password_request(std::string_view op,
  const dn &user,
  std::optional<std::string> old_password,
  std::string new_password) -> result<password_modify_call>
{
	const std::string context = op_context(op, user);
	if (new_password.empty()) {
		return fail(std::make_error_code(std::errc::invalid_argument), context + ": empty new password");
	}
	if (old_password && old_password->empty()) {
		return fail(std::make_error_code(std::errc::invalid_argument),
		  context + ": empty old password (reset_password() sets one without it)");
	}
	password_modify_params request{ .old_password = std::move(old_password), .new_password = std::move(new_password) };
	if (!user.empty()) {
		request.user = std::string(user.to_string());
	}
	auto call = password_modify_request(std::move(request));
	call.context = context + ": password modify (RFC 3062)";
	return call;
}

auto detail::set_password_result(result<extended_result> r, std::string_view context) -> result<void>
{
	auto done = password_modify_result(std::move(r), context);
	if (!done) {
		return std::unexpected(std::move(done.error()));
	}
	return {};
}

}// namespace jhetz::ldap
