// referral_target (referral.hpp): the request that progresses an operation
// at a referral's or continuation reference's target. Part of the codec.
#include "jhetz/ldap/referral.hpp"

#include "format_util.hpp"

#include <cstddef>
#include <string>
#include <utility>

namespace jhetz::ldap {
namespace {

	// At most this much of a server's extension type in an error context.
	constexpr std::size_t max_quoted = 256;

	// RFC 4516 section 2: an unimplemented critical extension forbids
	// processing the URL. This library implements none.
	auto check_extensions(const url &target) -> result<void>
	{
		for (const auto &e : target.extensions()) {
			if (e.critical) {
				std::string context = "referral: unsupported critical extension ";
				detail::append_sanitized(context, e.type, max_quoted);
				return fail(client_errc::invalid_url, context);
			}
		}
		return {};
	}

	// The URL's DN when present and not empty (section 4.1.10), else null.
	auto url_dn(const url &target) -> const dn *
	{
		const auto &d = target.base_dn();
		return d && !d->empty() ? &*d : nullptr;
	}

	// The common part of the operations that take only a DN from the URL.
	template<class Params> auto with_entry(const url &target, Params original, dn Params::*member) -> result<Params>
	{
		if (auto c = check_extensions(target); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (const dn *d = url_dn(target)) {
			original.*member = *d;
		}
		return original;
	}

}// namespace

auto referral_target(const url &target, search_params original, reference_kind kind) -> result<search_params>
{
	if (auto c = check_extensions(target); !c) {
		return std::unexpected(std::move(c.error()));
	}
	const bool reference = kind == reference_kind::continuation_reference;
	if (const dn *d = url_dn(target)) {
		original.base = *d;
	} else if (reference) {
		return fail(client_errc::invalid_url, "continuation reference: the URL names no DN (RFC 4511 section 4.5.3)");
	}
	if (const auto scope = target.scope()) {
		original.scope = *scope;
	} else if (reference && original.scope == search_scope::single_level) {
		original.scope = search_scope::base_object;
	}
	if (const auto &f = target.search_filter()) {
		original.filter = *f;
	}
	return original;
}

auto referral_target(const url &target, compare_params original) -> result<compare_params>
{
	return with_entry(target, std::move(original), &compare_params::entry);
}

auto referral_target(const url &target, add_params original) -> result<add_params>
{
	return with_entry(target, std::move(original), &add_params::entry);
}

auto referral_target(const url &target, modify_params original) -> result<modify_params>
{
	return with_entry(target, std::move(original), &modify_params::object);
}

auto referral_target(const url &target, del_params original) -> result<del_params>
{
	return with_entry(target, std::move(original), &del_params::entry);
}

auto referral_target(const url &target, modify_dn_params original) -> result<modify_dn_params>
{
	return with_entry(target, std::move(original), &modify_dn_params::entry);
}

}// namespace jhetz::ldap
