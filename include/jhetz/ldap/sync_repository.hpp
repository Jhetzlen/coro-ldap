// ldap::repository over the blocking facades, and ldap::load_schema for
// them, run with sync::run.
#pragma once

#include "jhetz/ldap/directory.hpp"
#include "jhetz/ldap/repository.hpp"
#include "jhetz/ldap/sync.hpp"

#include <string_view>
#include <utility>

namespace jhetz::ldap::sync {

template<directory D> [[nodiscard]] auto load_schema(D &d) -> result<server_schema>
{
	auto r = sync::run(d, [](auto &a) { return ldap::load_schema(a); });
	if (!r && (r.error().code == client_errc::would_deadlock || r.error().code == client_errc::not_connected)
		&& !std::string_view(r.error().context).starts_with(ldap::detail::load_schema_context)) {
		return std::unexpected(ldap::detail::with_context(std::move(r.error()), ldap::detail::load_schema_context));
	}
	return r;
}

}// namespace jhetz::ldap::sync
