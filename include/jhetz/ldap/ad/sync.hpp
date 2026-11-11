// Blocking counterparts of the ldap::ad operations (ad/password.hpp,
// ad/ranged_values.hpp), over
// the sync facade's connection, leases and client (sync.hpp): each runs
// the async function with sync::run. Part of jhetz::ldap_ad.
#pragma once

#include "jhetz/ldap/ad/password.hpp"
#include "jhetz/ldap/ad/ranged_values.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/sync.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::ad {

// As ad::change_password and ad::reset_password (ad/password.hpp),
// blocking. On a sync::client, on a shared lease of the pool, retried once
// after client_errc::not_sent.
template<sync::directory D>
[[nodiscard]] auto change_password(D &d, dn user, std::string_view old_password, std::string_view new_password)
  -> result<void>
{
	return sync::run(d, [&](auto &a) { return ad::change_password(a, std::move(user), old_password, new_password); });
}
template<sync::directory D>
[[nodiscard]] auto reset_password(D &d, dn user, std::string_view new_password) -> result<void>
{
	return sync::run(d, [&](auto &a) { return ad::reset_password(a, std::move(user), new_password); });
}

// As ad::read_all_values (ad/ranged_values.hpp), blocking, the values on
// the default resource. On a sync::client, one shared lease for every
// window, run once more after cond::connection_lost.
template<sync::directory D>
[[nodiscard]] auto read_all_values(D &d, dn object, std::string attribute, range_options options = {})
  -> result<string_list>
{
	return sync::run(
	  d, [&](auto &a) { return ad::read_all_values(a, std::move(object), std::move(attribute), options); });
}

}// namespace jhetz::ldap::ad
