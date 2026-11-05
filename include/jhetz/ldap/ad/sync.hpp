// Blocking counterparts of the ldap::ad operations (ad/password.hpp), over
// the sync facade's connection, lease and client (sync.hpp). Part of
// jhetz::ldap_ad.
#pragma once

#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sync.hpp"

#include <string_view>

namespace jhetz::ldap::ad {

// As ad::change_password and ad::reset_password (ad/password.hpp), blocking.
[[nodiscard]] auto
  change_password(sync::connection &c, dn user, std::string_view old_password, std::string_view new_password)
	-> result<void>;
[[nodiscard]] auto reset_password(sync::connection &c, dn user, std::string_view new_password) -> result<void>;
[[nodiscard]] auto
  change_password(sync::lease &c, dn user, std::string_view old_password, std::string_view new_password)
	-> result<void>;
[[nodiscard]] auto reset_password(sync::lease &c, dn user, std::string_view new_password) -> result<void>;
// On a shared lease of `pool`, retried once after client_errc::not_sent.
[[nodiscard]] auto
  change_password(sync::client &pool, dn user, std::string_view old_password, std::string_view new_password)
	-> result<void>;
[[nodiscard]] auto reset_password(sync::client &pool, dn user, std::string_view new_password) -> result<void>;

}// namespace jhetz::ldap::ad
