// Active Directory password changes: a ModifyRequest of unicodePwd
// (MS-ADTS 3.1.1.3.1.5) instead of RFC 3062.
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"

#include <boost/capy/task.hpp>

#include <string_view>

namespace jhetz::ldap::ad {

// change_password deletes the old value and adds the new one;
// reset_password replaces it. Refused before sending without TLS or a SASL
// confidentiality layer. The connection must outlive the task.
auto change_password(connection &c, dn user, std::string_view old_password, std::string_view new_password)
  -> boost::capy::task<result<void>>;
auto reset_password(connection &c, dn user, std::string_view new_password) -> boost::capy::task<result<void>>;

// As above on a shared lease of `pool`, retried once after not_sent; the
// tasks do not refer to `pool`.
auto change_password(client &pool, dn user, std::string_view old_password, std::string_view new_password)
  -> boost::capy::task<result<void>>;
auto reset_password(client &pool, dn user, std::string_view new_password) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::ad
