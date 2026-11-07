// Active Directory password changes: a ModifyRequest of unicodePwd
// (MS-ADTS 3.1.1.3.1.5), which AD DS, AD LDS and Samba AD use instead of
// RFC 3062 password modify. Part of jhetz::ldap_ad.
//
//   auto r = co_await ldap::ad::reset_password(conn, ldap::dn{"CN=jdoe,CN=Users,DC=example,DC=org"}, password);
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"

#include <boost/capy/task.hpp>

#include <string_view>

namespace jhetz::ldap::ad {

// change_password is a user's own change: one ModifyRequest of `user`'s
// unicodePwd deleting the old value and adding the new one
// (ad::password_value()). reset_password is an administrator's: one
// replacing it. Before anything is sent they fail with
// std::errc::invalid_argument for an empty new password (or old one, for a
// change), client_errc::invalid_dn for an empty `user`,
// client_errc::encode_error for a password that is not valid UTF-8, and
// client_errc::tls_required on an open connection that is neither
// TLS-protected (is_tls(): ldaps:// or after start_tls()) nor under a SASL
// confidentiality layer (security_layer() reports confidentiality: sasl_ntlm
// with either layer, sasl_gssapi with gssapi_security_layer::confidentiality;
// GSSAPI's integrity layer is refused). A server refusal keeps the server's
// result code and diagnostic, with the context "change password <user>:
// modify unicodePwd" (or "reset password"); the diagnostics of common
// refusals (0000052D: the password policy, 00000056: a wrong old password,
// ...) are explained in the context (ad::explain, ad/diagnostic.hpp).
// Passwords never appear in errors, and their memory is not wiped (see
// extended_operations.hpp on password memory). `c` is a connection (a
// shared lease's too); the connection must outlive the task;
// the passwords are read before the call returns.
auto change_password(connection &c, dn user, std::string_view old_password, std::string_view new_password)
  -> boost::capy::task<result<void>>;
auto reset_password(connection &c, dn user, std::string_view new_password) -> boost::capy::task<result<void>>;

// As above on a shared lease of `pool` (client::acquire()), retried once
// after client_errc::not_sent, as client's write forwarders are: the
// connection it failed on is closed (or being unbound), which acquire()
// never hands out, so the retry takes another pooled connection or opens a
// new one. An acquire() failure is returned as is, and so is the retry's
// outcome. Like acquire(), the tasks do not refer to `pool`.
auto change_password(client &pool, dn user, std::string_view old_password, std::string_view new_password)
  -> boost::capy::task<result<void>>;
auto reset_password(client &pool, dn user, std::string_view new_password) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::ad
