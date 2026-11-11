// Ranged retrieval (MS-ADTS 3.1.1.3.1.3.3): every value of a multi-valued
// attribute that Active Directory returns in windows of at most MaxValRange
// values (1500 by default), `member;range=0-1499`, then
// `member;range=1500-2999`, ... until a window ends with '*'. Part of
// jhetz::ldap_ad.
//
//   const ldap::dn staff{"CN=Staff,OU=Groups,DC=example,DC=org"};
//   auto members = co_await ldap::ad::read_all_values(conn, staff, "member");
#pragma once

#include "jhetz/ldap/ad/range.hpp"
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"

#include <boost/capy/task.hpp>

#include <cstdint>
#include <memory_resource>
#include <string>

namespace jhetz::ldap::ad {

struct range_options
{
	// Values asked for per search: 0 asks for the attribute without a range
	// and follows the windows the server chooses; N asks for
	// `attribute;range=low-(low+N-1)` each time (a server may answer with a
	// smaller window, which is followed).
	std::uint32_t step = 0;
};

// Every value of `attribute` of the entry `object`, in the order the
// server sends them, allocated from `mr`. Base-object searches for
// `attribute` (or `attribute;range=...`, options.step) until the answer
// holds the attribute without a range option, a window ending with '*',
// or no such attribute (no values, or none left: an empty list when the
// entry has none). The returned attributes are grouped by description
// without the range option (ignoring case); the answer is the group named
// `attribute`, else the only group: the server's name for an OID or an
// alias, which the following windows then ask for. In the group, one
// ranged attribute with at most one value-less plain one is a window
// (MS-ADTS 3.1.1.3.1.3.3), a lone plain one every value. With a step,
// when the first window comes back without values, it is asked for once
// more without a range, and that answer is taken as with no step (a
// ranged one continues in windows of the step): a server may ignore the
// range option (Samba on a numeric OID, slapd on every attribute). An
// attribute without values then costs two searches, and such a server
// sends every value in one answer; naming the attribute as the server
// does (its lDAPDisplayName) keeps the bound on a server that honours
// ranges. Fails before anything is sent with
// std::errc::invalid_argument for an empty `attribute` or one with a
// range option; with the search's error (context "read all values of
// <attribute> <object>"); with client_errc::unexpected_response when no
// entry comes back, it holds several groups none of which is `attribute`,
// the group holds two ranged attributes or a plain one with values next to
// a ranged one, a window does not start where the previous one ended,
// or the plain attribute follows a window; and with
// client_errc::decode_error for a malformed range option. The connection
// must outlive the task.
auto read_all_values(connection &c,
  dn object,
  std::string attribute,
  range_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<string_list>>;

// As above on one shared lease of `pool` (client::acquire()) for every
// window, run once more from the start on a new lease after
// cond::connection_lost. An acquire() failure is returned as is. Like
// acquire(), the task does not refer to `pool`.
auto read_all_values(client &pool,
  dn object,
  std::string attribute,
  range_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<string_list>>;

}// namespace jhetz::ldap::ad
