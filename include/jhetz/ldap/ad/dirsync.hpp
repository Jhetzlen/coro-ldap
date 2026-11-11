// DirSync polling (MS-ADTS 3.1.1.3.4.1.3): the objects changed in a naming
// context since a cookie, Active Directory's counterpart to RFC 4533's
// refreshOnly. Part of jhetz::ldap_ad.
//
//   auto changes = co_await ldap::ad::dirsync(conn,
//       {.base = ldap::dn{"DC=example,DC=org"}, .filter = ldap::filters::attr("objectClass") == "user",
//        .attributes = {"description", "member"}},
//       {.cookie = saved});
//   for (const ldap::entry &e : changes->entries) ...
//   saved = changes->cookie;                       // the next poll starts there
#pragma once

#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <cstddef>
#include <memory_resource>
#include <string>
#include <vector>

namespace jhetz::ldap::ad {

struct dirsync_result
{
	// Every object changed since the request's cookie, with the attributes
	// asked for that changed (all of them with an empty cookie), in the
	// order received; deleted objects only with ad::show_deleted in the
	// request's controls.
	std::pmr::vector<entry> entries{};
	// The CookieServer of the last response: the next poll's cookie.
	std::string cookie{};
	// The last response still said MoreResults after max_rounds searches:
	// call again now with `cookie` for the rest.
	bool more_results = false;
};

// The default bound on the searches of one dirsync() call.
inline constexpr std::size_t dirsync_default_max_rounds = 1000;

// Runs `request` with a DirSync control built from `options` (its cookie
// first, then each response's CookieServer) while the response says
// MoreResults, at most `max_rounds` searches, and returns the entries of
// every search and the last cookie. Each response is a complete batch and
// its CookieServer the point to resume from (MS-ADTS 3.1.1.3.4.1.3); a
// large naming context needs many rounds (MaxBytes and the server's
// MaxPageSize bound each one, so the default is about a million objects at
// AD's default MaxPageSize). When MoreResults is still set after
// `max_rounds` searches, the result has the entries so far, the last
// cookie and more_results set: a complete snapshot loops while
// more_results, and max_rounds = 1 returns one batch per call. A poller
// that only saves the cookie gets the rest on its next poll.
// `request.base` must be the root of a naming context and the caller needs
// the Replicating Directory Changes right, or
// dirsync_flags::object_security; the server refuses the search
// otherwise. `request.timeout` bounds each search, not the call. Errors:
// std::errc::invalid_argument when max_rounds is 0, before anything is
// sent; the search's (context "DirSync <base>"), a limit code included;
// client_errc::unexpected_response when a SearchResultDone has no DirSync
// control or asks for more results with a cookie already seen in this
// call (`options.cookie` included); decode_error for a malformed one. The
// connection must outlive the task; the entries are on `mr`.
auto dirsync(connection &c,
  search_params request,
  dirsync_request options = {},
  std::size_t max_rounds = dirsync_default_max_rounds,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<dirsync_result>>;

// As above on one shared lease of `pool` (client::acquire()) for every
// search, run once more from `options.cookie` on a new lease after
// cond::connection_lost, with the count of rounds reset. An acquire() failure is returned as is. Like
// acquire(), the task does not refer to `pool`.
auto dirsync(client &pool,
  search_params request,
  dirsync_request options = {},
  std::size_t max_rounds = dirsync_default_max_rounds,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<dirsync_result>>;

}// namespace jhetz::ldap::ad
