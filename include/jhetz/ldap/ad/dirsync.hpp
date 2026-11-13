// DirSync polling (MS-ADTS 3.1.1.3.4.1.3): the objects changed in a naming
// context since a cookie.
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
	// Changed objects with the changed attributes asked for, in order.
	std::pmr::vector<entry> entries{};
	// The next poll's cookie.
	std::string cookie{};
	// Still MoreResults after max_rounds searches: call again with `cookie`.
	bool more_results = false;
};

inline constexpr std::size_t dirsync_default_max_rounds = 1000;

// Runs `request` with a DirSync control while the response says
// MoreResults, at most `max_rounds` searches. The connection must outlive
// the task; the entries are on `mr`.
auto dirsync(connection &c,
  search_params request,
  dirsync_request options = {},
  std::size_t max_rounds = dirsync_default_max_rounds,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<dirsync_result>>;

// As above on one shared lease of `pool`, run once more after
// cond::connection_lost; the task does not refer to `pool`.
auto dirsync(client &pool,
  search_params request,
  dirsync_request options = {},
  std::size_t max_rounds = dirsync_default_max_rounds,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<dirsync_result>>;

}// namespace jhetz::ldap::ad
