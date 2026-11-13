// Ranged retrieval (MS-ADTS 3.1.1.3.1.3.3): every value of an attribute AD
// returns in windows (`member;range=0-1499`, ...).
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
	// 0: the windows the server chooses; N: `attribute;range=low-(low+N-1)`.
	std::uint32_t step = 0;
};

// Every value of `attribute` of `object`, in the order sent, on `mr`. The
// connection must outlive the task.
auto read_all_values(connection &c,
  dn object,
  std::string attribute,
  range_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<string_list>>;

// As above on one shared lease of `pool`, retried once after
// cond::connection_lost; the task does not refer to `pool`.
auto read_all_values(client &pool,
  dn object,
  std::string attribute,
  range_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<string_list>>;

}// namespace jhetz::ldap::ad
