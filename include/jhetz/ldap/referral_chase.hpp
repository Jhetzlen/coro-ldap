// Opt-in referral chasing for searches and compares (RFC 4511 sections
// 4.1.10, 4.5.3) from a bare connection, through a caller-supplied
// connector (docs/API.md, "jhetz/ldap/referral_chase.hpp").
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/referral.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstddef>
#include <functional>
#include <memory_resource>
#include <optional>
#include <string>
#include <vector>

namespace jhetz::ldap {

// Gives the connection a referred request goes to; null skips the URI.
using referral_connector = std::function<boost::capy::task<result<connection *>>(const url &target, std::size_t depth)>;

// connection::search, chasing referral results and continuation references;
// entries are allocated from `mr`.
auto chase_search(connection &origin,
  search_params request,
  referral_connector connector,
  referral_limits policy = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<search_result>>;

// connection::compare, chasing referral results.
auto chase_compare(connection &origin,
  compare_params request,
  referral_connector connector,
  referral_limits policy = {}) -> boost::capy::task<result<compare_result>>;

// A connector keeping the origin's security policy: allowed hosts and
// ports only, no TLS downgrade, bound only by `setup`; connections reused
// per server.
[[nodiscard]] auto make_same_policy_connector(boost::corosio::io_context &ioc,
  const connection &origin,
  connection_options options,
  std::vector<std::string> allowed_domains,
  session_setup setup = {}) -> referral_connector;

}// namespace jhetz::ldap
