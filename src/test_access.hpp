// Test hooks into ldap::client and ldap::connection.
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstdint>
#include <functional>
#include <memory_resource>

namespace jhetz::ldap::detail {

using pool_connector = std::function<boost::capy::task<result<
  connection>>(boost::corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)>;

struct test_access
{
	// Replaces the client's random jitter source.
	static void set_jitter(const client &c, std::function<double()> unit);
	// Replaces ldap::connect for the client's pooled connections.
	static void set_connector(const client &c, pool_connector open);
	// The message id the next request tries first.
	static void set_next_message_id(connection &c, std::int32_t id) noexcept;
};

}// namespace jhetz::ldap::detail
