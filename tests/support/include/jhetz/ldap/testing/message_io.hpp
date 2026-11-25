// net::read_message for the server side of a transport. Not part of the
// installed library.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"

#include <boost/capy/task.hpp>

#include <cstddef>

namespace jhetz::ldap::testing {

struct read_options
{
	std::size_t max_message_size = ber::default_max_message_size;
	decode_options decode{ .from = origin::client };
};

// The next complete LDAPMessage from `t`, decoded with `options.decode`;
// bytes after it stay in `buf`.
auto read_message(net::transport &t, net::read_buffer &buf, read_options options = {})
  -> boost::capy::task<result<message>>;

}// namespace jhetz::ldap::testing
