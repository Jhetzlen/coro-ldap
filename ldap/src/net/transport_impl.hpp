// Internal: the parts of net::transport that connect() fills in.
#pragma once

#include "jhetz/ldap/net/transport.hpp"

#include <boost/capy/io/any_stream.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <optional>
#include <string>
#include <utility>

namespace jhetz::ldap::net {

// Members are destroyed in reverse order: the type-erased view first, then
// the TLS layer (which refers to the socket), then the sockets.
struct transport::impl
{
	kind type = kind::none;
	std::pmr::string name{};
	std::optional<boost::corosio::tcp_socket> tcp{};
	std::optional<boost::corosio::local_stream_socket> local{};
	std::optional<boost::corosio::tls_context> tls_context{};
	// Reference mode over *tcp (see transport.hpp, StartTLS).
	std::optional<boost::corosio::openssl_stream> tls{};
	boost::capy::any_stream stream{};
};

struct transport_access
{
	static transport make(transport::kind k, std::string_view name) { return transport::make(k, name); }
	static transport::impl &get(transport &t) noexcept { return *t.impl_; }
};

}// namespace jhetz::ldap::net
