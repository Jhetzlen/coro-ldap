// Internal: the parts of net::transport that connect() fills in.
#pragma once

#include "jhetz/ldap/net/transport.hpp"

#include <boost/capy/io/any_stream.hpp>
#include <boost/corosio/local_stream_socket.hpp>
#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/tls_context.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace jhetz::ldap::net {

// Members are destroyed in reverse order: the type-erased view first, then
// the TLS layer (which refers to the socket), then the sockets.
struct transport::impl
{
	explicit impl(std::pmr::memory_resource *r)
	  : mr(r), name(r), host(r), peer_certificate(r), tls_server_end_point(r), tls_exporter(r)
	{}

	std::pmr::memory_resource *mr;// impl itself was allocated from it
	kind type = kind::none;
	std::pmr::string name;
	std::pmr::string host;// the URL's host (for StartTLS verification); empty for custom streams
	std::optional<boost::corosio::tcp_socket> tcp{};
	std::optional<boost::corosio::local_stream_socket> local{};
	std::optional<boost::corosio::tls_context> tls_context{};
	// Reference mode over *tcp (see transport.hpp, StartTLS).
	std::optional<boost::corosio::openssl_stream> tls{};
	// Read from the TLS session once its handshake succeeded
	// (detail::record_tls_session), cleared with `tls`: the server's
	// certificate (DER) and the channel bindings (empty: unavailable).
	std::pmr::vector<std::byte> peer_certificate;
	std::pmr::vector<std::byte> tls_server_end_point;
	std::pmr::vector<std::byte> tls_exporter;
	std::optional<channel_binding_type> default_channel_binding{};
	// An authentication (a SASL bind) used tls_exporter: RFC 9266 section
	// 4.1 forbids a second use on the connection, so later binds are not
	// given it (detail::authentication_channel_bindings). Cleared with the
	// rest by detail::clear_tls_session.
	bool tls_exporter_used = false;
	// kind::custom: the wrapped stream, owned (allocated from mr) and
	// destroyed by transport::destroy() after `stream`, which refers to it.
	void *custom = nullptr;
	transport::custom_ops custom_ops{};
	bool custom_closed = false;
	boost::capy::any_stream stream{};
};

struct transport_access
{
	static auto make(transport::kind k, std::string_view name, std::pmr::memory_resource *mr) -> transport
	{
		return transport::make(k, name, mr);
	}
	static auto get(transport &t) noexcept -> transport::impl & { return *t.impl_; }
	static auto get(const transport &t) noexcept -> const transport::impl & { return *t.impl_; }
};

}// namespace jhetz::ldap::net
