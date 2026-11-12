// Internal: the parts of net::transport that connect() fills in.
#pragma once

#include "jhetz/ldap/net/transport.hpp"

#include "sasl_layer.hpp"

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

// Destroyed in this order, each part before the one it refers to: the SASL
// layer's view (`layered`), the SASL layer, then for kind::custom the
// type-erased view and the custom stream; then the members in reverse
// order: the type-erased view, the TLS stream (which refers to the TCP
// socket), the TLS context and the sockets.
struct transport::layers
{
	explicit layers(std::pmr::memory_resource *r)
	  : mr(r), name(r), host(r), peer_certificate(r), tls_server_end_point(r), tls_exporter(r)
	{}
	layers(const layers &) = delete;
	auto operator=(const layers &) -> layers & = delete;
	layers(layers &&) = delete;
	auto operator=(layers &&) -> layers & = delete;
	~layers()
	{
		layered = {};
		sasl_layer.reset();
		if (custom != nullptr) {
			stream = {};
			custom_ops.destroy(custom, mr);
		}
	}

	std::pmr::memory_resource *mr;// this struct was allocated from it
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
	// destroyed by ~layers() after `stream`, which refers to it.
	void *custom = nullptr;
	transport::custom_ops custom_ops{};
	bool custom_closed = false;
	boost::capy::any_stream stream{};
	// The SASL security layer over `stream` (detail::install_security_layer),
	// and the view of it that stream() returns once it is set. Declared
	// after `stream`, which the layer refers to, so destroyed before it.
	std::optional<detail::sasl_layer_stream> sasl_layer{};
	boost::capy::any_stream layered{};
};

struct transport_access
{
	static auto make(transport::kind k, std::string_view name, std::pmr::memory_resource *mr) -> transport
	{
		return transport::make(k, name, mr);
	}
	static auto get(transport &t) noexcept -> transport::layers & { return *t.layers_; }
	static auto get(const transport &t) noexcept -> const transport::layers & { return *t.layers_; }
};

}// namespace jhetz::ldap::net
