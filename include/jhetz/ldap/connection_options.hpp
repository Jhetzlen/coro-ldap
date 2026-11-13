// The options of ldap::connect() and of an ldap::connection.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"

#include <chrono>
#include <cstddef>
#include <optional>

namespace jhetz::ldap {

struct connection_options
{
	// The whole connect; nullopt: no limit.
	std::optional<std::chrono::milliseconds> timeout{ net::connect_options::default_timeout };
	net::tls_options tls{};
	// Happy Eyeballs delay between connection attempts.
	std::chrono::milliseconds attempt_delay{ net::connect_options::default_attempt_delay };
	bool tcp_no_delay = true;
	// How long unbind() waits for the server's TLS close_notify; nullopt: no
	// limit.
	std::optional<std::chrono::milliseconds> tls_shutdown_timeout{ std::chrono::seconds(1) };
	// Largest PDU accepted from the server, checked from its header.
	std::size_t max_message_size = ber::default_max_message_size;
	// Most strings one response may decode to.
	std::size_t max_elements = default_max_elements;
	// Default limit for each operation; nullopt: none. An operation's own
	// `timeout` overrides it.
	std::optional<std::chrono::milliseconds> operation_timeout{};
	// ldap::connect() only: StartTLS right after connecting; not with ldaps://
	// or ldapi://.
	bool start_tls = false;
};

}// namespace jhetz::ldap
