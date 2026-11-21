// The options of ldap::connect() and of an ldap::connection.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/timeout.hpp"

#include <chrono>
#include <cstddef>

namespace jhetz::ldap {

// Every timeout: ldap::no_timeout for no limit.
struct connection_options
{
	static constexpr std::chrono::milliseconds default_tls_shutdown_timeout = std::chrono::seconds(1);
	static constexpr std::chrono::milliseconds default_operation_timeout = std::chrono::seconds(30);

	// The whole connect.
	std::chrono::milliseconds timeout{ net::connect_options::default_timeout };
	net::tls_options tls{};
	// Happy Eyeballs delay between connection attempts.
	std::chrono::milliseconds attempt_delay{ net::connect_options::default_attempt_delay };
	bool tcp_no_delay = true;
	// How long unbind() waits for the server's TLS close_notify.
	std::chrono::milliseconds tls_shutdown_timeout{ default_tls_shutdown_timeout };
	// Largest PDU accepted from the server, checked from its header.
	std::size_t max_message_size = ber::default_max_message_size;
	// Most strings one response may decode to.
	std::size_t max_elements = default_max_elements;
	// Limit for each operation; an operation's own `timeout` overrides it.
	std::chrono::milliseconds operation_timeout{ default_operation_timeout };
	// Lets a simple bind's password and a Password Modify (RFC 3062) cross a
	// TCP connection with neither TLS nor a SASL confidentiality layer.
	bool allow_cleartext_passwords = false;
	// ldap::connect() only: StartTLS right after connecting; not with ldaps://
	// or ldapi://.
	bool start_tls = false;
};

}// namespace jhetz::ldap
