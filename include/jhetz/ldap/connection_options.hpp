// The options of ldap::connect() and of an ldap::connection
// (connection.hpp): connect timeout and TLS, message and decoding limits,
// the default operation timeout, StartTLS on connect, schema checks of the
// typed operations and the password change method. Part of jhetz::ldap_net.
//
//   auto c = co_await ldap::connect(ioc, "ldap://ldap.example.org", {
//       .timeout           = 5s,
//       .operation_timeout = 30s,
//       .start_tls         = true,
//   });
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"

#include <chrono>
#include <cstddef>
#include <optional>

namespace jhetz::ldap {

// When typed operations check their struct against the server's schema
// (DESIGN.md section 6).
enum class schema_check {
	off,
	// The first search_as / modify<T> / add(dn, T) for each T loads the
	// subschema (once per connection) and runs validate<T>; errors in the
	// report fail the operation with client_errc::schema_mismatch (the
	// report in the context). The result is cached per connection and T,
	// and dropped by start_tls() (RFC 4513 section 3.1.5: what was read in
	// clear is read again over TLS).
	on_first_use,
};

// How connection::change_password and reset_password change a password.
enum class password_method {
	// Pick from the root DSE, read when first needed (one base search) and
	// kept for the connection until start_tls() (RFC 4513 section 3.1.5:
	// what was read in clear is read again over TLS): rfc3062 if its
	// supportedExtension lists password_modify_oid, else active_directory
	// if its supportedCapabilities lists ad::ds_capability_oid
	// (Samba AD too), else client_errc::no_password_method. A server
	// offering both gets rfc3062. A root DSE hidden by access controls
	// advertises neither: choose the method explicitly then.
	automatic,
	// RFC 3062 Password Modify (password_modify()). Never reads the root DSE.
	rfc3062,
	// Active Directory: a ModifyRequest of unicodePwd (ad_password_value()),
	// which needs TLS. Never reads the root DSE.
	active_directory,
};

struct connection_options
{
	// Budget for the whole connect (resolve, TCP, TLS handshake); see
	// net::connect_options. nullopt: no limit.
	std::optional<std::chrono::milliseconds> timeout{ net::connect_options::default_timeout };
	net::tls_options tls{};
	// Happy Eyeballs delay between connection attempts (see
	// net::connect_options::attempt_delay).
	std::chrono::milliseconds attempt_delay{ net::connect_options::default_attempt_delay };
	bool tcp_no_delay = true;
	// unbind() on a TLS connection (ldaps:// or after StartTLS) sends a TLS
	// close_notify and waits at most this long for the server's before
	// closing (net::transport::shutdown). nullopt: no limit.
	std::optional<std::chrono::milliseconds> tls_shutdown_timeout{ std::chrono::seconds(1) };
	// Largest PDU accepted from the server, checked from its header before
	// the body is read (client_errc::message_too_large, which closes the
	// connection). 16 MiB by default: one entry of a large group or with
	// photos and certificates can legitimately take several MiB.
	std::size_t max_message_size = ber::default_max_message_size;
	// Most strings one response may decode to (decode_options::max_elements):
	// bounds the memory a PDU of many tiny values takes once decoded. More
	// fail with client_errc::message_too_large, which closes the connection
	// like any response that does not decode.
	std::size_t max_elements = default_max_elements;
	// Default limit for each operation, from sending its request to its
	// final response (for a search: to the SearchResultDone, across every
	// next()). On expiry the operation fails with capy::error::timeout and
	// is abandoned. nullopt: no limit (cancel with a stop token instead).
	// An operation's own `timeout` overrides it, ldap::no_timeout for none.
	std::optional<std::chrono::milliseconds> operation_timeout{};
	// ldap::connect() only: upgrade an ldap:// connection with StartTLS
	// right after connecting (using `tls` and `timeout`), and fail if that
	// does not work. Not allowed with ldaps:// or ldapi:// (invalid_url).
	bool start_tls = false;
	ldap::schema_check schema_check = ldap::schema_check::off;
	// The method change_password() and reset_password() use unless a call
	// names one.
	ldap::password_method password_method = ldap::password_method::automatic;
};

}// namespace jhetz::ldap
