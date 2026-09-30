// Opening a transport for an LDAP URL (DESIGN.md section 7).
//
//   corosio::io_context ioc;
//   auto u = ldap::url::parse("ldaps://ldap.example.org");
//   ldap::result<net::transport> t = co_await net::connect(ioc, *u, {.timeout = 5s});
//
// ldap://   resolve the host, try each address in order, TCP_NODELAY on.
// ldaps://  the same, then a TLS client handshake (tls_options below).
// ldapi://  connect to the Unix domain socket named by the URL's host part.
//           Supported where Corosio has local_stream_socket (Linux, other
//           POSIX systems); tested on Linux only. The path must fit in
//           sockaddr_un (corosio::local_endpoint::max_path_length bytes).
//
// URLs connect() rejects with client_errc::invalid_url: an empty host (RFC
// 4516 leaves the server to client configuration; there is no portable
// default ldapi socket either), a host with control characters once decoded
// (`%00` would truncate it in C APIs; a leading NUL in an ldapi path, a Linux
// abstract socket, is allowed), and a URL with a critical extension (none is
// supported, RFC 4516 section 2.1). The DN and later parts are ignored.
//
// Errors are ldap::error with the underlying error_code kept as is (system
// errors such as connection_refused, Capy's timeout and canceled, OpenSSL
// errors from corosio::openssl_category()) and a context naming the target
// and the stage, e.g.
//   "connect ldaps://ldap.example.org:636: resolve"
//   "connect ldap://127.0.0.1:389: tcp connect 127.0.0.1:389"
//   "connect ldaps://localhost:636: tls handshake: server certificate: hostname mismatch (certificate depth 0)"
// A timeout fails with an error comparing equal to boost::capy::cond::timeout,
// naming the stage that was running.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tls_context.hpp>

#include <chrono>
#include <memory_resource>
#include <string>

namespace jhetz::ldap::net {

// How the server certificate is checked. There is deliberately no boolean:
// switching verification off has to be spelled out.
enum class certificate_verification : unsigned char {
	// Default: the chain must lead to a trusted CA, and the certificate must
	// match the host name (DNS name, or iPAddress entry for an IP literal).
	full,
	// Accept any certificate, including a self-signed or expired one for
	// another host. Anyone on the network path can then impersonate the
	// server and read the bind password. For tests and lab setups only.
	insecure_accept_any,
};

// TLS settings for ldaps:// (and StartTLS, step 7). The defaults are secure:
// certificate verification with the system trust store, host name check, SNI,
// TLS 1.2 or later. Strings are std::pmr::string (DESIGN.md section 8); from a
// std::string write `.ca_file = std::pmr::string(path)`.
struct tls_options
{
	certificate_verification verification = certificate_verification::full;

	// Trust anchors. If none of the three is set, the system default store is
	// used (OpenSSL honours SSL_CERT_FILE and SSL_CERT_DIR). Setting any of
	// them replaces the system store; they may be combined.
	std::pmr::string ca_file{};// PEM file with one or more CA certificates
	std::pmr::string ca_dir{};// directory hashed with `openssl rehash`
	std::pmr::string ca_pem{};// CA certificates as PEM text

	// Client certificate (mutual TLS / SASL EXTERNAL): PEM chain + PEM key.
	// Both or neither.
	std::pmr::string cert_file{};
	std::pmr::string key_file{};

	// Name sent as SNI and matched against the certificate. Empty: the URL's
	// host. Set it when connecting by address to a server whose certificate
	// only names its DNS name.
	std::pmr::string server_name{};

	boost::corosio::tls_version min_version = boost::corosio::tls_version::tls_1_2;
};

struct connect_options
{
	// Budget for the whole connect: resolve, every TCP attempt and the TLS
	// handshake together. Zero, negative or above 100 years: no limit.
	std::chrono::milliseconds timeout{ std::chrono::seconds(30) };
	tls_options tls{};
	// TCP_NODELAY on TCP transports: LDAP sends small requests and waits for
	// the answer, which Nagle's algorithm would delay.
	bool tcp_no_delay = true;
};

// Connects to the server named by `u`. `ioc` must outlive the transport and
// the returned task must run on `ioc`'s executor (connect() uses Corosio
// timers, which need an io_context). Arguments are taken by value, so the
// task does not depend on the caller's objects.
boost::capy::task<result<transport>> connect(boost::corosio::io_context &ioc, url u, connect_options options = {});

}// namespace jhetz::ldap::net
