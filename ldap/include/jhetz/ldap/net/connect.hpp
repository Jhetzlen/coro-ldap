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
//
// Timeouts: connect_options::timeout bounds the whole call, measured from its
// start. The name lookup runs detached (Corosio's getaddrinfo on a pool
// thread cannot be interrupted): on timeout connect() returns at once and the
// lookup's late result is dropped. The io_context still counts that lookup as
// work, so io_context::run() only returns once getaddrinfo has. With several addresses, each TCP attempt
// gets min(remaining, max(remaining / addresses left, 1 s)), so one
// black-holed address does not use up the budget of the others.
//
// Host name checks (inherited from OpenSSL through Corosio, which does not
// expose the flags): a DNS name is matched against the subjectAltName DNS
// entries, and against the subject CN when the certificate has no
// subjectAltName at all; wildcards such as `*.example.org` and partial ones
// such as `ld*.example.org` are accepted in the leftmost label only. An IP
// literal is matched against iPAddress entries (an IPv6 zone is not part of
// the match and not sent as SNI).
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tls_context.hpp>

#include <chrono>
#include <filesystem>
#include <memory_resource>
#include <optional>
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
// TLS 1.2 or later. A plain aggregate on purpose: this is configuration, read
// once per connect, not a hot path, so it is not allocator-aware (the pmr
// strings use the default resource). Files and directories are read and
// checked when connect() starts, before any network traffic: an unreadable
// file, a CA that does not parse, or a missing ca_dir fail at once.
struct tls_options
{
	certificate_verification verification = certificate_verification::full;

	// Trust anchors. If none of the three is set, the system default store is
	// used (OpenSSL honours SSL_CERT_FILE and SSL_CERT_DIR). Setting any of
	// them replaces the system store; they may be combined.
	std::filesystem::path ca_file{};// PEM file with one or more CA certificates
	std::filesystem::path ca_dir{};// directory hashed with `openssl rehash`
	std::pmr::string ca_pem{};// CA certificates as PEM text

	// Client certificate (mutual TLS / SASL EXTERNAL): PEM chain + PEM key.
	// Both or neither.
	std::filesystem::path cert_file{};
	std::filesystem::path key_file{};

	// Name sent as SNI and matched against the certificate. Empty: the URL's
	// host. Set it when connecting by address to a server whose certificate
	// only names its DNS name. Control characters (NUL included) are rejected.
	std::pmr::string server_name{};

	boost::corosio::tls_version min_version = boost::corosio::tls_version::tls_1_2;
};

struct connect_options
{
	// Budget for the whole connect: resolve, every TCP attempt and the TLS
	// handshake together, from the start of the call. nullopt: no limit.
	// Zero or negative: fails at once with boost::capy::error::timeout.
	std::optional<std::chrono::milliseconds> timeout{ std::chrono::seconds(30) };
	tls_options tls{};
	// TCP_NODELAY on TCP transports: LDAP sends small requests and waits for
	// the answer, which Nagle's algorithm would delay.
	bool tcp_no_delay = true;
};

// Connects to the server named by `u`. `ioc` must outlive the transport and
// the returned task must run on `ioc`'s executor (connect() uses Corosio
// timers, which need an io_context). As for every Corosio/Capy operation,
// its continuations must not run concurrently: a single-threaded io_context,
// or a strand over a multi-threaded one (DESIGN.md section 8: one connection,
// one executor). The detached name lookup may finish on any thread; it hands
// its result over through a mutex and a capy::async_waker, which is safe
// across threads. Arguments are taken by value, so the task does not
// depend on the caller's objects. The transport's own block and name are
// allocated from `mr`.
boost::capy::task<result<transport>> connect(boost::corosio::io_context &ioc,
  url u,
  connect_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

class read_buffer;

// Upgrades a plain TCP transport to TLS in place (StartTLS, RFC 4511
// section 4.14; the LDAP exchange before it is the connection's job). The
// same verification rules as ldaps:// apply (`options`; the name checked is
// options.server_name, else t.host()). Fails without touching the
// transport if it is not plain TCP (invalid_argument), if `pending` holds
// unread bytes (decode_error: they arrived before the handshake, so they
// were not protected; the plaintext injection of CVE-2011-0411), or if the
// TLS configuration is bad. A failed handshake leaves the transport
// unusable: close it. `timeout` bounds the handshake (nullopt: no limit).
// `t` and `pending` must outlive the task; no other read or write may be in
// flight on `t` meanwhile.
boost::capy::task<result<void>> start_tls(transport &t,
  const read_buffer &pending,
  tls_options options,
  std::optional<std::chrono::milliseconds> timeout = std::nullopt);

}// namespace jhetz::ldap::net
