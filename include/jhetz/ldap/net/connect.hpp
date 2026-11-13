// Opening a transport for an LDAP URL (DESIGN.md section 7).
//
//   corosio::io_context ioc;
//   auto u = ldap::url::parse("ldaps://ldap.example.org");
//   ldap::result<net::transport> t = co_await net::connect(ioc, *u, {.timeout = 5s});
//
// ldap://   resolve the host, connect with Happy Eyeballs (below), TCP_NODELAY on.
// ldaps://  the same, then a TLS client handshake (tls_options below).
// ldapi://  connect to the Unix domain socket named by the URL's host part,
//           through Corosio's local_stream_socket. The path must fit in
//           sockaddr_un (corosio::local_endpoint::max_path_length bytes).
//           Windows (AF_UNIX, Windows 10 1803+): code-only so far; Winsock
//           reads sun_path in the ANSI code page, so a path outside it
//           (non-ASCII on most systems) may not reach the right file.
//
// URLs connect() rejects with client_errc::invalid_url: an empty host (RFC
// 4516 leaves the server to client configuration; there is no portable
// default ldapi socket either), a host with control characters once decoded
// (`%00` would truncate it in C APIs; a leading NUL in an ldapi path, a Linux
// abstract socket, is allowed on Linux only), and a URL with a critical extension (none is
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
// work, so io_context::run() only returns once getaddrinfo has.
//
// Several addresses (Happy Eyeballs, RFC 8305): the addresses are reordered
// to alternate IPv6 and IPv4, starting with the family getaddrinfo put first.
// The first attempt starts at once; each next one starts when the previous
// one fails or after connect_options::attempt_delay, whichever comes first.
// Attempts then run side by side; the first to connect wins and the others
// are cancelled. A black-holed address so costs attempt_delay, not the
// budget. When every attempt fails, the error is the last failure's, e.g.
//   "connect ldap://ldap.example.org:389: tcp connect 192.0.2.7:389 (2 of 2 addresses tried)"
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

// How the host name is matched against the server certificate (with
// certificate_verification::full). IP literals are matched against
// iPAddress entries either way.
enum class host_name_matching : unsigned char {
	// Default (RFC 6125, RFC 4513 section 3.1.3): only subjectAltName DNS
	// names count, never the subject CN, and a wildcard must be the whole
	// leftmost label (`*.example.org`, not `ldap*.example.org`).
	strict,
	// OpenSSL 3's defaults: the subject CN is used when the certificate has
	// no subjectAltName DNS name, and partial wildcards match. For old
	// certificates only.
	legacy,
};

// TLS settings for ldaps:// and StartTLS. The defaults are secure: the
// system trust store, host name check, SNI, TLS 1.2 or later. Not
// allocator-aware (the pmr strings use the default resource). Files and
// directories are read and checked when connect() starts, before any
// network traffic: an unreadable file, a CA that does not parse, or a
// missing ca_dir fail at once.
struct tls_options
{
	certificate_verification verification = certificate_verification::full;

	// Trust anchors. If none of the three is set, the system default store
	// is used: OpenSSL's (SSL_CERT_FILE, SSL_CERT_DIR), or on Windows
	// CryptoAPI (CertGetCertificateChain with the SSL policy, soft-fail
	// revocation, held to OpenSSL's security level; host_matching as
	// elsewhere). CryptoAPI blocks the io_context's thread during the
	// handshake; the connect or StartTLS timeout bounds only its
	// revocation fetches (at most 20 s), not AIA or root fetches. Setting
	// any of them replaces the system store; they may be combined.
	std::filesystem::path ca_file{};// PEM file with one or more CA certificates
	// Directory hashed with `openssl rehash`. OpenSSL reads it lazily through
	// char paths: on Windows keep its path ASCII (files are opened by UTF-8
	// name but looked up with the ANSI stat()). The other files take any
	// name: they are read through std::filesystem::path.
	std::filesystem::path ca_dir{};
	std::pmr::string ca_pem{};// CA certificates as PEM text

	// Client certificate (mutual TLS / SASL EXTERNAL): PEM chain + PEM key.
	// Both or neither.
	std::filesystem::path cert_file{};
	std::filesystem::path key_file{};

	// Name sent as SNI and matched against the certificate. Empty: the URL's
	// host. Set it when connecting by address to a server whose certificate
	// only names its DNS name. Control characters (NUL included) are rejected.
	std::pmr::string server_name{};
	host_name_matching host_matching = host_name_matching::strict;

	boost::corosio::tls_version min_version = boost::corosio::tls_version::tls_1_2;
};

struct connect_options
{
	// The defaults of timeout and attempt_delay.
	static constexpr std::chrono::milliseconds default_timeout = std::chrono::seconds(30);
	static constexpr std::chrono::milliseconds default_attempt_delay = std::chrono::milliseconds(250);

	// Budget for the whole connect: resolve, every TCP attempt and the TLS
	// handshake together, from the start of the call. nullopt: no limit.
	// Zero or negative: fails at once with boost::capy::error::timeout.
	std::optional<std::chrono::milliseconds> timeout{ default_timeout };
	tls_options tls{};
	// Happy Eyeballs "Connection Attempt Delay" (RFC 8305 section 5, which
	// recommends 250 ms): how long an attempt runs alone before the next
	// address is tried in parallel. Zero: every address at once.
	std::chrono::milliseconds attempt_delay{ default_attempt_delay };
	// TCP_NODELAY on TCP transports: LDAP sends small requests and waits for
	// the answer, which Nagle's algorithm would delay.
	bool tcp_no_delay = true;
};

// Connects to the server named by `u`. `ioc` must outlive the transport and
// the task must run on `ioc`'s executor. Its continuations must not run
// concurrently: a single-threaded io_context, or a strand (DESIGN.md section
// 8). The detached name lookup may finish on any thread. To stop it from
// another thread, see with_stop in connection.hpp (locking_mode::safe only).
// Arguments are taken by value. The transport's block and name are
// allocated from `mr`.
auto connect(boost::corosio::io_context &ioc,
  url u,
  connect_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<transport>>;

class read_buffer;

// Upgrades a plain TCP transport to TLS in place (StartTLS, RFC 4511
// section 4.14; the LDAP exchange before it is the connection's job). The
// same verification rules as ldaps:// apply (`options`; the name checked is
// options.server_name, else t.host()). Fails without touching the
// transport if it is not plain TCP (invalid_argument), if `pending` holds
// unread bytes (decode_error: they arrived before the handshake, so they
// were not protected; the plaintext injection of CVE-2011-0411), or if the
// TLS configuration is bad. A failed handshake leaves the transport
// unusable: close it. If the handshake or its setup throws (bad_alloc), the
// transport is closed (and not is_tls()) before the exception propagates.
// `timeout` bounds the handshake (nullopt: no limit).
// `t` and `pending` must outlive the task; no other read or write may be in
// flight on `t` meanwhile.
auto start_tls(transport &t,
  const read_buffer &pending,
  tls_options options,
  std::optional<std::chrono::milliseconds> timeout = std::nullopt) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net
