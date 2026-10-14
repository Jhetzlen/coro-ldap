// Internal: the TLS client handshake shared by ldaps:// (connect.cpp) and
// StartTLS (step 7). Split in two so configuration errors surface before any
// network traffic: make_tls_setup() reads and checks the files, then
// tls_handshake() layers an openssl_stream in reference mode over the
// transport's plain tcp_socket and runs the client handshake.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/net/connect.hpp"

#include "deadline.hpp"
#include "transport_impl.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/tls_context.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace jhetz::ldap::net::detail {

// Shared with the verify callback: why it rejected the peer, e.g.
// "hostname mismatch (certificate depth 0)" (empty if it did not), and the
// DNS name to match strictly (host_name_matching::strict; empty for an IP
// literal or legacy matching), set by tls_handshake().
struct verify_failure
{
	std::string reason{};
	std::string strict_host{};
};

struct tls_setup
{
	boost::corosio::tls_context context{};
	std::shared_ptr<verify_failure> failure = std::make_shared<verify_failure>();
};

// Builds the client context from `options`: verification mode and trust
// anchors, client certificate, minimum version, server_name check. Every
// file is read and every certificate parsed here. Errors have contexts
// starting with "tls: ".
auto make_tls_setup(const tls_options &options) -> result<tls_setup>;

// The name for SNI and certificate verification: options.server_name if
// set, else `host` without an IPv6 zone ("fe80::1%eth0" -> "fe80::1"): the
// zone is local routing information, not part of the certificate's
// iPAddress.
auto tls_peer_name(std::string_view host, const tls_options &options) -> std::string;

// Requires im.tcp connected and !im.tls. `host` is the URL host; the name
// used for SNI and verification is options.server_name if set, else `host`
// without an IPv6 zone. On success im.tls and im.tls_context are set and
// im.stream points at the TLS layer; on an error or a throw (bad_alloc)
// neither is, and im.stream is unchanged. Errors have the context "tls
// handshake" (plus ": server certificate: <reason>" when verification failed).
auto tls_handshake(transport::impl &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net::detail
