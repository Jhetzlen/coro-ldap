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

struct ssl_st;// OpenSSL's SSL

namespace jhetz::ldap::net::detail {

// Shared between tls_handshake() and the verify callback, which runs
// during every handshake that receives a certificate, whatever the
// verification mode.
struct verify_state
{
	// Why the callback rejected the peer, e.g. "hostname mismatch
	// (certificate depth 0)"; empty if it did not.
	std::string reason{};
	// The DNS name to match strictly (host_name_matching::strict), set by
	// tls_handshake(); empty for an IP literal or legacy matching.
	std::string strict_host{};
	// The client's OpenSSL session. Corosio's openssl_stream does not expose
	// its SSL, but the verify callback reaches it (the store's ex_data).
	// Owned by the stream: only dereferenced by tls_handshake(), right after
	// the handshake succeeded (record_tls_session), which then resets it.
	ssl_st *ssl = nullptr;
};

struct tls_setup
{
	boost::corosio::tls_context context{};
	std::shared_ptr<verify_state> state = std::make_shared<verify_state>();
};

// Works around a Corosio race (coro-ldap-cx0): openssl_native_context
// allocates its process-wide SSL_CTX ex_data slot (sni_ctx_data_index)
// lazily and without synchronisation, when the first SSL_CTX is built, at a
// tls_context's first handshake. Two threads doing that at once can each
// allocate a slot and store their context data under one the other then
// overwrites; Corosio's verify trampoline later finds no data and returns
// OpenSSL's verdict without calling our verify callback (no peer
// certificate, no channel bindings, no strict host check). This runs one
// throwaway client handshake, on a thread of its own, against a stream
// that fails at once: building its SSL_CTX allocates the slot. A mutex
// makes every caller wait until that is done, so no first use can race it.
// make_tls_setup() calls it; any other thread that uses Corosio's OpenSSL
// streams while ours may run (the tests' servers) calls it before its first
// handshake. Returns false if the warm-up could not run (no thread,
// bad_alloc); the next call tries again, and tls_handshake() still fails
// closed meanwhile.
auto prime_corosio_openssl() noexcept -> bool;

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
// neither is, and im.stream is unchanged. On success the peer certificate
// and the channel bindings are recorded in im (record_tls_session), and
// renegotiation is off. A handshake that succeeded without running the
// verify callback (no certificate, or the Corosio race above) fails with
// client_errc::internal_error: it would have no peer data and, under full
// verification, no strict host check. That branch has no deterministic
// test: the race is not reproducible on demand and every certificate-based
// handshake runs the callback. Errors have the context "tls handshake"
// (plus ": server certificate: <reason>" when verification failed).
auto tls_handshake(transport::impl &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net::detail
