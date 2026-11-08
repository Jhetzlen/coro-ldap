// Internal: the TLS client handshake shared by ldaps:// (connect.cpp) and
// StartTLS. Split in two so configuration errors surface before any
// network traffic: make_tls_setup() reads and checks the files, then
// tls_handshake() layers an openssl_stream in reference mode over the
// transport's plain tcp_socket and runs the client handshake.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/net/connect.hpp"

#include "deadline.hpp"
#include "transport_layers.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/tls_context.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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
	// Default verification where the platform verifies the chain
	// (platform_verifies_chain(), Windows): OpenSSL's verdict on the chain
	// is replaced by this function's (verify_system_chain, trust_store.hpp),
	// run once at the leaf with OpenSSL's security level; its verdicts on
	// the leaf alone are kept (fatal_with_platform_chain). Set by
	// make_tls_setup(); null otherwise (tests may set a stand-in).
	using chain_verifier = auto (*)(std::span<const std::vector<unsigned char>> chain,
	  int security_level,
	  std::optional<std::chrono::milliseconds> timeout) -> result<void>;
	chain_verifier system_chain = nullptr;
	// verify_system_chain ran and accepted the chain. The callback then
	// resets the store's error to X509_V_OK (also after the errors it lets
	// through later), so SSL_get_verify_result() reports success; nothing
	// reads it today.
	bool system_chain_verified = false;
	// The handshake's deadline (tls_handshake()), which bounds
	// verify_system_chain's revocation retrieval (only: trust_store.hpp).
	deadline_t deadline{};
};

// Whether OpenSSL's verify error `error` (X509_V_ERR_*) at certificate
// depth `depth` still fails the handshake when the platform verifies the
// chain (verify_state::system_chain): the host name and IP address
// mismatches, EE_KEY_TOO_SMALL, and INVALID_PURPOSE at depth 0. The others
// are left to the platform.
auto fatal_with_platform_chain(int error, int depth) noexcept -> bool;

struct tls_setup
{
	boost::corosio::tls_context context{};
	std::shared_ptr<verify_state> state = std::make_shared<verify_state>();
};

// Works around a Corosio race (DESIGN.md section 3): runs one throwaway
// client handshake on a thread of its own so that Corosio allocates its
// process-wide SSL_CTX ex_data slot; a mutex makes every caller wait until
// that is done. make_tls_setup() calls it, and so must any other thread
// using Corosio's OpenSSL streams (the tests' servers) before its first
// handshake. Returns false if the warm-up could not run; the next call tries
// again.
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

// Requires im.tcp connected and !im.tls. `host` is the URL host (the peer
// name is tls_peer_name's). On success im.tls and im.tls_context are set,
// im.stream points at the TLS layer, the peer certificate and channel
// bindings are recorded (record_tls_session) and renegotiation is off; on
// an error or a throw none of that changes. A handshake that succeeded
// without running the verify callback (no certificate, or the Corosio race
// above), or under system chain verification without reaching it, fails
// with client_errc::internal_error. Errors have the context "tls handshake"
// (plus ": server certificate: <reason>" when verification failed).
auto tls_handshake(transport::layers &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net::detail
