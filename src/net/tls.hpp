// The TLS client handshake shared by ldaps:// and StartTLS:
// make_tls_setup() checks the configuration, tls_handshake() runs it.
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

// Shared between tls_handshake() and the verify callback.
struct verify_state
{
	// Why the callback rejected the peer; empty if it did not.
	std::string reason{};
	// The DNS name to match strictly (host_name_matching::strict), set by
	// tls_handshake(); empty for an IP literal or legacy matching.
	std::string strict_host{};
	// The DNS name for the subject CN fallback (host_name_matching::legacy).
	std::string legacy_host{};
	// The client's OpenSSL session, owned by the stream; read only right after
	// the handshake.
	ssl_st *ssl = nullptr;
	// Where the platform verifies the chain (Windows): replaces OpenSSL's
	// chain verdict; null otherwise.
	using chain_verifier = auto (*)(std::span<const std::vector<unsigned char>> chain,
	  int security_level,
	  std::optional<std::chrono::milliseconds> timeout) -> result<void>;
	chain_verifier system_chain = nullptr;
	// verify_system_chain ran and accepted the chain.
	bool system_chain_verified = false;
	// The handshake's deadline (tls_handshake()), which bounds
	// verify_system_chain's revocation retrieval (only: trust_store.hpp).
	deadline_t deadline{};
};

// Whether OpenSSL's verify `error` at `depth` still fails the handshake
// when the platform verifies the chain.
auto fatal_with_platform_chain(int error, int depth) noexcept -> bool;

struct tls_setup
{
	boost::corosio::tls_context context{};
	std::shared_ptr<verify_state> state = std::make_shared<verify_state>();
};

// Runs one throwaway handshake so that Corosio allocates its ex_data slot
// (DESIGN.md section 3); every thread using Corosio's OpenSSL streams calls
// it first. False if it could not run.
auto prime_corosio_openssl() noexcept -> bool;

// Builds the client context from `options`, reading every file and parsing
// every certificate; errors start with "tls: ".
auto make_tls_setup(const tls_options &options) -> result<tls_setup>;

// Drops the client certificate and key (files and PEM text), so that
// make_tls_setup() presents none.
void clear_client_credentials(tls_options &options) noexcept;

// options.server_name, else `host` without an IPv6 zone or a trailing dot.
auto tls_peer_name(std::string_view host, const tls_options &options) -> std::string;

// Runs the client handshake over im.tcp (connected, !im.tls); on success
// sets the TLS layer and records the session, on failure changes nothing.
// Errors have the context "tls handshake".
auto tls_handshake(transport::layers &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net::detail
