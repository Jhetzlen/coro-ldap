// Internal: the trust anchors of default verification (tls_options with no
// ca_file, ca_dir or ca_pem). Off Windows OpenSSL reads them itself
// (SSL_CERT_FILE, SSL_CERT_DIR, its compiled-in paths). On Windows, where
// OpenSSL reads no system store, they come from the CryptoAPI "ROOT" store
// (trust_store_win.cpp, the only Windows-specific part): enumerated per
// connection, filtered (system_certificate below), each passed to Corosio as
// PEM.
//
// Known gap: Windows downloads most Microsoft-trusted roots on demand
// (AuthRoot auto-update) while CryptoAPI builds a chain; a root that was
// never fetched is not in ROOT yet, so a server chaining to it fails to
// verify here although CryptoAPI clients accept it. Install the root (or
// pass ca_file) meanwhile.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <boost/corosio/tls_context.hpp>

#include <span>
#include <string>
#include <vector>

namespace jhetz::ldap::net::detail {

// One certificate of a system store, with what the store says about it.
struct system_certificate
{
	std::vector<unsigned char> der{};
	// The store's extended key usage property allows TLS server
	// authentication (or restricts nothing), and its disallowed extended
	// key usage property does not list it.
	bool server_auth = true;
	// Distrusted: marked disallowed (CERT_DISALLOWED_FILETIME_PROP_ID) or
	// also in the "Disallowed" store.
	bool distrusted = false;
};

// The anchors to trust from `certs`, as PEM: those allowed for server
// authentication and not distrusted, whose DER parses as one whole X.509
// certificate (d2i_X509; others are skipped). Corosio parses CAs as PEM only
// and fails the handshake on any bad one, hence the parse and the PEM.
// Leaves nothing on the thread's OpenSSL error queue.
auto trust_anchors_pem(std::span<const system_certificate> certs) -> std::vector<std::string>;

// Adds `anchors` to `ctx`. Fails with std::errc::no_such_file_or_directory
// when there is none (verification would reject every server), context
// "<what>: no usable trust anchor".
auto add_trust_anchors(boost::corosio::tls_context &ctx, std::span<const std::string> anchors, const std::string &what)
  -> result<void>;

// The platform's default trust anchors into `ctx`; errors have the context
// "tls: system trust store[: ...]". Defined in trust_store_default.cpp, or
// trust_store_win.cpp on Windows (CMake picks one).
auto load_system_trust(boost::corosio::tls_context &ctx) -> result<void>;

}// namespace jhetz::ldap::net::detail
