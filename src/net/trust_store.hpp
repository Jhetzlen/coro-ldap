// Internal: the trust anchors of default verification (tls_options with no
// ca_file, ca_dir or ca_pem). Off Windows OpenSSL reads them itself
// (SSL_CERT_FILE, SSL_CERT_DIR, its compiled-in paths). On Windows they come
// from the CryptoAPI "ROOT" store (trust_store_win.cpp), enumerated per
// connection, filtered (system_certificate) and passed to Corosio as PEM.
//
// On Windows, default verification also hands the server's chain to
// CryptoAPI (verify_system_chain), whose verdict replaces OpenSSL's on the
// chain; OpenSSL's verdicts on the leaf alone (host name, key size,
// purpose) are kept (tls.cpp fatal_with_platform_chain).
#pragma once

#include "jhetz/ldap/error.hpp"

#include <boost/corosio/tls_context.hpp>

#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace jhetz::ldap::net::detail {

// One certificate of a system store, with what the store says about it.
struct system_certificate
{
	std::vector<unsigned char> der{};
	// The store's extended key usage property allows TLS server
	// authentication (or restricts nothing), its disallowed extended key
	// usage property does not list it, and no NotBefore date applies to it
	// (CERT_NOT_BEFORE_FILETIME_PROP_ID: OpenSSL cannot trust a root for
	// certificates issued before a date only, so it is not trusted).
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

// Whether default verification (certificate_verification::full without
// ca_file, ca_dir or ca_pem) verifies the server's chain with
// verify_system_chain, whose verdict replaces OpenSSL's on the chain:
// true on Windows (CryptoAPI), false elsewhere (OpenSSL decides, with
// load_system_trust's anchors).
auto platform_verifies_chain() noexcept -> bool;

// CryptoAPI's strong signature lists (CERT_STRONG_SIGN_SERIALIZED_INFO, for
// CertGetCertificateChain) matching OpenSSL's security level
// `security_level` (SSL_get_security_level): the key sizes and signature
// hashes of OpenSSL's minbits_table for that level, e.g. level 2 is
// "RSA/2048;ECDSA/224" with SHA-256, SHA-384 or SHA-512. Stricter than
// OpenSSL for SHA-224, SHA-3, DSA, EdDSA and non-standard RSA sizes (DESIGN.md
// section 7). nullopt at level 0 or below.
struct strong_sign_lists
{
	// pwszCNGSignHashAlgids: "RSA/SHA256;ECDSA/SHA256;...".
	std::wstring sign_hash_algids{};
	// pwszCNGPubKeyMinBitLengths: "RSA/2048;ECDSA/224".
	std::wstring min_key_bits{};
};
auto strong_sign_for_level(int security_level) -> std::optional<strong_sign_lists>;

// Verifies the server certificate chain `chain` (DER, leaf first) for TLS
// server authentication with the platform's chain engine and SSL policy
// (Windows: CertGetCertificateChain for serverAuth with soft-fail revocation
// for every certificate but the root, then CertVerifyCertificateChainPolicy
// with CERT_CHAIN_POLICY_SSL), rejecting signatures and keys below
// `security_level` (strong_sign_for_level). The host name is not checked.
// `timeout` (nullopt: none) bounds only the revocation retrieval
// (revocation_retrieval_budget); AIA and AuthRoot fetches use the chain
// engine's own per-URL timeout. Blocks the calling thread. Errors have the
// context "Windows certificate chain: <why>". Off Windows:
// std::errc::function_not_supported.
// The cap on verify_system_chain's revocation retrieval.
inline constexpr std::chrono::milliseconds max_revocation_retrieval = std::chrono::seconds(20);

// verify_system_chain's budget for the revocation retrieval, every URL
// together (CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT): `timeout`, what is
// left of the deadline, at most max_revocation_retrieval, which also
// applies without a deadline (nullopt); at least 1 ms.
auto revocation_retrieval_budget(std::optional<std::chrono::milliseconds> timeout) noexcept
  -> std::chrono::milliseconds;

auto verify_system_chain(std::span<const std::vector<unsigned char>> chain,
  int security_level,
  std::optional<std::chrono::milliseconds> timeout) -> result<void>;

}// namespace jhetz::ldap::net::detail
