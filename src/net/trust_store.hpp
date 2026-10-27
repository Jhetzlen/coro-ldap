// Internal: the trust anchors of default verification (tls_options with no
// ca_file, ca_dir or ca_pem). Off Windows OpenSSL reads them itself
// (SSL_CERT_FILE, SSL_CERT_DIR, its compiled-in paths). On Windows, where
// OpenSSL reads no system store, they come from the CryptoAPI "ROOT" store
// (trust_store_win.cpp, the only Windows-specific part): enumerated per
// connection, filtered (system_certificate below), each passed to Corosio as
// PEM.
//
// On Windows, default verification also hands the server's chain to
// CryptoAPI (verify_system_chain), whose verdict replaces OpenSSL's on
// the chain: CryptoAPI fetches the AuthRoot roots Windows downloads on
// demand (a root never fetched is not in ROOT yet), and applies Windows'
// root program and revocation checks. The ROOT anchors still go to
// OpenSSL, which then builds and checks the chain as elsewhere; only its
// verdicts on the leaf alone are kept (tls.cpp fatal_with_platform_chain:
// the host name, the leaf's key size and its purpose), and CryptoAPI is
// given OpenSSL's security level for the rest of the chain
// (strong_sign_for_level).
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

// CryptoAPI's strong signature lists (CERT_STRONG_SIGN_SERIALIZED_INFO,
// given to CertGetCertificateChain) for OpenSSL's security level
// `security_level` (the X509_VERIFY_PARAM auth level OpenSSL checks the
// server's chain against: SSL_get_security_level, 2 by default since
// OpenSSL 3.2), so that CryptoAPI's verdict on the chain is not weaker than
// OpenSSL's CA_KEY_TOO_SMALL and CA_MD_TOO_WEAK checks it replaces. Level
// n requires the security bits of OpenSSL's table (crypto/x509/x509_vfy.c
// minbits_table: 80, 112, 128, 192, 256; above 5 as 5), which OpenSSL rates
// as: RSA keys of 1024, 2048, 3072, 7680, 15360 bits
// (ossl_ifc_ffc_compute_security_bits), EC curves of twice the bits
// (OpenSSL rates a curve at half its size), and signature hashes of twice
// the bits (half the digest size; SHA-1 counts 63, below every level, in
// crypto/x509/x509_set.c). So level 2 is
// "RSA/2048;ECDSA/224" and the RSA and ECDSA signatures with SHA-256,
// SHA-384 or SHA-512. Stricter than OpenSSL only where CNG has no name:
// SHA-224, DSA and EdDSA signatures are not listed, so they count as weak.
// nullopt at level 0 or below (OpenSSL checks nothing then).
struct strong_sign_lists
{
	// pwszCNGSignHashAlgids: "RSA/SHA256;ECDSA/SHA256;...".
	std::wstring sign_hash_algids{};
	// pwszCNGPubKeyMinBitLengths: "RSA/2048;ECDSA/224".
	std::wstring min_key_bits{};
};
auto strong_sign_for_level(int security_level) -> std::optional<strong_sign_lists>;

// Verifies the server certificate chain `chain` (DER: the leaf, then the
// other certificates the server sent) for TLS server authentication with
// the platform's chain engine and SSL policy (Windows:
// CertGetCertificateChain for serverAuth, revocation checked for every
// certificate but the root, then CertVerifyCertificateChainPolicy with
// CERT_CHAIN_POLICY_SSL; a revocation status that cannot be determined,
// e.g. an unreachable CRL, is not an error, a revoked certificate is).
// Signatures and keys below OpenSSL's `security_level` are rejected
// (strong_sign_for_level). The host name is not checked: it stays
// OpenSSL's (host_name_matching).
// `timeout` (what is left of the deadline; nullopt: none) bounds only the
// revocation retrieval, every CRL and OCSP URL together
// (revocation_retrieval_budget). The intermediates CryptoAPI fetches from
// AIA URLs and the roots and lists of AuthRoot auto-update are fetched
// with the chain engine's own per-URL timeout (Windows' default; Microsoft
// documents CERT_CHAIN_PARA::dwUrlRetrievalTimeout for revocation only),
// so the call can take longer than `timeout`: the revocation budget plus
// that timeout per such URL. Blocks the calling thread throughout. Errors
// have the context "Windows certificate chain: <why>". Not available off
// Windows (std::errc::function_not_supported).
// The cap on verify_system_chain's revocation retrieval: revocation is
// soft-fail, so waiting longer only delays the same verdict, with the
// thread blocked.
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
