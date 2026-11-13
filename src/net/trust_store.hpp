// The trust anchors of default verification: OpenSSL's own off Windows,
// the CryptoAPI "ROOT" store on Windows, where CryptoAPI also verifies the
// chain.
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
	// Allowed for TLS server authentication by the store's properties, with no
	// NotBefore date.
	bool server_auth = true;
	// Distrusted: marked disallowed (CERT_DISALLOWED_FILETIME_PROP_ID) or
	// also in the "Disallowed" store.
	bool distrusted = false;
};

// The anchors from `certs` allowed for server authentication, not
// distrusted and parsing as one X.509 certificate, as PEM.
auto trust_anchors_pem(std::span<const system_certificate> certs) -> std::vector<std::string>;

// Adds `anchors` to `ctx`; no_such_file_or_directory when there is none.
auto add_trust_anchors(boost::corosio::tls_context &ctx, std::span<const std::string> anchors, const std::string &what)
  -> result<void>;

// The platform's default trust anchors into `ctx`
// (trust_store_default.cpp, or trust_store_win.cpp on Windows).
auto load_system_trust(boost::corosio::tls_context &ctx) -> result<void>;

// True on Windows: verify_system_chain decides on the chain.
auto platform_verifies_chain() noexcept -> bool;

// CryptoAPI's strong signature lists matching OpenSSL's `security_level`
// (minbits_table); nullopt at level 0 or below.
struct strong_sign_lists
{
	// pwszCNGSignHashAlgids: "RSA/SHA256;ECDSA/SHA256;...".
	std::wstring sign_hash_algids{};
	// pwszCNGPubKeyMinBitLengths: "RSA/2048;ECDSA/224".
	std::wstring min_key_bits{};
};
auto strong_sign_for_level(int security_level) -> std::optional<strong_sign_lists>;

// Verifies `chain` (DER, leaf first) for TLS server authentication with the
// platform's chain engine and SSL policy, held to `security_level`; the
// host name is not checked. Blocks. Off Windows: function_not_supported.
// The cap on its revocation retrieval:
inline constexpr std::chrono::milliseconds max_revocation_retrieval = std::chrono::seconds(20);

// The revocation retrieval budget: `timeout`, at most
// max_revocation_retrieval, at least 1 ms.
auto revocation_retrieval_budget(std::optional<std::chrono::milliseconds> timeout) noexcept
  -> std::chrono::milliseconds;

auto verify_system_chain(std::span<const std::vector<unsigned char>> chain,
  int security_level,
  std::optional<std::chrono::milliseconds> timeout) -> result<void>;

}// namespace jhetz::ldap::net::detail
