// Default verification on Windows (trust_store.hpp): the CryptoAPI "ROOT"
// system store as OpenSSL's anchors, and verify_system_chain, whose verdict
// replaces OpenSSL's on the chain (so the filtering below no longer
// decides; a ROOT store that cannot be read still fails the connect).
// Compiled on Windows only (CMake picks this file instead of
// trust_store_default.cpp).
//
// Enumerated again for every context, like OpenSSL re-reading its files
// off Windows. Each root is kept only if its extended key usage property
// allows serverAuth (or restricts nothing), its disallowed extended key
// usage property does not list serverAuth, it has no NotBefore restriction
// on serverAuth (below), it has no CERT_DISALLOWED_FILETIME_PROP_ID
// property, and it is not in the "Disallowed" store (by SHA-1 thumbprint).
// The "CA" store (intermediates) never provides anchors. A store that
// cannot be enumerated to the end fails: no silent partial set.
//
// NotBefore: the root program stops trusting certificates a root issues
// after a date with the CERT_NOT_BEFORE_FILETIME_PROP_ID property, for the
// uses CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID lists (all uses when it is
// absent). OpenSSL cannot trust a root only for certificates issued before
// a date, so such a root is not an anchor for TLS servers at all (fail
// closed); pass it in ca_file to trust it anyway.
//
// verify_system_chain: the server's chain through CryptoAPI, as wldap32
// and Schannel clients verify it (see trust_store.hpp). Needs
// CERT_CHAIN_PARA_HAS_EXTRA_FIELDS (set for this file by CMake) for
// CERT_CHAIN_PARA::dwUrlRetrievalTimeout and pStrongSignPara.
#include "trust_store.hpp"

#include "../format_util.hpp"

#include <windows.h>
// After <windows.h>: WIN32_LEAN_AND_MEAN leaves it out of <windows.h>.
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace jhetz::ldap::net::detail {
namespace {

	struct store_closer
	{
		void operator()(void *store) const noexcept { CertCloseStore(static_cast<HCERTSTORE>(store), 0); }
	};
	using store_ptr = std::unique_ptr<void, store_closer>;

	constexpr DWORD sha1_size = 20;

	auto last_error() -> std::error_code { return { static_cast<int>(GetLastError()), std::system_category() }; }

	auto is_not_found(DWORD error) -> bool { return error == static_cast<DWORD>(CRYPT_E_NOT_FOUND); }

	// Room for a decoded structure of `size` bytes: max_align_t elements, as
	// it holds a CERT_ENHKEY_USAGE and the pointers and strings it points to.
	auto aligned_buffer(DWORD size) -> std::vector<std::max_align_t>
	{
		return std::vector<std::max_align_t>((size + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t));
	}

	auto lists_server_auth(const CERT_ENHKEY_USAGE &usage) -> bool
	{
		for (DWORD i = 0; i < usage.cUsageIdentifier; ++i) {
			const char *oid = usage.rgpszUsageIdentifier[i];
			if (oid != nullptr && std::string_view(oid) == szOID_PKIX_KP_SERVER_AUTH) {
				return true;
			}
		}
		return false;
	}

	// The certificate's extended key usage *property* (the store's
	// restriction, not the certificate's extension) allows serverAuth.
	// CertGetEnhancedKeyUsage with CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG:
	// failing with CRYPT_E_NOT_FOUND means no property (all uses); an empty
	// list means all uses if the last error is CRYPT_E_NOT_FOUND, none
	// otherwise. Any other failure skips the root.
	auto server_auth_allowed(PCCERT_CONTEXT cert) -> bool
	{
		DWORD size = 0;
		if (CertGetEnhancedKeyUsage(cert, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, nullptr, &size) == FALSE) {
			return is_not_found(GetLastError());
		}
		if (size < sizeof(CERT_ENHKEY_USAGE)) {
			return false;
		}
		std::vector<std::max_align_t> buffer = aligned_buffer(size);
		auto *usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data());
		SetLastError(0);
		if (CertGetEnhancedKeyUsage(cert, CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG, usage, &size) == FALSE) {
			return is_not_found(GetLastError());
		}
		if (usage->cUsageIdentifier == 0) {
			return is_not_found(GetLastError());
		}
		return lists_server_auth(*usage);
	}

	// wincrypt.h's CERT_NOT_BEFORE_FILETIME_PROP_ID and
	// CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID, which older SDKs lack.
	constexpr DWORD not_before_filetime_prop_id = 126;
	constexpr DWORD not_before_enhkey_usage_prop_id = 127;

	// What an ASN.1 encoded enhanced key usage property says about serverAuth.
	enum class usage_property : std::uint8_t {
		absent,
		lists_server_auth,
		omits_server_auth,
		unreadable,// there, but cannot be read or decoded
	};

	auto read_usage_property(PCCERT_CONTEXT cert, DWORD id) -> usage_property
	{
		DWORD size = 0;
		if (CertGetCertificateContextProperty(cert, id, nullptr, &size) == FALSE) {
			return is_not_found(GetLastError()) ? usage_property::absent : usage_property::unreadable;
		}
		std::vector<BYTE> encoded(size);
		if (CertGetCertificateContextProperty(cert, id, encoded.data(), &size) == FALSE) {
			return usage_property::unreadable;
		}
		DWORD decoded_size = 0;
		if (CryptDecodeObjectEx(
			  X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, encoded.data(), size, 0, nullptr, nullptr, &decoded_size)
			  == FALSE
			|| decoded_size < sizeof(CERT_ENHKEY_USAGE)) {
			return usage_property::unreadable;
		}
		std::vector<std::max_align_t> buffer = aligned_buffer(decoded_size);
		auto *usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data());
		if (CryptDecodeObjectEx(
			  X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, encoded.data(), size, 0, nullptr, usage, &decoded_size)
			== FALSE) {
			return usage_property::unreadable;
		}
		return lists_server_auth(*usage) ? usage_property::lists_server_auth : usage_property::omits_server_auth;
	}

	// The root program disables a use of a root by listing it in the
	// CERT_DISALLOWED_ENHKEY_USAGE_PROP_ID property. True when it lists
	// serverAuth, or when it is there but cannot be read (fail closed); no
	// property is false.
	auto server_auth_disallowed(PCCERT_CONTEXT cert) -> bool
	{
		const usage_property p = read_usage_property(cert, CERT_DISALLOWED_ENHKEY_USAGE_PROP_ID);
		return p == usage_property::lists_server_auth || p == usage_property::unreadable;
	}

	// A NotBefore date (header) applies to serverAuth: the date property is
	// there (whatever its value, or when it cannot be read), and the usage
	// property is absent (all uses), lists serverAuth or cannot be read.
	auto server_auth_not_before(PCCERT_CONTEXT cert) -> bool
	{
		DWORD size = 0;
		if (CertGetCertificateContextProperty(cert, not_before_filetime_prop_id, nullptr, &size) == FALSE
			&& is_not_found(GetLastError())) {
			return false;
		}
		return read_usage_property(cert, not_before_enhkey_usage_prop_id) != usage_property::omits_server_auth;
	}

	// Marked disallowed (the property's FILETIME is when; any value
	// distrusts it here).
	auto has_disallowed_filetime(PCCERT_CONTEXT cert) -> bool
	{
		DWORD size = 0;
		return CertGetCertificateContextProperty(cert, CERT_DISALLOWED_FILETIME_PROP_ID, nullptr, &size) != FALSE;
	}

	// `cert` is in `store`, by SHA-1 thumbprint. True too when the
	// thumbprint cannot be read (fail closed: the root is skipped).
	auto in_store(HCERTSTORE store, PCCERT_CONTEXT cert) -> bool
	{
		std::array<BYTE, sha1_size> hash{};
		DWORD size = sha1_size;
		if (CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, hash.data(), &size) == FALSE
			|| size != sha1_size) {
			return true;
		}
		CRYPT_HASH_BLOB blob{ .cbData = size, .pbData = hash.data() };
		PCCERT_CONTEXT found = CertFindCertificateInStore(
		  store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &blob, nullptr);
		if (found == nullptr) {
			return false;
		}
		CertFreeCertificateContext(found);
		return true;
	}

	auto describe(PCCERT_CONTEXT cert, HCERTSTORE disallowed) -> system_certificate
	{
		const BYTE *der = cert->pbCertEncoded;
		return {
			.der = std::vector<unsigned char>(der, der + cert->cbCertEncoded),
			.server_auth = server_auth_allowed(cert) && !server_auth_disallowed(cert) && !server_auth_not_before(cert),
			.distrusted = has_disallowed_filetime(cert) || in_store(disallowed, cert),
		};
	}

}// namespace

auto load_system_trust(boost::corosio::tls_context &ctx) -> result<void>
{
	const std::string what = "tls: system trust store";
	const store_ptr root(CertOpenSystemStoreW(0, L"ROOT"));
	if (!root) {
		const auto ec = last_error();
		return fail(ec, what + ": cannot open the ROOT store");
	}
	// Without it a distrusted root could slip in: fail closed.
	const store_ptr disallowed(CertOpenSystemStoreW(0, L"Disallowed"));
	if (!disallowed) {
		const auto ec = last_error();
		return fail(ec, what + ": cannot open the Disallowed store");
	}

	std::vector<system_certificate> certs;
	// CertEnumCertificatesInStore frees the previous context; the last call
	// returns null, so only an exception (bad_alloc) leaves one to free.
	PCCERT_CONTEXT cert = nullptr;
	try {
		while ((cert = CertEnumCertificatesInStore(root.get(), cert)) != nullptr) {
			if ((cert->dwCertEncodingType & X509_ASN_ENCODING) == 0 || cert->pbCertEncoded == nullptr) {
				continue;
			}
			certs.push_back(describe(cert, disallowed.get()));
		}
	} catch (...) {
		if (cert != nullptr) {
			CertFreeCertificateContext(cert);
		}
		throw;
	}
	// The loop ends on null: at the end of the store, or on a failure that
	// would leave the set partial.
	if (const DWORD error = GetLastError(); !is_not_found(error) && error != static_cast<DWORD>(ERROR_NO_MORE_FILES)) {
		return fail({ static_cast<int>(error), std::system_category() }, what + ": cannot enumerate the ROOT store");
	}
	return add_trust_anchors(ctx, trust_anchors_pem(certs), what);
}

namespace {

	struct certificate_freer
	{
		void operator()(const CERT_CONTEXT *cert) const noexcept { CertFreeCertificateContext(cert); }
	};
	using certificate_ptr = std::unique_ptr<const CERT_CONTEXT, certificate_freer>;

	struct chain_freer
	{
		void operator()(const CERT_CHAIN_CONTEXT *chain) const noexcept { CertFreeCertificateChain(chain); }
	};
	using chain_ptr = std::unique_ptr<const CERT_CHAIN_CONTEXT, chain_freer>;

	// SECURITY_FLAG_IGNORE_CERT_CN_INVALID (wininet.h, not included): the SSL
	// policy skips the name check, which stays OpenSSL's.
	constexpr DWORD ignore_cert_cn_invalid = 0x00001000;

	// The common reasons CertVerifyCertificateChainPolicy gives, by name.
	struct policy_error
	{
		HRESULT code;
		std::string_view text;
	};
	constexpr std::array policy_errors{
		policy_error{ .code = CERT_E_UNTRUSTEDROOT, .text = "untrusted root (CERT_E_UNTRUSTEDROOT)" },
		policy_error{ .code = CERT_E_CHAINING, .text = "no chain to a trusted root (CERT_E_CHAINING)" },
		policy_error{ .code = CERT_E_EXPIRED, .text = "expired or not yet valid (CERT_E_EXPIRED)" },
		policy_error{ .code = CERT_E_WRONG_USAGE, .text = "not valid for server authentication (CERT_E_WRONG_USAGE)" },
		policy_error{ .code = CRYPT_E_REVOKED, .text = "revoked (CRYPT_E_REVOKED)" },
		policy_error{ .code = CERT_E_REVOKED, .text = "revoked (CERT_E_REVOKED)" },
		policy_error{ .code = TRUST_E_CERT_SIGNATURE, .text = "bad signature (TRUST_E_CERT_SIGNATURE)" },
		policy_error{ .code = TRUST_E_BASIC_CONSTRAINTS,
		  .text = "basic constraints violated (TRUST_E_BASIC_CONSTRAINTS)" },
		policy_error{ .code = TRUST_E_EXPLICIT_DISTRUST, .text = "explicitly distrusted (TRUST_E_EXPLICIT_DISTRUST)" },
		policy_error{ .code = CERT_E_INVALID_NAME, .text = "name constraints violated (CERT_E_INVALID_NAME)" },
		policy_error{ .code = CERT_E_INVALID_POLICY, .text = "invalid certificate policy (CERT_E_INVALID_POLICY)" },
		policy_error{ .code = CERT_E_PATHLENCONST, .text = "path length constraint violated (CERT_E_PATHLENCONST)" },
		policy_error{ .code = CERT_E_CRITICAL, .text = "unknown critical extension (CERT_E_CRITICAL)" },
		policy_error{ .code = CERT_E_UNTRUSTEDTESTROOT, .text = "untrusted test root (CERT_E_UNTRUSTEDTESTROOT)" },
		policy_error{ .code = CRYPT_E_REVOCATION_OFFLINE,
		  .text = "revocation server offline (CRYPT_E_REVOCATION_OFFLINE)" },
		policy_error{ .code = CRYPT_E_NO_REVOCATION_CHECK,
		  .text = "revocation not checked (CRYPT_E_NO_REVOCATION_CHECK)" },
	};

	auto policy_reason(DWORD status) -> std::string
	{
		const auto code = static_cast<HRESULT>(status);
		const auto *const it =
		  std::ranges::find_if(policy_errors, [code](const policy_error &e) { return e.code == code; });
		if (it != policy_errors.end()) {
			return ldap::detail::format("Windows certificate chain: {} (0x{:08X})", it->text, status);
		}
		return ldap::detail::format("Windows certificate chain: rejected by the SSL policy (0x{:08X})", status);
	}

	auto chain_error(DWORD code, std::string_view what) -> std::unexpected<error>
	{
		return fail({ static_cast<int>(code), std::system_category() },
		  ldap::detail::format("Windows certificate chain: {} (0x{:08X})", what, code));
	}

	auto der_size(const std::vector<unsigned char> &der) -> std::optional<DWORD>
	{
		if (der.empty() || der.size() > std::numeric_limits<DWORD>::max()) {
			return std::nullopt;
		}
		return static_cast<DWORD>(der.size());
	}

}// namespace

auto platform_verifies_chain() noexcept -> bool { return true; }

auto verify_system_chain(std::span<const std::vector<unsigned char>> chain,
  int security_level,
  std::optional<std::chrono::milliseconds> timeout) -> result<void>
{
	if (chain.empty()) {
		return fail(std::make_error_code(std::errc::invalid_argument), "Windows certificate chain: no certificate");
	}
	const auto leaf_size = der_size(chain.front());
	if (!leaf_size) {
		return fail(std::make_error_code(std::errc::invalid_argument),
		  "Windows certificate chain: the server certificate is empty or too large");
	}
	const certificate_ptr leaf(CertCreateCertificateContext(X509_ASN_ENCODING, chain.front().data(), *leaf_size));
	if (!leaf) {
		return chain_error(GetLastError(), "the server certificate does not decode");
	}
	// The other certificates the server sent, for the chain engine to pick
	// intermediates from (trust comes only from the system stores).
	const store_ptr extra(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr));
	if (!extra) {
		return chain_error(GetLastError(), "cannot open a memory store");
	}
	for (const auto &der : chain.subspan(1)) {
		const auto size = der_size(der);
		// One the engine cannot decode is left out: the chain then fails
		// to build if it was needed, with the engine's reason.
		if (size) {
			CertAddEncodedCertificateToStore(static_cast<HCERTSTORE>(extra.get()),
			  X509_ASN_ENCODING,
			  der.data(),
			  *size,
			  CERT_STORE_ADD_ALWAYS,
			  nullptr);
		}
	}

	// rgpszUsageIdentifier is LPSTR*: a writable copy of the OID.
	std::string server_auth_oid = szOID_PKIX_KP_SERVER_AUTH;
	std::array<LPSTR, 1> server_auth{ server_auth_oid.data() };
	CERT_CHAIN_PARA para{};
	para.cbSize = sizeof(para);
	para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	para.RequestedUsage.Usage.cUsageIdentifier = static_cast<DWORD>(server_auth.size());
	para.RequestedUsage.Usage.rgpszUsageIdentifier = server_auth.data();
	// OpenSSL's security level for the signatures and keys of the chain
	// (trust_store.hpp strong_sign_for_level): without pStrongSignPara the
	// chain engine checks neither. dwFlags 0: CRL and OCSP signatures are
	// not held to it (OpenSSL checks no revocation at all), and
	// dwStrongSignFlags 0 checks the leaf's key length too.
	auto strong = strong_sign_for_level(security_level);
	CERT_STRONG_SIGN_SERIALIZED_INFO strong_info{};
	CERT_STRONG_SIGN_PARA strong_para{};
	if (strong) {
		strong_info.dwFlags = 0;
		strong_info.pwszCNGSignHashAlgids = strong->sign_hash_algids.data();
		strong_info.pwszCNGPubKeyMinBitLengths = strong->min_key_bits.data();
		strong_para.cbSize = sizeof(strong_para);
		strong_para.dwInfoChoice = CERT_STRONG_SIGN_SERIALIZED_INFO_CHOICE;
		// pSerializedInfo shares an anonymous union with pvInfo and pszOID.
		strong_para.pSerializedInfo = &strong_info;// NOLINT(cppcoreguidelines-pro-type-union-access)
		para.pStrongSignPara = &strong_para;
	}
	// The revocation retrieval, every CRL and OCSP URL together
	// (CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT), within what is left of
	// the connect's or StartTLS's deadline and at most
	// max_revocation_retrieval, with a deadline or without. Microsoft
	// documents dwUrlRetrievalTimeout for revocation only: AIA
	// intermediates and AuthRoot roots are fetched with the chain engine's
	// own per-URL timeout (trust_store.hpp).
	para.dwUrlRetrievalTimeout = static_cast<DWORD>(revocation_retrieval_budget(timeout).count());
	const DWORD flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
	PCCERT_CHAIN_CONTEXT raw_chain = nullptr;
	// HCCE_CURRENT_USER (null): the user's and the machine's stores, with
	// AuthRoot auto-update, as Schannel clients use.
	if (CertGetCertificateChain(
		  nullptr, leaf.get(), nullptr, static_cast<HCERTSTORE>(extra.get()), &para, flags, nullptr, &raw_chain)
		== FALSE) {
		return chain_error(GetLastError(), "CertGetCertificateChain failed");
	}
	const chain_ptr built(raw_chain);
	// Checked here rather than left to the SSL policy, whose mapping of it
	// to an error Microsoft does not document.
	if ((built->TrustStatus.dwErrorStatus & CERT_TRUST_HAS_WEAK_SIGNATURE) != 0) {
		return fail(std::make_error_code(std::errc::permission_denied),
		  ldap::detail::format("Windows certificate chain: a signature or key below OpenSSL's security level {} "
							   "(CERT_TRUST_HAS_WEAK_SIGNATURE)",
			security_level));
	}

	SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
	// cbSize shares an anonymous union with cbStruct in the SDK's struct.
	ssl.cbSize = sizeof(ssl);// NOLINT(cppcoreguidelines-pro-type-union-access)
	ssl.dwAuthType = AUTHTYPE_SERVER;
	ssl.fdwChecks = ignore_cert_cn_invalid;
	ssl.pwszServerName = nullptr;
	CERT_CHAIN_POLICY_PARA policy{};
	policy.cbSize = sizeof(policy);
	// Soft-fail revocation: a status that cannot be determined (no CRL or
	// OCSP reachable in time) is accepted, a revoked certificate is not.
	policy.dwFlags = CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS;
	policy.pvExtraPolicyPara = &ssl;
	CERT_CHAIN_POLICY_STATUS status{};
	status.cbSize = sizeof(status);
	if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, built.get(), &policy, &status) == FALSE) {
		return chain_error(GetLastError(), "CertVerifyCertificateChainPolicy failed");
	}
	if (status.dwError != 0) {
		return fail({ static_cast<int>(status.dwError), std::system_category() }, policy_reason(status.dwError));
	}
	return {};
}

}// namespace jhetz::ldap::net::detail
