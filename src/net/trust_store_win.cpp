// Default verification on Windows: CryptoAPI verifies the chain
// (verify_system_chain). Needs CERT_CHAIN_PARA_HAS_EXTRA_FIELDS (CMake).
#include "trust_store.hpp"

#include "../format_util.hpp"

#include <windows.h>
// After <windows.h>: WIN32_LEAN_AND_MEAN leaves it out of <windows.h>.
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
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
		const auto it = std::ranges::find_if(policy_errors, [code](const policy_error &e) { return e.code == code; });
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

// CryptoAPI decides on the chain (verify_system_chain): OpenSSL gets no
// anchors.
auto load_system_trust(boost::corosio::tls_context & /*ctx*/) -> result<void> { return {}; }

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
		// One the engine cannot decode is left out.
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
	// OpenSSL's security level for the chain's signatures and keys.
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
	// The revocation retrieval budget (CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT).
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
	// A weak signature is refused here.
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
