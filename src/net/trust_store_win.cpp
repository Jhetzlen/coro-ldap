// Default trust anchors on Windows: the CryptoAPI "ROOT" system store
// (trust_store.hpp). Compiled on Windows only (CMake picks this file
// instead of trust_store_default.cpp).
//
// Enumerated again for every context, like OpenSSL re-reading its files
// off Windows. Each root is kept only if its extended key usage property
// allows serverAuth (or restricts nothing), its disallowed extended key
// usage property does not list serverAuth, it has no
// CERT_DISALLOWED_FILETIME_PROP_ID property, and it is not in the
// "Disallowed" store (by SHA-1 thumbprint). The "CA" store (intermediates)
// never provides anchors. A store that cannot be enumerated to the end
// fails: no silent partial set.
#include "trust_store.hpp"

#include <windows.h>
// After <windows.h>: WIN32_LEAN_AND_MEAN leaves it out of <windows.h>.
#include <wincrypt.h>

#include <array>
#include <cstddef>
#include <memory>
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

	// The root program disables a use of a root by listing it in the
	// CERT_DISALLOWED_ENHKEY_USAGE_PROP_ID property (an ASN.1 encoded
	// enhanced key usage). True when it lists serverAuth, or when it is
	// there but cannot be read or decoded (fail closed); no property is
	// false.
	auto server_auth_disallowed(PCCERT_CONTEXT cert) -> bool
	{
		DWORD size = 0;
		if (CertGetCertificateContextProperty(cert, CERT_DISALLOWED_ENHKEY_USAGE_PROP_ID, nullptr, &size) == FALSE) {
			return !is_not_found(GetLastError());
		}
		std::vector<BYTE> encoded(size);
		if (CertGetCertificateContextProperty(cert, CERT_DISALLOWED_ENHKEY_USAGE_PROP_ID, encoded.data(), &size)
			== FALSE) {
			return true;
		}
		DWORD decoded_size = 0;
		if (CryptDecodeObjectEx(
			  X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, encoded.data(), size, 0, nullptr, nullptr, &decoded_size)
			  == FALSE
			|| decoded_size < sizeof(CERT_ENHKEY_USAGE)) {
			return true;
		}
		std::vector<std::max_align_t> buffer = aligned_buffer(decoded_size);
		auto *usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data());
		if (CryptDecodeObjectEx(
			  X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, encoded.data(), size, 0, nullptr, usage, &decoded_size)
			== FALSE) {
			return true;
		}
		return lists_server_auth(*usage);
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
			.server_auth = server_auth_allowed(cert) && !server_auth_disallowed(cert),
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

}// namespace jhetz::ldap::net::detail
