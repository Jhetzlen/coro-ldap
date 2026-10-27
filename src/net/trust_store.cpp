#include "trust_store.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <string_view>
#include <system_error>

namespace jhetz::ldap::net::detail {
namespace {

	struct bio_deleter
	{
		void operator()(BIO *p) const noexcept { BIO_free(p); }
	};
	struct x509_deleter
	{
		void operator()(X509 *p) const noexcept { X509_free(p); }
	};
	using bio_ptr = std::unique_ptr<BIO, bio_deleter>;
	using x509_ptr = std::unique_ptr<X509, x509_deleter>;

	// `der` as PEM if it is exactly one X.509 certificate, else empty.
	auto der_to_pem(const std::vector<unsigned char> &der) -> std::string
	{
		if (der.empty() || der.size() > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
			return {};
		}
		const unsigned char *p = der.data();
		const x509_ptr cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
		// The whole buffer: trailing bytes mean it was not one certificate.
		if (!cert || p != der.data() + der.size()) {
			return {};
		}
		const bio_ptr bio(BIO_new(BIO_s_mem()));
		if (!bio || PEM_write_bio_X509(bio.get(), cert.get()) != 1) {
			return {};
		}
		char *data = nullptr;
		const long n = BIO_get_mem_data(bio.get(), &data);
		if (n <= 0 || data == nullptr) {
			return {};
		}
		return { data, static_cast<std::size_t>(n) };
	}

}// namespace

auto trust_anchors_pem(std::span<const system_certificate> certs) -> std::vector<std::string>
{
	std::vector<std::string> out;
	for (const auto &c : certs) {
		if (!c.server_auth || c.distrusted) {
			continue;
		}
		if (auto pem = der_to_pem(c.der); !pem.empty()) {
			out.push_back(std::move(pem));
		}
	}
	ERR_clear_error();
	return out;
}

auto add_trust_anchors(boost::corosio::tls_context &ctx, std::span<const std::string> anchors, const std::string &what)
  -> result<void>
{
	if (anchors.empty()) {
		return fail(std::make_error_code(std::errc::no_such_file_or_directory), what + ": no usable trust anchor");
	}
	for (const auto &pem : anchors) {
		if (const auto ec = ctx.add_certificate_authority(pem); ec) {
			return fail(ec, what);
		}
	}
	return {};
}

auto strong_sign_for_level(int security_level) -> std::optional<strong_sign_lists>
{
	// OpenSSL's minbits_table (crypto/x509/x509_vfy.c), by level 1 to 5,
	// and the RSA sizes it rates at those bits.
	static constexpr std::array<int, 5> min_security_bits{ 80, 112, 128, 192, 256 };
	static constexpr std::array<int, 5> min_rsa_bits{ 1024, 2048, 3072, 7680, 15360 };
	static constexpr std::array<int, 3> sha2_digest_bits{ 256, 384, 512 };
	static constexpr std::array<std::wstring_view, 2> sign_algorithms{ L"RSA", L"ECDSA" };
	if (security_level <= 0) {
		return std::nullopt;
	}
	const auto level = static_cast<std::size_t>(std::min<int>(security_level, min_security_bits.size()));
	const int bits = min_security_bits.at(level - 1);
	strong_sign_lists out;
	for (const int digest : sha2_digest_bits) {
		if (digest < 2 * bits) {
			continue;
		}
		for (const auto algorithm : sign_algorithms) {
			if (!out.sign_hash_algids.empty()) {
				out.sign_hash_algids += L';';
			}
			out.sign_hash_algids += algorithm;
			out.sign_hash_algids += L"/SHA" + std::to_wstring(digest);
		}
	}
	out.min_key_bits = L"RSA/" + std::to_wstring(min_rsa_bits.at(level - 1)) + L";ECDSA/" + std::to_wstring(2 * bits);
	return out;
}

}// namespace jhetz::ldap::net::detail
