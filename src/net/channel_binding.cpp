#include "channel_binding.hpp"

#include "transport_layers.hpp"

#include "../scope_util.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

namespace jhetz::ldap::net::detail {
namespace {

	struct x509_deleter
	{
		void operator()(X509 *p) const noexcept { X509_free(p); }
	};
	using x509_ptr = std::unique_ptr<X509, x509_deleter>;

	struct openssl_deleter
	{
		void operator()(unsigned char *p) const noexcept { OPENSSL_free(p); }
	};
	// A buffer OpenSSL allocated (i2d_X509's DER).
	using openssl_bytes = std::unique_ptr<unsigned char, openssl_deleter>;

	// Drops the OpenSSL errors raised in its scope, keeping the caller's:
	// ERR_set_mark(), then ERR_pop_to_mark() on every way out.
	auto openssl_error_mark()
	{
		ERR_set_mark();
		return ldap::detail::scope_exit{ [] { ERR_pop_to_mark(); } };
	}

	// The digest of the certificate's signature algorithm for
	// tls-server-end-point, or null when the type is undefined for it.
	// X509_get_signature_info takes a non-const X509 (it may cache the
	// extensions), hence the caller's non-const certificate.
	auto end_point_digest(X509 *cert) -> const EVP_MD *
	{
		int md_nid = NID_undef;
		if (X509_get_signature_info(cert, &md_nid, nullptr, nullptr, nullptr) != 1) {
			return nullptr;
		}
		switch (md_nid) {
		case NID_undef:
			return nullptr;// no single hash function (Ed25519, Ed448)
		case NID_md5:
		case NID_sha1:
			return EVP_sha256();// RFC 5929 section 4.1
		default:
			return EVP_get_digestbynid(md_nid);
		}
	}

	// OpenLDAP's choice (libldap tls_o.c, tlso_session_endpoint): the
	// digest of the signature algorithm's OID alone, SHA-256 when it names
	// none (RSASSA-PSS, whose hash is in its parameters, Ed25519, Ed448)
	// or a weak one (MD2, MD4, MD5, SHA-1); null for an unknown algorithm.
	auto openldap_end_point_digest(const X509 *cert) -> const EVP_MD *
	{
		int md_nid = NID_undef;
		if (OBJ_find_sigid_algs(X509_get_signature_nid(cert), &md_nid, nullptr) != 1) {
			return nullptr;
		}
		switch (md_nid) {
		case NID_undef:
		case NID_md2:
		case NID_md4:
		case NID_md5:
		case NID_sha1:
			return EVP_sha256();
		default:
			if (const EVP_MD *md = EVP_get_digestbynid(md_nid); md != nullptr) {
				return md;
			}
			return EVP_sha256();
		}
	}

	auto digest_of(const X509 *cert, const EVP_MD *md) -> std::vector<std::byte>
	{
		if (md == nullptr) {
			return {};
		}
		unsigned char *raw = nullptr;
		const int n = i2d_X509(cert, &raw);
		const openssl_bytes der(raw);
		if (n <= 0) {
			return {};
		}
		std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
		unsigned int size = 0;
		if (EVP_Digest(der.get(), static_cast<std::size_t>(n), hash.data(), &size, md, nullptr) != 1) {
			return {};
		}
		const auto *p = reinterpret_cast<const std::byte *>(hash.data());
		return { p, p + size };
	}

	auto parse_der(std::span<const std::byte> certificate) -> x509_ptr
	{
		if (certificate.size() > static_cast<std::size_t>(std::numeric_limits<long>::max())) {
			return nullptr;
		}
		const auto *p = reinterpret_cast<const unsigned char *>(certificate.data());
		return x509_ptr(d2i_X509(nullptr, &p, static_cast<long>(certificate.size())));
	}

	// RFC 9266 section 3 makes tls-exporter SCRAM's default on TLS 1.3;
	// otherwise tls-server-end-point, which servers support widely, and
	// tls-exporter when it is all there is.
	auto default_type(const transport::layers &im, bool tls13) -> std::optional<channel_binding_type>
	{
		const bool exporter = !im.tls_exporter.empty();
		const bool end_point = !im.tls_server_end_point.empty();
		if (exporter && (tls13 || !end_point)) {
			return channel_binding_type::tls_exporter;
		}
		if (end_point) {
			return channel_binding_type::tls_server_end_point;
		}
		return std::nullopt;
	}

}// namespace

auto tls_server_end_point(std::span<const std::byte> certificate) -> std::vector<std::byte>
{
	const auto mark = openssl_error_mark();
	const x509_ptr cert = parse_der(certificate);
	return cert ? digest_of(cert.get(), end_point_digest(cert.get())) : std::vector<std::byte>{};
}

auto openldap_tls_server_end_point(std::span<const std::byte> certificate) -> std::vector<std::byte>
{
	const auto mark = openssl_error_mark();
	const x509_ptr cert = parse_der(certificate);
	return cert ? digest_of(cert.get(), openldap_end_point_digest(cert.get())) : std::vector<std::byte>{};
}

void record_tls_session(transport::layers &im, ssl_st *ssl)
{
	clear_tls_session(im);
	if (ssl == nullptr) {
		return;// defensive: tls_handshake() fails closed before this
	}
	// Errors left by what follows are dropped, the caller's are kept.
	const auto mark = openssl_error_mark();
	// RFC 9266 section 4.2: tls-exporter is undefined where renegotiation
	// is enabled, and a renegotiation (TLS 1.2; TLS 1.3 has none) could
	// change the certificate recorded here. The client refuses the
	// server's HelloRequest from now on (a no_renegotiation alert); an
	// OpenSSL server then fails the connection.
	SSL_set_options(ssl, SSL_OP_NO_RENEGOTIATION);
	if (X509 *cert = SSL_get0_peer_certificate(ssl); cert != nullptr) {
		unsigned char *raw = nullptr;
		const int n = i2d_X509(cert, &raw);
		const openssl_bytes der(raw);
		if (n > 0) {
			const auto *b = reinterpret_cast<const std::byte *>(der.get());
			im.peer_certificate.assign(b, b + n);
			auto hash = digest_of(cert, end_point_digest(cert));
			im.tls_server_end_point.assign(hash.begin(), hash.end());
		}
	}
	const bool tls13 = SSL_version(ssl) == TLS1_3_VERSION;
	if (tls13 || SSL_get_extms_support(ssl) == 1) {
		std::array<unsigned char, tls_exporter_size> key{};
		// RFC 9266 section 2: a zero-length context, which is not the same
		// as no context in TLS 1.2 (RFC 5705 section 4), hence use_context.
		const unsigned char no_bytes = 0;
		if (SSL_export_keying_material(
			  ssl, key.data(), key.size(), tls_exporter_label.data(), tls_exporter_label.size(), &no_bytes, 0, 1)
			== 1) {
			const auto *b = reinterpret_cast<const std::byte *>(key.data());
			im.tls_exporter.assign(b, b + key.size());
		}
	}
	im.default_channel_binding = default_type(im, tls13);
}

void clear_tls_session(transport::layers &im) noexcept
{
	im.peer_certificate.clear();
	im.tls_server_end_point.clear();
	im.tls_exporter.clear();
	im.default_channel_binding.reset();
	im.tls_exporter_used = false;
}

auto authentication_channel_bindings(const transport::layers &im) noexcept -> ldap::channel_bindings
{
	ldap::channel_bindings b{
		.tls_server_end_point = im.tls_server_end_point,
		.tls_exporter = im.tls_exporter,
		.default_type = im.default_channel_binding,
	};
	if (im.tls_exporter_used) {
		b.tls_exporter = {};
		if (b.default_type == channel_binding_type::tls_exporter) {
			b.default_type =
			  b.tls_server_end_point.empty() ? std::nullopt : std::optional(channel_binding_type::tls_server_end_point);
		}
	}
	return b;
}

}// namespace jhetz::ldap::net::detail
