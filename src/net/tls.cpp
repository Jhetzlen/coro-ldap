#include "tls.hpp"

#include "../format_util.hpp"

#include <boost/corosio/openssl_stream.hpp>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace corosio = boost::corosio;

namespace jhetz::ldap::net::detail {
namespace {

	// Splits PEM text into single certificates. Corosio's tls_context reads
	// only the first certificate of each CA entry, so bundles are added one
	// certificate at a time.
	std::vector<std::string> split_pem_certificates(std::string_view pem)
	{
		static constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----";
		static constexpr std::string_view end = "-----END CERTIFICATE-----";
		std::vector<std::string> out;
		std::size_t pos = 0;
		while (true) {
			const std::size_t b = pem.find(begin, pos);
			if (b == std::string_view::npos) break;
			const std::size_t e = pem.find(end, b);
			if (e == std::string_view::npos) break;
			out.emplace_back(pem.substr(b, e + end.size() - b));
			out.back() += '\n';
			pos = e + end.size();
		}
		return out;
	}

	// Deleters for the OpenSSL objects owned below. Each wraps the free call
	// rather than taking its address: some are macros in older OpenSSL.
	struct bio_deleter
	{
		void operator()(BIO *p) const noexcept { BIO_free(p); }
	};
	struct x509_deleter
	{
		void operator()(X509 *p) const noexcept { X509_free(p); }
	};
	struct evp_pkey_deleter
	{
		void operator()(EVP_PKEY *p) const noexcept { EVP_PKEY_free(p); }
	};
	struct asn1_octet_string_deleter
	{
		void operator()(ASN1_OCTET_STRING *p) const noexcept { ASN1_OCTET_STRING_free(p); }
	};
	using bio_ptr = std::unique_ptr<BIO, bio_deleter>;
	using x509_ptr = std::unique_ptr<X509, x509_deleter>;
	using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
	using asn1_octet_string_ptr = std::unique_ptr<ASN1_OCTET_STRING, asn1_octet_string_deleter>;

	// Read-only memory BIO over `pem`, or null. Null too above INT_MAX
	// bytes: BIO_new_mem_buf takes an int, so a larger size would wrap to a
	// truncated length, or a negative one (-1 means "up to the first NUL").
	bio_ptr pem_bio(const std::string &pem)
	{
		if (pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) return nullptr;
		return bio_ptr(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
	}

	// True if `pem` holds one certificate OpenSSL can parse. Corosio only
	// parses trust anchors when the handshake starts, which would make a
	// broken CA fail after the TCP connect; this checks it up front. A
	// failure leaves nothing on the thread's OpenSSL error queue.
	bool parses_as_certificate(const std::string &pem)
	{
		const bio_ptr bio = pem_bio(pem);
		if (bio && x509_ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) != nullptr) return true;
		ERR_clear_error();
		return false;
	}

	// Checks a client certificate chain file and key file before any network
	// traffic: Corosio only parses them when the handshake starts. The first
	// certificate of the chain must parse, the key must parse, and they must
	// belong together.
	// Password callback that refuses: with a null callback OpenSSL would prompt
	// on the terminal for an encrypted key. Encrypted keys are not supported.
	int no_password(char *, int, int, void *) { return -1; }

	result<void> check_client_credentials(const std::string &cert_pem,
	  const std::string &key_pem,
	  const std::string &cert_what,
	  const std::string &key_what)
	{
		const auto invalid = std::make_error_code(std::errc::invalid_argument);
		const x509_ptr cert = [&] {
			const bio_ptr bio = pem_bio(cert_pem);
			return x509_ptr(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
		}();
		if (!cert) {
			ERR_clear_error();
			return fail(invalid, cert_what + ": no parseable PEM certificate");
		}
		const evp_pkey_ptr key = [&] {
			const bio_ptr bio = pem_bio(key_pem);
			return evp_pkey_ptr(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, no_password, nullptr) : nullptr);
		}();
		if (!key) {
			ERR_clear_error();
			return fail(invalid, key_what + ": no parseable PEM private key (encrypted keys are not supported)");
		}
		if (X509_check_private_key(cert.get(), key.get()) != 1) {
			ERR_clear_error();
			return fail(invalid, key_what + ": does not match the certificate in " + cert_what);
		}
		return {};
	}

	std::optional<std::string> read_file(const std::filesystem::path &path)
	{
		std::ifstream in(path, std::ios::binary);
		if (!in) return std::nullopt;
		std::ostringstream s;
		s << in.rdbuf();
		if (in.bad()) return std::nullopt;
		return std::move(s).str();
	}

	result<void> add_cas(corosio::tls_context &ctx, std::string_view pem, const std::string &what)
	{
		const auto certs = split_pem_certificates(pem);
		if (certs.empty())
			return fail(std::make_error_code(std::errc::invalid_argument), what + ": no PEM certificate found");
		for (std::size_t i = 0; i < certs.size(); ++i) {
			if (!parses_as_certificate(certs[i]))
				return fail(std::make_error_code(std::errc::invalid_argument),
				  ldap::detail::format("{}: certificate {} of {} does not parse", what, i + 1, certs.size()));
			if (auto ec = ctx.add_certificate_authority(certs[i]); ec) return fail(ec, what);
		}
		return {};
	}

	bool has_control_character(std::string_view s) noexcept
	{
		return std::ranges::any_of(s, [](char c) {
			const auto b = static_cast<unsigned char>(c);
			return b < 0x20 || b == 0x7F;
		});
	}

	bool is_ip_literal(const std::string &name)
	{
		const asn1_octet_string_ptr ip(a2i_IPADDRESS(name.c_str()));
		if (!ip) {
			ERR_clear_error();
			return false;
		}
		return true;
	}

	result<void> check(std::error_code ec, const std::string &what)
	{
		if (ec) return fail(ec, what);
		return {};
	}

}// namespace

result<tls_setup> make_tls_setup(const tls_options &o)
{
	tls_setup setup;
	auto &ctx = setup.context;

	if (has_control_character(o.server_name))
		return fail(std::make_error_code(std::errc::invalid_argument), "tls: control character in server_name");

	if (auto r = check(ctx.set_min_protocol_version(o.min_version), "tls: minimum protocol version"); !r)
		return std::unexpected(std::move(r.error()));

	if (o.verification == certificate_verification::full) {
		if (auto r = check(ctx.set_verify_mode(corosio::tls_verify_mode::peer), "tls: verify mode"); !r)
			return std::unexpected(std::move(r.error()));
		const bool custom_trust = !o.ca_file.empty() || !o.ca_dir.empty() || !o.ca_pem.empty();
		if (!custom_trust) {
			if (auto r = check(ctx.set_default_verify_paths(), "tls: system trust store"); !r)
				return std::unexpected(std::move(r.error()));
		}
		if (!o.ca_file.empty()) {
			const std::string what = "tls: ca_file " + o.ca_file.string();
			auto pem = read_file(o.ca_file);
			if (!pem) return fail(std::make_error_code(std::errc::no_such_file_or_directory), what);
			if (auto r = add_cas(ctx, *pem, what); !r) return std::unexpected(std::move(r.error()));
		}
		if (!o.ca_dir.empty()) {
			const std::string what = "tls: ca_dir " + o.ca_dir.string();
			std::error_code ec;
			const auto status = std::filesystem::status(o.ca_dir, ec);
			if (!std::filesystem::exists(status))
				return fail(std::make_error_code(std::errc::no_such_file_or_directory), what);
			if (!std::filesystem::is_directory(status))
				return fail(std::make_error_code(std::errc::not_a_directory), what);
			if (auto r = check(ctx.add_verify_path(o.ca_dir.string()), what); !r)
				return std::unexpected(std::move(r.error()));
		}
		if (!o.ca_pem.empty()) {
			if (auto r = add_cas(ctx, o.ca_pem, "tls: ca_pem"); !r) return std::unexpected(std::move(r.error()));
		}
		// Records why verification failed; the handshake error itself only
		// says "certificate verify failed". Never relaxes the built-in
		// verdict; with strict_host set it also rejects a leaf that only
		// OpenSSL's lenient host matching accepted (Corosio has no option for
		// the X509_CHECK_FLAG_* flags, so the check is redone here).
		ctx.set_verify_callback([failure = setup.failure](bool preverified, corosio::verify_context &vc) {
			auto *store = static_cast<X509_STORE_CTX *>(vc.native_handle());
			if (store == nullptr) return preverified;
			if (preverified && !failure->strict_host.empty() && X509_STORE_CTX_get_error_depth(store) == 0) {
				const std::string &host = failure->strict_host;
				constexpr unsigned flags = X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
				if (X509_check_host(X509_STORE_CTX_get_current_cert(store), host.data(), host.size(), flags, nullptr)
					!= 1) {
					X509_STORE_CTX_set_error(store, X509_V_ERR_HOSTNAME_MISMATCH);
					preverified = false;
					if (failure->reason.empty())
						failure->reason =
						  "hostname mismatch (strict matching: subjectAltName DNS names only, no "
						  "partial wildcards; certificate depth 0)";
				}
			}
			if (!preverified && failure->reason.empty()) {
				const int err = X509_STORE_CTX_get_error(store);
				failure->reason = X509_verify_cert_error_string(err);
				ldap::detail::format_to(
				  failure->reason, " (certificate depth {})", X509_STORE_CTX_get_error_depth(store));
			}
			return preverified;
		});
	} else {
		if (auto r = check(ctx.set_verify_mode(corosio::tls_verify_mode::none), "tls: verify mode"); !r)
			return std::unexpected(std::move(r.error()));
	}

	if (o.cert_file.empty() != o.key_file.empty())
		return fail(
		  std::make_error_code(std::errc::invalid_argument), "tls: cert_file and key_file must be given together");
	if (!o.cert_file.empty()) {
		const std::string cert_what = "tls: cert_file " + o.cert_file.string();
		const std::string key_what = "tls: key_file " + o.key_file.string();
		const auto cert_pem = read_file(o.cert_file);
		if (!cert_pem) return fail(std::make_error_code(std::errc::no_such_file_or_directory), cert_what);
		const auto key_pem = read_file(o.key_file);
		if (!key_pem) return fail(std::make_error_code(std::errc::no_such_file_or_directory), key_what);
		if (auto r = check_client_credentials(*cert_pem, *key_pem, cert_what, key_what); !r)
			return std::unexpected(std::move(r.error()));
		if (auto r =
			  check(ctx.use_certificate_chain_file(o.cert_file.string()), "tls: cert_file " + o.cert_file.string());
		  !r)
			return std::unexpected(std::move(r.error()));
		if (auto r = check(ctx.use_private_key_file(o.key_file.string(), corosio::tls_file_format::pem),
			  "tls: key_file " + o.key_file.string());
		  !r)
			return std::unexpected(std::move(r.error()));
	}
	return setup;
}

std::string tls_peer_name(std::string_view host, const tls_options &options)
{
	if (!options.server_name.empty()) return std::string(options.server_name);
	if (host.contains(':')) host = host.substr(0, host.find('%'));// IPv6 literal
	return std::string(host);
}

boost::capy::task<result<void>> tls_handshake(transport::impl &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline)
{
	const std::string name = tls_peer_name(host, options);
	if (options.verification == certificate_verification::full && options.host_matching == host_name_matching::strict
		&& !is_ip_literal(name))
		setup.failure->strict_host = name;
	// im.tls is set only once the handshake succeeded: transport::is_tls()
	// says TLS protects the stream. Undone on a failed handshake, and on a
	// throw (bad_alloc) from openssl_stream's construction, set_hostname(),
	// the handshake's frame, bounded()'s or the timeout's stop_source. Back
	// to the plain socket; the connection is unusable anyway and must be
	// closed (the server expects a handshake now).
	struct undo_tls
	{
		transport::impl &im;
		bool keep = false;
		~undo_tls()
		{
			if (keep) return;
			im.tls.reset();
			im.tls_context.reset();
		}
	} undo{ im };
	im.tls_context.emplace(std::move(setup.context));
	im.tls.emplace(&*im.tcp, *im.tls_context);
	im.tls->set_hostname(name);
	auto [ec] = co_await bounded(im.tls->handshake(corosio::tls_role::client), deadline);
	if (ec) {
		std::string context = "tls handshake";
		if (!setup.failure->reason.empty()) context += ": server certificate: " + setup.failure->reason;
		co_return fail(ec, std::move(context));
	}
	im.stream = boost::capy::any_stream(&*im.tls);
	undo.keep = true;
	co_return result<void>{};
}

}// namespace jhetz::ldap::net::detail
