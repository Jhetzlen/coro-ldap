#include "tls.hpp"

#include <boost/corosio/openssl_stream.hpp>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <filesystem>
#include <fstream>
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

	// True if `pem` holds one certificate OpenSSL can parse. Corosio only
	// parses trust anchors when the handshake starts, which would make a
	// broken CA fail after the TCP connect; this checks it up front.
	bool parses_as_certificate(const std::string &pem)
	{
		BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
		if (bio == nullptr) return false;
		X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
		const bool ok = cert != nullptr;
		X509_free(cert);
		BIO_free(bio);
		return ok;
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
				  what + ": certificate " + std::to_string(i + 1) + " of " + std::to_string(certs.size())
					+ " does not parse");
			if (auto ec = ctx.add_certificate_authority(certs[i]); ec) return fail(ec, what);
		}
		return {};
	}

	bool has_control_character(std::string_view s) noexcept
	{
		for (char c : s) {
			const auto b = static_cast<unsigned char>(c);
			if (b < 0x20 || b == 0x7F) return true;
		}
		return false;
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
		// says "certificate verify failed". Returns the built-in verdict
		// unchanged, so it never relaxes verification.
		ctx.set_verify_callback([failure = setup.failure](bool preverified, corosio::verify_context &vc) {
			if (!preverified && failure->reason.empty()) {
				if (auto *store = static_cast<X509_STORE_CTX *>(vc.native_handle())) {
					const int err = X509_STORE_CTX_get_error(store);
					failure->reason = X509_verify_cert_error_string(err);
					failure->reason +=
					  " (certificate depth " + std::to_string(X509_STORE_CTX_get_error_depth(store)) + ")";
				}
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
	if (host.find(':') != std::string_view::npos) host = host.substr(0, host.find('%'));// IPv6 literal
	return std::string(host);
}

boost::capy::task<result<void>> tls_handshake(transport::impl &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline)
{
	const std::string name = tls_peer_name(host, options);
	im.tls_context.emplace(std::move(setup.context));
	im.tls.emplace(&*im.tcp, *im.tls_context);
	im.tls->set_hostname(name);
	auto [ec] = co_await bounded(im.tls->handshake(corosio::tls_role::client), deadline);
	if (ec) {
		// Back to the plain socket; after a failed handshake the connection
		// is unusable anyway and must be closed.
		im.tls.reset();
		im.tls_context.reset();
		std::string context = "tls handshake";
		if (!setup.failure->reason.empty()) context += ": server certificate: " + setup.failure->reason;
		co_return fail(ec, std::move(context));
	}
	im.stream = boost::capy::any_stream(&*im.tls);
	co_return result<void>{};
}

}// namespace jhetz::ldap::net::detail
