#include "jhetz/ldap/net/connect.hpp"

#include "transport_impl.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/timeout.hpp>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <chrono>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap::net {
namespace {

	using clock = std::chrono::steady_clock;
	using deadline_t = std::optional<clock::time_point>;

	// Awaits `a`, cancelled at `deadline` if there is one (the result then
	// compares equal to capy::cond::timeout).
	template<class A> capy::task<std::remove_cvref_t<capy::awaitable_result_t<A>>> bounded(A a, deadline_t deadline)
	{
		if (deadline) co_return co_await corosio::timeout(std::move(a), *deadline);
		co_return co_await std::move(a);
	}

	std::string to_text(const corosio::endpoint &ep)
	{
		const auto addr = ep.address().to_string();
		return ep.is_v6() ? "[" + addr + "]:" + std::to_string(ep.port()) : addr + ":" + std::to_string(ep.port());
	}

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

	// Error contexts are std::string (ldap::error is a step 3 type).
	std::string str(std::string_view s) { return std::string(s); }

	std::optional<std::string> read_file(const std::pmr::string &path)
	{
		std::ifstream in(path.c_str(), std::ios::binary);
		if (!in) return std::nullopt;
		std::ostringstream s;
		s << in.rdbuf();
		if (!in && !in.eof()) return std::nullopt;
		return std::move(s).str();
	}

	// First verification failure seen by the verify callback, e.g.
	// "Hostname mismatch" or "unable to get local issuer certificate".
	struct verify_failure
	{
		std::string reason{};
	};

	result<void> add_cas(corosio::tls_context &ctx, std::string_view pem, const std::string &what)
	{
		const auto certs = split_pem_certificates(pem);
		if (certs.empty())
			return fail(std::make_error_code(std::errc::invalid_argument), what + ": no PEM certificate found");
		for (const auto &c : certs)
			if (auto ec = ctx.add_certificate_authority(c); ec) return fail(ec, what);
		return {};
	}

	result<corosio::tls_context> make_tls_context(const tls_options &o, const std::shared_ptr<verify_failure> &failure)
	{
		corosio::tls_context ctx;
		auto check = [](std::error_code ec, const char *what) -> result<void> {
			if (ec) return fail(ec, what);
			return {};
		};

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
				auto pem = read_file(o.ca_file);
				if (!pem)
					return fail(
					  std::make_error_code(std::errc::no_such_file_or_directory), "tls: ca_file " + str(o.ca_file));
				if (auto r = add_cas(ctx, *pem, "tls: ca_file " + str(o.ca_file)); !r)
					return std::unexpected(std::move(r.error()));
			}
			if (!o.ca_dir.empty()) {
				if (auto r = check(ctx.add_verify_path(o.ca_dir), "tls: ca_dir"); !r)
					return std::unexpected(std::move(r.error()));
			}
			if (!o.ca_pem.empty()) {
				if (auto r = add_cas(ctx, o.ca_pem, "tls: ca_pem"); !r) return std::unexpected(std::move(r.error()));
			}
			// Records why verification failed; the handshake error itself only
			// says "certificate verify failed". Returns the built-in verdict
			// unchanged, so it never relaxes verification.
			ctx.set_verify_callback([failure](bool preverified, corosio::verify_context &vc) {
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
			if (auto r = check(ctx.use_certificate_chain_file(o.cert_file), "tls: cert_file"); !r)
				return std::unexpected(std::move(r.error()));
			if (auto r = check(ctx.use_private_key_file(o.key_file, corosio::tls_file_format::pem), "tls: key_file");
				!r)
				return std::unexpected(std::move(r.error()));
		}
		return ctx;
	}

	std::string stage_context(const std::string &target,
	  std::string_view stage,
	  std::error_code ec,
	  std::chrono::milliseconds timeout)
	{
		std::string out = target;
		out += ": ";
		out += stage;
		if (ec == capy::cond::timeout)
			out += ": gave up after the " + std::to_string(timeout.count()) + " ms connect timeout";
		return out;
	}

}// namespace

capy::task<result<transport>> connect(corosio::io_context &ioc, url u, connect_options options)
{
	const std::string server = str(to_string(u.scheme())) + "://" + str(u.authority());
	const std::string target = "connect " + server;

	if (u.host().empty())
		co_return fail(client_errc::invalid_url, target + ": the URL names no host (or, for ldapi, no socket path)");
	for (const auto &e : u.extensions())
		if (e.critical)
			co_return fail(client_errc::invalid_url, target + ": unsupported critical extension " + str(e.type));
	// Decoded hosts may hold any byte. getaddrinfo, OpenSSL's host name check
	// and sockaddr_un stop at a NUL, so "evil%00.example.org" would silently
	// become "evil". Only a leading NUL is meaningful: a Linux abstract socket.
	for (std::size_t i = 0; i < u.host().size(); ++i) {
		const auto c = static_cast<unsigned char>(u.host()[i]);
		const bool abstract_socket = u.scheme() == url_scheme::ldapi && i == 0 && c == 0;
		if ((c < 0x20 || c == 0x7F) && !abstract_socket)
			co_return fail(client_errc::invalid_url, target + ": control character in the host");
	}

	// No deadline for zero, negative, or so large that now() + timeout would
	// overflow the clock (e.g. milliseconds::max()).
	deadline_t deadline;
	constexpr auto no_limit_above = std::chrono::hours(24 * 365 * 100);
	if (options.timeout.count() > 0 && options.timeout < no_limit_above) deadline = clock::now() + options.timeout;

	// ---- ldapi://
	if (u.scheme() == url_scheme::ldapi) {
		if (u.host().size() > corosio::local_endpoint::max_path_length)
			co_return fail(std::make_error_code(std::errc::filename_too_long),
			  target + ": socket path longer than " + std::to_string(corosio::local_endpoint::max_path_length)
				+ " bytes");
		transport t = transport_access::make(transport::kind::local, server);
		auto &im = transport_access::get(t);
		im.local.emplace(ioc);
		auto [ec] = co_await bounded(im.local->connect(corosio::local_endpoint(u.host())), deadline);
		if (ec) co_return fail(ec, stage_context(target, "connect " + str(u.host()), ec, options.timeout));
		im.stream = capy::any_stream(&*im.local);
		co_return t;
	}

	// ---- ldaps://: TLS settings first, so configuration errors (missing CA
	// file, cert without key) fail before any network traffic.
	auto failure = std::make_shared<verify_failure>();
	std::optional<corosio::tls_context> tls_context;
	if (u.scheme() == url_scheme::ldaps) {
		auto ctx = make_tls_context(options.tls, failure);
		if (!ctx) {
			auto e = std::move(ctx.error());
			e.context = target + ": " + e.context;
			co_return std::unexpected(std::move(e));
		}
		tls_context.emplace(std::move(*ctx));
	}

	// ---- ldap:// and ldaps://: resolve
	const std::string port = std::to_string(u.port_or_default());
	corosio::resolver resolver(ioc);
	auto [rec, endpoints] =
	  co_await bounded(resolver.resolve(u.host(), port, corosio::resolve_flags::numeric_service), deadline);
	if (rec) co_return fail(rec, stage_context(target, "resolve " + str(u.host()), rec, options.timeout));
	if (endpoints.empty())
		co_return fail(std::make_error_code(std::errc::no_such_device_or_address),
		  target + ": resolve " + str(u.host()) + ": no address");

	// ---- TCP: each address in turn, until one accepts
	transport t = transport_access::make(transport::kind::tcp, server);
	auto &im = transport_access::get(t);
	im.tcp.emplace(ioc);
	std::error_code last;
	std::string last_endpoint;
	bool connected = false;
	for (const auto &ep : endpoints) {
		if (im.tcp->is_open()) im.tcp->close();
		last_endpoint = to_text(ep);
		auto [ec] = co_await bounded(im.tcp->connect(ep), deadline);
		if (!ec) {
			connected = true;
			break;
		}
		last = ec;
		if (ec == capy::cond::timeout || ec == capy::cond::canceled) break;// no time left / stopped
	}
	if (!connected) {
		std::string stage = "tcp connect " + last_endpoint;
		if (endpoints.size() > 1) stage += " (last of " + std::to_string(endpoints.size()) + " addresses)";
		co_return fail(last, stage_context(target, stage, last, options.timeout));
	}
	if (options.tcp_no_delay) {
		try {
			im.tcp->set_option(corosio::socket_option::no_delay(true));
		} catch (const std::system_error &e) {
			co_return fail(e.code(), target + ": set TCP_NODELAY");
		}
	}

	if (u.scheme() == url_scheme::ldap) {
		im.stream = capy::any_stream(&*im.tcp);
		co_return t;
	}

	// ---- ldaps://: TLS client handshake over the owned socket
	im.tls_context = std::move(tls_context);
	im.tls.emplace(&*im.tcp, *im.tls_context);
	im.tls->set_hostname(options.tls.server_name.empty() ? u.host() : options.tls.server_name);
	auto [hec] = co_await bounded(im.tls->handshake(corosio::tls_role::client), deadline);
	if (hec) {
		std::string stage = "tls handshake";
		if (!failure->reason.empty()) stage += ": server certificate: " + failure->reason;
		co_return fail(hec, stage_context(target, stage, hec, options.timeout));
	}
	im.stream = capy::any_stream(&*im.tls);
	co_return t;
}

}// namespace jhetz::ldap::net
