#include "tls.hpp"

#include "channel_binding.hpp"
#include "trust_store.hpp"

#include "../format_util.hpp"
#include "../scope_util.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/results.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/openssl_stream.hpp>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace corosio = boost::corosio;

namespace jhetz::ldap::net::detail {
namespace {

	// Deleters for the OpenSSL objects owned below, each wrapping the free call.
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
	struct x509_store_deleter
	{
		void operator()(X509_STORE *p) const noexcept { X509_STORE_free(p); }
	};
	struct x509_store_ctx_deleter
	{
		void operator()(X509_STORE_CTX *p) const noexcept { X509_STORE_CTX_free(p); }
	};
	using bio_ptr = std::unique_ptr<BIO, bio_deleter>;
	using x509_ptr = std::unique_ptr<X509, x509_deleter>;
	using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
	using asn1_octet_string_ptr = std::unique_ptr<ASN1_OCTET_STRING, asn1_octet_string_deleter>;
	using x509_store_ptr = std::unique_ptr<X509_STORE, x509_store_deleter>;
	using x509_store_ctx_ptr = std::unique_ptr<X509_STORE_CTX, x509_store_ctx_deleter>;

	// Read-only memory BIO over `pem`; null above INT_MAX bytes.
	auto pem_bio(std::string_view pem) -> bio_ptr
	{
		if (pem.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
			return nullptr;
		}
		return bio_ptr(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
	}

	// Refuses passwords: encrypted keys are not supported.
	auto no_password(char *, int, int, void *) -> int { return -1; }

	// A client certificate (then its chain) and key as PEM text, with the
	// error context naming each (never the PEM itself).
	struct client_credentials
	{
		std::string_view cert_pem;
		std::string_view key_pem;
		std::string_view cert_what;
		std::string_view key_what;
	};

	// Checks that the client certificate and key parse and belong together.
	auto check_client_credentials(const client_credentials &c) -> result<void>
	{
		const auto invalid = std::make_error_code(std::errc::invalid_argument);
		const x509_ptr cert = [&] {
			const bio_ptr bio = pem_bio(c.cert_pem);
			return x509_ptr(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
		}();
		if (!cert) {
			ERR_clear_error();
			return fail(invalid, std::string(c.cert_what) + ": no parseable PEM certificate");
		}
		const evp_pkey_ptr key = [&] {
			const bio_ptr bio = pem_bio(c.key_pem);
			return evp_pkey_ptr(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, no_password, nullptr) : nullptr);
		}();
		if (!key) {
			ERR_clear_error();
			return fail(
			  invalid, std::string(c.key_what) + ": no parseable PEM private key (encrypted keys are not supported)");
		}
		if (X509_check_private_key(cert.get(), key.get()) != 1) {
			ERR_clear_error();
			return fail(
			  invalid, std::string(c.key_what) + ": does not match the certificate in " + std::string(c.cert_what));
		}
		return {};
	}

	// A path as UTF-8, for error contexts and OpenSSL's char paths.
	auto path_text(const std::filesystem::path &path) -> std::string
	{
		const std::u8string u8 = path.u8string();
		std::string out(u8.size(), '\0');
		std::ranges::transform(u8, out.begin(), [](char8_t c) { return static_cast<char>(c); });
		return out;
	}

	// Through std::filesystem::path (wide on Windows), so any file name
	// opens; the contents then go to Corosio in memory, never as a char path.
	auto read_file(const std::filesystem::path &path) -> std::optional<std::string>
	{
		const std::ifstream in(path, std::ios::binary);
		if (!in) {
			return std::nullopt;
		}
		std::ostringstream s;
		s << in.rdbuf();
		if (in.bad()) {
			return std::nullopt;
		}
		return std::move(s).str();
	}

	// Checks a CA bundle as Corosio reads it; leaves the OpenSSL error queue
	// empty.
	auto check_ca_bundle(std::string_view pem, const std::string &what) -> result<void>
	{
		const bio_ptr bio = pem_bio(pem);
		for (std::size_t n = 1;; ++n) {
			if (bio && x509_ptr(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) != nullptr) {
				continue;
			}
			const unsigned long err = ERR_peek_last_error();
			ERR_clear_error();
			const bool no_more = bio && ERR_GET_LIB(err) == ERR_LIB_PEM && ERR_GET_REASON(err) == PEM_R_NO_START_LINE;
			if (!no_more) {
				return fail(std::make_error_code(std::errc::invalid_argument),
				  ldap::detail::format("{}: certificate {} does not parse", what, n));
			}
			if (n == 1) {
				return fail(std::make_error_code(std::errc::invalid_argument), what + ": no PEM certificate found");
			}
			return {};
		}
	}

	auto add_cas(corosio::tls_context &ctx, std::string_view pem, const std::string &what) -> result<void>
	{
		if (auto checked = check_ca_bundle(pem, what); !checked) {
			return checked;
		}
		if (const auto ec = ctx.add_certificate_authority(pem); ec) {
			return fail(ec, what);
		}
		return {};
	}

	auto has_control_character(std::string_view s) noexcept -> bool
	{
		return std::ranges::any_of(
		  s, [](char c) { return ldap::detail::is_ascii_control(static_cast<unsigned char>(c)); });
	}

	auto is_ip_literal(const std::string &name) -> bool
	{
		const asn1_octet_string_ptr ip(a2i_IPADDRESS(name.c_str()));
		if (!ip) {
			ERR_clear_error();
			return false;
		}
		return true;
	}

	// The verify callback's way to the client's SSL (verify_state).
	void record_ssl(verify_state &state, const X509_STORE_CTX *store) noexcept
	{
		state.ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
	}

	// The server's chain as DER: the leaf, then the rest it sent.
	auto peer_chain_der(const X509_STORE_CTX *store) -> std::vector<std::vector<unsigned char>>
	{
		std::vector<std::vector<unsigned char>> out;
		const auto add = [&out](X509 *cert) {
			const int size = i2d_X509(cert, nullptr);
			if (size <= 0) {
				return false;
			}
			std::vector<unsigned char> der(static_cast<std::size_t>(size));
			unsigned char *p = der.data();
			if (i2d_X509(cert, &p) != size) {
				return false;
			}
			out.push_back(std::move(der));
			return true;
		};
		X509 *leaf = X509_STORE_CTX_get0_cert(store);
		if (leaf == nullptr || !add(leaf)) {
			ERR_clear_error();
			return {};
		}
		if (STACK_OF(X509) *sent = X509_STORE_CTX_get0_untrusted(store); sent != nullptr) {
			for (int i = 0; i < sk_X509_num(sent); ++i) {
				X509 *cert = sk_X509_value(sent, i);
				if (cert != nullptr && X509_cmp(cert, leaf) != 0) {
					add(cert);
				}
			}
		}
		ERR_clear_error();
		return out;
	}

	// What is left of `deadline`, at least 1 ms; nullopt without one.
	auto time_left(const deadline_t &deadline) -> std::optional<std::chrono::milliseconds>
	{
		if (!deadline) {
			return std::nullopt;
		}
		const auto left = std::chrono::ceil<std::chrono::milliseconds>(*deadline - clock::now());
		return std::max(left, std::chrono::milliseconds(1));
	}

	// The platform's verdict on the chain, once at the leaf's final callback;
	// on acceptance the store's error is reset to X509_V_OK.
	auto verify_chain_with_platform(verify_state &state, X509_STORE_CTX *store) -> bool
	{
		state.system_chain_verified = false;
		const int security_level = X509_VERIFY_PARAM_get_auth_level(X509_STORE_CTX_get0_param(store));
		auto r = state.system_chain(peer_chain_der(store), security_level, time_left(state.deadline));
		if (!r) {
			X509_STORE_CTX_set_error(store, X509_V_ERR_CERT_REJECTED);
			if (state.reason.empty()) {
				state.reason.assign(r.error().context);
			}
			return false;
		}
		state.system_chain_verified = true;
		X509_STORE_CTX_set_error(store, X509_V_OK);
		return true;
	}

	// Whether `cert` matches `host` under X509_VERIFY_PARAM `flags`, by
	// OpenSSL's own host check.
	// NOLINTNEXTLINE(misc-const-correctness): OpenSSL 3's X509_STORE_CTX_init takes X509 *
	auto host_matches(X509 *cert, const std::string &host, unsigned flags) -> bool
	{
		const x509_store_ptr store(X509_STORE_new());
		const x509_store_ctx_ptr ctx(X509_STORE_CTX_new());
		if (!store || !ctx || X509_STORE_CTX_init(ctx.get(), store.get(), cert, nullptr) != 1) {
			return false;
		}
		X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx.get());
		if (X509_VERIFY_PARAM_set1_host(param, host.data(), host.size()) != 1) {
			return false;
		}
		X509_VERIFY_PARAM_set_hostflags(param, flags);
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
		X509_STORE_CTX_set_verify_cb(ctx.get(), [](int, X509_STORE_CTX *c) -> int {
			return X509_STORE_CTX_get_error(c) == X509_V_ERR_HOSTNAME_MISMATCH ? 0 : 1;
		});
		ERR_set_mark();
		const int verified = X509_verify_cert(ctx.get());
		ERR_pop_to_mark();
		return verified == 1;
	}

	// Whether `cert` has a subjectAltName DNS name.
	auto has_dns_alt_name(const X509 *cert) -> bool
	{
		auto *names = static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
		if (names == nullptr) {
			return false;
		}
		bool found = false;
		for (int i = 0; i < sk_GENERAL_NAME_num(names) && !found; ++i) {
			found = sk_GENERAL_NAME_value(names, i)->type == GEN_DNS;
		}
		GENERAL_NAMES_free(names);
		return found;
	}

	// The verify callback of certificate_verification::full: records why
	// verification failed, applies strict or legacy host matching, and defers
	// to the platform's chain verdict when it verifies the chain.
	auto verify_full(verify_state &state, bool preverified, X509_STORE_CTX *store) -> bool
	{
		if (store == nullptr) {
			return preverified;
		}
		record_ssl(state, store);
		if (!preverified && !state.legacy_host.empty()
			&& X509_STORE_CTX_get_error(store) == X509_V_ERR_HOSTNAME_MISMATCH
			&& X509_STORE_CTX_get_error_depth(store) == 0) {
			X509 *leaf = X509_STORE_CTX_get_current_cert(store);
			if (!has_dns_alt_name(leaf)
				&& host_matches(leaf, state.legacy_host, X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT)) {
				X509_STORE_CTX_set_error(store, X509_V_OK);
				return true;
			}
		}
		if (state.system_chain != nullptr && !preverified
			&& !fatal_with_platform_chain(X509_STORE_CTX_get_error(store), X509_STORE_CTX_get_error_depth(store))) {
			// The platform accepted: its verdict stands.
			if (state.system_chain_verified) {
				X509_STORE_CTX_set_error(store, X509_V_OK);
			}
			return true;
		}
		if (preverified && !state.strict_host.empty() && X509_STORE_CTX_get_error_depth(store) == 0) {
			const std::string &host = state.strict_host;
			constexpr unsigned flags = X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
			if (!host_matches(X509_STORE_CTX_get_current_cert(store), host, flags)) {
				X509_STORE_CTX_set_error(store, X509_V_ERR_HOSTNAME_MISMATCH);
				preverified = false;
				if (state.reason.empty()) {
					state.reason =
					  "hostname mismatch (strict matching: subjectAltName DNS names only, no "
					  "partial wildcards; certificate depth 0)";
				}
			}
		}
		if (preverified && state.system_chain != nullptr && X509_STORE_CTX_get_error_depth(store) == 0) {
			preverified = verify_chain_with_platform(state, store);
		}
		if (!preverified && state.reason.empty()) {
			const int err = X509_STORE_CTX_get_error(store);
			state.reason = X509_verify_cert_error_string(err);
			ldap::detail::format_to(state.reason, " (certificate depth {})", X509_STORE_CTX_get_error_depth(store));
		}
		return preverified;
	}

	// verify_full without exceptions: one fails verification.
	auto verify_full_noexcept(verify_state &state, bool preverified, X509_STORE_CTX *store) noexcept -> bool
	{
		try {
			return verify_full(state, preverified, store);
		} catch (...) {
			state.system_chain_verified = false;
			if (store != nullptr) {
				X509_STORE_CTX_set_error(store, X509_V_ERR_UNSPECIFIED);
			}
		}
		try {
			if (state.reason.empty()) {
				state.reason = "internal error in the certificate verify callback";
			}
		} catch (...) {
			return false;// no reason then; the handshake still fails
		}
		return false;
	}

	// The verify callback without verification: records the session, accepts
	// everything.
	auto verify_none(verify_state &state, const X509_STORE_CTX *store) noexcept -> bool
	{
		if (store != nullptr) {
			record_ssl(state, store);
		}
		return true;
	}

	// The stream under prime_corosio_openssl()'s handshake: every read and
	// write fails at once, so the handshake ends at its ClientHello.
	struct dead_stream
	{
		auto read_some(const auto & /*buffers*/) -> boost::capy::task<boost::capy::results<std::size_t>>
		{
			co_return { std::make_error_code(std::errc::not_connected), 0 };
		}
		auto write_some(const auto & /*buffers*/) -> boost::capy::task<boost::capy::results<std::size_t>>
		{
			co_return { std::make_error_code(std::errc::not_connected), 0 };
		}
	};

	// One throwaway client handshake on a thread of its own, allocating
	// Corosio's ex_data slot; its failure is expected.
	auto run_throwaway_handshake() noexcept -> bool
	{
		bool ran = false;
		try {
			std::thread([&ran] {
				try {
					corosio::io_context ioc;
					const corosio::tls_context ctx;
					corosio::openssl_stream stream(dead_stream{}, ctx);
					boost::capy::run_async(ioc.get_executor())(stream.handshake(corosio::tls_role::client));
					ioc.run();
					ran = true;
				} catch (...) {
					return;// bad_alloc: tls_handshake() still fails closed
				}
			}).join();
		} catch (...) {
			return false;// no thread (std::system_error)
		}
		return ran;
	}

	auto check(std::error_code ec, std::string_view what) -> result<void>
	{
		if (ec) {
			return fail(ec, what);
		}
		return {};
	}

	// ca_file, ca_dir or ca_pem replace the system's trust anchors.
	auto has_custom_trust(const tls_options &o) -> bool
	{
		return !o.ca_file.empty() || !o.ca_dir.empty() || !o.ca_pem.empty();
	}

	// The trust anchors of certificate_verification::full: the system's,
	// or ca_file, ca_dir and ca_pem.
	auto load_trust(corosio::tls_context &ctx, const tls_options &o) -> result<void>
	{
		if (!has_custom_trust(o)) {
			return load_system_trust(ctx);
		}
		if (!o.ca_file.empty()) {
			const std::string what = "tls: ca_file " + path_text(o.ca_file);
			auto pem = read_file(o.ca_file);
			if (!pem) {
				return fail(std::make_error_code(std::errc::no_such_file_or_directory), what);
			}
			if (auto r = add_cas(ctx, *pem, what); !r) {
				return r;
			}
		}
		if (!o.ca_dir.empty()) {
			const std::string what = "tls: ca_dir " + path_text(o.ca_dir);
			std::error_code ec;
			const auto status = std::filesystem::status(o.ca_dir, ec);
			if (!std::filesystem::exists(status)) {
				return fail(std::make_error_code(std::errc::no_such_file_or_directory), what);
			}
			if (!std::filesystem::is_directory(status)) {
				return fail(std::make_error_code(std::errc::not_a_directory), what);
			}
			// The directory goes as a UTF-8 path.
			if (auto r = check(ctx.add_verify_path(path_text(o.ca_dir)), what); !r) {
				return r;
			}
		}
		if (!o.ca_pem.empty()) {
			return add_cas(ctx, o.ca_pem, "tls: ca_pem");
		}
		return {};
	}

	// Checks a PEM certificate and key, then hands them to the context.
	// Corosio keeps its own copy of the key, which it does not wipe.
	auto use_client_credentials(corosio::tls_context &ctx, const client_credentials &c) -> result<void>
	{
		if (auto r = check_client_credentials(c); !r) {
			return r;
		}
		if (auto r = check(ctx.use_certificate_chain(c.cert_pem), c.cert_what); !r) {
			return r;
		}
		return check(ctx.use_private_key(c.key_pem, corosio::tls_file_format::pem), c.key_what);
	}

	// The client certificate and key, if any.
	auto load_client_credentials(corosio::tls_context &ctx, const tls_options &o) -> result<void>
	{
		const bool files = !o.cert_file.empty() || !o.key_file.empty();
		const bool text = !o.cert_pem.empty() || !o.key_pem.empty();
		if (files && text) {
			return fail(std::make_error_code(std::errc::invalid_argument),
			  "tls: the client certificate comes from either cert_file and key_file or cert_pem and key_pem, not both "
			  "pairs");
		}
		if (text) {
			if (o.cert_pem.empty() != o.key_pem.empty()) {
				return fail(std::make_error_code(std::errc::invalid_argument),
				  "tls: cert_pem and key_pem must be given together");
			}
			return use_client_credentials(ctx,
			  { .cert_pem = o.cert_pem,
				.key_pem = o.key_pem,
				.cert_what = "tls: cert_pem",
				.key_what = "tls: key_pem" });
		}
		if (o.cert_file.empty() != o.key_file.empty()) {
			return fail(
			  std::make_error_code(std::errc::invalid_argument), "tls: cert_file and key_file must be given together");
		}
		if (o.cert_file.empty()) {
			return {};
		}
		const std::string cert_what = "tls: cert_file " + path_text(o.cert_file);
		const std::string key_what = "tls: key_file " + path_text(o.key_file);
		const auto cert_pem = read_file(o.cert_file);
		if (!cert_pem) {
			return fail(std::make_error_code(std::errc::no_such_file_or_directory), cert_what);
		}
		auto key_pem = read_file(o.key_file);
		if (!key_pem) {
			return fail(std::make_error_code(std::errc::no_such_file_or_directory), key_what);
		}
		auto r = use_client_credentials(
		  ctx, { .cert_pem = *cert_pem, .key_pem = *key_pem, .cert_what = cert_what, .key_what = key_what });
		// The buffer read from key_file is ours to wipe; Corosio's copy is not wiped.
		OPENSSL_cleanse(key_pem->data(), key_pem->size());
		return r;
	}

}// namespace

// OpenSSL's own pair (X509_STORE_CTX_get_error, _get_error_depth).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto fatal_with_platform_chain(int error, int depth) noexcept -> bool
{
	switch (error) {
	case X509_V_ERR_HOSTNAME_MISMATCH:
	case X509_V_ERR_IP_ADDRESS_MISMATCH:
	case X509_V_ERR_EE_KEY_TOO_SMALL:
		return true;
	case X509_V_ERR_INVALID_PURPOSE:
		return depth == 0;
	default:
		return false;
	}
}

auto prime_corosio_openssl() noexcept -> bool
{
	// Concurrent callers wait for the warm-up under the lock; a failed one
	// (no thread, bad_alloc) is retried by the next caller.
	static std::mutex mutex;
	static bool primed = false;
	try {
		const std::scoped_lock lock(mutex);
		if (!primed) {
			primed = run_throwaway_handshake();
		}
		return primed;
	} catch (...) {
		return false;// the lock failed (std::system_error)
	}
}

// Every field load_client_credentials() reads.
void clear_client_credentials(tls_options &o) noexcept
{
	o.cert_file.clear();
	o.key_file.clear();
	o.cert_pem.clear();
	o.key_pem.clear();
}

auto make_tls_setup(const tls_options &o) -> result<tls_setup>
{
	// Before any of our tls_contexts reaches its first handshake (see tls.hpp).
	prime_corosio_openssl();
	tls_setup setup;
	auto &ctx = setup.context;

	if (has_control_character(o.server_name)) {
		return fail(std::make_error_code(std::errc::invalid_argument), "tls: control character in server_name");
	}

	if (auto r = check(ctx.set_min_protocol_version(o.min_version), "tls: minimum protocol version"); !r) {
		return std::unexpected(std::move(r.error()));
	}

	if (o.verification == certificate_verification::full) {
		if (auto r = check(ctx.set_verify_mode(corosio::tls_verify_mode::peer), "tls: verify mode"); !r) {
			return std::unexpected(std::move(r.error()));
		}
		if (auto r = load_trust(ctx, o); !r) {
			return std::unexpected(std::move(r.error()));
		}
		// The platform's own chain verification (Windows: CryptoAPI) for the
		// system trust store only: custom anchors are OpenSSL's alone.
		if (!has_custom_trust(o) && platform_verifies_chain()) {
			setup.state->system_chain = verify_system_chain;
		}
		ctx.set_verify_callback([state = setup.state](bool preverified, corosio::verify_context &vc) {
			return verify_full_noexcept(*state, preverified, static_cast<X509_STORE_CTX *>(vc.native_handle()));
		});
	} else {
		if (auto r = check(ctx.set_verify_mode(corosio::tls_verify_mode::none), "tls: verify mode"); !r) {
			return std::unexpected(std::move(r.error()));
		}
		ctx.set_verify_callback([state = setup.state](bool, corosio::verify_context &vc) {
			return verify_none(*state, static_cast<X509_STORE_CTX *>(vc.native_handle()));
		});
	}

	if (auto r = load_client_credentials(ctx, o); !r) {
		return std::unexpected(std::move(r.error()));
	}
	return setup;
}

auto tls_peer_name(std::string_view host, const tls_options &options) -> std::string
{
	std::string name;
	if (!options.server_name.empty()) {
		name.assign(options.server_name);
	} else if (host.contains(':')) {
		name.assign(host.substr(0, host.find('%')));// IPv6 literal
	} else {
		name.assign(host);
	}
	// A fully qualified name's trailing dot is dropped (RFC 6066 section 3);
	// one that would then read as an IP literal stays a DNS name.
	if (name.size() > 1 && name.ends_with('.')) {
		std::string bare = name.substr(0, name.size() - 1);
		if (!is_ip_literal(bare)) {
			return bare;
		}
	}
	return name;
}

auto tls_handshake(transport::layers &im,
  std::string_view host,
  const tls_options &options,
  tls_setup setup,
  deadline_t deadline) -> boost::capy::task<result<void>>
{
	// The documented precondition; both callers check for an open TCP transport.
	if (!im.tcp) {
		co_return fail(std::make_error_code(std::errc::invalid_argument), "tls handshake: no TCP socket");
	}
	const std::string name = tls_peer_name(host, options);
	if (options.verification == certificate_verification::full && options.host_matching == host_name_matching::strict
		&& !is_ip_literal(name)) {
		setup.state->strict_host = name;
	}
	if (options.verification == certificate_verification::full && options.host_matching == host_name_matching::legacy
		&& !is_ip_literal(name)) {
		setup.state->legacy_host = name;
	}
	setup.state->deadline = deadline;
	// im.tls is kept only if the handshake succeeds.
	ldap::detail::scope_exit undo_tls{ [&im] {
		clear_tls_session(im);
		im.tls.reset();
		im.tls_context.reset();
	} };
	const auto &ctx = im.tls_context.emplace(std::move(setup.context));
	auto &stream = im.tls.emplace(&*im.tcp, ctx);
	stream.set_hostname(name);
	auto [ec] = co_await bounded(stream.handshake(corosio::tls_role::client), deadline);
	if (ec) {
		std::string context = "tls handshake";
		if (!setup.state->reason.empty()) {
			context += ": server certificate: " + setup.state->reason;
		}
		co_return fail(ec, std::move(context));
	}
	// Fail closed if the verify callback never ran.
	if (setup.state->ssl == nullptr) {
		co_return fail(client_errc::internal_error, "tls handshake: the certificate verify callback did not run");
	}
	// Fail closed if OpenSSL's errors were let through for the platform's
	// verdict but the leaf's final callback, which asks for it, never ran.
	if (setup.state->system_chain != nullptr && !setup.state->system_chain_verified) {
		co_return fail(client_errc::internal_error, "tls handshake: the system certificate chain check did not run");
	}
	record_tls_session(im, std::exchange(setup.state->ssl, nullptr));
	im.stream = boost::capy::any_stream(&stream);
	undo_tls.release();
	co_return result<void>{};
}

}// namespace jhetz::ldap::net::detail
