// Helpers for the jhetz::ldap_net tests: running coroutines to completion
// with a time limit, a throwaway PKI built with the OpenSSL API, temp paths.
#pragma once

#include "jhetz/ldap/message.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace jhetz::ldap::test {

namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace std::chrono_literals;

// Upper bound for one test's I/O. Only reached when a test is broken (a
// coroutine waits for something that never comes); passing tests finish in
// milliseconds, and nothing sleeps.
inline constexpr std::chrono::seconds io_limit{ 20 };

// Starts `t` on `ioc`. The result (or exception) is stored in `out`.
template<class T> struct outcome
{
	std::optional<T> value{};
	std::exception_ptr error{};
	bool done() const noexcept { return value.has_value() || error != nullptr; }
	T &get()
	{
		if (error) std::rethrow_exception(error);
		if (!value) throw std::runtime_error("task did not finish within the time limit");
		return *value;
	}
};

template<> struct outcome<void>
{
	bool finished = false;
	std::exception_ptr error{};
	bool done() const noexcept { return finished || error != nullptr; }
	void get()
	{
		if (error) std::rethrow_exception(error);
		if (!finished) throw std::runtime_error("task did not finish within the time limit");
	}
};

template<class T> void spawn(corosio::io_context &ioc, capy::task<T> t, outcome<T> &out)
{
	if constexpr (std::is_void_v<T>)
		capy::run_async(
		  ioc.get_executor(), [&out] { out.finished = true; }, [&out](std::exception_ptr e) { out.error = e; })(
		  std::move(t));
	else
		capy::run_async(
		  ioc.get_executor(),
		  [&out](T v) { out.value.emplace(std::move(v)); },
		  [&out](std::exception_ptr e) { out.error = e; })(std::move(t));
}

// spawn() with a stop token, to cancel the task from the test.
template<class T> void spawn(corosio::io_context &ioc, std::stop_token st, capy::task<T> t, outcome<T> &out)
{
	if constexpr (std::is_void_v<T>)
		capy::run_async(
		  ioc.get_executor(),
		  std::move(st),
		  [&out] { out.finished = true; },
		  [&out](std::exception_ptr e) { out.error = e; })(std::move(t));
	else
		capy::run_async(
		  ioc.get_executor(),
		  std::move(st),
		  [&out](T v) { out.value.emplace(std::move(v)); },
		  [&out](std::exception_ptr e) { out.error = e; })(std::move(t));
}

// Runs `ioc` until it has no work left, at most io_limit.
inline void drive(corosio::io_context &ioc)
{
	ioc.run_for(io_limit);
	ioc.restart();
}

// Runs `ioc` until `done()` holds or it has no work left, at most io_limit.
// Unlike drive(), returns as soon as `done()` holds even if other coroutines
// (a scripted server waiting for the next request) still have work pending.
template<class Pred> void drive_until(corosio::io_context &ioc, Pred done)
{
	const auto deadline = std::chrono::steady_clock::now() + io_limit;
	while (!done() && ioc.run_one_until(deadline) != 0) {}
	ioc.restart();
}

// Runs one task to completion and returns its result, after running `ioc`
// until it has no work left (so peers spawned on it finish too).
template<class T> T run(corosio::io_context &ioc, capy::task<T> t)
{
	outcome<T> out;
	spawn(ioc, std::move(t), out);
	drive(ioc);
	if constexpr (std::is_void_v<T>)
		out.get();
	else
		return std::move(out.get());
}

// ---------------------------------------------------------------- messages

inline message bind_request_msg(std::int32_t id, std::string_view name = "cn=admin,dc=example,dc=org")
{
	return message{ id, bind_request{ 3, name, simple_auth{ "secret" } } };
}

inline message bind_response_msg(std::int32_t id, std::string_view diagnostic = {})
{
	return message{ id, bind_response{ { 0, "", diagnostic } } };
}

inline std::string bytes_of(const message &m)
{
	auto b = encode(m);
	if (!b) throw std::runtime_error("encode failed: " + std::string(b.error().message()));
	return std::string(reinterpret_cast<const char *>(b->data()), b->size());
}

// ---------------------------------------------------------------- PKI

// A throwaway CA and certificates signed by it, all in memory (EC P-256).
class test_pki
{
  public:
	struct issued
	{
		std::string cert_pem{};
		std::string key_pem{};
	};

	explicit test_pki(const char *ca_name = "jhetz-ldap test CA")
	{
		ca_key_.reset(generate_key());
		ca_cert_.reset(make_cert(ca_key_.get(), ca_name, nullptr, nullptr, true, {}, next_serial()));
		ca_pem_ = to_pem(ca_cert_.get());
	}

	const std::string &ca_pem() const noexcept { return ca_pem_; }

	// A leaf certificate for `subject_alt_names` ("DNS:localhost,IP:127.0.0.1").
	issued issue(const char *cn, const std::string &subject_alt_names)
	{
		std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(generate_key(), &EVP_PKEY_free);
		std::unique_ptr<X509, decltype(&X509_free)> cert(
		  make_cert(key.get(), cn, ca_cert_.get(), ca_key_.get(), false, subject_alt_names, next_serial()), &X509_free);
		return { to_pem(cert.get()), key_to_pem(key.get()) };
	}

  private:
	struct key_free
	{
		void operator()(EVP_PKEY *k) const noexcept { EVP_PKEY_free(k); }
	};
	struct cert_free
	{
		void operator()(X509 *c) const noexcept { X509_free(c); }
	};

	static void check(bool ok, const char *what)
	{
		if (!ok) throw std::runtime_error(std::string("test PKI: ") + what + " failed");
	}

	long next_serial() noexcept { return ++serial_; }

	static EVP_PKEY *generate_key()
	{
		std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
		  EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
		check(ctx != nullptr, "EVP_PKEY_CTX_new_id");
		check(EVP_PKEY_keygen_init(ctx.get()) == 1, "EVP_PKEY_keygen_init");
		check(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) == 1, "set curve");
		EVP_PKEY *key = nullptr;
		check(EVP_PKEY_keygen(ctx.get(), &key) == 1, "EVP_PKEY_keygen");
		return key;
	}

	static void add_ext(X509 *cert, X509V3_CTX *ctx, int nid, const std::string &value)
	{
		X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, ctx, nid, value.c_str());
		check(ext != nullptr, "X509V3_EXT_conf_nid");
		const bool ok = X509_add_ext(cert, ext, -1) == 1;
		X509_EXTENSION_free(ext);
		check(ok, "X509_add_ext");
	}

	static X509 *make_cert(EVP_PKEY *key,
	  const char *cn,
	  X509 *issuer,
	  EVP_PKEY *issuer_key,
	  bool ca,
	  const std::string &sans,
	  long serial)
	{
		X509 *cert = X509_new();
		check(cert != nullptr, "X509_new");
		check(X509_set_version(cert, 2) == 1, "X509_set_version");
		check(ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) == 1, "serial");
		check(X509_gmtime_adj(X509_getm_notBefore(cert), -3600) != nullptr, "notBefore");
		check(X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 3600) != nullptr, "notAfter");
		check(X509_set_pubkey(cert, key) == 1, "X509_set_pubkey");
		X509_NAME *name = X509_get_subject_name(cert);
		check(
		  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cn), -1, -1, 0)
			== 1,
		  "CN");
		check(X509_set_issuer_name(cert, issuer ? X509_get_subject_name(issuer) : name) == 1, "issuer");

		X509V3_CTX ctx;
		X509V3_set_ctx_nodb(&ctx);
		X509V3_set_ctx(&ctx, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
		add_ext(cert, &ctx, NID_subject_key_identifier, "hash");
		if (ca) {
			add_ext(cert, &ctx, NID_basic_constraints, "critical,CA:TRUE");
			add_ext(cert, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
		} else {
			add_ext(cert, &ctx, NID_authority_key_identifier, "keyid:always");
			add_ext(cert, &ctx, NID_basic_constraints, "CA:FALSE");
			add_ext(cert, &ctx, NID_key_usage, "critical,digitalSignature");
			add_ext(cert, &ctx, NID_ext_key_usage, "serverAuth,clientAuth");
			if (!sans.empty()) add_ext(cert, &ctx, NID_subject_alt_name, sans);
		}
		check(X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256()) > 0, "X509_sign");
		return cert;
	}

	static std::string from_bio(BIO *bio)
	{
		char *data = nullptr;
		const long len = BIO_get_mem_data(bio, &data);
		std::string out(data, static_cast<std::size_t>(len));
		BIO_free(bio);
		return out;
	}

	static std::string to_pem(X509 *cert)
	{
		BIO *bio = BIO_new(BIO_s_mem());
		check(bio != nullptr && PEM_write_bio_X509(bio, cert) == 1, "PEM_write_bio_X509");
		return from_bio(bio);
	}

	static std::string key_to_pem(EVP_PKEY *key)
	{
		BIO *bio = BIO_new(BIO_s_mem());
		check(bio != nullptr && PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
		  "PEM_write_bio_PrivateKey");
		return from_bio(bio);
	}

	std::unique_ptr<EVP_PKEY, key_free> ca_key_{};
	std::unique_ptr<X509, cert_free> ca_cert_{};
	std::string ca_pem_{};
	long serial_ = 0;
};

// ---------------------------------------------------------------- files

// A path in the temp directory, unique to this process and call, removed
// when the object goes away. Short enough for sockaddr_un.
class temp_path
{
  public:
	explicit temp_path(const char *suffix)
	{
		static std::atomic<int> counter{ 0 };
		path_ = (std::filesystem::temp_directory_path()
				 / ("jhetz-ldap-" + std::to_string(::getpid()) + "-" + std::to_string(counter++) + suffix))
				  .string();
	}
	temp_path(const temp_path &) = delete;
	temp_path &operator=(const temp_path &) = delete;
	~temp_path()
	{
		std::error_code ec;
		std::filesystem::remove(path_, ec);
	}
	const std::string &str() const noexcept { return path_; }

	void write(const std::string &contents) const
	{
		std::FILE *f = std::fopen(path_.c_str(), "wb");
		if (f == nullptr) throw std::runtime_error("cannot write " + path_);
		const bool ok = std::fwrite(contents.data(), 1, contents.size(), f) == contents.size();
		if (std::fclose(f) != 0 || !ok) throw std::runtime_error("cannot write " + path_);
	}

  private:
	std::string path_{};
};

// RFC 3986 percent-encoding of everything but unreserved characters.
inline std::string percent_encode(std::string_view s)
{
	static constexpr char hex[] = "0123456789ABCDEF";
	std::string out;
	for (char c : s) {
		const auto b = static_cast<unsigned char>(c);
		if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || c == '-' || c == '.'
			|| c == '_' || c == '~') {
			out += c;
		} else {
			out += '%';
			out += hex[b >> 4];
			out += hex[b & 0xF];
		}
	}
	return out;
}

}// namespace jhetz::ldap::test
