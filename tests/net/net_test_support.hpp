// Helpers for the jhetz::ldap_net tests: running coroutines to completion
// with a time limit, a throwaway PKI built with the OpenSSL API, temp paths.
#pragma once

#include "jhetz/ldap/message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <boost/capy/ex/frame_allocator.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <memory_resource>
#include <new>
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
	[[nodiscard]] auto done() const noexcept -> bool { return value.has_value() || error != nullptr; }
	auto get() -> T &
	{
		if (error) {
			std::rethrow_exception(error);
		}
		if (!value) {
			throw std::runtime_error("task did not finish within the time limit");
		}
		return *value;
	}
};

template<> struct outcome<void>
{
	bool finished = false;
	std::exception_ptr error{};
	[[nodiscard]] auto done() const noexcept -> bool { return finished || error != nullptr; }
	void get()
	{
		if (error) {
			std::rethrow_exception(error);
		}
		if (!finished) {
			throw std::runtime_error("task did not finish within the time limit");
		}
	}
};

template<class T> void spawn(corosio::io_context &ioc, capy::task<T> t, outcome<T> &out)
{
	if constexpr (std::is_void_v<T>) {
		capy::run_async(
		  ioc.get_executor(), [&out] { out.finished = true; }, [&out](std::exception_ptr e) { out.error = e; })(
		  std::move(t));
	} else {
		capy::run_async(
		  ioc.get_executor(),
		  [&out](T v) { out.value.emplace(std::move(v)); },
		  [&out](std::exception_ptr e) { out.error = e; })(std::move(t));
	}
}

// spawn() with a stop token, to cancel the task from the test.
template<class T> void spawn(corosio::io_context &ioc, std::stop_token st, capy::task<T> t, outcome<T> &out)
{
	if constexpr (std::is_void_v<T>) {
		capy::run_async(
		  ioc.get_executor(),
		  std::move(st),
		  [&out] { out.finished = true; },
		  [&out](std::exception_ptr e) { out.error = e; })(std::move(t));
	} else {
		capy::run_async(
		  ioc.get_executor(),
		  std::move(st),
		  [&out](T v) { out.value.emplace(std::move(v)); },
		  [&out](std::exception_ptr e) { out.error = e; })(std::move(t));
	}
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
template<class T> auto run(corosio::io_context &ioc, capy::task<T> t) -> T
{
	outcome<T> out;
	spawn(ioc, std::move(t), out);
	drive(ioc);
	if constexpr (std::is_void_v<T>) {
		out.get();
	} else {
		return std::move(out.get());
	}
}

// Runs one task until it finishes and returns its result, without waiting
// for other work on `ioc` (a server still parked on a read, say).
template<class T> auto finish(corosio::io_context &ioc, capy::task<T> t) -> T
{
	outcome<T> out;
	spawn(ioc, std::move(t), out);
	drive_until(ioc, [&out] { return out.done(); });
	if constexpr (std::is_void_v<T>) {
		out.get();
	} else {
		return std::move(out.get());
	}
}

// The io_context's frame allocator in the out-of-memory tests: counts the
// coroutine frames allocated from it (every run_async's and its task's, and
// their children's) and can fail one allocation with bad_alloc (or, with
// `other`, a std::runtime_error: an exception that is not bad_alloc).
class failing_frames final : public std::pmr::memory_resource
{
  public:
	// The n-th allocation from now fails (1 for the next one; 0: none).
	void fail_at(std::size_t n, bool other = false) noexcept
	{
		count_ = 0;
		fail_ = n;
		other_ = other;
	}
	// Allocations attempted since fail_at().
	[[nodiscard]] auto count() const noexcept -> std::size_t { return count_; }
	// Frames allocated and not yet freed.
	[[nodiscard]] auto live() const noexcept -> std::size_t { return live_; }

  private:
	auto do_allocate(std::size_t bytes, std::size_t align) -> void * override
	{
		if (++count_ == fail_) {
			if (other_) {
				throw std::runtime_error("injected frame allocation failure");
			}
			throw std::bad_alloc();
		}
		void *p = std::pmr::new_delete_resource()->allocate(bytes, align);
		++live_;
		return p;
	}
	void do_deallocate(void *p, std::size_t bytes, std::size_t align) override
	{
		--live_;
		std::pmr::new_delete_resource()->deallocate(p, bytes, align);
	}
	[[nodiscard]] auto do_is_equal(const std::pmr::memory_resource &other) const noexcept -> bool override
	{
		return this == &other;
	}

	std::size_t count_ = 0;
	std::size_t fail_ = 0;
	std::size_t live_ = 0;
	bool other_ = false;
};

// Corosio resumes coroutines without restoring the thread's current frame
// allocator, so it can still be a failing_frames once the io_context has
// run: cleared before that goes, for the frames made after the test.
struct clear_frame_allocator
{
	clear_frame_allocator() = default;
	clear_frame_allocator(const clear_frame_allocator &) = delete;
	auto operator=(const clear_frame_allocator &) -> clear_frame_allocator & = delete;
	~clear_frame_allocator() { capy::set_current_frame_allocator(nullptr); }
};

// Tests that rely on Linux loopback behaviour: all of 127/8 is routed to lo
// (127.0.0.2 works without configuration), and a listener with a full
// backlog drops SYNs instead of refusing them, so a connect stays pending.
// Other systems refuse such a connect or lack the address.
inline void skip_unless_linux_loopback()
{
#if !defined(__linux__)
	SKIP("needs Linux loopback behaviour (127/8 routed, SYN dropped at a full backlog)");
#endif
}

// ---------------------------------------------------------------- messages

inline auto bind_request_msg(std::int32_t id, std::string_view name = "cn=admin,dc=example,dc=org") -> message
{
	return message{ id, bind_request{ 3, name, simple_auth{ "secret" } } };
}

inline auto bind_response_msg(std::int32_t id, std::string_view diagnostic = {}) -> message
{
	return message{ id, bind_response{ { 0, "", diagnostic } } };
}

inline auto bytes_of(const message &m) -> std::string
{
	auto b = encode(m);
	if (!b) {
		throw std::runtime_error("encode failed: " + std::string(b.error().message()));
	}
	return std::string(ldap::detail::as_text(*b));
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

	[[nodiscard]] auto ca_pem() const noexcept -> const std::string & { return ca_pem_; }

	// The CA's subject name hash: "<hash, 8 hex digits>.0" is its file name
	// in a c_rehash-style CA directory.
	[[nodiscard]] auto ca_subject_hash() const -> unsigned long { return X509_subject_name_hash(ca_cert_.get()); }

	// `key_pem` re-encrypted with AES-256-CBC under `passphrase`.
	static auto encrypted_key_pem(const std::string &key_pem, const std::string &passphrase) -> std::string
	{
		BIO *in = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
		check(in != nullptr, "BIO_new_mem_buf");
		std::unique_ptr<EVP_PKEY, key_free> key(PEM_read_bio_PrivateKey(in, nullptr, nullptr, nullptr));
		BIO_free(in);
		check(key != nullptr, "PEM_read_bio_PrivateKey");
		BIO *bio = BIO_new(BIO_s_mem());
		check(bio != nullptr
				&& PEM_write_bio_PKCS8PrivateKey(bio,
					 key.get(),
					 EVP_aes_256_cbc(),
					 passphrase.data(),
					 static_cast<int>(passphrase.size()),
					 nullptr,
					 nullptr)
					 == 1,
		  "PEM_write_bio_PKCS8PrivateKey");
		return from_bio(bio);
	}

	// A leaf certificate for `subject_alt_names` ("DNS:localhost,IP:127.0.0.1").
	auto issue(const char *cn, const std::string &subject_alt_names) -> issued
	{
		std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(generate_key(), &EVP_PKEY_free);
		std::unique_ptr<X509, decltype(&X509_free)> cert(
		  make_cert(key.get(), cn, ca_cert_.get(), ca_key_.get(), false, subject_alt_names, next_serial()), &X509_free);
		return { .cert_pem = to_pem(cert.get()), .key_pem = key_to_pem(key.get()) };
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
		if (!ok) {
			throw std::runtime_error(std::string("test PKI: ") + what + " failed");
		}
	}

	auto next_serial() noexcept -> long { return ++serial_; }

	static auto generate_key() -> EVP_PKEY *
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

	static auto make_cert(EVP_PKEY *key,
	  const char *cn,
	  X509 *issuer,
	  EVP_PKEY *issuer_key,
	  bool ca,
	  const std::string &sans,
	  long serial) -> X509 *
	{
		X509 *cert = X509_new();
		check(cert != nullptr, "X509_new");
		check(X509_set_version(cert, 2) == 1, "X509_set_version");
		check(ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) == 1, "serial");
		check(X509_gmtime_adj(X509_getm_notBefore(cert), -3600) != nullptr, "notBefore");
		check(X509_gmtime_adj(X509_getm_notAfter(cert), 24L * 3600) != nullptr, "notAfter");
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
			if (!sans.empty()) {
				add_ext(cert, &ctx, NID_subject_alt_name, sans);
			}
		}
		check(X509_sign(cert, issuer_key ? issuer_key : key, EVP_sha256()) > 0, "X509_sign");
		return cert;
	}

	static auto from_bio(BIO *bio) -> std::string
	{
		char *data = nullptr;
		const long len = BIO_get_mem_data(bio, &data);
		std::string out(data, static_cast<std::size_t>(len));
		BIO_free(bio);
		return out;
	}

	static auto to_pem(X509 *cert) -> std::string
	{
		BIO *bio = BIO_new(BIO_s_mem());
		check(bio != nullptr && PEM_write_bio_X509(bio, cert) == 1, "PEM_write_bio_X509");
		return from_bio(bio);
	}

	static auto key_to_pem(EVP_PKEY *key) -> std::string
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
	auto operator=(const temp_path &) -> temp_path & = delete;
	~temp_path()
	{
		std::error_code ec;
		std::filesystem::remove(path_, ec);
	}
	[[nodiscard]] auto str() const noexcept -> const std::string & { return path_; }

	void write(const std::string &contents) const
	{
		std::FILE *f = std::fopen(path_.c_str(), "wb");
		if (f == nullptr) {
			throw std::runtime_error("cannot write " + path_);
		}
		const bool ok = std::fwrite(contents.data(), 1, contents.size(), f) == contents.size();
		if (std::fclose(f) != 0 || !ok) {
			throw std::runtime_error("cannot write " + path_);
		}
	}

  private:
	std::string path_{};
};

// RFC 3986 percent-encoding of everything but unreserved characters.
inline auto percent_encode(std::string_view s) -> std::string
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
