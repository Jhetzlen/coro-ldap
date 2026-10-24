// TLS channel bindings (channel_binding.hpp): tls-server-end-point's hash
// choice per signature algorithm (RFC 5929 section 4.1, and OpenLDAP's),
// then over ldaps:// against in-process servers: the peer certificate,
// tls-exporter (RFC 9266) equal to what the server's side computes,
// SCRAM-SHA-256-PLUS carrying it in c=, TLS 1.2 without the extended master
// secret, an Ed25519 server certificate, and renegotiation refused.
#include "../../src/net/channel_binding.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/sasl_scram.hpp"
#include "net_test_support.hpp"

#include <boost/corosio/openssl_stream.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tls_context.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_container_properties.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <latch>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::IsEmpty;
using Catch::Matchers::StartsWith;

namespace {

using bytes = std::vector<std::byte>;

struct pkey_free
{
	void operator()(EVP_PKEY *k) const noexcept { EVP_PKEY_free(k); }
};
struct x509_free
{
	void operator()(X509 *c) const noexcept { X509_free(c); }
};
using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using x509_ptr = std::unique_ptr<X509, x509_free>;

// A new key of `type` ("EC" with `curve`, "RSA", "ED25519").
auto keygen(const char *type, const char *curve = nullptr) -> pkey_ptr
{
	const std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
	  EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr), &EVP_PKEY_CTX_free);
	REQUIRE(ctx != nullptr);
	REQUIRE(EVP_PKEY_keygen_init(ctx.get()) == 1);
	if (curve != nullptr) {
		REQUIRE(EVP_PKEY_CTX_set_group_name(ctx.get(), curve) == 1);
	}
	EVP_PKEY *key = nullptr;
	REQUIRE(EVP_PKEY_keygen(ctx.get(), &key) == 1);
	return pkey_ptr(key);
}

auto ec_key(const char *curve) -> pkey_ptr { return keygen("EC", curve); }

auto rsa_key() -> EVP_PKEY *
{
	static const pkey_ptr key = keygen("RSA");// 2048 bits by default
	return key.get();
}

// A self-signed certificate signed with `md` (null for Ed25519), or with
// RSASSA-PSS when `pss` (MGF1 with the same hash).
auto self_signed_x509(EVP_PKEY *key, const EVP_MD *md, bool pss = false) -> x509_ptr
{
	x509_ptr cert(X509_new());
	REQUIRE(cert != nullptr);
	REQUIRE(X509_set_version(cert.get(), 2) == 1);
	REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1);
	REQUIRE(X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) != nullptr);
	REQUIRE(X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600) != nullptr);
	REQUIRE(X509_set_pubkey(cert.get(), key) == 1);
	X509_NAME *name = X509_get_subject_name(cert.get());
	REQUIRE(
	  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("cb"), -1, -1, 0)
	  == 1);
	REQUIRE(X509_set_issuer_name(cert.get(), name) == 1);
	if (pss) {
		const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
		EVP_PKEY_CTX *pctx = nullptr;
		REQUIRE(EVP_DigestSignInit(ctx.get(), &pctx, md, nullptr, key) == 1);
		REQUIRE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1);
		REQUIRE(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) == 1);
		REQUIRE(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1);
		REQUIRE(X509_sign_ctx(cert.get(), ctx.get()) > 0);
	} else {
		REQUIRE(X509_sign(cert.get(), key, md) > 0);
	}
	return cert;
}

auto der_of(const X509 *cert) -> bytes
{
	unsigned char *der = nullptr;
	const int n = i2d_X509(cert, &der);
	REQUIRE(n > 0);
	const auto *b = reinterpret_cast<const std::byte *>(der);
	bytes out(b, b + n);
	OPENSSL_free(der);
	return out;
}

auto self_signed(EVP_PKEY *key, const EVP_MD *md, bool pss = false) -> bytes
{
	return der_of(self_signed_x509(key, md, pss).get());
}

auto pem_of(const std::function<int(BIO *)> &write) -> std::string
{
	const std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
	REQUIRE(bio != nullptr);
	REQUIRE(write(bio.get()) == 1);
	char *data = nullptr;
	const long n = BIO_get_mem_data(bio.get(), &data);
	return { data, static_cast<std::size_t>(n) };
}

// A self-signed Ed25519 server certificate (no subjectAltName: connect
// with certificate_verification::insecure_accept_any).
struct ed25519_leaf
{
	std::string cert_pem{};
	std::string key_pem{};
	bytes der{};
};

auto ed25519_server() -> const ed25519_leaf &
{
	static const ed25519_leaf leaf = [] {
		const pkey_ptr key = keygen("ED25519");
		const x509_ptr cert = self_signed_x509(key.get(), nullptr);
		return ed25519_leaf{
			.cert_pem = pem_of([&](BIO *b) { return PEM_write_bio_X509(b, cert.get()); }),
			.key_pem = pem_of(
			  [&](BIO *b) { return PEM_write_bio_PrivateKey(b, key.get(), nullptr, nullptr, 0, nullptr, nullptr); }),
			.der = der_of(cert.get()),
		};
	}();
	return leaf;
}

auto digest(std::span<const std::byte> data, const EVP_MD *md) -> bytes
{
	std::array<unsigned char, EVP_MAX_MD_SIZE> out{};
	unsigned int n = 0;
	REQUIRE(EVP_Digest(data.data(), data.size(), out.data(), &n, md, nullptr) == 1);
	const auto *b = reinterpret_cast<const std::byte *>(out.data());
	return { b, b + n };
}

auto to_bytes(std::span<const std::byte> s) -> bytes { return { s.begin(), s.end() }; }

}// namespace

TEST_CASE("channel binding: tls-server-end-point hashes per signature algorithm", "[net][tls][channel_binding][rfc]")
{
	using net::detail::tls_server_end_point;
	SECTION("ECDSA with SHA-256: SHA-256")
	{
		const auto der = self_signed(ec_key("P-256").get(), EVP_sha256());
		CHECK(tls_server_end_point(der) == digest(der, EVP_sha256()));
	}
	SECTION("ECDSA with SHA-384: SHA-384")
	{
		const auto der = self_signed(ec_key("P-384").get(), EVP_sha384());
		const auto hash = tls_server_end_point(der);
		CHECK(hash.size() == 48);
		CHECK(hash == digest(der, EVP_sha384()));
	}
	SECTION("ECDSA with SHA-224: SHA-224")
	{
		const auto der = self_signed(ec_key("P-256").get(), EVP_sha224());
		CHECK(tls_server_end_point(der) == digest(der, EVP_sha224()));
	}
	SECTION("RSA with SHA-512: SHA-512")
	{
		const auto der = self_signed(rsa_key(), EVP_sha512());
		const auto hash = tls_server_end_point(der);
		CHECK(hash.size() == 64);
		CHECK(hash == digest(der, EVP_sha512()));
	}
	SECTION("RSASSA-PSS with SHA-384: SHA-384")
	{
		const auto der = self_signed(rsa_key(), EVP_sha384(), true);
		CHECK(tls_server_end_point(der) == digest(der, EVP_sha384()));
	}
	SECTION("RSA with SHA-1: SHA-256 instead")
	{
		const auto der = self_signed(rsa_key(), EVP_sha1());
		CHECK(tls_server_end_point(der) == digest(der, EVP_sha256()));
	}
	SECTION("RSA with MD5: SHA-256 instead")
	{
		const auto der = self_signed(rsa_key(), EVP_md5());
		CHECK(tls_server_end_point(der) == digest(der, EVP_sha256()));
	}
	SECTION("ECDSA with SHA-1: SHA-256 instead")
	{
		const auto der = self_signed(ec_key("P-256").get(), EVP_sha1());
		CHECK(tls_server_end_point(der) == digest(der, EVP_sha256()));
	}
	SECTION("Ed25519 (no separate hash function): undefined")
	{
		CHECK(tls_server_end_point(self_signed(keygen("ED25519").get(), nullptr)).empty());
	}
	SECTION("not a certificate")
	{
		const std::array<std::byte, 3> junk{ std::byte{ 0x30 }, std::byte{ 0x01 }, std::byte{ 0x00 } };
		CHECK(tls_server_end_point(junk).empty());
		CHECK(tls_server_end_point({}).empty());
	}
}

TEST_CASE("channel binding: OpenLDAP's tls-server-end-point hash choice", "[net][tls][channel_binding]")
{
	// libldap's tlso_session_endpoint: the hash the signature algorithm's
	// OID names, SHA-256 when it names none or a weak one.
	using net::detail::openldap_tls_server_end_point;
	SECTION("ECDSA with SHA-384: SHA-384, as RFC 5929")
	{
		const auto der = self_signed(ec_key("P-384").get(), EVP_sha384());
		CHECK(openldap_tls_server_end_point(der) == digest(der, EVP_sha384()));
	}
	SECTION("RSA with SHA-512: SHA-512, as RFC 5929")
	{
		const auto der = self_signed(rsa_key(), EVP_sha512());
		CHECK(openldap_tls_server_end_point(der) == digest(der, EVP_sha512()));
	}
	SECTION("RSASSA-PSS with SHA-384: SHA-256, where RFC 5929 takes SHA-384")
	{
		const auto der = self_signed(rsa_key(), EVP_sha384(), true);
		CHECK(openldap_tls_server_end_point(der) == digest(der, EVP_sha256()));
		CHECK(net::detail::tls_server_end_point(der) == digest(der, EVP_sha384()));
	}
	SECTION("Ed25519: SHA-256, where RFC 5929 has none")
	{
		const auto der = self_signed(keygen("ED25519").get(), nullptr);
		CHECK(openldap_tls_server_end_point(der) == digest(der, EVP_sha256()));
	}
	SECTION("RSA with SHA-1 or MD5: SHA-256")
	{
		const auto sha1 = self_signed(rsa_key(), EVP_sha1());
		CHECK(openldap_tls_server_end_point(sha1) == digest(sha1, EVP_sha256()));
		const auto md5 = self_signed(rsa_key(), EVP_md5());
		CHECK(openldap_tls_server_end_point(md5) == digest(md5, EVP_sha256()));
	}
	SECTION("not a certificate")
	{
		const std::array<std::byte, 3> junk{ std::byte{ 0x30 }, std::byte{ 0x01 }, std::byte{ 0x00 } };
		CHECK(openldap_tls_server_end_point(junk).empty());
		CHECK(openldap_tls_server_end_point({}).empty());
	}
}

// ---------------------------------------------------------------- over ldaps://

namespace {

const net::read_options as_server{ .decode = { .from = ldap::origin::client } };

auto pki() -> test_pki &
{
	static test_pki instance("jhetz-ldap channel binding test CA");
	return instance;
}

auto server_leaf() -> const test_pki::issued &
{
	static const auto leaf = pki().issue("localhost", "DNS:localhost,IP:127.0.0.1");
	return leaf;
}

auto client_leaf() -> const test_pki::issued &
{
	static const auto leaf = pki().issue("client", "");
	return leaf;
}

// What the server's side of the connection saw. Its SSL is reached the way
// the library reaches the client's (src/net/tls.hpp): through the verify
// callback, which runs because the server asks for a client certificate.
struct server_view
{
	SSL *ssl = nullptr;
	bytes exporter{};
	int version = 0;
	std::vector<std::string> sasl_credentials{};// of each BindRequest
};

// The server's certificate and key (PEM).
struct server_identity
{
	std::string cert_pem{};
	std::string key_pem{};
};

auto ecdsa_identity() -> server_identity
{
	return { .cert_pem = server_leaf().cert_pem, .key_pem = server_leaf().key_pem };
}

auto ed25519_identity() -> server_identity
{
	return { .cert_pem = ed25519_server().cert_pem, .key_pem = ed25519_server().key_pem };
}

auto server_context(const std::shared_ptr<server_view> &view,
  std::optional<corosio::tls_version> max_version,
  const server_identity &id) -> corosio::tls_context
{
	corosio::tls_context ctx;
	REQUIRE_FALSE(ctx.use_certificate(id.cert_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.use_private_key(id.key_pem, corosio::tls_file_format::pem));
	REQUIRE_FALSE(ctx.set_verify_mode(corosio::tls_verify_mode::require_peer));
	REQUIRE_FALSE(ctx.add_certificate_authority(pki().ca_pem()));
	if (max_version) {
		REQUIRE_FALSE(ctx.set_max_protocol_version(*max_version));
	}
	ctx.set_verify_callback([view](bool preverified, corosio::verify_context &vc) {
		auto *store = static_cast<X509_STORE_CTX *>(vc.native_handle());
		if (store != nullptr) {
			view->ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
		}
		return preverified;
	});
	return ctx;
}

// TLS handshake, then answers SASL BindRequests: each gets `answers` in
// turn (a saslBindInProgress with a SCRAM server-first-message built on
// the client's nonce, then invalidCredentials), and records them.
auto serve(corosio::tcp_acceptor &acc, corosio::tls_context ctx, std::shared_ptr<server_view> view)
  -> capy::task<std::string>
{
	auto [ec, peer] = co_await acc.accept();
	if (ec) {
		co_return "accept: " + ec.message();
	}
	corosio::openssl_stream stream(std::move(peer), ctx);
	auto [hec] = co_await stream.handshake(corosio::tls_role::server);
	if (hec) {
		co_return "server handshake: " + hec.message();
	}
	if (view->ssl == nullptr) {
		co_return "server: no SSL from the verify callback";
	}
	view->version = SSL_version(view->ssl);
	std::array<unsigned char, net::detail::tls_exporter_size> key{};
	const unsigned char no_bytes = 0;
	constexpr std::string_view label = "EXPORTER-Channel-Binding";// RFC 9266 section 2
	if (SSL_export_keying_material(view->ssl, key.data(), key.size(), label.data(), label.size(), &no_bytes, 0, 1)
		!= 1) {
		co_return "server: SSL_export_keying_material failed";
	}
	const auto *b = reinterpret_cast<const std::byte *>(key.data());
	view->exporter.assign(b, b + key.size());
	view->ssl = nullptr;// the stream's, gone when this coroutine ends

	net::transport t = net::transport::wrap(std::move(stream), "server");
	net::read_buffer buf;
	while (true) {
		auto req = co_await net::read_message(t, buf, as_server);
		if (!req) {
			co_return "";// the client went away
		}
		const auto *bind = std::get_if<ldap::bind_request>(&req->op);
		const auto *sasl = bind != nullptr ? std::get_if<ldap::sasl_auth>(&bind->authentication) : nullptr;
		if (sasl == nullptr) {
			co_return "server: expected a SASL BindRequest";
		}
		const std::string creds(sasl->credentials.value_or(""));
		view->sasl_credentials.push_back(creds);
		// The client-first-message gets a server-first-message with the
		// RFC 7677 salt and count on the client's nonce, the client-final-
		// message invalidCredentials. Anything else (EXTERNAL) gets
		// invalidCredentials straight away.
		constexpr std::int32_t in_progress = 14;// saslBindInProgress
		constexpr std::int32_t invalid_credentials = 49;
		std::string server_first;
		std::optional<std::string_view> server_creds;
		std::int32_t code = invalid_credentials;
		if (view->sasl_credentials.size() == 1 && creds.contains(",r=")) {
			server_first = "r=" + creds.substr(creds.find(",r=") + 3) + "srv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
			server_creds = server_first;
			code = in_progress;
		}
		const ldap::message answer{ req->id, ldap::bind_response{ ldap::ldap_result{ code }, server_creds } };
		if (auto w = co_await net::write_message(t, answer); !w) {
			co_return "server write: " + std::string(w.error().message());
		}
	}
}

struct tls_fixture
{
	corosio::io_context ioc;
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 16 };
	std::shared_ptr<server_view> view = std::make_shared<server_view>();
	outcome<std::string> server;
	temp_path cert{ u8".crt" };
	temp_path key{ u8".key" };

	explicit tls_fixture(std::optional<corosio::tls_version> max_version = std::nullopt,
	  const server_identity &id = ecdsa_identity())
	{
		cert.write(client_leaf().cert_pem);
		key.write(client_leaf().key_pem);
		spawn(ioc, serve(acc, server_context(view, max_version, id), view), server);
	}

	auto connect(net::certificate_verification verification = net::certificate_verification::full) -> ldap::connection
	{
		auto u = ldap::url::parse("ldaps://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
		REQUIRE(u.has_value());
		net::connect_options o;
		o.tls.verification = verification;
		if (verification == net::certificate_verification::full) {
			o.tls.ca_pem = std::pmr::string(pki().ca_pem());
		}
		o.tls.cert_file = cert.path();
		o.tls.key_file = key.path();
		auto t = finish(ioc, net::connect(ioc, *u, o));
		REQUIRE(t.has_value());
		// With TLS 1.3 the client's handshake may end before the server's.
		drive_until(ioc, [this] { return !view->exporter.empty() || server.done(); });
		REQUIRE(!view->exporter.empty());
		return { ioc, std::move(*t) };
	}
};

auto base64(std::span<const std::byte> data) -> std::string
{
	std::string out((4 * ((data.size() + 2) / 3)) + 1, '\0');
	const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
	  reinterpret_cast<const unsigned char *>(data.data()),
	  static_cast<int>(data.size()));
	out.resize(static_cast<std::size_t>(n));
	return out;
}

auto as_bytes(std::string_view s) -> bytes
{
	const auto b = std::as_bytes(std::span(s));
	return { b.begin(), b.end() };
}

// SCRAM-SHA-256-PLUS with `options` against the fixture's server: the
// client-first-message must start with `gs2` and the client-final-message's
// c= must be base64(gs2 + `data`).
void check_scram_plus(tls_fixture &f,
  ldap::connection &c,
  const ldap::sasl_scram_options &options,
  const std::string &gs2,
  const bytes &data)
{
	ldap::sasl_scram_sha256 mech("user", "pencil", options);
	auto r = finish(f.ioc, c.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::invalid_credentials);
	CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind SCRAM-SHA-256-PLUS"));
	REQUIRE(f.view->sasl_credentials.size() == 2);
	CHECK_THAT(f.view->sasl_credentials[0], StartsWith(gs2 + "n=user,r="));
	bytes input = as_bytes(gs2);
	input.insert(input.end(), data.begin(), data.end());
	CHECK_THAT(f.view->sasl_credentials[1], StartsWith("c=" + base64(input) + ",r="));
}

// The same in the RFC 5802 form: "p=<type>,,", then the binding data.
void check_scram_plus(tls_fixture &f,
  ldap::connection &c,
  std::optional<ldap::channel_binding_type> type,
  std::string_view expected_type,
  const bytes &expected_data)
{
	check_scram_plus(f,
	  c,
	  { .channel_binding = ldap::scram_channel_binding::plus, .binding_type = type },
	  "p=" + std::string(expected_type) + ",,",
	  expected_data);
}

// The same in OpenLDAP's form: "p=ldap,,", then "tls-server-end-point:"
// and OpenLDAP's hash of the server's certificate.
void check_openldap_scram_plus(tls_fixture &f, ldap::connection &c, const bytes &expected_hash)
{
	bytes data = as_bytes("tls-server-end-point:");
	data.insert(data.end(), expected_hash.begin(), expected_hash.end());
	check_scram_plus(f,
	  c,
	  { .channel_binding = ldap::scram_channel_binding::plus,
		.binding_form = ldap::scram_channel_binding_form::openldap },
	  "p=ldap,,",
	  data);
}

}// namespace

TEST_CASE("channel binding: ldaps:// with TLS 1.3", "[net][tls][channel_binding][scram]")
{
	tls_fixture f;
	auto c = f.connect();
	REQUIRE(c.is_tls());

	const bytes server_der = certificate_der(server_leaf().cert_pem);
	CHECK(to_bytes(c.peer_certificate()) == server_der);
	const auto b = c.channel_bindings();
	CHECK(f.view->version == TLS1_3_VERSION);
	REQUIRE(b.default_type == ldap::channel_binding_type::tls_exporter);
	CHECK(b.tls_exporter.size() == 32);
	CHECK(to_bytes(b.tls_exporter) == f.view->exporter);
	// The test CA signs with ECDSA-SHA-256.
	CHECK(to_bytes(b.tls_server_end_point) == digest(server_der, EVP_sha256()));

	SECTION("SCRAM-SHA-256-PLUS binds to tls-exporter by default")
	{
		check_scram_plus(f, c, std::nullopt, "tls-exporter", f.view->exporter);
	}
	SECTION("SCRAM-SHA-256-PLUS with tls-server-end-point")
	{
		check_scram_plus(f,
		  c,
		  ldap::channel_binding_type::tls_server_end_point,
		  "tls-server-end-point",
		  digest(server_der, EVP_sha256()));
	}
	SECTION("SCRAM-SHA-256-PLUS in OpenLDAP's form: tls-server-end-point")
	{
		check_openldap_scram_plus(f, c, digest(server_der, EVP_sha256()));
	}
	SECTION("SCRAM-SHA-256 for a server without -PLUS sends y,,")
	{
		ldap::sasl_scram_sha256 mech(
		  "user", "pencil", ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::not_offered });
		CHECK_FALSE(finish(f.ioc, c.sasl_bind(mech)).has_value());
		REQUIRE(f.view->sasl_credentials.size() == 2);
		CHECK_THAT(f.view->sasl_credentials[0], StartsWith("y,,n=user,r="));
		CHECK_THAT(f.view->sasl_credentials[1], StartsWith("c=eSws,r="));
	}

	c.close();
	CHECK(c.peer_certificate().empty());
	CHECK_FALSE(c.channel_bindings().default_type.has_value());
	CHECK(c.channel_bindings().tls_exporter.empty());
	drive(f.ioc);
	CHECK(f.server.get().empty());
}

namespace {

// A third-party mechanism that reads the bindings (as a -PLUS mechanism
// would) but does not override channel_binding_used(): its first message
// carries a SCRAM-like ",r=" for the test server, its second ends the bind.
class binding_reader final : public ldap::sasl_mechanism
{
  public:
	bool saw_exporter = false;

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "X-CB"; }
	void prepare(const ldap::sasl_bind_context &context) override
	{
		saw_exporter = !context.bindings.tls_exporter.empty();
	}
	auto start() -> ldap::result<std::optional<std::string>> override
	{
		return std::optional<std::string>("n,,n=user,r=cb");
	}
	auto step(std::optional<std::string_view>) -> ldap::result<std::optional<std::string>> override
	{
		return std::optional<std::string>("final");
	}
};

}// namespace

TEST_CASE("channel binding: tls-exporter serves one authentication per connection",
  "[net][tls][channel_binding][scram][rfc]")
{
	// RFC 9266 section 4.1: tls-exporter MUST NOT be used for more than one
	// authentication mechanism instance on a TLS connection. The first
	// bind fails (invalidCredentials) and still counts.
	const ldap::sasl_scram_options plus{ .channel_binding = ldap::scram_channel_binding::plus };
	SECTION("ECDSA certificate: the next bind uses tls-server-end-point")
	{
		tls_fixture f;
		auto c = f.connect();
		check_scram_plus(f, c, std::nullopt, "tls-exporter", f.view->exporter);

		ldap::sasl_scram_sha256 again("user", "pencil", plus);
		auto r = finish(f.ioc, c.sasl_bind(again));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		REQUIRE(f.view->sasl_credentials.size() == 3);
		CHECK_THAT(f.view->sasl_credentials[2], StartsWith("p=tls-server-end-point,,n=user,r="));
		// The accessor describes the connection: tls-exporter is still there.
		CHECK(to_bytes(c.channel_bindings().tls_exporter) == f.view->exporter);
		CHECK(c.channel_bindings().default_type == ldap::channel_binding_type::tls_exporter);

		// Asked for explicitly, it is refused before anything is sent.
		ldap::sasl_scram_sha256 exporter("user",
		  "pencil",
		  ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::plus,
			.binding_type = ldap::channel_binding_type::tls_exporter });
		r = finish(f.ioc, c.sasl_bind(exporter));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(c.is_open());
		CHECK(f.view->sasl_credentials.size() == 3);
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("Ed25519 certificate (no tls-server-end-point): the next bind fails")
	{
		tls_fixture f(std::nullopt, ed25519_identity());
		auto c = f.connect(net::certificate_verification::insecure_accept_any);
		check_scram_plus(f, c, std::nullopt, "tls-exporter", f.view->exporter);

		ldap::sasl_scram_sha256 again("user", "pencil", plus);
		auto r = finish(f.ioc, c.sasl_bind(again));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(std::string(r.error().context)
			  == "sasl bind SCRAM-SHA-256-PLUS: the TLS connection has no channel binding data");
		CHECK(c.is_open());
		CHECK(f.view->sasl_credentials.size() == 2);// nothing sent
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("the same mechanism object, bound again: tls-server-end-point")
	{
		tls_fixture f;
		auto c = f.connect();
		ldap::sasl_scram_sha256 mech("user", "pencil", plus);
		auto r = finish(f.ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		REQUIRE(f.view->sasl_credentials.size() == 2);
		CHECK_THAT(f.view->sasl_credentials[0], StartsWith("p=tls-exporter,,n=user,r="));

		r = finish(f.ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		REQUIRE(f.view->sasl_credentials.size() == 3);
		CHECK_THAT(f.view->sasl_credentials[2], StartsWith("p=tls-server-end-point,,n=user,r="));
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("a bind whose start() fails does not use it")
	{
		tls_fixture f;
		auto c = f.connect();
		ldap::sasl_scram_sha256 broken("user",
		  "pencil",
		  ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::plus, .max_iterations = 1 });
		auto r = finish(f.ioc, c.sasl_bind(broken));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("max_iterations 1 is outside 4096 .. 2^31-1"));
		CHECK(c.is_open());
		CHECK(f.view->sasl_credentials.empty());// nothing sent
		check_scram_plus(f, c, std::nullopt, "tls-exporter", f.view->exporter);
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("EXTERNAL does not use it")
	{
		tls_fixture f;
		auto c = f.connect();
		REQUIRE(f.view->version == TLS1_3_VERSION);
		ldap::sasl_external external;
		auto r = finish(f.ioc, c.sasl_bind(external));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		REQUIRE(f.view->sasl_credentials.size() == 1);
		f.view->sasl_credentials.clear();

		check_scram_plus(f, c, std::nullopt, "tls-exporter", f.view->exporter);
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("SCRAM-SHA-256 sending y,, does not use it")
	{
		tls_fixture f;
		auto c = f.connect();
		ldap::sasl_scram_sha256 y(
		  "user", "pencil", ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::not_offered });
		REQUIRE_FALSE(finish(f.ioc, c.sasl_bind(y)).has_value());
		REQUIRE(f.view->sasl_credentials.size() == 2);
		CHECK_THAT(f.view->sasl_credentials[0], StartsWith("y,,n=user,r="));

		ldap::sasl_scram_sha256 again("user", "pencil", plus);
		auto r = finish(f.ioc, c.sasl_bind(again));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		REQUIRE(f.view->sasl_credentials.size() == 3);
		CHECK_THAT(f.view->sasl_credentials[2], StartsWith("p=tls-exporter,,n=user,r="));
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("TLS 1.2 with the extended master secret: tls-server-end-point leaves it free")
	{
		tls_fixture f(corosio::tls_version::tls_1_2);
		auto c = f.connect();
		REQUIRE(f.view->version == TLS1_2_VERSION);
		REQUIRE_FALSE(c.channel_bindings().tls_exporter.empty());
		check_scram_plus(
		  f, c, std::nullopt, "tls-server-end-point", digest(certificate_der(server_leaf().cert_pem), EVP_sha256()));

		ldap::sasl_scram_sha256 exporter("user",
		  "pencil",
		  ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::plus,
			.binding_type = ldap::channel_binding_type::tls_exporter });
		auto r = finish(f.ioc, c.sasl_bind(exporter));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		REQUIRE(f.view->sasl_credentials.size() == 3);
		CHECK_THAT(f.view->sasl_credentials[2], StartsWith("p=tls-exporter,,n=user,r="));
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("a mechanism that does not say what it bound to counts as using it")
	{
		tls_fixture f;
		auto c = f.connect();
		binding_reader reader;
		auto r = finish(f.ioc, c.sasl_bind(reader));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK(reader.saw_exporter);
		REQUIRE(f.view->sasl_credentials.size() == 2);

		ldap::sasl_scram_sha256 again("user", "pencil", plus);
		r = finish(f.ioc, c.sasl_bind(again));
		REQUIRE_FALSE(r.has_value());
		REQUIRE(f.view->sasl_credentials.size() == 3);
		CHECK_THAT(f.view->sasl_credentials[2], StartsWith("p=tls-server-end-point,,n=user,r="));
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
}

TEST_CASE("channel binding: ldaps:// with TLS 1.2", "[net][tls][channel_binding][scram]")
{
	tls_fixture f(corosio::tls_version::tls_1_2);
	auto c = f.connect();
	REQUIRE(c.is_tls());
	CHECK(f.view->version == TLS1_2_VERSION);
	const auto b = c.channel_bindings();
	// tls-unique is RFC 5802's default for TLS 1.2; without it, tls-server-end-point.
	CHECK(b.default_type == ldap::channel_binding_type::tls_server_end_point);
	// OpenSSL negotiates the extended master secret by default, so
	// tls-exporter is defined too (RFC 9266 section 2).
	CHECK(to_bytes(b.tls_exporter) == f.view->exporter);
	check_scram_plus(
	  f, c, std::nullopt, "tls-server-end-point", digest(certificate_der(server_leaf().cert_pem), EVP_sha256()));
	c.close();
	drive(f.ioc);
	CHECK(f.server.get().empty());
}

TEST_CASE("channel binding: recorded without certificate verification too", "[net][tls][channel_binding]")
{
	tls_fixture f;
	auto c = f.connect(net::certificate_verification::insecure_accept_any);
	REQUIRE(c.is_tls());
	CHECK(to_bytes(c.peer_certificate()) == certificate_der(server_leaf().cert_pem));
	CHECK(to_bytes(c.channel_bindings().tls_exporter) == f.view->exporter);
	c.close();
	drive(f.ioc);
	CHECK(f.server.get().empty());
}

TEST_CASE("channel binding: none without TLS, and SCRAM-SHA-256-PLUS refuses to start", "[net][channel_binding][scram]")
{
	corosio::io_context ioc;
	corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 16);
	outcome<void> server;
	spawn(
	  ioc,
	  [](corosio::tcp_acceptor &a) -> capy::task<void> {
		  auto [ec, peer] = co_await a.accept();
		  if (ec) {
			  co_return;
		  }
		  std::array<char, 256> buf{};
		  // Nothing may arrive: the bind fails before sending.
		  auto [rec, n] = co_await peer.read_some(capy::mutable_buffer(buf.data(), buf.size()));
		  CHECK(n == 0);
	  }(acc),
	  server);
	auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
	REQUIRE(u.has_value());
	auto t = finish(ioc, net::connect(ioc, *u));
	REQUIRE(t.has_value());
	ldap::connection c(ioc, std::move(*t));
	CHECK(c.peer_certificate().empty());
	CHECK_FALSE(c.channel_bindings().default_type.has_value());

	ldap::sasl_scram_sha256 mech(
	  "user", "pencil", ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::plus });
	auto r = finish(ioc, c.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::tls_required);
	CHECK(std::string(r.error().context)
		  == "sasl bind SCRAM-SHA-256-PLUS: channel binding needs a TLS-protected connection");
	CHECK(c.is_open());
	c.close();
	drive(ioc);
	server.get();
}

TEST_CASE("channel binding: an Ed25519 server certificate", "[net][tls][channel_binding][scram]")
{
	// RFC 5929 defines no tls-server-end-point for it (no single hash
	// function); OpenLDAP's form hashes it with SHA-256.
	const auto &leaf = ed25519_server();
	SECTION("TLS 1.3: tls-exporter only")
	{
		tls_fixture f(std::nullopt, ed25519_identity());
		auto c = f.connect(net::certificate_verification::insecure_accept_any);
		CHECK(f.view->version == TLS1_3_VERSION);
		CHECK(to_bytes(c.peer_certificate()) == leaf.der);
		const auto b = c.channel_bindings();
		CHECK(b.tls_server_end_point.empty());
		CHECK(b.default_type == ldap::channel_binding_type::tls_exporter);
		CHECK(to_bytes(b.tls_exporter) == f.view->exporter);
		SECTION("SCRAM-SHA-256-PLUS: tls-exporter")
		{
			check_scram_plus(f, c, std::nullopt, "tls-exporter", f.view->exporter);
		}
		SECTION("SCRAM-SHA-256-PLUS in OpenLDAP's form: SHA-256 of the certificate")
		{
			check_openldap_scram_plus(f, c, digest(leaf.der, EVP_sha256()));
		}
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
	SECTION("TLS 1.2 with the extended master secret: tls-exporter is the default")
	{
		tls_fixture f(corosio::tls_version::tls_1_2, ed25519_identity());
		auto c = f.connect(net::certificate_verification::insecure_accept_any);
		CHECK(f.view->version == TLS1_2_VERSION);
		const auto b = c.channel_bindings();
		CHECK(b.tls_server_end_point.empty());
		CHECK(b.default_type == ldap::channel_binding_type::tls_exporter);
		CHECK(to_bytes(b.tls_exporter) == f.view->exporter);
		c.close();
		drive(f.ioc);
		CHECK(f.server.get().empty());
	}
}

TEST_CASE("channel binding: full verification still rejects an untrusted chain", "[net][tls][channel_binding]")
{
	tls_fixture f;
	auto u = ldap::url::parse("ldaps://127.0.0.1:" + std::to_string(f.acc.local_endpoint().port()));
	REQUIRE(u.has_value());
	const test_pki other("jhetz-ldap another CA");
	net::connect_options o;
	o.tls.ca_pem = std::pmr::string(other.ca_pem());
	auto t = finish(f.ioc, net::connect(f.ioc, *u, o));
	REQUIRE_FALSE(t.has_value());
	CHECK(t.error().code == ldap::cond::tls_failure);
	CHECK_THAT(std::string(t.error().context), ContainsSubstring("tls handshake: server certificate: "));
	drive(f.ioc);
	CHECK_THAT(f.server.get(), StartsWith("server handshake: "));
}

// ---------------------------------------------------------------- against a plain OpenSSL server

namespace {

auto openssl_error() -> std::string
{
	const unsigned long e = ERR_get_error();
	ERR_clear_error();
	const char *reason = ERR_reason_error_string(e);
	return reason != nullptr ? reason : "(no OpenSSL error)";
}

// A blocking OpenSSL server on a thread of its own, for what Corosio's
// tls_context cannot set up (SSL_CTX options such as
// SSL_OP_NO_EXTENDED_MASTER_SECRET) or do (renegotiation): it accepts one
// connection on 127.0.0.1, handshakes as TLS 1.2 at most, then runs
// `script` on the session. result() is the script's outcome (empty: as
// expected), or why the server failed before it.
class raw_tls_server
{
  public:
	using script = std::function<std::string(SSL *)>;

	raw_tls_server(const server_identity &id, std::uint64_t options, script run)
	{
		ctx_.reset(SSL_CTX_new(TLS_server_method()));
		REQUIRE(ctx_ != nullptr);
		REQUIRE(SSL_CTX_set_max_proto_version(ctx_.get(), TLS1_2_VERSION) == 1);
		SSL_CTX_set_options(ctx_.get(), options);
		const std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(
		  BIO_new_mem_buf(id.cert_pem.data(), static_cast<int>(id.cert_pem.size())), &BIO_free);
		const x509_ptr cert(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
		REQUIRE(cert != nullptr);
		REQUIRE(SSL_CTX_use_certificate(ctx_.get(), cert.get()) == 1);
		const std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(
		  BIO_new_mem_buf(id.key_pem.data(), static_cast<int>(id.key_pem.size())), &BIO_free);
		const pkey_ptr key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
		REQUIRE(key != nullptr);
		REQUIRE(SSL_CTX_use_PrivateKey(ctx_.get(), key.get()) == 1);

		listener_ = blocking_socket::listen_loopback(1);
		REQUIRE(listener_.valid());
		port_ = listener_.port();
		REQUIRE(port_ != 0);
		thread_ = std::thread([this, run = std::move(run)] { result_ = serve(run); });
	}

	raw_tls_server(const raw_tls_server &) = delete;
	auto operator=(const raw_tls_server &) -> raw_tls_server & = delete;

	// Unblocks the thread (accept, read) if a test failed half way. The
	// listener and the connection close only after the join, or under the
	// lock (serve), so no handle is reused under a call still to come.
	~raw_tls_server()
	{
		if (!thread_.joinable()) {
			return;
		}
		{
			const std::scoped_lock lock(conn_mutex_);
			stopping_ = true;
			if (conn_ != invalid_raw_socket) {
				shutdown_both(conn_);
			}
		}
		listener_.wake_accept();
		thread_.join();
	}

	[[nodiscard]] auto url() const -> std::string { return "ldaps://127.0.0.1:" + std::to_string(port_); }

	auto result() -> std::string
	{
		thread_.join();
		return result_;
	}

  private:
	struct ssl_ctx_free
	{
		void operator()(SSL_CTX *c) const noexcept { SSL_CTX_free(c); }
	};
	struct ssl_free
	{
		void operator()(SSL *s) const noexcept { SSL_free(s); }
	};

	auto serve(const script &run) -> std::string
	{
		blocking_socket conn = listener_.accept();
		if (!conn.valid()) {
			return "accept failed";
		}
		{
			const std::scoped_lock lock(conn_mutex_);
			if (stopping_) {
				return "stopped before the handshake";
			}
			conn_ = conn.handle();
		}
		std::string out;
		{
			const std::unique_ptr<SSL, ssl_free> ssl(SSL_new(ctx_.get()));
			if (ssl == nullptr || SSL_set_fd(ssl.get(), openssl_fd(conn.handle())) != 1) {
				out = "SSL_new failed";
			} else if (SSL_accept(ssl.get()) != 1) {
				out = "server handshake: " + openssl_error();
			} else {
				out = run(ssl.get());
			}
		}
		{
			const std::scoped_lock lock(conn_mutex_);
			conn_ = invalid_raw_socket;
		}
		return out;// conn closes here
	}

	std::unique_ptr<SSL_CTX, ssl_ctx_free> ctx_{};
	blocking_socket listener_{};
	std::mutex conn_mutex_{};
	raw_socket_handle conn_ = invalid_raw_socket;// open while set; guarded by conn_mutex_
	bool stopping_ = false;// the destructor runs; guarded by conn_mutex_
	std::uint16_t port_ = 0;
	std::thread thread_{};
	std::string result_{};
};

// Reads until the client goes away. Returns std::string, as raw_tls_server::script.
// NOLINTNEXTLINE(modernize-use-string-view): std::function<std::string(SSL *)> needs it
auto wait_for_close(SSL *ssl) -> std::string
{
	std::array<char, 256> buf{};
	while (SSL_read(ssl, buf.data(), static_cast<int>(buf.size())) > 0) {}
	return {};
}

// Reads the raw socket, past any TLS records, until the peer closes it, or
// for 10 s at most (a client that never closes fails the test, not hangs it).
void drain_until_close(raw_socket_handle s)
{
	set_receive_timeout(s, 10);
	std::array<char, 256> buf{};
	while (receive_some(s, buf) > 0) {}
}

// Reads one LDAP request (small enough for one read) and answers it if it
// is a BindRequest (success); the request's id, or 0.
auto answer_bind(SSL *ssl) -> std::int32_t
{
	std::array<std::byte, 4096> buf{};
	const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
	if (n <= 0) {
		return 0;
	}
	auto req = ldap::decode(std::span(buf.data(), static_cast<std::size_t>(n)), { .from = ldap::origin::client });
	if (!req || !std::holds_alternative<ldap::bind_request>(req->op)) {
		return 0;
	}
	const std::string answer = bytes_of(ldap::message{ req->id, ldap::bind_response{ ldap::ldap_result{ 0 } } });
	if (SSL_write(ssl, answer.data(), static_cast<int>(answer.size())) != static_cast<int>(answer.size())) {
		return 0;
	}
	return req->id;
}

auto connect_raw(corosio::io_context &ioc, const raw_tls_server &srv) -> ldap::connection
{
	auto u = ldap::url::parse(srv.url());
	REQUIRE(u.has_value());
	net::connect_options o;
	o.tls.verification = net::certificate_verification::insecure_accept_any;
	auto t = finish(ioc, net::connect(ioc, *u, o));
	REQUIRE(t.has_value());
	return { ioc, std::move(*t) };
}

}// namespace

TEST_CASE("channel binding: TLS 1.2 without the extended master secret", "[net][tls][channel_binding][scram][rfc]")
{
	// RFC 9266 section 2: tls-exporter only with the extended master
	// secret (RFC 7627) on TLS 1.2.
	corosio::io_context ioc;
	SECTION("ECDSA certificate: tls-server-end-point only")
	{
		raw_tls_server srv(ecdsa_identity(), SSL_OP_NO_EXTENDED_MASTER_SECRET, wait_for_close);
		auto c = connect_raw(ioc, srv);
		const bytes der = certificate_der(server_leaf().cert_pem);
		CHECK(to_bytes(c.peer_certificate()) == der);
		const auto b = c.channel_bindings();
		CHECK(b.tls_exporter.empty());
		CHECK(b.default_type == ldap::channel_binding_type::tls_server_end_point);
		CHECK(to_bytes(b.tls_server_end_point) == digest(der, EVP_sha256()));
		// Refused before anything is sent: the server reads nothing but the close.
		ldap::sasl_scram_sha256 mech("user",
		  "pencil",
		  ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::plus,
			.binding_type = ldap::channel_binding_type::tls_exporter });
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("no tls-exporter channel binding data"));
		c.close();
		CHECK(srv.result().empty());
	}
	SECTION("Ed25519 certificate: no channel binding at all")
	{
		raw_tls_server srv(ed25519_identity(), SSL_OP_NO_EXTENDED_MASTER_SECRET, wait_for_close);
		auto c = connect_raw(ioc, srv);
		CHECK(c.is_tls());
		CHECK(to_bytes(c.peer_certificate()) == ed25519_server().der);
		const auto b = c.channel_bindings();
		CHECK(b.tls_exporter.empty());
		CHECK(b.tls_server_end_point.empty());
		CHECK_FALSE(b.default_type.has_value());
		ldap::sasl_scram_sha256 mech(
		  "user", "pencil", ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::plus });
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("the TLS connection has no channel binding data"));
		c.close();
		CHECK(srv.result().empty());
	}
}

TEST_CASE("channel binding: the client refuses TLS 1.2 renegotiation", "[net][tls][channel_binding][rfc]")
{
	// RFC 9266 section 4.2: tls-exporter is undefined where renegotiation
	// is enabled, and after one the recorded certificate and bindings would
	// describe the old session. The server asks for a renegotiation
	// (HelloRequest) with its answer to the first bind; the client answers
	// with a no_renegotiation alert, which an OpenSSL server takes as a
	// fatal error (handshake_failure alert): the next request fails.
	corosio::io_context ioc;
	raw_tls_server srv(ecdsa_identity(), 0, [](SSL *ssl) -> std::string {
		std::array<std::byte, 4096> buf{};
		const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
		if (n <= 0) {
			return "read the first request: " + openssl_error();
		}
		auto req = ldap::decode(std::span(buf.data(), static_cast<std::size_t>(n)), { .from = ldap::origin::client });
		if (!req) {
			return "decode the first request";
		}
		if (SSL_renegotiate(ssl) != 1 || SSL_do_handshake(ssl) != 1) {
			return "HelloRequest: " + openssl_error();
		}
		const std::string answer = bytes_of(ldap::message{ req->id, ldap::bind_response{ ldap::ldap_result{ 0 } } });
		if (SSL_write(ssl, answer.data(), static_cast<int>(answer.size())) != static_cast<int>(answer.size())) {
			return "write the first answer: " + openssl_error();
		}
		if (answer_bind(ssl) != 0) {
			return "the client renegotiated";
		}
		std::string out = "refused: " + openssl_error();
		// The second request is still unread: closing now would reset
		// the connection, and Corosio fails a pending read on a reset
		// without reading the handshake_failure alert queued before it.
		// Read until the client closes, so the server's close sends a FIN.
		drain_until_close(socket_of_openssl_fd(SSL_get_fd(ssl)));
		return out;
	});
	auto c = connect_raw(ioc, srv);
	const auto before = to_bytes(c.channel_bindings().tls_exporter);
	CHECK(before.size() == 32);
	const ldap::dn admin_dn{ "cn=admin,dc=example,dc=org" };
	auto first = finish(ioc, c.simple_bind(admin_dn, "secret"));
	CHECK(first.has_value());
	auto second = finish(ioc, c.simple_bind(admin_dn, "secret"));
	REQUIRE_FALSE(second.has_value());
	UNSCOPED_INFO(second.error().message());
	CHECK(second.error().code == ldap::cond::tls_failure);
	CHECK_FALSE(c.is_open());
	CHECK(srv.result() == "refused: no renegotiation");
}

// coro-ldap-cx0: Corosio allocates its SSL_CTX ex_data slot when the
// process builds its first SSL_CTX, without synchronisation; threads doing
// that at once could leave a context without its data, and Corosio then
// skipped our verify callback (no peer certificate). The library primes the
// slot once (prime_corosio_openssl()) before its first tls_context, and
// fails a handshake whose verify callback did not run. The servers are
// plain OpenSSL, so the clients' contexts are the process's only Corosio
// ones. Meaningful in a fresh process (ctest runs each test case alone):
// without the workaround a TSan build reports the race in most runs (the
// threads must overlap), other builds lose a certificate only rarely.
TEST_CASE("channel binding: concurrent first TLS handshakes all record the peer", "[net][tls][channel_binding]")
{
	struct client_result
	{
		std::string error{};
		bytes certificate{};
	};
	constexpr std::size_t clients = 8;
	const bytes der = certificate_der(server_leaf().cert_pem);
	const std::string ca_pem = pki().ca_pem();
	std::vector<std::unique_ptr<raw_tls_server>> servers;
	servers.reserve(clients);
	for (std::size_t i = 0; i < clients; ++i) {
		servers.push_back(std::make_unique<raw_tls_server>(ecdsa_identity(), 0, wait_for_close));
	}
	std::vector<client_result> results(clients);
	std::latch start(static_cast<std::ptrdiff_t>(clients));
	// No Catch2 assertion on these threads: results are checked after join.
	// A thread that throws before arriving counts down in the catch, so the
	// others are not left waiting at the latch.
	auto client = [&start, &ca_pem](const std::string &url, client_result &out) {
		bool arrived = false;
		try {
			corosio::io_context ioc;
			net::connect_options o;
			o.tls.verification = net::certificate_verification::full;
			o.tls.ca_pem = std::pmr::string(ca_pem);
			const auto u = ldap::url::parse(url);
			arrived = true;
			start.arrive_and_wait();
			if (!u) {
				out.error = "url";
				return;
			}
			auto t = finish(ioc, net::connect(ioc, *u, o));
			if (!t) {
				out.error = std::string(t.error().context) + ": " + t.error().code.message();
				return;
			}
			out.certificate = to_bytes(t->peer_certificate());
		} catch (const std::exception &e) {
			if (!arrived) {
				start.count_down();
			}
			out.error = e.what();
		}
	};
	{
		std::vector<std::jthread> threads;
		threads.reserve(clients);
		for (std::size_t i = 0; i < clients; ++i) {
			threads.emplace_back(client, servers[i]->url(), std::ref(results[i]));
		}
	}
	for (std::size_t i = 0; i < clients; ++i) {
		CAPTURE(i);
		CHECK_THAT(results[i].error, IsEmpty());
		CHECK(results[i].certificate == der);
		CHECK_THAT(servers[i]->result(), IsEmpty());
	}
}
