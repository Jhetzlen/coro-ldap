// SASL GSSAPI without a KDC: the RFC 4752 security layer messages and the
// failures before anything is sent.
#include "../../src/sasl_gssapi_context.hpp"
#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using namespace std::string_view_literals;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;
using ldap::detail::gssapi_layer_offer;

namespace {

// The backend's context establishment call.
#ifdef _WIN32
constexpr bool sspi = true;
#else
constexpr bool sspi = false;
#endif
constexpr std::string_view init_call = sspi ? "InitializeSecurityContextW: " : "gss_init_sec_context: ";

// Sets an environment variable for the scope of a test, then restores it.
class scoped_env
{
  public:
	scoped_env(const char *name, const char *value) : name_(name)
	{
		// NOLINTNEXTLINE(concurrency-mt-unsafe): no other thread runs, see above
		if (const char *old = std::getenv(name)) {
			old_ = old;
		}
		set_env(name, value);
	}
	scoped_env(const scoped_env &) = delete;
	auto operator=(const scoped_env &) -> scoped_env & = delete;
	~scoped_env()
	{
		if (old_) {
			set_env(name_, old_->c_str());
		} else {
			unset_env(name_);
		}
	}

  private:
	const char *name_;
	std::optional<std::string> old_;
};

}// namespace

TEST_CASE("gssapi: the server's security layer offer", "[net][sasl][gssapi]")
{
	CHECK(ldap::detail::parse_gssapi_layer_offer("\x07\x00\x10\x00"sv) == gssapi_layer_offer{ 7, 0x1000 });
	CHECK(ldap::detail::parse_gssapi_layer_offer("\x01\x00\x00\x00"sv) == gssapi_layer_offer{ 1, 0 });
	CHECK(ldap::detail::parse_gssapi_layer_offer("\x06\xff\xff\xff"sv) == gssapi_layer_offer{ 6, 0xffffff });
	CHECK(ldap::detail::parse_gssapi_layer_offer("\xff\x01\x02\x03"sv) == gssapi_layer_offer{ 0xff, 0x010203 });
	for (auto bad : { ""sv, "\x01"sv, "\x01\x00\x00"sv, "\x01\x00\x00\x00\x00"sv }) {
		auto r = ldap::detail::parse_gssapi_layer_offer(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
		CHECK(r.error().code == ldap::cond::protocol_error);
	}
	CHECK(ldap::detail::parse_gssapi_layer_offer("\x01\x00\x00"sv).error().context
		  == "security layer offer of 3 bytes, not 4");
}

TEST_CASE("gssapi: the security layer selected", "[net][sasl][gssapi]")
{
	using ldap::gssapi_security_layer;
	using ldap::detail::gssapi_select_layer;
	constexpr std::uint8_t none = ldap::detail::gssapi_no_layer;
	constexpr std::uint8_t integrity = ldap::detail::gssapi_integrity;
	constexpr std::uint8_t confidentiality = ldap::detail::gssapi_confidentiality;
	const auto offer = [](std::uint8_t layers) { return gssapi_layer_offer{ .layers = layers, .max_size = 0x10000 }; };

	SECTION("none: no security layer, whatever else is offered")
	{
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 1, 3, 5, 7, 0xff })) {
			INFO("layers " << int{ layers });
			CHECK(gssapi_select_layer(offer(layers), gssapi_security_layer::none, false, false) == none);
			CHECK(gssapi_select_layer(offer(layers), gssapi_security_layer::none, true, false) == none);
		}
	}
	SECTION("none, from a server that requires integrity or confidentiality")
	{
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 2, 4, 6, 0xfe })) {
			INFO("layers " << int{ layers });
			auto r = gssapi_select_layer(offer(layers), gssapi_security_layer::none, false, false);
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::security_layer_required);
			CHECK(r.error().code == ldap::cond::access_denied);
			CHECK_THAT(std::string(r.error().context), ContainsSubstring("use TLS"));
			CHECK_THAT(std::string(r.error().context), ContainsSubstring("security_layer"));
		}
	}
	SECTION("integrity: integrity, else confidentiality")
	{
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::integrity, false, false) == integrity);
		CHECK(gssapi_select_layer(offer(2), gssapi_security_layer::integrity, true, false) == integrity);
		CHECK(gssapi_select_layer(offer(5), gssapi_security_layer::integrity, false, false) == confidentiality);
		auto r = gssapi_select_layer(offer(1), gssapi_security_layer::integrity, false, false);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::security_layer_unavailable);
		CHECK(r.error().code == ldap::cond::access_denied);
	}
	SECTION("confidentiality only")
	{
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::confidentiality, false, false) == confidentiality);
		CHECK(gssapi_select_layer(offer(4), gssapi_security_layer::confidentiality, true, false) == confidentiality);
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 1, 2, 3 })) {
			auto r = gssapi_select_layer(offer(layers), gssapi_security_layer::confidentiality, false, false);
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::security_layer_unavailable);
			CHECK(std::string(r.error().context) == "the server does not offer confidentiality protection");
		}
	}
	SECTION("best offered: the strongest, but none over TLS when offered")
	{
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::best_offered, false, false) == confidentiality);
		CHECK(gssapi_select_layer(offer(3), gssapi_security_layer::best_offered, false, false) == integrity);
		CHECK(gssapi_select_layer(offer(1), gssapi_security_layer::best_offered, false, false) == none);
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::best_offered, true, false) == none);
		CHECK(gssapi_select_layer(offer(6), gssapi_security_layer::best_offered, true, false) == confidentiality);
		CHECK(gssapi_select_layer(offer(2), gssapi_security_layer::best_offered, true, false) == integrity);
	}
	SECTION("require_tls without TLS: never none")
	{
		auto r = gssapi_select_layer(offer(1), gssapi_security_layer::best_offered, false, true);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("sasl_gssapi_options::require_tls"));
		CHECK_FALSE(gssapi_select_layer(offer(7), gssapi_security_layer::none, false, true).has_value());
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::best_offered, false, true) == confidentiality);
		CHECK(gssapi_select_layer(offer(3), gssapi_security_layer::integrity, false, true) == integrity);
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::best_offered, true, true) == none);
		CHECK(gssapi_select_layer(offer(7), gssapi_security_layer::none, true, true) == none);
	}
	SECTION("an offer of nothing")
	{
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 0, 8, 0xf0 })) {
			for (auto requested : { gssapi_security_layer::none, gssapi_security_layer::best_offered }) {
				auto r = gssapi_select_layer({ .layers = layers, .max_size = 0 }, requested, false, false);
				REQUIRE_FALSE(r.has_value());
				CHECK(r.error().code == ldap::client_errc::unexpected_response);
			}
		}
	}
	SECTION("a layer offered with a maximum buffer size of 0")
	{
		CHECK(gssapi_select_layer({ .layers = 7, .max_size = 0 }, gssapi_security_layer::none, false, false) == none);
		auto r = gssapi_select_layer({ .layers = 7, .max_size = 0 }, gssapi_security_layer::integrity, false, false);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
	}
}

TEST_CASE("gssapi: the context flags a security layer needs", "[net][sasl][gssapi]")
{
	using ldap::detail::gssapi_check_context_flags;
	using ldap::detail::gssapi_context_flags;
	constexpr gssapi_context_flags all{ .integrity = true, .confidentiality = true, .sequence = true };
	CHECK(gssapi_check_context_flags(all, false).has_value());
	CHECK(gssapi_check_context_flags(all, true).has_value());
	CHECK(gssapi_check_context_flags({ .integrity = true, .sequence = true }, false).has_value());
	CHECK(gssapi_check_context_flags({ .confidentiality = true, .sequence = true }, true).has_value());
	const auto refused = [](const gssapi_context_flags &flags, bool confidentiality, std::string_view why) {
		auto r = gssapi_check_context_flags(flags, confidentiality);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK(r.error().context == why);
	};
	refused({ .confidentiality = true, .sequence = true }, false, "the security context provides no integrity");
	refused({ .integrity = true, .sequence = true }, true, "the security context provides no confidentiality");
	// RFC 4752 section 3.1: no layer without sequence detection.
	constexpr std::string_view no_sequence =
	  "the security context provides no sequence detection (replayed or reordered buffers would pass)";
	refused({ .integrity = true, .confidentiality = true }, false, no_sequence);
	refused({ .integrity = true, .confidentiality = true }, true, no_sequence);
}

TEST_CASE("gssapi: the client's security layer reply", "[net][sasl][gssapi]")
{
	using ldap::detail::gssapi_layer_reply;
	SECTION("no security layer: maximum size 0, whatever is given")
	{
		CHECK(gssapi_layer_reply(1, 0x10000, "") == "\x01\x00\x00\x00"sv);
		CHECK(gssapi_layer_reply(1, 0, "") == "\x01\x00\x00\x00"sv);
	}
	SECTION("a layer: its maximum size, network byte order")
	{
		CHECK(gssapi_layer_reply(2, 0x10000, "") == "\x02\x01\x00\x00"sv);
		CHECK(gssapi_layer_reply(4, 0xffffff, "") == "\x04\xff\xff\xff"sv);
		CHECK(gssapi_layer_reply(4, 0x0102, "u:x") == "\x04\x00\x01\x02u:x"sv);
		for (std::uint32_t bad : { 0U, 0x1000000U, 0xffffffffU }) {
			auto r = gssapi_layer_reply(2, bad, "");
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::encode_error);
		}
	}
	SECTION("with an authorization identity, UTF-8")
	{
		CHECK(gssapi_layer_reply(1, 0, "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org")
			  == "\x01\x00\x00\x00"
				 "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org"sv);
		CHECK(gssapi_layer_reply(1, 0, "u:\xE6\x97\xA5\xE6\x9C\xAC\xF0\x9F\x98\x80")
			  == "\x01\x00\x00\x00u:\xE6\x97\xA5\xE6\x9C\xAC\xF0\x9F\x98\x80"sv);
	}
	SECTION("an authorization identity that is not valid UTF-8, or has a control character")
	{
		for (auto bad :
		  { "dn:\xC3"sv, "dn:\xC0\xAF"sv, "dn:\xED\xA0\x80"sv, "dn:a\nb"sv, "dn:a\0b"sv, "dn:\xC2\x85"sv }) {
			auto r = gssapi_layer_reply(1, 0, bad);
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::encode_error);
		}
	}
}

TEST_CASE("gssapi: no target without a host, nothing sent", "[net][sasl][gssapi]")
{
	mock_ldap m;// a wrapped transport: no host
	m.serve({});
	ldap::sasl_gssapi mech({ .require_tls = false });
	auto r = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::encode_error);
	CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: no target"));
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());
}

TEST_CASE("gssapi: invalid names are refused before anything is sent", "[net][sasl][gssapi]")
{
	tcp_mock_ldap m;
	m.serve({});
	const auto refused = [&m](ldap::sasl_gssapi_options options, std::string_view what) {
		ldap::sasl_gssapi mech(std::move(options));
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK(std::string(r.error().context) == "sasl bind GSSAPI: " + std::string(what));
	};
	refused({ .target = "ldap@\xFF", .require_tls = false }, "target is not valid UTF-8");
	refused({ .principal = "jdoe\r\n@EXAMPLE.ORG", .require_tls = false }, "principal contains a control character");
	refused({ .authz_id = "dn:\xE2\x82", .require_tls = false }, "authorization identity is not valid UTF-8");
	const auto refused_password = [&m](std::string principal, std::string password, std::string_view what) {
		ldap::sasl_gssapi mech(std::move(principal), std::move(password), { .require_tls = false });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK(std::string(r.error().context) == "sasl bind GSSAPI: " + std::string(what));
	};
	refused_password("jdoe", "pw\xC3", "password is not valid UTF-8");
	refused_password("", "pw", "a password without a principal");
	refused({ .security_layer = ldap::gssapi_security_layer::integrity, .max_receive_size = 0 },
	  "max_receive_size 0 out of range (1 to 16777215)");
	refused({ .security_layer = ldap::gssapi_security_layer::best_offered, .max_receive_size = 0x1000000 },
	  "max_receive_size 16777216 out of range (1 to 16777215)");
	m.check_server();
	CHECK(m.log.received.empty());
}

TEST_CASE("gssapi: GSS-API errors carry its status messages", "[net][sasl][gssapi]")
{
	// No KDC is contacted: there are no credentials to start with.
	const scoped_env config("KRB5_CONFIG", "/dev/null");
	const scoped_env cache("KRB5CCNAME", "FILE:/nonexistent/jhetz-ldap-test-ccache");
	const scoped_env keytab("KRB5_CLIENT_KTNAME", "FILE:/nonexistent/jhetz-ldap-test-keytab");
	tcp_mock_ldap m;
	m.serve({});

	SECTION("default credentials, default target ldap@<host>")
	{
		ldap::sasl_gssapi mech({ .require_tls = false });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: " + std::string(init_call)));
		if (!sspi) {
			// The major status message, then the mechanism's (minor) one.
			CHECK_THAT(std::string(r.error().context), ContainsSubstring("credentials"));
			CHECK_THAT(
			  std::string(r.error().context), ContainsSubstring("(") && ContainsSubstring("jhetz-ldap-test-ccache"));
		}
	}
	SECTION("an explicit principal, UTF-8")
	{
		ldap::sasl_gssapi mech(
		  { .target = "ldap@dc1.example.org", .principal = "j\xC3\xB6rg@EXAMPLE.ORG", .require_tls = false });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		if (!sspi) {
			CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: gss_acquire_cred: "));
		}
	}
	SECTION("a principal and a password, UTF-8")
	{
		ldap::sasl_gssapi mech("j\xC3\xB6rg@EXAMPLE.ORG",
		  "p\xC3\xA4ssw\xC3\xB6rd",
		  { .target = "ldap@dc1.example.org", .require_tls = false });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		if (!sspi) {
			CHECK_THAT(
			  std::string(r.error().context), StartsWith("sasl bind GSSAPI: gss_acquire_cred_with_password: "));
		}
	}
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());
}

TEST_CASE("gssapi: require_tls refuses plain LDAP without a security layer", "[net][sasl][gssapi]")
{
	const scoped_env config("KRB5_CONFIG", "/dev/null");
	const scoped_env cache("KRB5CCNAME", "FILE:/nonexistent/jhetz-ldap-test-ccache");
	const scoped_env keytab("KRB5_CLIENT_KTNAME", "FILE:/nonexistent/jhetz-ldap-test-keytab");
	tcp_mock_ldap m;
	m.serve({});

	SECTION("by default: tls_required before anything is sent")
	{
		ldap::sasl_gssapi mech;
		CHECK_FALSE(mech.offload_start());// nothing to offload: start() fails inline
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(r.error().code == ldap::cond::access_denied);
		CHECK_THAT(std::string(r.error().context),
		  StartsWith("sasl bind GSSAPI: GSSAPI without a security layer needs a TLS-protected connection"));
	}
	SECTION("a security layer stands in for TLS, as does require_tls = false: GSS-API is called")
	{
		for (const auto &options :
		  { ldap::sasl_gssapi_options{ .security_layer = ldap::gssapi_security_layer::integrity },
			ldap::sasl_gssapi_options{ .security_layer = ldap::gssapi_security_layer::confidentiality },
			ldap::sasl_gssapi_options{ .security_layer = ldap::gssapi_security_layer::best_offered },
			ldap::sasl_gssapi_options{ .require_tls = false } }) {
			ldap::sasl_gssapi mech(options);
			auto r = m.run(m.conn.sasl_bind(mech));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		}
	}
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());
}

TEST_CASE("gssapi: challenges and success out of order", "[net][sasl][gssapi]")
{
	ldap::sasl_gssapi mech;
	auto challenge = mech.step("token"sv);
	REQUIRE_FALSE(challenge.has_value());
	CHECK(challenge.error().code == ldap::client_errc::unexpected_response);
	auto success = mech.complete(std::nullopt);
	REQUIRE_FALSE(success.has_value());
	CHECK(success.error().code == ldap::client_errc::unexpected_response);
	CHECK(success.error().context == "the server reported success before the security layer negotiation");

	// A moved-from mechanism is still usable.
	ldap::sasl_gssapi other(std::move(mech));
	CHECK_FALSE(mech.complete(std::nullopt).has_value());// NOLINT(bugprone-use-after-move): moved-from state on purpose
	CHECK_FALSE(mech.step(std::nullopt).has_value());
	CHECK(mech.name() == "GSSAPI");
}

TEST_CASE("gssapi: offloaded steps", "[net][sasl][gssapi]")
{
	const scoped_env config("KRB5_CONFIG", "/dev/null");
	const scoped_env cache("KRB5CCNAME", "FILE:/nonexistent/jhetz-ldap-test-ccache");
	const scoped_env keytab("KRB5_CLIENT_KTNAME", "FILE:/nonexistent/jhetz-ldap-test-keytab");

	SECTION("the work outlives the mechanism")
	{
		ldap::sasl_work work;
		{
			ldap::sasl_gssapi mech({ .target = "ldap@dc1.example.org", .require_tls = false });
			work = mech.offload_start();
			REQUIRE(work);
		}
		auto r = work();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK_THAT(std::string(r.error().context), StartsWith(std::string(init_call)));
	}
	SECTION("steps while the work runs are refused; start() begins anew")
	{
		ldap::sasl_gssapi mech({ .target = "ldap@dc1.example.org", .require_tls = false });
		auto work = mech.offload_start();
		auto challenge = mech.step("token"sv);
		REQUIRE_FALSE(challenge.has_value());
		CHECK(challenge.error().context == "a challenge while the previous step still runs");
		auto success = mech.complete(std::nullopt);
		REQUIRE_FALSE(success.has_value());
		CHECK(success.error().context == "success while the previous step still runs");
		CHECK_FALSE(mech.offload_step("token"sv));// step() would refuse it
		auto again = mech.start();
		REQUIRE_FALSE(again.has_value());
		CHECK(again.error().code == ldap::client_errc::gssapi_failure);
		CHECK_FALSE(work().has_value());// the first state, still its own
	}
	SECTION("nothing to offload outside the context establishment")
	{
		ldap::sasl_gssapi mech;
		CHECK_FALSE(mech.offload_step("token"sv));
		CHECK_FALSE(mech.offload_step(std::nullopt));
	}
}

TEST_CASE("gssapi: the channel bindings' application data", "[net][sasl][gssapi][channel_binding]")
{
	using ldap::detail::gssapi_channel_binding_data;
	using enum ldap::gssapi_channel_binding;
	using enum ldap::gssapi_channel_binding_form;
	const std::array<std::byte, 3> hash{ std::byte{ 0x01 }, std::byte{ 0x00 }, std::byte{ 0xfe } };
	ldap::sasl_bind_context tls{ .host = "dc1.example.org", .tls = true };
	tls.bindings.tls_server_end_point = hash;
	const auto no_hash = [](const ldap::result<std::string> &r, std::string_view why) {
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(std::string(r.error().context)
			  == "the TLS connection has no tls-server-end-point channel binding data (" + std::string(why) + ")");
	};

	SECTION("over TLS: \"tls-server-end-point:\" and the connection's RFC 5929 hash")
	{
		CHECK(gssapi_channel_binding_data(tls, tls_server_end_point, rfc5929)
			  == std::string("tls-server-end-point:\x01\x00\xfe", 24));
	}
	SECTION("none, or no TLS: no bindings")
	{
		CHECK(gssapi_channel_binding_data(tls, none, rfc5929) == "");
		CHECK(gssapi_channel_binding_data(tls, none, openldap) == "");
		auto plain = tls;
		plain.tls = false;
		CHECK(gssapi_channel_binding_data(plain, tls_server_end_point, rfc5929) == "");
		CHECK(gssapi_channel_binding_data(plain, tls_server_end_point, openldap) == "");
	}
	SECTION("a certificate without a tls-server-end-point hash: refused, unless none")
	{
		auto ed = tls;
		ed.bindings.tls_server_end_point = {};
		no_hash(gssapi_channel_binding_data(ed, tls_server_end_point, rfc5929),
		  "no hash for the server's certificate, e.g. Ed25519 or Ed448, or no certificate");
		CHECK(gssapi_channel_binding_data(ed, none, rfc5929) == "");
	}
	SECTION("the openldap form hashes the peer certificate itself")
	{
		test_pki pki;// ECDSA P-256 with SHA-256: SHA-256 in both forms
		const auto der = certificate_der(pki.issue("dc1.example.org", "DNS:dc1.example.org").cert_pem);
		tls.peer_certificate = der;
		std::array<unsigned char, EVP_MAX_MD_SIZE> md{};
		unsigned int n = 0;
		REQUIRE(EVP_Digest(der.data(), der.size(), md.data(), &n, EVP_sha256(), nullptr) == 1);
		const auto out = gssapi_channel_binding_data(tls, tls_server_end_point, openldap);
		CHECK(out
			  == "tls-server-end-point:"
				   + std::string(reinterpret_cast<const char *>(md.data()), static_cast<std::size_t>(n)));
		const std::array<std::byte, 2> junk{ std::byte{ 0x30 }, std::byte{ 0x00 } };
		tls.peer_certificate = junk;
		no_hash(gssapi_channel_binding_data(tls, tls_server_end_point, openldap),
		  "no OpenLDAP hash for the server's certificate: not parsed, or an unknown signature algorithm, or no "
		  "certificate");
		CHECK(gssapi_channel_binding_data(tls, none, openldap) == "");
	}
}

TEST_CASE("gssapi: channel_binding_used says whether the exchange binds", "[net][sasl][gssapi][channel_binding]")
{
	const scoped_env config("KRB5_CONFIG", "/dev/null");
	const scoped_env cache("KRB5CCNAME", "FILE:/nonexistent/jhetz-ldap-test-ccache");
	const scoped_env keytab("KRB5_CLIENT_KTNAME", "FILE:/nonexistent/jhetz-ldap-test-keytab");
	const std::array<std::byte, 2> hash{ std::byte{ 0xaa }, std::byte{ 0xbb } };
	ldap::sasl_bind_context tls{ .host = "dc1.example.org", .tls = true };
	tls.bindings.tls_server_end_point = hash;

	SECTION("over TLS: tls-server-end-point, and gss_init_sec_context takes the bindings")
	{
		ldap::sasl_gssapi mech;
		mech.prepare(tls);
		CHECK(mech.channel_binding_used() == ldap::channel_binding_type::tls_server_end_point);
		// No credentials: the call fails after taking the bindings.
		auto r = mech.start();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK_THAT(std::string(r.error().context), StartsWith(std::string(init_call)));
		// The next bind, without TLS, has none.
		mech.prepare({ .host = "dc1.example.org" });
		CHECK_FALSE(mech.channel_binding_used().has_value());
	}
	SECTION("gssapi_channel_binding::none: none over TLS")
	{
		ldap::sasl_gssapi mech({ .channel_binding = ldap::gssapi_channel_binding::none });
		mech.prepare(tls);
		CHECK_FALSE(mech.channel_binding_used().has_value());
	}
	SECTION("over TLS without a hash: start() fails, no fallback to no bindings")
	{
		auto ed = tls;// an Ed25519 certificate: no RFC 5929 hash
		ed.bindings.tls_server_end_point = {};
		ldap::sasl_gssapi mech;
		mech.prepare(ed);
		CHECK_FALSE(mech.offload_start());// nothing to offload: start() fails inline
		auto r = mech.start();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK_THAT(std::string(r.error().context),
		  StartsWith("the TLS connection has no tls-server-end-point channel binding data"));
		CHECK_FALSE(mech.channel_binding_used().has_value());
		CHECK_FALSE(mech.step("token"sv).has_value());// no exchange started
		// The next bind, on a connection with a hash, binds again.
		mech.prepare(tls);
		CHECK(mech.channel_binding_used() == ldap::channel_binding_type::tls_server_end_point);
		r = mech.start();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
	}
	SECTION("over TLS without a hash, with none: no bindings, the bind goes on")
	{
		auto ed = tls;
		ed.bindings.tls_server_end_point = {};
		ldap::sasl_gssapi mech({ .channel_binding = ldap::gssapi_channel_binding::none });
		mech.prepare(ed);
		CHECK_FALSE(mech.channel_binding_used().has_value());
		auto r = mech.start();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);// the GSS-API call was made
	}
}

TEST_CASE("gssapi: UTF-8 to UTF-16", "[net][sasl][gssapi][sspi]")
{
	using ldap::detail::utf8_to_utf16;
	CHECK(utf8_to_utf16("", "x") == u"");
	CHECK(utf8_to_utf16("j\xC3\xB6rg", "x") == u"j\u00F6rg");
	// Outside the BMP: a surrogate pair.
	CHECK(utf8_to_utf16("\xF0\x9F\x94\x91 key", "x") == u"\U0001F511 key");
	CHECK(utf8_to_utf16("\xE6\x97\xA5\xE6\x9C\xAC", "x") == u"\u65E5\u672C");
	for (const auto bad : { "\xFF"sv, "\xC3"sv, "\xC0\xAF"sv, "\xED\xA0\x80"sv, "\xF4\x90\x80\x80"sv }) {
		auto r = utf8_to_utf16(bad, "password");
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::encode_error);
		CHECK(r.error().context == "password is not valid UTF-8");
	}
}

TEST_CASE("gssapi: the SSPI identity of a principal and password", "[net][sasl][gssapi][sspi]")
{
	using ldap::detail::make_sspi_identity;
	using fields = std::array<std::u16string, 3>;
	const auto identity = [](std::string_view principal, std::string_view password) {
		auto id = make_sspi_identity(principal, password);
		REQUIRE(id.has_value());
		return fields{ id->user, id->domain, id->password };
	};
	CHECK(identity("jdoe@EXAMPLE.ORG", "pw") == fields{ u"jdoe", u"EXAMPLE.ORG", u"pw" });
	CHECK(identity("EXAMPLE\\jdoe", "") == fields{ u"jdoe", u"EXAMPLE", u"" });
	CHECK(identity("jdoe", "") == fields{ u"jdoe", u"", u"" });
	// The last '@' separates the domain.
	CHECK(identity("j.doe@corp@EXAMPLE.ORG", "") == fields{ u"j.doe@corp", u"EXAMPLE.ORG", u"" });
	CHECK(identity("J\xC3\xB6rg@\xC3\x9C"
				   "BER.EXAMPLE",
			"p\xC3\xA4ss\xF0\x9F\x94\x91")
		  == fields{ u"J\u00F6rg",
			u"\u00DC"
			u"BER.EXAMPLE",
			u"p\u00E4ss\U0001F511" });
	auto empty = make_sspi_identity("@EXAMPLE.ORG", "pw");
	REQUIRE_FALSE(empty.has_value());
	CHECK(empty.error().context == "principal has no user name");
	auto bad = make_sspi_identity("jdoe", "\xFF");
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().context == "password is not valid UTF-8");
}

TEST_CASE("gssapi: the SSPI target name", "[net][sasl][gssapi][sspi]")
{
	using ldap::detail::sspi_target_name;
	CHECK(sspi_target_name("ldap@dc1.example.org") == u"ldap/dc1.example.org");
	CHECK(sspi_target_name("ldap/dc1.example.org") == u"ldap/dc1.example.org");
	CHECK(sspi_target_name("ldap/dc1.example.org@EXAMPLE.ORG") == u"ldap/dc1.example.org@EXAMPLE.ORG");
	CHECK(sspi_target_name("ldap@d\xC3\xBC.example") == u"ldap/d\u00FC.example");
}
