// SASL GSSAPI (sasl_gssapi.hpp) without a KDC: the RFC 4752 security layer
// messages, and the failures that happen before anything is sent. The
// Kerberos exchange itself is tested against slapd and a throwaway KDC
// (tests/integration/gssapi_tests.cpp, run_kdc.sh).
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <array>
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

// Sets an environment variable for the scope of a test, then restores it.
// Declared before the connection: no other thread (the offloaded steps)
// runs when it is set or restored, as the io_context waits for them.
class scoped_env
{
  public:
	scoped_env(const char *name, const char *value) : name_(name)
	{
		// NOLINTNEXTLINE(concurrency-mt-unsafe): no other thread runs, see above
		if (const char *old = std::getenv(name)) {
			old_ = old;
		}
		::setenv(name, value, 1);// NOLINT(concurrency-mt-unsafe): no other thread runs
	}
	scoped_env(const scoped_env &) = delete;
	auto operator=(const scoped_env &) -> scoped_env & = delete;
	~scoped_env()
	{
		if (old_) {
			::setenv(name_, old_->c_str(), 1);// NOLINT(concurrency-mt-unsafe): no other thread runs
		} else {
			::unsetenv(name_);// NOLINT(concurrency-mt-unsafe): no other thread runs
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

TEST_CASE("gssapi: the client's security layer reply", "[net][sasl][gssapi]")
{
	SECTION("no security layer, maximum size 0, whatever else is offered")
	{
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 1, 3, 5, 7, 0xff })) {
			INFO("layers " << int{ layers });
			CHECK(ldap::detail::gssapi_layer_reply({ layers, 0x10000 }, "") == "\x01\x00\x00\x00"sv);
		}
	}
	SECTION("with an authorization identity, UTF-8")
	{
		CHECK(ldap::detail::gssapi_layer_reply({ 7, 0 }, "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org")
			  == "\x01\x00\x00\x00"
				 "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org"sv);
		CHECK(ldap::detail::gssapi_layer_reply({ 1, 0 }, "u:\xE6\x97\xA5\xE6\x9C\xAC\xF0\x9F\x98\x80")
			  == "\x01\x00\x00\x00u:\xE6\x97\xA5\xE6\x9C\xAC\xF0\x9F\x98\x80"sv);
	}
	SECTION("a server that requires integrity or confidentiality")
	{
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 2, 4, 6, 0xfe })) {
			INFO("layers " << int{ layers });
			auto r = ldap::detail::gssapi_layer_reply({ .layers = layers, .max_size = 0x10000 }, "");
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::security_layer_required);
			CHECK(r.error().code == ldap::cond::access_denied);
			CHECK_THAT(std::string(r.error().context), ContainsSubstring("use TLS"));
		}
	}
	SECTION("an offer of nothing")
	{
		for (std::uint8_t layers : std::to_array<std::uint8_t>({ 0, 8, 0xf0 })) {
			auto r = ldap::detail::gssapi_layer_reply({ .layers = layers, .max_size = 0 }, "");
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::unexpected_response);
		}
	}
	SECTION("an authorization identity that is not valid UTF-8, or has a control character")
	{
		for (auto bad :
		  { "dn:\xC3"sv, "dn:\xC0\xAF"sv, "dn:\xED\xA0\x80"sv, "dn:a\nb"sv, "dn:a\0b"sv, "dn:\xC2\x85"sv }) {
			auto r = ldap::detail::gssapi_layer_reply({ .layers = 1, .max_size = 0 }, bad);
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::encode_error);
		}
	}
}

TEST_CASE("gssapi: no target without a host, nothing sent", "[net][sasl][gssapi]")
{
	mock_ldap m;// a wrapped transport: no host
	m.serve({});
	ldap::sasl_gssapi mech;
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
	refused({ .target = "ldap@\xFF" }, "target is not valid UTF-8");
	refused({ .principal = "jdoe\r\n@EXAMPLE.ORG" }, "principal contains a control character");
	refused({ .authz_id = "dn:\xE2\x82" }, "authorization identity is not valid UTF-8");
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
		ldap::sasl_gssapi mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK(r.error().code == ldap::cond::auth_failed);
		// The major status message, then the mechanism's (minor) one.
		CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: gss_init_sec_context: "));
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("credentials"));
		CHECK_THAT(
		  std::string(r.error().context), ContainsSubstring("(") && ContainsSubstring("jhetz-ldap-test-ccache"));
	}
	SECTION("an explicit principal, UTF-8")
	{
		ldap::sasl_gssapi mech({ .target = "ldap@dc1.example.org", .principal = "j\xC3\xB6rg@EXAMPLE.ORG" });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: gss_acquire_cred: "));
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

// sasl_bind runs the gss_acquire_cred and gss_init_sec_context calls on a
// thread of its own (offload_start, offload_step): the work shares the
// GSS-API handles with the mechanism, which leaves them alone meanwhile.
TEST_CASE("gssapi: offloaded steps", "[net][sasl][gssapi]")
{
	const scoped_env config("KRB5_CONFIG", "/dev/null");
	const scoped_env cache("KRB5CCNAME", "FILE:/nonexistent/jhetz-ldap-test-ccache");
	const scoped_env keytab("KRB5_CLIENT_KTNAME", "FILE:/nonexistent/jhetz-ldap-test-keytab");

	SECTION("the work outlives the mechanism")
	{
		ldap::sasl_work work;
		{
			ldap::sasl_gssapi mech({ .target = "ldap@dc1.example.org" });
			work = mech.offload_start();
			REQUIRE(work);
		}
		auto r = work();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK_THAT(std::string(r.error().context), StartsWith("gss_init_sec_context: "));
	}
	SECTION("steps while the work runs are refused; start() begins anew")
	{
		ldap::sasl_gssapi mech({ .target = "ldap@dc1.example.org" });
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
