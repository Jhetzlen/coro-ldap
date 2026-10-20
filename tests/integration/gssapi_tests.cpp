// SASL GSSAPI against a real slapd and a throwaway MIT Kerberos KDC:
//
//   tests/integration/run_kdc.sh tests/integration/run_slapd.sh ctest --test-dir build -L kerberos
//
// run_kdc.sh creates the realm EXAMPLE.ORG, the service principal
// ldap/localhost (slapd's keytab) and the users user007 and jörg (tickets
// in a credential cache collection, user007's the default); run_slapd.sh
// maps a principal to the entry of the same uid. Skipped without them, or
// when slapd does not offer GSSAPI (cyrus-sasl's gssapi plugin missing).
#include "../net/net_test_support.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

auto env(const char *name) -> std::string
{
	// NOLINTNEXTLINE(concurrency-mt-unsafe): nothing in this binary calls setenv while tests run
	const char *v = std::getenv(name);
	return v == nullptr ? std::string() : std::string(v);
}

const std::string user007 = "dn:uid=user007,ou=people,dc=example,dc=org";

auto trusting(ldap::connection_options o = {}) -> ldap::connection_options
{
	o.tls.ca_file = env("JHETZ_LDAP_IT_CA");
	o.timeout = std::chrono::seconds(10);
	o.operation_timeout = std::chrono::seconds(10);
	return o;
}

auto open(corosio::io_context &ioc, const std::string &url, const ldap::connection_options &o = trusting())
  -> ldap::connection
{
	auto u = ldap::url::parse(url);
	REQUIRE(u.has_value());
	auto c = finish(ioc, ldap::connect(ioc, *u, o));
	if (!c) {
		FAIL("connect " << url << ": " << c.error().message());
	}
	return std::move(*c);
}

// ldap://localhost:<port>: the service principal is ldap/localhost.
auto localhost_url() -> std::string
{
	std::string url = env("JHETZ_LDAP_IT_LDAP");
	const auto at = url.find("127.0.0.1");
	REQUIRE(at != std::string::npos);
	return url.replace(at, 9, "localhost");
}

// Skips the test unless slapd and the KDC are set up and slapd offers GSSAPI.
void require_kerberos()
{
	if (env("JHETZ_LDAP_IT_LDAP").empty() || env("JHETZ_LDAP_IT_KRB5_REALM").empty()) {
		SKIP("no slapd and KDC: run under run_kdc.sh run_slapd.sh");
	}
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	auto dse =
	  finish(ioc, c.search({ .scope = ldap::search_scope::base_object, .attributes = { "supportedSASLMechanisms" } }));
	REQUIRE(dse.has_value());
	REQUIRE(dse->size() == 1);
	const auto *mechs = (*dse)[0].find("supportedSASLMechanisms");
	if (mechs == nullptr || std::ranges::find(*mechs, "GSSAPI") == mechs->end()) {
		SKIP("slapd does not offer GSSAPI (cyrus-sasl's gssapi plugin not installed, or not on SASL_PATH)");
	}
}

auto bind_and_who(corosio::io_context &ioc, ldap::connection &c, ldap::sasl_gssapi &mech) -> std::string
{
	auto r = finish(ioc, c.sasl_bind(mech));
	if (!r) {
		FAIL("sasl bind: " << r.error().message());
	}
	auto who = finish(ioc, c.who_am_i());
	REQUIRE(who.has_value());
	return *who;
}

// Sets slapd's SASL security properties (olcSaslSecProps) for the test,
// then restores them.
class sasl_secprops
{
  public:
	sasl_secprops(corosio::io_context &ioc, const std::string &value)
	  : ioc_(ioc), config_(open(ioc, env("JHETZ_LDAP_IT_LDAP")))
	{
		auto b = finish(ioc_, config_.simple_bind(config_dn, "secret"));
		if (!b) {
			FAIL("bind as cn=config: " << b.error().message());
		}
		auto old = finish(ioc_,
		  config_.search(
			{ .base = config_dn, .scope = ldap::search_scope::base_object, .attributes = { "olcSaslSecProps" } }));
		REQUIRE(old.has_value());
		REQUIRE(old->size() == 1);
		if (const auto *v = (*old)[0].find("olcSaslSecProps"); v != nullptr && !v->empty()) {
			old_ = std::string((*v)[0]);
		}
		set(value);
	}
	sasl_secprops(const sasl_secprops &) = delete;
	auto operator=(const sasl_secprops &) -> sasl_secprops & = delete;
	~sasl_secprops()
	{
		try {
			if (old_) {
				set(*old_);
			} else {
				(void)finish(ioc_,
				  config_.modify({ .object = config_dn, .changes = { ldap::mod::remove("olcSaslSecProps", {}) } }));
			}
		} catch (...) {// NOLINT(bugprone-empty-catch): best-effort restore, a destructor must not throw
		}
	}

  private:
	void set(const std::string &value)
	{
		auto m = finish(ioc_,
		  config_.modify({ .object = config_dn, .changes = { ldap::mod::replace("olcSaslSecProps", { value }) } }));
		if (!m) {
			FAIL("set olcSaslSecProps: " << m.error().message());
		}
	}

	inline static const ldap::dn config_dn{ "cn=config" };
	corosio::io_context &ioc_;
	ldap::connection config_;
	std::optional<std::string> old_;
};

}// namespace

TEST_CASE("integration: SASL GSSAPI", "[integration][sasl][gssapi]")
{
	require_kerberos();
	corosio::io_context ioc;

	SECTION("default credentials, target ldap@<the URL's host>")
	{
		auto c = open(ioc, localhost_url());
		ldap::sasl_gssapi mech;
		CHECK(bind_and_who(ioc, c, mech) == user007);
		// The same object binds again, with a new security context.
		CHECK(bind_and_who(ioc, c, mech) == user007);
	}
	SECTION("an explicit target, connected by address")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		ldap::sasl_gssapi mech({ .target = "ldap@localhost" });
		CHECK(bind_and_who(ioc, c, mech) == user007);
	}
	SECTION("an explicit principal, UTF-8, from the cache collection")
	{
		auto c = open(ioc, localhost_url());
		ldap::sasl_gssapi jorg({ .principal = "j\xC3\xB6rg" });
		CHECK(bind_and_who(ioc, c, jorg) == "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org");
		ldap::sasl_gssapi with_realm({ .principal = "user007@" + env("JHETZ_LDAP_IT_KRB5_REALM") });
		CHECK(bind_and_who(ioc, c, with_realm) == user007);
	}
	SECTION("an authorization identity (its own: no proxy authorization rules needed)")
	{
		auto c = open(ioc, localhost_url());
		ldap::sasl_gssapi mech({ .authz_id = user007 });
		CHECK(bind_and_who(ioc, c, mech) == user007);
	}
	SECTION("over StartTLS and ldaps://")
	{
		auto o = trusting();
		o.start_tls = true;
		auto tls = open(ioc, localhost_url(), o);
		REQUIRE(tls.is_tls());
		ldap::sasl_gssapi mech;
		CHECK(bind_and_who(ioc, tls, mech) == user007);
		auto ldaps = open(ioc, env("JHETZ_LDAP_IT_LDAPS"));
		CHECK(bind_and_who(ioc, ldaps, mech) == user007);
	}
	SECTION("an unknown service principal")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		ldap::sasl_gssapi mech({ .target = "ldap@nowhere.example.org" });
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: gss_init_sec_context: "));
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("ldap/nowhere.example.org@"));
		CHECK(c.is_open());
		CHECK(finish(ioc, c.who_am_i()) == "");
	}
	SECTION("a principal without credentials")
	{
		auto c = open(ioc, localhost_url());
		ldap::sasl_gssapi mech({ .principal = "nobody" });
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::gssapi_failure);
		CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: gss_acquire_cred: "));
		CHECK(c.is_open());
	}
}

TEST_CASE("integration: SASL GSSAPI with a server that requires a security layer", "[integration][sasl][gssapi]")
{
	require_kerberos();
	corosio::io_context ioc;
	// minssf=1: over plain LDAP slapd offers integrity and confidentiality
	// only; over TLS, TLS provides the strength, and "no layer" is offered.
	const sasl_secprops secprops(ioc, "noanonymous,noplain,minssf=1");

	SECTION("plain LDAP: refused, the exchange aborted, the connection usable")
	{
		auto c = open(ioc, localhost_url());
		ldap::sasl_gssapi mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::security_layer_required);
		CHECK(r.error().code == ldap::cond::access_denied);
		CHECK_THAT(std::string(r.error().context), StartsWith("sasl bind GSSAPI: the server requires integrity"));
		REQUIRE(c.is_open());
		CHECK(finish(ioc, c.who_am_i()) == "");
	}
	SECTION("StartTLS: no layer is fine")
	{
		auto o = trusting();
		o.start_tls = true;
		auto c = open(ioc, localhost_url(), o);
		ldap::sasl_gssapi mech;
		CHECK(bind_and_who(ioc, c, mech) == user007);
	}
}
