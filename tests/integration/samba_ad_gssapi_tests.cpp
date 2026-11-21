// SASL GSSAPI against the Samba AD DCs' Kerberos:
//   tests/integration/run_samba_ad.sh ctest --test-dir build/gssapi -L samba_ad --output-on-failure
// Plain ldap:// with each layer, and TLS with channel bindings, on the
// strict and relaxed DCs. Skipped without Samba or Kerberos.
#include "../net/net_test_support.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sasl_gssapi.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstdlib>
#include <string>

namespace ldap = jhetz::ldap;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;

namespace {

auto env(const char *name) -> std::string
{
	// NOLINTNEXTLINE(concurrency-mt-unsafe): nothing in this binary calls setenv while tests run
	const char *v = std::getenv(name);
	return v == nullptr ? std::string() : std::string(v);
}

void require_kerberos()
{
	if (env("JHETZ_LDAP_IT_SAMBA_LDAP").empty()) {
		SKIP("no Samba AD DC: run under run_samba_ad.sh");
	}
	if (env("JHETZ_LDAP_IT_SAMBA_KRB5_TARGET").empty()) {
		SKIP("no Kerberos for the Samba AD DC (MIT kinit not found by run_samba_ad.sh)");
	}
}

const std::string alice_identity = "u:CORO\\alice";

auto samba_tls() -> ldap::connection_options
{
	ldap::connection_options o;
	o.tls.ca_file = env("JHETZ_LDAP_IT_SAMBA_CA");
	o.tls.server_name = std::pmr::string(env("JHETZ_LDAP_IT_SAMBA_TLS_NAME"));
	o.tls.host_matching = ldap::net::host_name_matching::legacy;
	o.timeout = std::chrono::seconds(10);
	o.operation_timeout = std::chrono::seconds(30);
	return o;
}

auto open(corosio::io_context &ioc, const std::string &url) -> ldap::connection
{
	auto u = ldap::url::parse(url);
	REQUIRE(u.has_value());
	auto c = finish(ioc, ldap::connect(ioc, *u, samba_tls()));
	if (!c) {
		FAIL("connect " << url << ": " << c.error().message());
	}
	return std::move(*c);
}

// Without a layer, plain ldap:// is allowed (require_tls = false).
auto gssapi(ldap::gssapi_security_layer layer) -> ldap::sasl_gssapi
{
	return ldap::sasl_gssapi(
	  { .target = env("JHETZ_LDAP_IT_SAMBA_KRB5_TARGET"), .require_tls = false, .security_layer = layer });
}

// Binds `c` as alice with `layer`; the identity the DC reports after it.
auto bind_and_who(corosio::io_context &ioc, ldap::connection &c, ldap::gssapi_security_layer layer)
  -> ldap::result<std::string>
{
	auto mech = gssapi(layer);
	if (auto b = finish(ioc, c.sasl_bind(mech)); !b) {
		return std::unexpected(std::move(b.error()));
	}
	return finish(ioc, ldap::who_am_i(c));
}

}// namespace

TEST_CASE("samba ad gssapi: plain ldap:// with each security layer", "[samba_ad][gssapi]")
{
	require_kerberos();
	draining_context ioc;

	SECTION("relaxed DC: no layer")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_SAMBA_RELAXED_LDAP"));
		auto who = bind_and_who(ioc, c, ldap::gssapi_security_layer::none);
		if (!who) {
			FAIL(who.error().message());
		}
		CHECK(*who == alice_identity);
		CHECK(c.security_layer() == ldap::sasl_protection::none);
	}
	SECTION("strict DC: no layer is refused")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_SAMBA_LDAP"));
		auto mech = gssapi(ldap::gssapi_security_layer::none);
		auto b = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(b.has_value());
		INFO(b.error().message());
		CHECK((b.error().code == ldap::errc::stronger_auth_required
			   || b.error().code == ldap::client_errc::security_layer_required));
	}
	SECTION("strict DC: integrity and confidentiality")
	{
		const auto layer =
		  GENERATE(ldap::gssapi_security_layer::integrity, ldap::gssapi_security_layer::confidentiality);
		CAPTURE(layer);
		auto c = open(ioc, env("JHETZ_LDAP_IT_SAMBA_LDAP"));
		auto who = bind_and_who(ioc, c, layer);
		if (!who) {
			FAIL(who.error().message());
		}
		CHECK(*who == alice_identity);
		CHECK(c.security_layer()
			  == (layer == ldap::gssapi_security_layer::integrity ? ldap::sasl_protection::integrity
																  : ldap::sasl_protection::confidentiality));
		// Later operations go through the layer.
		auto dse = finish(ioc, c.search(ldap::root_dse({ "defaultNamingContext" })));
		REQUIRE(dse.has_value());
		REQUIRE(dse->entries.size() == 1);
		const auto *nc = dse->entries[0].find("defaultNamingContext");
		REQUIRE(nc != nullptr);
		CHECK(*nc == std::pmr::vector<std::pmr::string>{ "DC=coro,DC=test" });
	}
}

TEST_CASE("samba ad gssapi: over TLS with channel bindings", "[samba_ad][gssapi]")
{
	require_kerberos();
	draining_context ioc;
	const bool strict = GENERATE(true, false);
	CAPTURE(strict);
	auto c = open(ioc, env(strict ? "JHETZ_LDAP_IT_SAMBA_LDAPS" : "JHETZ_LDAP_IT_SAMBA_RELAXED_LDAPS"));
	REQUIRE(c.is_tls());
	auto who = bind_and_who(ioc, c, ldap::gssapi_security_layer::none);
	if (!who) {
		FAIL(who.error().message());
	}
	CHECK(*who == alice_identity);
}
