// Integration tests against a real Samba Active Directory domain controller,
// started in Docker by run_samba_ad.sh (which sets the JHETZ_LDAP_IT_SAMBA_*
// variables):
//
//   tests/integration/run_samba_ad.sh ctest --test-dir build -L samba_ad --output-on-failure
//
// Two DCs of the same domain (CORO.TEST, samba-ad/Dockerfile): the strict
// one with Samba's default `ldap server require strong auth = yes` (on
// plain ldap:// only signed or sealed SASL binds, over TLS channel bindings
// required), the relaxed one with `no`. Their certificate is Samba's own,
// for CN=DC1.coro.test without a subjectAltName: the tests connect to
// 127.0.0.1 and match that name against the CN (host_name_matching::legacy).
// Without the variables every test is skipped.
#include "../net/net_test_support.hpp"
#include "jhetz/ldap/ad.hpp"
#include "jhetz/ldap/connection.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstdlib>
#include <string>

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

// Each test starts with it, so the skip is reported at the test.
void require_samba()
{
	if (env("JHETZ_LDAP_IT_SAMBA_LDAP").empty()) {
		SKIP("no Samba AD DC: run under run_samba_ad.sh");
	}
}

// The accounts samba-ad/Dockerfile creates.
const ldap::dn administrator{ "CN=Administrator,CN=Users,DC=coro,DC=test" };
const std::string administrator_password = "Adm1n-Passw0rd";
const ldap::dn pwchange{ "CN=pwchange,CN=Users,DC=coro,DC=test" };

auto strict_ldap() -> std::string { return env("JHETZ_LDAP_IT_SAMBA_LDAP"); }
auto strict_ldaps() -> std::string { return env("JHETZ_LDAP_IT_SAMBA_LDAPS"); }

// Trusts Samba's CA and matches its certificate's CN.
auto samba_tls(ldap::connection_options o = {}) -> ldap::connection_options
{
	o.tls.ca_file = env("JHETZ_LDAP_IT_SAMBA_CA");
	o.tls.server_name = std::pmr::string(env("JHETZ_LDAP_IT_SAMBA_TLS_NAME"));
	o.tls.host_matching = ldap::net::host_name_matching::legacy;
	o.timeout = std::chrono::seconds(10);
	o.operation_timeout = std::chrono::seconds(30);
	return o;
}

auto open(corosio::io_context &ioc, const std::string &url, const ldap::connection_options &o = samba_tls())
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

// To the strict DC over ldaps://, or over ldap:// and StartTLS.
auto open_tls(corosio::io_context &ioc, bool start_tls) -> ldap::connection
{
	if (start_tls) {
		auto o = samba_tls();
		o.start_tls = true;
		return open(ioc, strict_ldap(), o);
	}
	return open(ioc, strict_ldaps());
}

auto open_bound(corosio::io_context &ioc, bool start_tls, const ldap::dn &who, const std::string &password)
  -> ldap::connection
{
	auto c = open_tls(ioc, start_tls);
	auto b = finish(ioc, c.simple_bind(who, password));
	if (!b) {
		FAIL("bind as " << who.to_string() << ": " << b.error().message());
	}
	return c;
}

// The result of a simple bind as `who` on a new TLS connection.
auto try_bind(corosio::io_context &ioc, const ldap::dn &who, const std::string &password) -> ldap::result<void>
{
	auto c = open_tls(ioc, false);
	return finish(ioc, c.simple_bind(who, password));
}

void reset(corosio::io_context &ioc, const ldap::dn &who, const std::string &password)
{
	auto admin = open_bound(ioc, false, administrator, administrator_password);
	auto r = finish(ioc, admin.reset_password(who, password));
	if (!r) {
		FAIL("reset the password of " << who.to_string() << ": " << r.error().message());
	}
}

}// namespace

// ---------------------------------------------------------------- password changes (unicodePwd)

TEST_CASE("samba ad: change_password and reset_password", "[samba_ad][password]")
{
	require_samba();
	corosio::io_context ioc;
	const bool start_tls = GENERATE(false, true);
	CAPTURE(start_tls);

	SECTION("the root DSE advertises Active Directory and no RFC 3062: automatic picks active_directory")
	{
		auto c = open_tls(ioc, start_tls);
		auto dse = finish(ioc,
		  c.search({ .scope = ldap::search_scope::base_object,
			.attributes = { "supportedExtension", "supportedCapabilities" } }));
		REQUIRE(dse.has_value());
		REQUIRE(dse->size() == 1);
		const auto *caps = (*dse)[0].find("supportedCapabilities");
		REQUIRE(caps != nullptr);
		CHECK(std::ranges::contains(*caps, ldap::active_directory_capability_oid));
		const auto *extensions = (*dse)[0].find("supportedExtension");
		CHECK((extensions == nullptr || !std::ranges::contains(*extensions, ldap::password_modify_oid)));
		// automatic (the default) as Administrator: with RFC 3062 picked,
		// Samba would answer protocolError to an unknown extended operation.
		auto admin = open_bound(ioc, start_tls, administrator, administrator_password);
		auto r = finish(ioc, admin.reset_password(pwchange, "Auto-Passw0rd"));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "Auto-Passw0rd").has_value());
	}

	SECTION("reset_password as Administrator")
	{
		reset(ioc, pwchange, "Before-Reset-Passw0rd");
		auto admin = open_bound(ioc, start_tls, administrator, administrator_password);
		auto r =
		  finish(ioc, admin.reset_password(pwchange, "After-Reset-Passw0rd", ldap::password_method::active_directory));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "After-Reset-Passw0rd").has_value());
		auto old = try_bind(ioc, pwchange, "Before-Reset-Passw0rd");
		REQUIRE_FALSE(old.has_value());
		CHECK(old.error().code == ldap::errc::invalid_credentials);
	}

	SECTION("change_password as the user (delete the old value, add the new one)")
	{
		reset(ioc, pwchange, "Old-Passw0rd");
		auto user = open_bound(ioc, start_tls, pwchange, "Old-Passw0rd");
		auto r = finish(ioc, user.change_password(pwchange, "Old-Passw0rd", "New-Passw0rd"));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "New-Passw0rd").has_value());
		auto old = try_bind(ioc, pwchange, "Old-Passw0rd");
		REQUIRE_FALSE(old.has_value());
		CHECK(old.error().code == ldap::errc::invalid_credentials);
	}

	SECTION("a non-BMP password (UTF-16 surrogate pairs in unicodePwd)")
	{
		// U+1D11E MUSICAL SYMBOL G CLEF and U+1F511 KEY, outside the BMP.
		const std::string reset_to = "Pä𝄞-Passw0rd";
		const std::string changed_to = "Ünï-🔑-Passw0rd";
		reset(ioc, pwchange, reset_to);
		CHECK(try_bind(ioc, pwchange, reset_to).has_value());
		auto user = open_bound(ioc, start_tls, pwchange, reset_to);
		auto r = finish(ioc, user.change_password(pwchange, reset_to, changed_to));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, changed_to).has_value());
		// The same characters without the non-BMP one are another password.
		auto other = try_bind(ioc, pwchange, "Ünï--Passw0rd");
		REQUIRE_FALSE(other.has_value());
		CHECK(other.error().code == ldap::errc::invalid_credentials);
	}

	SECTION("a password the policy refuses: constraintViolation, 0000052D")
	{
		reset(ioc, pwchange, "Policy-Passw0rd");
		auto user = open_bound(ioc, start_tls, pwchange, "Policy-Passw0rd");
		auto r = finish(ioc, user.change_password(pwchange, "Policy-Passw0rd", "short"));
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::constraint_violation);
		CHECK_THAT(std::string(r.error().diagnostic), StartsWith("0000052D"));
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("does not meet the password policy"));
		// An administrator's reset is held to the policy too.
		auto admin = open_bound(ioc, start_tls, administrator, administrator_password);
		auto a = finish(ioc, admin.reset_password(pwchange, "short"));
		REQUIRE_FALSE(a.has_value());
		INFO(a.error().message());
		CHECK(a.error().code == ldap::errc::constraint_violation);
		CHECK_THAT(std::string(a.error().diagnostic), StartsWith("0000052D"));
		CHECK(try_bind(ioc, pwchange, "Policy-Passw0rd").has_value());
	}

	SECTION("a wrong old password: 00000056")
	{
		reset(ioc, pwchange, "Right-Passw0rd");
		auto user = open_bound(ioc, start_tls, pwchange, "Right-Passw0rd");
		auto r = finish(ioc, user.change_password(pwchange, "Wrong-Passw0rd", "Next-Passw0rd"));
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::constraint_violation);
		CHECK_THAT(std::string(r.error().diagnostic), StartsWith("00000056"));
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("the old password is wrong"));
		CHECK(try_bind(ioc, pwchange, "Right-Passw0rd").has_value());
	}
}

TEST_CASE("samba ad: a password change on plain ldap:// is refused before sending", "[samba_ad][password]")
{
	require_samba();
	corosio::io_context ioc;
	reset(ioc, pwchange, "Plain-Passw0rd");
	auto c = open(ioc, strict_ldap());
	SECTION("active_directory: nothing sent")
	{
		auto r = finish(ioc, c.reset_password(pwchange, "Never-Passw0rd", ldap::password_method::active_directory));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(r.error().diagnostic.empty());
		auto ch = finish(ioc,
		  c.change_password(pwchange, "Plain-Passw0rd", "Never-Passw0rd", ldap::password_method::active_directory));
		REQUIRE_FALSE(ch.has_value());
		CHECK(ch.error().code == ldap::client_errc::tls_required);
	}
	SECTION("automatic: the root DSE is read, then the modify is not sent")
	{
		auto r = finish(ioc, c.change_password(pwchange, "Plain-Passw0rd", "Never-Passw0rd"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(r.error().diagnostic.empty());
	}
	CHECK(c.is_open());
	CHECK(try_bind(ioc, pwchange, "Plain-Passw0rd").has_value());
}
