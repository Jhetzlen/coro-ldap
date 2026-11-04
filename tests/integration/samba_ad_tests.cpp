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
#include "jhetz/ldap/sasl_ntlm.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
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

const std::string alice_password = "Al1ce-Passw0rd";
const std::string jorg_password = "Jörg-𝄞-Pässw0rd";// U+1D11E, outside the BMP

auto strict_ldap() -> std::string { return env("JHETZ_LDAP_IT_SAMBA_LDAP"); }
auto strict_ldaps() -> std::string { return env("JHETZ_LDAP_IT_SAMBA_LDAPS"); }
auto relaxed_ldap() -> std::string { return env("JHETZ_LDAP_IT_SAMBA_RELAXED_LDAP"); }
auto relaxed_ldaps() -> std::string { return env("JHETZ_LDAP_IT_SAMBA_RELAXED_LDAPS"); }

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

// ---------------------------------------------------------------- SASL NTLM binds

namespace {

// To `url` over ldaps://, or over ldap:// and StartTLS.
auto open_tls_to(corosio::io_context &ioc, const std::string &ldaps, const std::string &ldap, bool start_tls)
  -> ldap::connection
{
	if (start_tls) {
		auto o = samba_tls();
		o.start_tls = true;
		return open(ioc, ldap, o);
	}
	return open(ioc, ldaps);
}

// Binds with `mech`, then asks who the connection is bound as.
auto ntlm_bind(corosio::io_context &ioc, ldap::connection &c, ldap::sasl_mechanism &mech) -> ldap::result<std::string>
{
	auto r = finish(ioc, c.sasl_bind(mech));
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	return finish(ioc, c.who_am_i());
}

// sasl_ntlm given the tls-server-end-point hash of another certificate (the
// connection's with one bit flipped): what a man in the middle relaying
// the bind to the DC over its own TLS connection would send.
class ntlm_wrong_binding final : public ldap::sasl_mechanism
{
  public:
	ntlm_wrong_binding(std::string username, std::string password) : ntlm_(std::move(username), std::move(password)) {}

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return ntlm_.name(); }
	void prepare(const ldap::sasl_bind_context &context) override
	{
		binding_.assign(context.bindings.tls_server_end_point.begin(), context.bindings.tls_server_end_point.end());
		REQUIRE_FALSE(binding_.empty());
		binding_[0] ^= std::byte{ 1 };
		ldap::sasl_bind_context other = context;
		other.bindings.tls_server_end_point = binding_;
		ntlm_.prepare(other);
	}
	auto start() -> ldap::result<std::optional<std::string>> override { return ntlm_.start(); }
	auto step(std::optional<std::string_view> challenge) -> ldap::result<std::optional<std::string>> override
	{
		return ntlm_.step(challenge);
	}
	auto complete(std::optional<std::string_view> server_creds) -> ldap::result<void> override
	{
		return ntlm_.complete(server_creds);
	}
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<ldap::channel_binding_type> override
	{
		return ntlm_.channel_binding_used();
	}

  private:
	ldap::sasl_ntlm ntlm_;
	std::vector<std::byte> binding_;
};

}// namespace

TEST_CASE("samba ad: sasl_ntlm binds over TLS with channel binding", "[samba_ad][ntlm]")
{
	require_samba();
	corosio::io_context ioc;
	const bool start_tls = GENERATE(false, true);
	CAPTURE(start_tls);
	// The strict DC: channel bindings required over TLS.
	auto c = open_tls_to(ioc, strict_ldaps(), strict_ldap(), start_tls);
	const struct
	{
		const char *name;
		std::string username;
		const std::string *password;
		std::string who;
	} cases[] = {
		{ .name = "UPN", .username = "alice@coro.test", .password = &alice_password, .who = "u:CORO\\alice" },
		{ .name = "DOMAIN\\user", .username = "CORO\\alice", .password = &alice_password, .who = "u:CORO\\alice" },
		{ .name = "a bare user name (the server's domain)",
		  .username = "alice",
		  .password = &alice_password,
		  .who = "u:CORO\\alice" },
		{ .name = "a non-ASCII UPN, a non-BMP password",
		  .username = "jörg@coro.test",
		  .password = &jorg_password,
		  .who = "u:CORO\\jörg" },
		{ .name = "a non-ASCII DOMAIN\\user, a non-BMP password",
		  .username = "CORO\\jörg",
		  .password = &jorg_password,
		  .who = "u:CORO\\jörg" },
		{ .name = "a non-ASCII user name in other case (uppercased by NTOWFv2)",
		  .username = "CORO\\JÖRG",
		  .password = &jorg_password,
		  .who = "u:CORO\\jörg" },
	};
	for (const auto &t : cases) {
		DYNAMIC_SECTION(t.name)
		{
			ldap::sasl_ntlm mech(t.username, *t.password);
			auto who = ntlm_bind(ioc, c, mech);
			if (!who) {
				FAIL(who.error().message());
			}
			CHECK(*who == t.who);
			CHECK(mech.channel_binding_used() == ldap::channel_binding_type::tls_server_end_point);
		}
	}
	SECTION("a wrong password: invalidCredentials")
	{
		ldap::sasl_ntlm mech("CORO\\alice", "Wrong-Passw0rd");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		// SEC_E_LOGON_DENIED (0x8009030C), "data 52e" (ERROR_LOGON_FAILURE),
		// in Windows' format.
		CHECK_THAT(std::string(r.error().diagnostic), StartsWith("8009030C"));
		CHECK_THAT(std::string(r.error().diagnostic), ContainsSubstring("data 52e"));
	}
}

TEST_CASE("samba ad: sasl_ntlm channel binding policy", "[samba_ad][ntlm]")
{
	require_samba();
	corosio::io_context ioc;
	const bool start_tls = GENERATE(false, true);
	CAPTURE(start_tls);
	// A refused binding is invalidCredentials with SEC_E_BAD_BINDINGS
	// (0x80090346) in Windows' diagnostic format.
	const auto bad_bindings = [](const ldap::result<void> &r) {
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK_THAT(std::string(r.error().diagnostic), StartsWith("80090346"));
	};
	SECTION("required (strict): a wrong binding is refused")
	{
		auto c = open_tls_to(ioc, strict_ldaps(), strict_ldap(), start_tls);
		ntlm_wrong_binding mech("CORO\\alice", alice_password);
		bad_bindings(finish(ioc, c.sasl_bind(mech)));
	}
	SECTION("required (strict): none is refused")
	{
		auto c = open_tls_to(ioc, strict_ldaps(), strict_ldap(), start_tls);
		ldap::sasl_ntlm mech("CORO\\alice", alice_password, { .channel_binding = ldap::ntlm_channel_binding::none });
		bad_bindings(finish(ioc, c.sasl_bind(mech)));
	}
	SECTION("not required (relaxed): none (no MsvAvChannelBindings) is accepted")
	{
		auto c = open_tls_to(ioc, relaxed_ldaps(), relaxed_ldap(), start_tls);
		ldap::sasl_ntlm mech("CORO\\alice", alice_password, { .channel_binding = ldap::ntlm_channel_binding::none });
		auto who = ntlm_bind(ioc, c, mech);
		if (!who) {
			FAIL(who.error().message());
		}
		CHECK(*who == "u:CORO\\alice");
		CHECK_FALSE(mech.channel_binding_used().has_value());
	}
	// Samba checks the bindings a client sends even with `ldap server
	// require strong auth = no` (only their absence is let through),
	// where Windows' LdapEnforceChannelBinding = 0 checks none.
	SECTION("not required (relaxed): a wrong binding is still refused")
	{
		auto c = open_tls_to(ioc, relaxed_ldaps(), relaxed_ldap(), start_tls);
		ntlm_wrong_binding mech("CORO\\alice", alice_password);
		bad_bindings(finish(ioc, c.sasl_bind(mech)));
	}
	SECTION("not required (relaxed): a correct binding is accepted")
	{
		auto c = open_tls_to(ioc, relaxed_ldaps(), relaxed_ldap(), start_tls);
		ldap::sasl_ntlm mech("CORO\\alice", alice_password);
		auto who = ntlm_bind(ioc, c, mech);
		if (!who) {
			FAIL(who.error().message());
		}
		CHECK(*who == "u:CORO\\alice");
	}
}

TEST_CASE("samba ad: sasl_ntlm without a security layer on plain ldap://", "[samba_ad][ntlm]")
{
	require_samba();
	corosio::io_context ioc;
	SECTION("require_tls (the default): refused before anything is sent")
	{
		auto c = open(ioc, strict_ldap());
		ldap::sasl_ntlm mech("CORO\\alice", alice_password);
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(r.error().diagnostic.empty());
		CHECK(c.is_open());
	}
	SECTION("signing required (strict): strongerAuthRequired")
	{
		auto c = open(ioc, strict_ldap());
		ldap::sasl_ntlm mech("CORO\\alice", alice_password, { .require_tls = false });
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::stronger_auth_required);
		// Windows says "00002028: LdapErr: ... The server requires binds to
		// turn on integrity checking ..."; Samba has no Win32 code here.
		CHECK(std::string(r.error().diagnostic) == "SASL:[GSS-SPNEGO]: Sign or Seal are required.");
	}
	SECTION("signing not required (relaxed): accepted")
	{
		auto c = open(ioc, relaxed_ldap());
		ldap::sasl_ntlm mech("CORO\\alice", alice_password, { .require_tls = false });
		auto who = ntlm_bind(ioc, c, mech);
		if (!who) {
			FAIL(who.error().message());
		}
		CHECK(*who == "u:CORO\\alice");
		CHECK(c.security_layer() == ldap::sasl_protection::none);
	}
}
