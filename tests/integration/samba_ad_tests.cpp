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
#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/ad/filetime.hpp"
#include "jhetz/ldap/ad/guid.hpp"
#include "jhetz/ldap/ad/password.hpp"
#include "jhetz/ldap/ad/sid.hpp"
#include "jhetz/ldap/ad/sync.hpp"
#include "jhetz/ldap/ad/user_account_control.hpp"
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/sasl_ntlm.hpp"
#include "jhetz/ldap/store.hpp"
#include "jhetz/ldap/sync.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/write.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;
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
	auto r = finish(ioc, ldap::ad::reset_password(admin, who, password));
	if (!r) {
		FAIL("reset the password of " << who.to_string() << ": " << r.error().message());
	}
}

}// namespace

// ---------------------------------------------------------------- password changes (unicodePwd)

TEST_CASE("samba ad: ad::change_password and ad::reset_password", "[samba_ad][password]")
{
	require_samba();
	draining_context ioc;
	const bool start_tls = GENERATE(false, true);
	CAPTURE(start_tls);

	SECTION("no RFC 3062: the core's password calls are refused")
	{
		auto c = open_tls(ioc, start_tls);
		auto dse = finish(ioc, c.search(ldap::root_dse({ "supportedExtension" })));
		REQUIRE(dse.has_value());
		REQUIRE(dse->entries.size() == 1);
		const auto *extensions = dse->entries[0].find("supportedExtension");
		CHECK((extensions == nullptr || !std::ranges::contains(*extensions, ldap::password_modify_oid)));
		reset(ioc, pwchange, "Core-Passw0rd");
		auto admin = open_bound(ioc, start_tls, administrator, administrator_password);
		auto r = finish(ioc, ldap::reset_password(admin, pwchange, "Never-Passw0rd"));
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::protocol_error);
		CHECK(try_bind(ioc, pwchange, "Core-Passw0rd").has_value());
	}

	SECTION("reset_password as Administrator")
	{
		reset(ioc, pwchange, "Before-Reset-Passw0rd");
		auto admin = open_bound(ioc, start_tls, administrator, administrator_password);
		auto r = finish(ioc, ldap::ad::reset_password(admin, pwchange, "After-Reset-Passw0rd"));
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
		auto r = finish(ioc, ldap::ad::change_password(user, pwchange, "Old-Passw0rd", "New-Passw0rd"));
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
		auto r = finish(ioc, ldap::ad::change_password(user, pwchange, reset_to, changed_to));
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
		auto r = finish(ioc, ldap::ad::change_password(user, pwchange, "Policy-Passw0rd", "short"));
		REQUIRE_FALSE(r.has_value());
		INFO(r.error().message());
		CHECK(r.error().code == ldap::errc::constraint_violation);
		CHECK_THAT(std::string(r.error().diagnostic), StartsWith("0000052D"));
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("does not meet the password policy"));
		// An administrator's reset is held to the policy too.
		auto admin = open_bound(ioc, start_tls, administrator, administrator_password);
		auto a = finish(ioc, ldap::ad::reset_password(admin, pwchange, "short"));
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
		auto r = finish(ioc, ldap::ad::change_password(user, pwchange, "Wrong-Passw0rd", "Next-Passw0rd"));
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
	draining_context ioc;
	reset(ioc, pwchange, "Plain-Passw0rd");
	auto c = open(ioc, strict_ldap());
	auto r = finish(ioc, ldap::ad::reset_password(c, pwchange, "Never-Passw0rd"));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::tls_required);
	CHECK(r.error().diagnostic.empty());
	auto ch = finish(ioc, ldap::ad::change_password(c, pwchange, "Plain-Passw0rd", "Never-Passw0rd"));
	REQUIRE_FALSE(ch.has_value());
	CHECK(ch.error().code == ldap::client_errc::tls_required);
	CHECK(c.is_open());
	CHECK(try_bind(ioc, pwchange, "Plain-Passw0rd").has_value());
}

TEST_CASE("samba ad: ad passwords through ldap::client and the sync facade", "[samba_ad][password]")
{
	require_samba();
	draining_context ioc;
	SECTION("ldap::client")
	{
		auto u = ldap::url::parse(strict_ldaps());
		REQUIRE(u.has_value());
		ldap::client pool(ioc,
		  { .servers = { *u },
			.connection = samba_tls(),
			.setup = ldap::simple_bind_setup(administrator, administrator_password) });
		auto r = finish(ioc, ldap::ad::reset_password(pool, pwchange, "Pool-Passw0rd"));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "Pool-Passw0rd").has_value());
		pool.close();
		drive(ioc);
	}
	SECTION("sync::connection")
	{
		reset(ioc, pwchange, "Sync-Old-Passw0rd");
		ldap::sync::connection c(samba_tls());
		REQUIRE(c.connect(strict_ldaps()).has_value());
		REQUIRE(c.simple_bind(pwchange, "Sync-Old-Passw0rd").has_value());
		auto r = ldap::ad::change_password(c, pwchange, "Sync-Old-Passw0rd", "Sync-New-Passw0rd");
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "Sync-New-Passw0rd").has_value());
	}
}

TEST_CASE("samba ad: a password change over the NTLM security layer on plain ldap://", "[samba_ad][password][ntlm]")
{
	require_samba();
	draining_context ioc;
	SECTION("integrity and confidentiality: both seal, both accepted")
	{
		// Integrity negotiates signing only, but NTLM over LDAP seals once
		// signing is negotiated: security_layer() reports confidentiality.
		const auto protection = GENERATE(ldap::sasl_protection::integrity, ldap::sasl_protection::confidentiality);
		CAPTURE(protection);
		reset(ioc, pwchange, "Sealed-Old-Passw0rd");
		auto c = open(ioc, strict_ldap());
		ldap::sasl_ntlm mech("CORO\\pwchange", "Sealed-Old-Passw0rd", { .security_layer = protection });
		auto b = finish(ioc, c.sasl_bind(mech));
		if (!b) {
			FAIL(b.error().message());
		}
		REQUIRE(c.security_layer() == ldap::sasl_protection::confidentiality);
		REQUIRE_FALSE(c.is_tls());
		auto r = finish(ioc, ldap::ad::change_password(c, pwchange, "Sealed-Old-Passw0rd", "Sealed-New-Passw0rd"));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "Sealed-New-Passw0rd").has_value());
		auto admin = open(ioc, strict_ldap());
		ldap::sasl_ntlm admin_mech("CORO\\Administrator", administrator_password, { .security_layer = protection });
		REQUIRE(finish(ioc, admin.sasl_bind(admin_mech)).has_value());
		auto reset_r = finish(ioc, ldap::ad::reset_password(admin, pwchange, "Sealed-Reset-Passw0rd"));
		if (!reset_r) {
			FAIL(reset_r.error().message());
		}
		CHECK(try_bind(ioc, pwchange, "Sealed-Reset-Passw0rd").has_value());
	}
	SECTION("an NTLM bind without a layer (relaxed DC): refused before sending")
	{
		reset(ioc, pwchange, "Unsealed-Passw0rd");
		auto c = open(ioc, relaxed_ldap());
		ldap::sasl_ntlm mech("CORO\\Administrator", administrator_password, { .require_tls = false });
		REQUIRE(finish(ioc, c.sasl_bind(mech)).has_value());
		REQUIRE(c.security_layer() == ldap::sasl_protection::none);
		auto r = finish(ioc, ldap::ad::reset_password(c, pwchange, "Never-Passw0rd"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(r.error().diagnostic.empty());
		CHECK(try_bind(ioc, pwchange, "Unsealed-Passw0rd").has_value());
	}
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
	return finish(ioc, ldap::who_am_i(c));
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
	draining_context ioc;
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
	draining_context ioc;
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
	draining_context ioc;
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

// ---------------------------------------------------------------- the NTLM security layer

namespace {

// A one-connection TCP relay to a DC that keeps every byte each side sent,
// for the test to read the protected buffers on the wire.
class recording_relay
{
  public:
	recording_relay(corosio::io_context &ioc, std::uint16_t target)
	  : ioc_(ioc), acc_(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1), client_(ioc), server_(ioc),
		target_(target)
	{
		spawn(ioc_, run(), running_);
	}
	recording_relay(const recording_relay &) = delete;
	auto operator=(const recording_relay &) -> recording_relay & = delete;
	// Driven after shut_down(), so the pumps finish even when a REQUIRE
	// left the test early.
	~recording_relay()
	{
		shut_down();
		drive(ioc_);
	}

	[[nodiscard]] auto url() const -> std::string
	{
		return "ldap://127.0.0.1:" + std::to_string(acc_.local_endpoint().port());
	}
	[[nodiscard]] auto from_client() const -> const std::string & { return from_client_; }
	[[nodiscard]] auto from_server() const -> const std::string & { return from_server_; }
	void shut_down()
	{
		acc_.close();
		client_.close();
		server_.close();
	}

  private:
	auto run() -> capy::task<void>
	{
		if (auto [ec] = co_await acc_.accept(client_); ec) {
			co_return;
		}
		if (auto [ec] = co_await server_.connect(corosio::endpoint(corosio::ipv4_address::loopback(), target_)); ec) {
			client_.close();
			co_return;
		}
		spawn(ioc_, pump(client_, server_, from_client_), up_);
		spawn(ioc_, pump(server_, client_, from_server_), down_);
	}

	static auto pump(corosio::tcp_socket &from, corosio::tcp_socket &to, std::string &record) -> capy::task<void>
	{
		std::array<char, 1 << 16> buf{};
		while (true) {
			auto [ec, n] = co_await from.read_some(capy::mutable_buffer(buf.data(), buf.size()));
			if (ec || n == 0) {
				break;
			}
			record.append(buf.data(), n);
			if (auto [wec, written] = co_await capy::write(to, capy::const_buffer(buf.data(), n)); wec) {
				break;
			}
		}
		from.close();
		to.close();
	}

	corosio::io_context &ioc_;
	corosio::tcp_acceptor acc_;
	corosio::tcp_socket client_;
	corosio::tcp_socket server_;
	std::uint16_t target_;
	std::string from_client_;
	std::string from_server_;
	outcome<void> running_;
	outcome<void> up_;
	outcome<void> down_;
};

auto port_of(const std::string &url) -> std::uint16_t
{
	auto u = ldap::url::parse(url);
	REQUIRE(u.has_value());
	REQUIRE(u->port().has_value());
	return *u->port();
}

// The protected buffers in one direction of a recorded connection: after
// `clear` LDAP messages in clear (the bind's), each four-octet big-endian
// length and the buffer it announces. Fails the test on bytes that do not
// frame that way.
auto sasl_buffers(std::string_view bytes, std::size_t clear) -> std::vector<std::string_view>
{
	const auto octet = [&bytes](std::size_t i) -> std::size_t {
		REQUIRE(i < bytes.size());
		return static_cast<unsigned char>(bytes[i]);
	};
	std::size_t at = 0;
	for (std::size_t m = 0; m < clear; ++m) {
		REQUIRE(octet(at) == 0x30);// LDAPMessage: SEQUENCE
		std::size_t length = octet(at + 1);
		std::size_t header = 2;
		if (length >= 0x80) {
			const std::size_t n = length & 0x7F;
			REQUIRE((n >= 1 && n <= 4));
			length = 0;
			for (std::size_t i = 0; i < n; ++i) {
				length = (length << 8) | octet(at + 2 + i);
			}
			header += n;
		}
		at += header + length;
	}
	std::vector<std::string_view> out;
	while (at < bytes.size()) {
		REQUIRE(bytes.size() - at >= 4);
		const std::size_t length = (octet(at) << 24) | (octet(at + 1) << 16) | (octet(at + 2) << 8) | octet(at + 3);
		REQUIRE(bytes.size() - at - 4 >= length);
		out.push_back(bytes.substr(at + 4, length));
		at += 4 + length;
	}
	return out;
}

// Checks each buffer's NTLMSSP_MESSAGE_SIGNATURE: at least the 16 octets,
// Version 1, then SeqNum counting from 0 (MS-NLMP section 2.2.2.9.2).
void check_signatures(const std::vector<std::string_view> &buffers)
{
	for (std::size_t i = 0; i < buffers.size(); ++i) {
		const auto b = buffers[i];
		INFO("buffer " << i);
		REQUIRE(b.size() >= ldap::detail::ntlm_signature_size);
		CHECK(b.substr(0, 4) == std::string_view("\x01\x00\x00\x00", 4));
		std::uint32_t seq = 0;
		for (std::size_t k = 0; k < 4; ++k) {
			seq |= static_cast<std::uint32_t>(static_cast<unsigned char>(b[12 + k])) << (8 * k);
		}
		CHECK(seq == i);
	}
}

auto longest(const std::vector<std::string_view> &buffers) -> std::size_t
{
	std::size_t n = 0;
	for (const auto b : buffers) {
		n = std::max(n, b.size());
	}
	return n;
}

// The NegotiateFlags of the NTLM NEGOTIATE_MESSAGE in `bytes` (the first
// BindRequest's credentials, sent in clear; MS-NLMP section 2.2.1.1).
auto negotiate_flags(std::string_view bytes) -> std::uint32_t
{
	constexpr std::string_view signature("NTLMSSP\0\x01\0\0\0", 12);
	const auto at = bytes.find(signature);
	REQUIRE(at != std::string_view::npos);
	REQUIRE(bytes.size() - at >= 16);
	std::uint32_t flags = 0;
	for (std::size_t k = 0; k < 4; ++k) {
		flags |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[at + 12 + k])) << (8 * k);
	}
	return flags;
}

const ldap::dn large{ "CN=large,CN=Users,DC=coro,DC=test" };

}// namespace

TEST_CASE("samba ad: the NTLM security layer on plain ldap://, entries over 128 KiB both ways",
  "[samba_ad][ntlm][layer]")
{
	require_samba();
	// Integrity negotiates signing only, but Samba (as Windows) seals over
	// LDAP once signing is negotiated, and so does the client: both are
	// sealed on the wire.
	const auto protection = GENERATE(ldap::sasl_protection::integrity, ldap::sasl_protection::confidentiality);
	CAPTURE(protection);
	draining_context ioc;
	// The strict DC: on plain ldap:// only a signed or sealed bind.
	recording_relay relay(ioc, port_of(strict_ldap()));
	auto c = open(ioc, relay.url());
	ldap::sasl_ntlm mech("CORO\\Administrator", administrator_password, { .security_layer = protection });
	auto who = ntlm_bind(ioc, c, mech);
	if (!who) {
		FAIL(who.error().message());
	}
	CHECK(*who == "u:CORO\\Administrator");
	CHECK(c.security_layer() == ldap::sasl_protection::confidentiality);

	// A jpegPhoto (no rangeUpper in AD's schema) of 300 000 octets, more
	// than two of the client's 128 KiB buffers, with a marker that would
	// show if the PDU crossed the wire in clear.
	const std::string marker = "coro-ldap: a marker never seen on the wire";
	std::string photo(300'000, '\0');
	// Every octet value, in no simple order (a multiplicative hash of the
	// offset).
	for (std::size_t i = 0; i < photo.size(); ++i) {
		photo[i] = static_cast<char>((i * 2'654'435'761U) >> 13);
	}
	std::ranges::copy(marker, photo.begin() + 1000);
	auto m = finish(ioc, c.modify({ .object = large, .changes = { ldap::mod::replace("jpegPhoto", { photo }) } }));
	if (!m) {
		FAIL(m.error().message());
	}
	auto back =
	  finish(ioc, c.search({ .base = large, .scope = ldap::search_scope::base_object, .attributes = { "jpegPhoto" } }));
	if (!back) {
		FAIL(back.error().message());
	}
	REQUIRE(back->entries.size() == 1);
	const auto *values = back->entries[0].find("jpegPhoto");
	REQUIRE(values != nullptr);
	REQUIRE(values->size() == 1);
	CHECK((*values)[0].size() == photo.size());
	// Compares by the first differing offset, not the 300 KB strings.
	const std::string_view got((*values)[0]);
	const auto first_difference = static_cast<std::size_t>(std::ranges::mismatch(got, photo).in1 - got.begin());
	INFO("first differing octet: " << first_difference);
	CHECK(first_difference == photo.size());
	REQUIRE(finish(ioc, c.unbind()).has_value());
	relay.shut_down();
	drive(ioc);

	// Two BindRequests and two BindResponses in clear, then only protected
	// buffers, each a signature then the (sealed) message.
	// Integrity asks for signing only, so the sealing on the wire is the
	// DC's force_wrap_seal (and the client's matching it), not a SEAL the
	// client negotiated.
	const auto flags = negotiate_flags(relay.from_client());
	CHECK((flags & ldap::detail::ntlmssp_negotiate_sign) != 0);
	CHECK(
	  ((flags & ldap::detail::ntlmssp_negotiate_seal) != 0) == (protection == ldap::sasl_protection::confidentiality));
	const auto up = sasl_buffers(relay.from_client(), 2);
	const auto down = sasl_buffers(relay.from_server(), 2);
	check_signatures(up);
	check_signatures(down);
	// The ModifyRequest went in buffers of 128 KiB: Samba put the PDU back
	// together.
	CHECK(longest(up) == std::size_t{ 1 } << 17);
	// Samba cut its SearchResultEntry into buffers of 128 KiB too
	// (gensec_max_input_size's default, the signature included).
	CHECK(longest(down) == std::size_t{ 1 } << 17);
	CHECK_FALSE(relay.from_client().contains(marker));
	CHECK_FALSE(relay.from_server().contains(marker));
}

// ---------------------------------------------------------------- objectSid, objectGUID, userAccountControl

namespace {

struct ad_account
{
	std::string sam_account_name;
	ldap::ad::sid object_sid;
	ldap::ad::guid object_guid;
	ldap::ad::user_account_control user_account_control{};
};

const ldap::dn domain{ "DC=coro,DC=test" };
const ldap::dn alice{ "CN=alice,CN=Users,DC=coro,DC=test" };
const ldap::dn typed_user{ "CN=coro-typed,CN=Users,DC=coro,DC=test" };

}// namespace

template<>
constexpr auto ldap::schema<ad_account> = ldap::describe(ldap::object_class("user"),
  ldap::field<&ad_account::sam_account_name>("sAMAccountName"),
  ldap::field<&ad_account::object_sid>("objectSid", ldap::read_only),
  ldap::field<&ad_account::object_guid>("objectGUID", ldap::read_only),
  ldap::field<&ad_account::user_account_control>("userAccountControl"));

namespace {

auto read_account(corosio::io_context &ioc, ldap::connection &c, const ldap::dn &who) -> ad_account
{
	ldap::store accounts(c, domain, ldap::named_by<&ad_account::sam_account_name>);
	auto r = finish(ioc, accounts.get_at(who));
	if (!r) {
		FAIL("read " << who.to_string() << ": " << r.error().message());
	}
	REQUIRE(r->has_value());
	return std::move(**r);
}

auto domain_sid(corosio::io_context &ioc, ldap::connection &c) -> ldap::ad::sid
{
	auto r = finish(
	  ioc, c.search({ .base = domain, .scope = ldap::search_scope::base_object, .attributes = { "objectSid" } }));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 1);
	const auto *values = r->entries[0].find("objectSid");
	REQUIRE(values != nullptr);
	REQUIRE(values->size() == 1);
	auto s = ldap::ad::sid::from_binary((*values)[0]);
	REQUIRE(s.has_value());
	return *s;
}

// `s` is the domain's SID plus one RID.
auto rid_in(const ldap::ad::sid &s, const ldap::ad::sid &dom) -> std::optional<std::uint32_t>
{
	const auto sub = s.sub_authorities();
	const auto prefix = dom.sub_authorities();
	if (s.identifier_authority() != dom.identifier_authority() || sub.size() != prefix.size() + 1
		|| !std::ranges::equal(sub.first(prefix.size()), prefix)) {
		return std::nullopt;
	}
	return sub.back();
}

}// namespace

TEST_CASE("samba ad: objectSid, objectGUID and userAccountControl as ad types", "[samba_ad][types]")
{
	require_samba();
	using enum ldap::ad::user_account_control;
	draining_context ioc;
	auto c = open_bound(ioc, false, administrator, administrator_password);

	const ldap::ad::sid dom = domain_sid(ioc, c);
	INFO("domain " << dom.to_string());
	CHECK_THAT(dom.to_string(), StartsWith("S-1-5-21-"));
	REQUIRE(dom.sub_authorities().size() == 4);

	SECTION("the schema: Octet String and INTEGER")
	{
		auto s = finish(ioc, ldap::load_schema(c));
		REQUIRE(s.has_value());
		const auto report = ldap::validate<ad_account>(*s);
		INFO(report.to_string());
		CHECK(report.ok());
	}

	SECTION("Administrator and alice")
	{
		const ad_account admin = read_account(ioc, c, administrator);
		CHECK(admin.sam_account_name == "Administrator");
		CHECK(rid_in(admin.object_sid, dom) == 500U);
		CHECK(has(admin.user_account_control, normal_account));
		CHECK_FALSE(has(admin.user_account_control, account_disable));

		const ad_account a = read_account(ioc, c, alice);
		CHECK(a.sam_account_name == "alice");
		const auto rid = rid_in(a.object_sid, dom);
		REQUIRE(rid.has_value());
		CHECK(*rid >= 1000U);
		CHECK(a.user_account_control == normal_account);
		CHECK(a.object_guid != ldap::ad::guid{});
		CHECK(a.object_guid != admin.object_guid);

		// The SID's and the GUID's binary forms, in typed filters.
		ldap::store accounts(c, domain, ldap::named_by<&ad_account::sam_account_name>);
		auto by_sid = finish(ioc,
		  accounts.search(
			ldap::filters::field<&ad_account::object_sid>() == a.object_sid, ldap::search_scope::whole_subtree));
		REQUIRE(by_sid.has_value());
		REQUIRE(by_sid->entries.size() == 1);
		CHECK(by_sid->entries[0].value.sam_account_name == "alice");
		auto by_guid = finish(ioc,
		  accounts.search(
			ldap::filters::field<&ad_account::object_guid>() == a.object_guid, ldap::search_scope::whole_subtree));
		REQUIRE(by_guid.has_value());
		REQUIRE(by_guid->entries.size() == 1);
		CHECK(by_guid->entries[0].value.object_sid == a.object_sid);
	}

	SECTION("a new user: SID from the domain, userAccountControl written back")
	{
		(void)finish(ioc, c.del({ .entry = typed_user }));
		auto added = finish(ioc,
		  c.add({ .entry = typed_user,
			.attributes = { { "objectClass", { "user" } }, { "sAMAccountName", { "coro-typed" } } } }));
		if (!added) {
			FAIL(added.error().message());
		}
		const ad_account fresh = read_account(ioc, c, typed_user);
		CHECK(rid_in(fresh.object_sid, dom).has_value());
		// AD creates a user without a password disabled.
		CHECK(has(fresh.user_account_control, normal_account | account_disable));

		ldap::store accounts(c, domain, ldap::named_by<&ad_account::sam_account_name>);
		auto m = finish(ioc,
		  accounts.modify_at(typed_user,
			{ ldap::replace<&ad_account::user_account_control>(fresh.user_account_control | dont_expire_passwd) }));
		if (!m) {
			FAIL(m.error().message());
		}
		const ad_account changed = read_account(ioc, c, typed_user);
		CHECK(changed.user_account_control == (fresh.user_account_control | dont_expire_passwd));
		CHECK(changed.object_sid == fresh.object_sid);
		CHECK(changed.object_guid == fresh.object_guid);
		CHECK(finish(ioc, c.del({ .entry = typed_user })).has_value());
	}
}

// ---------------------------------------------------------------- Show Deleted

TEST_CASE("samba ad: ad::show_deleted finds a deleted user's tombstone", "[samba_ad][show_deleted]")
{
	require_samba();
	draining_context ioc;
	auto c = open_bound(ioc, false, administrator, administrator_password);
	const ldap::dn doomed{ "CN=coro-deleted,CN=Users,DC=coro,DC=test" };
	(void)finish(ioc, c.del({ .entry = doomed }));
	auto added = finish(ioc,
	  c.add({ .entry = doomed,
		.attributes = { { "objectClass", { "user" } }, { "sAMAccountName", { "coro-deleted" } } } }));
	if (!added) {
		FAIL(added.error().message());
	}
	const ldap::ad::guid id = read_account(ioc, c, doomed).object_guid;
	REQUIRE(finish(ioc, c.del({ .entry = doomed })).has_value());

	const auto by_guid = ldap::filters::field<&ad_account::object_guid>() == id;
	auto hidden = finish(ioc, c.search({ .base = domain, .filter = by_guid, .attributes = { "isDeleted" } }));
	REQUIRE(hidden.has_value());
	CHECK(hidden->entries.empty());

	auto shown = finish(ioc,
	  c.search({ .base = domain,
		.filter = by_guid,
		.attributes = { "isDeleted", "objectGUID" },
		.controls = { ldap::ad::show_deleted{} } }));
	if (!shown) {
		FAIL(shown.error().message());
	}
	REQUIRE(shown->entries.size() == 1);
	const ldap::entry &tombstone = shown->entries[0];
	INFO(tombstone.dn);
	CHECK_THAT(std::string(tombstone.dn), ContainsSubstring(",CN=Deleted Objects,DC=coro,DC=test"));
	const auto *deleted = tombstone.find("isDeleted");
	REQUIRE(deleted != nullptr);
	CHECK(*deleted == std::pmr::vector<std::pmr::string>{ "TRUE" });
	const auto *guid_values = tombstone.find("objectGUID");
	REQUIRE(guid_values != nullptr);
	REQUIRE(guid_values->size() == 1);
	CHECK(ldap::ad::guid::from_binary((*guid_values)[0]) == id);
}
