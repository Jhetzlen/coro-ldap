// Integration tests against a real OpenLDAP slapd, started by
// run_slapd.sh (which sets the JHETZ_LDAP_IT_* variables):
//
//   tests/integration/run_slapd.sh ctest --test-dir build -L integration --output-on-failure
//
// Without those variables every test is skipped (ctest reports the run as
// skipped). The data is make_fixture.py's.
#include "../net/net_test_support.hpp"
#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/extended_operations.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/sasl_scram.hpp"
#include "jhetz/ldap/store.hpp"
#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/sync_extended_operations.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/work_guard.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <format>
#include <fstream>
#include <iterator>
#include <latch>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;

namespace {

auto env(const char *name) -> std::string
{
	// NOLINTNEXTLINE(concurrency-mt-unsafe): nothing in this binary calls setenv while tests run
	const char *v = std::getenv(name);
	return v == nullptr ? std::string() : std::string(v);
}

// The contents of the file at `path`; fails the test when it cannot be read.
auto read_text(const std::string &path) -> std::string
{
	std::ifstream in(path, std::ios::binary);
	if (!in) {
		FAIL("cannot read " << path);
	}
	return { std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
}

// Set by run_slapd.sh; each test starts with
// `if (!have_slapd()) SKIP(...)`, so the skip is reported at the test.
auto have_slapd() -> bool { return !env("JHETZ_LDAP_IT_LDAP").empty(); }

const ldap::dn admin{ "cn=admin,dc=example,dc=org" };
const ldap::dn people{ "ou=people,dc=example,dc=org" };

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

auto open_admin(corosio::io_context &ioc) -> ldap::connection
{
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	auto b = finish(ioc, c.simple_bind(admin, "secret"));
	if (!b) {
		FAIL("bind: " << b.error().message());
	}
	return c;
}

// SCRAM-SHA-256 that gives up on the server's first message, as on one it
// refuses: the client fails a step while slapd waits for the next one.
class scram_giving_up final : public ldap::sasl_mechanism
{
  public:
	[[nodiscard]] auto name() const noexcept -> std::string_view override { return scram.name(); }
	auto start() -> ldap::result<std::optional<std::string>> override { return scram.start(); }
	auto step(std::optional<std::string_view>) -> ldap::result<std::optional<std::string>> override
	{
		return ldap::fail(ldap::client_errc::unexpected_response, "giving up");
	}
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<ldap::channel_binding_type> override
	{
		return scram.channel_binding_used();
	}

  private:
	ldap::sasl_scram_sha256 scram{ "user007", "pw-user007" };
};

// slapd refuses anonymous binds (olcDisallows: bind_anon, set through
// cn=config, which run_slapd.sh makes writable) while this lives. The
// setting is global: the tests run one at a time, and it is restored even
// when the test fails. A failed restore fails the test.
class anonymous_binds_disallowed
{
  public:
	explicit anonymous_binds_disallowed(corosio::io_context &ioc)
	  : ioc_(&ioc), config_(open(ioc, env("JHETZ_LDAP_IT_LDAP")))
	{
		auto b = finish(*ioc_, config_.simple_bind(config_dn, "secret"));
		if (!b) {
			FAIL("bind as cn=config: " << b.error().message());
		}
		auto m = finish(*ioc_,
		  config_.modify({ .object = config_dn, .changes = { ldap::mod::add("olcDisallows", { "bind_anon" }) } }));
		if (!m) {
			FAIL("disallow bind_anon: " << m.error().message());
		}
	}

	anonymous_binds_disallowed(const anonymous_binds_disallowed &) = delete;
	auto operator=(const anonymous_binds_disallowed &) -> anonymous_binds_disallowed & = delete;

	// The failure is reported once, after the attempt. FAIL_CHECK throws
	// when Catch2 aborts the run (-a, -x): that only ends the run, as asked,
	// so it is caught rather than left to escape the destructor.
	~anonymous_binds_disallowed()
	{
		bool restored = false;
		std::string why;
		try {
			auto m = finish(*ioc_,
			  config_.modify(
				{ .object = config_dn, .changes = { ldap::mod::remove("olcDisallows", { "bind_anon" }) } }));
			restored = m.has_value();
			if (!m) {
				why = ": " + std::string(m.error().message());
			}
		} catch (...) {// NOLINT(bugprone-empty-catch): reported below as restored stays false
		}
		if (restored) {
			return;
		}
		try {
			FAIL_CHECK("could not allow bind_anon again, later tests run with it disallowed" << why);
		} catch (...) {// NOLINT(bugprone-empty-catch): Catch2 aborting the run, see above
		}
	}

  private:
	inline static const ldap::dn config_dn{ "cn=config" };
	corosio::io_context *ioc_;// non-null
	ldap::connection config_;
};

// slapd serves `cert_file` and `key_file` (olcTLSCertificateFile,
// olcTLSCertificateKeyFile through cn=config: slapd builds a new TLS
// context for later connections) while this lives, then run_slapd.sh's
// certificate again. A failed restore fails the test.
class server_certificate_swapped
{
  public:
	server_certificate_swapped(corosio::io_context &ioc, const std::string &cert_file, const std::string &key_file)
	  : ioc_(&ioc), config_(open(ioc, env("JHETZ_LDAP_IT_LDAP")))
	{
		auto b = finish(*ioc_, config_.simple_bind(config_dn, "secret"));
		if (!b) {
			FAIL("bind as cn=config: " << b.error().message());
		}
		if (auto m = set(cert_file, key_file); !m) {
			FAIL("switch the server certificate: " << m.error().message());
		}
	}

	server_certificate_swapped(const server_certificate_swapped &) = delete;
	auto operator=(const server_certificate_swapped &) -> server_certificate_swapped & = delete;

	// As ~anonymous_binds_disallowed.
	~server_certificate_swapped()
	{
		bool restored = false;
		std::string why;
		try {
			auto m = set(env("JHETZ_LDAP_IT_SERVER_CERT"), env("JHETZ_LDAP_IT_SERVER_KEY"));
			restored = m.has_value();
			if (!m) {
				why = ": " + std::string(m.error().message());
			}
		} catch (...) {// NOLINT(bugprone-empty-catch): reported below as restored stays false
		}
		if (restored) {
			return;
		}
		try {
			FAIL_CHECK("could not restore the server certificate, later tests run with another one" << why);
		} catch (...) {// NOLINT(bugprone-empty-catch): Catch2 aborting the run, see above
		}
	}

  private:
	auto set(const std::string &cert_file, const std::string &key_file) -> ldap::result<ldap::response>
	{
		return finish(*ioc_,
		  config_.modify({ .object = config_dn,
			.changes = { ldap::mod::replace("olcTLSCertificateFile", { cert_file }),
			  ldap::mod::replace("olcTLSCertificateKeyFile", { key_file }) } }));
	}

	inline static const ldap::dn config_dn{ "cn=config" };
	corosio::io_context *ioc_;// non-null
	ldap::connection config_;
};

// A unique RDN value per test run, so runs against the same server do not collide.
auto unique(std::string_view stem) -> std::string
{
	static int counter = 0;
	return std::string(stem) + "-" + std::to_string(process_id()) + "-" + std::to_string(counter++);
}

}// namespace

// ---------------------------------------------------------------- transports and binds

TEST_CASE("integration: every transport", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	SECTION("ldap://")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		CHECK_FALSE(c.is_tls());
		CHECK(finish(ioc, c.simple_bind(admin, "secret")).has_value());
		CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:cn=admin,dc=example,dc=org");
	}
	SECTION("ldaps://")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPS"));
		CHECK(c.is_tls());
		CHECK(finish(ioc, c.simple_bind(admin, "secret")).has_value());
	}
	SECTION("StartTLS")
	{
		auto u = env("JHETZ_LDAP_IT_LDAP");
		u.replace(u.find("127.0.0.1"), 9, "localhost");
		auto c = open(ioc, u, trusting({ .start_tls = true }));
		CHECK(c.is_tls());
		CHECK(finish(ioc, c.simple_bind(admin, "secret")).has_value());
	}
	SECTION("ldapi://")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPI"));
		CHECK(finish(ioc, ldap::who_am_i(c)) == "");// anonymous
	}
}

TEST_CASE("integration: bind success and failure", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	auto bad = finish(ioc, c.simple_bind(admin, "wrong"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::errc::invalid_credentials);
	CHECK(finish(ioc, c.simple_bind(ldap::dn{ "uid=user007,ou=people,dc=example,dc=org" }, "pw-user007")).has_value());
	CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:uid=user007,ou=people,dc=example,dc=org");
	CHECK(finish(ioc, c.unbind()).has_value());
}

TEST_CASE("integration: SASL EXTERNAL", "[integration][sasl]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	SECTION("over ldapi:// (peer credentials)")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPI"));
		ldap::sasl_external mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE(r.has_value());
		CHECK_THAT(finish(ioc, ldap::who_am_i(c)).value(), ContainsSubstring("cn=peercred,cn=external,cn=auth"));
	}
	SECTION("with a TLS client certificate")
	{
		ldap::connection_options o = trusting();
		o.tls.cert_file = env("JHETZ_LDAP_IT_CLIENT_CERT");
		o.tls.key_file = env("JHETZ_LDAP_IT_CLIENT_KEY");
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPS"), o);
		ldap::sasl_external mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE(r.has_value());
		CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:cn=client,dc=example,dc=org");
	}
}

TEST_CASE("integration: SASL SCRAM-SHA-256", "[integration][sasl][scram]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	// slapd offers SCRAM-SHA-256 only with cyrus-sasl's scram plugin installed.
	auto dse = finish(ioc, c.search(ldap::root_dse({ "supportedSASLMechanisms" })));
	REQUIRE(dse.has_value());
	REQUIRE(dse->entries.size() == 1);
	const auto *mechs = dse->entries[0].find("supportedSASLMechanisms");
	if (mechs == nullptr || std::ranges::find(*mechs, "SCRAM-SHA-256") == mechs->end()) {
		SKIP("slapd does not offer SCRAM-SHA-256 (cyrus-sasl scram plugin not installed)");
	}

	SECTION("the right password")
	{
		ldap::sasl_scram_sha256 mech("user007", "pw-user007");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE(r.has_value());
		CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:uid=user007,ou=people,dc=example,dc=org");
		// The same object binds again (fresh nonce).
		REQUIRE(finish(ioc, c.sasl_bind(mech)).has_value());
	}
	SECTION("a non-ASCII username and password, SASLprep'ed")
	{
		// Stored: uid "jörg", password "pässwörd 日本 €" (already in
		// SASLprep form). Given: "jo" U+0308 "rg" (decomposed) and the
		// password with a NO-BREAK SPACE and an IDEOGRAPHIC SPACE, which
		// SASLprep turns into the stored forms.
		ldap::sasl_scram_sha256 mech(
		  "jo\xCC\x88rg", "p\xC3\xA4ssw\xC3\xB6rd\xC2\xA0\xE6\x97\xA5\xE6\x9C\xAC\xE3\x80\x80\xE2\x82\xAC");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE(r.has_value());
		CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org");
	}
	SECTION("a non-ASCII password that is wrong")
	{
		ldap::sasl_scram_sha256 mech("j\xC3\xB6rg", "p\xC3\xA4ssw\xC3\xB6rd");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::auth_failed);
	}
	SECTION("a wrong password")
	{
		ldap::sasl_scram_sha256 mech("user007", "wrong");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK(c.is_open());
		CHECK(finish(ioc, ldap::who_am_i(c)) == "");
	}
	SECTION("a step the client fails mid-exchange")
	{
		// RFC 4511 section 4.2.1: the exchange is aborted, so slapd accepts
		// other operations again.
		scram_giving_up mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind SCRAM-SHA-256: giving up");
		REQUIRE(c.is_open());
		auto again = finish(ioc, c.search(ldap::root_dse({ "namingContexts" })));
		REQUIRE(again.has_value());
		CHECK(again->entries.size() == 1);
		CHECK(finish(ioc, ldap::who_am_i(c)) == "");
	}
	SECTION("a step the client fails, and a server that refuses the abort")
	{
		// slapd ends the exchange before it refuses the anonymous bind that
		// aborts it (inappropriateAuthentication): the connection stays
		// open and anonymous, and a bind then succeeds.
		// bind_anon refuses only anonymous binds, not anonymous operations:
		// the search succeeds only if the exchange ended (a server still in
		// it would answer operationsError).
		const anonymous_binds_disallowed disallowed(ioc);
		scram_giving_up mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind SCRAM-SHA-256: giving up");
		REQUIRE(c.is_open());
		auto again = finish(ioc, c.search(ldap::root_dse({ "namingContexts" })));
		REQUIRE(again.has_value());
		CHECK(again->entries.size() == 1);
		CHECK(finish(ioc, ldap::who_am_i(c)) == "");
		// The abort was refused: so is the same bind, made directly.
		auto anonymous = finish(ioc, c.simple_bind({}, ""));
		REQUIRE_FALSE(anonymous.has_value());
		CHECK(anonymous.error().code == ldap::errc::inappropriate_authentication);
		REQUIRE(c.is_open());
		REQUIRE(
		  finish(ioc, c.simple_bind(ldap::dn{ "uid=user007,ou=people,dc=example,dc=org" }, "pw-user007")).has_value());
		CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:uid=user007,ou=people,dc=example,dc=org");
	}
}

// ---------------------------------------------------------------- search

TEST_CASE("integration: SASL SCRAM-SHA-256-PLUS (channel binding)", "[integration][sasl][scram][channel_binding]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	// run_slapd.sh sets "sasl-cbinding tls-endpoint": slapd then offers
	// SCRAM-SHA-256-PLUS over TLS, with tls-server-end-point in OpenLDAP's
	// own form ("p=ldap", data "tls-server-end-point:<hash>"), not RFC
	// 5802's (scram_channel_binding_form::openldap).
	const bool over_start_tls = GENERATE(false, true);
	ldap::connection_options o = trusting();
	o.start_tls = over_start_tls;
	auto c = open(ioc, env(over_start_tls ? "JHETZ_LDAP_IT_LDAP" : "JHETZ_LDAP_IT_LDAPS"), o);
	REQUIRE(c.is_tls());
	CHECK_FALSE(c.peer_certificate().empty());
	auto dse = finish(ioc, c.search(ldap::root_dse({ "supportedSASLMechanisms" })));
	REQUIRE(dse.has_value());
	REQUIRE(dse->entries.size() == 1);
	const auto *mechs = dse->entries[0].find("supportedSASLMechanisms");
	if (mechs == nullptr || std::ranges::find(*mechs, "SCRAM-SHA-256-PLUS") == mechs->end()) {
		SKIP("slapd does not offer SCRAM-SHA-256-PLUS (no scram plugin, or no sasl-cbinding)");
	}
	CHECK(ldap::scram_channel_binding_for(*mechs) == ldap::scram_channel_binding::plus);
	// tls-server-end-point is implied, whatever the TLS version.
	const ldap::sasl_scram_options plus{
		.channel_binding = ldap::scram_channel_binding::plus,
		.binding_form = ldap::scram_channel_binding_form::openldap,
	};

	SECTION("tls-server-end-point binds")
	{
		ldap::sasl_scram_sha256 mech("user007", "pw-user007", plus);
		CHECK(mech.name() == "SCRAM-SHA-256-PLUS");
		auto r = finish(ioc, c.sasl_bind(mech));
		if (!r) {
			FAIL(r.error().message());
		}
		CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:uid=user007,ou=people,dc=example,dc=org");
	}
	SECTION("the RFC 5802 form is refused by slapd")
	{
		ldap::sasl_scram_options rfc = plus;
		rfc.binding_type = ldap::channel_binding_type::tls_server_end_point;
		rfc.binding_form = ldap::scram_channel_binding_form::rfc5802;
		ldap::sasl_scram_sha256 mech("user007", "pw-user007", rfc);
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK_THAT(std::string(r.error().message()), ContainsSubstring("Unsupported channel bindings type"));
		CHECK(c.is_open());
	}
	SECTION("a wrong password")
	{
		ldap::sasl_scram_sha256 mech("user007", "wrong", plus);
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::auth_failed);
	}
	SECTION("y,, to a server that supports -PLUS is refused (RFC 5802 section 6)")
	{
		// What a client that saw a list stripped of -PLUS by a man in the middle sends.
		ldap::sasl_scram_sha256 mech("user007",
		  "pw-user007",
		  ldap::sasl_scram_options{ .channel_binding = ldap::scram_channel_binding::not_offered });
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK(c.is_open());
	}
	SECTION("plain SCRAM-SHA-256 (n,,) still binds over TLS")
	{
		ldap::sasl_scram_sha256 mech("user007", "pw-user007");
		REQUIRE(finish(ioc, c.sasl_bind(mech)).has_value());
	}
}

TEST_CASE("integration: SCRAM-SHA-256-PLUS with an Ed25519 server certificate",
  "[integration][sasl][scram][channel_binding]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	// RFC 5929 has no tls-server-end-point for Ed25519; OpenLDAP (and so
	// scram_channel_binding_form::openldap) hashes it with SHA-256.
	const server_certificate_swapped swapped(
	  ioc, env("JHETZ_LDAP_IT_SERVER_ED25519_CERT"), env("JHETZ_LDAP_IT_SERVER_ED25519_KEY"));
	const bool over_start_tls = GENERATE(false, true);
	ldap::connection_options o = trusting();
	o.start_tls = over_start_tls;
	auto c = open(ioc, env(over_start_tls ? "JHETZ_LDAP_IT_LDAP" : "JHETZ_LDAP_IT_LDAPS"), o);
	REQUIRE(c.is_tls());
	const auto der = c.peer_certificate();
	REQUIRE(std::vector<std::byte>(der.begin(), der.end())
			== certificate_der(read_text(env("JHETZ_LDAP_IT_SERVER_ED25519_CERT"))));
	CHECK(c.channel_bindings().tls_server_end_point.empty());
	auto dse = finish(ioc, c.search(ldap::root_dse({ "supportedSASLMechanisms" })));
	REQUIRE(dse.has_value());
	REQUIRE(dse->entries.size() == 1);
	const auto *mechs = dse->entries[0].find("supportedSASLMechanisms");
	if (mechs == nullptr || std::ranges::find(*mechs, "SCRAM-SHA-256-PLUS") == mechs->end()) {
		SKIP("slapd does not offer SCRAM-SHA-256-PLUS (no scram plugin, or no sasl-cbinding)");
	}
	ldap::sasl_scram_sha256 mech("user007",
	  "pw-user007",
	  { .channel_binding = ldap::scram_channel_binding::plus,
		.binding_form = ldap::scram_channel_binding_form::openldap });
	auto r = finish(ioc, c.sasl_bind(mech));
	if (!r) {
		FAIL(r.error().message());
	}
	CHECK(finish(ioc, ldap::who_am_i(c)) == "dn:uid=user007,ou=people,dc=example,dc=org");
}

TEST_CASE("integration: plain, streaming and paged searches", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	const ldap::search_params all_users{ .base = people,
		.filter = ldap::filters::attr("objectClass") == "posixAccount",
		.attributes = { "uid", "uidNumber" } };

	auto plain = finish(ioc, c.search(all_users));
	REQUIRE(plain.has_value());
	CHECK(plain->entries.size() == 250);

	auto s = finish(ioc, c.search_stream(all_users));
	REQUIRE(s.has_value());
	std::size_t streamed = 0;
	while (true) {
		auto e = finish(ioc, s->next());
		REQUIRE(e.has_value());
		if (!*e) {
			break;
		}
		++streamed;
	}
	CHECK(streamed == 250);

	auto p = finish(ioc, ldap::search_paged(c, all_users, 40));
	REQUIRE(p.has_value());
	std::size_t paged = 0;
	while (true) {
		auto e = finish(ioc, p->next());
		REQUIRE(e.has_value());
		if (!*e) {
			break;
		}
		++paged;
	}
	CHECK(paged == 250);
	CHECK(p->pages() == 7);

	// The server's size limit (1000) is not hit, a client one is.
	auto limited = finish(ioc, c.search({ .base = people, .size_limit = 5 }));
	REQUIRE(limited.has_value());
	CHECK(limited->result_code == std::to_underlying(ldap::errc::size_limit_exceeded));
	CHECK_FALSE(limited->is_success());
	CHECK(limited->entries.size() == 5);
}

namespace {

// One page of `params` by hand (a search with the paged control): its
// entry count and the cookie the server returned.
struct manual_page
{
	std::size_t entries = 0;
	std::string cookie{};
};

auto page_by_hand(corosio::io_context &ioc, ldap::connection &c, ldap::search_params params, ldap::paged control)
  -> ldap::result<manual_page>
{
	params.controls = { std::move(control) };
	auto s = finish(ioc, c.search_stream(std::move(params)));
	if (!s) {
		return std::unexpected(std::move(s.error()));
	}
	manual_page out;
	while (true) {
		auto e = finish(ioc, s->next());
		if (!e) {
			return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			break;
		}
		++out.entries;
	}
	for (const auto &ctl : s->controls()) {
		if (ctl.type == ldap::paged_results_oid) {
			out.cookie = std::string(ldap::decode_paged_results(ctl)->cookie);
		}
	}
	return out;
}

}// namespace

TEST_CASE("integration: a paged search stopped between pages sends a release", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto u = env("JHETZ_LDAP_IT_LDAP");
	u.replace(u.find("127.0.0.1"), 9, "localhost");// the certificate's name, for StartTLS
	auto c = open(ioc, u);
	const ldap::search_params all_users{
		.base = people, .filter = ldap::filters::attr("objectClass") == "posixAccount", .attributes = { "uid" }
	};

	// slapd answers a release (RFC 2696 section 3: page size 0 and the last
	// cookie) with success, no entries and no cookie. Its paging state is
	// only the last entry sent, so the cookie is not refused afterwards.
	auto first = page_by_hand(ioc, c, all_users, { .page_size = 40 });
	REQUIRE(first.has_value());
	CHECK(first->entries == 40);
	REQUIRE_FALSE(first->cookie.empty());
	auto release = page_by_hand(ioc, c, all_users, { .page_size = 0, .cookie = first->cookie });
	REQUIRE(release.has_value());
	CHECK(release->entries == 0);
	CHECK(release->cookie.empty());

	// The paged_search sends that release when destroyed between pages; its
	// answer is read and dropped without harm. StartTLS waits for it (RFC
	// 4513 section 3.1.1; slapd would refuse a StartTLS sent before).
	{
		auto p = finish(ioc, ldap::search_paged(c, all_users, 40));
		REQUIRE(p.has_value());
		for (int i = 0; i < 40; ++i) {
			auto e = finish(ioc, p->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
		}
		drive_until(ioc, [&c] { return c.outstanding() == 0; });
		CHECK(p->pages() == 1);
		run_on(ioc, c.executor(), [&p] { *p = ldap::paged_search{}; });
	}
	CHECK(c.outstanding() == 1);// the release
	REQUIRE(finish(ioc, c.start_tls(trusting().tls)).has_value());
	CHECK(c.outstanding() == 0);
	CHECK(c.is_tls());
	auto all = finish(ioc, c.search(all_users));
	REQUIRE(all.has_value());
	CHECK(all->entries.size() == 250);
}

TEST_CASE("integration: large and binary values", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPS"));
	auto big = finish(ioc,
	  c.search({ .base = ldap::dn{ "cn=big,ou=groups,dc=example,dc=org" }, .scope = ldap::search_scope::base_object }));
	REQUIRE(big.has_value());
	REQUIRE(big->entries.size() == 1);
	CHECK(big->entries[0].find("member")->size() == 2000);

	auto photo = run(ioc,
	  c.search({ .base = ldap::dn{ "uid=photo,ou=people,dc=example,dc=org" },
		.scope = ldap::search_scope::base_object,
		.attributes = { "jpegPhoto" } }));
	REQUIRE(photo.has_value());
	const auto &bytes = photo->entries[0].find("jpegPhoto")->front();
	REQUIRE(bytes.size() == 10000);
	bool same = true;
	for (std::size_t i = 0; i < bytes.size(); ++i) {
		same = same && static_cast<unsigned char>(bytes[i]) == i % 251;
	}
	CHECK(same);
}

namespace {

struct person
{
	std::string uid;
	std::vector<std::string> cn;
	std::optional<std::string> mail;
	std::int64_t uid_number = 0;
	std::chrono::sys_seconds created{};
};

}// namespace

template<>
constexpr auto ldap::schema<person> = ldap::describe(ldap::object_class("inetOrgPerson", "posixAccount"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::cn>("cn"),
  ldap::field<&person::mail>("mail"),
  ldap::field<&person::uid_number>("uidNumber"),
  ldap::field<&person::created>("createTimestamp", ldap::read_only));

TEST_CASE("integration: typed search with the server's schema", "[integration][mapping]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"), trusting());
	auto s = finish(ioc, ldap::load_schema(c));
	REQUIRE(s.has_value());
	CHECK(s->attribute_count() > 100);
	CHECK(s->skipped() == 0);// every SYNTAX a numeric OID (RFC 4512 noidlen)
	const auto report = ldap::validate<person>(*s);
	INFO(report.to_string());
	CHECK(report.ok());

	ldap::store accounts(c, people, ldap::named_by<&person::uid>, { .schema_check = ldap::schema_check::on_first_use });
	auto r = finish(ioc, accounts.search(ldap::filters::field<&person::uid_number>() >= 10245));
	REQUIRE(r.has_value());
	REQUIRE(r->entries.size() == 5);
	CHECK(r->entries[0].value.mail.has_value());
	CHECK(r->entries[0].value.created.time_since_epoch().count() > 0);
}

// ---------------------------------------------------------------- writes

TEST_CASE("integration: add, modify, compare, rename and delete", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("it");
	const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");

	const ldap::add_params add{ .entry = entry,
		.attributes = { { "objectClass", { "inetOrgPerson", "posixAccount" } },
		  { "uid", { name } },
		  { "cn", { "Integration" } },
		  { "sn", { "Test" } },
		  { "uidNumber", { "500" } },
		  { "gidNumber", { "100" } },
		  { "homeDirectory", { "/tmp" } } } };
	REQUIRE(finish(ioc, c.add(add)).has_value());
	auto again = finish(ioc, c.add(add));// the server checks the schema first: send a valid entry
	REQUIRE_FALSE(again.has_value());
	CHECK(again.error().code == ldap::cond::already_exists);

	REQUIRE(run(ioc,
	  c.modify({ .object = entry,
		.changes = { ldap::mod::add("mail", { "a@example.org", "b@example.org" }),
		  ldap::mod::remove("mail", { "a@example.org" }),
		  ldap::mod::replace("cn", { "Renamed Integration" }),
		  ldap::mod::increment("uidNumber", "5") } }))
		.has_value());
	CHECK(finish(ioc, c.compare({ .entry = entry, .attribute = "mail", .value = "b@example.org" })) == true);
	CHECK(finish(ioc, c.compare({ .entry = entry, .attribute = "mail", .value = "a@example.org" })) == false);
	CHECK(finish(ioc, c.compare({ .entry = entry, .attribute = "uidNumber", .value = "505" })) == true);

	const ldap::dn renamed = *ldap::dn::parse("uid=" + name + "-r,ou=people,dc=example,dc=org");
	REQUIRE(finish(ioc, c.modify_dn({ .entry = entry, .new_rdn = renamed.rdns().front() })).has_value());
	auto gone = finish(ioc, c.search({ .base = entry, .scope = ldap::search_scope::base_object }));
	REQUIRE_FALSE(gone.has_value());
	CHECK(gone.error().code == ldap::cond::not_found);

	REQUIRE(finish(ioc, c.del({ .entry = renamed })).has_value());
	auto deleted = finish(ioc, c.del({ .entry = renamed }));
	REQUIRE_FALSE(deleted.has_value());
	CHECK(deleted.error().code == ldap::errc::no_such_object);
}

TEST_CASE("integration: modify DN to another OU and back, then rename", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("mv");
	const ldap::dn groups{ "ou=groups,dc=example,dc=org" };
	const ldap::dn entry = people.child(*ldap::rdn::parse("uid=" + name));
	const ldap::dn moved = groups.child(entry.rdns().front());
	REQUIRE(finish(ioc,
	  c.add({ .entry = entry,
		.attributes = { { "objectClass", { "inetOrgPerson" } },
		  { "uid", { name } },
		  { "cn", { "Mover" } },
		  { "sn", { "Déménageur" } } } }))
		.has_value());
	const auto exists = [&](const ldap::dn &d) {
		return finish(ioc, c.search({ .base = d, .scope = ldap::search_scope::base_object })).has_value();
	};

	REQUIRE(finish(ioc, c.modify_dn({ .entry = entry, .new_rdn = entry.rdns().front(), .new_superior = groups }))
		.has_value());
	CHECK_FALSE(exists(entry));
	CHECK(exists(moved));
	REQUIRE(finish(ioc, c.modify_dn({ .entry = moved, .new_rdn = moved.rdns().front(), .new_superior = people }))
		.has_value());
	CHECK(exists(entry));
	CHECK_FALSE(exists(moved));

	// Keep the old RDN value: the entry then has both uids.
	const ldap::rdn new_rdn = *ldap::rdn::parse("uid=" + name + "-r");
	const ldap::dn renamed = people.child(new_rdn);
	REQUIRE(finish(ioc, c.modify_dn({ .entry = entry, .new_rdn = new_rdn, .delete_old_rdn = false })).has_value());
	CHECK_FALSE(exists(entry));
	CHECK(finish(ioc, c.compare({ .entry = renamed, .attribute = "uid", .value = name })) == true);
	CHECK(finish(ioc, c.compare({ .entry = renamed, .attribute = "uid", .value = name + "-r" })) == true);
	auto taken = finish(ioc, c.modify_dn({ .entry = renamed, .new_rdn = ldap::rdn{ "uid=user001" } }));// a fixture user
	REQUIRE_FALSE(taken.has_value());
	CHECK(taken.error().code == ldap::errc::entry_already_exists);
	CHECK(std::string_view(taken.error().context) == "modify DN " + std::string(renamed.to_string()));

	REQUIRE(finish(ioc, c.del({ .entry = renamed })).has_value());
}

TEST_CASE("integration: assertion and pre/post-read controls", "[integration][controls]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("ctl");
	const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");
	using ldap::filters::attr;
	// UTF-8 values all the way: in the assertion filter and in the entries read back.
	const char before_sn[] = "\xC3\x86r\xC3\xB8";// Ærø
	const char after_sn[] = "\xE6\x97\xA5\xE6\x9C\xAC";// 日本

	// Post-read on an add: the entry as stored.
	auto added = finish(ioc,
	  c.add({ .entry = entry,
		.attributes = { { "objectClass", { "inetOrgPerson" } },
		  { "uid", { name } },
		  { "cn", { "C" } },
		  { "sn", { before_sn } } },
		.controls = { ldap::post_read{ .attributes = { "sn", "entryUUID" } } } }));
	REQUIRE(added.has_value());
	auto stored = ldap::find_post_read(added->controls);
	REQUIRE(stored.has_value());
	REQUIRE(stored->has_value());
	CHECK(ldap::dn::parse((*stored)->dn).value() == entry);
	REQUIRE((*stored)->find("sn") != nullptr);
	CHECK(*(*stored)->find("sn") == ldap::string_list{ before_sn });
	CHECK((*stored)->find("entryUUID") != nullptr);// operational attributes can be asked for by name
	CHECK((*stored)->find("cn") == nullptr);

	// Assertion holds: the modify runs; pre-read and post-read show both sides.
	auto changed = finish(ioc,
	  c.modify({ .object = entry,
		.changes = { ldap::mod::replace("sn", { after_sn }) },
		.controls = { ldap::assertion{ .filter = attr("sn") == before_sn },
		  ldap::pre_read{ .attributes = { "sn" } },
		  ldap::post_read{ .attributes = { "sn" } } } }));
	REQUIRE(changed.has_value());
	auto before = ldap::find_pre_read(changed->controls);
	auto after = ldap::find_post_read(changed->controls);
	REQUIRE(before.has_value());
	REQUIRE(before->has_value());
	REQUIRE(after.has_value());
	REQUIRE(after->has_value());
	CHECK(*(*before)->find("sn") == ldap::string_list{ before_sn });
	CHECK(*(*after)->find("sn") == ldap::string_list{ after_sn });

	// Assertion fails: nothing changes, the connection stays usable.
	auto refused = finish(ioc,
	  c.modify({ .object = entry,
		.changes = { ldap::mod::replace("sn", { "Again" }) },
		.controls = { ldap::assertion{ .filter = attr("sn") == before_sn } } }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::errc::assertion_failed);
	CHECK(finish(ioc, c.compare({ .entry = entry, .attribute = "sn", .value = after_sn })) == true);
	// On a search the assertion applies to the base entry.
	auto search_refused = finish(ioc,
	  c.search({ .base = entry,
		.scope = ldap::search_scope::base_object,
		.controls = { ldap::assertion{ .filter = attr("sn") == before_sn } } }));
	REQUIRE_FALSE(search_refused.has_value());
	CHECK(search_refused.error().code == ldap::errc::assertion_failed);

	// Pre-read on a delete: the entry as it was.
	auto deleted = finish(ioc,
	  c.del({ .entry = entry,
		.controls = {
		  ldap::assertion{ .filter = attr("sn") == after_sn }, ldap::pre_read{ .attributes = { "sn" } } } }));
	REQUIRE(deleted.has_value());
	auto last = ldap::find_pre_read(deleted->controls);
	REQUIRE(last.has_value());
	REQUIRE(last->has_value());
	CHECK(*(*last)->find("sn") == ldap::string_list{ after_sn });
}

TEST_CASE("integration: transactions (RFC 5805)", "[integration][transaction]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const auto person = [](const std::string &uid) -> ldap::add_params {
		return { .entry = *ldap::dn::parse("uid=" + uid + ",ou=people,dc=example,dc=org"),
			.attributes = { { "objectClass", { "inetOrgPerson" } },
			  { "uid", { uid } },
			  { "cn", { "T" } },
			  { "sn", { "\xC3\x86" } } } };
	};
	const auto exists = [&](const ldap::dn &d) {
		auto r = finish(ioc, c.search({ .base = d, .scope = ldap::search_scope::base_object }));
		return r.has_value();
	};
	// Absent, and not merely unreadable.
	const auto not_exists = [&](const ldap::dn &d) {
		auto r = finish(ioc, c.search({ .base = d, .scope = ldap::search_scope::base_object }));
		return !r.has_value() && r.error().code == ldap::errc::no_such_object;
	};

	auto dse = finish(ioc, c.search(ldap::root_dse({ "supportedExtension" })));
	REQUIRE(dse.has_value());
	REQUIRE(dse->entries.size() == 1);
	const auto *extensions = dse->entries[0].find("supportedExtension");
	if (extensions == nullptr || !std::ranges::contains(*extensions, ldap::start_transaction_oid)) {
		SKIP("slapd does not advertise Start Transaction (" << ldap::start_transaction_oid << ")");
	}
	auto t = finish(ioc, c.begin_transaction());
	if (!t
		&& (t.error().code == ldap::errc::protocol_error
			|| t.error().code == ldap::errc::unavailable_critical_extension)) {
		SKIP("slapd without transactions: " << t.error().message());
	}
	REQUIRE(t.has_value());
	const std::string a = unique("txa");
	const std::string b = unique("txb");
	auto first = finish(ioc, t->add(person(a)));
	REQUIRE(first.has_value());
	auto second = finish(ioc, t->add(person(b)));
	REQUIRE(second.has_value());
	CHECK(second->message_id != first->message_id);
	// Deferred: nothing is applied before the commit.
	CHECK(not_exists(person(a).entry));
	auto done = finish(ioc, t->commit());
	REQUIRE(done.has_value());
	CHECK(exists(person(a).entry));
	CHECK(exists(person(b).entry));

	// A conflicting update fails the whole commit, which names it; the
	// other update is not applied either.
	auto u = finish(ioc, c.begin_transaction());
	REQUIRE(u.has_value());
	const std::string fresh = unique("txc");
	REQUIRE(finish(ioc, u->add(person(fresh))).has_value());
	auto dup = finish(ioc, u->add(person(a)));
	REQUIRE(dup.has_value());
	auto refused = finish(ioc, u->commit());
	REQUIRE_FALSE(refused.has_value());
	INFO(refused.error().message());
	CHECK(refused.error().code == ldap::errc::entry_already_exists);
	CHECK_THAT(std::string(refused.error().context),
	  ContainsSubstring(
		"update message " + std::to_string(dup->message_id) + " (add uid=" + a + ",ou=people,dc=example,dc=org)"));
	CHECK(not_exists(person(fresh).entry));

	// Abort, explicit and by destruction: nothing applied, the connection
	// stays usable.
	auto v = finish(ioc, c.begin_transaction());
	REQUIRE(v.has_value());
	REQUIRE(finish(ioc, v->del({ .entry = person(a).entry })).has_value());
	REQUIRE(finish(ioc, v->abort()).has_value());
	{
		auto w = finish(ioc, c.begin_transaction());
		REQUIRE(w.has_value());
		REQUIRE(finish(ioc, w->del({ .entry = person(b).entry })).has_value());
	}
	// The destructor's abort is queued, not awaited, and slapd allows one
	// transaction per connection: wait until its answer has arrived (it is
	// counted as outstanding until then) before the next Start Transaction.
	// slapd may answer the who_am_i first, hence the loop.
	for (int i = 0; i < 100 && c.outstanding() != 0; ++i) {
		REQUIRE(finish(ioc, ldap::who_am_i(c)).has_value());
	}
	REQUIRE(c.outstanding() == 0);
	CHECK(exists(person(a).entry));
	CHECK(exists(person(b).entry));

	// The primitives, deleting both in one transaction.
	auto id = finish(ioc, c.start_transaction());
	REQUIRE(id.has_value());
	for (const auto &uid : { a, b }) {
		auto d = finish(ioc,
		  c.del({ .entry = person(uid).entry,
			.controls = { ldap::transaction_specification{ .identifier = std::string(*id) } } }));
		REQUIRE(d.has_value());
	}
	REQUIRE(finish(ioc, c.end_transaction(*id)).has_value());
	CHECK(not_exists(person(a).entry));
	CHECK(not_exists(person(b).entry));
}

TEST_CASE("integration: matched values", "[integration][controls]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	using ldap::filters::attr;

	// One member of cn=big's 2000.
	const char member[] = "uid=member0042,ou=elsewhere,dc=example,dc=org";
	auto big = finish(ioc,
	  c.search({ .base = ldap::dn{ "cn=big,ou=groups,dc=example,dc=org" },
		.scope = ldap::search_scope::base_object,
		.attributes = { "member", "cn" },
		.controls = {
		  ldap::matched_values{ .values_return_filter = { attr("member") == member }, .critical = true } } }));
	REQUIRE(big.has_value());
	REQUIRE(big->entries.size() == 1);
	REQUIRE(big->entries.front().find("member") != nullptr);
	CHECK(*big->entries.front().find("member") == ldap::string_list{ member });
	// RFC 3876 returns cn with no values; slapd leaves it out.
	CHECK(big->entries.front().find("cn") == nullptr);

	// Several items in the RFC 3876 string form, UTF-8 values.
	const char sn[] = "\xC3\x85ngstr\xC3\xB6m";// Ångström
	auto items = ldap::parse_values_return_filter("((sn=*ngstr*)(cn=nobody)(objectClass=inetOrgPerson))");
	REQUIRE(items.has_value());
	auto jorg = finish(ioc,
	  c.search({ .base = ldap::dn{ "uid=j\xC3\xB6rg,ou=people,dc=example,dc=org" },
		.scope = ldap::search_scope::base_object,
		.attributes = { "sn", "cn", "objectClass" },
		.controls = { ldap::matched_values{ .values_return_filter = std::move(*items) } } }));
	REQUIRE(jorg.has_value());
	REQUIRE(jorg->entries.size() == 1);
	REQUIRE(jorg->entries.front().find("sn") != nullptr);
	CHECK(*jorg->entries.front().find("sn") == ldap::string_list{ sn });
	CHECK(jorg->entries.front().find("cn") == nullptr);
	CHECK(*jorg->entries.front().find("objectClass") == ldap::string_list{ "inetOrgPerson" });

	// An extensible match picks the matching rule: caseExactMatch keeps
	// "User 001" but not "user 001"; the entries themselves are unaffected.
	const auto cn_exact = [&](const char *value) {
		auto r = finish(ioc,
		  c.search({ .base = people,
			.filter = attr("uid") == "user001",
			.attributes = { "cn", "uid" },
			.controls = { ldap::matched_values{
			  .values_return_filter = { ldap::filter::raw(std::string("(cn:caseExactMatch:=") + value + ")").value(),
				attr("uid").present() } } } }));
		REQUIRE(r.has_value());
		REQUIRE(r->entries.size() == 1);
		CHECK(r->entries.front().find("uid") != nullptr);
		return r->entries.front().find("cn") != nullptr;
	};
	CHECK(cn_exact("User 001"));
	CHECK_FALSE(cn_exact("user 001"));

	// The client refuses what RFC 3876 excludes, before sending.
	auto refused = finish(ioc,
	  c.search({ .base = people,
		.controls = { ldap::matched_values{ .values_return_filter = { attr("cn") == "x" && attr("sn") == "y" } } } }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::client_errc::invalid_filter);
}

TEST_CASE("integration: the relax rules control", "[integration][controls]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("relax");
	const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");
	REQUIRE(finish(ioc,
	  c.add({ .entry = entry,
		.attributes = { { "objectClass", { "inetOrgPerson" } },
		  { "uid", { name } },
		  { "cn", { "R" } },
		  { "sn", { "R" } } } }))
		.has_value());

	// createTimestamp is NO-USER-MODIFICATION: refused, even to the rootdn,
	// unless the modify relaxes the rules (as a migration restoring it would).
	const char migrated[] = "20010203040506Z";
	auto refused =
	  finish(ioc, c.modify({ .object = entry, .changes = { ldap::mod::replace("createTimestamp", { migrated }) } }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::errc::constraint_violation);
	auto relaxed = finish(ioc,
	  c.modify({ .object = entry,
		.changes = { ldap::mod::replace("createTimestamp", { migrated }) },
		.controls = { ldap::relax_rules{} } }));
	REQUIRE(relaxed.has_value());
	CHECK(finish(ioc, c.compare({ .entry = entry, .attribute = "createTimestamp", .value = migrated })) == true);

	REQUIRE(finish(ioc, c.del({ .entry = entry })).has_value());
}

TEST_CASE("integration: server side sort", "[integration][controls]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	if (env("JHETZ_LDAP_IT_SORT").empty()) {
		SKIP("slapd without the sssvlv overlay");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	auto s = finish(ioc,
	  c.search_stream({ .base = people,
		.filter = ldap::filters::attr("objectClass") == "posixAccount",
		.attributes = { "uid", "uidNumber" },
		.controls = {
		  ldap::server_side_sort{ .keys = { { .attribute = "uidNumber", .reverse = true } }, .critical = true } } }));
	REQUIRE(s.has_value());
	std::vector<std::string> uids;
	while (true) {
		auto e = finish(ioc, s->next());
		REQUIRE(e.has_value());
		if (!*e) {
			break;
		}
		REQUIRE((*e)->find("uid") != nullptr);
		uids.emplace_back((*e)->find("uid")->front());
	}
	REQUIRE(uids.size() == 250);
	CHECK(uids.front() == "user249");
	CHECK(uids[1] == "user248");
	CHECK(uids.back() == "user000");
	auto sorted = ldap::find_sort_result(s->controls());
	REQUIRE(sorted.has_value());
	REQUIRE(sorted->has_value());
	CHECK((*sorted)->is_success());

	// An ordering rule given by name: sn descending ("249" .. "000").
	auto by_sn = finish(ioc,
	  c.search({ .base = people,
		.filter = ldap::filters::attr("objectClass") == "posixAccount",
		.attributes = { "sn" },
		.controls = { ldap::server_side_sort{
		  .keys = { { .attribute = "sn", .ordering_rule = "caseIgnoreOrderingMatch", .reverse = true } },
		  .critical = true } } }));
	REQUIRE(by_sn.has_value());
	REQUIRE(by_sn->entries.size() == 250);
	CHECK(by_sn->entries.front().find("sn")->front() == "249");
	CHECK(by_sn->entries.back().find("sn")->front() == "000");

	// cn has no ORDERING rule: a critical sort by it fails the search.
	auto refused = finish(ioc,
	  c.search({ .base = people,
		.controls = { ldap::server_side_sort{ .keys = { { .attribute = "cn" } }, .critical = true } } }));
	REQUIRE_FALSE(refused.has_value());
	INFO(refused.error().message());
	CHECK(refused.error().code.category() == ldap::result_category());
}

namespace {

// One virtual list view window over the posixAccounts sorted by uidNumber
// (user000 .. user249): the uids, the VLV response, or the search's error.
// `context` is sent as the contextID and replaced by the response's: slapd
// keeps a sort state per contextID and refuses new ones (busy) once a
// connection holds sssvlv-maxperconn of them, so a client scrolling one list
// sends it back.
struct vlv_window
{
	std::vector<std::string> uids{};
	std::optional<ldap::vlv_response> response{};
	std::optional<ldap::error> error{};
};

auto vlv_window_of(corosio::io_context &ioc,
  ldap::connection &c,
  std::optional<std::string> &context,
  ldap::virtual_list_view vlv) -> vlv_window
{
	vlv.context_id = context;
	auto s = finish(ioc,
	  c.search_stream({ .base = people,
		.filter = ldap::filters::attr("objectClass") == "posixAccount",
		.attributes = { "uid" },
		.controls = {
		  ldap::server_side_sort{ .keys = { { .attribute = "uidNumber" } }, .critical = true }, std::move(vlv) } }));
	REQUIRE(s.has_value());
	vlv_window out;
	while (true) {
		auto e = finish(ioc, s->next());
		if (!e) {
			out.error = std::move(e.error());
			break;
		}
		if (!*e) {
			break;
		}
		out.uids.emplace_back((*e)->find("uid")->front());
	}
	auto r = ldap::find_vlv_response(s->controls());
	REQUIRE(r.has_value());
	if (*r) {
		out.response = std::move(**r);
		context.reset();
		if (out.response->context_id) {
			context.emplace(*out.response->context_id);
		}
	}
	return out;
}

}// namespace

TEST_CASE("integration: virtual list view", "[integration][controls]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	if (env("JHETZ_LDAP_IT_SORT").empty()) {
		SKIP("slapd without the sssvlv overlay");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	using uids = std::vector<std::string>;
	std::optional<std::string> context;

	// The 100th entry and two on each side, the server's count unknown.
	auto mid = vlv_window_of(ioc,
	  c,
	  context,
	  { .before_count = 2, .after_count = 2, .target = ldap::vlv_by_offset{ .offset = 100 }, .critical = true });
	REQUIRE_FALSE(mid.error.has_value());
	CHECK(mid.uids == uids{ "user097", "user098", "user099", "user100", "user101" });
	REQUIRE(mid.response.has_value());
	CHECK(mid.response->is_success());
	CHECK(mid.response->target_position == 100);
	CHECK(mid.response->content_count == 250);

	// The next window, with the server's count and contextID sent back.
	CHECK(context.has_value());// sssvlv sends one
	auto next = vlv_window_of(ioc,
	  c,
	  context,
	  { .before_count = 2,
		.after_count = 2,
		.target = ldap::vlv_by_offset{ .offset = 102, .content_count = mid.response->content_count } });
	REQUIRE_FALSE(next.error.has_value());
	CHECK(next.uids == uids{ "user099", "user100", "user101", "user102", "user103" });
	REQUIRE(next.response.has_value());
	CHECK(next.response->target_position == 102);

	// The first and the last entries: offset 1, and offset == contentCount.
	auto first = vlv_window_of(ioc, c, context, { .after_count = 1 });
	CHECK(first.uids == uids{ "user000", "user001" });
	auto last = vlv_window_of(
	  ioc, c, context, { .before_count = 1, .target = ldap::vlv_by_offset{ .offset = 250, .content_count = 250 } });
	CHECK(last.uids == uids{ "user248", "user249" });

	// Typedown: the first uidNumber >= 10200 is user200's.
	auto typed =
	  vlv_window_of(ioc, c, context, { .after_count = 4, .target = ldap::vlv_greater_than_or_equal{ "10200" } });
	REQUIRE_FALSE(typed.error.has_value());
	CHECK(typed.uids == uids{ "user200", "user201", "user202", "user203", "user204" });
	REQUIRE(typed.response.has_value());
	CHECK(typed.response->target_position == 201);
	// No entry that large: targetPosition is contentCount + 1, and the
	// window ends with the list.
	auto past = vlv_window_of(
	  ioc, c, context, { .before_count = 1, .after_count = 1, .target = ldap::vlv_greater_than_or_equal{ "99999" } });
	REQUIRE_FALSE(past.error.has_value());
	CHECK(past.uids == uids{ "user249" });
	REQUIRE(past.response.has_value());
	CHECK(past.response->target_position == 251);

	// An offset beyond the list fails the search with 76; the response
	// control says why (slapd: 77, not the draft's offsetRangeError).
	auto beyond = vlv_window_of(
	  ioc, c, context, { .after_count = 4, .target = ldap::vlv_by_offset{ .offset = 500, .content_count = 250 } });
	REQUIRE(beyond.error.has_value());
	CHECK(beyond.error->code == ldap::errc::virtual_list_view_error);
	REQUIRE(beyond.response.has_value());
	CHECK_FALSE(beyond.response->is_success());
	INFO("virtualListViewResult " << beyond.response->result_code);
	CHECK(c.is_open());

	// search() works too (it drops the response control).
	auto plain = finish(ioc,
	  c.search({ .base = people,
		.filter = ldap::filters::attr("objectClass") == "posixAccount",
		.attributes = { "uid" },
		.controls = { ldap::server_side_sort{ .keys = { { .attribute = "uidNumber", .reverse = true } } },
		  ldap::virtual_list_view{ .after_count = 2 } } }));
	REQUIRE(plain.has_value());
	REQUIRE(plain->entries.size() == 3);
	CHECK(plain->entries.front().find("uid")->front() == "user249");

	// Without the sort control the client refuses, before sending.
	auto unsorted = finish(ioc, c.search({ .base = people, .controls = { ldap::virtual_list_view{} } }));
	REQUIRE_FALSE(unsorted.has_value());
	CHECK(unsorted.error().code == ldap::client_errc::encode_error);
}

namespace {

// One page of `params` by hand, with `control` added: the uids it returned
// and the cookie of its paged results control.
struct uid_page
{
	std::vector<std::string> uids{};
	std::string cookie{};
};

auto uid_page_by_hand(corosio::io_context &ioc, ldap::connection &c, ldap::search_params params, ldap::paged control)
  -> ldap::result<uid_page>
{
	params.controls.emplace_back(std::move(control));
	auto s = finish(ioc, c.search_stream(std::move(params)));
	if (!s) {
		return std::unexpected(std::move(s.error()));
	}
	uid_page out;
	while (true) {
		auto e = finish(ioc, s->next());
		if (!e) {
			return std::unexpected(std::move(e.error()));
		}
		if (!*e) {
			break;
		}
		out.uids.emplace_back((*e)->find("uid")->front());
	}
	for (const auto &ctl : s->controls()) {
		if (ctl.type == ldap::paged_results_oid) {
			out.cookie = std::string(ldap::decode_paged_results(ctl)->cookie);
		}
	}
	return out;
}

// user<n>*, by sn descending if `sorted`.
auto hundred_users(int n, bool sorted) -> ldap::search_params
{
	ldap::search_params p{ .base = people,
		.filter = ldap::filters::attr("uid").starts_with("user" + std::to_string(n)),
		.attributes = { "uid" } };
	if (sorted) {
		p.controls.emplace_back(ldap::server_side_sort{
		  .keys = { { .attribute = "sn", .ordering_rule = "caseIgnoreOrderingMatch", .reverse = true } } });
	}
	return p;
}

// "user<n><99 - first>" .. "user<n><99 - first - count + 1>".
auto descending_uids(int n, int first, int count) -> std::vector<std::string>
{
	std::vector<std::string> out;
	out.reserve(static_cast<std::size_t>(count));
	for (int i = 0; i < count; ++i) {
		out.emplace_back(std::format("user{}{:02}", n, 99 - first - i));
	}
	return out;
}

}// namespace

namespace {

// One message of a content synchronization search, as the test needs it.
struct sync_event
{
	std::optional<ldap::sync_state> state{};// an entry's
	std::string dn{};
	std::string entry_uuid{};// the entryUUID attribute, if asked for
	std::optional<ldap::sync_info> info{};// a Sync Info Message
};

auto next_sync_event(corosio::io_context &ioc, ldap::search_stream &s) -> std::optional<sync_event>
{
	auto i = finish(ioc, s.next_item());
	if (!i) {
		FAIL("sync search: " << i.error().message());
	}
	if (!*i) {
		return std::nullopt;
	}
	sync_event out;
	if (const auto *e = std::get_if<ldap::search_entry>(&**i)) {
		auto state = ldap::find_sync_state(e->controls);
		REQUIRE(state.has_value());
		REQUIRE(state->has_value());
		out.state = std::move(**state);
		out.dn = e->dn;
		if (const auto *u = e->find("entryUUID")) {
			out.entry_uuid = u->front();
		}
	} else if (const auto *m = std::get_if<ldap::intermediate>(&**i)) {
		auto info = ldap::decode_sync_info(*m);
		REQUIRE(info.has_value());
		out.info = std::move(*info);
	} else {
		FAIL("sync search: unexpected reference");
	}
	return out;
}

}// namespace

TEST_CASE("integration: content synchronization (RFC 4533)", "[integration][controls][content_sync]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	if (env("JHETZ_LDAP_IT_SYNCREPL").empty()) {
		SKIP("slapd without the syncprov overlay");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("sync");
	const ldap::dn base = *ldap::dn::parse("ou=" + name + ",dc=example,dc=org");
	const ldap::dn first = base.child(ldap::rdn{ "cn=first" });
	const ldap::dn second = base.child(ldap::rdn{ "cn=second" });
	REQUIRE(
	  finish(ioc, c.add({ .entry = base, .attributes = { { "objectClass", { "organizationalUnit" } } } })).has_value());
	for (const auto &e : { first, second }) {
		REQUIRE(finish(ioc,
		  c.add({ .entry = e,
			.attributes = { { "objectClass", { "person" } },
			  { "cn", { std::string(e.rdns().front().to_string()).substr(3) } },
			  { "sn", { "Ærø" } } } }))
			.has_value());
	}
	const auto sync_search = [&](ldap::sync_request request) {
		return finish(ioc,
		  c.search_stream({ .base = base,
			.attributes = { "cn", "sn", "entryUUID" },
			.controls = { std::move(request) },
			.timeout = ldap::no_timeout,
			.intermediate_responses = true }));
	};
	const auto dn_of = [](const ldap::dn &d) { return std::string(d.to_string()); };

	// refreshOnly without a cookie: the whole content, then a cookie.
	auto all = sync_search(ldap::sync_request{});
	REQUIRE(all.has_value());
	std::vector<std::string> dns;
	while (auto ev = next_sync_event(ioc, *all)) {
		if (ev->state) {
			CHECK(ev->state->state == ldap::sync_state_type::add);
			CHECK(ldap::to_string(ev->state->entry_uuid) == ev->entry_uuid);
			dns.push_back(ev->dn);
		}
	}
	std::ranges::sort(dns);
	CHECK(dns == std::vector<std::string>{ dn_of(first), dn_of(second), dn_of(base) });
	auto done = ldap::find_sync_done(all->controls());
	REQUIRE(done.has_value());
	REQUIRE(done->has_value());
	REQUIRE((*done)->cookie.has_value());
	const std::string cookie((*done)->cookie->begin(), (*done)->cookie->end());
	CHECK_FALSE(cookie.empty());

	// A change, then refreshOnly from the cookie: only that change.
	REQUIRE(
	  finish(ioc, c.modify({ .object = second, .changes = { ldap::mod::replace("sn", { "日本" }) } })).has_value());
	auto since = sync_search(ldap::sync_request{ .cookie = cookie });
	REQUIRE(since.has_value());
	std::vector<std::string> changed;
	while (auto ev = next_sync_event(ioc, *since)) {
		if (ev->state && ev->state->state != ldap::sync_state_type::present) {
			changed.push_back(ev->dn);
		}
	}
	CHECK(changed == std::vector<std::string>{ dn_of(second) });
	auto resumed = ldap::find_sync_done(since->controls());
	REQUIRE(resumed.has_value());
	REQUIRE(resumed->has_value());
	REQUIRE((*resumed)->cookie.has_value());
	const std::string next_cookie((*resumed)->cookie->begin(), (*resumed)->cookie->end());
	CHECK(next_cookie != cookie);

	// refreshAndPersist from the latest cookie: the refresh ends with a
	// Sync Info Message, then a change made on another connection arrives
	// while the search runs on (no timeout: the connection's is 10 s).
	auto persist =
	  sync_search(ldap::sync_request{ .mode = ldap::sync_mode::refresh_and_persist, .cookie = next_cookie });
	REQUIRE(persist.has_value());
	bool refreshed = false;
	while (!refreshed) {
		auto ev = next_sync_event(ioc, *persist);
		REQUIRE(ev.has_value());
		CHECK_FALSE((ev->state && ev->state->state != ldap::sync_state_type::present));
		refreshed = ev->info
					&& (ev->info->type == ldap::sync_info_type::refresh_delete
						|| ev->info->type == ldap::sync_info_type::refresh_present)
					&& ev->info->refresh_done;
	}
	auto other = open_admin(ioc);
	REQUIRE(
	  finish(ioc, other.modify({ .object = first, .changes = { ldap::mod::replace("sn", { "Zoë" }) } })).has_value());
	std::optional<sync_event> change;
	while (!change) {
		auto ev = next_sync_event(ioc, *persist);
		REQUIRE(ev.has_value());// the persist phase does not end
		if (ev->state) {
			change = std::move(ev);
		}
	}
	CHECK(change->dn == dn_of(first));
	CHECK(
	  (change->state->state == ldap::sync_state_type::modify || change->state->state == ldap::sync_state_type::add));
	CHECK(ldap::to_string(change->state->entry_uuid) == change->entry_uuid);
	CHECK_FALSE(persist->done());
	*persist = ldap::search_stream{};// abandons the search

	for (const auto &e : { first, second, base }) {
		REQUIRE(finish(ioc, c.del({ .entry = e })).has_value());
	}
}

// slapd keeps one paged search per connection (RFC 2696 section 3 lets a
// server age out older ones). Without sorting, resuming any but the
// last-answered one fails cleanly: back-mdb compares the request's cookie (an
// entry ID) with the connection's last returned one, older gives 53
// unwillingToPerform and newer 2 protocolError. With the sssvlv overlay
// (sorted paged searches), any non-empty cookie resumes the connection's
// latest sorted paged search: sssvlv looks the session up by ps_cookie, which
// slapd's control parser copies from the connection's last returned cookie,
// and never reads the request's own cookie (ps_cookieval; OpenLDAP 2.7.1).
// The client cannot tell: concurrent sorted paged searches need one
// connection each, which this checks.
TEST_CASE("integration: concurrent paged searches with and without sorting", "[integration][controls]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	if (env("JHETZ_LDAP_IT_SORT").empty()) {
		SKIP("slapd without the sssvlv overlay");
	}
	draining_context ioc;

	SECTION("unsorted on one connection: the older search's cookie is refused")
	{
		// unwilling_to_perform because user0xx were loaded before user1xx:
		// A's cookie is a lower entry ID than B's. Started the other way
		// round, A's next page would get protocol_error.
		auto c = open_admin(ioc);
		auto a1 = uid_page_by_hand(ioc, c, hundred_users(0, false), { .page_size = 20 });
		auto b1 = uid_page_by_hand(ioc, c, hundred_users(1, false), { .page_size = 20 });
		REQUIRE(a1.has_value());
		REQUIRE(b1.has_value());
		CHECK(a1->uids.size() == 20);
		CHECK(b1->uids.size() == 20);
		auto a2 = uid_page_by_hand(ioc, c, hundred_users(0, false), { .page_size = 20, .cookie = a1->cookie });
		REQUIRE_FALSE(a2.has_value());
		CHECK(a2.error().code == ldap::errc::unwilling_to_perform);
		auto b2 = uid_page_by_hand(ioc, c, hundred_users(1, false), { .page_size = 20, .cookie = b1->cookie });
		REQUIRE(b2.has_value());
		CHECK(b2->uids.front() == "user120");
	}

	SECTION("sorted on one connection: the older search's cookie resumes the latest (slapd bug)")
	{
		auto c = open_admin(ioc);
		auto a1 = uid_page_by_hand(ioc, c, hundred_users(0, true), { .page_size = 20 });
		auto b1 = uid_page_by_hand(ioc, c, hundred_users(1, true), { .page_size = 20 });
		REQUIRE(a1.has_value());
		REQUIRE(b1.has_value());
		CHECK(a1->uids == descending_uids(0, 0, 20));
		CHECK(b1->uids == descending_uids(1, 0, 20));
		REQUIRE_FALSE(a1->cookie.empty());
		CHECK(a1->cookie != b1->cookie);
		// The request carries A's own cookie, filter and sort; the answer is
		// B's second page. Pins the slapd sssvlv bug: failing
		// here means slapd fixed it, so update the notes of search_paged
		// (connection.hpp), docs/API.md and this section.
		INFO(
		  "pinned slapd sssvlv bug (coro-ldap-seo): if this fails slapd fixed it; update search_paged notes, "
		  "docs/API.md, this section");
		auto a2 = uid_page_by_hand(ioc, c, hundred_users(0, true), { .page_size = 20, .cookie = a1->cookie });
		INFO((a2.has_value() ? std::pmr::string{} : a2.error().message()));
		REQUIRE(a2.has_value());
		CHECK(a2->uids == descending_uids(1, 20, 20));
	}

	SECTION("sorted, one connection each: every search gets its own entries")
	{
		std::vector<ldap::connection> conns;
		std::vector<ldap::paged_search> searches;
		for (int n = 0; n < 3; ++n) {
			conns.push_back(open_admin(ioc));
			auto p = finish(ioc, ldap::search_paged(conns.back(), hundred_users(n, true), 20));
			REQUIRE(p.has_value());
			searches.push_back(std::move(*p));
		}
		// One entry of each in turn, so their pages interleave.
		std::vector<std::vector<std::string>> uids(3);
		for (bool more = true; more;) {
			more = false;
			for (std::size_t i = 0; i < searches.size(); ++i) {
				if (searches[i].done()) {
					continue;
				}
				auto e = finish(ioc, searches[i].next());
				REQUIRE(e.has_value());
				if (!*e) {
					continue;
				}
				uids[i].emplace_back((*e)->find("uid")->front());
				more = true;
			}
		}
		// user2xx has 50 users (user200 .. user249).
		CHECK(uids[0] == descending_uids(0, 0, 100));
		CHECK(uids[1] == descending_uids(1, 0, 100));
		CHECK(uids[2] == descending_uids(2, 50, 50));
		CHECK(searches[0].pages() == 5);
		CHECK(searches[1].pages() == 5);
		CHECK(searches[2].pages() == 3);
	}
}

TEST_CASE("integration: password modify (RFC 3062)", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("pw");
	const std::string who = "uid=" + name + ",ou=people,dc=example,dc=org";
	const ldap::dn entry = *ldap::dn::parse(who);
	REQUIRE(finish(ioc,
	  c.add({ .entry = entry,
		.attributes = { { "objectClass", { "inetOrgPerson" } },
		  { "uid", { name } },
		  { "cn", { "Password" } },
		  { "sn", { "Test" } },
		  { "userPassword", { "start" } } } }))
		.has_value());

	// The admin sets a password, then has the server generate one.
	auto set = finish(ioc, ldap::password_modify(c, { .user = who, .new_password = "first" }));
	REQUIRE(set.has_value());
	CHECK_FALSE(set->has_value());
	{
		auto u = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		CHECK(finish(ioc, u.simple_bind(entry, "first")).has_value());
		// This server's ACL (read only) refuses users their own change.
		auto own = finish(ioc, ldap::password_modify(u, { .old_password = "first", .new_password = "second" }));
		REQUIRE_FALSE(own.has_value());
		CHECK(own.error().code == ldap::errc::insufficient_access_rights);
		CHECK(own.error().context == "password modify");
	}
	auto generated = finish(ioc, ldap::password_modify(c, { .user = who }));
	REQUIRE(generated.has_value());
	REQUIRE(generated->has_value());
	CHECK_FALSE((*generated)->empty());
	{
		auto u = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		CHECK(finish(ioc, u.simple_bind(entry, **generated)).has_value());
		auto old = finish(ioc, u.simple_bind(entry, "first"));
		REQUIRE_FALSE(old.has_value());
		CHECK(old.error().code == ldap::errc::invalid_credentials);
	}
	REQUIRE(finish(ioc, c.del({ .entry = entry })).has_value());
}

TEST_CASE("integration: change_password and reset_password (RFC 3062)", "[integration][password]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	const std::string name = unique("pwc");
	const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");
	REQUIRE(finish(ioc,
	  c.add({ .entry = entry,
		.attributes = { { "objectClass", { "inetOrgPerson" } },
		  { "uid", { name } },
		  { "cn", { "Password" } },
		  { "sn", { "Test" } },
		  { "userPassword", { "start" } } } }))
		.has_value());
	const auto binds = [&](std::string password) {
		auto u = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		return finish(ioc, u.simple_bind(entry, std::move(password))).has_value();
	};

	const std::string first = "pässwörd 日本 \xF0\x9F\x94\x91";
	REQUIRE(finish(ioc, ldap::reset_password(c, entry, first)).has_value());
	CHECK(binds(first));
	REQUIRE(finish(ioc, ldap::change_password(c, entry, first, "second")).has_value());
	CHECK(binds("second"));
	CHECK_FALSE(binds(first));
	// slapd checks the old password.
	auto wrong = finish(ioc, ldap::change_password(c, entry, "not-the-password", "third"));
	REQUIRE_FALSE(wrong.has_value());
	INFO(wrong.error().message());
	CHECK_FALSE(std::string(wrong.error().message()).contains("not-the-password"));
	CHECK(binds("second"));
	REQUIRE(finish(ioc, c.del({ .entry = entry })).has_value());
}

// ---------------------------------------------------------------- sync connection

TEST_CASE("integration: the sync connection", "[integration][sync]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	SECTION("StartTLS, then writes")
	{
		auto u = env("JHETZ_LDAP_IT_LDAP");
		u.replace(u.find("127.0.0.1"), 9, "localhost");
		auto opened = ldap::sync::connect(*ldap::url::parse(u), trusting());
		REQUIRE(opened.has_value());
		auto &c = *opened;
		CHECK_FALSE(c.is_tls());
		net::tls_options tls;
		tls.ca_file = env("JHETZ_LDAP_IT_CA");
		// Out of REQUIRE, which spells its expression twice (one unevaluated).
		const auto started = c.start_tls(std::move(tls));
		REQUIRE(started.has_value());
		CHECK(c.is_tls());
		REQUIRE(c.simple_bind(admin, "secret").has_value());

		const std::string name = unique("sync");
		const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");
		const ldap::add_params add{ .entry = entry,
			.attributes = { { "objectClass", { "inetOrgPerson" } },
			  { "uid", { name } },
			  { "cn", { "Synchrone" } },
			  { "sn", { "Zoë" } } } };
		REQUIRE(c.add(add).has_value());
		auto again = c.add(add);
		REQUIRE_FALSE(again.has_value());
		CHECK(again.error().code == ldap::cond::already_exists);
		REQUIRE(
		  c.modify({ .object = entry, .changes = { ldap::mod::add("mail", { "sync@example.org" }) } }).has_value());
		CHECK(c.compare({ .entry = entry, .attribute = "mail", .value = "sync@example.org" }) == true);
		CHECK(c.compare({ .entry = entry, .attribute = "sn", .value = "Zoe" }) == false);
		auto pw = ldap::sync::password_modify(c, { .user = std::string(entry.to_string()) });
		REQUIRE(pw.has_value());
		CHECK(pw->has_value());
		const ldap::dn renamed = *ldap::dn::parse("uid=" + name + "-r,ou=people,dc=example,dc=org");
		REQUIRE(c.modify_dn({ .entry = entry, .new_rdn = renamed.rdns().front() }).has_value());
		const ldap::dn groups{ "ou=groups,dc=example,dc=org" };
		REQUIRE(
		  c.modify_dn({ .entry = renamed, .new_rdn = renamed.rdns().front(), .new_superior = groups }).has_value());
		REQUIRE(
		  c.modify_dn({ .entry = groups.child(renamed.rdns().front()),
						.new_rdn = renamed.rdns().front(),
						.new_superior = renamed.parent() })
			.has_value());
		REQUIRE(c.modify_dn({ .entry = renamed, .new_rdn = entry.rdns().front() }).has_value());
		REQUIRE(c.modify_dn({ .entry = entry, .new_rdn = renamed.rdns().front() }).has_value());
		REQUIRE(c.del({ .entry = renamed }).has_value());
		auto gone = c.del({ .entry = renamed });
		REQUIRE_FALSE(gone.has_value());
		CHECK(gone.error().code == ldap::errc::no_such_object);
		auto x = c.extended({ .name = std::string(ldap::who_am_i_oid) });
		REQUIRE(x.has_value());
		CHECK(x->value == "dn:cn=admin,dc=example,dc=org");
		REQUIRE(c.unbind().has_value());
		CHECK_FALSE(c.is_open());
	}
	SECTION("SASL EXTERNAL over ldapi://, then close")
	{
		auto opened = ldap::sync::connect(*ldap::url::parse(env("JHETZ_LDAP_IT_LDAPI")), trusting());
		REQUIRE(opened.has_value());
		auto &c = *opened;
		ldap::sasl_external mech;
		REQUIRE(c.sasl_bind(mech).has_value());
		CHECK_THAT(ldap::sync::who_am_i(c).value(), ContainsSubstring("cn=peercred,cn=external,cn=auth"));
		c.close();
		CHECK_FALSE(c.is_open());
	}
}

TEST_CASE("integration: transactions through the sync connection", "[integration][sync][transaction]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	auto opened = ldap::sync::connect(*ldap::url::parse(env("JHETZ_LDAP_IT_LDAP")), trusting());
	REQUIRE(opened.has_value());
	auto &c = *opened;
	REQUIRE(c.simple_bind(admin, "secret").has_value());
	const auto state = [&c](const ldap::dn &d) {
		return c.search({ .base = d, .scope = ldap::search_scope::base_object, .attributes = { "mail" } });
	};
	const auto absent = [&](const ldap::dn &d) {
		auto r = state(d);
		return !r.has_value() && r.error().code == ldap::errc::no_such_object;
	};
	auto t = c.begin_transaction();
	if (!t
		&& (t.error().code == ldap::errc::protocol_error
			|| t.error().code == ldap::errc::unavailable_critical_extension)) {
		SKIP("slapd without transactions: " << t.error().message());
	}
	REQUIRE(t.has_value());
	CHECK(t->is_open());

	// add, modify and modify DN, applied together at the commit.
	const std::string name = unique("stx");
	const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");
	const ldap::dn renamed = *ldap::dn::parse("uid=" + name + "-r,ou=people,dc=example,dc=org");
	REQUIRE(
	  t->add({ .entry = entry,
			   .attributes = { { "objectClass", { "inetOrgPerson" } },
				 { "uid", { name } },
				 { "cn", { "Transaktion" } },
				 { "sn", { "Zoë" } } } })
		.has_value());
	REQUIRE(t->modify({ .object = entry, .changes = { ldap::mod::add("mail", { "stx@example.org" }) } }).has_value());
	REQUIRE(t->modify_dn({ .entry = entry, .new_rdn = renamed.rdns().front() }).has_value());
	CHECK(absent(entry));// deferred
	REQUIRE(t->commit().has_value());
	CHECK_FALSE(t->is_open());
	CHECK(absent(entry));
	auto after = state(renamed);
	REQUIRE(after.has_value());
	REQUIRE(after->entries.size() == 1);
	CHECK(*after->entries[0].find("mail") == ldap::string_list{ "stx@example.org" });

	// abort(): nothing applied.
	auto u = c.begin_transaction();
	REQUIRE(u.has_value());
	REQUIRE(u->del({ .entry = renamed }).has_value());
	REQUIRE(u->abort().has_value());
	CHECK(state(renamed).has_value());

	// Move-assigned over, an open transaction is aborted and its answer
	// waited for: slapd allows one transaction per connection, and the
	// next Start Transaction succeeds.
	auto v = c.begin_transaction();
	REQUIRE(v.has_value());
	REQUIRE(v->del({ .entry = renamed }).has_value());
	*v = std::move(*u);// u's is settled already: nothing more is sent for it
	CHECK_FALSE(v->is_open());
	auto refused = u->del({ .entry = renamed });
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::client_errc::not_connected);
	CHECK(state(renamed).has_value());
	auto w = c.begin_transaction();
	REQUIRE(w.has_value());
	CHECK(w->identifier().empty());
	REQUIRE(w->del({ .entry = renamed }).has_value());
	REQUIRE(w->commit().has_value());
	CHECK(absent(renamed));
}

// ---------------------------------------------------------------- cancellation

TEST_CASE("integration: cancellation mid-search", "[integration]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	{
		auto s = finish(ioc, c.search_stream({ .base = people }));
		REQUIRE(s.has_value());
		auto first = finish(ioc, s->next());
		REQUIRE(first.has_value());
		REQUIRE(first->has_value());
	}// abandoned with entries still coming
	std::stop_source stop;
	outcome<ldap::result<ldap::search_result>> cancelled;
	spawn(ioc, stop.get_token(), c.search({ .base = people }), cancelled);
	stop.request_stop();
	drive(ioc);
	REQUIRE(cancelled.get().has_value() == false);
	CHECK(cancelled.get().error().code == ldap::cond::canceled);
	// The connection still works, and late responses were dropped.
	auto after = finish(ioc,
	  c.search(
		{ .base = ldap::dn{ "uid=user001,ou=people,dc=example,dc=org" }, .scope = ldap::search_scope::base_object }));
	REQUIRE(after.has_value());
	CHECK(after->entries.size() == 1);
	CHECK(c.outstanding() == 0);
}

// ---------------------------------------------------------------- fault injection

namespace {

enum class fault {
	truncate,// forward the server's first bytes, then close mid-PDU
	oversized,// replace the server's answer with a PDU declaring a 2 GiB length
	close,// close as soon as the server answers
};

// A one-connection TCP proxy between the client and slapd that breaks the
// server's first answer in the given way (the client's bytes pass through).
auto proxy(corosio::io_context &ioc, corosio::tcp_acceptor &acc, std::uint16_t server_port, fault f) -> capy::task<void>
{
	auto [aec, client] = co_await acc.accept();
	if (aec) {
		co_return;
	}
	corosio::tcp_socket server(ioc);
	auto [cec] = co_await server.connect(corosio::endpoint(corosio::ipv4_address::loopback(), server_port));
	if (cec) {
		co_return;
	}
	net::transport to_client = net::transport::wrap(std::move(client), "proxy client");
	net::transport to_server = net::transport::wrap(std::move(server), "proxy server");
	net::read_buffer from_client;
	net::read_buffer from_server;
	// One request in, one (broken) answer out.
	auto req = co_await net::read_frame(to_client, from_client, ldap::ber::default_max_message_size);
	if (!req) {
		co_return;
	}
	if (auto w = co_await net::write_bytes(to_server, from_client.data().first(*req)); !w) {
		co_return;
	}
	auto resp = co_await net::read_frame(to_server, from_server, ldap::ber::default_max_message_size);
	if (!resp) {
		co_return;
	}
	switch (f) {
	case fault::truncate:
		(void)co_await net::write_bytes(to_client, from_server.data().first(*resp / 2));
		break;
	case fault::oversized: {
		const std::byte huge[] = { std::byte{ 0x30 },
			std::byte{ 0x84 },
			std::byte{ 0x7f },
			std::byte{ 0xff },
			std::byte{ 0xff },
			std::byte{ 0xff } };
		(void)co_await net::write_bytes(to_client, huge);
		break;
	}
	case fault::close:
		break;
	}
	// Returning closes both sockets.
}

}// namespace

TEST_CASE("integration: a broken server answer closes the connection", "[integration][faults]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	const struct
	{
		const char *name;
		fault f;
		std::error_code code;
	} cases[] = {
		{ .name = "truncated PDU", .f = fault::truncate, .code = capy::error::eof },
		{ .name = "oversized length", .f = fault::oversized, .code = ldap::client_errc::message_too_large },
		{ .name = "closed mid-response", .f = fault::close, .code = capy::error::eof },
	};
	for (const auto &c : cases) {
		DYNAMIC_SECTION(c.name)
		{
			draining_context ioc;
			corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 4);
			outcome<void> p;
			spawn(ioc, proxy(ioc, acc, *server->port(), c.f), p);
			auto conn = open(ioc, "ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
			auto r = finish(ioc, conn.search({ .base = people }));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == c.code);
			CHECK_FALSE(conn.is_open());
			auto later = finish(ioc, conn.simple_bind(admin, "secret"));
			REQUIRE_FALSE(later.has_value());
			CHECK(later.error().code == ldap::client_errc::not_sent);
			conn.close();
			drive(ioc);
			CHECK(p.done());
		}
	}
}

// ---------------------------------------------------------------- ldap::client

namespace {

// Forwards to a socket owned by the relay, so the relay can still close it
// (transport::close() does nothing on a wrapped stream).
struct relay_socket
{
	corosio::tcp_socket *s;
	template<capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers) { return s->write_some(buffers); }
};

// A TCP relay to slapd, PDU by PDU, whose connections the test can cut: what
// the client sees when the server (or a middlebox) drops a connection.
class relay
{
  public:
	relay(corosio::io_context &ioc, std::uint16_t target)
	  : ioc_(ioc), acc_(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 8), target_(target)
	{
		spawn(ioc_, accept_loop(), accepting_);
	}
	relay(const relay &) = delete;
	auto operator=(const relay &) -> relay & = delete;
	~relay() { shut_down(); }

	[[nodiscard]] auto url() const -> std::string
	{
		return "ldap://127.0.0.1:" + std::to_string(acc_.local_endpoint().port());
	}
	[[nodiscard]] auto relayed() const -> std::size_t { return relayed_; }
	// Drops the n-th relayed connection, on both sides.
	void cut(std::size_t n)
	{
		pairs_.at(n).client.close();
		pairs_.at(n).server.close();
	}
	void shut_down()
	{
		acc_.close();
		for (auto &p : pairs_) {
			p.client.close();
			p.server.close();
		}
	}

  private:
	struct pair
	{
		corosio::tcp_socket client;
		corosio::tcp_socket server;
	};

	auto accept_loop() -> capy::task<void>
	{
		while (true) {
			auto &p = pairs_.emplace_back(corosio::tcp_socket(ioc_), corosio::tcp_socket(ioc_));
			if (auto [ec] = co_await acc_.accept(p.client); ec) {
				co_return;
			}
			if (auto [ec] = co_await p.server.connect(corosio::endpoint(corosio::ipv4_address::loopback(), target_));
			  ec) {
				co_return;
			}
			++relayed_;
			spawn(ioc_, pump(p.client, p.server), pumps_.emplace_back());
			spawn(ioc_, pump(p.server, p.client), pumps_.emplace_back());
		}
	}

	static auto pump(corosio::tcp_socket &from, corosio::tcp_socket &to) -> capy::task<void>
	{
		net::transport in = net::transport::wrap(relay_socket{ &from }, "relay in");
		net::transport out = net::transport::wrap(relay_socket{ &to }, "relay out");
		net::read_buffer buf;
		while (true) {
			auto n = co_await net::read_frame(in, buf, ldap::ber::default_max_message_size);
			if (!n) {
				break;
			}
			auto w = co_await net::write_bytes(out, buf.data().first(*n));
			buf.consume(*n);
			if (!w) {
				break;
			}
		}
		from.close();
		to.close();
	}

	corosio::io_context &ioc_;
	corosio::tcp_acceptor acc_;
	std::uint16_t target_;
	std::deque<pair> pairs_{};
	std::deque<outcome<void>> pumps_{};
	outcome<void> accepting_{};
	std::size_t relayed_ = 0;
};

}// namespace

TEST_CASE("integration: ldap::client's write forwarders", "[integration][client][write]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	draining_context ioc;
	ldap::client pool(
	  ioc, { .servers = { *server }, .connection = trusting(), .setup = ldap::simple_bind_setup(admin, "secret") });
	const std::string name = unique("pool");
	const ldap::dn entry = people.child(*ldap::rdn::parse("uid=" + name));
	const ldap::dn groups{ "ou=groups,dc=example,dc=org" };
	const auto exists = [&](const ldap::dn &d) {
		return finish(ioc, pool.search({ .base = d, .scope = ldap::search_scope::base_object })).has_value();
	};

	const ldap::add_params add{ .entry = entry,
		.attributes = {
		  { "objectClass", { "inetOrgPerson" } }, { "uid", { name } }, { "cn", { "Pool" } }, { "sn", { "Writer" } } } };
	REQUIRE(finish(ioc, pool.add(add)).has_value());
	auto again = finish(ioc, pool.add(add));
	REQUIRE_FALSE(again.has_value());
	CHECK(again.error().code == ldap::errc::entry_already_exists);
	CHECK(std::string_view(again.error().context) == "add " + std::string(entry.to_string()));
	const ldap::dn incomplete = people.child(*ldap::rdn::parse("uid=" + name + "-x"));
	auto refused = finish(ioc,
	  pool.add(
		{ .entry = incomplete, .attributes = { { "objectClass", { "inetOrgPerson" } }, { "cn", { "No Sn" } } } }));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::errc::object_class_violation);
	CHECK_THAT(std::string(refused.error().diagnostic), ContainsSubstring("sn"));

	REQUIRE(finish(ioc, pool.modify({ .object = entry, .changes = { ldap::mod::add("mail", { "pool@example.org" }) } }))
		.has_value());
	CHECK(finish(ioc, pool.compare({ .entry = entry, .attribute = "mail", .value = "pool@example.org" })) == true);

	REQUIRE(finish(ioc, pool.modify_dn({ .entry = entry, .new_rdn = entry.rdns().front(), .new_superior = groups }))
		.has_value());
	const ldap::dn moved = groups.child(entry.rdns().front());
	CHECK(exists(moved));
	const ldap::dn back = people.child(*ldap::rdn::parse("uid=" + name + "-b"));
	REQUIRE(finish(ioc, pool.modify_dn({ .entry = moved, .new_rdn = back.rdns().front(), .new_superior = people }))
		.has_value());
	const ldap::dn renamed = people.child(*ldap::rdn::parse("uid=" + name + "-r"));
	REQUIRE(finish(ioc, pool.modify_dn({ .entry = back, .new_rdn = renamed.rdns().front() })).has_value());
	CHECK_FALSE(exists(back));
	CHECK(exists(renamed));

	REQUIRE(finish(
	  ioc, pool.modify({ .object = renamed, .changes = { ldap::mod::replace("mail", { "plain@example.org" }) } }))
		.has_value());
	CHECK(finish(ioc, pool.compare({ .entry = renamed, .attribute = "mail", .value = "plain@example.org" })) == true);

	REQUIRE(finish(ioc, pool.del({ .entry = renamed })).has_value());
	auto gone = finish(ioc, pool.del({ .entry = renamed }));
	REQUIRE_FALSE(gone.has_value());
	CHECK(gone.error().code == ldap::errc::no_such_object);
	CHECK(pool.connections() == 1);
	pool.close();
	drive(ioc);
}

namespace {

struct staff
{
	std::string uid;
	std::string cn;
	std::string sn;
	std::optional<std::string> mail;
};

}// namespace

template<>
constexpr auto ldap::schema<staff> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&staff::uid>("uid"),
  ldap::field<&staff::cn>("cn"),
  ldap::field<&staff::sn>("sn"),
  ldap::field<&staff::mail>("mail"));

TEST_CASE("integration: search_paged over ldap::client", "[integration][client]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	draining_context ioc;
	ldap::client pool(ioc, { .servers = { *server }, .connection = trusting(), .max_connections = 2 });
	const ldap::search_params all_users{
		.base = people, .filter = ldap::filters::attr("objectClass") == "posixAccount", .attributes = { "uid" }
	};
	auto p = finish(ioc, ldap::search_paged(pool, all_users, 40));
	REQUIRE(p.has_value());
	std::size_t paged = 0;
	while (true) {
		// Other operations on the pool run on the other connection meanwhile.
		REQUIRE(finish(ioc, pool.search(ldap::root_dse({ "namingContexts" }))).has_value());
		auto e = finish(ioc, p->next());
		REQUIRE(e.has_value());
		if (!*e) {
			break;
		}
		++paged;
	}
	CHECK(paged == 250);
	CHECK(p->pages() == 7);
}

TEST_CASE("integration: ldap::store over ldap::client", "[integration][client][store]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	draining_context ioc;
	ldap::client pool(
	  ioc, { .servers = { *server }, .connection = trusting(), .setup = ldap::simple_bind_setup(admin, "secret") });
	ldap::store s(pool, people, ldap::named_by<&staff::uid>, { .schema_check = ldap::schema_check::on_first_use });
	const std::string name = unique("store");

	REQUIRE(finish(ioc, s.add(staff{ .uid = name, .cn = "Störe", .sn = "Typed", .mail = std::nullopt })).has_value());
	auto got = finish(ioc, s.get(name));
	REQUIRE(got.has_value());
	REQUIRE(got->has_value());
	CHECK((*got)->cn == "Störe");
	CHECK_FALSE((*got)->mail.has_value());

	REQUIRE(finish(ioc, s.modify(name, { ldap::replace<&staff::mail>(name + "@example.org") })).has_value());
	auto found = finish(ioc, s.search(ldap::filters::field<&staff::uid>() == name));
	REQUIRE(found.has_value());
	CHECK(found->is_success());
	REQUIRE(found->entries.size() == 1);
	CHECK(found->entries[0].dn == *s.dn_of(name));
	CHECK(found->entries[0].value.mail == name + "@example.org");

	auto pages = finish(ioc, s.search_paged(1, ldap::filters::field<&staff::uid>() == name));
	REQUIRE(pages.has_value());
	auto paged = finish(ioc, pages->next());
	REQUIRE(paged.has_value());
	REQUIRE(paged->has_value());
	CHECK((*paged)->value.cn == "Störe");
	auto paged_end = finish(ioc, pages->next());
	REQUIRE(paged_end.has_value());
	CHECK_FALSE(paged_end->has_value());
	auto streamed = finish(ioc, s.search_stream(ldap::filters::field<&staff::uid>() == name));
	REQUIRE(streamed.has_value());
	auto one = finish(ioc, streamed->next());
	REQUIRE(one.has_value());
	REQUIRE(one->has_value());
	CHECK((*one)->dn == *s.dn_of(name));
	auto stream_end = finish(ioc, streamed->next());
	REQUIRE(stream_end.has_value());
	CHECK_FALSE(stream_end->has_value());

	// A naming value that needs escaping in a DN, and non-ASCII.
	const std::string renamed = name + ", J\xC3\xBCrgen+1";
	REQUIRE(finish(ioc, s.rename(name, renamed)).has_value());
	auto old_name = finish(ioc, s.get(name));
	REQUIRE(old_name.has_value());
	CHECK_FALSE(old_name->has_value());
	auto new_name = finish(ioc, s.get(renamed));
	REQUIRE(new_name.has_value());
	REQUIRE(new_name->has_value());
	CHECK((*new_name)->uid == renamed);// the old RDN's value was removed
	CHECK((*new_name)->cn == "Störe");

	ldap::store groups(pool, ldap::dn{ "ou=groups,dc=example,dc=org" }, ldap::named_by<&staff::uid>);
	REQUIRE(finish(ioc, s.move(renamed, groups)).has_value());
	auto moved = finish(ioc, groups.get(renamed));
	REQUIRE(moved.has_value());
	REQUIRE(moved->has_value());
	auto left = finish(ioc, s.get(renamed));
	REQUIRE(left.has_value());
	CHECK_FALSE(left->has_value());
	auto not_there = finish(ioc, s.move(renamed, groups.base()));// not under s's base any more
	REQUIRE_FALSE(not_there.has_value());
	CHECK(not_there.error().code == ldap::errc::no_such_object);
	REQUIRE(finish(ioc, groups.move(renamed, people)).has_value());
	REQUIRE(finish(ioc, s.rename(renamed, name)).has_value());

	REQUIRE(finish(ioc, s.remove(name)).has_value());
	auto gone = finish(ioc, s.get(name));
	REQUIRE(gone.has_value());
	CHECK_FALSE(gone->has_value());
}

namespace {

struct contact
{
	std::string uid;
	std::string cn;
	std::string sn;
	std::optional<std::string> mail;
	std::vector<std::string> telephone;
	std::vector<std::string> description;
};

}// namespace

template<>
constexpr auto ldap::schema<contact> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&contact::uid>("uid"),
  ldap::field<&contact::cn>("cn"),
  ldap::field<&contact::sn>("sn"),
  ldap::field<&contact::mail>("mail"),
  ldap::field<&contact::telephone>("telephoneNumber"),
  ldap::field<&contact::description>("description"));

TEST_CASE("integration: store::update sends only what differs", "[integration][store][update]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	ldap::store s(c, people, ldap::named_by<&contact::uid>, { .schema_check = ldap::schema_check::on_first_use });
	const std::string name = unique("update");
	REQUIRE(finish(ioc,
	  s.add(contact{ .uid = name,
		.cn = "Update",
		.sn = "Typed",
		.mail = name + "@example.org",
		.telephone = { "+1 555 0100", "+1 555 0101" },
		.description = { "Foo", "bar" } }))
		.has_value());
	auto found = finish(ioc, s.search(ldap::filters::field<&contact::uid>() == name));
	REQUIRE(found.has_value());
	REQUIRE(found->entries.size() == 1);
	const ldap::record<contact> original = found->entries[0];

	contact changed = original.value;
	changed.cn = "Upd\xC3\xA4ted";
	changed.mail.reset();
	changed.telephone = { "+1 555 0101", "+1 555 0102" };
	// The same value under caseIgnoreMatch: deleted, then added again.
	changed.description = { "foo", "bar" };
	auto r = finish(ioc, s.update(original, changed));
	if (!r) {
		FAIL(r.error().message());
	}
	CHECK(r->has_value());
	auto got = finish(ioc, s.get(name));
	REQUIRE(got.has_value());
	REQUIRE(got->has_value());
	CHECK((*got)->cn == "Upd\xC3\xA4ted");
	CHECK_FALSE((*got)->mail.has_value());
	auto phones = (*got)->telephone;
	std::ranges::sort(phones);
	CHECK(phones == std::vector<std::string>{ "+1 555 0101", "+1 555 0102" });
	auto descriptions = (*got)->description;
	std::ranges::sort(descriptions);
	CHECK(descriptions == std::vector<std::string>{ "bar", "foo" });

	auto unchanged = finish(ioc, s.update(**got, **got));
	REQUIRE(unchanged.has_value());
	CHECK_FALSE(unchanged->has_value());
	contact cleared = **got;
	cleared.telephone.clear();
	cleared.description.clear();
	REQUIRE(finish(ioc, s.update(**got, cleared)).has_value());
	auto after = finish(ioc, s.get(name));
	REQUIRE(after.has_value());
	REQUIRE(after->has_value());
	CHECK((*after)->telephone.empty());
	CHECK((*after)->description.empty());

	contact renamed = cleared;
	renamed.uid = name + "-r";
	auto refused = finish(ioc, s.update(cleared, renamed));
	REQUIRE_FALSE(refused.has_value());
	CHECK(refused.error().code == ldap::client_errc::naming_value_changed);
	REQUIRE(finish(ioc, s.remove(name)).has_value());
}

namespace {

struct posix_user
{
	std::string uid;
	std::string cn;
	std::string sn;
	std::int64_t uid_number = 0;
	std::int64_t gid_number = 0;
	std::string home_directory;
	std::optional<std::string> login_shell;
};

}// namespace

template<>
constexpr auto ldap::schema<posix_user> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::auxiliary_class("posixAccount", "shadowAccount"),
  ldap::field<&posix_user::uid>("uid"),
  ldap::field<&posix_user::cn>("cn"),
  ldap::field<&posix_user::sn>("sn"),
  ldap::field<&posix_user::uid_number>("uidNumber"),
  ldap::field<&posix_user::gid_number>("gidNumber"),
  ldap::field<&posix_user::home_directory>("homeDirectory"),
  ldap::field<&posix_user::login_shell>("loginShell"));

TEST_CASE("integration: a store adds auxiliary object classes", "[integration][store][auxiliary]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	draining_context ioc;
	auto c = open_admin(ioc);
	auto schema = finish(ioc, ldap::load_schema(c));
	REQUIRE(schema.has_value());
	const auto report = ldap::validate<posix_user>(*schema);
	INFO(report.to_string());
	CHECK(report.ok());
	CHECK(std::ranges::none_of(report.issues, [](const auto &i) {
		return i.what == ldap::schema_issue::kind::must_attribute_not_mapped
			   || i.what == ldap::schema_issue::kind::not_auxiliary;
	}));

	ldap::store s(c, people, ldap::named_by<&posix_user::uid>, { .schema_check = ldap::schema_check::on_first_use });
	const std::string name = unique("aux");
	auto added = finish(ioc,
	  s.add(posix_user{ .uid = name,
		.cn = "Auxiliary",
		.sn = "Posix",
		.uid_number = 7001,
		.gid_number = 100,
		.home_directory = "/home/" + name,
		.login_shell = std::nullopt }));
	if (!added) {
		FAIL(added.error().message());
	}
	auto read = finish(ioc,
	  c.search({ .base = *s.dn_of(name), .scope = ldap::search_scope::base_object, .attributes = { "objectClass" } }));
	REQUIRE(read.has_value());
	REQUIRE(read->entries.size() == 1);
	REQUIRE(read->entries[0].find("objectClass") != nullptr);
	auto classes = *read->entries[0].find("objectClass");
	std::ranges::sort(classes);
	CHECK(classes == ldap::string_list{ "inetOrgPerson", "posixAccount", "shadowAccount" });

	auto got = finish(ioc, s.get(name));
	REQUIRE(got.has_value());
	REQUIRE(got->has_value());
	CHECK((*got)->home_directory == "/home/" + name);
	auto found = finish(ioc, s.search(ldap::filters::field<&posix_user::uid_number>() == 7001));
	REQUIRE(found.has_value());
	REQUIRE(found->entries.size() == 1);
	CHECK(found->entries[0].value.uid == name);
	REQUIRE(finish(ioc, s.remove(name)).has_value());
}

TEST_CASE("integration: ldap::client replaces a connection the server dropped", "[integration][client]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	draining_context ioc;
	relay r(ioc, *server->port());
	{
		auto u = ldap::url::parse(r.url());
		REQUIRE(u.has_value());
		ldap::client pool(ioc,
		  { .servers = { *u },
			.connection = trusting(),
			.setup = ldap::simple_bind_setup(admin, "secret"),
			.idle_check = std::chrono::milliseconds(0) });
		{
			auto l = finish(ioc, pool.acquire());
			REQUIRE(l.has_value());
			CHECK(finish(ioc, ldap::who_am_i(*(*l))) == "dn:cn=admin,dc=example,dc=org");
		}
		r.cut(0);
		{
			// The idle check finds the connection dead: a new one, set up again.
			auto l = finish(ioc, pool.acquire());
			REQUIRE(l.has_value());
			CHECK(r.relayed() == 2);
			CHECK(finish(ioc, ldap::who_am_i(*(*l))) == "dn:cn=admin,dc=example,dc=org");
			auto entries = finish(ioc, (*l)->search({ .base = people, .scope = ldap::search_scope::base_object }));
			REQUIRE(entries.has_value());
			CHECK(entries->entries.size() == 1);
		}
		CHECK(pool.connections() == 1);
	}
	r.shut_down();
	drive(ioc);
}

// ---------------------------------------------------------------- threads

namespace {

// Searches, compares and an add / modify / delete of an entry of its own,
// `rounds` times, on `d` (a connection or a client).
template<class D> auto threaded_worker(D &d, std::string name, int rounds, std::atomic<int> &failed) -> capy::task<void>
{
	const ldap::dn entry = *ldap::dn::parse("uid=" + name + ",ou=people,dc=example,dc=org");
	const auto check = [&failed](bool ok) {
		if (!ok) {
			++failed;
		}
	};
	for (int i = 0; i < rounds; ++i) {
		auto found = co_await d.search({ .base = people,
		  .scope = ldap::search_scope::single_level,
		  .filter = ldap::filters::attr("uid") == "user01" + std::to_string(i % 10) });
		check(found && found->entries.size() == 1);
		check((co_await d.add({ .entry = entry,
				 .attributes = { { "objectClass", { "inetOrgPerson" } },
				   { "uid", { name } },
				   { "cn", { "T" } },
				   { "sn", { "T" } } } }))
			.has_value());
		auto same = co_await d.compare({ .entry = entry, .attribute = "cn", .value = "T" });
		check(same && *same);
		check((co_await d.modify({ .object = entry, .changes = { ldap::mod::replace("cn", { "U" }) } })).has_value());
		check((co_await d.del({ .entry = entry })).has_value());
	}
}

// Reads through a store shared by every worker, and a search_stream.
auto store_worker(ldap::store<&staff::uid, ldap::client> &s, ldap::client &pool, int rounds, std::atomic<int> &failed)
  -> capy::task<void>
{
	for (int i = 0; i < rounds; ++i) {
		auto got = co_await s.get("user01" + std::to_string(i % 10));
		if (!got || !got->has_value()) {
			++failed;
		}
		auto stream = co_await pool.search_stream({ .base = people,
		  .scope = ldap::search_scope::single_level,
		  .filter = ldap::filters::attr("uid") == "user010" });
		std::size_t n = 0;
		if (stream) {
			while (true) {
				auto e = co_await stream->next();
				if (!e || !*e) {
					if (!e) {
						++failed;
					}
					break;
				}
				++n;
			}
		}
		if (n != 1) {
			++failed;
		}
	}
}

void run_threaded(corosio::io_context &ioc, std::vector<capy::task<void>> tasks)
{
	std::latch done(static_cast<std::ptrdiff_t>(tasks.size()));
	std::optional<capy::work_guard<corosio::io_context::executor_type>> guard(std::in_place, ioc.get_executor());
	for (auto &t : tasks) {
		capy::run_async(
		  ioc.get_executor(),
		  [&done] { done.count_down(); },
		  [&done](const std::exception_ptr &) { done.count_down(); })(std::move(t));
	}
	constexpr int pool_threads = 4;
	std::vector<std::thread> threads;
	threads.reserve(pool_threads);
	for (int i = 0; i < pool_threads; ++i) {
		threads.emplace_back([&ioc] { ioc.run(); });
	}
	done.wait();
	guard.reset();// run() returns once no work is left
	for (auto &t : threads) {
		t.join();
	}
	ioc.restart();
}

}// namespace

TEST_CASE("integration: one connection, one client and one store from several threads", "[integration][threads]")
{
	if (!have_slapd()) {
		SKIP("no slapd: run under run_slapd.sh");
	}
	constexpr int workers = 8;
	constexpr int rounds = 10;
	std::atomic<int> failed = 0;
	draining_context ioc;
	auto c = open_admin(ioc);
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	ldap::client pool(ioc,
	  { .servers = { *server },
		.connection = trusting(),
		.setup = ldap::simple_bind_setup(admin, "secret"),
		.max_connections = 3 });
	ldap::store staffs(pool, people, ldap::named_by<&staff::uid>, { .schema_check = ldap::schema_check::on_first_use });
	std::vector<capy::task<void>> tasks;
	for (int i = 0; i < workers; ++i) {
		tasks.push_back(threaded_worker(c, unique("thc"), rounds, failed));
		tasks.push_back(threaded_worker(pool, unique("thp"), rounds, failed));
		tasks.push_back(store_worker(staffs, pool, rounds, failed));
	}
	run_threaded(ioc, std::move(tasks));
	CHECK(failed == 0);
	CHECK(c.is_open());
	CHECK(pool.connections() <= 3);
}
