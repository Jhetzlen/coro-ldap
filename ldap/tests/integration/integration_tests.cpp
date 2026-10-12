// Integration tests against a real OpenLDAP slapd, started by
// run_slapd.sh (which sets the JHETZ_LDAP_IT_* variables):
//
//   ldap/tests/integration/run_slapd.sh ctest --test-dir build -L integration --output-on-failure
//
// Without those variables every test is skipped (ctest reports the run as
// skipped). The data is make_fixture.py's.
#include "../net/net_test_support.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/sasl_scram.hpp"
#include "jhetz/ldap/sync.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <stop_token>
#include <string>
#include <unistd.h>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

std::string env(const char *name)
{
	const char *v = std::getenv(name);
	return v == nullptr ? std::string() : std::string(v);
}

#define REQUIRE_SLAPD()                                                                  \
	do {                                                                                 \
		if (env("JHETZ_LDAP_IT_LDAP").empty()) SKIP("no slapd: run under run_slapd.sh"); \
	} while (false)

const ldap::dn admin{ "cn=admin,dc=example,dc=org" };
const ldap::dn people{ "ou=people,dc=example,dc=org" };

ldap::connection_options trusting(ldap::connection_options o = {})
{
	o.tls.ca_file = env("JHETZ_LDAP_IT_CA");
	o.timeout = std::chrono::seconds(10);
	o.operation_timeout = std::chrono::seconds(10);
	return o;
}

ldap::connection open(corosio::io_context &ioc, const std::string &url, const ldap::connection_options &o = trusting())
{
	auto u = ldap::url::parse(url);
	REQUIRE(u.has_value());
	auto c = finish(ioc, ldap::connect(ioc, *u, o));
	if (!c) FAIL("connect " << url << ": " << c.error().message());
	return std::move(*c);
}

ldap::connection open_admin(corosio::io_context &ioc)
{
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	auto b = finish(ioc, c.simple_bind(admin, "secret"));
	if (!b) FAIL("bind: " << b.error().message());
	return c;
}

// SCRAM-SHA-256 that gives up on the server's first message, as on one it
// refuses: the client fails a step while slapd waits for the next one.
class scram_giving_up final : public ldap::sasl_mechanism
{
  public:
	std::string_view name() const noexcept override { return scram.name(); }
	ldap::result<std::optional<std::string>> start() override { return scram.start(); }
	ldap::result<std::optional<std::string>> step(std::optional<std::string_view>) override
	{
		return ldap::fail(ldap::client_errc::unexpected_response, "giving up");
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
	  : ioc_(ioc), config_(open(ioc, env("JHETZ_LDAP_IT_LDAP")))
	{
		auto b = finish(ioc_, config_.simple_bind(config_dn, "secret"));
		if (!b) FAIL("bind as cn=config: " << b.error().message());
		auto m = finish(ioc_,
		  config_.modify({ .object = config_dn, .changes = { ldap::mod::add("olcDisallows", { "bind_anon" }) } }));
		if (!m) FAIL("disallow bind_anon: " << m.error().message());
	}

	anonymous_binds_disallowed(const anonymous_binds_disallowed &) = delete;
	anonymous_binds_disallowed &operator=(const anonymous_binds_disallowed &) = delete;

	// The failure is reported once, after the attempt. FAIL_CHECK throws
	// when Catch2 aborts the run (-a, -x): that only ends the run, as asked,
	// so it is caught rather than left to escape the destructor.
	~anonymous_binds_disallowed()
	{
		bool restored = false;
		std::string why;
		try {
			auto m = finish(ioc_,
			  config_.modify(
				{ .object = config_dn, .changes = { ldap::mod::remove("olcDisallows", { "bind_anon" }) } }));
			restored = m.has_value();
			if (!m) why = ": " + std::string(m.error().message());
		} catch (...) {}
		if (restored) return;
		try {
			FAIL_CHECK("could not allow bind_anon again, later tests run with it disallowed" << why);
		} catch (...) {}
	}

  private:
	inline static const ldap::dn config_dn{ "cn=config" };
	corosio::io_context &ioc_;
	ldap::connection config_;
};

// A unique RDN value per test run, so runs against the same server do not collide.
std::string unique(std::string_view stem)
{
	static int counter = 0;
	return std::string(stem) + "-" + std::to_string(::getpid()) + "-" + std::to_string(counter++);
}

}// namespace

// ---------------------------------------------------------------- transports and binds

TEST_CASE("integration: every transport", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	SECTION("ldap://")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		CHECK_FALSE(c.is_tls());
		CHECK(finish(ioc, c.simple_bind(admin, "secret")).has_value());
		CHECK(finish(ioc, c.who_am_i()) == "dn:cn=admin,dc=example,dc=org");
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
		CHECK(finish(ioc, c.who_am_i()) == "");// anonymous
	}
}

TEST_CASE("integration: bind success and failure", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	auto bad = finish(ioc, c.simple_bind(admin, "wrong"));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::errc::invalid_credentials);
	CHECK(finish(ioc, c.simple_bind(ldap::dn{ "uid=user007,ou=people,dc=example,dc=org" }, "pw-user007")).has_value());
	CHECK(finish(ioc, c.who_am_i()) == "dn:uid=user007,ou=people,dc=example,dc=org");
	CHECK(finish(ioc, c.unbind()).has_value());
}

TEST_CASE("integration: SASL EXTERNAL", "[integration][sasl]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	SECTION("over ldapi:// (peer credentials)")
	{
		auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPI"));
		ldap::sasl_external mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE(r.has_value());
		CHECK_THAT(finish(ioc, c.who_am_i()).value(), ContainsSubstring("cn=peercred,cn=external,cn=auth"));
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
		CHECK(finish(ioc, c.who_am_i()) == "dn:cn=client,dc=example,dc=org");
	}
}

TEST_CASE("integration: SASL SCRAM-SHA-256", "[integration][sasl][scram]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	// slapd offers SCRAM-SHA-256 only with cyrus-sasl's scram plugin installed.
	auto dse =
	  finish(ioc, c.search({ .scope = ldap::search_scope::base_object, .attributes = { "supportedSASLMechanisms" } }));
	REQUIRE(dse.has_value());
	REQUIRE(dse->size() == 1);
	const auto *mechs = (*dse)[0].find("supportedSASLMechanisms");
	if (mechs == nullptr || std::ranges::find(*mechs, "SCRAM-SHA-256") == mechs->end())
		SKIP("slapd does not offer SCRAM-SHA-256 (cyrus-sasl scram plugin not installed)");

	SECTION("the right password")
	{
		ldap::sasl_scram_sha256 mech("user007", "pw-user007");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE(r.has_value());
		CHECK(finish(ioc, c.who_am_i()) == "dn:uid=user007,ou=people,dc=example,dc=org");
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
		CHECK(finish(ioc, c.who_am_i()) == "dn:uid=j\xC3\xB6rg,ou=people,dc=example,dc=org");
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
		CHECK(finish(ioc, c.who_am_i()) == "");
	}
	SECTION("a step the client fails mid-exchange")
	{
		// RFC 4511 section 4.2.1: the exchange is aborted, so slapd accepts
		// other operations again (coro_http_client-f1e).
		scram_giving_up mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind SCRAM-SHA-256: giving up");
		REQUIRE(c.is_open());
		auto again =
		  finish(ioc, c.search({ .scope = ldap::search_scope::base_object, .attributes = { "namingContexts" } }));
		REQUIRE(again.has_value());
		CHECK(again->size() == 1);
		CHECK(finish(ioc, c.who_am_i()) == "");
	}
	SECTION("a step the client fails, and a server that refuses the abort")
	{
		// slapd ends the exchange before it refuses the anonymous bind that
		// aborts it (inappropriateAuthentication): the connection stays
		// open and anonymous, and a bind then succeeds (coro_http_client-f1e.1).
		// bind_anon refuses only anonymous binds, not anonymous operations:
		// the search succeeds only if the exchange ended (a server still in
		// it would answer operationsError).
		const anonymous_binds_disallowed disallowed(ioc);
		scram_giving_up mech;
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind SCRAM-SHA-256: giving up");
		REQUIRE(c.is_open());
		auto again =
		  finish(ioc, c.search({ .scope = ldap::search_scope::base_object, .attributes = { "namingContexts" } }));
		REQUIRE(again.has_value());
		CHECK(again->size() == 1);
		CHECK(finish(ioc, c.who_am_i()) == "");
		// The abort was refused: so is the same bind, made directly.
		auto anonymous = finish(ioc, c.simple_bind({}, ""));
		REQUIRE_FALSE(anonymous.has_value());
		CHECK(anonymous.error().code == ldap::errc::inappropriate_authentication);
		REQUIRE(c.is_open());
		REQUIRE(
		  finish(ioc, c.simple_bind(ldap::dn{ "uid=user007,ou=people,dc=example,dc=org" }, "pw-user007")).has_value());
		CHECK(finish(ioc, c.who_am_i()) == "dn:uid=user007,ou=people,dc=example,dc=org");
	}
}

// ---------------------------------------------------------------- search

TEST_CASE("integration: plain, streaming and paged searches", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	const ldap::search_params all_users{ .base = people,
		.filter = ldap::filters::attr("objectClass") == "posixAccount",
		.attributes = { "uid", "uidNumber" } };

	auto plain = finish(ioc, c.search(all_users));
	REQUIRE(plain.has_value());
	CHECK(plain->size() == 250);

	auto s = finish(ioc, c.search_stream(all_users));
	REQUIRE(s.has_value());
	std::size_t streamed = 0;
	while (true) {
		auto e = finish(ioc, s->next());
		REQUIRE(e.has_value());
		if (!*e) break;
		++streamed;
	}
	CHECK(streamed == 250);

	auto p = finish(ioc, c.search_paged(all_users, 40));
	REQUIRE(p.has_value());
	std::size_t paged = 0;
	while (true) {
		auto e = finish(ioc, p->next());
		REQUIRE(e.has_value());
		if (!*e) break;
		++paged;
	}
	CHECK(paged == 250);
	CHECK(p->pages() == 7);

	// The server's size limit (1000) is not hit, a client one is.
	auto limited = finish(ioc, c.search({ .base = people, .size_limit = 5 }));
	REQUIRE_FALSE(limited.has_value());
	CHECK(limited.error().code == ldap::errc::size_limit_exceeded);
}

namespace {

// One page of `params` by hand (a search with the paged control): its
// entry count and the cookie the server returned.
struct manual_page
{
	std::size_t entries = 0;
	std::string cookie{};
};

ldap::result<manual_page>
  page_by_hand(corosio::io_context &ioc, ldap::connection &c, ldap::search_params params, ldap::paged control)
{
	params.controls = { std::move(control) };
	auto s = finish(ioc, c.search_stream(std::move(params)));
	if (!s) return std::unexpected(std::move(s.error()));
	manual_page out;
	while (true) {
		auto e = finish(ioc, s->next());
		if (!e) return std::unexpected(std::move(e.error()));
		if (!*e) break;
		++out.entries;
	}
	for (const auto &ctl : s->controls())
		if (ctl.type == ldap::paged_results_oid) out.cookie = std::string(ldap::decode_paged_results(ctl)->cookie);
	return out;
}

}// namespace

TEST_CASE("integration: a paged search stopped between pages sends a release", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
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
		auto p = finish(ioc, c.search_paged(all_users, 40));
		REQUIRE(p.has_value());
		for (int i = 0; i < 40; ++i) {
			auto e = finish(ioc, p->next());
			REQUIRE(e.has_value());
			REQUIRE(e->has_value());
		}
		drive_until(ioc, [&c] { return c.outstanding() == 0; });
		CHECK(p->pages() == 1);
	}
	CHECK(c.outstanding() == 1);// the release
	REQUIRE(finish(ioc, c.start_tls(trusting().tls)).has_value());
	CHECK(c.outstanding() == 0);
	CHECK(c.is_tls());
	auto all = finish(ioc, c.search(all_users));
	REQUIRE(all.has_value());
	CHECK(all->size() == 250);
}

TEST_CASE("integration: large and binary values", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAPS"));
	auto big = finish(ioc,
	  c.search({ .base = ldap::dn{ "cn=big,ou=groups,dc=example,dc=org" }, .scope = ldap::search_scope::base_object }));
	REQUIRE(big.has_value());
	REQUIRE(big->size() == 1);
	CHECK((*big)[0].find("member")->size() == 2000);

	auto photo = run(ioc,
	  c.search({ .base = ldap::dn{ "uid=photo,ou=people,dc=example,dc=org" },
		.scope = ldap::search_scope::base_object,
		.attributes = { "jpegPhoto" } }));
	REQUIRE(photo.has_value());
	const auto &bytes = (*photo)[0].find("jpegPhoto")->front();
	REQUIRE(bytes.size() == 10000);
	bool same = true;
	for (std::size_t i = 0; i < bytes.size(); ++i) same = same && static_cast<unsigned char>(bytes[i]) == i % 251;
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
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"), trusting({ .schema_check = ldap::schema_check::on_first_use }));
	auto s = finish(ioc, c.load_schema());
	REQUIRE(s.has_value());
	CHECK(s->attribute_count() > 100);
	CHECK(s->skipped() == 0);// every SYNTAX a numeric OID (RFC 4512 noidlen)
	const auto report = ldap::validate<person>(*s);
	INFO(report.to_string());
	CHECK(report.ok());

	auto r = finish(
	  ioc, c.search_as<person>({ .base = people, .filter = ldap::filters::field<&person::uid_number>() >= 10245 }));
	REQUIRE(r.has_value());
	REQUIRE(r->size() == 5);
	CHECK((*r)[0].mail.has_value());
	CHECK((*r)[0].created.time_since_epoch().count() > 0);
}

// ---------------------------------------------------------------- writes

TEST_CASE("integration: add, modify, compare, rename and delete", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
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

TEST_CASE("integration: assertion and pre/post-read controls", "[integration][controls]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
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

TEST_CASE("integration: server side sort", "[integration][controls]")
{
	REQUIRE_SLAPD();
	if (env("JHETZ_LDAP_IT_SORT").empty()) SKIP("slapd without the sssvlv overlay");
	corosio::io_context ioc;
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
		if (!*e) break;
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
	REQUIRE(by_sn->size() == 250);
	CHECK(by_sn->front().find("sn")->front() == "249");
	CHECK(by_sn->back().find("sn")->front() == "000");

	// cn has no ORDERING rule: a critical sort by it fails the search.
	auto refused = finish(ioc,
	  c.search({ .base = people,
		.controls = { ldap::server_side_sort{ .keys = { { .attribute = "cn" } }, .critical = true } } }));
	REQUIRE_FALSE(refused.has_value());
	INFO(refused.error().message());
	CHECK(refused.error().code.category() == ldap::result_category());
}

TEST_CASE("integration: password modify (RFC 3062)", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
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
	auto set = finish(ioc, c.password_modify({ .user = who, .new_password = "first" }));
	REQUIRE(set.has_value());
	CHECK_FALSE(set->has_value());
	{
		auto u = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
		CHECK(finish(ioc, u.simple_bind(entry, "first")).has_value());
		// This server's ACL (read only) refuses users their own change.
		auto own = finish(ioc, u.password_modify({ .old_password = "first", .new_password = "second" }));
		REQUIRE_FALSE(own.has_value());
		CHECK(own.error().code == ldap::errc::insufficient_access_rights);
		CHECK(own.error().context == "password modify");
	}
	auto generated = finish(ioc, c.password_modify({ .user = who }));
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

// ---------------------------------------------------------------- sync connection

TEST_CASE("integration: the sync connection", "[integration][sync]")
{
	REQUIRE_SLAPD();
	SECTION("StartTLS, then writes")
	{
		ldap::sync::connection c(trusting());
		auto u = env("JHETZ_LDAP_IT_LDAP");
		u.replace(u.find("127.0.0.1"), 9, "localhost");
		REQUIRE(c.connect(*ldap::url::parse(u)).has_value());
		CHECK_FALSE(c.is_tls());
		net::tls_options tls;
		tls.ca_file = env("JHETZ_LDAP_IT_CA");
		REQUIRE(c.start_tls(std::move(tls)).has_value());
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
		auto pw = c.password_modify({ .user = std::string(entry.to_string()) });
		REQUIRE(pw.has_value());
		CHECK(pw->has_value());
		const ldap::dn renamed = *ldap::dn::parse("uid=" + name + "-r,ou=people,dc=example,dc=org");
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
		ldap::sync::connection c(trusting());
		REQUIRE(c.connect(*ldap::url::parse(env("JHETZ_LDAP_IT_LDAPI"))).has_value());
		ldap::sasl_external mech;
		REQUIRE(c.sasl_bind(mech).has_value());
		CHECK_THAT(c.who_am_i().value(), ContainsSubstring("cn=peercred,cn=external,cn=auth"));
		c.close();
		CHECK_FALSE(c.is_open());
	}
}

// ---------------------------------------------------------------- cancellation

TEST_CASE("integration: cancellation mid-search", "[integration]")
{
	REQUIRE_SLAPD();
	corosio::io_context ioc;
	auto c = open(ioc, env("JHETZ_LDAP_IT_LDAP"));
	{
		auto s = finish(ioc, c.search_stream({ .base = people }));
		REQUIRE(s.has_value());
		auto first = finish(ioc, s->next());
		REQUIRE(first.has_value());
		REQUIRE(first->has_value());
	}// abandoned with entries still coming
	std::stop_source stop;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> cancelled;
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
	CHECK(after->size() == 1);
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
capy::task<void> proxy(corosio::io_context &ioc, corosio::tcp_acceptor &acc, std::uint16_t server_port, fault f)
{
	auto [aec, client] = co_await acc.accept();
	if (aec) co_return;
	corosio::tcp_socket server(ioc);
	auto [cec] = co_await server.connect(corosio::endpoint(corosio::ipv4_address::loopback(), server_port));
	if (cec) co_return;
	net::transport to_client = net::transport::wrap(std::move(client), "proxy client");
	net::transport to_server = net::transport::wrap(std::move(server), "proxy server");
	net::read_buffer from_client, from_server;
	// One request in, one (broken) answer out.
	auto req = co_await net::read_frame(to_client, from_client, ldap::ber::default_max_message_size);
	if (!req) co_return;
	if (auto w = co_await net::write_bytes(to_server, from_client.data().first(*req)); !w) co_return;
	auto resp = co_await net::read_frame(to_server, from_server, ldap::ber::default_max_message_size);
	if (!resp) co_return;
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
	REQUIRE_SLAPD();
	const auto server = ldap::url::parse(env("JHETZ_LDAP_IT_LDAP"));
	REQUIRE(server.has_value());
	const struct
	{
		const char *name;
		fault f;
		std::error_code code;
	} cases[] = {
		{ "truncated PDU", fault::truncate, capy::error::eof },
		{ "oversized length", fault::oversized, ldap::client_errc::message_too_large },
		{ "closed mid-response", fault::close, capy::error::eof },
	};
	for (const auto &c : cases) {
		DYNAMIC_SECTION(c.name)
		{
			corosio::io_context ioc;
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
			CHECK(later.error().code == ldap::client_errc::not_connected);
			conn.close();
			drive(ioc);
			CHECK(p.done());
		}
	}
}
