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
	SECTION("a wrong password")
	{
		ldap::sasl_scram_sha256 mech("user007", "wrong");
		auto r = finish(ioc, c.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK(c.is_open());
		CHECK(finish(ioc, c.who_am_i()) == "");
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
