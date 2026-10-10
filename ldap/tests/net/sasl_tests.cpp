// SASL binds (connection::sasl_bind) against the scripted mock server.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <optional>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;

namespace {

ldap::message sasl_resp(std::int32_t id, std::int32_t code, std::optional<std::string_view> creds = {})
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ code }, creds } };
}

ldap::message sasl_req(std::int32_t id, std::string_view mech, std::optional<std::string_view> creds)
{
	return ldap::message{ id, ldap::bind_request{ 3, "", ldap::sasl_auth{ mech, creds } } };
}

// A made-up multi-step mechanism: sends "hello", then answers each
// challenge with "re:<challenge>", and records the final server creds.
class echo_mechanism final : public ldap::sasl_mechanism
{
  public:
	std::vector<std::string> challenges;
	std::optional<std::string> final_creds;
	bool reject_final = false;

	std::string_view name() const noexcept override { return "X-ECHO"; }
	ldap::result<std::optional<std::string>> start() override
	{
		challenges.clear();
		return std::optional<std::string>("hello");
	}
	ldap::result<std::optional<std::string>> step(std::optional<std::string_view> c) override
	{
		challenges.emplace_back(c.value_or("<none>"));
		if (c == "bad") return ldap::fail(ldap::client_errc::decode_error, "X-ECHO: bad challenge");
		return std::optional<std::string>("re:" + std::string(c.value_or("")));
	}
	ldap::result<void> complete(std::optional<std::string_view> c) override
	{
		if (c) final_creds.emplace(*c);
		if (reject_final) return ldap::fail(ldap::client_errc::decode_error, "X-ECHO: server signature mismatch");
		return {};
	}
};

}// namespace

TEST_CASE("sasl: EXTERNAL in one step", "[net][sasl]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 0) }), answer({ sasl_resp(2, 0) }) });
	ldap::sasl_external plain;
	REQUIRE(m.run(m.conn.sasl_bind(plain)).has_value());
	ldap::sasl_external as_other("dn:uid=jdoe,ou=people,dc=example,dc=org");
	REQUIRE(m.run(m.conn.sasl_bind(as_other)).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0] == sasl_req(1, "EXTERNAL", ""));
	CHECK(m.log.received[1] == sasl_req(2, "EXTERNAL", "dn:uid=jdoe,ou=people,dc=example,dc=org"));
}

TEST_CASE("sasl: failure codes keep the connection usable", "[net][sasl]")
{
	mock_ldap m;
	m.serve(
	  { answer({ ldap::message{ 1, ldap::bind_response{ ldap::ldap_result{ 48, "", "no client certificate" } } } }),
		answer({ sasl_resp(2, 7) }),
		answer({ bind_resp(3) }) });
	ldap::sasl_external mech;
	auto r = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::inappropriate_authentication);
	CHECK(r.error().code == ldap::cond::auth_failed);
	CHECK(r.error().diagnostic == "no client certificate");
	CHECK(r.error().context == "sasl bind EXTERNAL");
	auto unsupported = m.run(m.conn.sasl_bind(mech));
	REQUIRE_FALSE(unsupported.has_value());
	CHECK(unsupported.error().code == ldap::errc::auth_method_not_supported);
	CHECK(m.conn.is_open());
	CHECK(m.run(m.conn.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret")).has_value());
	m.check_server();
}

TEST_CASE("sasl: a multi-step exchange with server credentials", "[net][sasl]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "c1") }),
	  answer({ sasl_resp(2, 14) }),
	  answer({ sasl_resp(3, 0, "server-final") }) });
	echo_mechanism mech;
	REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
	CHECK(mech.challenges == std::vector<std::string>{ "c1", "<none>" });
	CHECK(mech.final_creds == "server-final");
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
	CHECK(m.log.received[1] == sasl_req(2, "X-ECHO", "re:c1"));
	CHECK(m.log.received[2] == sasl_req(3, "X-ECHO", "re:"));
}

TEST_CASE("sasl: mechanism errors abort the bind", "[net][sasl]")
{
	SECTION("a challenge the mechanism rejects")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "bad") }) });
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind X-ECHO: X-ECHO: bad challenge");
		CHECK(m.conn.is_open());
	}
	SECTION("final server credentials the mechanism rejects")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 0, "forged") }) });
		echo_mechanism mech;
		mech.reject_final = true;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("server signature mismatch"));
	}
	SECTION("EXTERNAL given a challenge")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "what?") }) });
		ldap::sasl_external mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("EXTERNAL has a single step"));
	}
	SECTION("a server that never finishes")
	{
		mock_ldap m;
		std::vector<step> script;
		for (std::int32_t id = 1; id <= 32; ++id) script.push_back(answer({ sasl_resp(id, 14, "more") }));
		m.serve(script);
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("still in progress after 32 steps"));
		m.check_server();
	}
}

// RFC 4511 section 4.2.1: nothing is sent while a BindRequest is outstanding.
// A request started during a SASL exchange waits for all of its steps.
TEST_CASE("sasl: requests started during the exchange wait for its end", "[net][sasl][rfc]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "c1") }),
	  answer({ sasl_resp(3, 14) }),
	  answer({ sasl_resp(4, 0, "server-final") }),
	  answer({ done_msg(2) }) });
	echo_mechanism mech;
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.sasl_bind(mech), bind);
	spawn(m.ioc, m.conn.search({}), search);// id 2, held
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	CHECK(bind.get().has_value());
	CHECK(search.get().has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 4);
	CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
	CHECK(m.log.received[1] == sasl_req(3, "X-ECHO", "re:c1"));
	CHECK(m.log.received[2] == sasl_req(4, "X-ECHO", "re:"));
	CHECK(m.log.received[3].id == 2);
}
