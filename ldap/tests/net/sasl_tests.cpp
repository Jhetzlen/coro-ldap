// SASL binds (connection::sasl_bind) against the scripted mock server.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/sasl_scram.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"
#include "scram_test_access.hpp"

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

// The anonymous simple bind that aborts a SASL exchange (RFC 4511 section 4.2.1).
ldap::message abort_req(std::int32_t id)
{
	return ldap::message{ id, ldap::bind_request{ 3, "", ldap::simple_auth{ "" } } };
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
		m.serve({ answer({ sasl_resp(1, 14, "bad") }), answer({ bind_resp(2) }) });
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind X-ECHO: X-ECHO: bad challenge");
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
	SECTION("a server that refuses the abort")
	{
		// The server's state is unknown: the connection is closed, and the
		// mechanism's error is still the result.
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "bad") }), answer({ bind_resp(2, 1, "no") }) });
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context == "sasl bind X-ECHO: X-ECHO: bad challenge");
		CHECK_FALSE(m.conn.is_open());
		m.check_server();
		auto later = m.run(m.conn.who_am_i());
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::client_errc::not_connected);
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("could not be aborted"));
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
		// The server considers the connection bound: it is closed, and later
		// operations name the reason.
		CHECK_FALSE(m.conn.is_open());
		auto later = m.run(m.conn.who_am_i());
		REQUIRE_FALSE(later.has_value());
		CHECK(later.error().code == ldap::client_errc::not_connected);
		CHECK_THAT(std::string(later.error().context), ContainsSubstring("server signature mismatch"));
	}
	SECTION("EXTERNAL given a challenge")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, "what?") }), answer({ bind_resp(2) }) });
		ldap::sasl_external mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("EXTERNAL has a single step"));
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
	SECTION("a server that never finishes")
	{
		mock_ldap m;
		std::vector<step> script;
		for (std::int32_t id = 1; id <= 32; ++id) script.push_back(answer({ sasl_resp(id, 14, "more") }));
		script.push_back(answer({ bind_resp(33) }));
		m.serve(script);
		echo_mechanism mech;
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("still in progress after 32 steps"));
		m.check_server();
		REQUIRE(m.log.received.size() == 33);
		CHECK(m.log.received[32] == abort_req(33));
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

// RFC 4511 section 4.2.1: a client that gives up on a SASL exchange the
// server still considers in progress aborts it with another bind before
// anything else is sent (coro_http_client-f1e).
TEST_CASE("sasl: a failed exchange is aborted before held requests are sent", "[net][sasl][rfc]")
{
	mock_ldap m;
	m.serve({ answer({ sasl_resp(1, 14, "bad") }), answer({ bind_resp(3) }), answer({ done_msg(2) }) });
	echo_mechanism mech;
	outcome<ldap::result<void>> bind;
	outcome<ldap::result<std::pmr::vector<ldap::entry>>> search;
	spawn(m.ioc, m.conn.sasl_bind(mech), bind);
	spawn(m.ioc, m.conn.search({}), search);// id 2, held
	drive_until(m.ioc, [&] { return bind.done() && search.done(); });
	REQUIRE_FALSE(bind.get().has_value());
	CHECK(bind.get().error().context == "sasl bind X-ECHO: X-ECHO: bad challenge");
	CHECK(search.get().has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 3);
	CHECK(m.log.received[0] == sasl_req(1, "X-ECHO", "hello"));
	CHECK(m.log.received[1] == abort_req(3));
	CHECK(m.log.received[2].id == 2);
}

// SCRAM-SHA-256 with the RFC 7677 section 3 test vector (the mechanism's
// own tests are in sasl_scram_tests.cpp).
TEST_CASE("sasl: SCRAM-SHA-256 with the RFC 7677 test vector", "[net][sasl][scram][rfc]")
{
	constexpr std::string_view client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
	constexpr std::string_view server_first =
	  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
	constexpr std::string_view client_final =
	  "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
	constexpr std::string_view server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
	auto mech = ldap::detail::scram_test_access::with_nonce("user", "pencil", "", "rOprNGfwEbeRWgbNEkqO");

	SECTION("server-final-message with the success result")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }), answer({ sasl_resp(2, 0, server_final) }) });
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[0] == sasl_req(1, "SCRAM-SHA-256", client_first));
		CHECK(m.log.received[1] == sasl_req(2, "SCRAM-SHA-256", client_final));
	}
	SECTION("server-final-message as a last challenge")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }),
		  answer({ sasl_resp(2, 14, server_final) }),
		  answer({ sasl_resp(3, 0) }) });
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[2] == sasl_req(3, "SCRAM-SHA-256", ""));
	}
	SECTION("a server that does not prove it knows the password")
	{
		// Each time the server reported success: the connection is closed.
		auto refused = [&](std::vector<step> script, std::string_view why) {
			mock_ldap m;
			m.serve(std::move(script));
			auto r = m.run(m.conn.sasl_bind(mech));
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::unexpected_response);
			CHECK(std::string(r.error().context) == "sasl bind SCRAM-SHA-256: " + std::string(why));
			CHECK_FALSE(m.conn.is_open());
			m.check_server();
		};
		refused({ answer({ sasl_resp(1, 14, server_first) }), answer({ sasl_resp(2, 0) }) },
		  "the server reported success without a server signature (v=)");
		refused({ answer({ sasl_resp(1, 14, server_first) }),
				  answer({ sasl_resp(2, 0, "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=") }) },
		  "wrong server signature: the server could not be authenticated");
		refused({ answer({ sasl_resp(1, 0) }) },
		  "the server reported success before the exchange was complete (no server signature)");
	}
	SECTION("a wrong server signature as a challenge")
	{
		// The server has not reported success yet: the bind fails, the
		// connection is not closed.
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }),
		  answer({ sasl_resp(2, 14, "v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=") }),
		  answer({ bind_resp(3) }) });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().context
			  == "sasl bind SCRAM-SHA-256: wrong server signature: the server could not be authenticated");
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 3);
		CHECK(m.log.received[2] == abort_req(3));
	}
	SECTION("the server refuses the proof")
	{
		mock_ldap m;
		m.serve({ answer({ sasl_resp(1, 14, server_first) }),
		  answer({ ldap::message{ 2, ldap::bind_response{ ldap::ldap_result{ 49 }, "e=invalid-proof" } } }) });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK(r.error().code == ldap::cond::auth_failed);
		CHECK(m.conn.is_open());
	}
	SECTION("a server nonce that does not extend the client's")
	{
		mock_ldap m;
		m.serve(
		  { answer({ sasl_resp(1, 14, "r=forged,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") }), answer({ bind_resp(2) }) });
		auto r = m.run(m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("does not start with the client nonce"));
		CHECK(m.conn.is_open());
		m.check_server();
		REQUIRE(m.log.received.size() == 2);
		CHECK(m.log.received[1] == abort_req(2));
	}
}
