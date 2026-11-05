// change_password / reset_password (RFC 3062 password modify) against the
// scripted mock server: the requests sent, the bound user's own change, and
// the refusals before sending.
#include "jhetz/ldap/connection.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace ldap = jhetz::ldap;
using namespace jhetz::ldap::test;
using namespace std::literals;
using ldap::client_errc;

namespace {

const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
const std::string jdoe_context = "uid=jdoe,ou=people,dc=example,dc=org";
constexpr std::string_view old_pw = "Old-S3cret";
constexpr std::string_view new_pw = "New-S3cret";

auto extended_ok(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::extended_response{ ldap::ldap_result{ 0 } } };
}

// SEQUENCE { [0] jdoe, [1] old_pw, [2] new_pw } and SEQUENCE { [0] jdoe, [2] new_pw }.
const std::string change_value =
  "\x30\x3e\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x81\x0aOld-S3cret\x82\x0aNew-S3cret"s;
const std::string reset_value = "\x30\x32\x80\x24uid=jdoe,ou=people,dc=example,dc=org\x82\x0aNew-S3cret"s;

auto password_modify_request(std::int32_t id, const std::string &value) -> ldap::message
{
	return ldap::message{ id, ldap::extended_request{ ldap::password_modify_oid, value } };
}

// No password in the error, in any of its parts.
void check_no_password(const ldap::error &e)
{
	const std::string text(e.message());
	CHECK_FALSE(text.contains(old_pw));
	CHECK_FALSE(text.contains(new_pw));
}

}// namespace

TEST_CASE("change_password: RFC 3062 password modify, no root DSE read", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ extended_ok(1) }), answer({ extended_ok(2) }) });
	CHECK(m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw))).has_value());
	CHECK(m.run(m.conn.reset_password(jdoe, std::string(new_pw))).has_value());
	m.check_server();

	REQUIRE(m.log.received.size() == 2);
	CHECK(m.log.received[0] == password_modify_request(1, change_value));
	CHECK(m.log.received[1] == password_modify_request(2, reset_value));
}

TEST_CASE("change_password: the bound user's own, no userIdentity", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ extended_ok(1) }) });
	CHECK(m.run(m.conn.change_password({}, "o", "n")).has_value());
	m.check_server();
	REQUIRE(m.log.received.size() == 1);
	CHECK(m.log.received[0] == password_modify_request(1, "\x30\x06\x81\x01o\x82\x01n"s));
}

TEST_CASE("change_password: refused before sending", "[net][password]")
{
	mock_ldap m;
	m.serve({});
	const auto invalid = std::make_error_code(std::errc::invalid_argument);
	auto no_new = m.run(m.conn.change_password(jdoe, std::string(old_pw), ""));
	REQUIRE_FALSE(no_new.has_value());
	CHECK(no_new.error().code == invalid);
	CHECK(std::string(no_new.error().context) == "change password " + jdoe_context + ": empty new password");
	auto no_old = m.run(m.conn.change_password(jdoe, "", std::string(new_pw)));
	REQUIRE_FALSE(no_old.has_value());
	CHECK(no_old.error().code == invalid);
	CHECK(std::string(no_old.error().context)
		  == "change password " + jdoe_context + ": empty old password (reset_password() sets one without it)");
	auto reset = m.run(m.conn.reset_password(jdoe, ""));
	REQUIRE_FALSE(reset.has_value());
	CHECK(reset.error().code == invalid);
	CHECK(m.conn.is_open());
	m.check_server();
	CHECK(m.log.received.empty());

	ldap::connection none;
	auto closed = m.run(none.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(closed.has_value());
	CHECK(closed.error().code == client_errc::not_connected);
}

TEST_CASE("change_password: a server error", "[net][password]")
{
	mock_ldap m;
	m.serve({ answer({ ldap::message{ 1, ldap::extended_response{ ldap::ldap_result{ 49, "", "wrong" } } } }) });
	auto r = m.run(m.conn.change_password(jdoe, std::string(old_pw), std::string(new_pw)));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::errc::invalid_credentials);
	CHECK(std::string(r.error().context) == "change password " + jdoe_context + ": password modify (RFC 3062)");
	check_no_password(r.error());
	m.check_server();
}
