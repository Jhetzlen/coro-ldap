#include "jhetz/ldap/error.hpp"

#include <catch2/catch_test_macros.hpp>

#include <iterator>
#include <string>
#include <system_error>

namespace ldap = jhetz::ldap;

// All 38 non-success resultCodes of RFC 4511 section 4.1.9 / Appendix A.
TEST_CASE("ldap::errc keeps RFC 4511 resultCode numbers", "[error]")
{
	STATIC_REQUIRE(static_cast<int>(ldap::errc::operations_error) == 1);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::protocol_error) == 2);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::time_limit_exceeded) == 3);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::size_limit_exceeded) == 4);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::compare_false) == 5);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::compare_true) == 6);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::auth_method_not_supported) == 7);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::stronger_auth_required) == 8);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::referral) == 10);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::admin_limit_exceeded) == 11);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::unavailable_critical_extension) == 12);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::confidentiality_required) == 13);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::sasl_bind_in_progress) == 14);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::no_such_attribute) == 16);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::undefined_attribute_type) == 17);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::inappropriate_matching) == 18);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::constraint_violation) == 19);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::attribute_or_value_exists) == 20);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::invalid_attribute_syntax) == 21);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::no_such_object) == 32);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::alias_problem) == 33);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::invalid_dn_syntax) == 34);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::alias_dereferencing_problem) == 36);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::inappropriate_authentication) == 48);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::invalid_credentials) == 49);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::insufficient_access_rights) == 50);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::busy) == 51);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::unavailable) == 52);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::unwilling_to_perform) == 53);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::loop_detect) == 54);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::naming_violation) == 64);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::object_class_violation) == 65);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::not_allowed_on_non_leaf) == 66);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::not_allowed_on_rdn) == 67);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::entry_already_exists) == 68);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::object_class_mods_prohibited) == 69);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::affects_multiple_dsas) == 71);
	STATIC_REQUIRE(static_cast<int>(ldap::errc::other) == 80);
}

TEST_CASE("every errc and client_errc has a real message", "[error]")
{
	constexpr ldap::errc all[] = {
		ldap::errc::operations_error,
		ldap::errc::protocol_error,
		ldap::errc::time_limit_exceeded,
		ldap::errc::size_limit_exceeded,
		ldap::errc::compare_false,
		ldap::errc::compare_true,
		ldap::errc::auth_method_not_supported,
		ldap::errc::stronger_auth_required,
		ldap::errc::referral,
		ldap::errc::admin_limit_exceeded,
		ldap::errc::unavailable_critical_extension,
		ldap::errc::confidentiality_required,
		ldap::errc::sasl_bind_in_progress,
		ldap::errc::no_such_attribute,
		ldap::errc::undefined_attribute_type,
		ldap::errc::inappropriate_matching,
		ldap::errc::constraint_violation,
		ldap::errc::attribute_or_value_exists,
		ldap::errc::invalid_attribute_syntax,
		ldap::errc::no_such_object,
		ldap::errc::alias_problem,
		ldap::errc::invalid_dn_syntax,
		ldap::errc::alias_dereferencing_problem,
		ldap::errc::inappropriate_authentication,
		ldap::errc::invalid_credentials,
		ldap::errc::insufficient_access_rights,
		ldap::errc::busy,
		ldap::errc::unavailable,
		ldap::errc::unwilling_to_perform,
		ldap::errc::loop_detect,
		ldap::errc::naming_violation,
		ldap::errc::object_class_violation,
		ldap::errc::not_allowed_on_non_leaf,
		ldap::errc::not_allowed_on_rdn,
		ldap::errc::entry_already_exists,
		ldap::errc::object_class_mods_prohibited,
		ldap::errc::affects_multiple_dsas,
		ldap::errc::other,
	};
	STATIC_REQUIRE(std::size(all) == 38);
	for (auto e : all) {
		const auto text = std::error_code(e).message();
		INFO("errc " << static_cast<int>(e) << ": " << text);
		CHECK_FALSE(text.empty());
		CHECK(text.find("unknown") == std::string::npos);
	}
	for (int v = 1; v <= static_cast<int>(ldap::client_errc::invalid_url); ++v) {
		const auto text = std::error_code(static_cast<ldap::client_errc>(v)).message();
		INFO("client_errc " << v << ": " << text);
		CHECK_FALSE(text.empty());
		CHECK(text.find("unknown") == std::string::npos);
	}
}

TEST_CASE("ldap error categories", "[error]")
{
	std::error_code rc = ldap::errc::invalid_credentials;
	CHECK(rc.value() == 49);
	CHECK(std::string(rc.category().name()) == "ldap.result");
	CHECK(rc.message() == "invalid credentials");
	CHECK(std::error_code(ldap::errc::no_such_object).message() == "no such object");
	CHECK(ldap::result_category().message(0) == "success");
	CHECK(ldap::result_category().message(9) == "unknown LDAP result code 9");

	std::error_code cc = ldap::client_errc::decode_error;
	CHECK(cc.value() == 1);
	CHECK(std::string(cc.category().name()) == "ldap.client");
	CHECK(cc.message() == "malformed protocol data");
	CHECK(ldap::client_category().message(999) == "unknown LDAP client error 999");

	// Same number, different category: not equal.
	CHECK(std::error_code(ldap::errc::operations_error) != std::error_code(ldap::client_errc::decode_error));
	CHECK(rc == ldap::errc::invalid_credentials);
	CHECK(cc == ldap::client_errc::decode_error);
}

TEST_CASE("ldap::error message and helpers", "[error]")
{
	ldap::error e = ldap::make_error(ldap::client_errc::integer_overflow, "ber: INTEGER at offset 12");
	CHECK(e.code == ldap::client_errc::integer_overflow);
	CHECK(e.message() == "ber: INTEGER at offset 12: integer does not fit in 64 bits [ldap.client:5]");

	ldap::error s;
	s.code = ldap::errc::no_such_object;
	s.diagnostic = "entry not found";
	s.matched_dn = "dc=example,dc=org";
	s.referrals = { "ldap://a.example.org", "ldap://b.example.org" };
	CHECK(s.message()
      == "no such object [ldap.result:32]; server: entry not found; matched DN: dc=example,dc=org; "
         "referrals: ldap://a.example.org ldap://b.example.org");

	ldap::result<int> r = ldap::fail(ldap::client_errc::would_deadlock, "sync");
	REQUIRE_FALSE(r);
	CHECK(r.error().code == ldap::client_errc::would_deadlock);
	CHECK(r.error().context == "sync");

	ldap::error copy = s;
	CHECK(copy == s);
}
