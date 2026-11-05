// ad::explain: the Win32 error code that starts an AD diagnosticMessage.
#include "jhetz/ldap/ad/diagnostic.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

namespace ldap = jhetz::ldap;

namespace {

auto explained(std::string_view diagnostic) -> std::string_view
{
	ldap::error e = ldap::make_error(ldap::errc::constraint_violation);
	e.diagnostic.assign(diagnostic);
	return ldap::ad::explain(e);
}

}// namespace

TEST_CASE("ad::explain: the Win32 codes of a failed password change", "[ad][diagnostic]")
{
	CHECK(explained("0000052D: Constraint violation - check_password_restrictions: the password does not meet the "
					"complexity criteria!")
		  == "the new password does not meet the password policy (length, complexity, history or minimum age)");
	CHECK(explained("00000056: AtrErr: DSID-03190F80, #1:\n\t0: 00000056: DSID-03190F80, problem 1005 "
					"(CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)\n")
		  == "the old password is wrong");
	CHECK(explained("00000005: SecErr: DSID-031A11E5, problem 4003 (INSUFF_ACCESS_RIGHTS)")
		  == "not allowed to set this user's password");
	CHECK(explained("00000775: account locked out") == "the account is locked out");
	// Lower-case hex is hex too.
	CHECK(explained("0000052d: Constraint violation") != std::string_view{});
}

TEST_CASE("ad::explain: other codes and diagnostics that are not AD's", "[ad][diagnostic]")
{
	CHECK(explained("00002077: SvcErr: DSID-03190EF9, problem 5003 (WILL_NOT_PERFORM)").empty());
	CHECK(explained("insufficient access").empty());
	CHECK(explained("0000002G: not hexadecimal").empty());
	CHECK(explained("0000052D").empty());// no colon
	CHECK(explained("0000052D-").empty());
	CHECK(explained("").empty());
	CHECK(ldap::ad::explain(ldap::error{}).empty());
}
