// SCRAM-SHA-256 mechanism (sasl_scram.hpp), driven directly: the RFC 7677
// test vector, input preparation and every rejection path. The exchange
// through connection::sasl_bind is in sasl_tests.cpp.
#include "jhetz/ldap/sasl_scram.hpp"
#include "scram_test_access.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;
using Catch::Matchers::ContainsSubstring;
using Catch::Matchers::StartsWith;

namespace {

// RFC 7677 section 3.
constexpr std::string_view rfc_nonce = "rOprNGfwEbeRWgbNEkqO";
constexpr std::string_view rfc_client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
constexpr std::string_view rfc_server_first =
  "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
constexpr std::string_view rfc_client_final =
  "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
constexpr std::string_view rfc_server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

ldap::sasl_scram_sha256 rfc_mech(std::string password = "pencil")
{
	return ldap::detail::scram_test_access::with_nonce("user", std::move(password), "", std::string(rfc_nonce));
}

// The response of a start() or step() that must succeed with one.
std::string response(ldap::result<std::optional<std::string>> r)
{
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	return **r;
}

// start() and step() up to the client-final-message of the RFC vector.
void to_client_final(ldap::sasl_scram_sha256 &m)
{
	REQUIRE(response(m.start()) == rfc_client_first);
	REQUIRE(response(m.step(rfc_server_first)) == rfc_client_final);
}

// The error of a step() given `server_first` after start().
ldap::error first_error(std::string_view server_first)
{
	auto m = rfc_mech();
	REQUIRE(m.start().has_value());
	auto r = m.step(server_first);
	REQUIRE_FALSE(r.has_value());
	return r.error();
}

ldap::error final_error(std::optional<std::string_view> server_final)
{
	auto m = rfc_mech();
	to_client_final(m);
	auto r = m.complete(server_final);
	REQUIRE_FALSE(r.has_value());
	return r.error();
}

ldap::error start_error(std::string user, std::string password, std::string authz = {})
{
	ldap::sasl_scram_sha256 m(std::move(user), std::move(password), std::move(authz));
	auto r = m.start();
	REQUIRE_FALSE(r.has_value());
	return r.error();
}

}// namespace

TEST_CASE("scram: the RFC 7677 test vector", "[sasl][scram][rfc]")
{
	auto m = rfc_mech();
	CHECK(m.name() == "SCRAM-SHA-256");
	to_client_final(m);
	CHECK(m.complete(rfc_server_final).has_value());

	SECTION("the mechanism can be reused for another bind")
	{
		to_client_final(m);
		CHECK(m.complete(rfc_server_final).has_value());
	}
	SECTION("server-final-message as a challenge, then success without data")
	{
		to_client_final(m);
		CHECK(response(m.step(rfc_server_final)).empty());
		CHECK(m.complete(std::nullopt).has_value());
	}
	SECTION("extensions after the known attributes are ignored")
	{
		REQUIRE(m.start().has_value());
		// The extension changes the AuthMessage, so only the proof's presence is checked.
		auto r = m.step(std::string(rfc_server_first) + ",x=ext");
		REQUIRE(r.has_value());
		CHECK_THAT(r->value(), StartsWith("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p="));
	}
}

TEST_CASE("scram: escaping and the authorization identity", "[sasl][scram]")
{
	// Expected values computed with Python's hashlib (PBKDF2-HMAC-SHA-256).
	auto m = ldap::detail::scram_test_access::with_nonce("j=d,oe", "pencil", "dn:uid=jdoe,dc=example", "fixednonce");
	CHECK(response(m.start()) == std::string("n,a=dn:uid=3Djdoe=2Cdc=3Dexample,n=j=3Dd=2Coe,r=fixednonce"));
	CHECK(response(m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=4096"))
		  == std::string("c=bixhPWRuOnVpZD0zRGpkb2U9MkNkYz0zRGV4YW1wbGUs,r=fixednoncesrv,p=31crlYM8R5NoEgzgx/"
						 "TA0to1PCcfN0YCd0Ylzn3Tg1w="));
	CHECK(m.complete("v=44oJZOE51dvHBrJoVQjNtv0u5bbyofhujrU0K4VF1rs=").has_value());
}

TEST_CASE("scram: random client nonces", "[sasl][scram]")
{
	ldap::sasl_scram_sha256 m("user", "pencil");
	std::set<std::string> seen;
	for (int i = 0; i < 16; ++i) {
		auto r = m.start();
		REQUIRE(r.has_value());
		REQUIRE(r->has_value());
		const std::string &first = **r;
		REQUIRE_THAT(first, StartsWith("n,,n=user,r="));
		const std::string nonce = first.substr(std::string_view("n,,n=user,r=").size());
		CHECK(nonce.size() == 24);
		for (const char c : nonce) CHECK((c > 0x20 && c < 0x7f && c != ','));
		seen.insert(nonce);
	}
	CHECK(seen.size() == 16);
}

TEST_CASE("scram: SASLprep and input checks", "[sasl][scram]")
{
	auto check = [](const ldap::error &e, std::string_view what) {
		CHECK(e.code == ldap::client_errc::encode_error);
		CHECK(e.code == ldap::cond::invalid_input);
		CHECK_THAT(std::string(e.context), StartsWith(std::string(what)));
		CHECK_THAT(std::string(e.context), !ContainsSubstring("s3cret"));
	};
	check(start_error("", "s3cret"), "empty username");
	check(start_error("user", ""), "empty password");
	check(start_error("us\ter", "s3cret"), "username contains a control character");
	check(start_error("user", std::string("s3cret\0x", 8)), "password contains a control character");
	check(start_error("user", "s3cret\x7f"), "password contains a control character");
	check(start_error("j\xc3\xb6rg", "s3cret"), "username is not ASCII");
	check(start_error("user", "s3cr\xc3\xa9t"), "password is not ASCII");
	check(start_error("user", "s3cret", "dn:\n"), "authorization identity contains a control character");
	// Printable ASCII, including spaces and SCRAM's separators, is accepted.
	ldap::sasl_scram_sha256 ok("a b=c,d", " p,=w ");
	CHECK(ok.start().has_value());
}

TEST_CASE("scram: server-first-message rejections", "[sasl][scram]")
{
	auto refused = [](const ldap::error &e, std::string_view what) {
		CHECK(e.code == ldap::client_errc::unexpected_response);
		CHECK(e.code == ldap::cond::protocol_error);
		CHECK_THAT(std::string(e.context), ContainsSubstring(std::string(what)));
	};
	auto malformed = [](const ldap::error &e, std::string_view what) {
		CHECK(e.code == ldap::client_errc::decode_error);
		CHECK_THAT(std::string(e.context), ContainsSubstring(std::string(what)));
	};
	refused(first_error("r=XXXprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"),
	  "does not start with the client nonce");
	refused(first_error("r=rOprNGfwEbe,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"), "does not start with the client nonce");
	refused(
	  first_error("r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"), "does not extend the client nonce");
	refused(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4095"),
	  "iteration count 4095 is below the minimum of 4096");
	refused(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4000000000"), "above the maximum");
	refused(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1000001"),
	  "iteration count 1000001 is above the maximum of 1000000");
	refused(first_error("m=must,r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"), "mandatory extension");

	malformed(first_error(""), "server-first-message");
	malformed(first_error("garbage"), "server-first-message");
	malformed(first_error("s=W22ZaJ0SNY7soEsUEjb6gQ==,r=rOprNGfwEbeRWgbNEkqO,i=4096"), "no nonce");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqO sp,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"), "nonce");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,i=4096"), "no salt");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=,i=4096"), "salt is not valid base64");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22Z*J0SNY7soEsUEjb6gQ==,i=4096"), "salt is not valid base64");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ=,i=4096"), "salt is not valid base64");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ=="), "no iteration count");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096x"), "iteration count");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=04096"), "iteration count");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=99999999999"), "iteration count");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,"), "extension");
	malformed(first_error("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,junk"), "extension");

	SECTION("no challenge at all")
	{
		auto m = rfc_mech();
		REQUIRE(m.start().has_value());
		auto r = m.step(std::nullopt);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
	}
}

TEST_CASE("scram: server-final-message rejections (mutual authentication)", "[sasl][scram]")
{
	SECTION("wrong server signature")
	{
		auto e = final_error("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
		CHECK(e.code == ldap::client_errc::unexpected_response);
		CHECK(e.context == "wrong server signature: the server could not be authenticated");
		// message() says what went wrong once, then the code's text.
		CHECK(std::string(e.message())
			  == "wrong server signature: the server could not be authenticated: unexpected response from the server "
				 "[ldap.client:"
				   + std::to_string(static_cast<int>(ldap::client_errc::unexpected_response)) + "]");
	}
	SECTION("a signature of the wrong length")
	{
		auto e = final_error("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl9");
		CHECK(e.code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(e.context), ContainsSubstring("wrong server signature"));
	}
	SECTION("the client used the wrong password")
	{
		auto m = rfc_mech("pencil2");
		REQUIRE(m.start().has_value());
		auto r = m.step(rfc_server_first);
		REQUIRE(r.has_value());
		CHECK(r->value() != rfc_client_final);
		CHECK_FALSE(m.complete(rfc_server_final).has_value());
	}
	SECTION("a server error")
	{
		auto e = final_error("e=invalid-proof");
		CHECK(e.code == ldap::client_errc::unexpected_response);
		CHECK(e.context == "the server reported an error: \"invalid-proof\"");
	}
	SECTION("success without server-final-message")
	{
		auto e = final_error(std::nullopt);
		CHECK(e.code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(e.context), ContainsSubstring("without a server signature"));
		CHECK_THAT(std::string(final_error("").context), ContainsSubstring("without a server signature"));
	}
	SECTION("malformed server-final-message")
	{
		CHECK(final_error("x=1").code == ldap::client_errc::decode_error);
		CHECK(final_error("v=***").code == ldap::client_errc::decode_error);
		CHECK(final_error(std::string(rfc_server_final) + ",").code == ldap::client_errc::decode_error);
	}
	SECTION("success right after the client-first-message")
	{
		auto m = rfc_mech();
		REQUIRE(m.start().has_value());
		auto r = m.complete(rfc_server_final);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("before the exchange was complete"));
	}
	SECTION("a signature cannot be replayed into a later bind")
	{
		auto m = rfc_mech();
		to_client_final(m);
		REQUIRE(m.complete(rfc_server_final).has_value());
		REQUIRE(m.start().has_value());
		CHECK_FALSE(m.complete(rfc_server_final).has_value());
	}
	SECTION("server-final-message as a challenge, then more data")
	{
		auto m = rfc_mech();
		to_client_final(m);
		REQUIRE(m.step(rfc_server_final).has_value());
		CHECK_FALSE(m.complete(rfc_server_final).has_value());
	}
	SECTION("a wrong signature sent as a challenge")
	{
		auto m = rfc_mech();
		to_client_final(m);
		auto r = m.step("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
		REQUIRE_FALSE(r.has_value());
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("wrong server signature"));
	}
	SECTION("a challenge after the exchange")
	{
		auto m = rfc_mech();
		to_client_final(m);
		REQUIRE(m.step(rfc_server_final).has_value());
		auto r = m.step("more");
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
	}
}
