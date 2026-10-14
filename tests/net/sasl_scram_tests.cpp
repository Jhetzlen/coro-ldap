// SCRAM-SHA-256 mechanism (sasl_scram.hpp), driven directly: the RFC 7677
// test vector, input preparation and every rejection path. The exchange
// through connection::sasl_bind is in sasl_tests.cpp.
#include "jhetz/ldap/sasl_scram.hpp"
#include "scram_test_access.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

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

auto rfc_mech(std::string password = "pencil") -> ldap::sasl_scram_sha256
{
	return ldap::detail::scram_test_access::with_nonce("user", std::move(password), "", std::string(rfc_nonce));
}

// The response of a start() or step() that must succeed with one.
auto response(ldap::result<std::optional<std::string>> r) -> std::string
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
auto first_error(std::string_view server_first) -> ldap::error
{
	auto m = rfc_mech();
	REQUIRE(m.start().has_value());
	auto r = m.step(server_first);
	REQUIRE_FALSE(r.has_value());
	return r.error();
}

auto final_error(std::optional<std::string_view> server_final) -> ldap::error
{
	auto m = rfc_mech();
	to_client_final(m);
	auto r = m.complete(server_final);
	REQUIRE_FALSE(r.has_value());
	return r.error();
}

auto start_error(std::string user, std::string password, std::string authz = {}) -> ldap::error
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

TEST_CASE("scram: a GS2 header with one byte past a base64 group", "[sasl][scram]")
{
	// "n,a=u:bob," is 10 bytes (1 mod 3), so c= ends in "=="; checked with
	// `printf 'n,a=u:bob,' | base64`. Proof and signature from Python's hashlib.
	auto m = ldap::detail::scram_test_access::with_nonce("user", "pencil", "u:bob", "fixednonce");
	CHECK(response(m.start()) == "n,a=u:bob,n=user,r=fixednonce");
	CHECK(response(m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=4096"))
		  == "c=bixhPXU6Ym9iLA==,r=fixednoncesrv,p=jpj8q4xge3eOzcY2SZneuFcJZQ2ClSsgmvemVL61f8s=");
	CHECK(m.complete("v=j2XIKPPyr6tpEvuVuZIzqnAREfc+3qIlk1j6i51Y6H4=").has_value());
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
		for (const char c : nonce) {
			CHECK((c > 0x20 && c < 0x7f && c != ','));
		}
		seen.insert(nonce);
	}
	CHECK(seen.size() == 16);
}

namespace {

// Bytes as hex, for INFO().
auto hex(std::string_view s) -> std::string
{
	std::ostringstream out;
	for (const char c : s) {
		out << std::hex << (static_cast<unsigned>(static_cast<unsigned char>(c)) | 0x100u) % 0x100u << ' ';
	}
	return out.str();
}

// The username as start() sends it (SASLprep'ed and escaped).
auto sent_username(std::string username) -> std::string
{
	auto m = ldap::detail::scram_test_access::with_nonce(std::move(username), "pencil", "", "fixednonce");
	const std::string first = response(m.start());
	REQUIRE_THAT(first, StartsWith("n,,n="));
	REQUIRE_THAT(first, Catch::Matchers::EndsWith(",r=fixednonce"));
	return first.substr(5, first.size() - 5 - std::string_view(",r=fixednonce").size());
}

// The client-final-message for `password` (fixed username, nonce and
// server-first-message): equal for passwords that SASLprep makes equal.
auto client_final_for(std::string password) -> std::string
{
	auto m = ldap::detail::scram_test_access::with_nonce("user", std::move(password), "", "fixednonce");
	REQUIRE(m.start().has_value());
	return response(m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=4096"));
}

void check_input_error(const ldap::error &e, std::string_view context, std::string_view secret = "s3cret")
{
	CHECK(e.code == ldap::client_errc::encode_error);
	CHECK(e.code == ldap::cond::invalid_input);
	CHECK(e.context == context);
	CHECK_THAT(std::string(e.message()), StartsWith(std::string(context) + ": value cannot be encoded"));
	CHECK_THAT(std::string(e.message()), !ContainsSubstring(std::string(secret)));
	CHECK_THAT(std::string(e.message()), !ContainsSubstring("SCRAM"));
}

}// namespace

TEST_CASE("scram: SASLprep, the RFC 4013 section 3 examples", "[sasl][scram][rfc]")
{
	// 1. SOFT HYPHEN mapped to nothing.
	CHECK(sent_username("I\xC2\xAD"
						"X")
		  == "IX");
	CHECK(client_final_for("I\xC2\xAD"
						   "X")
		  == client_final_for("IX"));
	// 2., 3. No transformation; case is preserved.
	CHECK(sent_username("user") == "user");
	CHECK(sent_username("USER") == "USER");
	CHECK(client_final_for("USER") != client_final_for("user"));
	// 4. FEMININE ORDINAL INDICATOR (U+00AA) -> "a" (NFKC).
	CHECK(sent_username("\xC2\xAA") == "a");
	CHECK(client_final_for("\xC2\xAA") == client_final_for("a"));
	// 5. ROMAN NUMERAL NINE (U+2168) -> "IX" (NFKC).
	CHECK(sent_username("\xE2\x85\xA8") == "IX");
	CHECK(client_final_for("\xE2\x85\xA8") == client_final_for("IX"));
	// 6. U+0007: prohibited.
	check_input_error(
	  start_error("user", "\x07"), "password contains a character prohibited by SASLprep (RFC 4013 section 2.3)");
	// 7. U+0627 U+0031: bidi violation (starts but does not end with an RandALCat character).
	check_input_error(start_error("user",
						"\xD8\xA7"
						"1"),
	  "password breaks the bidirectional text rules of SASLprep (RFC 3454 section 6)");
}

TEST_CASE("scram: SASLprep mapping and normalization", "[sasl][scram]")
{
	// NFKC: composition, compatibility characters.
	CHECK(sent_username("A\xCC\x8Angstro\xCC\x88m") == "\xC3\x85ngstr\xC3\xB6m");
	CHECK(sent_username("\xEF\xBC\xAA\xC3\xB6rg") == "J\xC3\xB6rg");// FULLWIDTH J
	CHECK(sent_username("\xEF\xAC\x81le") == "file");// LATIN SMALL LIGATURE FI
	// Already prepared non-ASCII text is sent unchanged.
	CHECK(sent_username("j\xC3\xB6rg") == "j\xC3\xB6rg");
	CHECK(sent_username("\xE5\xB1\xB1\xE7\x94\xB0") == "\xE5\xB1\xB1\xE7\x94\xB0");
	CHECK(sent_username("\xD7\xA9\xD7\x9C\xD7\x95\xD7\x9D") == "\xD7\xA9\xD7\x9C\xD7\x95\xD7\x9D");// RTL only
	// B.1, mapped to nothing: SOFT HYPHEN, ZERO WIDTH JOINER, ZERO WIDTH NO-BREAK SPACE.
	CHECK(sent_username("a\xC2\xAD"
						"b\xE2\x80\x8D"
						"c\xEF\xBB\xBF"
						"d")
		  == "abcd");
	// ZERO WIDTH SPACE is in both B.1 and C.1.2: ICU applies the C.1.2
	// mapping (to U+0020), as PostgreSQL's SASLprep does.
	CHECK(sent_username("a\xE2\x80\x8B"
						"b")
		  == "a b");
	// C.1.2, non-ASCII spaces mapped to U+0020: NO-BREAK SPACE, EM SPACE, IDEOGRAPHIC SPACE.
	CHECK(sent_username("a\xC2\xA0"
						"b\xE2\x80\x83"
						"c\xE3\x80\x80"
						"d")
		  == "a b c d");
	CHECK(client_final_for("p\xC2\xA0w") == client_final_for("p w"));
	// Escaping comes after the preparation: FULLWIDTH EQUALS SIGN and COMMA.
	CHECK(sent_username("a\xEF\xBC\x9D"
						"b\xEF\xBC\x8C"
						"c")
		  == "a=3Db=2Cc");
	// The username is a query: code points unassigned in Unicode 3.2 pass
	// (U+1F600, U+0221).
	CHECK(sent_username("\xF0\x9F\x98\x80") == "\xF0\x9F\x98\x80");
	CHECK(sent_username("\xC8\xA1") == "\xC8\xA1");
}

TEST_CASE("scram: SASLprep rejections and input checks", "[sasl][scram]")
{
	const std::string prohibited = "contains a character prohibited by SASLprep (RFC 4013 section 2.3)";
	check_input_error(start_error("", "s3cret"), "empty username");
	check_input_error(start_error("user", ""), "empty password");
	check_input_error(start_error("\xC2\xAD", "s3cret"), "username is empty after SASLprep");
	check_input_error(start_error("user", "\xE2\x80\x8D\xC2\xAD"), "password is empty after SASLprep", "\xE2\x80\x8D");

	// Prohibited, in the username and in the password.
	check_input_error(start_error("us\ter", "s3cret"), "username " + prohibited);
	for (const std::string_view c : {
		   std::string_view("\0", 1),// C.2.1 ASCII control
		   std::string_view("\x7F"),// C.2.1 DEL
		   std::string_view("\xC2\x85"),// C.2.2 NEXT LINE
		   std::string_view("\xE2\x80\xA8"),// C.2.2 LINE SEPARATOR
		   std::string_view("\xEE\x80\x80"),// C.3 private use U+E000
		   std::string_view("\xEF\xBF\xBF"),// C.4 non-character U+FFFF
		   std::string_view("\xEF\xBF\xBD"),// C.6 REPLACEMENT CHARACTER
		   std::string_view("\xE2\xBF\xB0"),// C.7 ideographic description U+2FF0
		   std::string_view("\xE2\x80\x8E"),// C.8 LEFT-TO-RIGHT MARK
		   std::string_view("\xE2\x80\xAE"),// C.8 RIGHT-TO-LEFT OVERRIDE
		   std::string_view("\xF3\xA0\x80\x81"),// C.9 LANGUAGE TAG U+E0001
		 }) {
		INFO("code point " << hex(c));
		check_input_error(start_error("user", "s3cret" + std::string(c)), "password " + prohibited);
		check_input_error(start_error("u" + std::string(c), "s3cret"), "username " + prohibited);
	}

	// Bidi (RFC 3454 section 6): RandALCat and LCat mixed, or an RTL
	// string that does not end with an RandALCat character.
	const std::string bidi = "breaks the bidirectional text rules of SASLprep (RFC 3454 section 6)";
	check_input_error(start_error("\xD7\xA9"
								  "a"
								  "\xD7\x9D",
						"s3cret"),
	  "username " + bidi);
	check_input_error(start_error("user",
						"\xD7\xA9\xD7\x9C"
						"1"),
	  "password " + bidi);
	CHECK(client_final_for("\xD8\xA7"
						   "1"
						   "\xD8\xA8")
			.size()
		  > 0);// RTL, digits inside: fine

	// The password is a stored string: unassigned code points (Unicode 3.2) are refused.
	const std::string unassigned = "password contains a code point unassigned in Unicode 3.2 (RFC 4013 section 2.5)";
	check_input_error(start_error("user", "s3cret\xF0\x9F\x98\x80"), unassigned);
	check_input_error(start_error("user", "s3cret\xC8\xA1"), unassigned);

	// Invalid UTF-8: truncated, overlong, a surrogate, above U+10FFFF, stray bytes.
	for (const std::string_view bad : {
		   std::string_view("\xC3"),
		   std::string_view("\xC0\xAF"),
		   std::string_view("\xE0\x80\xAF"),
		   std::string_view("\xED\xA0\x80"),
		   std::string_view("\xF4\x90\x80\x80"),
		   std::string_view("\xFF"),
		   std::string_view("\x80"),
		   std::string_view("\xE2\x82"),
		 }) {
		INFO("bytes " << hex(bad));
		check_input_error(start_error("u" + std::string(bad), "s3cret"), "username is not valid UTF-8");
		check_input_error(start_error("user", "s3cret" + std::string(bad)), "password is not valid UTF-8");
		check_input_error(
		  start_error("user", "s3cret", "u:" + std::string(bad)), "authorization identity is not valid UTF-8");
	}

	// The authorization identity: UTF-8, no control characters (C0, DEL, C1); not SASLprep'ed.
	for (const std::string_view control : {
		   std::string_view("\0", 1),
		   std::string_view("\n"),
		   std::string_view("\x1F"),
		   std::string_view("\x7F"),
		   std::string_view("\xC2\x80"),// U+0080
		   std::string_view("\xC2\x85"),// U+0085 NEXT LINE
		   std::string_view("\xC2\x9F"),// U+009F
		 }) {
		INFO("bytes " << hex(control));
		check_input_error(start_error("user", "s3cret", "u:a" + std::string(control)),
		  "authorization identity contains a control character");
	}
	// Just outside the control ranges, and other non-ASCII characters, go on the wire as given.
	for (const std::string_view ok : {
		   std::string_view(" ~"),
		   std::string_view("\xC2\xA0"),// U+00A0 NO-BREAK SPACE
		   std::string_view("\xC2\xAD"),// U+00AD SOFT HYPHEN
		   std::string_view("\xE2\x80\x8E"),// U+200E LEFT-TO-RIGHT MARK
		   std::string_view("\xE2\x80\xA8"),// U+2028 LINE SEPARATOR
		   std::string_view("\xF0\x9F\x98\x80"),// U+1F600
		 }) {
		INFO("bytes " << hex(ok));
		auto m = ldap::detail::scram_test_access::with_nonce("user", "pencil", "u:" + std::string(ok), "fixednonce");
		CHECK(response(m.start()) == "n,a=u:" + std::string(ok) + ",n=user,r=fixednonce");
	}
	{
		auto m = ldap::detail::scram_test_access::with_nonce(
		  "user", "pencil", "dn:cn=J\xC3\xB6rg \xEF\xBC\xAA,dc=example", "fixednonce");
		CHECK(response(m.start()) == "n,a=dn:cn=3DJ\xC3\xB6rg \xEF\xBC\xAA=2Cdc=3Dexample,n=user,r=fixednonce");
	}

	// Printable ASCII, including spaces and SCRAM's separators, is accepted.
	ldap::sasl_scram_sha256 ok("a b=c,d", " p,=w ");
	CHECK(ok.start().has_value());
}

TEST_CASE("scram: the prepared password is held only from start() until the proof", "[sasl][scram]")
{
	using access = ldap::detail::scram_test_access;
	// U+00AA FEMININE ORDINAL INDICATOR: NFKC makes it 'a'.
	auto m = access::with_nonce("user", "s3cret\xC2\xAA", "", "fixednonce");
	CHECK(access::prepared_password(m).empty());
	REQUIRE(m.start().has_value());
	CHECK(access::prepared_password(m) == "s3creta");
	REQUIRE(m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=4096").has_value());
	CHECK(access::prepared_password(m).empty());

	// A start() that fails, on the password or on any other check, leaves none.
	auto bad_authz = access::with_nonce("user", "s3cret", "dn:\n", "fixednonce");
	CHECK_FALSE(bad_authz.start().has_value());
	CHECK(access::prepared_password(bad_authz).empty());
	auto bad_nonce = access::with_nonce("user", "s3cret", "", "bad,nonce");
	CHECK_FALSE(bad_nonce.start().has_value());
	CHECK(access::prepared_password(bad_nonce).empty());
	auto bad_password = access::with_nonce("user", "s3cret\x7F", "", "fixednonce");
	CHECK_FALSE(bad_password.start().has_value());
	CHECK(access::prepared_password(bad_password).empty());
	auto bad_user = access::with_nonce("us\ter", "s3cret", "", "fixednonce");
	CHECK_FALSE(bad_user.start().has_value());
	CHECK(access::prepared_password(bad_user).empty());
}

TEST_CASE("scram: a non-ASCII exchange", "[sasl][scram]")
{
	// Username "A" U+030A "ngstro" U+0308 "m" (decomposed), password
	// "p" U+00E4 "ss" U+00A0 "w" U+00F6 "rd" U+2168 U+00AD. Expected values
	// computed independently with Python: SASLprep from the stringprep
	// module (Unicode 3.2 tables), PBKDF2 and HMAC from hashlib / hmac over
	// the prepared UTF-8 bytes ("\xC3\x85ngstr\xC3\xB6m", "p\xC3\xA4ss w\xC3\xB6rdIX").
	auto m = ldap::detail::scram_test_access::with_nonce(
	  "A\xCC\x8Angstro\xCC\x88m", "p\xC3\xA4ss\xC2\xA0w\xC3\xB6rd\xE2\x85\xA8\xC2\xAD", "", "fixednonce");
	CHECK(response(m.start()) == "n,,n=\xC3\x85ngstr\xC3\xB6m,r=fixednonce");
	CHECK(response(m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=4096"))
		  == "c=biws,r=fixednoncesrv,p=Y11RbG3iFQ+PS2iZbI5QTUxQOcGMUdBmwdZHIALNcls=");
	CHECK(m.complete("v=co+6SuWgvyobykMIOtBkZKlvkGQGAhKa/0rxVdUVyj4=").has_value());
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
				   + std::to_string(std::to_underlying(ldap::client_errc::unexpected_response)) + "]");
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
	SECTION("a server error is quoted as UTF-8, sanitized and cut on a code point boundary")
	{
		auto context = [](std::string_view value) {
			return std::string(final_error("e=" + std::string(value)).context);
		};
		const std::string prefix = "the server reported an error: ";
		// Valid UTF-8 is kept.
		CHECK(context("d\xC3\xA9j\xC3\xA0 vu \xE2\x82\xAC \xF0\x9F\x98\x80")
			  == prefix + "\"d\xC3\xA9j\xC3\xA0 vu \xE2\x82\xAC \xF0\x9F\x98\x80\"");
		// Control characters (C0, DEL, C1) and ill-formed sequences become U+FFFD.
		CHECK(context("a\x01" "b\x7F" "c\xC2\x85" "d\xFF" "e\xC3" "f\xED\xA0\x80" "g")
			  == prefix + "\"a\xEF\xBF\xBD" "b\xEF\xBF\xBD" "c\xEF\xBF\xBD" "d\xEF\xBF\xBD" "e\xEF\xBF\xBD"
						  "f\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD" "g\"");
		// The bidi controls (Bidi_Control: U+061C, U+200E, U+200F,
		// U+202A-U+202E, U+2066-U+2069) and U+2028/U+2029 become U+FFFD.
		const std::string fffd = "\xEF\xBF\xBD";
		const std::string_view replaced[] = {
			"\xD8\x9C",// U+061C ARABIC LETTER MARK
			"\xE2\x80\x8E",// U+200E LRM
			"\xE2\x80\x8F",// U+200F RLM
			"\xE2\x80\xA8",// U+2028 LINE SEPARATOR
			"\xE2\x80\xA9",// U+2029 PARAGRAPH SEPARATOR
			"\xE2\x80\xAA",// U+202A LRE
			"\xE2\x80\xAB",// U+202B RLE
			"\xE2\x80\xAC",// U+202C PDF
			"\xE2\x80\xAD",// U+202D LRO
			"\xE2\x80\xAE",// U+202E RLO
			"\xE2\x81\xA6",// U+2066 LRI
			"\xE2\x81\xA7",// U+2067 RLI
			"\xE2\x81\xA8",// U+2068 FSI
			"\xE2\x81\xA9",// U+2069 PDI
		};
		for (const std::string_view c : replaced) {
			CAPTURE(c);
			CHECK(context("a" + std::string(c) + "b") == prefix + "\"a" + fffd + "b\"");
		}
		// A Trojan Source style message: RLO ... PDI.
		CHECK(context("ok\xE2\x80\xAE"
					  "deliaf\xE2\x81\xA9!")
			  == prefix + "\"ok" + fffd + "deliaf" + fffd + "!\"");
		// Their neighbours and the other format characters are text and are
		// kept: U+061B, U+200C ZWNJ, U+200D ZWJ in an emoji sequence, U+2027,
		// U+202F, U+2065, U+206A, the tag characters of a subdivision flag,
		// and letters, CJK and emoji.
		const std::string kept =
		  "\xD8\x9B"// U+061B
		  "\xE2\x80\x8C"// U+200C
		  "\xF0\x9F\x91\xA9\xE2\x80\x8D\xF0\x9F\x92\xBB"// U+1F469 U+200D U+1F4BB
		  "\xE2\x80\xA7"// U+2027
		  "\xE2\x80\xAF"// U+202F
		  "\xE2\x81\xA5"// U+2065
		  "\xE2\x81\xAA";// U+206A
		CHECK(context(kept) == prefix + "\"" + kept + "\"");
		const std::string scotland =
		  "\xF0\x9F\x8F\xB4\xF3\xA0\x81\xA7\xF3\xA0\x81\xA2\xF3\xA0\x81\xB3"
		  "\xF3\xA0\x81\xA3\xF3\xA0\x81\xB4\xF3\xA0\x81\xBF";// U+1F3F4 U+E0067...U+E007F
		CHECK(context("\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC " + scotland)
			  == prefix + "\"\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC " + scotland + "\"");
		// The cut counts the bytes of the value, before replacement.
		CHECK(context(std::string(61, 'x') + "\xE2\x80\xAE") == prefix + "\"" + std::string(61, 'x') + fffd + "\"");
		CHECK(context(std::string(62, 'x') + "\xE2\x80\xAE") == prefix + "\"" + std::string(62, 'x') + "...\"");
		// At most 64 bytes of the value, never half a character.
		std::string e_acute;
		for (int i = 0; i < 40; ++i) {
			e_acute += "\xC3\xA9";
		}
		CHECK(context(e_acute) == prefix + "\"" + e_acute.substr(0, 64) + "...\"");
		CHECK(context("a" + e_acute) == prefix + "\"a" + e_acute.substr(0, 62) + "...\"");
		CHECK(context(std::string(64, 'x')) == prefix + "\"" + std::string(64, 'x') + "\"");
		CHECK(context(std::string(65, 'x')) == prefix + "\"" + std::string(64, 'x') + "...\"");
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

TEST_CASE("scram: a configured maximum iteration count", "[sasl][scram]")
{
	using access = ldap::detail::scram_test_access;
	auto mech = [](std::uint32_t max) {
		return access::with_nonce("user", "pencil", ldap::sasl_scram_options{ .max_iterations = max }, "fixednonce");
	};
	SECTION("a higher count is refused, the bound itself accepted")
	{
		auto m = mech(10'000);
		REQUIRE(m.start().has_value());
		auto r = m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=10001");
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK(r.error().code == ldap::cond::protocol_error);
		CHECK(r.error().context == "iteration count 10001 is above the maximum of 10000");
		REQUIRE(m.start().has_value());
		CHECK(m.step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=10000").has_value());
	}
	SECTION("a bound outside 4096 .. 2^31-1 is refused by start()")
	{
		for (const std::uint32_t max : { 0U, 4095U, 0x8000'0000U }) {
			CAPTURE(max);
			auto m = mech(max);
			auto r = m.start();
			REQUIRE_FALSE(r.has_value());
			CHECK(r.error().code == ldap::client_errc::encode_error);
			CHECK_THAT(std::string(r.error().context), ContainsSubstring("max_iterations"));
		}
		auto m = mech(0x7fff'ffff);
		CHECK(m.start().has_value());
	}
}

TEST_CASE("scram: the SaltedPassword is cached per salt and iteration count", "[sasl][scram]")
{
	using access = ldap::detail::scram_test_access;
	auto m = access::with_nonce(
	  "user", "pencil", ldap::sasl_scram_options{ .offload_above_iterations = 0 }, std::string(rfc_nonce));
	m.prepare({ .can_offload = true });
	CHECK(access::cached_iterations(m) == 0);

	// First bind: PBKDF2 is offloaded (offload_above_iterations = 0); the
	// work gives the RFC's proof, and its SaltedPassword is kept.
	REQUIRE(response(m.start()) == rfc_client_first);
	auto work = m.offload_step(rfc_server_first);
	REQUIRE(work);
	CHECK(response(work()) == rfc_client_final);
	CHECK(m.complete(rfc_server_final).has_value());
	CHECK(access::cached_iterations(m) == 4096);

	// Same salt and count: nothing to offload, step() derives the keys
	// from the cache.
	REQUIRE(response(m.start()) == rfc_client_first);
	CHECK_FALSE(m.offload_step(rfc_server_first));
	CHECK(response(m.step(rfc_server_first)) == rfc_client_final);
	CHECK(m.complete(rfc_server_final).has_value());

	// Another salt or count: PBKDF2 again.
	REQUIRE(m.start().has_value());
	CHECK(m.offload_step("r=rOprNGfwEbeRWgbNEkqOsrv,s=QSXCR+Q6sek8bf92,i=4096"));
	REQUIRE(m.start().has_value());
	CHECK(m.offload_step("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4097"));

	// The inline path fills the cache too, and replaces it.
	REQUIRE(m.start().has_value());
	REQUIRE(m.step("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=5000").has_value());
	CHECK(access::cached_iterations(m) == 5000);
	REQUIRE(m.start().has_value());
	CHECK_FALSE(m.offload_step("r=rOprNGfwEbeRWgbNEkqOsrv,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=5000"));
}

TEST_CASE("scram: when PBKDF2 is offloaded", "[sasl][scram]")
{
	using access = ldap::detail::scram_test_access;
	constexpr std::string_view heavy = "r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=16385";
	constexpr std::string_view light = "r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=16384";
	SECTION("above offload_above_iterations (16384 by default), when sasl_bind allows it")
	{
		auto m = access::with_nonce("user", "pencil", "", "fixednonce");
		REQUIRE(m.start().has_value());
		CHECK_FALSE(m.offload_step(heavy));// no prepare(): not allowed
		m.prepare({ .can_offload = false });// locking_mode::unsafe
		CHECK_FALSE(m.offload_step(heavy));
		m.prepare({ .can_offload = true });
		CHECK_FALSE(m.offload_step(light));
		CHECK_FALSE(m.offload_step(std::nullopt));
		CHECK_FALSE(m.offload_step("r=fixednoncesrv,s=QSXCR+Q6sek8bf92,i=1000001"));// step() refuses it
		CHECK_FALSE(m.offload_step("garbage"));
		CHECK(m.offload_step(heavy));
		// Once offloaded, the exchange waits for the server-final-message.
		CHECK_FALSE(m.offload_step(heavy));
	}
	SECTION("a step given up on runs on alone, while the next bind goes on inline")
	{
		auto m = access::with_nonce(
		  "user", "pencil", ldap::sasl_scram_options{ .offload_above_iterations = 0 }, std::string(rfc_nonce));
		m.prepare({ .can_offload = true });
		REQUIRE(m.start().has_value());
		auto stale = m.offload_step(rfc_server_first);
		REQUIRE(stale);
		// sasl_bind gave up: a new bind, then the old work completes.
		REQUIRE(response(m.start()) == rfc_client_first);
		CHECK(access::prepared_password(m) == "pencil");
		m.prepare({ .can_offload = false });
		CHECK(response(m.step(rfc_server_first)) == rfc_client_final);
		CHECK(response(stale()) == rfc_client_final);
		CHECK(m.complete(rfc_server_final).has_value());
		// A work that never ran gives the exchange no signature.
		auto m2 = access::with_nonce(
		  "user", "pencil", ldap::sasl_scram_options{ .offload_above_iterations = 0 }, std::string(rfc_nonce));
		m2.prepare({ .can_offload = true });
		REQUIRE(m2.start().has_value());
		auto never = m2.offload_step(rfc_server_first);
		REQUIRE(never);
		CHECK(access::prepared_password(m2).empty());// moved into the work
		auto r = m2.complete(rfc_server_final);
		REQUIRE_FALSE(r.has_value());
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("wrong server signature"));
	}
}
