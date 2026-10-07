#include "jhetz/ldap/dn.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <stdexcept>
#include <string>

namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using namespace std::string_literals;

namespace {

ldap::dn parse(std::string_view text)
{
	auto d = ldap::dn::parse(text);
	REQUIRE(d.has_value());
	return *d;
}

ldap::rdn single(std::string type, std::string value)
{
	return ldap::rdn{ { ldap::ava{ ldap::attribute::unchecked(std::move(type)), std::move(value) } } };
}

}// namespace

// Literals are checked at compile time with the same scanner as parse().
static_assert(ldap::detail::is_dn(""));
static_assert(ldap::detail::is_dn("cn=x,dc=example,dc=org"));
static_assert(ldap::detail::is_dn("OU=Sales+CN=J.  Smith,DC=example,DC=net"));
static_assert(!ldap::detail::is_dn("cn"));
static_assert(!ldap::detail::is_dn("cn=x,"));

TEST_CASE("RFC 4514 section 4 examples", "[dn]")
{
	SECTION("plain")
	{
		const auto d = parse("UID=jsmith,DC=example,DC=net");
		REQUIRE(d.rdns().size() == 3);
		CHECK(d.rdns()[0].avas[0].type.name() == "UID");
		CHECK(d.rdns()[0].avas[0].value == "jsmith");
		CHECK(d.to_string() == "UID=jsmith,DC=example,DC=net");
	}
	SECTION("multi-valued RDN")
	{
		const auto d = parse("OU=Sales+CN=J.  Smith,DC=example,DC=net");
		REQUIRE(d.rdns().size() == 3);
		REQUIRE(d.rdns()[0].avas.size() == 2);
		CHECK(d.rdns()[0].avas[1].value == "J.  Smith");
		CHECK(d.to_string() == "OU=Sales+CN=J.  Smith,DC=example,DC=net");
	}
	SECTION("escaped specials")
	{
		const auto d = parse("CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net");
		CHECK(d.rdns()[0].avas[0].value == "James \"Jim\" Smith, III");
		CHECK(d.to_string() == "CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net");
	}
	SECTION("hex-escaped control character")
	{
		const auto d = parse("CN=Before\\0dAfter,DC=example,DC=net");
		CHECK(d.rdns()[0].avas[0].value == "Before\rAfter");
		CHECK(d.to_string() == "CN=Before\\0dAfter,DC=example,DC=net");
	}
	SECTION("#hexstring (BER) value")
	{
		const auto d = parse("1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com");
		const auto &a = d.rdns()[0].avas[0];
		CHECK(a.hex_form);
		CHECK(a.value == "\x04\x02Hi");
		CHECK(d.to_string() == "1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com");
	}
	SECTION("UTF-8 via hex pairs")
	{
		const auto d = parse("CN=Lu\\C4\\8Di\\C4\\87");
		CHECK(d.rdns()[0].avas[0].value == "Lu\xc4\x8di\xc4\x87");
		CHECK(d.to_string() == "CN=Lu\xc4\x8di\xc4\x87");
		CHECK(parse(d.to_string()) == d);
	}
}

TEST_CASE("dn::to_string escapes what RFC 4514 requires", "[dn]")
{
	using P = std::pair<std::string, std::string>;
	const auto [value, text] = GENERATE(P{ " lead", "cn=\\ lead" },
	  P{ "#hash", "cn=\\#hash" },
	  P{ "mid#dle", "cn=mid#dle" },
	  P{ "trail ", "cn=trail\\ " },
	  P{ " ", "cn=\\ " },
	  P{ "  ", "cn=\\ \\ " },
	  P{ "a  b", "cn=a  b" },
	  P{ "a,b+c\"d\\e<f>g;h", "cn=a\\,b\\+c\\\"d\\\\e\\<f\\>g\\;h" },
	  P{ "x=y", "cn=x=y" },
	  P{ "nul\0"s, "cn=nul\\00" },
	  P{ "\x7f\x1f", "cn=\\7f\\1f" },
	  P{ "\xc3\xa9", "cn=\xc3\xa9" },
	  P{ "", "cn=" });
	INFO(text);
	const auto d = ldap::dn{}.child(single("cn", value));
	CHECK(d.to_string() == std::string_view(text));
	const auto back = parse(text);
	CHECK(back == d);
	CHECK(back.rdns()[0].avas[0].value == std::string_view(value));
}

TEST_CASE("dn parsing leniency", "[dn]")
{
	// Spaces around separators and '=' (RFC 2253 section 4), unescaped
	// trailing spaces dropped.
	CHECK(parse("cn = x , dc = y") == parse("cn=x,dc=y"));
	CHECK(parse(" cn=x + sn=y ") == parse("cn=x+sn=y"));
	CHECK(parse("cn=x   ").rdns()[0].avas[0].value == "x");
	CHECK(parse("cn=x\\  ").rdns()[0].avas[0].value == "x ");
	CHECK(parse("cn=#0102 ,dc=y").rdns()[0].avas[0].value == "\x01\x02");
	CHECK(parse("cn=a\\=b").rdns()[0].avas[0].value == "a=b");
}

TEST_CASE("dn equality", "[dn]")
{
	// Attribute types case-insensitively, values exactly.
	CHECK(parse("CN=John,DC=Example") == parse("cn=John,dc=Example"));
	CHECK(parse("cn=John") != parse("cn=john"));
	CHECK(parse("cn=John") != parse("sn=John"));
	CHECK(parse("cn=a,dc=x") != parse("cn=a"));
	// Escaped and unescaped spellings of the same value.
	CHECK(parse("cn=a\\2cb") == parse("cn=a\\,b"));
	CHECK(parse("cn=\\4a") == parse("cn=J"));
	// Multi-valued RDN: AVA order does not matter.
	CHECK(parse("cn=a+sn=b,dc=x") == parse("SN=b+CN=a,DC=x"));
	CHECK(parse("cn=a+sn=b") != parse("cn=a+sn=c"));
	CHECK(parse("cn=a+cn=a") != parse("cn=a+sn=b"));
	CHECK(parse("cn=a+sn=b") != parse("cn=a"));
	// Longer than the comparison's stack buffer (16 AVAs): falls back to the heap.
	std::string forward;
	std::string backward;
	for (int i = 0; i < 40; ++i) {
		const auto a = "a" + std::to_string(i) + "=v";
		forward += (i == 0 ? "" : "+") + a;
		backward = a + (i == 0 ? "" : "+") + backward;
	}
	CHECK(parse(forward) == parse(backward));
	CHECK(parse(forward) != parse(backward + "x"));
	// '#' form and string form are different values here (no schema).
	CHECK(parse("cn=#6162") != parse("cn=ab"));
	// No normalization beyond that (documented limit).
	CHECK(parse("cn=a b") != parse("cn=a  b"));
}

TEST_CASE("dn structure: rdns, parent, child, empty", "[dn]")
{
	const auto d = parse("uid=jdoe,ou=people,dc=example,dc=org");
	CHECK_FALSE(d.empty());
	CHECK(d.rdns().size() == 4);
	CHECK(d.parent() == parse("ou=people,dc=example,dc=org"));
	CHECK(d.parent().parent().parent() == parse("dc=org"));
	CHECK(d.parent().parent().parent().parent().empty());
	CHECK(ldap::dn{}.parent().empty());
	CHECK(d.parent().child(single("uid", "jdoe")) == d);

	const auto root = parse("");
	CHECK(root.empty());
	CHECK(root.to_string().empty());
	CHECK(root == ldap::dn{});

	CHECK_THROWS_AS(d.child(ldap::rdn{}), std::invalid_argument);
	CHECK_THROWS_AS(d.child(single("bad type", "x")), std::invalid_argument);
	CHECK_THROWS_AS(d.child(ldap::rdn{ { ldap::ava{ ldap::attribute{ "cn" }, "", true } } }), std::invalid_argument);
}

TEST_CASE("dn literal constructor", "[dn]")
{
	const ldap::dn base{ "ou=people,dc=example,dc=org" };
	CHECK(base == parse("ou=people,dc=example,dc=org"));
	CHECK(base.to_string() == "ou=people,dc=example,dc=org");
}

TEST_CASE("invalid DNs are rejected", "[dn]")
{
	const std::string bad = GENERATE(as<std::string>{},
	  "cn",
	  "=x",
	  "cn=x,",
	  ",cn=x",
	  "cn=x,,dc=y",
	  "cn=x;dc=y",
	  "cn=x+",
	  "+cn=x",
	  "cn=a\\",
	  "cn=a\\z",
	  "cn=a\\zz",
	  "cn=a\\4",
	  "cn=#abc",
	  "cn=#",
	  "cn=#zz",
	  "cn=#0102x",
	  "cn=\"x\"",
	  "cn=a<b",
	  "cn=a>b",
	  "cn;lang-en=x",
	  "1.2.=x",
	  "1.02=x",
	  "c_n=x",
	  "-cn=x",
	  " ",
	  "cn=a\0b"s);
	INFO(bad);
	auto d = ldap::dn::parse(bad);
	REQUIRE_FALSE(d);
	CHECK(d.error().code == client_errc::invalid_dn);
	CHECK(d.error().context.find("position") != std::string::npos);
}

TEST_CASE("dn to_string/parse round-trips arbitrary values", "[dn]")
{
	std::string all;
	for (int c = 0; c < 256; ++c) all += static_cast<char>(c);
	for (std::size_t start = 0; start < all.size(); start += 7) {
		const std::string value = all.substr(start, 13) + " ";
		const auto d = ldap::dn{ "dc=example" }.child(ldap::rdn{
		  { ldap::ava{ ldap::attribute{ "cn" }, value }, ldap::ava{ ldap::attribute{ "2.5.4.4" }, " " + value } } });
		const auto text = d.to_string();
		INFO(text);
		CHECK(parse(text) == d);
		CHECK(parse(text).to_string() == text);
	}
}
