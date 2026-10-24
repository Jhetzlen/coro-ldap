#include "counting_resource.hpp"
#include "jhetz/ldap/dn.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <memory_resource>
#include <stdexcept>
#include <string>

namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::counting_resource;
using jhetz::ldap::test::scoped_default_resource;
using namespace std::string_literals;

namespace {

auto parse(std::string_view text) -> ldap::dn
{
	auto d = ldap::dn::parse(text);
	REQUIRE(d.has_value());
	return *d;
}

auto single(const std::string &type, const std::string &value) -> ldap::rdn
{
	return ldap::rdn{ { ldap::ava{ ldap::attribute::unchecked(type), value } } };
}

}// namespace

// Literals are checked at compile time with the same scanner as parse().
static_assert(ldap::detail::is_dn(""));
static_assert(ldap::detail::is_dn("cn=x,dc=example,dc=org"));
static_assert(ldap::detail::is_dn("OU=Sales+CN=J.  Smith,DC=example,DC=net"));
static_assert(!ldap::detail::is_dn("cn"));
static_assert(!ldap::detail::is_dn("cn=x,"));
// UTF-8 at compile time (the hand-rolled check; ICU at run time).
static_assert(ldap::detail::is_dn("cn=caf\xc3\xa9,dc=\xf0\x9f\x98\x80"));
static_assert(!ldap::detail::is_dn("cn=\xed\xa0\x80"));
static_assert(!ldap::detail::is_dn("cn=\xf4\x90\x80\x80"));
static_assert(!ldap::detail::is_dn("cn=\xc0\xaf"));
static_assert(!ldap::detail::is_dn("cn=\xf0\x9f\x98"));
static_assert(ldap::detail::is_rdn("uid=jdoe"));
static_assert(ldap::detail::is_rdn("OU=Sales + CN=J.  Smith"));
static_assert(ldap::detail::is_rdn("cn=a\\,b"));// an escaped comma is part of the value
static_assert(!ldap::detail::is_rdn(""));
static_assert(!ldap::detail::is_rdn("uid=jdoe,dc=org"));
static_assert(!ldap::detail::is_rdn("uid=jdoe,"));
static_assert(!ldap::detail::is_rdn("uid"));

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
		const auto d = parse(R"(CN=James \"Jim\" Smith\, III,DC=example,DC=net)");
		CHECK(d.rdns()[0].avas[0].value == "James \"Jim\" Smith, III");
		CHECK(d.to_string() == R"(CN=James \"Jim\" Smith\, III,DC=example,DC=net)");
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
		const auto d = parse(R"(CN=Lu\C4\8Di\C4\87)");
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
	CHECK(ldap::escape_dn_value(value) == std::string_view(text).substr(3));// what to_string writes
}

TEST_CASE("escape_dn_value: RFC 4514 text that parses back to the value", "[dn][escape]")
{
	const std::string value = GENERATE(std::string{},
	  "plain"s,
	  " both ends "s,
	  "#"s,
	  "# "s,
	  "a#b "s,
	  "\\"s,
	  ",+\"<>;\\="s,
	  "\0"s,
	  "caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac"s,// 2- and 3-byte UTF-8
	  "\xf0\x9f\x98\x80 \xf0\x90\x8d\x88"s,// 4-byte UTF-8
	  "\xff\xc3"s,// not UTF-8
	  "\xf0\x9f\x98"s);// truncated 4-byte sequence
	INFO(value);
	const auto text = ldap::escape_dn_value(value);
	const auto d = parse("cn=" + std::string(text) + ",dc=org");
	REQUIRE(d.rdns().size() == 2);
	CHECK(d.rdns()[0].avas[0].value == std::string_view(value));
	CHECK_FALSE(d.rdns()[0].avas[0].hex_form);
	CHECK(ldap::dn{}.child(single("cn", value)).to_string() == std::string_view("cn=" + std::string(text)));
}

TEST_CASE("escape_dn_value keeps UTF-8 and escapes only specials", "[dn][escape]")
{
	CHECK(ldap::escape_dn_value("\xf0\x9f\x98\x80") == "\xf0\x9f\x98\x80");
	CHECK(ldap::escape_dn_value("J\xc3\xb6rg, Smith") == "J\xc3\xb6rg\\, Smith");
	CHECK(ldap::escape_dn_value("#a#") == "\\#a#");
	CHECK(ldap::escape_dn_value(" a ") == "\\ a\\ ");
	CHECK(ldap::escape_dn_value("\xff") == "\\ff");
	CHECK(ldap::escape_dn_value("a\0b"s) == "a\\00b");
	CHECK(ldap::escape_dn_value("").empty());
	counting_resource mr;
	const auto s = ldap::escape_dn_value("a long enough value to need an allocation", &mr);
	CHECK(s.get_allocator().resource() == &mr);
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

// ---------------------------------------------------------------- building DNs from parts

TEST_CASE("rdn literal constructor", "[dn][rdn]")
{
	const ldap::rdn uid{ "uid=jdoe" };
	REQUIRE(uid.avas.size() == 1);
	CHECK(uid.avas[0].type == ldap::attribute{ "uid" });
	CHECK(uid.avas[0].value == "jdoe");
	CHECK(uid == single("uid", "jdoe"));
	CHECK(uid.to_string() == "uid=jdoe");

	const ldap::rdn multi{ "OU=Sales + CN=J.  Smith" };
	REQUIRE(multi.avas.size() == 2);
	CHECK(multi.avas[1].value == "J.  Smith");
	CHECK(multi.to_string() == "OU=Sales+CN=J.  Smith");
	CHECK(multi == ldap::rdn{ "cn=J.  Smith+ou=Sales" });// a set: order and type case do not matter

	const ldap::rdn escaped{ "cn=Smith\\, John" };
	CHECK(escaped.avas[0].value == "Smith, John");
	CHECK(escaped.to_string() == "cn=Smith\\, John");

	const ldap::rdn hex{ "1.3.6.1.4.1.1466.0=#04024869" };
	CHECK(hex.avas[0].hex_form);
	CHECK(hex.to_string() == "1.3.6.1.4.1.1466.0=#04024869");
}

TEST_CASE("rdn::parse", "[dn][rdn]")
{
	SECTION("valid")
	{
		auto r = ldap::rdn::parse("uid=jdoe");
		REQUIRE(r.has_value());
		CHECK(*r == ldap::rdn{ "uid=jdoe" });
		auto m = ldap::rdn::parse("cn=a+sn=b");
		REQUIRE(m.has_value());
		CHECK(m->avas.size() == 2);
		CHECK(m->to_string() == "cn=a+sn=b");
	}
	SECTION("invalid")
	{
		struct case_t
		{
			std::string text;
			const char *context;
		};
		const case_t c = GENERATE(values<case_t>({
		  { "", "rdn: empty" },
		  { "uid=jdoe,dc=org", "rdn: 2 RDNs where one is expected" },
		  { "uid=jdoe,", "rdn: syntax error at position 9" },
		  { ",uid=jdoe", "rdn: syntax error at position 0" },
		  { "uid", "rdn: syntax error at position 3" },
		  { "cn=a+", "rdn: syntax error at position 5" },
		  { " ", "rdn: syntax error at position 1" },
		}));
		INFO(c.text);
		auto r = ldap::rdn::parse(c.text);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::invalid_dn);
		CHECK(r.error().context == c.context);
	}
}

TEST_CASE("rdn to_string/parse round-trips arbitrary values", "[dn][rdn]")
{
	std::string all;
	for (int c = 0; c < 256; ++c) {
		all += static_cast<char>(c);
	}
	for (std::size_t start = 0; start < all.size(); start += 7) {
		const std::string value = " " + all.substr(start, 13) + " ";
		const ldap::rdn r{ { ldap::ava{ ldap::attribute{ "cn" }, value },
		  ldap::ava{ ldap::attribute{ "sn" }, value } } };
		const auto text = r.to_string();
		INFO(text);
		auto back = ldap::rdn::parse(text);
		REQUIRE(back.has_value());
		CHECK(*back == r);
		CHECK(back->to_string() == text);
	}
}

TEST_CASE("dn::child of an rdn", "[dn][rdn]")
{
	const ldap::dn base{ "ou=people,dc=example,dc=org" };
	CHECK(base.child(ldap::rdn{ "uid=jdoe" }) == ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" });
	CHECK(base.child(ldap::rdn{ "uid=jdoe" }).to_string() == "uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(base.child(ldap::rdn{ "cn=a+sn=b" }).to_string() == "cn=a+sn=b,ou=people,dc=example,dc=org");
	const auto runtime = ldap::rdn::parse(std::string("uid=") + "x\\,y");
	REQUIRE(runtime.has_value());
	CHECK(base.child(*runtime).to_string() == "uid=x\\,y,ou=people,dc=example,dc=org");
	CHECK(ldap::dn{}.child(ldap::rdn{ "dc=org" }) == ldap::dn{ "dc=org" });
	CHECK(base.child(ldap::rdn{ "uid=jdoe" }).parent() == base);
}

TEST_CASE("dn::child of a relative dn", "[dn]")
{
	const ldap::dn base{ "dc=example,dc=org" };
	const ldap::dn relative{ "uid=jdoe,ou=people" };
	const auto d = base.child(relative);
	// The relative DN's leftmost RDN stays the most specific (RFC 4514).
	CHECK(d == ldap::dn{ "uid=jdoe,ou=people,dc=example,dc=org" });
	CHECK(d.to_string() == "uid=jdoe,ou=people,dc=example,dc=org");
	CHECK(parse(d.to_string()) == d);
	CHECK(d.parent().parent() == base);
	CHECK(base.child(ldap::dn{}) == base);// nothing below
	CHECK(ldap::dn{}.child(relative) == relative);// under the root DSE
	CHECK(base.child(ldap::dn{ "ou=people" }).child(ldap::rdn{ "uid=jdoe" }) == d);
	CHECK(base.child(ldap::dn{ "cn=a+sn=b,ou=x" }).to_string() == "cn=a+sn=b,ou=x,dc=example,dc=org");
}

TEST_CASE("rdn and child allocate from the given resource", "[dn][rdn][pmr]")
{
	std::byte storage[8192];
	std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
	scoped_default_resource guard(std::pmr::null_memory_resource());

	const ldap::rdn lit(ldap::rdn::literal("cn=a long common name\\, with spaces+uid=someone-long"), &arena);
	CHECK(lit.get_allocator().resource() == &arena);
	CHECK(lit.avas[1].value.get_allocator().resource() == &arena);
	CHECK(lit.avas[1].type.get_allocator().resource() == &arena);

	auto parsed = ldap::rdn::parse("uid=a-user-with-a-long-name-to-allocate", &arena);
	REQUIRE(parsed.has_value());
	CHECK(parsed->get_allocator().resource() == &arena);
	CHECK(parsed->avas[0].value.get_allocator().resource() == &arena);
	CHECK(parsed->to_string(&arena).get_allocator().resource() == &arena);

	const ldap::dn base(ldap::dn::literal("ou=people,dc=example,dc=org"), &arena);
	const ldap::dn relative(ldap::dn::literal("uid=someone-with-a-long-name,ou=a-long-unit-name"), &arena);
	const auto under = base.child(relative);
	CHECK(under.get_allocator().resource() == &arena);
	CHECK(under.rdns()[0].avas[0].value.get_allocator().resource() == &arena);
	CHECK(under.rdns()[3].avas[0].type.get_allocator().resource() == &arena);
	const auto child = base.child(*parsed);
	CHECK(child.get_allocator().resource() == &arena);
	CHECK(child.rdns()[0].avas[0].value.get_allocator().resource() == &arena);
}

TEST_CASE("child uses the dn's resource, not the argument's", "[dn][rdn][pmr]")
{
	counting_resource base_mr;
	counting_resource other_mr;
	const ldap::dn base(ldap::dn::literal("ou=people,dc=example,dc=org"), &base_mr);
	const ldap::dn relative(ldap::dn::literal("uid=someone-with-a-long-name,ou=a-long-unit-name"), &other_mr);
	const ldap::rdn r(ldap::rdn::literal("uid=someone-with-a-long-name"), &other_mr);
	const std::size_t other_before = other_mr.allocations();
	const std::size_t base_before = base_mr.allocations();

	const auto a = base.child(relative);
	const auto b = base.child(r);
	CHECK(a.get_allocator().resource() == &base_mr);
	CHECK(a.rdns()[0].avas[0].value.get_allocator().resource() == &base_mr);
	CHECK(b.rdns()[0].avas[0].value.get_allocator().resource() == &base_mr);
	CHECK(base_mr.allocations() > base_before);
	CHECK(other_mr.allocations() == other_before);
}

TEST_CASE("child of an rvalue rdn on another resource uses the dn's resource", "[dn][rdn][pmr]")
{
	counting_resource base_mr;
	counting_resource other_mr;
	const ldap::dn base(ldap::dn::literal("ou=people,dc=example,dc=org"), &base_mr);
	auto r = ldap::rdn::parse("cn=a long common name to allocate+uid=someone-with-a-long-name", &other_mr);
	REQUIRE(r.has_value());
	const std::size_t other_before = other_mr.allocations();

	const auto d = base.child(std::move(*r));
	CHECK(
	  d.to_string() == "cn=a long common name to allocate+uid=someone-with-a-long-name,ou=people,dc=example,dc=org");
	CHECK(d.get_allocator().resource() == &base_mr);
	for (const auto &a : d.rdns()[0].avas) {
		CHECK(a.type.get_allocator().resource() == &base_mr);
		CHECK(a.value.get_allocator().resource() == &base_mr);
	}
	CHECK(other_mr.allocations() == other_before);// copied, not moved, across resources
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
	CHECK(d.error().context.contains("position"));
}

TEST_CASE("dn to_string/parse round-trips arbitrary values", "[dn]")
{
	std::string all;
	for (int c = 0; c < 256; ++c) {
		all += static_cast<char>(c);
	}
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

// ---------------------------------------------------------------- RFC conformance

// RFC 4514 section 2 converts a DN to a UTF-8 string; section 3 only allows
// valid UTF-8 (stringchar = SUTF1 / UTFMB), any other octet is a hex pair.
TEST_CASE("RFC 4514 2: printed DNs are valid UTF-8", "[dn][rfc]")
{
	CHECK(parse("cn=\\ff").to_string() == "cn=\\ff");
	CHECK(ldap::dn{}.child(single("cn", "a\xc3")).to_string() == "cn=a\\c3");// truncated sequence
	CHECK(parse("cn=\\c3\\a9").to_string() == "cn=\xc3\xa9");// valid UTF-8 is kept
	// Each octet of an ill-formed sequence is escaped; U+10FFFF and
	// noncharacters are well-formed and kept.
	CHECK(ldap::dn{}.child(single("cn", "\xf4\x90\x80\x80")).to_string() == "cn=\\f4\\90\\80\\80");
	CHECK(ldap::dn{}.child(single("cn", "\xed\xa0\x80")).to_string() == "cn=\\ed\\a0\\80");
	CHECK(
	  ldap::dn{}.child(single("cn", "\xf4\x8f\xbf\xbf\xef\xbf\xbf")).to_string() == "cn=\xf4\x8f\xbf\xbf\xef\xbf\xbf");
}

TEST_CASE("RFC 4514 3: DN text with invalid UTF-8 is rejected", "[dn][rfc]")
{
	const std::string bad = GENERATE(as<std::string>{},
	  "cn=\xff",
	  "cn=a\xc3,dc=x",// truncated sequence
	  "cn=\xc0\xaf",// overlong '/'
	  "cn=\xed\xa0\x80",// UTF-16 surrogate
	  "cn=\xf4\x90\x80\x80",// above U+10FFFF
	  "cn=\xf5\x80\x80\x80",// lead octet above U+10FFFF
	  "cn=\xe0\x9f\xbf",// overlong 3-octet form
	  "cn=\xf0\x8f\xbf\xbf",// overlong 4-octet form
	  "cn=\x80");// stray continuation octet
	auto d = ldap::dn::parse(bad);
	REQUIRE_FALSE(d.has_value());
	CHECK(d.error().code == client_errc::invalid_dn);
}
