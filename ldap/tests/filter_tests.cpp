#include "jhetz/ldap/filter.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <stdexcept>
#include <string>
#include <utility>

namespace ber = jhetz::ldap::ber;
namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::hex;
using namespace std::string_literals;

namespace {

ldap::result<std::vector<std::byte>> to_ber(std::string_view text)
{
	ber::writer w;
	auto r = ldap::encode_filter(w, text);
	if (!r) return std::unexpected(r.error());
	return w.take();
}

// text -> BER -> canonical text; also checks canonical text -> same BER.
std::string canonical(std::string_view text)
{
	auto b = to_ber(text);
	REQUIRE(b.has_value());
	ber::reader r(*b);
	auto t = ldap::decode_filter(r);
	REQUIRE(t.has_value());
	CHECK(r.empty());
	auto again = to_ber(*t);
	REQUIRE(again.has_value());
	CHECK(hex(*again) == hex(*b));
	return *t;
}

}// namespace

TEST_CASE("filter builders produce escaped RFC 4515 text", "[filter][builder]")
{
	using namespace ldap::filters;
	CHECK((attr("cn") == "Babs Jensen").text == "(cn=Babs Jensen)");
	CHECK((attr("uidNumber") >= "1000").text == "(uidNumber>=1000)");
	CHECK((attr("uidNumber") <= "2000").text == "(uidNumber<=2000)");
	CHECK(attr("sn").approx("smith").text == "(sn~=smith)");
	CHECK(attr("mail").present().text == "(mail=*)");
	CHECK(attr("cn").starts_with("Jo").text == "(cn=Jo*)");
	CHECK(attr("cn").ends_with("son").text == "(cn=*son)");
	CHECK(attr("cn").contains("oh").text == "(cn=*oh*)");
	CHECK(attr("cn").starts_with("").text == "(cn=*)");
	CHECK(attr("cn").contains("").text == "(cn=*)");
	CHECK((attr("cn;lang-en") == "x").text == "(cn;lang-en=x)");
	CHECK((attr("2.5.4.3") == "x").text == "(2.5.4.3=x)");

	SECTION("every special byte is escaped")
	{
		CHECK((attr("cn") == "a*b(c)d\\e"s + '\0' + "f").text == "(cn=a\\2ab\\28c\\29d\\5ce\\00f)");
		CHECK(ldap::escape_filter_value("\xc3\xa9\n") == "\xc3\xa9\n");
		CHECK(attr("cn").starts_with("*").text == "(cn=\\2a*)");
	}
	SECTION("injection attempts stay inside the value")
	{
		const std::string evil = "x)(uid=*";
		const auto f = attr("objectClass") == "person" && attr("uid") == evil;
		CHECK(f.text == "(&(objectClass=person)(uid=x\\29\\28uid=\\2a))");
		CHECK(canonical(f.text) == f.text);
		// The BER has exactly two equality assertions, the second with the raw value.
		auto b = to_ber(f.text);
		REQUIRE(b);
		ber::reader r(*b);
		auto a = r.enter(ber::context(0));
		REQUIRE(a);
		REQUIRE(a->enter(ber::context(3)));
		auto uid = a->enter(ber::context(3));
		REQUIRE(uid);
		CHECK(uid->read_string() == "uid");
		CHECK(uid->read_string() == evil);
		CHECK(a->empty());
	}
	SECTION("operators")
	{
		const auto a = attr("a") == "1";
		const auto b = attr("b") == "2";
		const auto c = attr("c") == "3";
		CHECK((a && b).text == "(&(a=1)(b=2))");
		CHECK((a || b).text == "(|(a=1)(b=2))");
		CHECK((!a).text == "(!(a=1))");
		// Chains are flattened, mixed operators nest.
		CHECK((a && b && c).text == "(&(a=1)(b=2)(c=3))");
		CHECK((a && (b && c)).text == "(&(a=1)(b=2)(c=3))");
		CHECK((a || b || c).text == "(|(a=1)(b=2)(c=3))");
		CHECK(((a || b) && c).text == "(&(|(a=1)(b=2))(c=3))");
		CHECK(((a && b) || c).text == "(|(&(a=1)(b=2))(c=3))");
		// A value ending in an escaped paren is still recognized as one group.
		const auto p = attr("x") == ")";
		CHECK((p && a && b).text == "(&(x=\\29)(a=1)(b=2))");
		// Raw text that is not one group is not merged.
		const auto raw = ldap::filter::raw("(&(a=1))(b=2)");
		CHECK((raw && c).text == "(&(&(a=1))(b=2)(c=3))");
		// Long chains stay flat, far below max_filter_depth.
		ldap::filter all = a;
		for (int i = 0; i < 200; ++i) all = all && (attr("n") == std::to_string(i));
		CHECK(to_ber(all.text).has_value());
	}
	SECTION("DESIGN.md example")
	{
		const std::string user_input = "x)(uid=*";
		const std::string prefix = "j";
		auto f = attr("objectClass") == "person" && (attr("uid") == user_input || attr("mail").starts_with(prefix))
				 && !attr("disabled").present();
		CHECK(f.text == "(&(objectClass=person)(|(uid=x\\29\\28uid=\\2a)(mail=j*))(!(disabled=*)))");
		CHECK(canonical(f.text) == f.text);
	}
	SECTION("attribute objects")
	{
		CHECK((attr(ldap::attribute{ "mail" }) == "x").text == "(mail=x)");
		CHECK_THROWS_AS(attr(ldap::attribute::unchecked("uid=*)(cn")), std::invalid_argument);
	}
}

TEST_CASE("filter parser accepts RFC 4515 and returns canonical text", "[filter][parser]")
{
	using P = std::pair<std::string, std::string>;
	const auto [input, expected] = GENERATE(
	  // RFC 4515 section 4 examples
	  P{ "(cn=Babs Jensen)", "(cn=Babs Jensen)" },
	  P{ "(!(cn=Tim Howes))", "(!(cn=Tim Howes))" },
	  P{ "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))", "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))" },
	  P{ "(o=univ*of*mich*)", "(o=univ*of*mich*)" },
	  P{ "(seeAlso=)", "(seeAlso=)" },
	  P{ "(cn:caseExactMatch:=Fred Flintstone)", "(cn:caseExactMatch:=Fred Flintstone)" },
	  P{ "(cn:=Betty Rubble)", "(cn:=Betty Rubble)" },
	  P{ "(sn:dn:2.4.6.8.10:=Barney Rubble)", "(sn:dn:2.4.6.8.10:=Barney Rubble)" },
	  P{ "(o:dn:=Ace Industry)", "(o:dn:=Ace Industry)" },
	  P{ "(:1.2.3:=Wilma Flintstone)", "(:1.2.3:=Wilma Flintstone)" },
	  P{ "(:DN:2.4.6.8.10:=Dino)", "(:dn:2.4.6.8.10:=Dino)" },
	  P{ "(o=Parens R Us \\28for all your parenthetical needs\\29)",
		"(o=Parens R Us \\28for all your parenthetical needs\\29)" },
	  P{ "(cn=*\\2A*)", "(cn=*\\2a*)" },
	  P{ "(filename=C:\\5cMyFile)", "(filename=C:\\5cMyFile)" },
	  P{ "(bin=\\00\\00\\00\\04)", "(bin=\\00\\00\\00\x04)" },
	  P{ "(sn=Lu\\c4\\8di\\c4\\87)", "(sn=Lu\xc4\x8di\xc4\x87)" },
	  P{ "(1.3.6.1.4.1.1466.0=\\04\\02\\48\\69)", "(1.3.6.1.4.1.1466.0=\x04\x02Hi)" },
	  // RFC 4526 absolute true / false
	  P{ "(&)", "(&)" },
	  P{ "(|)", "(|)" },
	  P{ "(!(&))", "(!(&))" },
	  // other forms
	  P{ "(cn;lang-en;x-foo=x)", "(cn;lang-en;x-foo=x)" },
	  P{ "(2.5.4.3=x)", "(2.5.4.3=x)" },
	  P{ "(cn=a**b)", "(cn=a*b)" },
	  P{ "(cn=**b)", "(cn=*b)" },
	  P{ "(cn=a***)", "(cn=a*)" },
	  P{ "(cn=*)", "(cn=*)" },
	  P{ "(cn=\\2a)", "(cn=\\2a)" },
	  P{ "(cn= spaced )", "(cn= spaced )" },
	  P{ "(cn:dn:dn:=x)", "(cn:dn:dn:=x)" },
	  P{ "(cn:1.2.3:=)", "(cn:1.2.3:=)" },
	  P{ "(cn~=)", "(cn~=)" },
	  P{ "(cn=\xc3\xa9)", "(cn=\xc3\xa9)" },
	  // leniency: missing outer parentheses
	  P{ "uid=jdoe", "(uid=jdoe)" },
	  P{ "cn=a*", "(cn=a*)" },
	  P{ "&(a=b)(c=d)", "(&(a=b)(c=d))" });
	INFO(input);
	CHECK(canonical(input) == expected);
}

TEST_CASE("filter BER for selected forms", "[filter][parser]")
{
	CHECK(hex(*to_ber("(&)")) == "A0 00");
	CHECK(hex(*to_ber("(|)")) == "A1 00");
	CHECK(hex(*to_ber("(cn=*)")) == "87 02 63 6E");
	CHECK(hex(*to_ber("(!(a=b))")) == "A2 08 A3 06 04 01 61 04 01 62");
	CHECK(hex(*to_ber("(a=*x*)")) == "A4 08 04 01 61 30 03 81 01 78");
	// dnAttributes is DEFAULT FALSE: omitted unless :dn is given.
	CHECK(hex(*to_ber("(a:=x)")) == "A9 06 82 01 61 83 01 78");
	CHECK(hex(*to_ber("(a:dn:=x)")) == "A9 09 82 01 61 83 01 78 84 01 FF");
	CHECK(hex(*to_ber("(:r:=x)")) == "A9 06 81 01 72 83 01 78");
}

TEST_CASE("filter parser rejects malformed text", "[filter][parser]")
{
	const std::string bad = GENERATE(as<std::string>{},
	  "",
	  "()",
	  "(cn=x",
	  "cn=x)",
	  "((cn=x))",
	  "(cn=x))",
	  "(cn=x)(sn=y)",
	  "(cn=x) ",
	  " (cn=x)",
	  "(& (a=b))",
	  "(!(a=b)(c=d))",
	  "(!)",
	  "(&(a=b)",
	  "(cn=a(b)",
	  "(cn=\\2)",
	  "(cn=\\zz)",
	  "(cn=\\)",
	  "(cn=\\2g)",
	  "(cn~=a*)",
	  "(cn>=*)",
	  "(cn<=a*b)",
	  "(cn:=a*)",
	  "(=x)",
	  "(c n=x)",
	  "(cn;=x)",
	  "(cn;lang_en=x)",
	  "(1cn=x)",
	  "(-cn=x)",
	  "(1.02=x)",
	  "(1=x)",
	  "(cn=**)",
	  "(cn>x)",
	  "(cn~x)",
	  "(:=x)",
	  "(:dn:=x)",
	  "(cn::=x)",
	  "(cn:dn:r:dn:=x)",
	  "(cn:r1:r2:=x)",
	  "(cn:1.2.:=x)",
	  "(cn:dn)",
	  "(cn:=x",
	  "(cn=x\0y)"s,
	  "(cn=x"s + '\0' + ")");
	INFO(bad);
	ber::writer w;
	auto r = ldap::encode_filter(w, bad);
	REQUIRE_FALSE(r);
	CHECK(r.error().code == client_errc::invalid_filter);
	CHECK(r.error().context.find("position") != std::string::npos);
	CHECK(w.bytes().empty());
}

TEST_CASE("filter parse errors report the position in the caller's text", "[filter][parser]")
{
	auto ctx = [](std::string_view text) { return to_ber(text).error().context; };
	CHECK(ctx("(cn=a(b)") == "filter: unescaped '(' or NUL in value at position 5");
	CHECK(ctx("(&(cn=x)(sn=\\zz))") == "filter: invalid escape (expected \\ and two hex digits) at position 12");
	CHECK(ctx("(c n=x)") == "filter: expected a filter type ('=', '~=', '>=', '<=' or ':=') at position 2");
	// Wrapped text: positions still refer to the original.
	CHECK(ctx("cn=a(b") == "filter: unescaped '(' or NUL in value at position 4");
	CHECK(ctx("(cn=x)(sn=y)") == "filter: unexpected characters after the filter at position 6");
}

TEST_CASE("filter nesting is bounded", "[filter][parser]")
{
	auto nested = [](std::size_t depth, const std::string &open) {
		std::string t;
		for (std::size_t i = 1; i < depth; ++i) t += open;
		t += "(a=b)";
		for (std::size_t i = 1; i < depth; ++i) t += ")";
		return t;
	};
	CHECK(to_ber(nested(ldap::max_filter_depth, "(&")).has_value());
	CHECK(to_ber(nested(ldap::max_filter_depth, "(!")).has_value());
	auto too_deep = to_ber(nested(ldap::max_filter_depth + 1, "(|"));
	REQUIRE_FALSE(too_deep);
	CHECK(too_deep.error().code == client_errc::invalid_filter);
	CHECK(too_deep.error().context.find("nested too deeply") != std::string::npos);

	// Bombs fail quickly without deep recursion.
	CHECK(to_ber(std::string(100'000, '(')).error().code == client_errc::invalid_filter);
	std::string bomb;
	for (int i = 0; i < 100'000; ++i) bomb += "(!";
	CHECK(to_ber(bomb).error().code == client_errc::invalid_filter);
	bomb.clear();
	for (int i = 0; i < 100'000; ++i) bomb += "(&";
	CHECK(to_ber(bomb).error().code == client_errc::invalid_filter);
}

TEST_CASE("decode_filter rejects BER without an RFC 4515 form", "[filter][decode]")
{
	auto decode = [](auto body) {
		ber::writer w;
		body(w);
		auto bytes = w.take();
		ber::reader r(bytes);
		auto t = ldap::decode_filter(r);
		if (!t) CHECK(r.offset() == 0);// unchanged on failure
		return t;
	};
	auto code = [&](auto body) {
		auto t = decode(body);
		REQUIRE_FALSE(t);
		return t.error().code;
	};
	auto substrings = [](auto items) {
		return [items](ber::writer &w) {
			w.constructed(ber::context(4), [&](ber::writer &s) {
				s.octet_string("cn");
				s.constructed(ber::tags::sequence, items);
			});
		};
	};

	CHECK(code([](ber::writer &w) { w.octet_string("bad attr", ber::context(7)); }) == client_errc::decode_error);
	CHECK(code([](ber::writer &w) {
		w.constructed(ber::context(3), [](ber::writer &a) {
			a.octet_string("cn=x");
			a.octet_string("v");
		});
	}) == client_errc::decode_error);
	CHECK(code(substrings([](ber::writer &) {})) == client_errc::decode_error);
	CHECK(code(substrings([](ber::writer &s) { s.octet_string("", ber::context(1)); })) == client_errc::decode_error);
	CHECK(code(substrings([](ber::writer &s) {
		s.octet_string("a", ber::context(1));
		s.octet_string("b", ber::context(0));
	})) == client_errc::decode_error);
	CHECK(code(substrings([](ber::writer &s) {
		s.octet_string("a", ber::context(2));
		s.octet_string("b", ber::context(1));
	})) == client_errc::decode_error);
	CHECK(code(substrings([](ber::writer &s) { s.octet_string("a", ber::context(3)); })) == client_errc::decode_error);
	CHECK(code([](ber::writer &w) {
		w.constructed(ber::context(9), [](ber::writer &e) { e.octet_string("v", ber::context(3)); });
	}) == client_errc::decode_error);
	CHECK(code([](ber::writer &w) {
		w.constructed(ber::context(9), [](ber::writer &e) {
			e.octet_string("dn", ber::context(1));
			e.octet_string("cn", ber::context(2));
			e.octet_string("v", ber::context(3));
		});
	}) == client_errc::decode_error);
	CHECK(code([](ber::writer &w) {
		w.constructed(ber::context(2), [](ber::writer &n) {
			n.octet_string("a", ber::context(7));
			n.octet_string("b", ber::context(7));
		});
	}) == client_errc::decode_error);
	CHECK(
	  code([](ber::writer &w) { w.constructed(ber::context(2), [](ber::writer &) {}); }) == client_errc::decode_error);
	CHECK(code([](ber::writer &w) { w.octet_string("a", ber::context(10)); }) == client_errc::unexpected_tag);
	CHECK(code([](ber::writer &w) { w.octet_string("a"); }) == client_errc::unexpected_tag);

	// Depth: max_filter_depth nested elements decode, one more does not.
	auto nested = [](std::size_t depth) {
		return [depth](ber::writer &w) {
			auto rec = [](auto &self, ber::writer &x, std::size_t left) -> void {
				if (left == 1) {
					x.octet_string("a", ber::context(7));
					return;
				}
				x.constructed(ber::context(0), [&](ber::writer &y) { self(self, y, left - 1); });
			};
			rec(rec, w, depth);
		};
	};
	CHECK(decode(nested(ldap::max_filter_depth)).has_value());
	CHECK(code(nested(ldap::max_filter_depth + 1)) == client_errc::nesting_too_deep);

	// Accepted variations: explicit dnAttributes FALSE, unknown trailing elements.
	auto t = decode([](ber::writer &w) {
		w.constructed(ber::context(9), [](ber::writer &e) {
			e.octet_string("cn", ber::context(2));
			e.octet_string("v", ber::context(3));
			e.boolean(false, ber::context(4));
			e.null(ber::context(5));
		});
	});
	CHECK(t == "(cn:=v)");
}

TEST_CASE("equality builder round-trips every byte", "[filter][builder]")
{
	std::string all;
	for (int c = 0; c < 256; ++c) all += static_cast<char>(c);
	for (const std::string &v : { all, ""s, "*"s, "\\"s, "()"s, "\0"s }) {
		const auto f = ldap::filters::attr("cn") == v;
		auto b = to_ber(f.text);
		REQUIRE(b);
		ber::reader r(*b);
		auto eq = r.enter(ber::context(3));
		REQUIRE(eq);
		CHECK(eq->read_string() == "cn");
		CHECK(eq->read_string() == v);
		CHECK(canonical(f.text) == f.text);
	}
}
