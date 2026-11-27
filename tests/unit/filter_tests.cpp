#include "counting_resource.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <chrono>
#include <concepts>
#include <iterator>
#include <memory_resource>
#include <ranges>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace ber = jhetz::ldap::ber;
namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::hex;
using namespace std::string_literals;
using namespace std::string_view_literals;

namespace {

auto parsed(std::string_view text) -> ldap::filter
{
	auto f = ldap::filter::parse(text);
	INFO(text);
	REQUIRE(f.has_value());
	return std::move(*f);
}

auto to_ber(const ldap::filter &f, const ldap::filter_limits &limits = {}) -> ldap::result<std::pmr::vector<std::byte>>
{
	ber::writer w;
	auto r = ldap::encode_filter(w, f, limits);
	if (!r) {
		CHECK(w.bytes().empty());
		return std::unexpected(r.error());
	}
	return w.take();
}

auto from_ber(std::span<const std::byte> bytes, const ldap::filter_limits &limits = {}) -> ldap::result<ldap::filter>
{
	ber::reader r(bytes);
	auto f = ldap::testing::decode_filter(r, limits);
	if (f) {
		CHECK(r.empty());
	} else {
		CHECK(r.offset() == 0);// unchanged on failure
	}
	return f;
}

// Text -> tree -> canonical text; also checks tree -> BER -> the same tree,
// and that the canonical text parses to the same tree again.
auto canonical(std::string_view text) -> std::string
{
	const auto f = parsed(text);
	auto b = to_ber(f);
	REQUIRE(b.has_value());
	auto back = from_ber(*b);
	REQUIRE(back.has_value());
	CHECK(*back == f);
	const std::string out(f.to_string());
	CHECK(parsed(out) == f);
	CHECK(back->to_string() == std::string_view(out));
	return out;
}

auto text_of(const ldap::filter &f) -> std::string { return std::string(f.to_string()); }

// `t && f`, `f || t` and `!t` give filters.
template<class T>
concept combinable = requires(const T &t, const ldap::filter &f) {
	{ t && f } -> std::same_as<ldap::filter>;
	{ f || t } -> std::same_as<ldap::filter>;
	{ !t } -> std::same_as<ldap::filter>;
};

}// namespace

TEST_CASE("filter builders make one-node trees with unescaped values", "[filter][builder]")
{
	using namespace ldap::filters;
	using kind = ldap::filter::kind;
	CHECK(text_of(attr("cn") == "Babs Jensen") == "(cn=Babs Jensen)");
	CHECK(text_of(attr("uidNumber") >= "1000") == "(uidNumber>=1000)");
	CHECK(text_of(attr("uidNumber") <= "2000") == "(uidNumber<=2000)");
	CHECK(text_of(attr("sn").approx("smith")) == "(sn~=smith)");
	CHECK(text_of(attr("mail").present()) == "(mail=*)");
	CHECK(text_of(attr("cn").starts_with("Jo")) == "(cn=Jo*)");
	CHECK(text_of(attr("cn").ends_with("son")) == "(cn=*son)");
	CHECK(text_of(attr("cn").contains("oh")) == "(cn=*oh*)");
	CHECK(text_of(attr("cn").starts_with("")) == "(cn=*)");
	CHECK(text_of(attr("cn").ends_with("")) == "(cn=*)");
	CHECK(text_of(attr("cn").contains("")) == "(cn=*)");
	CHECK(text_of(attr("cn;lang-en") == "x") == "(cn;lang-en=x)");
	CHECK(text_of(attr("2.5.4.3") == "x") == "(2.5.4.3=x)");

	SECTION("the tree")
	{
		const auto eq = attr("cn") == "a*b";
		CHECK(eq.root().kind() == kind::equality);
		CHECK(eq.root().attribute() == "cn");
		CHECK(eq.root().value() == "a*b");// unescaped
		CHECK(eq.root().children().empty());
		CHECK(eq.depth() == 1);
		CHECK(eq.elements() == 1);
		CHECK((attr("cn") >= "1").root().kind() == kind::greater_or_equal);
		CHECK((attr("cn") <= "1").root().kind() == kind::less_or_equal);
		CHECK(attr("cn").approx("1").root().kind() == kind::approx);
		CHECK(attr("cn").present().root().kind() == kind::present);
		CHECK(attr("cn").contains("").root().kind() == kind::present);

		const auto sw = attr("cn").starts_with("J(");
		CHECK(sw.root().kind() == kind::substrings);
		CHECK(sw.root().initial() == "J(");
		CHECK(sw.root().any().empty());
		CHECK_FALSE(sw.root().final());
		const auto c = attr("cn").contains("o");
		CHECK_FALSE(c.root().initial());
		CHECK(std::vector<std::string_view>(c.root().any().begin(), c.root().any().end())
			  == std::vector<std::string_view>{ "o" });
		CHECK(attr("cn").ends_with("x").root().final() == "x");
	}
	SECTION("every special byte is escaped in the text, and kept as is in the tree")
	{
		const auto f = attr("cn") == "a*b(c)d\\e"s + '\0' + "f";
		CHECK(text_of(f) == "(cn=a\\2ab\\28c\\29d\\5ce\\00f)");
		CHECK(f.root().value() == "a*b(c)d\\e"s + '\0' + "f");
		CHECK(ldap::escape_filter_value("\xc3\xa9\n") == "\xc3\xa9\n");
		CHECK(text_of(attr("cn").starts_with("*")) == "(cn=\\2a*)");
	}
	SECTION("injection attempts stay inside the value")
	{
		const std::string evil = "x)(uid=*";
		const auto f = attr("objectClass") == "person" && attr("uid") == evil;
		CHECK(text_of(f) == "(&(objectClass=person)(uid=x\\29\\28uid=\\2a))");
		CHECK(canonical(text_of(f)) == text_of(f));
		// The BER has exactly two equality assertions, the second with the raw value.
		auto b = to_ber(f);
		REQUIRE(b);
		ber::reader r(*b);
		auto a = r.enter(ber::context(0));
		REQUIRE(a);
		REQUIRE(a->enter(ber::context(3)));
		auto uid = a->enter(ber::context(3));
		REQUIRE(uid);
		CHECK(uid->read_string() == "uid");
		CHECK(uid->read_string() == std::string_view(evil));
		CHECK(a->empty());
	}
	SECTION("operators")
	{
		const auto a = attr("a") == "1";
		const auto b = attr("b") == "2";
		const auto c = attr("c") == "3";
		CHECK(text_of(a && b) == "(&(a=1)(b=2))");
		CHECK(text_of(a || b) == "(|(a=1)(b=2))");
		CHECK(text_of(!a) == "(!(a=1))");
		CHECK(text_of(!!a) == "(!(!(a=1)))");
		// Chains are flattened whichever way they nest; mixed operators nest.
		CHECK(text_of(a && b && c) == "(&(a=1)(b=2)(c=3))");
		CHECK(text_of(a && (b && c)) == "(&(a=1)(b=2)(c=3))");
		CHECK(text_of((a && b) && (c && a)) == "(&(a=1)(b=2)(c=3)(a=1))");
		CHECK(text_of(a || b || c) == "(|(a=1)(b=2)(c=3))");
		CHECK(text_of(a || (b || c)) == "(|(a=1)(b=2)(c=3))");
		CHECK(text_of((a || b) && c) == "(&(|(a=1)(b=2))(c=3))");
		CHECK(text_of((a && b) || c) == "(|(&(a=1)(b=2))(c=3))");
		CHECK(text_of(c || (a && b)) == "(|(c=3)(&(a=1)(b=2)))");
		CHECK((a && b && c).depth() == 2);
		CHECK((a && b && c).elements() == 4);
		CHECK(((a || b) && !c).depth() == 3);
		CHECK(((a || b) && !c).elements() == 6);
		// Operands are not changed; the same operand can appear twice.
		CHECK(text_of(a && a) == "(&(a=1)(a=1))");
		CHECK(text_of(a) == "(a=1)");
		// Rvalue operands on either side (their storage is reused).
		CHECK(text_of((attr("x") == "1") && (attr("y") == "2" || attr("z") == "3")) == "(&(x=1)(|(y=2)(z=3)))");
		CHECK(text_of((attr("x") == "1" && attr("y") == "2") && (attr("z") == "3" && attr("w") == "4"))
			  == "(&(x=1)(y=2)(z=3)(w=4))");
		// Long chains stay flat, far below max_filter_depth.
		ldap::filter all = a;
		for (int i = 0; i < 200; ++i) {
			all = all && (attr("n") == std::to_string(i));
		}
		CHECK(all.depth() == 2);
		CHECK(all.elements() == 202);
		CHECK(to_ber(all).has_value());
	}
	SECTION("DESIGN.md example")
	{
		const std::string user_input = "x)(uid=*";
		const std::string prefix = "j";
		auto f = attr("objectClass") == "person" && (attr("uid") == user_input || attr("mail").starts_with(prefix))
				 && !attr("disabled").present();
		CHECK(text_of(f) == "(&(objectClass=person)(|(uid=x\\29\\28uid=\\2a)(mail=j*))(!(disabled=*)))");
		CHECK(canonical(text_of(f)) == text_of(f));
		CHECK(f == parsed("(&(objectClass=person)(|(uid=x\\29\\28uid=\\2a)(mail=j*))(!(disabled=*)))"));
	}
	SECTION("attribute objects")
	{
		CHECK(text_of(attr(ldap::attribute{ "mail" }) == "x") == "(mail=x)");
		const auto bad = attr(ldap::attribute::unchecked("uid=*)(cn")) == "x";
		CHECK(bad.empty());
		REQUIRE(bad.build_error().has_value());
		CHECK(bad.build_error()->code == ldap::client_errc::invalid_attribute);
		CHECK(
		  attr(ldap::attribute::unchecked("")).present().build_error()->code == ldap::client_errc::invalid_attribute);
	}
	SECTION("empty filters")
	{
		const ldap::filter empty;
		CHECK(empty.empty());
		CHECK(empty.depth() == 0);
		CHECK(empty.to_string().empty());
		CHECK(empty == ldap::filter{});
		CHECK_FALSE(empty == (attr("a") == "1"));
		// Combining never turns an empty filter into a condition.
		CHECK((empty && attr("a") == "1").empty());
		CHECK((attr("a") == "1" || empty).empty());
		CHECK((!empty).empty());
		auto r = to_ber(empty);
		REQUIRE_FALSE(r);
		CHECK(r.error().code == client_errc::invalid_filter);
		CHECK(r.error().context == "filter: empty");
		CHECK_FALSE(empty.build_error().has_value());
	}
}

TEST_CASE("filter::failed keeps its error through the operators", "[filter][builder]")
{
	using ldap::filters::attr;
	const auto why = ldap::make_error(client_errc::encode_error, "value \xC3\xA9: refused");
	const auto failed = ldap::filter::failed(why);
	CHECK(failed.empty());
	CHECK(failed.to_string().empty());
	CHECK(failed == ldap::filter{});
	CHECK(failed.build_error() == why);
	const auto other = ldap::filter::failed(ldap::make_error(client_errc::invalid_filter, "other"));
	CHECK((attr("a") == "1" && failed).build_error() == why);
	CHECK((failed || attr("a") == "1").build_error() == why);
	CHECK((failed && other).build_error() == why);
	CHECK((ldap::filter{} || failed).build_error() == why);
	CHECK((!failed).build_error() == why);
	ldap::filter moved = ldap::filter::failed(why);
	const ldap::filter to(std::move(moved));
	CHECK(to.build_error() == why);
	CHECK_FALSE(moved.build_error().has_value());// NOLINT(bugprone-use-after-move)
	std::pmr::monotonic_buffer_resource mr;
	CHECK(ldap::filter(failed, &mr).build_error() == why);
	auto r = to_ber(failed && attr("a") == "1");
	REQUIRE_FALSE(r);
	CHECK(r.error() == why);
}

TEST_CASE("combining parsed filters cannot change their meaning", "[filter][builder]")
{
	using namespace ldap::filters;
	const auto c = attr("c") == "3";
	SECTION("malformed text is rejected by filter::parse(), so there is nothing to combine")
	{
		// Built unsafely by string concatenation with user input "x)(|(uid=*".
		for (auto text : { "(uid=x)(|(uid=*)"sv, "a=1)(|(b=*)"sv, "(&(a=1))(b=2)"sv, "(a=\\zz)"sv, ""sv }) {
			INFO(text);
			auto r = ldap::filter::parse(text);
			REQUIRE_FALSE(r);
			CHECK(r.error().code == client_errc::invalid_filter);
		}
		// A result<filter> is not a filter: `filter::parse(...) && f` does not make a
		// filter until the error is handled.
		STATIC_CHECK_FALSE(combinable<ldap::result<ldap::filter>>);
		STATIC_CHECK(combinable<ldap::filter>);
	}
	SECTION("a parsed operand is one subtree of the result, whatever it contains")
	{
		for (auto text : { "cn=x"sv,
			   "(cn=x)"sv,
			   "(x=\\29\\28)"sv,
			   "(&(x=\\29))"sv,
			   "(|(a=1)(b=2))"sv,
			   "(!(a=*))"sv,
			   "(&)"sv,
			   "(|)"sv,
			   "(cn:dn:2.5.13.5:=a\\29)"sv,
			   "(cn=*\\28*\\29*)"sv }) {
			INFO(text);
			const auto p = parsed(text);
			const auto neg = !p;
			// (!p): exactly p below the new node, in text and in BER.
			CHECK(text_of(neg) == "(!" + text_of(p) + ")");
			const auto operand = *to_ber(p);
			const auto negated = *to_ber(neg);
			ber::reader r(negated);
			auto inner = r.enter(ber::context(2));
			REQUIRE(inner);
			CHECK(inner->remaining() == operand.size());
			CHECK(hex(std::span(negated).subspan(negated.size() - operand.size())) == hex(operand));
			// p || c and c && p: p is a child (or, for an OR resp. AND, its
			// children are), so the text of p appears unchanged.
			const std::string pt = text_of(p);
			const auto or_ = text_of(p || c);
			const auto and_ = text_of(c && p);
			if (p.root().kind() == ldap::filter::kind::or_) {
				CHECK(or_ == pt.substr(0, pt.size() - 1) + "(c=3))");
			} else {
				CHECK(or_ == "(|" + pt + "(c=3))");
			}
			if (p.root().kind() == ldap::filter::kind::and_) {
				CHECK(and_ == "(&(c=3)" + pt.substr(2));
			} else {
				CHECK(and_ == "(&(c=3)" + pt + ")");
			}
			// And the combination is the tree that parsing its text gives.
			CHECK(parsed(or_) == (p || c));
			CHECK(parsed(and_) == (c && p));
		}
	}
	SECTION("merging an AND into an AND (an OR into an OR) keeps the meaning")
	{
		CHECK(text_of(parsed("&(a=1)(b=2)") && c) == "(&(a=1)(b=2)(c=3))");
		CHECK(text_of(parsed("(|(a=1)(b=2))") && c) == "(&(|(a=1)(b=2))(c=3))");
		// (&) is true, so (&) && c is c; (|) is false, so (|) || c is c.
		CHECK(text_of(parsed("(&)") && c) == "(&(c=3))");
		CHECK(text_of(parsed("(|)") || c) == "(|(c=3))");
		CHECK(text_of(parsed("(|)") && c) == "(&(|)(c=3))");
	}
}

TEST_CASE("filter equality compares trees", "[filter]")
{
	using namespace ldap::filters;
	CHECK(parsed("(&(a=1)(b=2))") == (attr("a") == "1" && attr("b") == "2"));
	CHECK(parsed("uid=jdoe") == parsed("(uid=jdoe)"));
	CHECK(parsed("(cn=\\41)") == parsed("(cn=A)"));
	CHECK(parsed("(cn=a**b)") == parsed("(cn=a*b)"));
	CHECK(parsed("(cn=*)") == attr("cn").present());
	CHECK(parsed("(cn=J*)") == attr("cn").starts_with("J"));
	CHECK(parsed("(A:DN:=v)") == parsed("(A:dn:=v)"));

	CHECK_FALSE(parsed("(cn=a)") == parsed("(CN=a)"));// descriptions compare exactly
	CHECK_FALSE(parsed("(cn=a)") == parsed("(cn=A)"));
	CHECK_FALSE(parsed("(cn=a)") == parsed("(cn>=a)"));
	CHECK_FALSE(parsed("(&(a=1)(b=2))") == parsed("(&(b=2)(a=1))"));
	CHECK_FALSE(parsed("(&(a=1)(b=2))") == parsed("(|(a=1)(b=2))"));
	CHECK_FALSE(parsed("(&(a=1)(b=2))") == parsed("(&(a=1))"));
	CHECK_FALSE(parsed("(&(a=1))") == parsed("(&(a=1)(b=2))"));
	CHECK_FALSE(parsed("(&(&(a=1))(b=2))") == parsed("(&(&(a=1)(b=2)))"));
	CHECK_FALSE(parsed("(cn=a*b)") == parsed("(cn=a*b*)"));
	CHECK_FALSE(parsed("(cn=*a*b)") == parsed("(cn=*a*b*)"));
	CHECK_FALSE(parsed("(cn=*a*)") == parsed("(cn=a*)"));
	CHECK_FALSE(parsed("(cn:=v)") == parsed("(cn:dn:=v)"));
	CHECK_FALSE(parsed("(cn:1.2:=v)") == parsed("(cn:1.3:=v)"));
	CHECK_FALSE(parsed("(!(a=1))") == parsed("(a=1)"));
	CHECK_FALSE(parsed("(cn=a*b*)") == parsed("(cn=a*b*c*)"));// the same parts, then one more
	CHECK_FALSE(parsed("(&)") == parsed("(&(a=1))"));// an absolute true has no children
	CHECK_FALSE(parsed("(&(a=1))") == parsed("(&)"));
	// No any part between initial and final.
	const auto no_any = parsed("(cn=a*b)");
	CHECK(std::ranges::empty(no_any.root().any()));

	// Copies are equal and independent.
	const auto f = parsed("(&(a=1)(|(b=*)(c=x*y)))");
	auto g = f;
	CHECK(g == f);
	g = g && parsed("(d=1)");
	CHECK_FALSE(g == f);
	CHECK(text_of(f) == "(&(a=1)(|(b=*)(c=x*y)))");
}

TEST_CASE("filter views expose every node", "[filter]")
{
	using kind = ldap::filter::kind;
	const auto f = parsed("(&(objectClass=person)(|(cn=Jo*hn*Sm*ith)(!(uid=admin)))(sn:dn:2.5.13.5:=x)(:1.2.3:=y))");
	const auto root = f.root();
	CHECK(root.kind() == kind::and_);
	CHECK(root.attribute().empty());
	std::vector<ldap::filter::view> children(root.children().begin(), root.children().end());
	REQUIRE(children.size() == 4);
	CHECK(children[0].kind() == kind::equality);
	CHECK(children[0].attribute() == "objectClass");
	CHECK(children[0].value() == "person");

	std::vector<ldap::filter::view> alts(children[1].children().begin(), children[1].children().end());
	REQUIRE(alts.size() == 2);
	CHECK(alts[0].kind() == kind::substrings);
	CHECK(alts[0].attribute() == "cn");
	CHECK(alts[0].initial() == "Jo");
	CHECK(std::vector<std::string_view>(alts[0].any().begin(), alts[0].any().end())
		  == std::vector<std::string_view>{ "hn", "Sm" });
	CHECK(alts[0].final() == "ith");
	CHECK(alts[0].children().empty());// parts are not children
	CHECK(alts[1].kind() == kind::not_);
	REQUIRE_FALSE(alts[1].children().empty());
	CHECK((*alts[1].children().begin()).value() == "admin");

	CHECK(children[2].kind() == kind::extensible_match);
	CHECK(children[2].attribute() == "sn");
	CHECK(children[2].dn_attributes());
	CHECK(children[2].matching_rule() == "2.5.13.5");
	CHECK(children[2].value() == "x");
	CHECK(children[3].attribute().empty());
	CHECK_FALSE(children[3].dn_attributes());
	CHECK(children[3].matching_rule() == "1.2.3");

	CHECK(f.depth() == 4);
	CHECK(f.elements() == 12);// 8 nodes and 4 substring parts
	// Leaves have no parts or children.
	CHECK_FALSE(children[0].initial());
	CHECK(children[0].any().empty());
	CHECK_FALSE(children[0].final());
}

// child_range and substring_range are borrowed views.
static_assert(std::ranges::view<ldap::filter::child_range>);
static_assert(std::ranges::borrowed_range<ldap::filter::child_range>);
static_assert(std::ranges::forward_range<ldap::filter::child_range>);
static_assert(std::ranges::view<ldap::filter::substring_range>);
static_assert(std::ranges::borrowed_range<ldap::filter::substring_range>);
static_assert(std::ranges::forward_range<ldap::filter::substring_range>);
// view_interface is an empty base: the layout is still just the iterator.
static_assert(sizeof(ldap::filter::child_range) == sizeof(ldap::filter::child_iterator));
static_assert(sizeof(ldap::filter::substring_range) == sizeof(ldap::filter::substring_iterator));
static_assert(std::is_trivially_copyable_v<ldap::filter::child_range>);
static_assert(std::is_trivially_copyable_v<ldap::filter::substring_range>);

TEST_CASE("filter child and substring ranges are borrowed views", "[filter]")
{
	using kind = ldap::filter::kind;
	using view = ldap::filter::view;
	const auto f = parsed("(&(objectClass=person)(cn=*)(sn=Jo*hn*Sm*ith)(mail=*))");

	// find on the temporary range returns a real iterator.
	auto it = std::ranges::find(f.root().children(), kind::present, &view::kind);
	static_assert(std::same_as<decltype(it), ldap::filter::child_iterator>);
	REQUIRE(it != ldap::filter::child_iterator{});
	CHECK((*it).attribute() == "cn");
	CHECK(std::ranges::find(f.root().children(), kind::approx, &view::kind) == ldap::filter::child_iterator{});

	auto subs = std::ranges::find(f.root().children(), kind::substrings, &view::kind);
	REQUIRE(subs != ldap::filter::child_iterator{});
	auto part = std::ranges::find((*subs).any(), "Sm"sv);
	static_assert(std::same_as<decltype(part), ldap::filter::substring_iterator>);
	REQUIRE(part != ldap::filter::substring_iterator{});
	CHECK(*part == "Sm");
	CHECK(std::ranges::distance((*subs).any()) == 2);

	// Members from view_interface (front, operator bool); empty() is ours.
	CHECK(f.root().children().front().attribute() == "objectClass");
	CHECK(static_cast<bool>(f.root().children()));
	CHECK_FALSE(static_cast<bool>((*it).children()));
	CHECK((*subs).any().front() == "hn");
	CHECK((*it).any().empty());

	// Composes with adaptors, by value, without dangling.
	auto present = f.root().children() | std::views::filter([](view v) { return v.kind() == kind::present; })
				   | std::views::transform(&view::attribute);
	CHECK(std::ranges::to<std::vector<std::string_view>>(present) == std::vector<std::string_view>{ "cn", "mail" });
	auto lengths = (*subs).any() | std::views::transform([](std::string_view s) { return s.size(); });
	CHECK(std::ranges::to<std::vector<std::size_t>>(lengths) == std::vector<std::size_t>{ 2, 2 });
	auto first_two = f.root().children() | std::views::take(2) | std::views::transform(&view::attribute);
	CHECK(std::ranges::to<std::vector<std::string_view>>(first_two)
		  == std::vector<std::string_view>{ "objectClass", "cn" });
}

TEST_CASE("filter parser accepts RFC 4515 text; to_string is canonical", "[filter][parser]")
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
	auto ber_of = [](std::string_view text) { return hex(*to_ber(parsed(text))); };
	CHECK(ber_of("(&)") == "A0 00");
	CHECK(ber_of("(|)") == "A1 00");
	CHECK(ber_of("(cn=*)") == "87 02 63 6E");
	CHECK(ber_of("(!(a=b))") == "A2 08 A3 06 04 01 61 04 01 62");
	CHECK(ber_of("(a=*x*)") == "A4 08 04 01 61 30 03 81 01 78");
	// dnAttributes is DEFAULT FALSE: omitted unless :dn is given.
	CHECK(ber_of("(a:=x)") == "A9 06 82 01 61 83 01 78");
	CHECK(ber_of("(a:dn:=x)") == "A9 09 82 01 61 83 01 78 84 01 FF");
	CHECK(ber_of("(:r:=x)") == "A9 06 81 01 72 83 01 78");
	// Builders write the same bytes.
	using namespace ldap::filters;
	CHECK(hex(*to_ber(attr("cn").present())) == "87 02 63 6E");
	CHECK(hex(*to_ber(!(attr("a") == "b"))) == "A2 08 A3 06 04 01 61 04 01 62");
	CHECK(hex(*to_ber(attr("a").contains("x"))) == "A4 08 04 01 61 30 03 81 01 78");
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
	  "(cn=x"s + '\0' + ")",
	  "(cn"s + '\0' + "=x)",
	  "(cn=*\\zz*)",
	  "(cn=*\\2*)");
	INFO(bad);
	auto r = ldap::filter::parse(bad);
	REQUIRE_FALSE(r);
	CHECK(r.error().code == client_errc::invalid_filter);
	CHECK(r.error().context.contains("position"));
}

TEST_CASE("filter parse errors report the position in the caller's text", "[filter][parser]")
{
	auto ctx = [](std::string_view text) { return std::string(ldap::filter::parse(text).error().context); };
	CHECK(ctx("(cn=a(b)") == "filter: unescaped '(' or NUL in value at position 5");
	CHECK(ctx("(&(cn=x)(sn=\\zz))") == "filter: invalid escape (expected \\ and two hex digits) at position 12");
	CHECK(ctx("(c n=x)") == "filter: expected a filter type ('=', '~=', '>=', '<=' or ':=') at position 2");
	CHECK(ctx("(cn=**)") == "filter: substring filter without any substring at position 4");
	CHECK(ctx("(cn~=a*)") == "filter: unescaped '*' in value at position 6");
	// Wrapped text: positions still refer to the original.
	CHECK(ctx("cn=a(b") == "filter: unescaped '(' or NUL in value at position 4");
	CHECK(ctx("(cn=x)(sn=y)") == "filter: unexpected characters after the filter at position 6");
}

TEST_CASE("filter nesting is bounded", "[filter][limits]")
{
	auto nested = [](std::size_t depth, const std::string &open) {
		std::string t;
		for (std::size_t i = 1; i < depth; ++i) {
			t += open;
		}
		t += "(a=b)";
		for (std::size_t i = 1; i < depth; ++i) {
			t += ')';
		}
		return t;
	};
	CHECK(parsed(nested(ldap::max_filter_depth, "(&")).depth() == ldap::max_filter_depth);
	CHECK(to_ber(parsed(nested(ldap::max_filter_depth, "(!"))).has_value());
	auto too_deep = ldap::filter::parse(nested(ldap::max_filter_depth + 1, "(|"));
	REQUIRE_FALSE(too_deep);
	CHECK(too_deep.error().code == client_errc::invalid_filter);
	CHECK(too_deep.error().context == "filter: nested too deeply (more than 24 levels) at position 48");

	// Custom limits.
	auto custom_deep = ldap::filter::parse(nested(3, "(&"), { .max_depth = 2 });
	REQUIRE_FALSE(custom_deep);
	CHECK(custom_deep.error().code == client_errc::invalid_filter);
	CHECK(custom_deep.error().context == "filter: nested too deeply (more than 2 levels) at position 4");
	CHECK(ldap::filter::parse(nested(30, "(&"), { .max_depth = 30 }).has_value());

	// Bombs fail quickly without deep recursion.
	CHECK(ldap::filter::parse(std::string(100'000, '(')).error().code == client_errc::invalid_filter);
	std::string bomb;
	for (int i = 0; i < 100'000; ++i) {
		bomb += "(!";
	}
	CHECK(ldap::filter::parse(bomb).error().code == client_errc::invalid_filter);
	bomb.clear();
	for (int i = 0; i < 100'000; ++i) {
		bomb += "(&";
	}
	CHECK(ldap::filter::parse(bomb).error().code == client_errc::invalid_filter);
}

TEST_CASE("builders beyond the limits fail when encoded", "[filter][limits][builder]")
{
	using namespace ldap::filters;
	SECTION("depth: fails with invalid_filter, before anything is written")
	{
		auto f = attr("a") == "b";
		for (std::size_t i = 1; i < ldap::max_filter_depth; ++i) {
			f = !std::move(f);
		}
		CHECK(f.depth() == ldap::max_filter_depth);
		CHECK(to_ber(f).has_value());
		f = !std::move(f);
		auto r = to_ber(f);
		REQUIRE_FALSE(r);
		CHECK(r.error().code == client_errc::invalid_filter);
		CHECK(r.error().context == "filter: nested too deeply (25 levels, at most 24)");
		CHECK(to_ber(f, { .max_depth = 25 }).has_value());
	}
	SECTION("a very deep builder filter is safe to copy, compare, print and destroy")
	{
		// No recursion anywhere except encoding, which refuses it first.
		auto f = attr("a") == "b";
		for (int i = 0; i < 200'000; ++i) {
			f = !std::move(f);
		}
		CHECK(f.depth() == 200'001);
		const auto copy = f;
		CHECK(copy == f);
		CHECK_FALSE(copy == !f);
		const auto text = f.to_string();
		CHECK(text.size() == (200'000uz * 3) + 5);
		CHECK(text.starts_with("(!(!(!"));
		CHECK(text.substr(200'000uz * 2).starts_with("(a=b))))"));
		CHECK(text.ends_with("))))"));
		CHECK(to_ber(f).error().code == client_errc::invalid_filter);
		auto alternating = attr("a") == "b";
		for (int i = 0; i < 100'000; ++i) {
			alternating =
			  i % 2 == 0 ? (std::move(alternating) || attr("x") == "1") : (std::move(alternating) && attr("y") == "2");
		}
		CHECK(alternating.depth() == 100'001);
		CHECK(to_ber(alternating).error().code == client_errc::invalid_filter);
	}
	SECTION("elements")
	{
		auto f = attr("m") == "0";
		for (std::size_t i = 1; i + 1 < ldap::max_filter_elements; ++i) {
			f = std::move(f) || attr("m") == "1";
		}
		CHECK(f.elements() == ldap::max_filter_elements);
		CHECK(to_ber(f).has_value());
		f = std::move(f) || attr("m") == "2";
		auto r = to_ber(f);
		REQUIRE_FALSE(r);
		CHECK(r.error().code == client_errc::invalid_filter);
		CHECK(r.error().context == "filter: too many elements (10001, at most 10000)");
	}
}

TEST_CASE("combining a filter with itself copies instead of emptying it", "[filter][builder]")
{
	using namespace ldap::filters;
	const auto expected_and = (attr("cn") == "x" && attr("cn") == "x").to_string();
	const auto expected_or = (attr("cn") == "x" || attr("cn") == "x").to_string();
	{
		auto f = attr("cn") == "x";
		f = std::move(f) && f;
		CHECK(f.to_string() == expected_and);
	}
	{
		auto f = attr("cn") == "x";
		f = f && std::move(f);
		CHECK(f.to_string() == expected_and);
	}
	{
		auto f = attr("cn") == "x";
		f = std::move(f) && std::move(f);
		CHECK(f.to_string() == expected_and);
	}
	{
		auto f = attr("cn") == "x";
		f = std::move(f) || f;
		CHECK(f.to_string() == expected_or);
	}
	{
		auto f = attr("cn") == "x";
		f = std::move(f) || std::move(f);
		CHECK(f.to_string() == expected_or);
	}
	{
		auto f = attr("cn") == "x";
		f = f || std::move(f);
		CHECK(f.to_string() == expected_or);
	}
}

TEST_CASE("combining with an rvalue on another resource copies onto the left one's", "[filter][builder][pmr]")
{
	using namespace ldap::filters;
	jhetz::ldap::test::counting_resource left_mr;
	jhetz::ldap::test::counting_resource right_mr;
	const auto f = ldap::filter::parse("(cn=a-long-value-that-allocates)", &left_mr);
	REQUIRE(f.has_value());
	auto g = ldap::filter::parse("(sn=another-long-value-that-allocates)", &right_mr);
	REQUIRE(g.has_value());
	const auto combined = *f || std::move(*g);
	CHECK(combined.to_string() == "(|(cn=a-long-value-that-allocates)(sn=another-long-value-that-allocates))");
	CHECK(combined.get_allocator().resource() == &left_mr);
}

TEST_CASE("building long chains is linear in either direction", "[filter][builder]")
{
	// Each would take minutes if a combination copied the accumulated side.
	using namespace ldap::filters;
	constexpr int n = 100'000;
	const auto start = std::chrono::steady_clock::now();
	ldap::filter left = attr("a") == "0";
	for (int i = 1; i < n; ++i) {
		left = std::move(left) || attr("a") == "1";
	}
	ldap::filter right = attr("a") == "0";
	for (int i = 1; i < n; ++i) {
		right = attr("a") == "1" || std::move(right);
	}
	ldap::filter lvalue_right = attr("a") == "0";
	const auto leaf = attr("a") == "1";
	for (int i = 1; i < n; ++i) {
		lvalue_right = leaf || std::move(lvalue_right);
	}
	const auto elapsed = std::chrono::steady_clock::now() - start;
	CHECK(left.elements() == n + 1);
	CHECK(right.elements() == n + 1);
	CHECK(lvalue_right.elements() == n + 1);
	CHECK(left.depth() == 2);
	CHECK_FALSE(left == right);// (a=0) is first in one, last in the other
	CHECK(elapsed < std::chrono::seconds(20));// ~10 ms normally, even under ASan
}

TEST_CASE("filters are limited to max_filter_elements elements", "[filter][limits]")
{
	auto and_of = [](std::size_t children) {
		std::string t = "(&";
		for (std::size_t i = 0; i < children; ++i) {
			t += "(a=*)";
		}
		return t + ")";
	};
	// The AND itself counts: 1 + 9,999 children is the maximum.
	CHECK(parsed(and_of(ldap::max_filter_elements - 1)).elements() == ldap::max_filter_elements);
	auto too_many = ldap::filter::parse(and_of(ldap::max_filter_elements));
	REQUIRE_FALSE(too_many);
	CHECK(too_many.error().code == client_errc::invalid_filter);
	CHECK(too_many.error().context == "filter: too many elements (more than 10000) at position 49997");
	auto custom_many = ldap::filter::parse(and_of(3), { .max_elements = 3 });
	REQUIRE_FALSE(custom_many);
	CHECK(custom_many.error().context == "filter: too many elements (more than 3) at position 12");
	CHECK(ldap::filter::parse(and_of(2), { .max_elements = 3 }));
	// Substring parts count: one node and five parts.
	CHECK(parsed("(a=1*2*3*4*5)").elements() == 6);
	CHECK_FALSE(ldap::filter::parse("(a=1*2*3*4*5)", { .max_elements = 5 }));
	CHECK(ldap::filters::attr("cn").contains("x").elements() == 2);
	// A substring filter with a huge number of parts is capped like any other.
	std::string many = "(a=";
	for (std::size_t i = 0; i < ldap::max_filter_elements; ++i) {
		many += "x*";
	}
	many += "x)";
	auto capped = ldap::filter::parse(many);
	REQUIRE_FALSE(capped);
	CHECK(capped.error().context == "filter: too many elements (more than 10000) at position 20002");

	// Encode with custom limits.
	CHECK_FALSE(to_ber(parsed(and_of(3)), { .max_elements = 3 }));
	CHECK(to_ber(parsed(and_of(2)), { .max_elements = 3 }));

	// Decode: BER built directly, 3 bytes per child (87 01 61).
	auto ber_and_of = [](std::size_t children) {
		ber::writer w;
		w.constructed(ber::context(0), [&](ber::writer &a) {
			for (std::size_t i = 0; i < children; ++i) {
				a.octet_string("a", ber::context(7));
			}
		});
		return w.take();
	};
	CHECK(from_ber(ber_and_of(ldap::max_filter_elements - 1)).has_value());
	{
		// Many times the limit: fails at the first element over it.
		auto t = from_ber(ber_and_of(100'000));
		REQUIRE_FALSE(t);
		CHECK(t.error().code == client_errc::decode_error);
		CHECK(t.error().context.contains("more than 10000 filter elements"));
	}
	{
		// Decoding counts substring parts as elements.
		const auto parts = to_ber(parsed("(a=1*2*3)"));
		REQUIRE(parts.has_value());
		auto t = from_ber(*parts, { .max_elements = 3 });
		REQUIRE_FALSE(t);
		CHECK(t.error().code == client_errc::decode_error);
		CHECK(t.error().context.starts_with("filter: more than 3 filter elements at offset "));
		CHECK(from_ber(*parts, { .max_elements = 4 }).has_value());
	}
	{
		const auto small = ber_and_of(3);
		CHECK_FALSE(from_ber(small, { .max_elements = 3 }));
		auto t = from_ber(small, { .max_elements = 4 });
		REQUIRE(t);
		CHECK(t->to_string() == "(&(a=*)(a=*)(a=*))");
		CHECK(t->elements() == 4);
		CHECK(t->depth() == 2);
	}
}

TEST_CASE("decode_filter rejects BER without an RFC 4515 form", "[filter][decode]")
{
	auto decode = [](auto body) {
		ber::writer w;
		body(w);
		return from_ber(w.take());
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
		w.constructed(ber::context(9), [](ber::writer &e) {
			e.octet_string("1.2.", ber::context(1));
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
	auto deep = decode(nested(ldap::max_filter_depth + 1));
	REQUIRE_FALSE(deep.has_value());
	CHECK(std::string(deep.error().context)
		  == "filter: more than " + std::to_string(ldap::max_filter_depth) + " levels at offset "
			   + std::to_string(2 * ldap::max_filter_depth));

	// Accepted variations: explicit dnAttributes FALSE, unknown trailing
	// elements. The tree is the same as without them.
	auto t = decode([](ber::writer &w) {
		w.constructed(ber::context(9), [](ber::writer &e) {
			e.octet_string("cn", ber::context(2));
			e.octet_string("v", ber::context(3));
			e.boolean(false, ber::context(4));
			e.null(ber::context(5));
		});
	});
	REQUIRE(t);
	CHECK(t->to_string() == "(cn:=v)");
	CHECK(*t == parsed("(cn:=v)"));
}

TEST_CASE("equality builder round-trips every byte", "[filter][builder]")
{
	std::string all;
	for (int c = 0; c < 256; ++c) {
		all += static_cast<char>(c);
	}
	for (const std::string &v : { all, ""s, "*"s, "\\"s, "()"s, "\0"s }) {
		const auto f = ldap::filters::attr("cn") == v;
		auto b = to_ber(f);
		REQUIRE(b);
		ber::reader r(*b);
		auto eq = r.enter(ber::context(3));
		REQUIRE(eq);
		CHECK(eq->read_string() == "cn");
		CHECK(eq->read_string() == std::string_view(v));
		auto back = from_ber(*b);
		REQUIRE(back);
		CHECK(*back == f);
		CHECK(back->root().value() == std::string_view(v));
		CHECK(canonical(text_of(f)) == text_of(f));
	}
}

TEST_CASE("extensible match builders", "[filter][builders]")
{
	using ldap::filters::attr;
	CHECK(attr("cn").matches("caseExactMatch", "Jane").to_string() == "(cn:caseExactMatch:=Jane)");
	CHECK(attr("ou").matches("", "people", true).to_string() == "(ou:dn:=people)");
	CHECK(attr("cn").matches("2.5.13.5", "x*y", true).to_string() == "(cn:dn:2.5.13.5:=x\\2ay)");
	CHECK(ldap::filters::rule_matches("2.5.13.5", "v").to_string() == "(:2.5.13.5:=v)");
	CHECK(ldap::filters::rule_matches("dn", "v", true).to_string() == "(:dn:dn:=v)");
	// Same trees as the parsed text.
	CHECK(attr("cn").matches("caseExactMatch", "Jane", true) == parsed("(cn:dn:caseExactMatch:=Jane)"));
	CHECK(ldap::filters::rule_matches("1.2.3", "v") == parsed("(:1.2.3:=v)"));
	const auto ext = attr("cn").matches("caseExactMatch", "Jane", true);
	const auto view = ext.root();
	CHECK(view.kind() == ldap::filter::kind::extensible_match);
	CHECK(view.matching_rule() == "caseExactMatch");
	CHECK(view.dn_attributes());
	// Round trip through BER.
	const auto f = attr("cn").matches("caseExactMatch", "Jane");
	CHECK(from_ber(*to_ber(f)).value() == f);

	const auto failed_with = [](const ldap::filter &bad) {
		const auto why = bad.build_error();
		return bad.empty() && why && why->code == ldap::client_errc::invalid_filter;
	};
	CHECK(failed_with(attr("cn").matches("not a rule!", "v")));
	CHECK(failed_with(attr("cn").matches("dn", "v")));
	CHECK(failed_with(ldap::filters::rule_matches("", "v")));
	CHECK(attr("cn").matches("dn", "v").build_error()->context
		  == "filters: a matching rule named \"dn\" needs dn_attributes");
}

// ---------------------------------------------------------------- escaping helpers

TEST_CASE("escape_filter_value is what to_string writes, and unescape_filter_value reverses it", "[filter][escape]")
{
	using namespace ldap::filters;
	const std::string value = GENERATE(std::string{},
	  "plain"s,
	  " spaces "s,
	  "*"s,
	  "("s,
	  ")"s,
	  "\\"s,
	  "\0"s,
	  "x)(uid=*"s,
	  "a=b#c,d+e;f<g>h\""s,
	  "caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac"s,// 2- and 3-byte UTF-8
	  "\xf0\x9f\x98\x80\xf0\x90\x8d\x88"s,// 4-byte UTF-8
	  "\xff\xc3"s,// not UTF-8
	  "\xf0\x9f\x98"s);// truncated 4-byte sequence
	INFO(value);
	const auto text = std::string(ldap::escape_filter_value(value));
	CHECK(text_of(attr("cn") == value) == "(cn=" + text + ")");
	const auto back = ldap::unescape_filter_value(text);
	REQUIRE(back.has_value());
	CHECK(*back == std::string_view(value));
	const auto parsed = ldap::filter::parse("(cn=" + text + ")");
	REQUIRE(parsed.has_value());
	CHECK(parsed->root().value() == value);
}

TEST_CASE("escape_filter_value keeps UTF-8 and escapes only specials", "[filter][escape]")
{
	CHECK(ldap::escape_filter_value("\xf0\x9f\x98\x80") == "\xf0\x9f\x98\x80");
	CHECK(ldap::escape_filter_value("a*b(c)d\\e"s + '\0') == "a\\2ab\\28c\\29d\\5ce\\00");
	CHECK(ldap::escape_filter_value(" #,=\n") == " #,=\n");
	CHECK(ldap::escape_filter_value("").empty());
}

TEST_CASE("unescape_filter_value", "[filter][escape]")
{
	CHECK(ldap::unescape_filter_value("\\2A\\2a\\c3\\A9") == "**\xc3\xa9");// hex in either case
	CHECK(ldap::unescape_filter_value("\\ff\\00") == "\xff\0"sv);// escapes give any octet
	CHECK(ldap::unescape_filter_value("\xf0\x9f\x98\x80 ok") == "\xf0\x9f\x98\x80 ok");
	CHECK(ldap::unescape_filter_value("") == "");
	CHECK(ldap::unescape_filter_value("a\\").error().context
		  == "filter value: invalid escape (expected \\ and two hex digits) at position 1");
	using P = std::pair<std::string, std::string>;
	const auto [text, what] = GENERATE(P{ "\\", "invalid escape" },
	  P{ "\\4", "invalid escape" },
	  P{ "\\zz", "invalid escape" },
	  P{ "\\4g", "invalid escape" },
	  P{ "\\x41", "invalid escape" },
	  P{ "a*", "unescaped '*'" },
	  P{ "(", "unescaped '('" },
	  P{ ")", "unescaped ')'" },
	  P{ "a\0b"s, "NUL" },
	  P{ "\xff", "invalid UTF-8" },
	  P{ "\xf0\x9f\x98", "invalid UTF-8" });
	INFO(text);
	const auto r = ldap::unescape_filter_value(text);
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::invalid_filter);
	CHECK(r.error().context.contains(what));
	// filter::parse rejects the same value (an unescaped '*' would make it a
	// substring filter there).
	if (!text.contains('*')) {
		CHECK_FALSE(ldap::filter::parse("(cn=" + text + ")").has_value());
	}
}

// ---------------------------------------------------------------- RFC conformance

TEST_CASE("RFC 4515 3: printed filters are valid UTF-8", "[filter][rfc]")
{
	using namespace ldap::filters;
	CHECK(ldap::escape_filter_value("\xff") == "\\ff");
	CHECK(ldap::escape_filter_value("a\xc3") == "a\\c3");// truncated sequence
	CHECK(ldap::escape_filter_value("\xc3\xa9") == "\xc3\xa9");// valid UTF-8 is kept
	CHECK(ldap::escape_filter_value("\xf4\x90\x80\x80") == "\\f4\\90\\80\\80");// above U+10FFFF
	CHECK(ldap::escape_filter_value("\xed\xbf\xbf") == "\\ed\\bf\\bf");// surrogate
	CHECK(ldap::escape_filter_value("\xf4\x8f\xbf\xbf") == "\xf4\x8f\xbf\xbf");// U+10FFFF is kept
	CHECK(text_of(attr("cn") == "\x80") == "(cn=\\80)");
	CHECK(text_of(attr("cn").starts_with("\xfe")) == "(cn=\\fe*)");
	CHECK(text_of(parsed("(cn=\\ff)")) == "(cn=\\ff)");
}

TEST_CASE("RFC 4515 3: filter text with invalid UTF-8 is rejected", "[filter][parser][rfc]")
{
	const std::string bad = GENERATE(as<std::string>{},
	  "(cn=\xff)",
	  "(cn=a\xc3)",// truncated sequence
	  "(cn=\xc0\xaf)",// overlong '/'
	  "(cn=\xed\xa0\x80)",// UTF-16 surrogate
	  "(cn=\xf4\x90\x80\x80)",// above U+10FFFF
	  "(cn=\xf5\x80\x80\x80)",// lead octet above U+10FFFF
	  "(cn=\xe0\x9f\xbf)",// overlong 3-octet form
	  "(cn=\xf0\x8f\xbf\xbf)",// overlong 4-octet form
	  "(cn=\xf0\x9f\x98)",// truncated 4-octet sequence
	  "(cn=\x80*)");
	INFO(hex(std::as_bytes(std::span(bad))));
	auto r = ldap::filter::parse(bad);
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::invalid_filter);
}
