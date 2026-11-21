#include "counting_resource.hpp"
#include "jhetz/ldap/url.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ldap = jhetz::ldap;
using ldap::client_errc;
using ldap::search_scope;
using ldap::url_scheme;
using namespace std::string_literals;
using namespace std::string_view_literals;
using strings = std::pmr::vector<std::pmr::string>;

namespace {

auto parse(std::string_view text) -> ldap::url
{
	auto u = ldap::url::parse(text);
	INFO(text << " -> " << (u ? std::string("ok") : std::string(u.error().message())));
	REQUIRE(u.has_value());
	// Every accepted URL round-trips.
	auto back = ldap::url::parse(u->to_string());
	INFO("to_string: " << u->to_string());
	REQUIRE(back.has_value());
	CHECK(*back == *u);
	CHECK(back->to_string() == u->to_string());
	return *u;
}

void rejected(std::string_view text)
{
	auto u = ldap::url::parse(text);
	INFO(text);
	REQUIRE_FALSE(u.has_value());
	CHECK(u.error().code == client_errc::invalid_url);
	CHECK(u.error().context.starts_with("url: "));
}

auto dn(std::string_view text) -> ldap::dn { return *ldap::dn::parse(text); }

}// namespace

TEST_CASE("RFC 4516 section 4 examples", "[url]")
{
	SECTION("ldap:///o=University%20of%20Michigan,c=US")
	{
		const auto u = parse("ldap:///o=University%20of%20Michigan,c=US");
		CHECK(u.scheme() == url_scheme::ldap);
		CHECK(u.host().empty());
		CHECK_FALSE(u.port());
		CHECK(u.port_or_default() == 389);
		REQUIRE(u.base_dn());
		CHECK(*u.base_dn() == dn("o=University of Michigan,c=US"));
		CHECK(u.attributes().empty());
		CHECK_FALSE(u.scope());
		CHECK_FALSE(u.search_filter());
		CHECK(u.to_string() == "ldap:///o=University%20of%20Michigan,c=US");
	}
	SECTION("host and port")
	{
		const auto u = parse("ldap://ldap1.example.net/o=University%20of%20Michigan,c=US");
		CHECK(u.host() == "ldap1.example.net");
		CHECK(u.authority() == "ldap1.example.net:389");
	}
	SECTION("attributes")
	{
		const auto u = parse("ldap://ldap1.example.net/o=University%20of%20Michigan,c=US?postalAddress");
		CHECK(u.attributes() == strings{ "postalAddress" });
	}
	SECTION("scope and filter")
	{
		const auto u = parse("ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)");
		CHECK(u.port() == 6666);
		CHECK(u.scope() == search_scope::whole_subtree);
		REQUIRE(u.search_filter());
		CHECK(u.search_filter()->to_string() == "(cn=Babs Jensen)");
		CHECK(u.search_filter()->root().value() == "Babs Jensen");
		CHECK(
		  u.to_string() == "ldap://ldap1.example.net:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)");
	}
	SECTION("one level, no attributes")
	{
		const auto u = parse("LDAP://ldap1.example.com/c=GB?objectClass?ONE");
		CHECK(u.scheme() == url_scheme::ldap);
		CHECK(u.attributes() == strings{ "objectClass" });
		CHECK(u.scope() == search_scope::single_level);
		CHECK(u.to_string() == "ldap://ldap1.example.com/c=GB?objectClass?one");
	}
	SECTION("escaped question mark in the DN")
	{
		const auto u = parse("ldap://ldap2.example.com/o=Question%3f,c=US?mail");
		CHECK(*u.base_dn() == dn("o=Question?,c=US"));
		CHECK(u.attributes() == strings{ "mail" });
		CHECK(u.to_string() == "ldap://ldap2.example.com/o=Question%3F,c=US?mail");
	}
	SECTION("filter with an escaped NUL")
	{
		const auto u = parse(
		  "ldap://ldap3.example.com/o=Babsco,c=US???"
		  "(four-octet=%5c00%5c00%5c00%5c04)");
		CHECK(u.search_filter()->to_string() == "(four-octet=\\00\\00\\00\x04)");
		CHECK(u.search_filter()->root().value() == "\0\0\0\x04"sv);
	}
	SECTION("DN with an escaped comma")
	{
		const auto u = parse("ldap://ldap.example.com/o=An%20Example%5C2C%20Inc.,c=US");
		CHECK(*u.base_dn() == dn("o=An Example\\2C Inc.,c=US"));
		CHECK(u.base_dn()->rdns()[0].avas[0].value == "An Example, Inc.");
	}
	SECTION("bindname extension, not critical and critical")
	{
		const auto u = parse("ldap:///??sub??e-bindname=cn=Manager%2cdc=example%2cdc=com");
		REQUIRE(u.extensions().size() == 1);
		CHECK(u.extensions()[0].type == "e-bindname");
		CHECK(u.extensions()[0].value == "cn=Manager,dc=example,dc=com");
		CHECK_FALSE(u.extensions()[0].critical);
		CHECK_FALSE(u.has_critical_extension());

		const auto c = parse(
		  "ldap:///??sub??"
		  "!e-bindname=cn=Manager%2cdc=example%2cdc=com");
		CHECK(c.extensions()[0].critical);
		CHECK(c.has_critical_extension());
		CHECK(c.to_string() == "ldap:///??sub??" "!e-bindname=cn=Manager%2Cdc=example%2Cdc=com");
	}
}

TEST_CASE("URL schemes and default ports", "[url]")
{
	CHECK(parse("ldap://h").port_or_default() == 389);
	CHECK(parse("ldaps://h").port_or_default() == 636);
	CHECK(parse("LdApS://h").scheme() == url_scheme::ldaps);
	CHECK(parse("ldaps://h:1636").port_or_default() == 1636);
	CHECK(parse("ldaps://h").authority() == "h:636");
	CHECK(parse("ldap://h:").port() == std::nullopt);// empty port: default
	CHECK(parse("ldap://h:0389").port() == 389);
	CHECK(parse("ldap://h:65535").port() == 65535);
	CHECK(parse("ldap://").host().empty());
	CHECK(parse("ldap://:1389").port() == 1389);
	CHECK(ldap::url{}.to_string() == "ldap://");

	// Explicit default port is kept as written.
	const auto explicit_port = parse("ldap://h:389");
	CHECK(explicit_port.port() == 389);
	CHECK(explicit_port.to_string() == "ldap://h:389");
	CHECK(explicit_port != parse("ldap://h"));
}

TEST_CASE("ldapi URLs", "[url]")
{
	const auto u = parse("ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi");
	CHECK(u.scheme() == url_scheme::ldapi);
	CHECK(u.host() == "/var/run/slapd/ldapi");
	CHECK_FALSE(u.port());
	CHECK(u.port_or_default() == 0);
	CHECK(u.authority() == "%2Fvar%2Frun%2Fslapd%2Fldapi");
	CHECK(u.to_string() == "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi");

	CHECK(parse("ldapi://%2ftmp%2fa%20b/dc=x").host() == "/tmp/a b");
	CHECK(parse("ldapi://").host().empty());
	CHECK(parse("ldapi:///dc=example,dc=com").base_dn() == dn("dc=example,dc=com"));

	rejected("ldapi://%2Ftmp%2Fs:389");// no port
	rejected("ldapi://[::1]");
	rejected("ldapi:///tmp/sock");// the path must be encoded ('/' starts the DN) - here "tmp/sock" is not a DN
}

TEST_CASE("URL hosts", "[url]")
{
	SECTION("IPv4 and names")
	{
		CHECK(parse("ldap://127.0.0.1:1389").host() == "127.0.0.1");
		CHECK_FALSE(parse("ldap://127.0.0.1").host_is_ipv6());
		CHECK(parse("ldap://Example.COM").host() == "Example.COM");// kept as written
		CHECK(parse("ldap://a%2Db").host() == "a-b");
		CHECK(parse("ldap://a%2Db").to_string() == "ldap://a-b");
	}
	SECTION("IPv6")
	{
		const auto u = parse("ldap://[::1]:1389/dc=x");
		CHECK(u.host() == "::1");
		CHECK(u.host_is_ipv6());
		CHECK(u.port() == 1389);
		CHECK(u.authority() == "[::1]:1389");
		CHECK(u.to_string() == "ldap://[::1]:1389/dc=x");

		CHECK(parse("ldaps://[2001:db8::7]").authority() == "[2001:db8::7]:636");
		CHECK(parse("ldap://[::]").host() == "::");
		CHECK(parse("ldap://[1:2:3:4:5:6:7:8]").host() == "1:2:3:4:5:6:7:8");
		CHECK(parse("ldap://[1:2:3:4:5:6:7::]").host() == "1:2:3:4:5:6:7::");
		CHECK(parse("ldap://[::ffff:192.0.2.1]").host() == "::ffff:192.0.2.1");
		CHECK(parse("ldap://[1:2:3:4:5:6:1.2.3.4]").host() == "1:2:3:4:5:6:1.2.3.4");
		CHECK(parse("ldap://[fe80::1%25eth0]:389").host() == "fe80::1%eth0");
		CHECK(parse("ldap://[fe80::1%25eth0]:389").to_string() == "ldap://[fe80::1%25eth0]:389");
		// ':' (or '%') inside the zone stays encoded; only the address keeps literal ':'.
		CHECK(parse("ldap://[fe80::1%25a%3Ab]").host() == "fe80::1%a:b");
		CHECK(parse("ldap://[fe80::1%25a%3Ab]").to_string() == "ldap://[fe80::1%25a%3Ab]");
		CHECK(parse("ldap://[fe80::1%25a%25b]").to_string() == "ldap://[fe80::1%25a%25b]");

		for (const auto *bad : { "ldap://[::1",
			   "ldap://[]",
			   "ldap://[1:2:3:4:5:6:7:8:9]",
			   "ldap://[1::2::3]",
			   "ldap://[12345::]",
			   "ldap://[:1]",
			   "ldap://[1:]",
			   "ldap://[1:2:3:4:5:6:7]",
			   "ldap://[::1.2.3]",
			   "ldap://[::256.1.1.1]",
			   "ldap://[::01.1.1.1]",
			   "ldap://[v1.x]",
			   "ldap://[::1]x",
			   "ldap://[::1]:x",
			   "ldap://[fe80::1%25]",
			   "ldap://[fe80::1%eth0]",
			   "ldap://[g::1]" }) {
			rejected(bad);
		}
	}
	SECTION("invalid")
	{
		rejected("ldap://user@host");
		rejected("ldap://h:65536");
		rejected("ldap://h:0");
		rejected("ldap://h:12a");
		rejected("ldap://h:-1");
		rejected("ldap://h h");
		rejected("ldap://h%");
		rejected("ldap://h%2");
		rejected("ldap://h%zz");
		rejected("ldap://h:1:2");
		rejected("ldap://h?cn");// '?' needs the "/" first
		rejected("ldap://h#frag");
	}
}

TEST_CASE("URL parts after the host", "[url]")
{
	SECTION("absent vs empty DN")
	{
		CHECK_FALSE(parse("ldap://h").base_dn());
		const auto root = parse("ldap://h/");
		REQUIRE(root.base_dn());
		CHECK(root.base_dn()->empty());
		CHECK(root.to_string() == "ldap://h/");
		CHECK(parse("ldap://h/???") == root);// empty parts are absent
	}
	SECTION("attributes")
	{
		const auto u = parse("ldap://h/dc=x?cn,mail,*,+,1.1,cn;lang-en");
		CHECK(u.attributes() == strings{ "cn", "mail", "*", "+", "1.1", "cn;lang-en" });
		CHECK(parse("ldap://h/?a%2Cb").attributes() == strings{ "a,b" });
		CHECK(parse("ldap://h/?a%2Cb").to_string() == "ldap://h/?a%2Cb");
		rejected("ldap://h/?a,,b");
		rejected("ldap://h/?a,");
		rejected("ldap://h/?,a");
	}
	SECTION("scope")
	{
		CHECK(parse("ldap://h/??base").scope() == search_scope::base_object);
		CHECK(parse("ldap://h/??One").scope() == search_scope::single_level);
		CHECK(parse("ldap://h/??SUB").scope() == search_scope::whole_subtree);
		CHECK_FALSE(parse("ldap://h/??").scope());
		rejected("ldap://h/??subtree");
		rejected("ldap://h/??children");
	}
	SECTION("filter")
	{
		// ldapsearch-style, unwrapped: the same filter as (uid=jdoe), printed canonically.
		CHECK(parse("ldap://h/???uid=jdoe").search_filter()->to_string() == "(uid=jdoe)");
		CHECK(parse("ldap://h/???uid=jdoe")
			  == parse("ldap://h/???"
					   "(uid=jdoe)"));
		CHECK(parse("ldap://h/???uid=jdoe").to_string() == "ldap://h/???" "(uid=jdoe)");
		CHECK(parse("ldap://h/???"
					"(&(a=1)(b=2))")
				.search_filter()
				->to_string()
			  == "(&(a=1)(b=2))");
		CHECK(parse("ldap://h/???"
					"(cn=a%3Fb)")
				.search_filter()
				->to_string()
			  == "(cn=a?b)");
		CHECK(parse("ldap://h/???" "(cn=a%3Fb)").to_string() == "ldap://h/???" "(cn=a%3Fb)");
		rejected(
		  "ldap://h/???"
		  "(cn=a");
		rejected(
		  "ldap://h/???"
		  "(cn=a)(b=c)");
	}
	SECTION("extensions")
	{
		const auto u = parse("ldap://h/????x,!1.2.3=,y=a%2Cb");
		REQUIRE(u.extensions().size() == 3);
		CHECK(u.extensions()[0] == ldap::url_extension{ "x", std::nullopt, false });
		CHECK(u.extensions()[1] == ldap::url_extension{ "1.2.3", "", true });
		CHECK(u.extensions()[2] == ldap::url_extension{ "y", "a,b", false });
		CHECK(u.to_string() == "ldap://h/????x,!1.2.3=,y=a%2Cb");
		rejected("ldap://h/????x,,y");
		rejected(
		  "ldap://h/????"
		  "!");
		rejected(
		  "ldap://h/????"
		  "=v");
		rejected("ldap://h/????1x=v");// neither descriptor nor numeric OID
		rejected("ldap://h/????a b");
	}
	SECTION("only the parts needed are written")
	{
		CHECK(parse("ldap://h/dc=x???").to_string() == "ldap://h/dc=x");
		CHECK(parse("ldap://h/dc=x??sub?").to_string() == "ldap://h/dc=x??sub");
		CHECK(parse("ldap://h/???" "(a=b)?").to_string() == "ldap://h/???" "(a=b)");
	}
	SECTION("lenient characters")
	{
		// Unencoded spaces and UTF-8 are accepted after the host and encoded
		// by to_string.
		const auto u = parse("ldap://h/cn=J\xC3\xBCrgen M,dc=x");
		CHECK(u.base_dn()->rdns()[0].avas[0].value == "J\xC3\xBCrgen M");
		CHECK(u.to_string() == "ldap://h/cn=J%C3%BCrgen%20M,dc=x");
	}
	SECTION("invalid")
	{
		rejected("ldap://h/cn");// not a DN
		rejected("ldap://h/cn=a\\");// '\' must be encoded
		rejected("ldap://h/cn=%5C");// ... and is then still an invalid DN escape
		rejected("ldap://h/dc=x?a?sub?(a=b)?e?more");
		rejected("ldap://h/dc=x#f");
		rejected("ldap://h/dc=%0");
		rejected("ldap://h/dc=x\x01");
		rejected("ldap://h/dc=x\"");
	}
}

TEST_CASE("URL parts must be UTF-8 after percent-decoding", "[url]")
{
	// RFC 4516 section 2: the percent-decoded attributes, filter and
	// extensions are UTF-8; an ill-formed sequence is rejected, encoded or not.
	auto utf8_error = [](std::string_view text, std::string_view what) {
		auto u = ldap::url::parse(text);
		INFO(text);
		REQUIRE_FALSE(u.has_value());
		CHECK(u.error().code == client_errc::invalid_url);
		CHECK(u.error().context.starts_with("url: ill-formed UTF-8 in "s + std::string(what)));
	};
	SECTION("well-formed UTF-8 is accepted in every part")
	{
		const auto u = parse("ldap://h/dc=x?%C3%A9,\xC3\xA9?sub?(cn=J%C3%BCrgen)?x=%E2%82%AC,y=\xF0\x9F\x98\x80");
		CHECK(u.attributes() == strings{ "\xC3\xA9", "\xC3\xA9" });
		CHECK(u.search_filter()->root().value() == "J\xC3\xBCrgen");
		CHECK(u.extensions()[0].value == "\xE2\x82\xAC");
		CHECK(u.extensions()[1].value == "\xF0\x9F\x98\x80");
	}
	SECTION("attributes")
	{
		utf8_error("ldap://h/dc=x?cn,%FF", "attribute");
		utf8_error("ldap://h/dc=x?\xC3", "attribute");// truncated
		utf8_error("ldap://h/dc=x?%C0%AF", "attribute");// overlong
		utf8_error("ldap://h/dc=x?%ED%A0%80", "attribute");// surrogate
	}
	SECTION("filter")
	{
		utf8_error("ldap://h/dc=x??sub?(cn=%FF)", "filter");
		utf8_error("ldap://h/dc=x??sub?(cn=\x80)", "filter");
		utf8_error("ldap://h/dc=x??sub?(cn=%F4%90%80%80)", "filter");// above U+10FFFF
	}
	SECTION("extensions")
	{
		utf8_error("ldap://h/dc=x????x=%FF", "extension value");
		utf8_error(
		  "ldap://h/dc=x????"
		  "!1.2.3=a\xE2\x82",
		  "extension value");
		// The type is an OID: any non-ASCII byte fails that check.
		rejected("ldap://h/dc=x????%FE");
		rejected("ldap://h/dc=x????\xC3\xA9");
	}
	SECTION("the error gives the URL offset of the ill-formed byte")
	{
		// After "%C3%A9" (one decoded character, six URL bytes) the bad %FF
		// is at URL offset 26, decoded byte 7 of the filter.
		auto u = ldap::url::parse("ldap://h/??sub?(cn=a%C3%A9%FF)");
		REQUIRE_FALSE(u.has_value());
		CHECK(
		  std::string(u.error().context) == "url: ill-formed UTF-8 in filter (RFC 4516 parts are UTF-8) at offset 26");
		auto raw = ldap::url::parse("ldap://h/dc=x?cn,a\xC3");// truncated, unencoded
		REQUIRE_FALSE(raw.has_value());
		CHECK(std::string(raw.error().context)
			  == "url: ill-formed UTF-8 in attribute (RFC 4516 parts are UTF-8) at offset 18");
		auto value = ldap::url::parse("ldap://h/dc=x????x=%41%FF");
		REQUIRE_FALSE(value.has_value());
		CHECK(std::string(value.error().context)
			  == "url: ill-formed UTF-8 in extension value (RFC 4516 parts are UTF-8) at offset 22");
	}
	SECTION("the DN, through dn::parse")
	{
		rejected("ldap://h/cn=%FF");
		rejected("ldap://h/cn=\xC3");
	}
}

TEST_CASE("URL schemes and structure errors", "[url]")
{
	rejected("");
	rejected("ldap:");
	rejected("ldap:/h");
	rejected("http://h");
	rejected("ldapx://h");
	rejected("://h");
	rejected("ldap//h");
}

TEST_CASE("URL percent-encoding round trip of every byte", "[url]")
{
	// Every byte value in a DN or filter value, and every UTF-8 text in an
	// attribute or extension value, survives to_string -> parse.
	std::string all;
	for (int b = 1; b < 256; ++b) {
		all += static_cast<char>(b);
	}
	std::string filter_value;
	for (char c : all) {
		// Specials, and octets 0x80-0xFF (alone, none is valid UTF-8).
		if (c == '*' || c == '(' || c == ')' || c == '\\' || static_cast<unsigned char>(c) >= 0x80u) {
			static constexpr char hex[] = "0123456789abcdef";
			filter_value += '\\';
			filter_value += hex[(unsigned{ static_cast<unsigned char>(c) } >> 4U) & 0xFU];
			filter_value += hex[unsigned{ static_cast<unsigned char>(c) } & 0xFU];
		} else {
			filter_value += c;
		}
	}
	std::string encoded = "ldap://h/cn=";
	for (char c : all) {
		static constexpr char hex[] = "0123456789ABCDEF";
		encoded += "%5C";// DN escape '\' + two hex digits, itself percent-encoded
		encoded += hex[(unsigned{ static_cast<unsigned char>(c) } >> 4U) & 0xFU];
		encoded += hex[unsigned{ static_cast<unsigned char>(c) } & 0xFU];
	}
	encoded += '?';
	auto pct = [](std::string_view s) {
		static constexpr char hex[] = "0123456789ABCDEF";
		std::string out;
		for (char c : s) {
			out += '%';
			out += hex[(unsigned{ static_cast<unsigned char>(c) } >> 4U) & 0xFU];
			out += hex[unsigned{ static_cast<unsigned char>(c) } & 0xFU];
		}
		return out;
	};
	// The attributes and extension values are UTF-8 (RFC 4516 section 2):
	// every ASCII byte, and multi-byte sequences of each length.
	const std::string text = all.substr(0, 0x7F) + "\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80";
	encoded += pct(text) + "??" + pct("(cn=" + filter_value + ")") + "?x=" + pct(text);
	const auto u = parse(encoded);
	CHECK(u.base_dn()->rdns()[0].avas[0].value == std::string_view(all));
	CHECK(u.attributes() == strings{ std::pmr::string(text) });
	CHECK(u.search_filter()->to_string() == std::string_view("(cn=" + filter_value + ")"));
	CHECK(u.search_filter()->root().value() == std::string_view(all));
	CHECK(u.extensions()[0].value == std::string_view(text));
}

TEST_CASE("URL allocations go through the given memory resource", "[url][pmr]")
{
	using jhetz::ldap::test::counting_resource;
	// Long enough that no string fits the small-string buffer.
	const std::string_view text =
	  "ldaps://a-rather-long-host-name.example.org:1636/dc=example,dc=org"
	  "?givenName,surname-that-is-long?sub?(cn=x)?e-bindname=cn=Manager%2Cdc=example%2Cdc=org";

	counting_resource counting;
	{
		auto u = ldap::url::parse(text, &counting);
		REQUIRE(u.has_value());
		CHECK(counting.allocations() > 0);
		CHECK(u->get_allocator().resource() == &counting);
		CHECK(u->host().get_allocator().resource() == &counting);
		CHECK(u->attributes().get_allocator().resource() == &counting);
		CHECK(u->attributes()[1].get_allocator().resource() == &counting);
		CHECK(u->extensions().get_allocator().resource() == &counting);
		CHECK(u->extensions()[0].type.get_allocator().resource() == &counting);
		CHECK(u->extensions()[0].value->get_allocator().resource() == &counting);
		// The DN and filter too.
		CHECK(u->base_dn()->get_allocator().resource() == &counting);
		CHECK(u->base_dn()->rdns()[0].avas[0].value.get_allocator().resource() == &counting);
		CHECK(u->search_filter()->get_allocator().resource() == &counting);

		// to_string / authority into a chosen resource.
		const auto before = counting.allocations();
		const auto printed = u->to_string(&counting);
		CHECK(printed.get_allocator().resource() == &counting);
		CHECK(counting.allocations() > before);

		// A plain copy uses the default resource; the allocator-extended copy the
		// one given, with equal contents.
		const ldap::url copy = *u;
		CHECK(copy.get_allocator().resource() == std::pmr::get_default_resource());
		CHECK(copy.extensions()[0].type.get_allocator().resource() == std::pmr::get_default_resource());
		CHECK(copy == *u);

		std::pmr::monotonic_buffer_resource arena;
		const ldap::url in_arena(*u, &arena);
		CHECK(in_arena == *u);
		CHECK(in_arena.host().get_allocator().resource() == &arena);
		CHECK(in_arena.extensions()[0].value->get_allocator().resource() == &arena);
		CHECK(in_arena.base_dn()->get_allocator().resource() == &arena);
		CHECK(in_arena.search_filter()->get_allocator().resource() == &arena);

		// Moving with the same resource keeps it; with another one copies into it.
		ldap::url moved(ldap::url(*u, &counting), &counting);
		CHECK(moved.get_allocator().resource() == &counting);
		ldap::url moved_elsewhere(ldap::url(*u, &counting), &arena);
		CHECK(moved_elsewhere.get_allocator().resource() == &arena);
		CHECK(moved_elsewhere == *u);

		// Assignment keeps the target's resource, extensions included (also when
		// the target had no extension value before).
		{
			auto target = ldap::url::parse("ldap://h/????short", &arena);
			REQUIRE(target.has_value());
			*target = *u;
			CHECK(*target == *u);
			CHECK(target->host().get_allocator().resource() == &arena);
			CHECK(target->attributes()[0].get_allocator().resource() == &arena);
			CHECK(target->extensions()[0].type.get_allocator().resource() == &arena);
			CHECK(target->extensions()[0].value->get_allocator().resource() == &arena);
			// DN and filter were absent in the target: engaged on its resource.
			CHECK(target->base_dn()->get_allocator().resource() == &arena);
			CHECK(target->search_filter()->get_allocator().resource() == &arena);
			auto target2 = ldap::url::parse("ldap://h", &arena);
			*target2 = ldap::url(*u, &counting);// move assignment across resources
			CHECK(*target2 == *u);
			CHECK(target2->extensions()[0].value->get_allocator().resource() == &arena);
			CHECK(target2->base_dn()->rdns()[0].get_allocator().resource() == &arena);
			CHECK(target2->search_filter()->get_allocator().resource() == &arena);
		}

		// A pmr::vector<url> hands its resource to its elements.
		std::pmr::vector<ldap::url> referrals(&arena);
		referrals.push_back(*u);
		CHECK(referrals[0].get_allocator().resource() == &arena);
		CHECK(referrals[0].attributes()[0].get_allocator().resource() == &arena);
	}
	CHECK(counting.outstanding() == 0);// everything was given back
}

TEST_CASE("URL parsing into a monotonic buffer", "[url][pmr]")
{
	std::byte storage[4096];
	std::pmr::monotonic_buffer_resource arena(storage, sizeof storage, std::pmr::null_memory_resource());
	// With a null upstream, anything that does not come from the buffer throws.
	auto u = ldap::url::parse("ldapi://%2Fvar%2Frun%2Fslapd%2Fvery-long-socket-name-for-ldapi", &arena);
	REQUIRE(u.has_value());
	CHECK(u->host() == "/var/run/slapd/very-long-socket-name-for-ldapi");
	CHECK(u->host().get_allocator().resource() == &arena);

	// A DN and a filter, with values too long for the small-string buffer.
	auto full = ldap::url::parse(
	  "ldap://h/cn=a-value-well-beyond-the-small-string-size,dc=example???"
	  "(cn=another-long-assertion-value*)",
	  &arena);
	REQUIRE(full.has_value());
	CHECK(full->base_dn()->rdns()[0].avas[0].value.get_allocator().resource() == &arena);
	CHECK(full->search_filter()->get_allocator().resource() == &arena);
}

TEST_CASE("server URLs: check_server and parse_server", "[url]")
{
	for (const auto *ok : { "ldap://ldap.example.org",
		   "LDAPS://ldap.example.org:636",
		   "ldap://ldap.example.org/",
		   "ldap://[::1]:389",
		   "ldap://[fe80::1%25eth0]",
		   "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
		   "ldap://h/????bindname=cn%3Dx",
		   "ldap://h/???",
		   "ldap://caf%C3%A9.example" }) {
		INFO(ok);
		auto u = ldap::url::parse_server(ok);
		CHECK(u.has_value());
		CHECK(ldap::url::parse(ok)->check_server().has_value());
	}
	const auto refused = [](std::string_view text, std::string_view context) {
		INFO(text);
		auto u = ldap::url::parse_server(text);
		REQUIRE_FALSE(u.has_value());
		CHECK(u.error().code == client_errc::invalid_url);
		CHECK(std::string_view(u.error().context) == context);
	};
	constexpr auto no_search = "url: a server URL names no DN, attributes, scope or filter"sv;
	refused("ldap://h/dc=example,dc=org", no_search);
	refused("ldap://h/?cn", no_search);
	refused("ldap://h/??sub", no_search);
	refused("ldap://h/??\?(cn=x)", no_search);
	refused("ldap://", "url: the URL names no host (or, for ldapi, no socket path)");
	refused("ldapi://", "url: the URL names no host (or, for ldapi, no socket path)");
	refused("ldap://h/???\?!x-unknown", "url: unsupported critical extension x-unknown");
	refused("ldap://evil%00.example.org", "url: control character in the host");
	refused("ldap://h%7F", "url: control character in the host");
	refused("ldap://%FF", "url: ill-formed UTF-8 in the host");
	refused("ldap://%C3", "url: ill-formed UTF-8 in the host");
	refused("ldaps://%C0%AF.example", "url: ill-formed UTF-8 in the host");
	refused("ldap://[fe80::1%25e%FF]", "url: ill-formed UTF-8 in the host");
	CHECK(ldap::url::parse_server("ldapi://%2Ftmp%2F%FF").has_value());
	refused("ldap://h:0", "url: port 0 at offset 9");
	refused("http://h", "url: scheme is not ldap, ldaps or ldapi at offset 0");
}

TEST_CASE("server URLs: url::server builds one from its parts", "[url]")
{
	using ldap::url_scheme;
	const auto made = [](url_scheme scheme, std::string_view host, std::optional<std::uint16_t> port) {
		auto u = ldap::url::server(scheme, host, port);
		REQUIRE(u.has_value());
		CHECK(ldap::url::parse_server(u->to_string()) == *u);
		return std::string(u->to_string());
	};
	CHECK(made(url_scheme::ldaps, "dc1.example.org", 636) == "ldaps://dc1.example.org:636");
	CHECK(made(url_scheme::ldap, "dc1.example.org", std::nullopt) == "ldap://dc1.example.org");
	CHECK(made(url_scheme::ldap, "192.0.2.1", 389) == "ldap://192.0.2.1:389");
	CHECK(made(url_scheme::ldap, "::1", 389) == "ldap://[::1]:389");
	CHECK(made(url_scheme::ldap, "fe80::1%eth0", std::nullopt) == "ldap://[fe80::1%25eth0]");
	CHECK(made(url_scheme::ldapi, "/run/slapd/ldapi", std::nullopt) == "ldapi://%2Frun%2Fslapd%2Fldapi");
	// Taken as decoded: no percent-decoding, nothing parsed after the host.
	CHECK(made(url_scheme::ldap, "a%41b", std::nullopt) == "ldap://a%2541b");
	CHECK(ldap::url::server(url_scheme::ldap, "a%41b")->host() == "a%41b");
	CHECK(made(url_scheme::ldap, "h/dc=x?cn", std::nullopt) == "ldap://h%2Fdc=x%3Fcn");
	CHECK(made(url_scheme::ldap, "caf\xC3\xA9.example", std::nullopt) == "ldap://caf%C3%A9.example");
	const auto refused =
	  [](url_scheme scheme, std::string_view host, std::optional<std::uint16_t> port, std::string_view context) {
		  INFO(host);
		  auto u = ldap::url::server(scheme, host, port);
		  REQUIRE_FALSE(u.has_value());
		  CHECK(u.error().code == client_errc::invalid_url);
		  CHECK(std::string_view(u.error().context) == context);
	  };
	refused(url_scheme::ldap, "", std::nullopt, "url: the URL names no host (or, for ldapi, no socket path)");
	refused(url_scheme::ldap, "evil\n.example.org", std::nullopt, "url: control character in the host");
	refused(url_scheme::ldap, "\xFF", std::nullopt, "url: ill-formed UTF-8 in the host");
	refused(url_scheme::ldap, "h", 0, "url: port 0");
	refused(url_scheme::ldapi, "/run/ldapi", 389, "url: port not allowed in an ldapi URL");
	refused(url_scheme::ldap, "h:389", std::nullopt, "url: invalid IPv6 address");
	refused(url_scheme::ldap, "fe80::1%", std::nullopt, "url: invalid IPv6 address");
}

TEST_CASE("server URLs: parse_servers", "[url]")
{
	auto list = ldap::url::parse_servers({ "ldap://a.example.org", "ldaps://b.example.org" });
	REQUIRE(list.has_value());
	REQUIRE(list->size() == 2);
	CHECK((*list)[0].host() == "a.example.org");
	CHECK((*list)[1].scheme() == url_scheme::ldaps);

	const std::vector<std::string> config{ "ldap://a.example.org", "ldap://b.example.org/dc=x" };
	auto bad = ldap::url::parse_servers(config);
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::invalid_url);
	CHECK(std::string_view(bad.error().context)
		  == "servers[1]: url: a server URL names no DN, attributes, scope or filter");

	auto none = ldap::url::parse_servers(std::vector<std::string_view>{});
	REQUIRE(none.has_value());
	CHECK(none->empty());

	std::pmr::monotonic_buffer_resource arena;
	auto on_arena = ldap::url::parse_servers({ "ldap://a.example.org" }, &arena);
	REQUIRE(on_arena.has_value());
	CHECK((*on_arena)[0].get_allocator().resource() == &arena);
}

TEST_CASE("server URLs: the compile-time checked literal", "[url]")
{
	const ldap::url u{ "ldaps://ldap.example.org:1636" };
	CHECK(u.scheme() == url_scheme::ldaps);
	CHECK(u.host() == "ldap.example.org");
	CHECK(u.port() == 1636);
	CHECK(u == *ldap::url::parse("ldaps://ldap.example.org:1636"));

	std::pmr::monotonic_buffer_resource arena;
	const ldap::url on_arena{ "ldap://[::1]/", &arena };
	CHECK(on_arena.get_allocator().resource() == &arena);
	CHECK(on_arena.host() == "::1");
	CHECK(on_arena.host_is_ipv6());
	CHECK(on_arena.base_dn() == ldap::dn{});

	using ldap::detail::is_server_url_literal;
	static_assert(is_server_url_literal("ldap://h"));
	static_assert(is_server_url_literal("LdApI://%2Ftmp%2Fs"));
	static_assert(is_server_url_literal("ldap://h:"));
	static_assert(is_server_url_literal("ldap://[2001:db8::1%25en0]:389/"));
	static_assert(is_server_url_literal("ldap://192.0.2.1:65535"));
	static_assert(!is_server_url_literal("ldap://"));
	static_assert(!is_server_url_literal("ldap://h/dc=x"));
	static_assert(!is_server_url_literal("ldap://h/????e"));
	static_assert(!is_server_url_literal("ldap://h?x"));
	static_assert(!is_server_url_literal("ldap://h#f"));
	static_assert(!is_server_url_literal("ldap://u@h"));
	static_assert(!is_server_url_literal("ldap://h:0"));
	static_assert(!is_server_url_literal("ldap://h:65536"));
	static_assert(!is_server_url_literal("ldap://h:1:2"));
	static_assert(!is_server_url_literal("ldap://h%0"));
	static_assert(!is_server_url_literal("ldap://h%00"));
	static_assert(!is_server_url_literal("ldapi://s:1"));
	static_assert(!is_server_url_literal("ldapi://[::1]"));
	static_assert(!is_server_url_literal("ldap://[::1"));
	static_assert(!is_server_url_literal("ldap://[v1.x]"));
	static_assert(!is_server_url_literal("ldap://[::1]x"));
	static_assert(!is_server_url_literal("ldap://[::1%25]"));
	static_assert(!is_server_url_literal("http://h"));
	static_assert(!is_server_url_literal("ldap:/h"));
	static_assert(!is_server_url_literal("ldap://%FF"));
	static_assert(!is_server_url_literal("ldap://%C3"));
	static_assert(!is_server_url_literal("ldap://%C3:389"));
	static_assert(!is_server_url_literal("ldap://%C0%AF"));
	static_assert(!is_server_url_literal("ldap://%ED%A0%80"));
	static_assert(!is_server_url_literal("ldap://[fe80::1%25e%FF]"));
	static_assert(is_server_url_literal("ldap://%F0%9F%98%80.example"));
	static_assert(is_server_url_literal("ldapi://%2Ftmp%2F%FF"));

	// What the literal accepts, parse_server accepts too.
	for (const auto *text : { "ldap://h",
		   "LdApI://%2Ftmp%2Fs",
		   "ldap://h:",
		   "ldap://[2001:db8::1%25en0]:389/",
		   "ldap://192.0.2.1:65535",
		   "ldap://a!$&'()*+,;=b",
		   "ldap://%C3%A9",
		   "ldap://%F0%9F%98%80.example",
		   "ldapi://%2Ftmp%2F%FF",
		   "ldap://[::ffff:192.0.2.1]" }) {
		INFO(text);
		CHECK(ldap::detail::is_server_url_literal(text));
		CHECK(ldap::url::parse_server(text).has_value());
	}
}
