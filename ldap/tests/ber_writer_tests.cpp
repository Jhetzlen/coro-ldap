#include "jhetz/ldap/ber.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <limits>
#include <stdexcept>
#include <string>

namespace ber = jhetz::ldap::ber;
using jhetz::ldap::test::bytes;
using jhetz::ldap::test::hex;

namespace {

std::string encode_integer(std::int64_t v)
{
	ber::writer w;
	w.integer(v);
	return hex(w.bytes());
}

}// namespace

TEST_CASE("ber::writer encodes INTEGER in minimal two's complement", "[ber][writer]")
{
	CHECK(encode_integer(0) == "02 01 00");
	CHECK(encode_integer(1) == "02 01 01");
	CHECK(encode_integer(127) == "02 01 7F");
	CHECK(encode_integer(128) == "02 02 00 80");
	CHECK(encode_integer(255) == "02 02 00 FF");
	CHECK(encode_integer(256) == "02 02 01 00");
	CHECK(encode_integer(-1) == "02 01 FF");
	CHECK(encode_integer(-128) == "02 01 80");
	CHECK(encode_integer(-129) == "02 02 FF 7F");
	CHECK(encode_integer(-256) == "02 02 FF 00");
	CHECK(encode_integer(std::numeric_limits<std::int64_t>::max()) == "02 08 7F FF FF FF FF FF FF FF");
	CHECK(encode_integer(std::numeric_limits<std::int64_t>::min()) == "02 08 80 00 00 00 00 00 00 00");
}

TEST_CASE("ber::writer encodes BOOLEAN, NULL, ENUMERATED and OCTET STRING", "[ber][writer]")
{
	ber::writer w;
	w.boolean(true);
	w.boolean(false);
	w.null();
	w.enumerated(3);
	w.octet_string(std::string_view{});
	w.octet_string("ab");
	const auto raw = bytes({ 0x01, 0x02 });
	w.octet_string(std::span<const std::byte>(raw));
	CHECK(hex(w.bytes()) == "01 01 FF 01 01 00 05 00 0A 01 03 04 00 04 02 61 62 04 02 01 02");
}

TEST_CASE("ber::writer uses minimal definite lengths", "[ber][writer]")
{
	const auto header_for = [](std::size_t n) {
		ber::writer w;
		w.octet_string(std::string(n, 'a'));
		auto out = w.take();
		CHECK(w.bytes().empty());
		REQUIRE(out.size() > n);
		return hex(std::span(out).first(out.size() - n));
	};
	CHECK(header_for(0) == "04 00");
	CHECK(header_for(127) == "04 7F");
	CHECK(header_for(128) == "04 81 80");
	CHECK(header_for(255) == "04 81 FF");
	CHECK(header_for(256) == "04 82 01 00");
	CHECK(header_for(65535) == "04 82 FF FF");
	CHECK(header_for(65536) == "04 83 01 00 00");
}

TEST_CASE("ber::writer backpatches constructed lengths", "[ber][writer]")
{
	SECTION("short form")
	{
		ber::writer w;
		w.constructed(ber::tags::sequence, [](ber::writer &) {});
		CHECK(hex(w.bytes()) == "30 00");
	}
	SECTION("long form after the content grows past 127 bytes")
	{
		ber::writer w;
		w.constructed(ber::tags::sequence, [](ber::writer &s) {
			s.octet_string(std::string(200, 'x'));// 04 81 C8 + 200 = 203 bytes
		});
		const auto &out = w.bytes();
		REQUIRE(out.size() == 3 + 203);
		CHECK(hex(std::span(out).first(6)) == "30 81 CB 04 81 C8");
	}
	SECTION("nested, with a length needing two octets")
	{
		ber::writer w;
		w.constructed(ber::tags::sequence, [](ber::writer &a) {
			a.constructed(ber::tags::set, [](ber::writer &b) { b.octet_string(std::string(300, 'y')); });
			a.null();
		});
		const auto &out = w.bytes();
		// set: 31 82 01 30 | 04 82 01 2C + 300 -> 304 content, 308 total; + null 2 = 310
		REQUIRE(out.size() == 4 + 310);
		CHECK(hex(std::span(out).first(8)) == "30 82 01 36 31 82 01 30");
		CHECK(hex(std::span(out).last(2)) == "05 00");
	}
	SECTION("the constructed bit is set by constructed() and cleared otherwise")
	{
		ber::writer w;
		w.constructed(ber::context(3), [](ber::writer &c) { c.octet_string("a", ber::context(1, true)); });
		CHECK(hex(w.bytes()) == "A3 03 81 01 61");
	}
	SECTION("an exception from the body removes the partial element")
	{
		ber::writer w;
		w.null();
		CHECK_THROWS_AS(w.constructed(ber::tags::sequence,
						  [](ber::writer &s) {
							  s.integer(5);
							  throw std::runtime_error("boom");
						  }),
		  std::runtime_error);
		CHECK(hex(w.bytes()) == "05 00");
	}
}

TEST_CASE("ber::writer builds an anonymous simple bind request", "[ber][writer]")
{
	ber::writer w;
	w.constructed(ber::tags::sequence, [](ber::writer &msg) {
		msg.integer(1);// messageID
		msg.constructed(ber::application(0), [](ber::writer &bind) {
			bind.integer(3);// version
			bind.octet_string(std::string_view{});// name
			bind.octet_string(std::string_view{}, ber::context(0));// simple
		});
	});
	CHECK(hex(w.bytes()) == "30 0C 02 01 01 60 07 02 01 03 04 00 80 00");
}

TEST_CASE("ber tags", "[ber][tag]")
{
	STATIC_REQUIRE(ber::identifier_octet(ber::tags::sequence) == std::byte{ 0x30 });
	STATIC_REQUIRE(ber::identifier_octet(ber::tags::set) == std::byte{ 0x31 });
	STATIC_REQUIRE(ber::identifier_octet(ber::application(0, true)) == std::byte{ 0x60 });
	STATIC_REQUIRE(ber::identifier_octet(ber::context(0)) == std::byte{ 0x80 });
	STATIC_REQUIRE(ber::identifier_octet(ber::context(3, true)) == std::byte{ 0xA3 });
	STATIC_REQUIRE(ber::identifier_octet(ber::private_tag(30)) == std::byte{ 0xDE });
	STATIC_REQUIRE(ber::tags::enumerated.number == 10);

	CHECK_THROWS_AS(ber::context(31), std::invalid_argument);
	ber::writer w;
	CHECK_THROWS_AS(w.null(ber::tag{ ber::tag_class::context, false, 31 }), std::invalid_argument);
	CHECK(w.bytes().empty());

	CHECK(ber::to_string(ber::tags::sequence) == "[UNIVERSAL 16 constructed]");
	CHECK(ber::to_string(ber::context(0)) == "[CONTEXT 0]");
	CHECK(ber::to_string(ber::application(3, true)) == "[APPLICATION 3 constructed]");
	CHECK(ber::to_string(ber::private_tag(1)) == "[PRIVATE 1]");
}
