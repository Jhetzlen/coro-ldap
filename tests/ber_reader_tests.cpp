#include "jhetz/ldap/ber.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <limits>
#include <string>

namespace ber = jhetz::ldap::ber;
using jhetz::ldap::client_errc;
using jhetz::ldap::test::bytes;
using jhetz::ldap::test::hex;

namespace {

template<class T> auto code_of(const jhetz::ldap::result<T> &r) -> std::error_code
{
	REQUIRE_FALSE(r.has_value());
	return r.error().code;
}

template<class T> auto context_of(const jhetz::ldap::result<T> &r) -> std::string
{
	REQUIRE_FALSE(r.has_value());
	return std::string(r.error().context);
}

}// namespace

TEST_CASE("ber::reader round-trips integers", "[ber][reader]")
{
	const std::int64_t value = GENERATE(std::int64_t{ 0 },
	  1,
	  -1,
	  127,
	  128,
	  -128,
	  -129,
	  255,
	  256,
	  65535,
	  65536,
	  -65536,
	  0x7FFF'FFFF,
	  -0x8000'0000LL,
	  std::numeric_limits<std::int64_t>::max(),
	  std::numeric_limits<std::int64_t>::min(),
	  std::numeric_limits<std::int64_t>::max() - 1,
	  std::numeric_limits<std::int64_t>::min() + 1);
	ber::writer w;
	w.integer(value);
	w.enumerated(value);
	w.integer(value, ber::context(5));
	ber::reader r(w.bytes());
	CHECK(r.read_integer() == value);
	CHECK(r.read_enumerated() == value);
	CHECK(r.read_integer(ber::context(5)) == value);
	CHECK(r.empty());
}

TEST_CASE("ber::reader round-trips the other primitive types", "[ber][reader]")
{
	ber::writer w;
	w.boolean(true);
	w.boolean(false);
	w.null();
	w.octet_string(std::string_view{});
	w.octet_string("hello");
	w.octet_string(std::string(1000, 'z'), ber::context(2));
	w.boolean(true, ber::context(1));
	w.null(ber::context(7));

	ber::reader r(w.bytes());
	CHECK(r.read_boolean() == true);
	CHECK(r.read_boolean() == false);
	CHECK(r.read_null().has_value());
	auto empty = r.read_octet_string();
	REQUIRE(empty);
	CHECK(empty->empty());
	CHECK(r.read_string() == "hello");
	CHECK(r.read_string(ber::context(2)) == std::pmr::string(1000, 'z'));
	CHECK(r.read_boolean(ber::context(1)) == true);
	CHECK(r.read_null(ber::context(7)).has_value());
	CHECK(r.empty());
	CHECK(r.expect_end().has_value());
}

TEST_CASE("ber::reader decodes lenient but valid encodings", "[ber][reader]")
{
	SECTION("non-minimal integers of up to 8 octets")
	{
		const auto data = bytes({ 0x02, 0x02, 0x00, 0x7F, 0x02, 0x03, 0xFF, 0xFF, 0x80 });
		ber::reader r(data);
		CHECK(r.read_integer() == 127);
		CHECK(r.read_integer() == -128);
	}
	SECTION("any non-zero BOOLEAN octet is true")
	{
		const auto data = bytes({ 0x01, 0x01, 0x01 });
		ber::reader r(data);
		CHECK(r.read_boolean() == true);
	}
	SECTION("non-minimal long-form lengths")
	{
		const auto data = bytes({ 0x04, 0x81, 0x02, 0x61, 0x62, 0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 0x63 });
		ber::reader r(data);
		CHECK(r.read_string() == "ab");
		CHECK(r.read_string() == "c");
		CHECK(r.empty());
	}
}

TEST_CASE("ber::reader walks nested constructed elements", "[ber][reader]")
{
	ber::writer w;
	w.constructed(ber::tags::sequence, [](ber::writer &a) {
		a.integer(1);
		a.constructed(ber::tags::set, [](ber::writer &b) {
			b.octet_string("x");
			b.constructed(ber::context(0), [](ber::writer &c) { c.boolean(true); });
		});
		a.null();
	});

	ber::reader top(w.bytes());
	auto seq = top.enter();
	REQUIRE(seq);
	CHECK(top.empty());
	CHECK(seq->depth() == 1);
	CHECK(seq->read_integer() == 1);
	auto set = seq->enter(ber::tags::set);
	REQUIRE(set);
	CHECK(set->depth() == 2);
	CHECK(set->read_string() == "x");
	auto ctx = set->enter(ber::context(0));// constructed flag of the argument is not needed
	REQUIRE(ctx);
	CHECK(ctx->read_boolean() == true);
	CHECK(ctx->expect_end().has_value());
	CHECK(set->expect_end().has_value());
	CHECK(seq->read_null().has_value());
	CHECK(seq->expect_end().has_value());
}

TEST_CASE("ber::reader reads back a bind request field by field", "[ber][reader]")
{
	const auto data = bytes({ 0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 });
	ber::reader r(data);

	auto msg = r.enter(ber::tags::sequence);
	REQUIRE(msg);
	CHECK(msg->read_integer() == 1);// messageID
	CHECK(msg->peek_tag() == ber::application(0, true));
	auto bind = msg->enter(ber::application(0));
	REQUIRE(bind);
	CHECK(bind->read_integer() == 3);// version
	CHECK(bind->read_string() == "");// name
	CHECK(bind->peek_tag() == ber::context(0));
	auto password = bind->read_octet_string(ber::context(0));
	REQUIRE(password);
	CHECK(password->empty());
	CHECK(bind->expect_end().has_value());
	CHECK(msg->expect_end().has_value());
	CHECK(r.expect_end().has_value());
}

TEST_CASE("ber::reader::read returns raw elements", "[ber][reader]")
{
	const auto data = bytes({ 0x04, 0x02, 0x61, 0x62, 0xA1, 0x03, 0x01, 0x01, 0xFF });
	ber::reader r(data);
	auto a = r.read();
	REQUIRE(a);
	CHECK(a->t == ber::tags::octet_string);
	CHECK(a->offset == 0);
	CHECK(a->header_size == 2);
	CHECK(hex(a->content) == "61 62");
	CHECK(r.offset() == 4);
	CHECK(r.remaining() == 5);

	CHECK(code_of(r.read(ber::tags::sequence)) == client_errc::unexpected_tag);
	CHECK(r.remaining() == 5);
	auto b = r.read(ber::context(1, true));
	REQUIRE(b);
	CHECK(b->offset == 4);
	CHECK(hex(b->content) == "01 01 FF");
	CHECK(r.empty());
}

TEST_CASE("ber::reader rejects malformed input", "[ber][reader][malformed]")
{
	SECTION("empty input")
	{
		ber::reader r({});
		CHECK(code_of(r.peek_tag()) == client_errc::decode_error);
		CHECK(code_of(r.read()) == client_errc::decode_error);
		CHECK(code_of(r.read_integer()) == client_errc::decode_error);
	}
	SECTION("truncated header")
	{
		const auto only_tag = bytes({ 0x02 });
		CHECK(code_of(ber::reader(only_tag).read()) == client_errc::decode_error);
		const auto partial_length = bytes({ 0x04, 0x82, 0x01 });
		ber::reader r(partial_length);
		auto e = r.read();
		CHECK(code_of(e) == client_errc::decode_error);
		CHECK(context_of(e).contains("truncated header"));
		CHECK(r.offset() == 0);
	}
	SECTION("truncated content / length beyond the input")
	{
		const auto data = bytes({ 0x30, 0x03, 0x04, 0x05, 0x61, 0x62 });
		ber::reader r(data);
		auto seq = r.enter();
		REQUIRE(seq);// outer element itself is complete
		auto s = seq->read_octet_string();
		CHECK(code_of(s) == client_errc::decode_error);
		CHECK(context_of(s).contains("offset 2"));

		const auto huge = bytes({ 0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 });
		CHECK(code_of(ber::reader(huge).read()) == client_errc::decode_error);
	}
	SECTION("indefinite length")
	{
		const auto data = bytes({ 0x30, 0x80, 0x05, 0x00, 0x00, 0x00 });
		auto e = ber::reader(data).enter();
		CHECK(code_of(e) == client_errc::decode_error);
		CHECK(context_of(e).contains("indefinite"));
	}
	SECTION("length of length too big")
	{
		const auto five = bytes({ 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x61 });
		CHECK(code_of(ber::reader(five).read()) == client_errc::decode_error);
		const auto reserved = bytes({ 0x04, 0xFF });
		CHECK(code_of(ber::reader(reserved).read()) == client_errc::decode_error);
	}
	SECTION("high-tag-number form")
	{
		const auto data = bytes({ 0x9F, 0x1F, 0x01, 0x00 });
		ber::reader r(data);
		CHECK(code_of(r.peek_tag()) == client_errc::unsupported_tag);
		CHECK(code_of(r.read()) == client_errc::unsupported_tag);
	}
	SECTION("INTEGER with 9 octets")
	{
		const auto data = bytes({ 0x02, 0x09, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0 });
		ber::reader r(data);
		auto v = r.read_integer();
		CHECK(code_of(v) == client_errc::integer_overflow);
		CHECK(context_of(v).contains("offset 0"));
		CHECK(r.offset() == 0);// unchanged on failure
	}
	SECTION("empty INTEGER and ENUMERATED")
	{
		const auto data = bytes({ 0x02, 0x00, 0x0A, 0x00 });
		ber::reader r(data);
		CHECK(code_of(r.read_integer()) == client_errc::decode_error);
		REQUIRE(r.read());
		CHECK(code_of(r.read_enumerated()) == client_errc::decode_error);
	}
	SECTION("BOOLEAN with length != 1")
	{
		const auto zero = bytes({ 0x01, 0x00 });
		CHECK(code_of(ber::reader(zero).read_boolean()) == client_errc::decode_error);
		const auto two = bytes({ 0x01, 0x02, 0xFF, 0xFF });
		CHECK(code_of(ber::reader(two).read_boolean()) == client_errc::decode_error);
	}
	SECTION("NULL with content")
	{
		const auto data = bytes({ 0x05, 0x01, 0x00 });
		CHECK(code_of(ber::reader(data).read_null()) == client_errc::decode_error);
	}
	SECTION("wrong expected tag")
	{
		const auto data = bytes({ 0x04, 0x01, 0x61 });
		ber::reader r(data);
		auto v = r.read_integer();
		CHECK(code_of(v) == client_errc::unexpected_tag);
		CHECK(context_of(v).contains("[UNIVERSAL 4]"));
		CHECK(code_of(r.read_boolean()) == client_errc::unexpected_tag);
		CHECK(code_of(r.read_octet_string(ber::context(4))) == client_errc::unexpected_tag);
		CHECK(code_of(r.enter()) == client_errc::unexpected_tag);
		CHECK(r.read_string() == "a");// still readable after the failures
	}
	SECTION("constructed form where primitive is required, and vice versa")
	{
		const auto constructed_string = bytes({ 0x24, 0x03, 0x04, 0x01, 0x61 });
		CHECK(code_of(ber::reader(constructed_string).read_octet_string()) == client_errc::unexpected_tag);
		const auto primitive_seq = bytes({ 0x10, 0x00 });
		CHECK(code_of(ber::reader(primitive_seq).enter()) == client_errc::unexpected_tag);
	}
	SECTION("trailing garbage")
	{
		const auto data = bytes({ 0x30, 0x05, 0x02, 0x01, 0x07, 0xDE, 0xAD });
		ber::reader r(data);
		auto seq = r.enter();
		REQUIRE(seq);
		CHECK(seq->read_integer() == 7);
		auto end = seq->expect_end();
		CHECK(code_of(end) == client_errc::decode_error);
		CHECK(context_of(end).contains("offset 5"));
	}
}

TEST_CASE("ber::reader bounds nesting depth", "[ber][reader][malformed]")
{
	// 40 nested SEQUENCEs around a NULL, built inside out.
	std::vector<std::byte> data = bytes({ 0x05, 0x00 });
	for (int i = 0; i < 40; ++i) {
		const auto len = static_cast<std::byte>(data.size());
		data.insert(data.begin(), { std::byte{ 0x30 }, len });
	}

	const auto depth_reached = [&](std::size_t max_depth) {
		ber::reader r(data, max_depth);
		std::size_t depth = 0;
		while (true) {
			auto next = r.enter();
			if (!next) {
				CHECK(next.error().code == client_errc::nesting_too_deep);
				return depth;
			}
			r = *next;
			++depth;
			if (depth == 40) {
				CHECK(r.read_null().has_value());
				return depth;
			}
		}
	};
	CHECK(depth_reached(ber::reader::default_max_depth) == 32);
	CHECK(depth_reached(4) == 4);
	CHECK(depth_reached(0) == 0);
	CHECK(depth_reached(100) == 40);
}

TEST_CASE("ber::reader error offsets are absolute", "[ber][reader]")
{
	// SEQUENCE { INTEGER 1, SEQUENCE { INTEGER with 9 octets } }
	const auto data = bytes({ 0x30, 0x10, 0x02, 0x01, 0x01, 0x30, 0x0B, 0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
	ber::reader r(data);
	auto a = r.enter();
	REQUIRE(a);
	REQUIRE(a->read_integer() == 1);
	auto b = a->enter();
	REQUIRE(b);
	CHECK(b->offset() == 7);
	auto v = b->read_integer();
	CHECK(code_of(v) == client_errc::integer_overflow);
	CHECK(context_of(v).contains("at offset 7"));
}

TEST_CASE("ber::reader::read(tag) ignores the constructed bit of the expected tag", "[ber][reader]")
{
	const auto data = bytes({ 0xA1, 0x02, 0x05, 0x00, 0x81, 0x00 });
	ber::reader r(data);
	auto a = r.read(ber::context(1));
	REQUIRE(a);
	CHECK(a->t == ber::context(1, true));// real bit is kept
	CHECK(hex(a->content) == "05 00");
	CHECK(code_of(r.read(ber::context(2))) == client_errc::unexpected_tag);
	CHECK(code_of(r.read(ber::application(1))) == client_errc::unexpected_tag);
	auto b = r.read(ber::context(1, true));
	REQUIRE(b);
	CHECK(b->t == ber::context(1));
	CHECK(r.empty());
}

TEST_CASE("ber::reader::enter_encapsulated", "[ber][reader]")
{
	// SEQUENCE { OCTET STRING { SEQUENCE { INTEGER with 9 octets } } }
	const auto data = bytes({ 0x30, 0x0F, 0x04, 0x0D, 0x30, 0x0B, 0x02, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9 });

	SECTION("offsets in errors are absolute")
	{
		ber::reader r(data);
		auto a = r.enter();
		REQUIRE(a);
		auto b = a->enter_encapsulated();
		REQUIRE(b);
		CHECK(a->empty());
		CHECK(b->depth() == 2);
		CHECK(b->offset() == 4);
		auto c = b->enter();
		REQUIRE(c);
		CHECK(c->depth() == 3);
		CHECK(c->offset() == 6);
		auto v = c->read_integer();
		CHECK(code_of(v) == client_errc::integer_overflow);
		CHECK(context_of(v).contains("at offset 6"));
	}
	SECTION("the depth limit applies across encapsulation")
	{
		ber::reader r(data, 2);
		auto a = r.enter();
		REQUIRE(a);
		auto b = a->enter_encapsulated();
		REQUIRE(b);
		auto deep = b->enter();
		CHECK(code_of(deep) == client_errc::nesting_too_deep);
		CHECK(context_of(deep) == "ber: more than 2 levels at offset 4");

		ber::reader shallow(data, 1);
		auto s = shallow.enter();
		REQUIRE(s);
		CHECK(code_of(s->enter_encapsulated()) == client_errc::nesting_too_deep);
		CHECK(s->remaining() == 15);// unchanged on failure
	}
	SECTION("tag checks")
	{
		ber::reader r(data);
		CHECK(code_of(r.enter_encapsulated()) == client_errc::unexpected_tag);// constructed SEQUENCE
		const auto ctx = bytes({ 0x80, 0x02, 0x05, 0x00 });
		ber::reader c(ctx);
		CHECK(code_of(c.enter_encapsulated()) == client_errc::unexpected_tag);
		auto inner = c.enter_encapsulated(ber::context(0));
		REQUIRE(inner);
		CHECK(inner->read_null().has_value());
		CHECK(inner->expect_end().has_value());
	}
}
