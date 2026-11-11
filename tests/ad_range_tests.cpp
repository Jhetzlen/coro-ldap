// ad::parse_range and ad::with_range: the range option of MS-ADTS
// 3.1.1.3.1.3.3.
#include "jhetz/ldap/ad/range.hpp"

#include <catch2/catch_test_macros.hpp>

#include <limits>
#include <optional>
#include <string>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;

TEST_CASE("ad::parse_range: windows and the last one", "[ad][range]")
{
	auto r = ad::parse_range("member;range=0-1499");
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK(**r == ad::ranged_description{ .type = "member", .range = { .low = 0, .high = 1499 } });

	r = ad::parse_range("member;range=1500-*");
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK(**r == ad::ranged_description{ .type = "member", .range = { .low = 1500 } });

	// The option name in any case; other options kept in order.
	r = ad::parse_range("userCertificate;binary;Range=3-3;lang-en");
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK((*r)->type == "userCertificate;binary;lang-en");
	CHECK((*r)->range == ad::value_range{ .low = 3, .high = 3 });

	r = ad::parse_range("member;range=0-4294967295");
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK((*r)->range.high == std::numeric_limits<std::uint32_t>::max());
}

TEST_CASE("ad::parse_range: no range option", "[ad][range]")
{
	for (const char *d : { "member", "member;binary", "member;ranger", "range=0-1" }) {
		CAPTURE(d);
		auto r = ad::parse_range(d);
		REQUIRE(r.has_value());
		CHECK_FALSE(r->has_value());
	}
}

TEST_CASE("ad::parse_range: malformed ranges", "[ad][range]")
{
	for (const char *d : { "member;range=",
		   "member;range=0",
		   "member;range=-5",
		   "member;range=0-",
		   "member;range=a-5",
		   "member;range=+1-5",
		   "member;range=5-3",
		   "member;range=0-**",
		   "member;range=4294967296-*",
		   "member;range=0-4294967296",
		   "member;range=0-1;range=2-3",
		   ";range=0-*" }) {
		CAPTURE(d);
		auto r = ad::parse_range(d);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
	}
}

TEST_CASE("ad::with_range: the description a request asks for", "[ad][range]")
{
	CHECK(ad::with_range("member", { .low = 0, .high = 1499 }) == "member;range=0-1499");
	CHECK(ad::with_range("member", { .low = 1500 }) == "member;range=1500-*");
	const std::string again = ad::with_range("member;binary", { .low = 7, .high = 9 });
	auto r = ad::parse_range(again);
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK(**r == ad::ranged_description{ .type = "member;binary", .range = { .low = 7, .high = 9 } });
}
