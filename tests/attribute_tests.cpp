#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/entry.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
using jhetz::ldap::client_errc;
using namespace std::string_literals;
using namespace std::string_view_literals;

static_assert(ldap::detail::is_attribute_description("cn"));
static_assert(ldap::detail::is_attribute_description("userCertificate;binary"));
static_assert(ldap::detail::is_attribute_description("2.5.4.3;lang-en;x-1"));
static_assert(!ldap::detail::is_attribute_description("cn;"));
static_assert(!ldap::detail::is_attribute_description("1cn"));

TEST_CASE("valid attribute descriptions", "[attribute]")
{
	const std::string good = GENERATE(as<std::string>{},
	  "cn",
	  "objectClass",
	  "x-custom-attr",
	  "cn;lang-en",
	  "cn;lang-en;phonetic",
	  "2.5.4.3",
	  "1.3.6.1.4.1.1466.115.121.1.15",
	  "0.0",
	  "10.20;x");
	INFO(good);
	auto a = ldap::attribute::parse(good);
	REQUIRE(a);
	CHECK(a->name() == std::string_view(good));
}

TEST_CASE("invalid attribute descriptions", "[attribute]")
{
	const std::string bad = GENERATE(as<std::string>{},
	  "",
	  "1",
	  "1.",
	  ".1",
	  "1..2",
	  "01.2",
	  "1.02",
	  "-cn",
	  "c n",
	  "c_n",
	  "cn;",
	  "cn;;x",
	  "cn;a_b",
	  ";x",
	  "cn=x",
	  "member;range=0-1499");
	INFO(bad);
	auto b = ldap::attribute::parse(bad);
	REQUIRE_FALSE(b);
	CHECK(b.error().code == client_errc::invalid_attribute);
}

TEST_CASE("attribute::parse shows its input sanitized", "[attribute]")
{
	const std::string fffd = "\xEF\xBF\xBD";// U+FFFD
	const auto context = [](std::string_view text) {
		auto r = ldap::attribute::parse(text);
		REQUIRE_FALSE(r);
		return std::string(r.error().context);
	};
	// Valid non-ASCII UTF-8 is kept; CR LF, ESC, bidi controls and ill-formed bytes are not.
	CHECK(context("n\xC3\xA9 \xE6\x97\xA5\r\n\x1B\xE2\x80\xAE\xFF")
		  == "attribute: \"n\xC3\xA9 \xE6\x97\xA5" + fffd + fffd + fffd + fffd + fffd
			   + "\" is not an attribute description");
	CHECK(context(std::string(1000, '_'))
		  == "attribute: \"" + std::string(64, '_') + "...\" is not an attribute description");
}

TEST_CASE("ci_hash / ci_equal fold A-Z only, in every byte position", "[attribute]")
{
	// Every pair of byte values, at each position of strings around the
	// 8-byte word boundaries: ci_equal agrees with iequals (byte-wise
	// ascii_lower), and equal strings hash the same.
	const ldap::detail::ci_hash hash;
	const ldap::detail::ci_equal equal;
	const std::string base = "abcdefghijklmnopqrstuvwxyz";
	std::size_t mismatches = 0;
	std::size_t hash_mismatches = 0;
	std::size_t equal_pairs = 0;
	for (std::size_t len : { 1u, 2u, 7u, 8u, 9u, 15u, 16u, 17u, 25u }) {
		for (std::size_t pos : { std::size_t{ 0 }, len / 2, len - 1 }) {
			std::string x = base.substr(0, len);
			std::string y = x;
			for (int c = 0; c < 256; ++c) {
				x[pos] = static_cast<char>(c);
				for (int d = 0; d < 256; ++d) {
					y[pos] = static_cast<char>(d);
					const bool expected = ldap::detail::iequals(x, y);
					if (equal(x, y) != expected) {
						++mismatches;
					}
					if (expected) {
						++equal_pairs;
						if (hash(x) != hash(y)) {
							++hash_mismatches;
						}
					}
				}
			}
		}
	}
	CHECK(mismatches == 0);
	CHECK(hash_mismatches == 0);
	CHECK(equal_pairs == 9uz * 3 * (256 + 2 * 26));// each byte with itself, A-Z with a-z both ways
	CHECK_FALSE(equal("ab", "abc"));
	CHECK(equal("", ""));
	CHECK(hash("") == hash(std::string_view()));
	CHECK(hash("a") != hash(std::string_view("a\0", 2)));
}

TEST_CASE("ci_hash: no full 64-bit collisions among similar OIDs", "[attribute]")
{
	// A single multiply per word let these collide in all 64 bits.
	const ldap::detail::ci_hash hash;
	CHECK(hash("1.3.6.1.4.1.0.14.1.8") != hash("1.3.6.1.4.1.0.18.1.4"));
	// 8000 OIDs 1.3.6.1.4.1.a.b.1.c (the weak mix gave 40 collisions).
	std::vector<std::size_t> hashes;
	for (int a = 0; a < 20; ++a) {
		for (int b = 0; b < 20; ++b) {
			for (int c = 0; c < 20; ++c) {
				hashes.push_back(
				  hash("1.3.6.1.4.1." + std::to_string(a) + "." + std::to_string(b) + ".1." + std::to_string(c)));
			}
		}
	}
	std::ranges::sort(hashes);
	CHECK(std::ranges::adjacent_find(hashes) == hashes.end());
}

TEST_CASE("ci_hash: strings of different lengths do not collide", "[attribute]")
{
	// The length XORed into the seed shared bits with the first word, so
	// these collided in all 64 bits.
	const ldap::detail::ci_hash hash;
	CHECK(hash("1.1.1.1.1") != hash("3.1.1.1.1.1"));
	CHECK(hash("2.2.2.2.2") != hash("0.2.2.2.2.2"));
	CHECK(hash("abbbbbbbb") != hash("bbbbbbbbbb"));
	CHECK(hash("a") != hash(std::string_view("b\0", 2)));

	const auto distinct = [](std::vector<std::size_t> hashes) {
		std::ranges::sort(hashes);
		return std::ranges::adjacent_find(hashes) == hashes.end();
	};
	// Every byte (bar A-Z, which fold onto a-z) repeated, lengths 1..64:
	// the length-in-seed hash had 7 collisions here.
	std::vector<std::size_t> hashes;
	for (int c = 0; c < 256; ++c) {
		if (c < 'A' || c > 'Z') {
			for (std::size_t n = 1; n <= 64; ++n) {
				hashes.push_back(hash(std::string(n, static_cast<char>(c))));
			}
		}
	}
	CHECK(distinct(std::exchange(hashes, {})));
	// Periodic OID-like strings: "<d>" + ".<e>" * k.
	for (char d = '0'; d <= '9'; ++d) {
		for (char e = '0'; e <= '9'; ++e) {
			std::string s(1, d);
			for (int k = 1; k <= 24; ++k) {
				s += std::string{ '.', e };
				hashes.push_back(hash(s));
			}
		}
	}
	CHECK(distinct(std::exchange(hashes, {})));
}

namespace {

// The rounds of hash_value (attribute.cpp) and their inverse, to build names
// that collide under the hash as it was before it had a seed.
constexpr std::uint64_t k1 = 0x9E37'79B9'7F4A'7C15ull, k2 = 0xD6E8'FEB8'6659'FD93ull;

constexpr auto inverse(std::uint64_t odd) -> std::uint64_t// mod 2^64, by Newton's iteration
{
	std::uint64_t x = odd;
	for (int i = 0; i < 6; ++i) {
		x *= 2 - odd * x;
	}
	return x;
}

constexpr auto mix(std::uint64_t h, std::uint64_t w) -> std::uint64_t
{
	h = (h ^ w) * k1;
	h ^= h >> 32;
	h *= k2;
	return h ^ (h >> 32);
}

// The x with mix(0, x) == h.
constexpr auto unmix(std::uint64_t h) -> std::uint64_t
{
	h ^= h >> 32;
	h *= inverse(k2);
	h ^= h >> 32;
	return h * inverse(k1);
}

static_assert(unmix(mix(0, 0x0123'4567'89AB'CDEFull)) == 0x0123'4567'89AB'CDEFull);

}// namespace

// coro-ldap-pyf: hash_value started from a fixed state and its
// rounds are invertible, so anyone could compute attribute names colliding
// in all 64 bits, and a server sending them made entry::from quadratic.
TEST_CASE("ci_hash is seeded: names crafted to collide under a fixed start spread", "[attribute]")
{
	// 16-byte names "<8 digits><w2>": with the old start h0, the state after
	// both words is the same for every name, so the old hash was too.
	constexpr std::uint64_t h0 = 0xCBF2'9CE4'8422'2325ull;
	const std::uint64_t target = mix(mix(h0, 1), 2);
	const auto word = [](std::string_view s) {
		std::uint64_t w{};
		std::memcpy(&w, s.data(), 8);// as hash_value loads it
		return w;
	};
	std::vector<std::string> names;
	for (int i = 0; names.size() < 2000; ++i) {
		const std::string digits = std::format("{:08}", i);
		const std::uint64_t w2 = unmix(target) ^ mix(h0, word(digits));
		std::string name = digits + std::string(8, '\0');
		std::memcpy(name.data() + 8, &w2, 8);
		// No A-Z, which the hash would fold: names stay as computed.
		if (std::ranges::any_of(name, [](char c) { return c >= 'A' && c <= 'Z'; })) {
			continue;
		}
		REQUIRE(mix(mix(h0, word(name)), word(std::string_view(name).substr(8))) == target);
		names.push_back(std::move(name));
	}

	std::vector<std::size_t> hashes;
	for (const auto &n : names) {
		hashes.push_back(ldap::hash_value(n));
	}
	std::ranges::sort(hashes);
	CHECK(std::ranges::adjacent_find(hashes) == hashes.end());

	// And entry::from keeps them apart.
	ldap::search_result_entry e("cn=x");
	for (const auto &n : names) {
		e.attributes.emplace_back(n, std::initializer_list<std::string_view>{ "v" });
	}
	const auto out = ldap::entry::from(std::move(e));
	CHECK(out.attributes.size() == names.size());
	CHECK(out.find(names.back()) != nullptr);
}

TEST_CASE("attribute comparison and hashing ignore case", "[attribute]")
{
	const ldap::attribute a{ "objectClass" };
	const ldap::attribute b = *ldap::attribute::parse("OBJECTCLASS");
	CHECK(a == b);
	CHECK(a.name() == "objectClass");// spelling kept
	CHECK(std::hash<ldap::attribute>{}(a) == std::hash<ldap::attribute>{}(b));
	CHECK(a != ldap::attribute{ "objectClasses" });
	CHECK(ldap::attribute{ "cn;LANG-EN" } == ldap::attribute{ "CN;lang-en" });
	CHECK(ldap::attribute{ "cn" } != ldap::attribute{ "cn;lang-en" });

	CHECK(ldap::attribute{ "a" } < ldap::attribute{ "B" });
	CHECK(ldap::attribute{ "B" } > ldap::attribute{ "a" });
	CHECK(ldap::attribute{ "cn" } < ldap::attribute{ "cn;x" });
	CHECK((ldap::attribute{ "CN" } <=> ldap::attribute{ "cn" }) == 0);

	std::unordered_set<ldap::attribute> set{
		ldap::attribute{ "mail" }, ldap::attribute{ "MAIL" }, ldap::attribute{ "cn" }
	};
	CHECK(set.size() == 2);
	std::map<ldap::attribute, int> ordered{ { ldap::attribute{ "Mail" }, 1 } };
	CHECK(ordered.count(ldap::attribute{ "mail" }) == 1);

	// Server-supplied names are kept as sent.
	const auto range = ldap::attribute::unchecked("member;range=0-1499");
	CHECK(range.name() == "member;range=0-1499");
	CHECK(range == ldap::attribute::unchecked("MEMBER;RANGE=0-1499"));
}

TEST_CASE("entry from a search result entry", "[entry]")
{
	ldap::search_result_entry e{ "uid=jdoe,dc=example,dc=org",
		{ { "cn", { "John", "Johnny" } },
		  { "objectClass", { "top", "person" } },
		  { "jpegPhoto", { "\xff\xd8\0\x01"s } },
		  { "CN", { "J" } },
		  { "member;range=0-1499", { "a" } },
		  { "noValues", {} } } };
	const auto x = ldap::entry::from(e);
	CHECK(x.dn == "uid=jdoe,dc=example,dc=org");
	REQUIRE(x.attributes.size() == 5);
	CHECK(x.attributes[0].type.name() == "cn");
	CHECK(x.attributes[1].type.name() == "objectClass");

	const auto *cn = x.find("CN");
	REQUIRE(cn != nullptr);
	CHECK(*cn == ldap::string_list{ "John", "Johnny", "J" });
	CHECK(x.find(ldap::attribute{ "OBJECTCLASS" }) == &x.attributes[1].values);
	CHECK(x.find("jpegphoto")->front() == "\xff\xd8\0\x01"sv);
	CHECK(x.find("member;range=0-1499") != nullptr);
	CHECK(x.find("member") == nullptr);
	CHECK(x.find("mail") == nullptr);
	REQUIRE(x.find("novalues") != nullptr);
	CHECK(x.find("novalues")->empty());
	CHECK(ldap::entry::from(e) == x);
}
