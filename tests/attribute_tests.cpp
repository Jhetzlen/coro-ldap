#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"

#include "../src/icu_util.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
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

namespace {

// The code point of the well-formed n-octet UTF-8 sequence at the start of s.
auto decode_utf8(std::string_view s, std::size_t n) -> UChar32
{
	const auto at = [&](std::size_t k) { return std::uint32_t{ static_cast<unsigned char>(s[k]) }; };
	if (n == 1) {
		return static_cast<UChar32>(at(0));
	}
	std::uint32_t c = at(0) & (0x7Fu >> n);
	for (std::size_t k = 1; k < n; ++k) {
		c = (c << 6u) | (at(k) & 0x3Fu);
	}
	return static_cast<UChar32>(c);
}

// The length of the maximal subpart (Unicode section 3.9) at the start of
// the ill-formed s.
auto maximal_subpart(std::string_view s) -> std::size_t
{
	std::size_t best = 1;
	for (std::size_t k = 2; k <= std::min<std::size_t>(4, s.size()); ++k) {
		std::array<char, 4> padded{ '\x80', '\x80', '\x80', '\x80' };
		std::copy_n(s.begin(), k, padded.begin());
		if (ldap::detail::constexpr_utf8_sequence_length({ padded.data(), padded.size() }, 0) < k) {
			break;
		}
		best = k;
	}
	return best;
}

}// namespace

// The ICU and the constant-evaluation UTF-8 checks agree on every 1- to
// 3-octet string and the 4-octet edge cases; utf8_next agrees too.
TEST_CASE("utf8_sequence_length: the compile-time check matches ICU", "[attribute][utf8]")
{
	std::size_t mismatches = 0;
	std::size_t step_mismatches = 0;
	const auto compare = [&](std::string_view s) {
		const std::size_t expected = ldap::detail::constexpr_utf8_sequence_length(s, 0);
		if (expected != ldap::detail::utf8_sequence_length(s, 0)) {
			++mismatches;
		}
		const auto [c, n] = ldap::detail::utf8_next(s, 0);
		const bool step_ok =
		  expected != 0 ? n == expected && c == decode_utf8(s, expected) : c < 0 && n == maximal_subpart(s);
		if (!step_ok) {
			++step_mismatches;
		}
	};
	std::string s;
	for (unsigned a = 0; a < 0x100; ++a) {
		s.assign(1, static_cast<char>(a));
		compare(s);
		for (unsigned b = 0; b < 0x100; ++b) {
			s.assign({ static_cast<char>(a), static_cast<char>(b) });
			compare(s);
			if (a < 0xC2) {
				continue;// ASCII, a stray continuation or an invalid lead: one octet decides
			}
			for (unsigned c = 0; c < 0x100; ++c) {
				s.assign({ static_cast<char>(a), static_cast<char>(b), static_cast<char>(c) });
				compare(s);
			}
		}
	}
	const std::vector<unsigned> edges{ 0x00, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xFF };
	for (unsigned a = 0xC0; a < 0x100; ++a) {
		for (const unsigned b : edges) {
			for (const unsigned c : edges) {
				for (const unsigned d : edges) {
					s.assign(
					  { static_cast<char>(a), static_cast<char>(b), static_cast<char>(c), static_cast<char>(d) });
					compare(s);
				}
			}
		}
	}
	CHECK(mismatches == 0);
	CHECK(step_mismatches == 0);

	// At compile time (the path the DN literals take).
	static_assert(ldap::detail::utf8_sequence_length("\xC3\xA9", 0) == 2);
	static_assert(ldap::detail::utf8_sequence_length("\xF4\x8F\xBF\xBF", 0) == 4);// U+10FFFF
	static_assert(ldap::detail::utf8_sequence_length("\xF4\x90\x80\x80", 0) == 0);// above U+10FFFF
	static_assert(ldap::detail::utf8_sequence_length("\xED\xA0\x80", 0) == 0);// surrogate
	static_assert(ldap::detail::utf8_sequence_length("\xC0\xAF", 0) == 0);// overlong
	static_assert(ldap::detail::utf8_sequence_length("\xF0\x9F\x98", 0) == 0);// truncated
	// And at run time, through ICU.
	CHECK(ldap::detail::utf8_sequence_length("\xF0\x9F\x98\x80", 0) == 4);
	CHECK(ldap::detail::utf8_sequence_length("\xF0\x9F\x98", 0) == 0);
	CHECK(ldap::detail::utf8_sequence_length("\xF5\x80\x80\x80", 0) == 0);
}

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
	// Every pair of byte values around the 8-byte word boundaries: ci_equal
	// agrees with iequals, and equal strings hash the same.
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
	CHECK(equal_pairs == 9uz * 3 * (256 + (2 * 26)));// each byte with itself, A-Z with a-z both ways
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

// The rounds of hash_value and their inverse, to build colliding names for
// an unseeded hash.
constexpr std::uint64_t k1 = 0x9E37'79B9'7F4A'7C15ull, k2 = 0xD6E8'FEB8'6659'FD93ull;

constexpr auto inverse(std::uint64_t odd) -> std::uint64_t// mod 2^64, by Newton's iteration
{
	std::uint64_t x = odd;
	for (int i = 0; i < 6; ++i) {
		x *= 2 - (odd * x);
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

TEST_CASE("ci_hash is seeded: names crafted to collide under a fixed start spread", "[attribute]")
{
	// 16-byte names "<8 digits><w2>" with the same state from a fixed start h0.
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
	hashes.reserve(names.size());
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
	// Not `== 0`: Catch2's decomposer would pass the 0 as an int, which
	// MSVC's comparison operators (taking a literal zero) refuse.
	CHECK((ldap::attribute{ "CN" } <=> ldap::attribute{ "cn" }) == std::weak_ordering::equivalent);

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

TEST_CASE("entry::parsed_dn", "[entry]")
{
	ldap::entry x;
	x.dn = "uid=J\\C3\\BCrgen,ou=Le\xc3\xbcte,dc=example,dc=org";
	const auto d = x.parsed_dn();
	REQUIRE(d.has_value());
	CHECK(*d == ldap::dn::parse("uid=J\xc3\xbcrgen,ou=Le\xc3\xbcte,dc=example,dc=org").value());
	CHECK(d->parent() == ldap::dn{ "ou=Le\xc3\xbcte,dc=example,dc=org" });

	x.dn = "";
	REQUIRE(x.parsed_dn().has_value());
	CHECK(x.parsed_dn()->empty());

	x.dn = "not a dn";
	const auto bad = x.parsed_dn();
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == ldap::client_errc::invalid_dn);
}

TEST_CASE("entry::find compares options as a set", "[entry]")
{
	const auto x = ldap::entry::from(ldap::search_result_entry{ "cn=X,dc=example,dc=org",
	  { { "userCertificate;binary;lang-en", { "der" } }, { "cn;lang-en;x-foo", { "Ecks" } }, { "sn", { "Y" } } } });
	CHECK(x.find("userCertificate;lang-en;binary") == &x.attributes[0].values);
	CHECK(x.find("USERCERTIFICATE;LANG-EN;BINARY") == &x.attributes[0].values);
	CHECK(x.find("userCertificate;binary") == nullptr);
	CHECK(x.find("userCertificate;binary;lang-en;lang-fr") == nullptr);
	CHECK(x.find("userCertificate") == nullptr);
	CHECK(x.find("cn;x-foo;lang-en") == &x.attributes[1].values);
	CHECK(x.find("cn;lang-en") == nullptr);
	CHECK(x.find("sn;lang-en") == nullptr);
	CHECK(x.find("sn") == &x.attributes[2].values);
}

TEST_CASE("same_description", "[entry]")
{
	using ldap::detail::same_description;
	CHECK(same_description("cn", "CN"));
	CHECK(same_description("cn;lang-en;binary", "CN;Binary;LANG-EN"));
	CHECK(same_description("cn;lang-en;lang-en", "cn;lang-en"));
	CHECK_FALSE(same_description("cn", "cn;lang-en"));
	CHECK_FALSE(same_description("cn;lang-en", "cn"));
	CHECK_FALSE(same_description("cn;lang-en", "sn;lang-en"));
	CHECK_FALSE(same_description("cn;lang-en", "cn;lang-en;x-foo"));
	CHECK_FALSE(same_description("cn;lang-en;x-foo", "cn;lang-en"));
}
