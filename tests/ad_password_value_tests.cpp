// ad::password_value: the quoted UTF-16LE unicodePwd value.
#include "jhetz/ldap/ad/password_value.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

#ifdef __linux__
#include <sys/mman.h>
#endif

namespace ldap = jhetz::ldap;
using namespace std::literals;
using ldap::client_errc;

TEST_CASE("ad::password_value: quoted UTF-16LE, full Unicode", "[ad][password]")
{
	CHECK(ldap::ad::password_value("") == "\"\0\"\0"s);
	CHECK(ldap::ad::password_value("ab") == "\"\0a\0b\0\"\0"s);
	// U+00E9, U+20AC, U+65E5 and U+1F600 (outside the BMP: a surrogate pair,
	// D83D DE00, each unit little-endian).
	CHECK(ldap::ad::password_value("\xC3\xA9\xE2\x82\xAC\xE6\x97\xA5\xF0\x9F\x98\x80")
		  == "\"\0\xE9\0\xAC\x20\xE5\x65\x3D\xD8\x00\xDE\"\0"s);
	// A quote inside the password is just a character.
	CHECK(ldap::ad::password_value("a\"b") == "\"\0a\0\"\0b\0\"\0"s);

	// Ill-formed UTF-8: a truncated sequence, an overlong form, a
	// surrogate, a code point above U+10FFFF. The password is never quoted.
	for (std::string_view bad :
	  { "S3cret\xC3"sv, "S3cret\xC0\xAF"sv, "S3cret\xED\xA0\x80"sv, "S3cret\xF4\x90\x80\x80"sv }) {
		auto r = ldap::ad::password_value(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::encode_error);
		CHECK(std::string(r.error().context) == "Active Directory password value: the password is not valid UTF-8");
	}
}

TEST_CASE("ad::password_value: a password over the length limit", "[ad][password]")
{
#ifdef __linux__
	// One byte over the limit, over a reserved, never touched mapping.
	constexpr std::size_t size = (INT32_MAX / 2) - 1;
	void *p = mmap(nullptr, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED) {
		SKIP("cannot reserve 1 GiB of address space");
	}
	auto r = ldap::ad::password_value(std::string_view(static_cast<const char *>(p), size));
	munmap(p, size);
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::encode_error);
	CHECK(std::string(r.error().context) == "Active Directory password value: the password is too long");
#else
	SKIP("needs mmap");
#endif
}
