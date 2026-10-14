// server_schema lookups do not allocate. A separate executable: it replaces
// the global operator new / delete to count allocations, which must not
// affect the other tests. The whole unaligned family is replaced (with
// ASan, new and delete must come from the same side); the aligned family is
// left to the implementation (std::string never uses it).
#include "jhetz/ldap/schema.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include <vector>

namespace {

thread_local std::size_t allocations = 0;

auto counted_alloc(std::size_t n) noexcept -> void *
{
	++allocations;
	return std::malloc(n == 0 ? 1 : n);
}

auto counted_alloc_or_throw(std::size_t n) -> void *
{
	if (void *p = counted_alloc(n)) {
		return p;
	}
	throw std::bad_alloc();
}

}// namespace

auto operator new(std::size_t n) -> void * { return counted_alloc_or_throw(n); }
auto operator new[](std::size_t n) -> void * { return counted_alloc_or_throw(n); }
auto operator new(std::size_t n, const std::nothrow_t &) noexcept -> void * { return counted_alloc(n); }
auto operator new[](std::size_t n, const std::nothrow_t &) noexcept -> void * { return counted_alloc(n); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }
void operator delete(void *p, const std::nothrow_t &) noexcept { std::free(p); }
void operator delete[](void *p, const std::nothrow_t &) noexcept { std::free(p); }

namespace ldap = jhetz::ldap;

TEST_CASE("schema: lookups do not allocate", "[schema][alloc]")
{
	// Names longer than the small-string buffer: a lower-cased std::string
	// copy of them would allocate.
	const std::pmr::vector<std::pmr::string> types{
		"( 1.2.840.113556.1.4.656 NAME 'userPrincipalName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'passwordPolicyAttribute' SUP userPrincipalName )",
	};
	const std::pmr::vector<std::pmr::string> classes{ "( 1.3.6.1.4.1.42.2.27.8.2.1 NAME 'passwordPolicySubentry' )" };
	const auto s = ldap::server_schema::parse(types, classes);

	// The counter sees the allocations of this thread.
	std::size_t before = allocations;
	auto probe = std::make_unique<std::string>(64, 'x');
	CHECK(allocations - before == 2);
	probe.reset();

	before = allocations;
	const auto *upn = s.find_attribute("USERPRINCIPALNAME;lang-en-with-a-long-option");
	const auto *policy = s.find_attribute("PasswordPolicyAttribute");
	const auto *by_oid = s.find_attribute("1.3.6.1.4.1.42.2.27.8.1.1");
	const auto *missing = s.find_attribute("someAttributeThatIsNotThere");
	const auto *oc = s.find_object_class("PASSWORDPOLICYSUBENTRY");
	const auto *oc_by_oid = s.find_object_class("1.3.6.1.4.1.42.2.27.8.2.1");
	const std::size_t lookup_allocations = allocations - before;

	CHECK(lookup_allocations == 0);
	REQUIRE(upn != nullptr);
	CHECK(upn->oid == "1.2.840.113556.1.4.656");
	REQUIRE(policy != nullptr);
	CHECK(by_oid == policy);
	CHECK(missing == nullptr);
	REQUIRE(oc != nullptr);
	CHECK(oc_by_oid == oc);
}
