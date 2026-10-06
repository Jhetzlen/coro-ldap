#include "jhetz/ldap/controls.hpp"

#include "counting_resource.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory_resource>
#include <optional>
#include <string>

namespace ldap = jhetz::ldap;

TEST_CASE("typed request controls encode to their wire form", "[controls]")
{
	CHECK(ldap::to_control(ldap::manage_dsa_it{}).value() == ldap::control{ ldap::manage_dsa_it_oid, false });
	CHECK(ldap::to_control(ldap::manage_dsa_it{ .critical = true }).value()
		  == ldap::control{ ldap::manage_dsa_it_oid, true });
	// RFC 4370: always critical; the value is the authzId itself.
	CHECK(ldap::to_control(ldap::proxied_authorization{ "u:jdoe" }).value()
		  == ldap::control{ ldap::proxied_authorization_oid, true, "u:jdoe" });
	CHECK(ldap::to_control(ldap::proxied_authorization{}).value()
		  == ldap::control{ ldap::proxied_authorization_oid, true, "" });
	const auto p = ldap::to_control(ldap::paged{ .page_size = 50, .cookie = "abc", .critical = true });
	REQUIRE(p.has_value());
	CHECK(*p == *ldap::encode_paged_results({ 50, "abc" }, true));
	CHECK(ldap::to_control(ldap::control{ "1.2.3", true, "v" }).value() == ldap::control{ "1.2.3", true, "v" });

	auto negative = ldap::to_control(ldap::paged{ .page_size = -1 });
	REQUIRE_FALSE(negative.has_value());
	CHECK(negative.error().code == ldap::client_errc::encode_error);
}

TEST_CASE("controls are encoded on the given resource", "[controls][pmr]")
{
	jhetz::ldap::test::counting_resource mr;
	std::pmr::vector<ldap::control> out(&mr);
	REQUIRE(ldap::append_controls({ ldap::paged{ .page_size = 5 }, ldap::proxied_authorization{ "dn:cn=x" } }, out)
			  .has_value());
	REQUIRE(out.size() == 2);
	for (const auto &c : out) CHECK(c.get_allocator().resource() == &mr);
	CHECK(mr.allocations() > 0);
}

TEST_CASE("find_paged", "[controls]")
{
	std::pmr::vector<ldap::control> none{ ldap::control{ "1.2.3" } };
	auto r = ldap::find_paged(none);
	REQUIRE(r.has_value());
	CHECK_FALSE(r->has_value());

	std::pmr::vector<ldap::control> some{ ldap::control{ "1.2.3" }, *ldap::encode_paged_results({ 0, "next" }) };
	auto p = ldap::find_paged(some);
	REQUIRE(p.has_value());
	REQUIRE(p->has_value());
	CHECK((*p)->cookie == "next");

	std::pmr::vector<ldap::control> bad{ ldap::control{ ldap::paged_results_oid, false, "x" } };
	auto b = ldap::find_paged(bad);
	REQUIRE_FALSE(b.has_value());
	CHECK(b.error().code == ldap::cond::protocol_error);
}
