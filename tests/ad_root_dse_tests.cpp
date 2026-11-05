#include "jhetz/ldap/ad/root_dse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <string_view>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;

namespace {

auto root_dse(std::initializer_list<std::string_view> capabilities) -> ldap::entry
{
	ldap::entry e;
	e.attributes.emplace_back(
	  ldap::attribute::unchecked("supportedLDAPVersion"), std::initializer_list<std::string_view>{ "3" });
	e.attributes.emplace_back(ldap::attribute::unchecked("supportedCapabilities"), capabilities);
	return e;
}

}// namespace

TEST_CASE("ad::edition_of: AD DS", "[ad]")
{
	// A Windows Server 2016 domain controller's list.
	const auto dse = root_dse({ "1.2.840.113556.1.4.800",
	  "1.2.840.113556.1.4.1670",
	  "1.2.840.113556.1.4.1791",
	  "1.2.840.113556.1.4.1935",
	  "1.2.840.113556.1.4.2080",
	  "1.2.840.113556.1.4.2237" });
	CHECK(ad::edition_of(dse) == ad::edition::ds);
	CHECK(ad::is_active_directory(dse));
}

TEST_CASE("ad::edition_of: AD LDS", "[ad]")
{
	const auto dse = root_dse({ "1.2.840.113556.1.4.1851",
	  "1.2.840.113556.1.4.1670",
	  "1.2.840.113556.1.4.1791",
	  "1.2.840.113556.1.4.1935",
	  "1.2.840.113556.1.4.2080",
	  "1.2.840.113556.1.4.2237" });
	CHECK(ad::edition_of(dse) == ad::edition::lds);
	CHECK(ad::is_active_directory(dse));
}

TEST_CASE("ad::edition_of: Samba AD", "[ad]")
{
	const auto dse = root_dse({ "1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791" });
	CHECK(ad::edition_of(dse) == ad::edition::ds);
	CHECK(ad::is_active_directory(dse));
}

TEST_CASE("ad::edition_of: both capabilities give ds", "[ad]")
{
	CHECK(ad::edition_of(root_dse({ ad::lds_capability_oid, ad::ds_capability_oid })) == ad::edition::ds);
}

TEST_CASE("ad::edition_of: OpenLDAP and missing capabilities", "[ad]")
{
	SECTION("OpenLDAP lists no supportedCapabilities")
	{
		ldap::entry e;
		e.attributes.emplace_back(ldap::attribute::unchecked("supportedExtension"),
		  std::initializer_list<std::string_view>{ "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.4.1.4203.1.11.3" });
		e.attributes.emplace_back(
		  ldap::attribute::unchecked("supportedLDAPVersion"), std::initializer_list<std::string_view>{ "3" });
		CHECK(ad::edition_of(e) == ad::edition::none);
		CHECK_FALSE(ad::is_active_directory(e));
	}
	SECTION("an empty entry")
	{
		CHECK(ad::edition_of(ldap::entry{}) == ad::edition::none);
		CHECK_FALSE(ad::is_active_directory(ldap::entry{}));
	}
	SECTION("other capabilities only")
	{
		CHECK_FALSE(ad::is_active_directory(root_dse({ "1.2.840.113556.1.4.1670" })));
	}
	SECTION("supportedCapabilities without values (typesOnly)") { CHECK_FALSE(ad::is_active_directory(root_dse({}))); }
	SECTION("a prefix of the OID does not match")
	{
		CHECK_FALSE(ad::is_active_directory(root_dse({ "1.2.840.113556.1.4.80", "1.2.840.113556.1.4.18510" })));
	}
}

TEST_CASE("ad::edition_of: the attribute name is case-insensitive", "[ad]")
{
	ldap::entry e;
	e.attributes.emplace_back(ldap::attribute::unchecked("SUPPORTEDCAPABILITIES"),
	  std::initializer_list<std::string_view>{ ad::ds_capability_oid });
	CHECK(ad::edition_of(e) == ad::edition::ds);
}
