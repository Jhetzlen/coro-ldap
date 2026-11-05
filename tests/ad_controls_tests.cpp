#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <variant>

namespace ldap = jhetz::ldap;
namespace ad = jhetz::ldap::ad;
using namespace std::string_literals;

TEST_CASE("ad::show_deleted: the control (MS-ADTS 3.1.1.3.4.1.14)", "[ad][controls]")
{
	CHECK(ad::show_deleted_oid == "1.2.840.113556.1.4.417");
	const ldap::control c = ad::show_deleted{};
	CHECK(c == ldap::control{ ad::show_deleted_oid, true });
	CHECK_FALSE(c.value.has_value());
	CHECK(ldap::control(ad::show_deleted{ .critical = false }) == ldap::control{ ad::show_deleted_oid, false });

	// Controls [0] SEQUENCE { LDAPOID, criticality TRUE }, no controlValue.
	const auto bytes = ldap::encode(ldap::message{ 1,
	  ldap::search_request{
		"DC=example,DC=org", ldap::search_scope::whole_subtree, ldap::filter::raw("(isDeleted=TRUE)").value() },
	  { ad::show_deleted{} } });
	REQUIRE(bytes.has_value());
	const std::string tail =
	  "\xA0\x1D\x30\x1B\x04\x16"
	  "1.2.840.113556.1.4.417"
	  "\x01\x01\xFF"s;
	CHECK(std::string_view(reinterpret_cast<const char *>(bytes->data()), bytes->size()).ends_with(tail));
}

TEST_CASE("ad::show_deleted: in any operation's controls", "[ad][controls]")
{
	const ldap::search_params search{ .base = ldap::dn{}, .controls = { ad::show_deleted{}, ldap::manage_dsa_it{} } };
	REQUIRE(search.controls.size() == 2);
	CHECK(std::get<ldap::control>(search.controls[0]).type == ad::show_deleted_oid);

	const ldap::modify_params modify{ .controls = { ad::show_deleted{} } };
	CHECK(std::get<ldap::control>(modify.controls[0]).criticality);
	const ldap::del_params del{ .controls = { ad::show_deleted{ .critical = false } } };
	CHECK_FALSE(std::get<ldap::control>(del.controls[0]).criticality);

	const ldap::request_controls shared{ ad::show_deleted{} };
	auto converted = ldap::controls_for<ldap::search_controls>(shared);
	REQUIRE(converted.has_value());
	CHECK(std::get<ldap::control>((*converted)[0]) == ldap::control{ ad::show_deleted_oid, true });
}
