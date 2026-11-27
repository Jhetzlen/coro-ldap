#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"

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
		"DC=example,DC=org", ldap::search_scope::whole_subtree, ldap::filter::parse("(isDeleted=TRUE)").value() },
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

// ---------------------------------------------------------------- DirSync

namespace {

auto raw(const ldap::control &c) -> std::string { return std::string(c.value.value_or(std::pmr::string{})); }

}// namespace

TEST_CASE("ad::dirsync_request: the value (MS-ADTS 3.1.1.3.4.1.3)", "[ad][controls][dirsync]")
{
	CHECK(ad::dirsync_oid == "1.2.840.113556.1.4.841");
	const ad::dirsync_request r{ .flags = ad::dirsync_flags::incremental_values | ad::dirsync_flags::object_security,
		.cookie = "c" };
	const ldap::control c = r;
	CHECK(c.type == ad::dirsync_oid);
	CHECK(c.criticality);
	// Flags as AD's signed 32-bit INTEGER, MaxBytes 1048576, Cookie.
	CHECK(raw(c) == "\x30\x0E\x02\x04\x80\x00\x00\x01\x02\x03\x10\x00\x00\x04\x01\x63"s);
	CHECK(ldap::testing::ad::decode_dirsync_request(c) == r);

	// An empty cookie (the first poll) is an empty OCTET STRING.
	const ldap::control first = ad::dirsync_request{ .max_bytes = 0, .critical = false };
	CHECK_FALSE(first.criticality);
	CHECK(raw(first) == "\x30\x08\x02\x01\x00\x02\x01\x00\x04\x00"s);

	// Flags written unsigned (five octets) read the same.
	const ldap::control unsigned_flags{
		ad::dirsync_oid, true, "\x30\x0D\x02\x05\x00\x80\x00\x00\x00\x02\x01\x05\x04\x01x"s
	};
	auto d = ldap::testing::ad::decode_dirsync_request(unsigned_flags);
	REQUIRE(d.has_value());
	CHECK(d->flags == ad::dirsync_flags::incremental_values);
	CHECK(has(d->flags, ad::dirsync_flags::incremental_values));
	CHECK(d->max_bytes == 5);
	CHECK(d->cookie == "x");

	// In a search's controls.
	const ldap::search_params search{ .base = ldap::dn{}, .controls = { r } };
	CHECK(std::get<ldap::control>(search.controls[0]) == c);
}

TEST_CASE("ad::dirsync_response: the value", "[ad][controls][dirsync]")
{
	const ad::dirsync_response r{ .more_results = true, .cookie_server = "MSDS\x01"s };
	const ldap::control c = ldap::testing::ad::encode_dirsync_response(r);
	CHECK_FALSE(c.criticality);
	CHECK(raw(c) == "\x30\x0D\x02\x01\x01\x02\x01\x00\x04\x05MSDS\x01"s);
	CHECK(ad::decode_dirsync_response(c) == r);

	// Any non-zero MoreResults is true; trailing elements are skipped.
	const ldap::control other{ ad::dirsync_oid, false, "\x30\x0A\x02\x01\x07\x02\x01\x00\x04\x00\x05\x00"s };
	auto d = ad::decode_dirsync_response(other);
	REQUIRE(d.has_value());
	CHECK(d->more_results);
	CHECK(d->cookie_server.empty());

	std::pmr::vector<ldap::control> controls{ ldap::control{ "1.2.3" }, c };
	auto found = ad::find_dirsync_response(controls);
	REQUIRE(found.has_value());
	REQUIRE(found->has_value());
	CHECK(**found == r);
	controls.pop_back();
	found = ad::find_dirsync_response(controls);
	REQUIRE(found.has_value());
	CHECK_FALSE(found->has_value());
}

TEST_CASE("ad::dirsync: malformed values", "[ad][controls][dirsync]")
{
	for (const std::string &value : {
		   ""s,
		   "\x30\x00"s,
		   "\x30\x06\x02\x01\x00\x02\x01\x00"s,// no cookie
		   "\x30\x0C\x02\x05\x01\x00\x00\x00\x00\x02\x01\x00\x04\x00"s,// 2^32
		   "\x30\x09\x02\x01\x00\x02\x01\x00\x01\x01\xFF"s,// a BOOLEAN for the cookie
		   "\x30\x08\x02\x01\x00\x02\x01\x00\x04\x00\x00"s,// trailing octet after the SEQUENCE
		 }) {
		CAPTURE(value);
		const ldap::control c{ ad::dirsync_oid, true, value };
		auto req = ldap::testing::ad::decode_dirsync_request(c);
		REQUIRE_FALSE(req.has_value());
		CHECK((req.error().code == ldap::client_errc::decode_error
			   || req.error().code == ldap::client_errc::unexpected_tag));
		auto resp = ad::decode_dirsync_response(c);
		REQUIRE_FALSE(resp.has_value());
	}
	// MaxBytes outside the signed 32-bit range.
	auto big = ldap::testing::ad::decode_dirsync_request(
	  ldap::control{ ad::dirsync_oid, true, "\x30\x0C\x02\x01\x00\x02\x05\x00\x80\x00\x00\x00\x04\x00"s });
	REQUIRE_FALSE(big.has_value());
	CHECK(big.error().code == ldap::client_errc::decode_error);
	// Another control, or none.
	CHECK_FALSE(ldap::testing::ad::decode_dirsync_request(ldap::control{ "1.2.3", true, "\x30\x00"s }).has_value());
	CHECK_FALSE(ad::decode_dirsync_response(ldap::control{ ad::dirsync_oid }).has_value());
}

// ---------------------------------------------------------------- change notification

TEST_CASE("ad::notification: the control (MS-ADTS 3.1.1.3.4.1.9)", "[ad][controls][notification]")
{
	CHECK(ad::notification_oid == "1.2.840.113556.1.4.528");
	const ldap::control c = ad::notification{};
	CHECK(c == ldap::control{ ad::notification_oid, true });
	CHECK_FALSE(c.value.has_value());
	CHECK(ldap::control(ad::notification{ .critical = false }) == ldap::control{ ad::notification_oid, false });
}

TEST_CASE("ad::notification_search: the search AD expects", "[ad][controls][notification]")
{
	const auto s = ad::notification_search(
	  ldap::dn{ "CN=Users,DC=example,DC=org" }, ldap::search_scope::single_level, { "description", "member" });
	CHECK(s.base.to_string() == "CN=Users,DC=example,DC=org");
	CHECK(s.scope == ldap::search_scope::single_level);
	CHECK(s.filter.to_string() == "(objectClass=*)");
	CHECK(s.attributes == ldap::string_list{ "description", "member" });
	REQUIRE(s.controls.size() == 1);
	CHECK(std::get<ldap::control>(s.controls[0]) == ldap::control{ ad::notification_oid, true });
	CHECK(s.timeout == ldap::no_timeout);

	const auto base = ad::notification_search(ldap::dn{ "CN=x,DC=example,DC=org" });
	CHECK(base.scope == ldap::search_scope::base_object);
	CHECK(base.attributes.empty());
}
