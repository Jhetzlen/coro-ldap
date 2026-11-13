#include "jhetz/ldap/controls.hpp"

#include "counting_resource.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using jhetz::ldap::test::from_hex;
using jhetz::ldap::test::hex;

namespace {

auto value_hex(const ldap::control &c) -> std::string
{
	REQUIRE(c.value.has_value());
	return hex(std::as_bytes(std::span(*c.value)));
}

// A control whose value is the given hex bytes.
auto with_value(std::string_view oid, std::string_view hex_value) -> ldap::control
{
	const auto b = from_hex(hex_value);
	return ldap::control{ oid, false, ldap::detail::as_text(b) };
}

}// namespace

TEST_CASE("typed request controls encode to their wire form", "[controls]")
{
	CHECK(ldap::to_control(ldap::manage_dsa_it{}).value() == ldap::control{ ldap::manage_dsa_it_oid, false });
	CHECK(ldap::to_control(ldap::manage_dsa_it{ .critical = true }).value()
		  == ldap::control{ ldap::manage_dsa_it_oid, true });
	// draft-zeilenga-ldap-relax: no value, critical by default.
	CHECK(ldap::to_control(ldap::relax_rules{}).value() == ldap::control{ "1.3.6.1.4.1.4203.666.5.12", true });
	CHECK(!ldap::to_control(ldap::relax_rules{}).value().value.has_value());
	CHECK(ldap::to_control(ldap::relax_rules{ .critical = false }).value()
		  == ldap::control{ ldap::relax_rules_oid, false });
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

// The applicability table (controls.hpp), row by row against the RFCs.
using ldap::applies_to;
using enum ldap::operation_kind;
static_assert(
  applies_to<ldap::paged>(search) && !applies_to<ldap::paged>(modify) && !applies_to<ldap::paged>(extended));
static_assert(applies_to<ldap::server_side_sort>(search) && !applies_to<ldap::server_side_sort>(compare));
static_assert(applies_to<ldap::sync_request>(search) && !applies_to<ldap::sync_request>(add));
static_assert(applies_to<ldap::matched_values>(search) && !applies_to<ldap::matched_values>(modify)
			  && !applies_to<ldap::matched_values>(compare) && !applies_to<ldap::matched_values>(extended));
static_assert(!std::is_convertible_v<ldap::matched_values, ldap::compare_controls::value_type>);
static_assert(applies_to<ldap::virtual_list_view>(search) && !applies_to<ldap::virtual_list_view>(modify)
			  && !applies_to<ldap::virtual_list_view>(extended));
static_assert(!std::is_convertible_v<ldap::virtual_list_view, ldap::del_controls::value_type>);
static_assert(applies_to<ldap::pre_read>(modify) && applies_to<ldap::pre_read>(del)
			  && applies_to<ldap::pre_read>(modify_dn) && !applies_to<ldap::pre_read>(add)
			  && !applies_to<ldap::pre_read>(search));
static_assert(applies_to<ldap::post_read>(add) && applies_to<ldap::post_read>(modify)
			  && applies_to<ldap::post_read>(modify_dn) && !applies_to<ldap::post_read>(del)
			  && !applies_to<ldap::post_read>(compare));
static_assert(applies_to<ldap::relax_rules>(add) && applies_to<ldap::relax_rules>(del)
			  && applies_to<ldap::relax_rules>(modify) && applies_to<ldap::relax_rules>(modify_dn)
			  && !applies_to<ldap::relax_rules>(search) && !applies_to<ldap::relax_rules>(compare)
			  && !applies_to<ldap::relax_rules>(extended));
// RFC 4528 section 3 and RFC 3296 section 3: on an extended operation only
// where its document defines them, which none typed here does.
static_assert(applies_to<ldap::assertion>(compare) && applies_to<ldap::assertion>(search)
			  && !applies_to<ldap::assertion>(extended));
static_assert(applies_to<ldap::manage_dsa_it>(search) && !applies_to<ldap::manage_dsa_it>(extended));
static_assert(applies_to<ldap::proxied_authorization>(extended));
static_assert(applies_to<ldap::control>(search) && applies_to<ldap::control>(extended));
static_assert(!std::is_convertible_v<ldap::pre_read, ldap::add_controls::value_type>);
static_assert(!std::is_convertible_v<ldap::post_read, ldap::del_controls::value_type>);
static_assert(!std::is_convertible_v<ldap::paged, ldap::modify_controls::value_type>);
static_assert(std::is_convertible_v<ldap::control, ldap::compare_controls::value_type>);
static_assert(!std::is_convertible_v<ldap::assertion, ldap::extended_controls::value_type>);
static_assert(!std::is_convertible_v<ldap::manage_dsa_it, ldap::extended_controls::value_type>);

TEST_CASE("the applicability table at run time", "[controls]")
{
	const std::vector<ldap::operation_kind> ops{ search, add, modify, modify_dn, del, compare, extended };
	const std::vector<std::string_view> names{
		"search", "add", "modify", "modify DN", "delete", "compare", "extended operation"
	};
	for (std::size_t i = 0; i < ops.size(); ++i) {
		CHECK(ldap::operation_name(ops[i]) == names[i]);
		CHECK(applies_to<ldap::matched_values>(ops[i]) == (ops[i] == search));
	}
	CHECK(ldap::operation_name(static_cast<ldap::operation_kind>(200)) == "operation");
	const auto set = ldap::operation_set_of(ops[2], ops[5]);
	CHECK(set.contains(modify));
	CHECK(set.contains(compare));
	CHECK_FALSE(set.contains(search));
}

TEST_CASE("controls_for checks a shared list against the operation", "[controls]")
{
	const ldap::request_controls shared{ ldap::manage_dsa_it{},
		ldap::control{ "1.2.3", false },
		ldap::assertion{ .filter = ldap::filters::attr("cn") == "x" } };
	const auto compare = ldap::controls_for<ldap::compare_controls>(shared);
	REQUIRE(compare.has_value());
	REQUIRE(compare->size() == 3);
	CHECK(std::holds_alternative<ldap::manage_dsa_it>((*compare)[0]));
	CHECK(std::get<ldap::control>((*compare)[1]).type == "1.2.3");
	CHECK(std::holds_alternative<ldap::assertion>((*compare)[2]));

	const auto add = ldap::controls_for<ldap::add_controls>(
	  ldap::request_controls{ ldap::post_read{}, ldap::pre_read{ .attributes = { "cn" } } });
	REQUIRE_FALSE(add.has_value());
	CHECK(add.error().code == ldap::client_errc::encode_error);
	CHECK(std::string(add.error().context) == "pre_read is not valid on add (RFC 4527 section 3.1)");

	const auto del = ldap::controls_for<ldap::del_controls>(ldap::request_controls{ ldap::post_read{} });
	REQUIRE_FALSE(del.has_value());
	CHECK(std::string(del.error().context) == "post_read is not valid on delete (RFC 4527 section 3.2)");

	const auto mod = ldap::controls_for<ldap::modify_dn_controls>(ldap::request_controls{ ldap::paged{} });
	REQUIRE_FALSE(mod.has_value());
	CHECK(std::string(mod.error().context) == "paged is not valid on modify DN (RFC 2696 section 2)");

	const auto search = ldap::controls_for<ldap::search_controls>(ldap::request_controls{ ldap::relax_rules{} });
	REQUIRE_FALSE(search.has_value());
	CHECK(std::string(search.error().context)
		  == "relax_rules is not valid on search (draft-zeilenga-ldap-relax-03 section 2)");

	const auto ext = ldap::controls_for<ldap::extended_controls>(ldap::request_controls{ ldap::sync_request{} });
	REQUIRE_FALSE(ext.has_value());
	CHECK(
	  std::string(ext.error().context) == "sync_request is not valid on an extended operation (RFC 4533 section 2.2)");

	const auto shared_ext = ldap::controls_for<ldap::extended_controls>(shared);
	REQUIRE_FALSE(shared_ext.has_value());
	CHECK(std::string(shared_ext.error().context)
		  == "manage_dsa_it is not valid on an extended operation (RFC 3296 section 3)");

	CHECK(ldap::controls_for<ldap::search_controls>({}).value().empty());
}

TEST_CASE("controls are encoded on the given resource", "[controls][pmr]")
{
	jhetz::ldap::test::counting_resource mr;
	std::pmr::vector<ldap::control> out(&mr);
	REQUIRE(ldap::append_controls(
	  ldap::search_controls{ ldap::paged{ .page_size = 5 }, ldap::proxied_authorization{ "dn:cn=x" } }, out)
		.has_value());
	REQUIRE(out.size() == 2);
	for (const auto &c : out) {
		CHECK(c.get_allocator().resource() == &mr);
	}
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
	// BER errors name the control: their offsets are relative to its value.
	CHECK(b.error().context == "paged results: ber: truncated header at offset 0");
	std::pmr::vector<ldap::control> no_size{ ldap::control{
	  ldap::paged_results_oid, false, std::string("\x30\x02\x04\x00", 4) } };
	auto n = ldap::find_paged(no_size);
	REQUIRE_FALSE(n.has_value());
	CHECK(n.error().context
		  == "paged results: ber: reading INTEGER: expected [UNIVERSAL 2], got [UNIVERSAL 4] at offset 2");

	// The first control of the OID wins; later ones are not decoded.
	std::pmr::vector<ldap::control> two{ *ldap::encode_paged_results({ 0, "first" }),
		*ldap::encode_paged_results({ 0, "second" }),
		ldap::control{ ldap::paged_results_oid, false, "x" } };
	auto f = ldap::find_paged(two);
	REQUIRE(f.has_value());
	REQUIRE(f->has_value());
	CHECK((*f)->cookie == "first");
	std::pmr::vector<ldap::control> bad_first{ ldap::control{ ldap::paged_results_oid, false, "x" },
		*ldap::encode_paged_results({ 0, "second" }) };
	CHECK_FALSE(ldap::find_paged(bad_first).has_value());
}

// ---------------------------------------------------------------- server side sort (RFC 2891)

TEST_CASE("server side sort request control", "[controls][sort]")
{
	const auto c = ldap::to_control(ldap::server_side_sort{
	  .keys = { { .attribute = "cn" }, { .attribute = "sn", .ordering_rule = "2.5.13.3", .reverse = true } },
	});
	REQUIRE(c.has_value());
	CHECK(c->type == ldap::sort_request_oid);
	CHECK(c->type == "1.2.840.113556.1.4.473");
	CHECK_FALSE(c->criticality);
	// SEQUENCE { SEQUENCE { "cn" }, SEQUENCE { "sn", [0] "2.5.13.3", [1] TRUE } }
	CHECK(value_hex(*c) == "30 19 30 04 04 02 63 6E 30 11 04 02 73 6E 80 08 32 2E 35 2E 31 33 2E 33 81 01 FF");

	const auto critical =
	  ldap::to_control(ldap::server_side_sort{ .keys = { { .attribute = "uid" } }, .critical = true });
	REQUIRE(critical.has_value());
	CHECK(critical->criticality);
	CHECK(value_hex(*critical) == "30 07 30 05 04 03 75 69 64");

	auto none = ldap::to_control(ldap::server_side_sort{});
	REQUIRE_FALSE(none.has_value());
	CHECK(none.error().code == ldap::client_errc::encode_error);
	CHECK(none.error().context == "server side sort: no sort keys");
	auto unnamed = ldap::to_control(ldap::server_side_sort{ .keys = { { .attribute = "cn" }, { .reverse = true } } });
	REQUIRE_FALSE(unnamed.has_value());
	CHECK(unnamed.error().code == ldap::client_errc::encode_error);
	CHECK(unnamed.error().context == "server side sort: key 2 has no attribute");
}

TEST_CASE("sort result response control", "[controls][sort]")
{
	const auto ok = ldap::encode_sort_result(ldap::sort_result{ 0 });
	REQUIRE(ok.has_value());
	CHECK(ok->type == ldap::sort_response_oid);
	CHECK(value_hex(*ok) == "30 03 0A 01 00");
	const auto failed = ldap::encode_sort_result({ 18, "cn" }, true);
	REQUIRE(failed.has_value());
	CHECK(failed->criticality);
	CHECK(value_hex(*failed) == "30 07 0A 01 12 80 02 63 6E");

	CHECK(ldap::decode_sort_result(*ok).value() == ldap::sort_result{ 0 });
	CHECK(ldap::decode_sort_result(*ok)->is_success());
	const auto f = ldap::decode_sort_result(*failed);
	REQUIRE(f.has_value());
	CHECK(f->result_code == 18);
	CHECK_FALSE(f->is_success());
	CHECK(f->attribute_type == "cn");

	// Unknown result codes are kept; unknown trailing elements are skipped;
	// an empty attributeType is the same as none.
	CHECK(ldap::decode_sort_result(with_value(ldap::sort_response_oid, "30 04 0A 02 11 67")).value()
		  == ldap::sort_result{ 4455 });
	CHECK(ldap::decode_sort_result(with_value(ldap::sort_response_oid, "30 09 0A 01 00 80 01 78 04 01 79")).value()
		  == ldap::sort_result{ 0, "x" });
	CHECK(ldap::decode_sort_result(with_value(ldap::sort_response_oid, "30 05 0A 01 35 80 00")).value()
		  == ldap::sort_result{ 53 });
}

TEST_CASE("malformed sort result controls", "[controls][sort]")
{
	auto code_of = [](const ldap::control &c) {
		auto r = ldap::decode_sort_result(c);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
		return r.error().code;
	};
	CHECK(code_of(ldap::control{ "1.2.3", false, "" }) == ldap::client_errc::decode_error);// other control
	CHECK(code_of(ldap::control{ ldap::sort_response_oid }) == ldap::client_errc::decode_error);// no value
	CHECK(code_of(with_value(ldap::sort_response_oid, "")) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::sort_response_oid, "30 00")) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::sort_response_oid, "30 03 02 01 00")) == ldap::client_errc::unexpected_tag);
	CHECK(code_of(with_value(ldap::sort_response_oid, "31 03 0A 01 00")) == ldap::client_errc::unexpected_tag);
	CHECK(code_of(with_value(ldap::sort_response_oid, "30 03 0A 01")) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::sort_response_oid, "30 03 0A 01 00 00")) == ldap::client_errc::decode_error);
	CHECK(
	  code_of(with_value(ldap::sort_response_oid, "30 07 0A 05 01 00 00 00 00")) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::sort_response_oid, "30 05 0A 01 00 A0 00")) == ldap::client_errc::unexpected_tag);
	CHECK(code_of(with_value(ldap::sort_response_oid, "30 05 0A 01 00 80 05")) == ldap::client_errc::decode_error);

	// Contexts name the control; offsets are within its value.
	CHECK(ldap::decode_sort_result(ldap::control{ "1.2.3" }).error().context
		  == "sort result: control type is 1.2.3, not 1.2.840.113556.1.4.474");
	CHECK(ldap::decode_sort_result(ldap::control{ ldap::sort_response_oid }).error().context
		  == "sort result: control has no value");
	CHECK(ldap::decode_sort_result(with_value(ldap::sort_response_oid, "30 03 02 01 00")).error().context
		  == "sort result: ber: reading ENUMERATED: expected [UNIVERSAL 10], got [UNIVERSAL 2] at offset 2");
}

TEST_CASE("find_sort_result", "[controls][sort]")
{
	std::pmr::vector<ldap::control> none{ ldap::control{ "1.2.3" }, *ldap::encode_paged_results({ 0, "" }) };
	auto r = ldap::find_sort_result(none);
	REQUIRE(r.has_value());
	CHECK_FALSE(r->has_value());

	std::pmr::vector<ldap::control> some{ ldap::control{ "1.2.3" }, *ldap::encode_sort_result({ 53, "sn" }) };
	auto s = ldap::find_sort_result(some);
	REQUIRE(s.has_value());
	REQUIRE(s->has_value());
	CHECK(**s == ldap::sort_result{ 53, "sn" });

	std::pmr::vector<ldap::control> bad{ ldap::control{ ldap::sort_response_oid, false, "x" } };
	auto b = ldap::find_sort_result(bad);
	REQUIRE_FALSE(b.has_value());
	CHECK(b.error().code == ldap::cond::protocol_error);
}

// ---------------------------------------------------------------- assertion (RFC 4528)

TEST_CASE("assertion control", "[controls][assertion]")
{
	using ldap::filters::attr;
	const auto c = ldap::to_control(ldap::assertion{ .filter = attr("cn") == "x" });
	REQUIRE(c.has_value());
	CHECK(c->type == ldap::assertion_oid);
	CHECK(c->type == "1.3.6.1.1.12");
	CHECK(c->criticality);// critical unless asked otherwise
	// The value is the Filter itself: equalityMatch [3] { "cn", "x" }.
	CHECK(value_hex(*c) == "A3 07 04 02 63 6E 04 01 78");

	const auto f = ldap::filter::raw("(&(objectClass=person)(!(sn=Doe)))").value();
	const auto lenient = ldap::to_control(ldap::assertion{ .filter = f, .critical = false });
	REQUIRE(lenient.has_value());
	CHECK_FALSE(lenient->criticality);
	ldap::ber::writer w;
	REQUIRE(ldap::encode_filter(w, f).has_value());
	CHECK(value_hex(*lenient) == hex(w.bytes()));

	auto empty = ldap::to_control(ldap::assertion{});
	REQUIRE_FALSE(empty.has_value());
	CHECK(empty.error().code == ldap::client_errc::invalid_filter);
	CHECK(empty.error().context == "assertion: filter: empty");
}

// ---------------------------------------------------------------- matched values (RFC 3876)

TEST_CASE("matched values request control", "[controls][matched_values]")
{
	using ldap::filters::attr;
	const auto c = ldap::to_control(ldap::matched_values{ .values_return_filter = { attr("mail") == "x" } });
	REQUIRE(c.has_value());
	CHECK(c->type == ldap::matched_values_oid);
	CHECK(c->type == "1.2.826.0.1.3344810.2.3");
	CHECK_FALSE(c->criticality);
	// SEQUENCE { equalityMatch [3] { "mail", "x" } }
	CHECK(value_hex(*c) == "30 0B A3 09 04 04 6D 61 69 6C 04 01 78");

	// Every SimpleFilterItem choice, in order: [3] .. [9], the extensible
	// match as SimpleMatchingAssertion (rule [1], type [2], value [3]).
	const auto all = ldap::to_control(ldap::matched_values{ .values_return_filter = { attr("cn") == "a",
															  ldap::filter::raw("(cn=a*b)").value(),
															  attr("n") >= "1",
															  attr("n") <= "2",
															  attr("cn").present(),
															  attr("cn").approx("c"),
															  ldap::filter::raw("(cn:2.5.13.5:=d)").value() },
	  .critical = true });
	REQUIRE(all.has_value());
	CHECK(all->criticality);
	CHECK(value_hex(*all)
		  == "30 47 A3 07 04 02 63 6E 04 01 61 A4 0C 04 02 63 6E 30 06 80 01 61 82 01 62 A5 06 04 01 6E 04 01 31"
			 " A6 06 04 01 6E 04 01 32 87 02 63 6E A8 07 04 02 63 6E 04 01 63"
			 " A9 11 81 08 32 2E 35 2E 31 33 2E 35 82 02 63 6E 83 01 64");
	// ... and decodes back to the same items, with the criticality.
	const auto back = ldap::decode_matched_values(*all);
	REQUIRE(back.has_value());
	CHECK(back->critical);
	CHECK(*back
		  == ldap::matched_values{ .values_return_filter = {
									 attr("cn") == "a",
									 ldap::filter::raw("(cn=a*b)").value(),
									 attr("n") >= "1",
									 attr("n") <= "2",
									 attr("cn").present(),
									 attr("cn").approx("c"),
									 ldap::filter::raw("(cn:2.5.13.5:=d)").value(),
								   },
			.critical = true });

	// UTF-8 values pass through unchanged.
	const auto utf8 =
	  ldap::to_control(ldap::matched_values{ .values_return_filter = { attr("sn") == "\xC3\x85ngstr\xC3\xB6m" } });
	REQUIRE(utf8.has_value());
	CHECK(value_hex(*utf8) == "30 12 A3 10 04 02 73 6E 04 0A C3 85 6E 67 73 74 72 C3 B6 6D");
}

TEST_CASE("matched values items RFC 3876 excludes", "[controls][matched_values]")
{
	using ldap::filters::attr;
	const auto refused = [](const ldap::matched_values &v) {
		auto c = ldap::to_control(v);
		REQUIRE_FALSE(c.has_value());
		return c.error();
	};
	const auto none = refused({});
	CHECK(none.code == ldap::client_errc::encode_error);
	CHECK(none.context == "matched values: no filter items");

	const auto both =
	  refused({ .values_return_filter = { attr("cn") == "x", attr("cn") == "x" && attr("sn") == "y" } });
	CHECK(both.code == ldap::client_errc::invalid_filter);
	CHECK(both.context == "matched values: item 2 is (&...), not a simple filter item (RFC 3876 section 2)");
	CHECK(refused({ .values_return_filter = { attr("cn") == "x" || attr("sn") == "y" } }).context
		  == "matched values: item 1 is (|...), not a simple filter item (RFC 3876 section 2)");
	CHECK(refused({ .values_return_filter = { !(attr("cn") == "x") } }).context
		  == "matched values: item 1 is (!...), not a simple filter item (RFC 3876 section 2)");
	CHECK(refused({ .values_return_filter = { ldap::filter::raw("(&)").value() } }).context
		  == "matched values: item 1 is (&...), not a simple filter item (RFC 3876 section 2)");
	// SimpleMatchingAssertion has no dnAttributes.
	const auto dn = refused({ .values_return_filter = { ldap::filter::raw("(ou:dn:=people)").value() } });
	CHECK(dn.code == ldap::client_errc::invalid_filter);
	CHECK(dn.context
		  == "matched values: item 1 is an extensible match with dnAttributes, not a simple filter item (RFC 3876 "
			 "section 2)");
	const auto empty = refused({ .values_return_filter = { attr("cn") == "x", ldap::filter{} } });
	CHECK(empty.code == ldap::client_errc::invalid_filter);
	CHECK(empty.context == "matched values: item 2 is empty");
	// Without dnAttributes an extensible match is fine.
	CHECK(
	  ldap::to_control(ldap::matched_values{ .values_return_filter = { ldap::filter::raw("(ou:=people)").value() } })
		.has_value());
}

TEST_CASE("parse_values_return_filter", "[controls][matched_values]")
{
	using ldap::filters::attr;
	// RFC 3876 section 5, example 1.
	const auto example = ldap::parse_values_return_filter("((mail=*hotmail.com)(telephoneNumber=*))");
	REQUIRE(example.has_value());
	REQUIRE(example->size() == 2);
	CHECK((*example)[0] == attr("mail").ends_with("hotmail.com"));
	CHECK((*example)[1] == attr("telephoneNumber").present());
	// Example 2, and a single item without the outer parentheses.
	CHECK(ldap::parse_values_return_filter("((attributeTypes=1.2.3.4.5))").value()
		  == std::vector{ attr("attributeTypes") == "1.2.3.4.5" });
	CHECK(ldap::parse_values_return_filter("(attributeTypes=1.2.3.4.5)").value()
		  == std::vector{ attr("attributeTypes") == "1.2.3.4.5" });
	// Escaped parentheses in values, UTF-8, extensible match.
	const auto escaped = ldap::parse_values_return_filter("((cn=a\\29b\\28)(sn=\xC3\x85*)(cn:caseExactMatch:=x))");
	REQUIRE(escaped.has_value());
	REQUIRE(escaped->size() == 3);
	CHECK((*escaped)[0] == (attr("cn") == "a)b("));
	CHECK((*escaped)[1] == attr("sn").starts_with("\xC3\x85"));
	CHECK((*escaped)[2] == ldap::filter::raw("(cn:caseExactMatch:=x)").value());

	// What libldap sends for that list (ldapsearch -E 'mv=((mail=*example*)(cn:caseExactMatch:=x))').
	const auto libldap = ldap::parse_values_return_filter("((mail=*example*)(cn:caseExactMatch:=x))");
	REQUIRE(libldap.has_value());
	const auto wire = ldap::to_control(ldap::matched_values{ .values_return_filter = *libldap });
	REQUIRE(wire.has_value());
	CHECK(value_hex(*wire)
		  == "30 2C A4 11 04 04 6D 61 69 6C 30 09 81 07 65 78 61 6D 70 6C 65 A9 17 81 0E 63 61 73 65 45 78 61 63 74 4D"
			 " 61 74 63 68 82 02 63 6E 83 01 78");

	const auto fails = [](std::string_view text) {
		auto r = ldap::parse_values_return_filter(text);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::invalid_filter);
		return std::string(r.error().context);
	};
	CHECK(fails("((cn=x)(&(a=b)(c=d)))")
		  == "matched values: item 2 is (&...), not a simple filter item (RFC 3876 section 2)");
	CHECK(fails("(|(a=b)(c=d))") == "matched values: item 1 is (|...), not a simple filter item (RFC 3876 section 2)");
	CHECK(fails("((ou:dn:=x))")
		  == "matched values: item 1 is an extensible match with dnAttributes, not a simple filter item (RFC 3876 "
			 "section 2)");
	CHECK(fails("(())").starts_with("matched values: item 1: filter: "));
	CHECK(fails("((cn=x)") == "matched values: unbalanced parentheses at position 1");
	CHECK(fails("((cn=x)(sn=y)") == "matched values: unbalanced parentheses at position 7");
	CHECK(fails("((cn=x)sn=y)") == "matched values: expected '(' at position 7");
	CHECK(fails("((cn=x)(sn=y)x") == "matched values: no closing parenthesis at position 14");
	CHECK(fails("((cn=x)(sn=y\\)") == "matched values: unbalanced parentheses at position 7");
	CHECK(fails("").starts_with("matched values: item 1: filter: "));
	// Positions in an item's errors count from the start of the whole text.
	CHECK(fails("(=y)") == "matched values: item 1: filter: invalid attribute description at position 1");
	CHECK(fails("((cn=x)(=y))") == "matched values: item 2: filter: invalid attribute description at position 8");
}

TEST_CASE("decode_matched_values", "[controls][matched_values]")
{
	const auto c = with_value(ldap::matched_values_oid, "30 0B A3 09 04 04 6D 61 69 6C 04 01 78");
	const auto v = ldap::decode_matched_values(c);
	REQUIRE(v.has_value());
	CHECK_FALSE(v->critical);
	CHECK(*v == ldap::matched_values{ .values_return_filter = { ldap::filters::attr("mail") == "x" } });

	const auto context_of = [](const ldap::control &bad) {
		auto r = ldap::decode_matched_values(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
		return std::string(r.error().context);
	};
	CHECK(context_of(ldap::control{ "1.2.3" }) == "matched values: control type is 1.2.3, not 1.2.826.0.1.3344810.2.3");
	CHECK(context_of(ldap::control{ ldap::matched_values_oid }) == "matched values: control has no value");
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 00")) == "matched values: no filter items");
	// (&(cn=x)) and an explicit dnAttributes TRUE are not SimpleFilterItems.
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 0B A0 09 A3 07 04 02 63 6E 04 01 78"))
		  == "matched values: item 1 is (&...), not a simple filter item (RFC 3876 section 2) at offset 2");
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 10 87 02 63 6E A9 0A 82 02 63 6E 83 01 78 84 01 FF"))
		  == "matched values: item 2 is an extensible match with dnAttributes, not a simple filter item (RFC 3876 "
			 "section 2) at offset 6");
	// An explicit dnAttributes FALSE is refused too.
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 0C A9 0A 82 02 63 6E 83 01 78 84 01 00"))
		  == "matched values: item 1 is an extensible match with dnAttributes, not a simple filter item (RFC 3876 "
			 "section 2) at offset 2");
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 04 87 02 63 6E 00"))
		  == "matched values: ber: 1 unexpected trailing bytes at offset 6");
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 03 87 02 63")).starts_with("matched values: ber: "));
	CHECK(
	  context_of(with_value(ldap::matched_values_oid, "30 04 04 02 63 6E")).starts_with("matched values: filter: "));
	// An extensible match whose content is not BER.
	CHECK(context_of(with_value(ldap::matched_values_oid, "30 04 A9 02 82 05")).starts_with("matched values: "));
}

namespace {

// (cn=x*x*...*x) with `parts` substrings: parts + 1 filter elements.
auto many_substrings(std::size_t parts) -> ldap::filter
{
	std::string text = "(cn=x";
	for (std::size_t i = 1; i < parts; ++i) {
		text += "*x";
	}
	text += ')';
	auto f = ldap::filter::raw(text, ldap::filter_limits{ .max_elements = 2 * ldap::max_filter_elements });
	REQUIRE(f.has_value());
	REQUIRE(f->elements() == parts + 1);
	return std::move(*f);
}

}// namespace

TEST_CASE("matched values: the filter element limit", "[controls][matched_values]")
{
	using ldap::filters::attr;
	// Encoding: an item over the limit names its position.
	const auto too_big = ldap::to_control(ldap::matched_values{
	  .values_return_filter = { attr("cn") == "x", many_substrings(ldap::max_filter_elements) } });
	REQUIRE_FALSE(too_big.has_value());
	CHECK(too_big.error().code == ldap::client_errc::invalid_filter);
	CHECK(std::string(too_big.error().context)
		  == "matched values: item 2: filter: too many elements (10001, at most 10000)");

	// Decoding: the items share one budget; an item after it is spent fails.
	ldap::ber::writer w;
	w.constructed(ldap::ber::tags::sequence, [](ldap::ber::writer &list) {
		REQUIRE(ldap::encode_filter(list, many_substrings(ldap::max_filter_elements - 1)).has_value());
		REQUIRE(ldap::encode_filter(list, attr("cn") == "x").has_value());
	});
	auto r =
	  ldap::decode_matched_values(ldap::control{ ldap::matched_values_oid, false, ldap::detail::as_text(w.bytes()) });
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::decode_error);
	CHECK(std::string(r.error().context).starts_with("matched values: more than 10000 filter elements at offset "));
}

// ---------------------------------------------------------------- virtual list view (draft-ietf-ldapext-ldapv3-vlv-09)

namespace {

// The 8-byte contextID slapd's sssvlv returned in the captures below.
constexpr std::string_view sssvlv_context_hex = "A0 1D 00 78 F7 7F 00 00";
auto sssvlv_context() -> std::string
{
	const auto b = from_hex(sssvlv_context_hex);
	return std::string(ldap::detail::as_text(b));
}

}// namespace

TEST_CASE("virtual list view request control", "[controls][vlv]")
{
	const auto first = ldap::to_control(ldap::virtual_list_view{});
	REQUIRE(first.has_value());
	CHECK(first->type == ldap::vlv_request_oid);
	CHECK(first->type == "2.16.840.1.113730.3.4.9");
	CHECK_FALSE(first->criticality);
	// beforeCount 0, afterCount 0, byOffset [0] { offset 1, contentCount 0 }: the first entry.
	CHECK(value_hex(*first) == "30 0E 02 01 00 02 01 00 A0 06 02 01 01 02 01 00");

	// What libldap sends for ldapsearch -E 'vlv=1/1/5/0', then for the next
	// window with the server's count and contextID.
	const auto by_offset = ldap::to_control(
	  ldap::virtual_list_view{ .before_count = 1, .after_count = 1, .target = ldap::vlv_by_offset{ .offset = 5 } });
	REQUIRE(by_offset.has_value());
	CHECK(value_hex(*by_offset) == "30 0E 02 01 01 02 01 01 A0 06 02 01 05 02 01 00");
	const auto next = ldap::to_control(ldap::virtual_list_view{ .before_count = 1,
	  .after_count = 1,
	  .target = ldap::vlv_by_offset{ .offset = 6, .content_count = 250 },
	  .context_id = sssvlv_context(),
	  .critical = true });
	REQUIRE(next.has_value());
	CHECK(next->criticality);
	CHECK(value_hex(*next)
		  == "30 19 02 01 01 02 01 01 A0 07 02 01 06 02 02 00 FA 04 08 " + std::string(sssvlv_context_hex));

	// greaterThanOrEqual [1] AssertionValue (ldapsearch -E 'vlv=0/4:10200'),
	// UTF-8 passed through, and an empty contextID is still sent.
	const auto typedown = ldap::to_control(
	  ldap::virtual_list_view{ .after_count = 4, .target = ldap::vlv_greater_than_or_equal{ .value = "10200" } });
	REQUIRE(typedown.has_value());
	CHECK(value_hex(*typedown) == "30 0D 02 01 00 02 01 04 81 05 31 30 32 30 30");
	const auto utf8 = ldap::to_control(ldap::virtual_list_view{
	  .target = ldap::vlv_greater_than_or_equal{ .value = "\xC3\x85" }, .context_id = std::string() });
	REQUIRE(utf8.has_value());
	CHECK(value_hex(*utf8) == "30 0C 02 01 00 02 01 00 81 02 C3 85 04 00");

	const auto refused = [](const ldap::virtual_list_view &v) {
		auto c = ldap::to_control(v);
		REQUIRE_FALSE(c.has_value());
		CHECK(c.error().code == ldap::client_errc::encode_error);
		return std::string(c.error().context);
	};
	CHECK(refused({ .before_count = -1 }) == "virtual list view: beforeCount -1 is negative");
	CHECK(refused({ .after_count = -2 }) == "virtual list view: afterCount -2 is negative");
	CHECK(
	  refused({ .target = ldap::vlv_by_offset{ .offset = 0 } }) == "virtual list view: offset 0 outside 1..2147483647");
	CHECK(refused({ .target = ldap::vlv_by_offset{ .offset = 1, .content_count = -1 } })
		  == "virtual list view: contentCount -1 is negative");
}

TEST_CASE("decode_virtual_list_view", "[controls][vlv]")
{
	const ldap::virtual_list_view all[] = {
		{},
		{ .before_count = 9,
		  .after_count = 10,
		  .target = ldap::vlv_by_offset{ .offset = 53424, .content_count = 78564 },
		  .context_id = sssvlv_context(),
		  .critical = true },
		{ .after_count = 19, .target = ldap::vlv_greater_than_or_equal{ .value = "B" } },
		{ .target = ldap::vlv_greater_than_or_equal{}, .context_id = std::string() },
	};
	for (const auto &v : all) {
		const auto c = ldap::to_control(v);
		REQUIRE(c.has_value());
		CHECK(ldap::decode_virtual_list_view(*c).value() == v);
	}
	// Unknown trailing elements are skipped.
	CHECK(ldap::decode_virtual_list_view(
			with_value(ldap::vlv_request_oid, "30 14 02 01 00 02 01 00 A0 09 02 01 01 02 01 00 01 01 00 02 01 07"))
			.value()
		  == ldap::virtual_list_view{});

	const auto context_of = [](const ldap::control &bad) {
		auto r = ldap::decode_virtual_list_view(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
		return std::string(r.error().context);
	};
	CHECK(
	  context_of(ldap::control{ "1.2.3" }) == "virtual list view: control type is 1.2.3, not 2.16.840.1.113730.3.4.9");
	CHECK(context_of(ldap::control{ ldap::vlv_request_oid }) == "virtual list view: control has no value");
	CHECK(context_of(with_value(ldap::vlv_request_oid, "30 0E 02 01 00 02 01 00 A0 06 02 01 00 02 01 00"))
		  == "virtual list view: offset 0 outside 1..2147483647 at offset 10");
	CHECK(context_of(with_value(ldap::vlv_request_oid, "30 0E 02 01 FF 02 01 00 A0 06 02 01 01 02 01 00"))
		  == "virtual list view: beforeCount -1 outside 0..2147483647 at offset 2");
	CHECK(context_of(with_value(ldap::vlv_request_oid, "30 08 02 01 00 02 01 00 82 00"))
		  == "virtual list view: target: expected [CONTEXT 0] or [CONTEXT 1] at offset 8");
	CHECK(context_of(with_value(ldap::vlv_request_oid, "30 06 02 01 00 02 01 00"))
		  == "virtual list view: target: expected [CONTEXT 0] or [CONTEXT 1] at offset 8");
	CHECK(context_of(with_value(ldap::vlv_request_oid, "30 08 02 01 00 02 01 00 81 00 00"))
		.starts_with("virtual list view: ber: "));
	CHECK(context_of(with_value(ldap::vlv_request_oid, "30 07 02 01 00 02 01 00 81"))
		.starts_with("virtual list view: ber: "));
}

TEST_CASE("virtual list view response control", "[controls][vlv]")
{
	// slapd's answer to 1/1/5/0 over 250 sorted entries.
	const ldap::vlv_response at5{ 5, 250, 0, sssvlv_context() };
	const auto c = ldap::encode_vlv_response(at5);
	REQUIRE(c.has_value());
	CHECK(c->type == ldap::vlv_response_oid);
	CHECK(c->type == "2.16.840.1.113730.3.4.10");
	CHECK(value_hex(*c) == "30 14 02 01 05 02 02 00 FA 0A 01 00 04 08 " + std::string(sssvlv_context_hex));
	const auto back = ldap::decode_vlv_response(*c);
	REQUIRE(back.has_value());
	CHECK(*back == at5);
	CHECK(back->is_success());
	REQUIRE(back->context_id.has_value());
	CHECK(std::string_view(*back->context_id) == sssvlv_context());

	// No entry >= the value: targetPosition is contentCount + 1 (section 5).
	const auto past = ldap::decode_vlv_response(with_value(
	  ldap::vlv_response_oid, "30 15 02 02 00 FB 02 02 00 FA 0A 01 00 04 08 " + std::string(sssvlv_context_hex)));
	REQUIRE(past.has_value());
	CHECK(past->target_position == 251);
	CHECK(past->content_count == 250);
	// An offset beyond the list: slapd's resultCode 76 comes with
	// virtualListViewResult 77, not the draft's offsetRangeError (61).
	const auto range = ldap::decode_vlv_response(with_value(
	  ldap::vlv_response_oid, "30 14 02 01 00 02 02 00 FA 0A 01 4D 04 08 " + std::string(sssvlv_context_hex)));
	REQUIRE(range.has_value());
	CHECK(range->result_code == 77);
	CHECK_FALSE(range->is_success());

	// No contextID, an empty one, unknown trailing elements, unknown codes.
	CHECK(value_hex(ldap::encode_vlv_response({ 1, 10 }, true).value()) == "30 09 02 01 01 02 01 0A 0A 01 00");
	const auto none = ldap::decode_vlv_response(with_value(ldap::vlv_response_oid, "30 09 02 01 01 02 01 0A 0A 01 3C"));
	REQUIRE(none.has_value());
	CHECK(*none == ldap::vlv_response{ 1, 10, 60 });
	CHECK_FALSE(none->context_id.has_value());
	const auto empty =
	  ldap::decode_vlv_response(with_value(ldap::vlv_response_oid, "30 0E 02 01 01 02 01 0A 0A 01 00 04 00 01 01 FF"));
	REQUIRE(empty.has_value());
	CHECK(*empty == ldap::vlv_response{ 1, 10, 0, "" });
	CHECK(value_hex(ldap::encode_vlv_response(*empty).value()) == "30 0B 02 01 01 02 01 0A 0A 01 00 04 00");

	auto negative = ldap::encode_vlv_response({ -1, 10 });
	REQUIRE_FALSE(negative.has_value());
	CHECK(negative.error().code == ldap::client_errc::encode_error);
	CHECK(negative.error().context == "vlv response: targetPosition -1 or contentCount 10 is negative");

	const auto context_of = [](const ldap::control &bad) {
		auto r = ldap::decode_vlv_response(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::cond::protocol_error);
		return std::string(r.error().context);
	};
	CHECK(context_of(ldap::control{ "1.2.3" }) == "vlv response: control type is 1.2.3, not 2.16.840.1.113730.3.4.10");
	CHECK(context_of(ldap::control{ ldap::vlv_response_oid }) == "vlv response: control has no value");
	CHECK(context_of(with_value(ldap::vlv_response_oid, "30 09 02 01 FF 02 01 0A 0A 01 00"))
		  == "vlv response: message: targetPosition -1 outside 0..2147483647 at offset 2");
	CHECK(context_of(with_value(ldap::vlv_response_oid, "30 06 02 01 01 02 01 0A")).starts_with("vlv response: ber: "));
	CHECK(context_of(with_value(ldap::vlv_response_oid, "30 09 02 01 01 02 01 0A 02 01 00"))
		  == "vlv response: ber: reading ENUMERATED: expected [UNIVERSAL 10], got [UNIVERSAL 2] at offset 8");
	CHECK(context_of(with_value(ldap::vlv_response_oid, "30 09 02 01 01 02 01 0A 0A 01 00 00"))
		.starts_with("vlv response: ber: "));
}

TEST_CASE("find_vlv_response", "[controls][vlv][pmr]")
{
	const std::pmr::vector<ldap::control> none{ *ldap::encode_sort_result(ldap::sort_result{ 0 }) };
	CHECK_FALSE(ldap::find_vlv_response(none).value().has_value());

	jhetz::ldap::test::counting_resource mr;
	const std::pmr::vector<ldap::control> some{ *ldap::encode_sort_result(ldap::sort_result{ 0 }),
		*ldap::encode_vlv_response({ 3, 100, 0, "ctx" }) };
	auto r = ldap::find_vlv_response(some, &mr);
	REQUIRE(r.has_value());
	REQUIRE(r->has_value());
	CHECK(**r == ldap::vlv_response{ 3, 100, 0, "ctx" });
	CHECK((*r)->get_allocator().resource() == &mr);
	CHECK((*r)->context_id->get_allocator().resource() == &mr);

	const std::pmr::vector<ldap::control> bad{ ldap::control{ ldap::vlv_response_oid, false, "x" } };
	auto b = ldap::find_vlv_response(bad);
	REQUIRE_FALSE(b.has_value());
	CHECK(b.error().code == ldap::cond::protocol_error);

	// Allocator-extended copies keep the given resource, plain copies use the default one.
	jhetz::ldap::test::counting_resource other;
	const ldap::vlv_response copied(**r, ldap::vlv_response::allocator_type(&other));
	CHECK(copied == **r);
	CHECK(copied.context_id->get_allocator().resource() == &other);
	const ldap::vlv_response plain(copied);// NOLINT(performance-unnecessary-copy-initialization): the copy is tested
	CHECK(plain.get_allocator().resource() == std::pmr::get_default_resource());
	ldap::vlv_response assigned{ ldap::vlv_response::allocator_type(&other) };
	assigned = **r;
	CHECK(assigned == **r);
	CHECK(assigned.context_id->get_allocator().resource() == &other);
}

TEST_CASE("a virtual list view needs a sort control", "[controls][vlv]")
{
	const ldap::server_side_sort by_uid_number{ .keys = { { .attribute = "uidNumber" } } };
	std::pmr::vector<ldap::control> out;
	auto alone = ldap::append_controls(ldap::search_controls{ ldap::virtual_list_view{} }, out);
	REQUIRE_FALSE(alone.has_value());
	CHECK(alone.error().code == ldap::client_errc::encode_error);
	CHECK(std::string(alone.error().context)
		  == "virtual_list_view needs a server_side_sort control on the same search (draft-ietf-ldapext-ldapv3-vlv-09 "
			 "section 6.1)");

	// The order does not matter, and a raw sort control counts.
	out.clear();
	CHECK(ldap::append_controls(ldap::search_controls{ ldap::virtual_list_view{}, by_uid_number }, out).has_value());
	CHECK(out.size() == 2);
	out.clear();
	CHECK(ldap::append_controls(
	  ldap::request_controls{ ldap::control{ ldap::sort_request_oid, true, "raw" }, ldap::virtual_list_view{} }, out)
		.has_value());
	// A raw VLV control is not checked.
	out.clear();
	CHECK(ldap::append_controls(ldap::search_controls{ ldap::control{ ldap::vlv_request_oid, false, "raw" } }, out)
		.has_value());
}

// ---------------------------------------------------------------- pre-read / post-read (RFC 4527)

TEST_CASE("pre-read and post-read request controls", "[controls][read_entry]")
{
	const auto pre = ldap::to_control(ldap::pre_read{ .attributes = { "cn", "+" } });
	REQUIRE(pre.has_value());
	CHECK(pre->type == ldap::pre_read_oid);
	CHECK(pre->type == "1.3.6.1.1.13.1");
	CHECK_FALSE(pre->criticality);
	CHECK(value_hex(*pre) == "30 07 04 02 63 6E 04 01 2B");

	const auto post = ldap::to_control(ldap::post_read{ .critical = true });
	REQUIRE(post.has_value());
	CHECK(post->type == ldap::post_read_oid);
	CHECK(post->type == "1.3.6.1.1.13.2");
	CHECK(post->criticality);
	CHECK(value_hex(*post) == "30 00");// empty selection: all user attributes
}

namespace {

auto sample_entry() -> ldap::search_result_entry
{
	return ldap::search_result_entry{ "uid=jdoe,ou=people,dc=example,dc=org",
		{ ldap::partial_attribute{ "cn", { "John Doe" } }, ldap::partial_attribute{ "mail", { "a@x", "b@x" } } } };
}

}// namespace

TEST_CASE("pre-read and post-read response controls", "[controls][read_entry]")
{
	const auto e = sample_entry();
	const auto post = ldap::encode_read_entry(ldap::post_read_oid, e);
	REQUIRE(post.has_value());
	CHECK(post->type == ldap::post_read_oid);
	// The value is a whole SearchResultEntry, [APPLICATION 4].
	CHECK(value_hex(*post).starts_with("64 "));
	CHECK(ldap::decode_read_entry(*post).value() == e);
	const auto pre = ldap::encode_read_entry(ldap::pre_read_oid, e, true);
	REQUIRE(pre.has_value());
	CHECK(pre->criticality);
	CHECK(ldap::decode_read_entry(*pre).value() == e);

	// An entry without attributes: 64 07 04 03 "c=x" 30 00.
	CHECK(ldap::decode_read_entry(with_value(ldap::pre_read_oid, "64 07 04 03 63 3D 78 30 00")).value()
		  == ldap::search_result_entry{ "c=x", {} });
	// Unknown trailing elements in the entry are skipped, as in a message.
	CHECK(ldap::decode_read_entry(with_value(ldap::pre_read_oid, "64 0A 04 03 63 3D 78 30 00 04 01 7A")).value()
		  == ldap::search_result_entry{ "c=x", {} });

	auto wrong = ldap::encode_read_entry("1.2.3", e);
	REQUIRE_FALSE(wrong.has_value());
	CHECK(wrong.error().code == ldap::client_errc::encode_error);
}

TEST_CASE("malformed pre-read and post-read controls", "[controls][read_entry]")
{
	auto code_of = [](const ldap::control &c, const ldap::decode_options &o = {}) {
		auto r = ldap::decode_read_entry(c, o);
		REQUIRE_FALSE(r.has_value());
		return r.error().code;
	};
	CHECK(code_of(ldap::control{ "1.2.3", false, "" }) == ldap::client_errc::decode_error);
	CHECK(code_of(ldap::control{ ldap::post_read_oid }) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::post_read_oid, "")) == ldap::client_errc::decode_error);
	// Not a SearchResultEntry: a plain SEQUENCE, another operation, a primitive [APPLICATION 4].
	CHECK(code_of(with_value(ldap::post_read_oid, "30 07 04 03 63 3D 78 30 00")) == ldap::client_errc::unexpected_tag);
	CHECK(code_of(with_value(ldap::post_read_oid, "65 07 04 03 63 3D 78 30 00")) == ldap::client_errc::unexpected_tag);
	CHECK(code_of(with_value(ldap::post_read_oid, "44 03 63 3D 78")) == ldap::client_errc::unexpected_tag);
	// Truncated, missing the attribute list, trailing bytes, a bad attribute.
	CHECK(code_of(with_value(ldap::post_read_oid, "64 07 04 03 63 3D 78 30")) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::post_read_oid, "64 05 04 03 63 3D 78")) == ldap::client_errc::decode_error);
	CHECK(
	  code_of(with_value(ldap::post_read_oid, "64 07 04 03 63 3D 78 30 00 00 00")) == ldap::client_errc::decode_error);
	CHECK(code_of(with_value(ldap::post_read_oid, "64 0B 04 03 63 3D 78 30 04 30 02 04 00"))
		  == ldap::client_errc::decode_error);
	// Depth and element limits apply.
	const auto big = ldap::encode_read_entry(ldap::pre_read_oid, sample_entry()).value();
	CHECK(code_of(big, { .max_elements = 3 }) == ldap::client_errc::message_too_large);
	CHECK(code_of(big, { .max_depth = 2 }) == ldap::client_errc::nesting_too_deep);
	CHECK(ldap::decode_read_entry(big, { .max_elements = 6 }).has_value());

	CHECK(ldap::decode_read_entry(ldap::control{ "1.2.3" }).error().context
		  == "read entry: control type is 1.2.3, not pre-read or post-read");
	CHECK(
	  ldap::decode_read_entry(ldap::control{ ldap::pre_read_oid }).error().context == "pre-read: control has no value");
	CHECK(ldap::decode_read_entry(with_value(ldap::post_read_oid, "64 07 04 03 63 3D 78 30 00 00 00")).error().context
		  == "post-read: ber: 2 unexpected trailing bytes at offset 9");
	CHECK(ldap::encode_read_entry("1.2.3", sample_entry()).error().context
		  == "read entry control: 1.2.3 is not pre-read or post-read");
}

TEST_CASE("control errors show the control type sanitized", "[controls]")
{
	const std::string fffd = "\xEF\xBF\xBD";// U+FFFD
	// Valid non-ASCII UTF-8 is kept; CR LF, ESC and bidi controls are not.
	const std::string type = "1.2\r\n\x1B\xE2\x80\xAE\xC3\xA9\xE6\x97\xA5";
	const std::string shown = "1.2" + fffd + fffd + fffd + fffd + "\xC3\xA9\xE6\x97\xA5";
	CHECK(std::string(ldap::decode_sort_result(ldap::control{ type }).error().context)
		  == "sort result: control type is " + shown + ", not 1.2.840.113556.1.4.474");
	CHECK(std::string(ldap::decode_read_entry(ldap::control{ type }).error().context)
		  == "read entry: control type is " + shown + ", not pre-read or post-read");
	CHECK(std::string(ldap::encode_read_entry(type, sample_entry()).error().context)
		  == "read entry control: " + shown + " is not pre-read or post-read");
	// Cut at 64 bytes, never inside a character.
	CHECK(std::string(ldap::decode_sort_result(ldap::control{ std::string(63, '1') + "\xC3\xA9" }).error().context)
		  == "sort result: control type is " + std::string(63, '1') + "..., not 1.2.840.113556.1.4.474");
}

TEST_CASE("find_pre_read and find_post_read", "[controls][read_entry]")
{
	const std::pmr::vector<ldap::control> both{ ldap::control{ "1.2.3" },
		*ldap::encode_read_entry(ldap::pre_read_oid, ldap::search_result_entry{ "uid=a", { { "sn", { "Old" } } } }),
		*ldap::encode_read_entry(ldap::post_read_oid, ldap::search_result_entry{ "uid=a", { { "sn", { "New" } } } }) };
	auto pre = ldap::find_pre_read(both);
	REQUIRE(pre.has_value());
	REQUIRE(pre->has_value());
	CHECK((*pre)->dn == "uid=a");
	REQUIRE((*pre)->find("SN") != nullptr);
	CHECK((*pre)->find("SN")->front() == "Old");
	auto post = ldap::find_post_read(both);
	REQUIRE(post.has_value());
	REQUIRE(post->has_value());
	CHECK((*post)->find("sn")->front() == "New");

	const std::pmr::vector<ldap::control> none{ ldap::control{ "1.2.3" } };
	CHECK_FALSE(ldap::find_pre_read(none).value().has_value());
	CHECK_FALSE(ldap::find_post_read(none).value().has_value());

	const std::pmr::vector<ldap::control> bad{ ldap::control{ ldap::post_read_oid, false, "entry" } };
	CHECK_FALSE(ldap::find_pre_read(bad).value().has_value());
	auto b = ldap::find_post_read(bad);
	REQUIRE_FALSE(b.has_value());
	CHECK(b.error().code == ldap::cond::protocol_error);
}

TEST_CASE("new typed controls and their results use the given resource", "[controls][pmr]")
{
	jhetz::ldap::test::counting_resource mr;
	std::pmr::vector<ldap::control> out(&mr);
	REQUIRE(ldap::append_controls(ldap::request_controls{ ldap::server_side_sort{ .keys = { { .attribute = "cn" } } },
									ldap::assertion{ .filter = ldap::filters::attr("cn") == "x" },
									ldap::pre_read{ .attributes = { "cn" } },
									ldap::post_read{} },
	  out)
		.has_value());
	REQUIRE(out.size() == 4);
	for (const auto &c : out) {
		CHECK(c.get_allocator().resource() == &mr);
	}

	jhetz::ldap::test::counting_resource decoded;
	const std::pmr::vector<ldap::control> in{ *ldap::encode_sort_result({ 18, "cn" }),
		*ldap::encode_read_entry(ldap::post_read_oid, sample_entry()) };
	auto s = ldap::find_sort_result(in, &decoded);
	REQUIRE(s.has_value());
	REQUIRE(s->has_value());
	CHECK((*s)->get_allocator().resource() == &decoded);
	auto e = ldap::find_post_read(in, &decoded);
	REQUIRE(e.has_value());
	REQUIRE(e->has_value());
	CHECK((*e)->get_allocator().resource() == &decoded);
	CHECK(decoded.allocations() > 0);
}

// ---------------------------------------------------------------- against OpenLDAP

// Bytes captured between OpenLDAP 2.7's ldapsearch / ldapmodify and slapd
// (sssvlv):
//   ldapsearch -E '!sss=-uidNumber' / -E '!sss=-sn:caseIgnoreOrderingMatch'
//   ldapmodify -e postread=sn,cn (add), -e '!assert=(sn=Ærø)' -e preread=sn -e postread=sn (modify)
namespace {

constexpr const char cap_dn[] = "uid=cap,ou=people,dc=example,dc=org";
constexpr std::string_view cap_dn_hex =
  "75 69 64 3D 63 61 70 2C 6F 75 3D 70 65 6F 70 6C 65 2C 64 63 3D 65 78 61 6D 70 6C "
  "65 2C 64 63 3D 6F 72 67";
constexpr const char aero[] = "\xC3\x86r\xC3\xB8";// Ærø
constexpr const char nihon[] = "\xE6\x97\xA5\xE6\x9C\xAC";// 日本
constexpr const char zoe[] = "Zo\xC3\xAB \xC3\x86r\xC3\xB8";// Zoë Ærø

auto message_hex(const ldap::message &m) -> std::string
{
	auto bytes = ldap::encode(m);
	REQUIRE(bytes.has_value());
	return hex(*bytes);
}

auto decoded(std::string_view message_hex) -> ldap::message
{
	const auto b = from_hex(message_hex);
	auto m = ldap::decode(b);
	REQUIRE(m.has_value());
	return std::move(*m);
}

}// namespace

TEST_CASE("server side sort controls match OpenLDAP", "[controls][sort][openldap]")
{
	const auto desc_uid_number = ldap::to_control(
	  ldap::server_side_sort{ .keys = { { .attribute = "uidNumber", .reverse = true } }, .critical = true });
	REQUIRE(desc_uid_number.has_value());
	CHECK(desc_uid_number->criticality);
	CHECK(value_hex(*desc_uid_number) == "30 10 30 0E 04 09 75 69 64 4E 75 6D 62 65 72 81 01 FF");

	const auto desc_sn = ldap::to_control(ldap::server_side_sort{
	  .keys = { { .attribute = "sn", .ordering_rule = "caseIgnoreOrderingMatch", .reverse = true } },
	  .critical = true });
	REQUIRE(desc_sn.has_value());
	CHECK(value_hex(*desc_sn)
		  == "30 22 30 20 04 02 73 6E 80 17 63 61 73 65 49 67 6E 6F 72 65 4F 72 64 65 72 69 6E 67 4D 61 74 63 68 81 01 "
			 "FF");

	// libldap with two keys (-E '!sss=-uidNumber/sn:2.5.13.3'): the [0] / [1] order within a key.
	const auto two = ldap::to_control(ldap::server_side_sort{
	  .keys = { { .attribute = "uidNumber", .reverse = true }, { .attribute = "sn", .ordering_rule = "2.5.13.3" } } });
	REQUIRE(two.has_value());
	CHECK(value_hex(*two)
		  == "30 20 30 0E 04 09 75 69 64 4E 75 6D 62 65 72 81 01 FF 30 0E 04 02 73 6E 80 08 32 2E 35 2E 31 33 2E 33");

	// slapd's SearchResultDone after a successful sort.
	const auto done = decoded(
	  "30 2F 02 01 02 65 07 0A 01 00 04 00 04 00 A0 21 30 1F 04 16 31 2E 32 2E 38 34 30 2E 31 "
	  "31 33 35 35 36 2E 31 2E 34 2E 34 37 34 04 05 30 03 0A 01 00");
	auto sorted = ldap::find_sort_result(done.controls);
	REQUIRE(sorted.has_value());
	REQUIRE(sorted->has_value());
	CHECK(**sorted == ldap::sort_result{ 0 });
	// ... which is what encode_sort_result produces.
	CHECK(ldap::encode_sort_result(ldap::sort_result{ 0 }).value() == done.controls.at(0));
}

TEST_CASE("virtual list view controls match OpenLDAP", "[controls][vlv][openldap]")
{
	// ldapsearch -E '!sss=uidNumber' -E 'vlv=1/1/5/0': libldap's SearchRequest, byte for byte.
	ldap::message search{ 2,
		ldap::search_request{ "ou=people,dc=example,dc=org",
		  ldap::search_scope::whole_subtree,
		  ldap::filters::attr("objectClass") == "posixAccount",
		  { "uid" } } };
	REQUIRE(ldap::append_controls(
	  ldap::search_controls{ ldap::server_side_sort{ .keys = { { .attribute = "uidNumber" } }, .critical = true },
		ldap::virtual_list_view{ .before_count = 1, .after_count = 1, .target = ldap::vlv_by_offset{ .offset = 5 } } },
	  search.controls)
		.has_value());
	CHECK(message_hex(search)
		  == "30 81 B2 02 01 02 63 50 04 1B 6F 75 3D 70 65 6F 70 6C 65 2C 64 63 3D 65 78 61 6D 70 6C 65 2C 64 63 3D 6F 72"
			 " 67 0A 01 02 0A 01 00 02 01 00 02 01 00 01 01 00 A3 1B 04 0B 6F 62 6A 65 63 74 43 6C 61 73 73 04 0C 70 6F"
			 " 73 69 78 41 63 63 6F 75 6E 74 30 05 04 03 75 69 64"
			 " A0 5B"
			 " 30 2C 04 16 31 2E 32 2E 38 34 30 2E 31 31 33 35 35 36 2E 31 2E 34 2E 34 37 33 01 01 FF"
			 " 04 0F 30 0D 30 0B 04 09 75 69 64 4E 75 6D 62 65 72"
			 " 30 2B 04 17 32 2E 31 36 2E 38 34 30 2E 31 2E 31 31 33 37 33 30 2E 33 2E 34 2E 39"
			 " 04 10 30 0E 02 01 01 02 01 01 A0 06 02 01 05 02 01 00");

	// slapd's SearchResultDone: the sort result, then the VLV response.
	const auto done = decoded(
	  "30 63 02 01 02 65 07 0A 01 00 04 00 04 00 A0 55 30 1F 04 16 31 2E 32 2E 38 34 30 2E 31 31 33 35 35 36 2E 31 2E"
	  " 34 2E 34 37 34 04 05 30 03 0A 01 00 30 32 04 18 32 2E 31 36 2E 38 34 30 2E 31 2E 31 31 33 37 33 30 2E 33 2E 34"
	  " 2E 31 30 04 16 30 14 02 01 05 02 02 00 FA 0A 01 00 04 08 A0 1D 00 78 F7 7F 00 00");
	auto sorted = ldap::find_sort_result(done.controls);
	REQUIRE(sorted.has_value());
	REQUIRE(sorted->has_value());
	CHECK((*sorted)->is_success());
	auto window = ldap::find_vlv_response(done.controls);
	REQUIRE(window.has_value());
	REQUIRE(window->has_value());
	CHECK(**window == ldap::vlv_response{ 5, 250, 0, sssvlv_context() });
	CHECK(ldap::encode_vlv_response(**window).value() == done.controls.at(1));
}

TEST_CASE("assertion and pre/post-read controls match OpenLDAP", "[controls][assertion][read_entry][openldap]")
{
	// ldapmodify's ModifyRequest, byte for byte.
	ldap::message modify{ 2,
		ldap::modify_request{ cap_dn,
		  { ldap::modify_change{ ldap::modify_operation::replace, ldap::partial_attribute{ "sn", { nihon } } } } } };
	REQUIRE(ldap::append_controls(ldap::modify_controls{ ldap::assertion{ .filter = ldap::filters::attr("sn") == aero },
									ldap::pre_read{ .attributes = { "sn" } },
									ldap::post_read{ .attributes = { "sn" } } },
	  modify.controls)
		.has_value());
	CHECK(message_hex(modify)
		  == "30 81 99 02 01 02 66 3C 04 23 " + std::string(cap_dn_hex)
			   + " 30 15 30 13 0A 01 02 30 0E 04 02 73 6E 31 08 04 06 E6 97 A5 E6 9C AC"
				 " A0 56"
				 " 30 20 04 0C 31 2E 33 2E 36 2E 31 2E 31 2E 31 32 01 01 FF 04 0D A3 0B 04 02 73 6E 04 05 C3 86 72 C3 B8"
				 " 30 18 04 0E 31 2E 33 2E 36 2E 31 2E 31 2E 31 33 2E 31 04 06 30 04 04 02 73 6E"
				 " 30 18 04 0E 31 2E 33 2E 36 2E 31 2E 31 2E 31 33 2E 32 04 06 30 04 04 02 73 6E");

	// slapd's ModifyResponse: the entry before and after, UTF-8 values intact.
	const auto response = decoded("30 81 A8 02 01 02 67 07 0A 01 00 04 00 04 00 A0 81 99"
								  " 30 4A 04 0E 31 2E 33 2E 36 2E 31 2E 31 2E 31 33 2E 31 04 38 64 36 04 23 "
								  + std::string(cap_dn_hex)
								  + " 30 0F 30 0D 04 02 73 6E 31 07 04 05 C3 86 72 C3 B8"
									" 30 4B 04 0E 31 2E 33 2E 36 2E 31 2E 31 2E 31 33 2E 32 04 39 64 37 04 23 "
								  + std::string(cap_dn_hex) + " 30 10 30 0E 04 02 73 6E 31 08 04 06 E6 97 A5 E6 9C AC");
	auto before = ldap::find_pre_read(response.controls);
	REQUIRE(before.has_value());
	REQUIRE(before->has_value());
	CHECK((*before)->dn == cap_dn);
	CHECK(*(*before)->find("sn") == ldap::string_list{ aero });
	auto after = ldap::find_post_read(response.controls);
	REQUIRE(after.has_value());
	REQUIRE(after->has_value());
	CHECK(*(*after)->find("sn") == ldap::string_list{ nihon });
	// encode_read_entry gives slapd's control values back.
	CHECK(
	  ldap::encode_read_entry(ldap::pre_read_oid, ldap::search_result_entry{ cap_dn, { { "sn", { aero } } } }).value()
	  == response.controls.at(0));
	CHECK(
	  ldap::encode_read_entry(ldap::post_read_oid, ldap::search_result_entry{ cap_dn, { { "sn", { nihon } } } }).value()
	  == response.controls.at(1));

	// The add's post-read (two attributes, in the server's order).
	const auto add_selection = ldap::to_control(ldap::post_read{ .attributes = { "sn", "cn" } });
	REQUIRE(add_selection.has_value());
	CHECK(value_hex(*add_selection) == "30 08 04 02 73 6E 04 02 63 6E");
	const auto added = decoded("30 6E 02 01 02 69 07 0A 01 00 04 00 04 00 A0 60 30 5E 04 0E 31 2E 33 2E 36 2E 31 2E 31 "
							   "2E 31 33 2E 32 04 4C 64 4A 04 23 "
							   + std::string(cap_dn_hex)
							   + " 30 23 30 12 04 02 63 6E 31 0C 04 0A 5A 6F C3 AB 20 C3 86 72 C3 B8"
								 " 30 0D 04 02 73 6E 31 07 04 05 C3 86 72 C3 B8");
	auto stored = ldap::find_post_read(added.controls);
	REQUIRE(stored.has_value());
	REQUIRE(stored->has_value());
	CHECK(*(*stored)->find("cn") == ldap::string_list{ zoe });
	CHECK(*(*stored)->find("sn") == ldap::string_list{ aero });

	// slapd's answer to a false assertion: resultCode 122.
	const auto refused = decoded("30 0C 02 01 02 67 07 0A 01 7A 04 00 04 00");
	CHECK(std::get<ldap::modify_response>(refused.op).result.to_error().code == ldap::errc::assertion_failed);
}

// ---------------------------------------------------------------- transaction specification (RFC 5805)

static_assert(
  applies_to<ldap::transaction_specification>(add) && applies_to<ldap::transaction_specification>(modify)
  && applies_to<ldap::transaction_specification>(modify_dn) && applies_to<ldap::transaction_specification>(del)
  && !applies_to<ldap::transaction_specification>(search) && !applies_to<ldap::transaction_specification>(compare)
  && !applies_to<ldap::transaction_specification>(extended));
static_assert(!std::is_convertible_v<ldap::transaction_specification, ldap::extended_controls::value_type>);

TEST_CASE("transaction specification control", "[controls][transaction]")
{
	// Always critical; the value is the identifier itself (RFC 5805 section 2.2).
	const auto c = ldap::to_control(ldap::transaction_specification{ .identifier = std::string("t\0x", 3) });
	REQUIRE(c.has_value());
	CHECK(*c == ldap::control{ "1.3.6.1.1.21.2", true, std::string_view("t\0x", 3) });
	CHECK(ldap::decode_transaction_specification(*c)
		  == ldap::transaction_specification{ .identifier = std::string("t\0x", 3) });

	const auto context_of = [](const ldap::control &bad) {
		auto r = ldap::decode_transaction_specification(bad);
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
		return std::string(r.error().context);
	};
	CHECK(context_of(ldap::control{ ldap::transaction_specification_oid, false, "t" })
		  == "transaction specification: control is not critical (RFC 5805 section 2.2)");
	CHECK(context_of(ldap::control{ ldap::transaction_specification_oid, true })
		  == "transaction specification: control has no value");
	CHECK(context_of(ldap::control{ "1.2.3", true, "t" })
		  == "transaction specification: control type is 1.2.3, not 1.3.6.1.1.21.2");

	// The shared list converts for an update only.
	const ldap::request_controls shared{ ldap::transaction_specification{ .identifier = "t" } };
	CHECK(ldap::controls_for<ldap::del_controls>(shared).has_value());
	const auto on_search = ldap::controls_for<ldap::search_controls>(shared);
	REQUIRE_FALSE(on_search.has_value());
	CHECK(on_search.error().context == "transaction_specification is not valid on search (RFC 5805 section 2.2)");
}

TEST_CASE("transaction specification refuses proxied authorization (RFC 5805 section 4.4)", "[controls][transaction]")
{
	constexpr std::string_view refused =
	  "proxied_authorization is not valid on an update in a transaction: put it on "
	  "the Start Transaction request (RFC 5805 section 4.4)";
	const auto encoded = [](const ldap::modify_controls &list) {
		std::pmr::vector<ldap::control> wire;
		return ldap::append_controls(list, wire);
	};
	const ldap::transaction_specification spec{ .identifier = "t" };
	const auto typed = encoded({ spec, ldap::proxied_authorization{ "u:jdoe" } });
	REQUIRE_FALSE(typed.has_value());
	CHECK(typed.error().code == ldap::client_errc::encode_error);
	CHECK(typed.error().context == refused);
	// A raw proxied authorization control counts, before or after.
	const auto raw = encoded({ ldap::control{ ldap::proxied_authorization_oid, true, "u:jdoe" }, spec });
	REQUIRE_FALSE(raw.has_value());
	CHECK(raw.error().context == refused);
	// Each alone is fine; so is a raw transaction specification (unchecked,
	// like every raw control).
	CHECK(encoded({ spec, ldap::assertion{ .filter = ldap::filters::attr("cn") == "x" } }).has_value());
	CHECK(encoded({ ldap::proxied_authorization{ "u:jdoe" } }).has_value());
	CHECK(encoded(
	  { ldap::control{ ldap::transaction_specification_oid, true, "t" }, ldap::proxied_authorization{ "u:jdoe" } })
		.has_value());
}
