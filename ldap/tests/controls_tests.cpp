#include "jhetz/ldap/controls.hpp"

#include "counting_resource.hpp"
#include "test_util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ldap = jhetz::ldap;
using jhetz::ldap::test::from_hex;
using jhetz::ldap::test::hex;

namespace {

std::string value_hex(const ldap::control &c)
{
	REQUIRE(c.value.has_value());
	return hex(std::as_bytes(std::span(*c.value)));
}

// A control whose value is the given hex bytes.
ldap::control with_value(std::string_view oid, std::string_view hex_value)
{
	const auto b = from_hex(hex_value);
	return ldap::control{ oid, false, std::string_view(reinterpret_cast<const char *>(b.data()), b.size()) };
}

}// namespace

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
	const auto ok = ldap::encode_sort_result({ 0 });
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

ldap::search_result_entry sample_entry()
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
	REQUIRE(ldap::append_controls({ ldap::server_side_sort{ .keys = { { .attribute = "cn" } } },
									ldap::assertion{ .filter = ldap::filters::attr("cn") == "x" },
									ldap::pre_read{ .attributes = { "cn" } },
									ldap::post_read{} },
	  out)
			  .has_value());
	REQUIRE(out.size() == 4);
	for (const auto &c : out) CHECK(c.get_allocator().resource() == &mr);

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
// (with the sssvlv overlay) through a logging TCP proxy:
//   ldapsearch -E '!sss=-uidNumber' / -E '!sss=-sn:caseIgnoreOrderingMatch'
//   ldapmodify -e postread=sn,cn (add), -e '!assert=(sn=Ærø)' -e preread=sn -e postread=sn (modify)
// The values are UTF-8 (sn "Ærø", then "日本"; cn "Zoë Ærø").
namespace {

constexpr const char cap_dn[] = "uid=cap,ou=people,dc=example,dc=org";
constexpr std::string_view cap_dn_hex =
  "75 69 64 3D 63 61 70 2C 6F 75 3D 70 65 6F 70 6C 65 2C 64 63 3D 65 78 61 6D 70 6C "
  "65 2C 64 63 3D 6F 72 67";
constexpr const char aero[] = "\xC3\x86r\xC3\xB8";// Ærø
constexpr const char nihon[] = "\xE6\x97\xA5\xE6\x9C\xAC";// 日本
constexpr const char zoe[] = "Zo\xC3\xAB \xC3\x86r\xC3\xB8";// Zoë Ærø

std::string message_hex(const ldap::message &m)
{
	auto bytes = ldap::encode(m);
	REQUIRE(bytes.has_value());
	return hex(*bytes);
}

ldap::message decoded(std::string_view message_hex)
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
	CHECK(ldap::encode_sort_result({ 0 }).value() == done.controls.at(0));
}

TEST_CASE("assertion and pre/post-read controls match OpenLDAP", "[controls][assertion][read_entry][openldap]")
{
	// ldapmodify's ModifyRequest, byte for byte.
	ldap::message modify{ 2,
		ldap::modify_request{ cap_dn,
		  { ldap::modify_change{ ldap::modify_operation::replace, ldap::partial_attribute{ "sn", { nihon } } } } } };
	REQUIRE(ldap::append_controls({ ldap::assertion{ .filter = ldap::filters::attr("sn") == aero },
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
