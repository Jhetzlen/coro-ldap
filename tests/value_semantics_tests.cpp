// Value semantics of the allocator-aware types: value_semantics.hpp's checks
// on a sample of each.
#include "counting_resource.hpp"
#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/url.hpp"
#include "test_util.hpp"
#include "value_semantics.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <memory_resource>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
using jhetz::ldap::test::check_value_semantics;
using jhetz::ldap::test::counting_resource;
using jhetz::ldap::test::hex;
using jhetz::ldap::test::mr;
using jhetz::ldap::test::resources;

namespace {

const std::string_view long_dn = "uid=a-user-with-a-long-name,ou=people,dc=example,dc=org";
const std::string_view long_value = "a value long enough to allocate";

auto sample_result() -> ldap::ldap_result
{
	return { 32, long_dn, "a diagnostic message long enough", { "ldap://referral.example.org/dc=example,dc=org" } };
}

auto sample_control() -> ldap::control { return { "1.2.840.113556.1.4.319", true, long_value }; }

auto sample_sasl() -> ldap::sasl_auth { return { "SCRAM-SHA-256-PLUS-LONG", "n,,n=user,r=a-long-client-nonce" }; }

auto sample_modify_dn() -> ldap::modify_dn_request
{
	return { long_dn, "uid=a-new-rdn-long-enough", false, "ou=a-new-superior,dc=example,dc=org" };
}

auto result_members(const ldap::ldap_result &r) -> resources
{
	return { mr(r.diagnostic_message), r.referral.get_allocator().resource(), mr(r.referral.at(0)) };
}

}// namespace

TEST_CASE("value semantics: shared parts", "[value_semantics][message]")
{
	check_value_semantics(sample_result(), result_members);
	check_value_semantics(sample_control(), [](const ldap::control &c) { return resources{ mr(c.value.value()) }; });
	check_value_semantics(ldap::partial_attribute{ "a-long-attribute-type", { long_value, "another long value" } },
	  [](const ldap::partial_attribute &p) { return resources{ mr(p.values.at(1)) }; });
	check_value_semantics(ldap::attribute_value_assertion{ "a-long-attribute-description", long_value },
	  [](const ldap::attribute_value_assertion &x) { return resources{ mr(x.assertion_value) }; });
	check_value_semantics(
	  ldap::del_response{ sample_result() }, [](const ldap::del_response &r) { return result_members(r.result); });
}

TEST_CASE("value semantics: bind", "[value_semantics][message]")
{
	const ldap::sasl_auth mechanism_only("SCRAM-SHA-256-PLUS-LONG");
	CHECK(mechanism_only.mechanism == "SCRAM-SHA-256-PLUS-LONG");
	CHECK_FALSE(mechanism_only.credentials.has_value());
	check_value_semantics(ldap::simple_auth{ "a password long enough to allocate" });
	check_value_semantics(
	  sample_sasl(), [](const ldap::sasl_auth &s) { return resources{ mr(s.credentials.value()) }; });
	const auto bind_members = [](const ldap::bind_request &r) {
		resources out{ mr(r.name) };
		if (const auto *s = std::get_if<ldap::sasl_auth>(&r.authentication)) {
			out.push_back(mr(s->mechanism));
			if (s->credentials) {
				out.push_back(mr(*s->credentials));
			}
		} else {
			out.push_back(mr(std::get<ldap::simple_auth>(r.authentication).password));
		}
		return out;
	};
	check_value_semantics(ldap::bind_request{ 3, long_dn, sample_sasl() }, bind_members);
	check_value_semantics(ldap::bind_request{ 3, long_dn, ldap::simple_auth{ long_value } }, bind_members);
	check_value_semantics(
	  ldap::bind_response{ sample_result(), "server-sasl-credentials-long-enough" }, [](const ldap::bind_response &r) {
		  auto out = result_members(r.result);
		  out.push_back(mr(r.server_sasl_creds.value()));
		  return out;
	  });
}

TEST_CASE("value semantics: search", "[value_semantics][message]")
{
	check_value_semantics(ldap::search_request{ long_dn,
							ldap::search_scope::whole_subtree,
							ldap::filters::attr("uid") == long_value,
							{ "a-long-attribute-name", "another-long-attribute" } },
	  [](const ldap::search_request &r) {
		  return resources{ r.filter.get_allocator().resource(), mr(r.attributes.at(1)) };
	  });
	check_value_semantics(ldap::search_result_entry{ long_dn, { { "a-long-attribute-type", { long_value } } } },
	  [](const ldap::search_result_entry &e) {
		  return resources{ mr(e.attributes.at(0).type), mr(e.attributes.at(0).values.at(0)) };
	  });
	check_value_semantics(ldap::search_result_reference{ ldap::string_list{ "ldap://a-long-host.example.org/" } },
	  [](const ldap::search_result_reference &r) { return resources{ mr(r.uris.at(0)) }; });
	check_value_semantics(ldap::search_result_done{ sample_result() });
}

TEST_CASE("value semantics: update operations", "[value_semantics][message]")
{
	const ldap::modify_change change{ ldap::modify_operation::replace, { "a-long-attribute-type", { long_value } } };
	check_value_semantics(
	  change, [](const ldap::modify_change &c) { return resources{ mr(c.modification.values.at(0)) }; });
	check_value_semantics(ldap::modify_request{ long_dn, { change } },
	  [](const ldap::modify_request &r) { return resources{ mr(r.changes.at(0).modification.type) }; });
	check_value_semantics(ldap::add_request{ long_dn, { { "a-long-attribute-type", { long_value } } } },
	  [](const ldap::add_request &r) { return resources{ mr(r.attributes.at(0).values.at(0)) }; });
	const ldap::modify_request no_changes(long_dn);
	CHECK(no_changes.object == long_dn);
	CHECK(no_changes.changes.empty());
	const ldap::add_request no_attributes(long_dn);
	CHECK(no_attributes.entry == long_dn);
	CHECK(no_attributes.attributes.empty());
	check_value_semantics(ldap::del_request{ long_dn });
	check_value_semantics(sample_modify_dn(),
	  [](const ldap::modify_dn_request &r) { return resources{ mr(r.new_rdn), mr(r.new_superior.value()) }; });
	check_value_semantics(ldap::compare_request{ long_dn, { "a-long-attribute-description", long_value } },
	  [](const ldap::compare_request &r) { return resources{ mr(r.ava.attribute_desc), mr(r.ava.assertion_value) }; });
	check_value_semantics(ldap::modify_dn_response{ sample_result() });
}

TEST_CASE("value semantics: extended and intermediate", "[value_semantics][message]")
{
	check_value_semantics(ldap::extended_request{ ldap::start_tls_oid, long_value },
	  [](const ldap::extended_request &r) { return resources{ mr(r.request_value.value()) }; });
	check_value_semantics(ldap::extended_response{ sample_result(), ldap::notice_of_disconnection_oid, long_value },
	  [](const ldap::extended_response &r) {
		  return resources{ mr(r.response_name.value()), mr(r.response_value.value()) };
	  });
	check_value_semantics(
	  ldap::intermediate_response{ "1.3.6.1.4.1.4203.1.9.1.4", long_value }, [](const ldap::intermediate_response &r) {
		  return resources{ mr(r.response_name.value()), mr(r.response_value.value()) };
	  });
}

TEST_CASE("value semantics: message and controls", "[value_semantics][message]")
{
	const auto message_members = [](const ldap::message &m) {
		resources out{ std::visit(
		  [](const auto &op) -> std::pmr::memory_resource * {
			  if constexpr (requires { op.get_allocator(); }) {
				  return op.get_allocator().resource();
			  } else {
				  return nullptr;
			  }
		  },
		  m.op) };
		for (const auto &c : m.controls) {
			out.push_back(mr(c.type));
			if (c.value) {
				out.push_back(mr(*c.value));
			}
		}
		return out;
	};
	check_value_semantics(ldap::message{ 7, sample_modify_dn(), { sample_control() } }, message_members);
	check_value_semantics(
	  ldap::message{ 8, ldap::extended_request{ ldap::start_tls_oid, long_value } }, message_members);
	check_value_semantics(ldap::paged_results{ 500, "a-paged-results-cookie-long-enough" });
	check_value_semantics(ldap::sort_result{ 16, "a-long-attribute-type-name" });
}

TEST_CASE("value semantics: entry and attribute_values", "[value_semantics][attribute]")
{
	const ldap::attribute_values values(ldap::attribute("description"), { long_value, "another long value" });
	CHECK(values.type.name() == "description");
	REQUIRE(values.values.size() == 2);
	CHECK(values.values[1] == "another long value");
	{
		counting_resource arena;
		const ldap::attribute_values on_arena(
		  ldap::attribute("description"), { long_value }, ldap::attribute_values::allocator_type(&arena));
		CHECK(on_arena.get_allocator().resource() == &arena);
		CHECK(on_arena.type.get_allocator().resource() == &arena);
		CHECK(mr(on_arena.values.at(0)) == &arena);
	}
	check_value_semantics(values, [](const ldap::attribute_values &v) {
		return resources{ v.type.get_allocator().resource(), mr(v.values.at(1)) };
	});

	ldap::entry e;
	e.dn = long_dn;
	e.attributes.push_back(values);
	check_value_semantics(e, [](const ldap::entry &x) {
		return resources{ x.attributes.at(0).get_allocator().resource(), mr(x.attributes.at(0).values.at(0)) };
	});
}

TEST_CASE("value semantics: url_extension and url", "[value_semantics][url]")
{
	check_value_semantics(ldap::url_extension{ "a-long-extension-type", long_value, true },
	  [](const ldap::url_extension &x) { return resources{ mr(x.value.value()) }; });

	// Self-assignment leaves the extension as it was.
	ldap::url_extension x{ "a-long-extension-type", long_value, true };
	const ldap::url_extension &alias = x;
	x = alias;
	CHECK(x == ldap::url_extension{ "a-long-extension-type", long_value, true });
	ldap::url_extension &same = x;
	x = std::move(same);
	CHECK(x == ldap::url_extension{ "a-long-extension-type", long_value, true });

	// An extension without a value resets the target's value.
	x = ldap::url_extension{ "bindname" };
	CHECK_FALSE(x.value.has_value());
	x = ldap::url_extension{ "a-long-extension-type", long_value, true };
	ldap::url_extension no_value{ "bindname" };
	x = std::move(no_value);
	CHECK_FALSE(x.value.has_value());
	CHECK(x.type == "bindname");
	x = ldap::url_extension{ "a-long-extension-type", long_value, true };
	const ldap::url_extension bare{ "bindname" };
	x = bare;
	CHECK(x == bare);

	const auto u = ldap::url::parse(
	  "ldap://a-long-host-name.example.org:389/dc=example,dc=org?cn,mail?sub?(uid=someone)?!bindname=cn=manager");
	REQUIRE(u.has_value());
	// Self-move-assignment leaves the URL as it was.
	ldap::url same_url = *u;
	ldap::url &alias_url = same_url;
	same_url = std::move(alias_url);
	CHECK(same_url == *u);
	check_value_semantics(*u, [](const ldap::url &v) {
		resources out{ v.base_dn().value().get_allocator().resource(),
			v.search_filter().value().get_allocator().resource() };
		for (const auto &ext : v.extensions()) {
			out.push_back(ext.get_allocator().resource());
		}
		return out;
	});
}

TEST_CASE("value semantics: ber::writer", "[value_semantics][ber]")
{
	counting_resource ra;
	counting_resource rb;
	const ldap::ber::writer::allocator_type a(&ra);
	const ldap::ber::writer::allocator_type b(&rb);
	ldap::ber::writer w(a);
	w.octet_string(std::string(100, 'x'));
	const auto expected = hex(w.bytes());

	const ldap::ber::writer copy(w, b);
	CHECK(hex(copy.bytes()) == expected);
	CHECK(copy.get_allocator().resource() == &rb);

	ldap::ber::writer tmp(w, a);
	const ldap::ber::writer moved_same(std::move(tmp), a);
	CHECK(hex(moved_same.bytes()) == expected);
	CHECK(moved_same.get_allocator().resource() == &ra);

	ldap::ber::writer tmp2(w, a);
	const ldap::ber::writer moved_other(std::move(tmp2), b);
	CHECK(hex(moved_other.bytes()) == expected);
	CHECK(moved_other.get_allocator().resource() == &rb);

	ldap::ber::writer target(b);
	target = w;
	CHECK(hex(target.bytes()) == expected);
	CHECK(target.get_allocator().resource() == &rb);
	const ldap::ber::writer &alias = target;
	target = alias;// self-assignment keeps the bytes
	CHECK(hex(target.bytes()) == expected);
	CHECK(target.get_allocator().resource() == &rb);
	ldap::ber::writer source(w, a);
	ldap::ber::writer target2(b);
	target2 = std::move(source);
	CHECK(hex(target2.bytes()) == expected);
	CHECK(target2.get_allocator().resource() == &rb);
	// Checks the moved-from state on purpose: cleared, still usable.
	// NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
	CHECK(source.bytes().empty());
	CHECK(source.get_allocator().resource() == &ra);
}

TEST_CASE("ber::universal builds universal tags at run time", "[value_semantics][ber]")
{
	std::uint8_t number = 16;// not a constant expression
	CHECK(ldap::ber::universal(number, true) == ldap::ber::tags::sequence);
	number = 4;
	CHECK(ldap::ber::universal(number) == ldap::ber::tags::octet_string);
	number = 31;
	CHECK_THROWS_AS(ldap::ber::universal(number), std::invalid_argument);
}

TEST_CASE("filter iterators: postfix increment", "[value_semantics][filter]")
{
	const auto f = ldap::filter::raw("(&(a=1)(b=2)(c=3))");
	REQUIRE(f.has_value());
	const auto children = f->root().children();
	auto it = children.begin();
	const auto old = it++;
	CHECK((*old).attribute() == "a");
	CHECK((*it).attribute() == "b");
	it++;
	CHECK((*it).attribute() == "c");
	it++;
	CHECK(it == children.end());

	const auto s = ldap::filter::raw("(cn=init*x*y*fin)");
	REQUIRE(s.has_value());
	const auto any = s->root().any();
	auto si = any.begin();
	const auto sold = si++;
	CHECK(*sold == "x");
	CHECK(*si == "y");
	si++;
	CHECK(si == any.end());
}

namespace {

// Self-move-assignment leaves `sample` as it was.
template<class T> void check_self_move(const T &sample)
{
	T x = sample;
	T &same = x;
	x = std::move(same);
	CHECK(x == sample);
}

}// namespace

TEST_CASE("value semantics: ava and attribute", "[value_semantics][dn][attribute]")
{
	check_value_semantics(ldap::ava{ ldap::attribute{ "a-long-attribute-type-name" }, long_value },
	  [](const ldap::ava &x) { return resources{ x.type.get_allocator().resource(), mr(x.value) }; });
	CHECK(ldap::attribute{}.empty());
	CHECK_FALSE(ldap::attribute{ "cn" }.empty());
}

TEST_CASE("value semantics: content synchronization", "[value_semantics][content_sync]")
{
	ldap::sync_uuid uuid;
	uuid.bytes[0] = std::byte{ 0x12 };
	const std::string_view cookie = "rid=001,csn=20261104120000.000000Z#000000#000#000000";
	check_value_semantics(ldap::sync_state{ ldap::sync_state_type::modify, uuid, cookie },
	  [](const ldap::sync_state &x) { return resources{ mr(x.cookie.value()) }; });
	check_value_semantics(
	  ldap::sync_done{ cookie, true }, [](const ldap::sync_done &x) { return resources{ mr(x.cookie.value()) }; });
	ldap::sync_info info{ ldap::sync_info_type::sync_id_set, cookie };
	info.refresh_deletes = true;
	info.sync_uuids = { uuid, ldap::sync_uuid{} };
	check_value_semantics(info, [](const ldap::sync_info &x) { return resources{ mr(x.cookie.value()) }; });
	check_self_move(ldap::sync_state{ ldap::sync_state_type::modify, uuid, cookie });
	check_self_move(ldap::sync_done{ cookie, true });
	check_self_move(info);
}

TEST_CASE("value semantics: virtual list view and transactions", "[value_semantics][message]")
{
	check_value_semantics(ldap::vlv_response{ 3, 120, 0, "a-context-id-long-enough-to-allocate" },
	  [](const ldap::vlv_response &x) { return resources{ mr(x.context_id.value()) }; });
	check_self_move(ldap::vlv_response{ 3, 120, 0, "a-context-id-long-enough-to-allocate" });
	check_value_semantics(ldap::end_transaction_request{ false, "a-transaction-identifier-long-enough" },
	  [](const ldap::end_transaction_request &x) { return resources{ mr(x.identifier) }; });
	const ldap::update_controls updates{ 7, { sample_control() } };
	check_value_semantics(
	  updates, [](const ldap::update_controls &x) { return resources{ mr(x.controls.at(0).value.value()) }; });
	check_value_semantics(
	  ldap::end_transaction_response{ 9, { updates } }, [](const ldap::end_transaction_response &x) {
		  return resources{ x.updates_controls.at(0).get_allocator().resource(),
			  mr(x.updates_controls.at(0).controls.at(0).type) };
	  });
}

TEST_CASE("value semantics: intermediate", "[value_semantics][message]")
{
	check_value_semantics(
	  ldap::intermediate{ ldap::intermediate_response{ "1.3.6.1.4.1.4203.1.9.1.4", long_value }, { sample_control() } },
	  [](const ldap::intermediate &x) { return resources{ mr(x.response_value.value()), mr(x.controls.at(0).type) }; });
}
