// Messages covering every protocolOp alternative with optional fields both set
// and unset. Shared by the unit tests and message_fuzz_replay (seed inputs).
#pragma once

#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::test {

inline auto sample_result() -> ldap_result
{
	return { 32, "dc=example,dc=org", "no such entry", { "ldap://a.example.org/", "ldap://b.example.org/" } };
}

inline auto raw_filter(std::string_view text) -> filter { return filter::raw(text).value(); }

// A syncUUID of distinct octets.
inline auto sample_uuid() -> sync_uuid
{
	sync_uuid u;
	for (std::size_t i = 0; i < u.bytes.size(); ++i) {
		u.bytes[i] = static_cast<std::byte>(0xA0 + i);
	}
	return u;
}

inline auto sample_refresh_present() -> sync_info
{
	sync_info out{ sync_info_type::refresh_present, "rid=000,csn=2" };
	out.refresh_done = false;
	return out;
}

inline auto sample_sync_id_set() -> sync_info
{
	sync_info out{ sync_info_type::sync_id_set };
	out.refresh_deletes = true;
	out.sync_uuids = { sample_uuid(), sync_uuid{} };
	return out;
}

inline auto sample_messages() -> std::vector<message>
{
	using namespace std::string_literals;
	const std::string_view dn = "uid=jdoe,ou=people,dc=example,dc=org";
	search_request typed_only{ "", search_scope::subordinate_subtree, raw_filter(R"((bin=\00\ff\2a))"), { "*", "+" } };
	typed_only.deref = deref_aliases::always;
	typed_only.size_limit = max_int;
	typed_only.time_limit = max_int;
	typed_only.types_only = true;
	search_request people{ "ou=people,dc=example,dc=org",
		search_scope::whole_subtree,
		raw_filter("(&(objectClass=person)(|(uid=jdoe)(mail=j*@*.org))(!(disabled=TRUE))"
				   "(cn:dn:2.5.13.5:=x\\2ay)(sn~=smith)(uidNumber>=1000)(uidNumber<=2000)(&)(|))"),
		{ "uid", "mail", "cn;lang-en", "1.3.6.1.4.1.1466.101.120.16" } };
	people.deref = deref_aliases::finding_base_obj;
	people.size_limit = 500;
	people.time_limit = 30;
	std::vector<protocol_op> ops{
		bind_request{ 3, dn, simple_auth{ "secret" } },
		bind_request{ 2, "", simple_auth{ "" } },
		bind_request{ 3, "", sasl_auth{ "EXTERNAL", {} } },
		bind_request{ 127, "", sasl_auth{ "GSSAPI", "\0\x01\xff"s } },
		bind_response{},
		bind_response{ ldap_result{ 14 }, "\x60\x82"s },
		bind_response{ sample_result(), ""s },
		unbind_request{},
		std::move(people),
		search_request{},
		typed_only,
		search_result_entry{},
		search_result_entry{ dn,
		  { { "cn", { "John", "Johnny" } },
			{ "jpegPhoto", { "\xff\xd8\0"s } },
			{ "empty", {} },
			{ "member;range=0-*", { "cn=a" } } } },
		search_result_done{},
		search_result_done{ sample_result() },
		search_result_reference{ { "ldap://a.example.org/dc=x", "ldap://b.example.org/dc=x??sub" } },
		search_result_reference{ { "ldap://c.example.org/" } },
		modify_request{ dn,
		  { { modify_operation::add, { "mail", { "a@x", "b@x" } } },
			{ modify_operation::delete_, { "phone", {} } },
			{ modify_operation::replace, { "sn", { "Doe" } } },
			{ modify_operation::increment, { "uidNumber", { "1" } } } } },
		modify_request{},
		modify_response{ sample_result() },
		add_request{ dn, { { "objectClass", { "top", "person" } }, { "cn", { "J" } } } },
		add_response{},
		del_request{ dn },
		del_request{},
		del_response{ sample_result() },
		modify_dn_request{ dn, "uid=john", true, "ou=x" },
		modify_dn_request{ dn, "uid=john", false },
		modify_dn_response{},
		compare_request{ dn, { "userPassword", "\0secret"s } },
		compare_response{ ldap_result{ 6 } },
		abandon_request{ 0 },
		abandon_request{ max_int },
		extended_request{ start_tls_oid, {} },
		extended_request{ "1.3.6.1.4.1.4203.1.11.1", "\x30\x00"s },
		extended_response{},
		extended_response{ sample_result(), "1.2.3", "v" },
		extended_response{ ldap_result{ 4711 }, {}, ""s },
		intermediate_response{},
		intermediate_response{ "1.2.3" },
		intermediate_response{ {}, "\x01"s },
		intermediate_response{ "1.2.3", "v" },
		// RFC 4533's Sync Info Messages, one per alternative.
		testing::encode_sync_info(sync_info{ sync_info_type::new_cookie, "rid=000,csn=1" }).value(),
		testing::encode_sync_info(sync_info{ sync_info_type::refresh_delete }).value(),
		testing::encode_sync_info(sample_refresh_present()).value(),
		testing::encode_sync_info(sample_sync_id_set()).value(),
		// RFC 5805's End Transaction request and response values.
		extended_request{ end_transaction_oid, encode_end_transaction_request({ false, "txn" }) },
		extended_response{ ldap_result{ 68 },
		  {},
		  testing::encode_end_transaction_response(
			end_transaction_response{ 3, { update_controls{ 2, { control{ "1.2.3", false, "v" } } } } })
			.value() },
	};
	std::vector<message> out;
	out.reserve(ops.size() + 2);
	std::int32_t id = 1;
	for (auto &op : ops) {
		out.emplace_back(id++, std::move(op));
	}
	out.emplace_back(0, extended_response{ {}, notice_of_disconnection_oid });
	out.emplace_back(max_int, unbind_request{});
	return out;
}

inline auto sample_controls() -> std::pmr::vector<control>
{
	return { encode_paged_results({ 100, "\x01\x02" }, true).value(),
		control{ "1.2.840.113556.1.4.805" },
		control{ "1.2.3.4", true, "" },
		testing::encode_sort_result({ 18, "cn" }).value(),
		testing::encode_read_entry(post_read_oid, search_result_entry{ "cn=x", { { "cn", { "x", "y" } } } }).value(),
		encode_sync_request(sync_request{ .mode = sync_mode::refresh_and_persist, .cookie = "c", .reload_hint = true })
		  .value(),
		testing::encode_sync_state(sync_state{ sync_state_type::modify, sample_uuid(), "c" }).value(),
		testing::encode_sync_done(sync_done{ "c", true }).value(),
		to_control(matched_values{ .values_return_filter = { filters::attr("mail").ends_with("@example.org"),
									 raw_filter("(cn:caseExactMatch:=x)") } })
		  .value(),
		to_control(virtual_list_view{ .before_count = 9,
					 .after_count = 10,
					 .target = vlv_by_offset{ .offset = 53424, .content_count = 78564 },
					 .context_id = "c" })
		  .value(),
		to_control(virtual_list_view{ .target = vlv_greater_than_or_equal{ "B" } }).value(),
		testing::encode_vlv_response(vlv_response{ 5, 250, 0, "c" }).value(),
		to_control(transaction_specification{ .identifier = "txn" }).value(),
		ad::encode_dirsync_request(
		  ad::dirsync_request{ .flags = ad::dirsync_flags::incremental_values, .max_bytes = 100, .cookie = "c" }),
		testing::ad::encode_dirsync_response(ad::dirsync_response{ .more_results = true, .cookie_server = "c" }) };
}

}// namespace jhetz::ldap::test
