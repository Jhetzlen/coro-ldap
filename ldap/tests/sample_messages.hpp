// Messages covering every protocolOp alternative with optional fields both set
// and unset. Shared by the unit tests and message_fuzz_replay (seed inputs).
#pragma once

#include "jhetz/ldap/message.hpp"

#include <string>
#include <vector>

namespace jhetz::ldap::test {

inline ldap_result sample_result()
{
	return { .result_code = 32,
		.matched_dn = "dc=example,dc=org",
		.diagnostic_message = "no such entry",
		.referral = { "ldap://a.example.org/", "ldap://b.example.org/" } };
}

inline std::vector<message> sample_messages()
{
	using namespace std::string_literals;
	const std::string dn = "uid=jdoe,ou=people,dc=example,dc=org";
	std::vector<protocol_op> ops{
		bind_request{ .version = 3, .name = dn, .authentication = simple_auth{ "secret" } },
		bind_request{ .version = 2, .name = "", .authentication = simple_auth{ "" } },
		bind_request{ .version = 3, .name = "", .authentication = sasl_auth{ "EXTERNAL", {} } },
		bind_request{ .version = 127, .name = "", .authentication = sasl_auth{ "GSSAPI", "\0\x01\xff"s } },
		bind_response{},
		bind_response{ .result = { .result_code = 14 }, .server_sasl_creds = "\x60\x82"s },
		bind_response{ .result = sample_result(), .server_sasl_creds = ""s },
		unbind_request{},
		search_request{ .base_object = "ou=people,dc=example,dc=org",
		  .scope = search_scope::whole_subtree,
		  .deref = deref_aliases::finding_base_obj,
		  .size_limit = 500,
		  .time_limit = 30,
		  .filter = filter::raw("(&(objectClass=person)(|(uid=jdoe)(mail=j*@*.org))(!(disabled=TRUE))"
								"(cn:dn:2.5.13.5:=x\\2ay)(sn~=smith)(uidNumber>=1000)(uidNumber<=2000)(&)(|))"),
		  .attributes = { "uid", "mail", "cn;lang-en", "1.3.6.1.4.1.1466.101.120.16" } },
		search_request{},
		search_request{ .scope = search_scope::subordinate_subtree,
		  .deref = deref_aliases::always,
		  .size_limit = max_int,
		  .time_limit = max_int,
		  .types_only = true,
		  .filter = filter::raw("(bin=\\00\xff\\2a)"),// canonical: only * ( ) \ and NUL are escaped
		  .attributes = { "*", "+" } },
		search_result_entry{},
		search_result_entry{ .object_name = dn,
		  .attributes = { { "cn", { "John", "Johnny" } }, { "jpegPhoto", { "\xff\xd8\0"s } }, { "empty", {} } } },
		search_result_done{},
		search_result_done{ sample_result() },
		search_result_reference{ { "ldap://a.example.org/dc=x", "ldap://b.example.org/dc=x??sub" } },
		search_result_reference{},
		modify_request{ .object = dn,
		  .changes = { { modify_operation::add, { "mail", { "a@x", "b@x" } } },
			{ modify_operation::delete_, { "phone", {} } },
			{ modify_operation::replace, { "sn", { "Doe" } } },
			{ modify_operation::increment, { "uidNumber", { "1" } } } } },
		modify_request{},
		modify_response{ sample_result() },
		add_request{ .entry = dn, .attributes = { { "objectClass", { "top", "person" } }, { "cn", { "J" } } } },
		add_response{},
		del_request{ dn },
		del_request{},
		del_response{ sample_result() },
		modify_dn_request{ .entry = dn, .new_rdn = "uid=john", .delete_old_rdn = true, .new_superior = "ou=x" },
		modify_dn_request{ .entry = dn, .new_rdn = "uid=john", .delete_old_rdn = false },
		modify_dn_response{},
		compare_request{ .entry = dn, .ava = { "userPassword", "\0secret"s } },
		compare_response{ { .result_code = 6 } },
		abandon_request{ 0 },
		abandon_request{ max_int },
		extended_request{ std::string(start_tls_oid), {} },
		extended_request{ "1.3.6.1.4.1.4203.1.11.1", "\x30\x00"s },
		extended_response{},
		extended_response{ .result = sample_result(), .response_name = "1.2.3", .response_value = "v" },
		extended_response{ .result = { .result_code = 4711 }, .response_value = ""s },
		intermediate_response{},
		intermediate_response{ .response_name = "1.2.3" },
		intermediate_response{ .response_value = "\x01"s },
		intermediate_response{ .response_name = "1.2.3", .response_value = "v" },
	};
	std::vector<message> out;
	std::int32_t id = 1;
	for (auto &op : ops) out.push_back(message{ .id = id++, .op = std::move(op) });
	out.push_back(
	  message{ .id = 0, .op = extended_response{ .response_name = std::string(notice_of_disconnection_oid) } });
	out.push_back(message{ .id = max_int, .op = unbind_request{} });
	return out;
}

inline std::vector<control> sample_controls()
{
	return { encode_paged_results({ .size = 100, .cookie = "\x01\x02" }, true).value(),
		control{ .type = "1.2.840.113556.1.4.805" },
		control{ .type = "1.2.3.4", .criticality = true, .value = "" } };
}

}// namespace jhetz::ldap::test
