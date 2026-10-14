// Messages covering every protocolOp alternative with optional fields both set
// and unset. Shared by the unit tests and message_fuzz_replay (seed inputs).
#pragma once

#include "jhetz/ldap/message.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::test {

inline ldap_result sample_result()
{
	return { 32, "dc=example,dc=org", "no such entry", { "ldap://a.example.org/", "ldap://b.example.org/" } };
}

inline filter raw_filter(std::string_view text) { return filter::raw(text).value(); }

inline std::vector<message> sample_messages()
{
	using namespace std::string_literals;
	const std::string_view dn = "uid=jdoe,ou=people,dc=example,dc=org";
	search_request typed_only{ "", search_scope::subordinate_subtree, raw_filter("(bin=\\00\\ff\\2a)"), { "*", "+" } };
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
		bind_response{ { 14 }, "\x60\x82"s },
		bind_response{ sample_result(), ""s },
		unbind_request{},
		std::move(people),
		search_request{},
		typed_only,
		search_result_entry{},
		search_result_entry{
		  dn, { { "cn", { "John", "Johnny" } }, { "jpegPhoto", { "\xff\xd8\0"s } }, { "empty", {} } } },
		search_result_done{},
		search_result_done{ sample_result() },
		search_result_reference{ { "ldap://a.example.org/dc=x", "ldap://b.example.org/dc=x??sub" } },
		search_result_reference{},
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
		compare_response{ { 6 } },
		abandon_request{ 0 },
		abandon_request{ max_int },
		extended_request{ start_tls_oid, {} },
		extended_request{ "1.3.6.1.4.1.4203.1.11.1", "\x30\x00"s },
		extended_response{},
		extended_response{ sample_result(), "1.2.3", "v" },
		extended_response{ { 4711 }, {}, ""s },
		intermediate_response{},
		intermediate_response{ "1.2.3" },
		intermediate_response{ {}, "\x01"s },
		intermediate_response{ "1.2.3", "v" },
	};
	std::vector<message> out;
	std::int32_t id = 1;
	for (auto &op : ops) {
		out.push_back(message{ id++, std::move(op) });
	}
	out.push_back(message{ 0, extended_response{ {}, notice_of_disconnection_oid } });
	out.push_back(message{ max_int, unbind_request{} });
	return out;
}

inline std::pmr::vector<control> sample_controls()
{
	return { encode_paged_results({ 100, "\x01\x02" }, true).value(),
		control{ "1.2.840.113556.1.4.805" },
		control{ "1.2.3.4", true, "" },
		encode_sort_result({ 18, "cn" }).value(),
		encode_read_entry(post_read_oid, search_result_entry{ "cn=x", { { "cn", { "x", "y" } } } }).value() };
}

}// namespace jhetz::ldap::test
