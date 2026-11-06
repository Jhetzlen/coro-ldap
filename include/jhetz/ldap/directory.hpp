// The `directory` concept: what the layers over the core (ldap::store,
// load_schema, ...) run their requests on. ldap::connection,
// ldap::client and a shared lease's ldap::shared_connection satisfy it.
//
//   ldap::result<ldap::server_schema> s = co_await ldap::load_schema(pool);
#pragma once

#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/schema.hpp"

#include <boost/capy/task.hpp>

#include <concepts>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {

// The protocol operations a directory runs, with connection's names and
// results.
template<class D>
concept directory = requires(D &d, search_params s, add_params a, modify_params m, del_params r, modify_dn_params n) {
	{ d.search(std::move(s)) } -> std::same_as<boost::capy::task<result<search_result>>>;
	{ d.add(std::move(a)) } -> std::same_as<boost::capy::task<result<response>>>;
	{ d.modify(std::move(m)) } -> std::same_as<boost::capy::task<result<response>>>;
	{ d.del(std::move(r)) } -> std::same_as<boost::capy::task<result<response>>>;
	{ d.modify_dn(std::move(n)) } -> std::same_as<boost::capy::task<result<response>>>;
};

namespace detail {
	// The steps of load_schema, for the async and the blocking forms.
	inline constexpr std::string_view load_schema_context = "load schema";
	struct subschema_search
	{
		search_params request;
		std::string where;// the DN as the root DSE wrote it
	};
	// The search of the subschema entry the root DSE names
	// (subschemaSubentry), cn=Subschema if it names none. A name that is
	// not a DN fails with invalid_dn.
	[[nodiscard]] auto subschema_request(const result<search_result> &root) -> result<subschema_search>;
	// The schema in the subschema entry that `sub` found at `where`.
	[[nodiscard]] auto subschema_of(result<search_result> sub, std::string_view where) -> result<server_schema>;

	// client_errc::schema_mismatch with the report, for the type named `type`.
	[[nodiscard]] auto schema_mismatch(std::string_view type, const schema_report &report) -> error;

	// An operation's error context: "search ou=people,dc=example,dc=org",
	// `search ""` for the root DSE. The DN is often the server's text (an
	// entry's DN, a referral's): sanitized and cut at 256 bytes, as an
	// entry's in decode errors.
	auto op_context(std::string_view op, const dn &d) -> std::string;
}// namespace detail

// Reads the server's subschema (RFC 4512 section 4.2): the root DSE's
// subschemaSubentry (cn=Subschema if it names none), then that entry's
// attributeTypes and objectClasses. Errors have the context "load schema".
// `d` must outlive the task.
template<directory D> auto load_schema(D &d) -> boost::capy::task<result<server_schema>>
{
	auto sub = detail::subschema_request(co_await d.search(root_dse({ "subschemaSubentry" })));
	if (!sub) {
		co_return std::unexpected(std::move(sub.error()));
	}
	co_return detail::subschema_of(co_await d.search(std::move(sub->request)), sub->where);
}

}// namespace jhetz::ldap
