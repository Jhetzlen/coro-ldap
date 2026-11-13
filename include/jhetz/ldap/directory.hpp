// The `directory` concept: what repository, load_schema and the other
// layers run on (ldap::connection, ldap::client).
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

class client;

template<class D>
concept directory =
  requires(D &d, search_params s, add_params a, modify_params m, del_params r, modify_dn_params n, compare_params c) {
	  { d.search(std::move(s)) } -> std::same_as<boost::capy::task<result<search_result>>>;
	  { d.add(std::move(a)) } -> std::same_as<boost::capy::task<result<response>>>;
	  { d.modify(std::move(m)) } -> std::same_as<boost::capy::task<result<response>>>;
	  { d.del(std::move(r)) } -> std::same_as<boost::capy::task<result<response>>>;
	  { d.modify_dn(std::move(n)) } -> std::same_as<boost::capy::task<result<response>>>;
	  { d.compare(std::move(c)) } -> std::same_as<boost::capy::task<result<compare_result>>>;
  };

namespace detail {
	inline constexpr std::string_view load_schema_context = "load schema";
	struct subschema_search
	{
		search_params request;
		std::string where;// the DN as the root DSE wrote it
	};
	// The search of the root DSE's subschemaSubentry (cn=Subschema if none).
	[[nodiscard]] auto subschema_request(const result<search_result> &root) -> result<subschema_search>;
	[[nodiscard]] auto subschema_of(result<search_result> sub, std::string_view where) -> result<server_schema>;

	// The error of a search that ended with a limit code.
	[[nodiscard]] auto search_error(const search_result &r, std::string_view context) -> error;

	// client_errc::schema_mismatch with the report.
	[[nodiscard]] auto schema_mismatch(std::string_view type, const schema_report &report) -> error;
}// namespace detail

// Reads the server's subschema (RFC 4512 section 4.2). `d` must outlive the
// task.
template<directory D> auto load_schema(D &d) -> boost::capy::task<result<server_schema>>
{
	auto sub = detail::subschema_request(co_await d.search(root_dse({ "subschemaSubentry" })));
	if (!sub) {
		co_return std::unexpected(std::move(sub.error()));
	}
	co_return detail::subschema_of(co_await d.search(std::move(sub->request)), sub->where);
}

// load_schema on one shared lease of a client's pool, retried once after
// cond::connection_lost. `c` must outlive the task.
auto load_schema(client &c) -> boost::capy::task<result<server_schema>>;

}// namespace jhetz::ldap
