// The requests of ldap::connection's operations (connection.hpp) as plain
// aggregates for designated initializers (DESIGN.md section 3), the
// ldap::mod builders of a ModifyRequest's changes, what the operations
// return besides success, and the OIDs of the extended operations and
// capabilities the connection knows. Part of jhetz::ldap (the codec): no
// Corosio or Capy, the requests are encoded when an operation sends them.
//
//   co_await c->modify({
//       .object  = ldap::dn{"uid=jdoe,ou=people,dc=example,dc=org"},
//       .changes = {ldap::mod::replace("mail", {"jdoe@example.org"}), ldap::mod::increment("loginCount")},
//   });
#pragma once

#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

// For the `timeout` of a request below: no client-side limit for this
// operation, whatever connection_options::operation_timeout says (nullopt
// means "the connection's default" there). For a search that is meant to
// run until stopped, such as a refreshAndPersist content synchronization
// (content_sync.hpp): cancel it with a stop token or by destroying its
// stream. Any timeout too large for the clock (now + timeout overflows)
// also means no limit.
inline constexpr std::chrono::milliseconds no_timeout = std::chrono::milliseconds::max();

// A search, as a plain aggregate for designated initializers (DESIGN.md
// section 3). Values are validated when the request is encoded: a negative
// size_limit or time_limit, or a time_limit above max_int seconds, fails with
// encode_error, an empty filter with invalid_filter, before anything is sent.
struct search_params
{
	dn base{};// the empty DN is the root DSE
	search_scope scope = search_scope::whole_subtree;
	ldap::filter filter = filters::attr("objectClass").present();
	// Attribute selectors as sent: descriptions, "*" (all user attributes),
	// "+" (operational, RFC 3673), "1.1" (none). Empty: all user attributes.
	string_list attributes{};
	deref_aliases deref = deref_aliases::never;
	std::int32_t size_limit = 0;// entries; 0 = no client-requested limit
	std::chrono::seconds time_limit{ 0 };// 0 = no client-requested limit (sent to the server)
	bool types_only = false;
	// Request controls: typed (ldap::paged, ldap::manage_dsa_it, ...) or a
	// raw ldap::control (controls.hpp).
	request_controls controls{};
	// Client-side limit for the whole search, from sending it to the
	// SearchResultDone across every next() (see
	// connection_options::operation_timeout, which applies if this is
	// nullopt; ldap::no_timeout: none). Unlike time_limit it is enforced
	// by the client.
	std::optional<std::chrono::milliseconds> timeout{};
	// Keep the IntermediateResponses (RFC 4511 section 4.13) the server
	// sends during the search, for search_stream::next_item(). False: they
	// are skipped unread, as everywhere else. Only next_item() returns them;
	// next(), search() and search_paged() ignore it (they are decoded and
	// dropped).
	bool intermediate_responses = false;
};

// The other operations (step 6), as plain aggregates like search_params.
// `controls` and `timeout` mean the same everywhere: request controls, and
// a client-side limit overriding connection_options::operation_timeout
// (ldap::no_timeout: none).

// AddRequest (RFC 4511 section 4.7). Every attribute needs at least one
// value (encode_error otherwise, before anything is sent).
struct add_params
{
	dn entry{};
	std::pmr::vector<partial_attribute> attributes{};// {"cn", {"Jane Doe"}}, ...
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ModifyRequest (RFC 4511 section 4.6): changes applied in order, atomically.
// Build them with ldap::mod::add / remove / replace / increment.
struct modify_params
{
	dn object{};
	std::pmr::vector<modify_change> changes{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

namespace mod {
	// Adds values (at least one).
	[[nodiscard]] auto add(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change;
	// Deletes the given values, or the whole attribute if none are given.
	[[nodiscard]] auto remove(std::string_view type, std::initializer_list<std::string_view> values = {})
	  -> modify_change;
	// Replaces all values (none: deletes the attribute if present).
	[[nodiscard]] auto replace(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change;
	// Adds `delta` to an integer attribute (RFC 4525 Modify-Increment).
	[[nodiscard]] auto increment(std::string_view type, std::string_view delta = "1") -> modify_change;
}// namespace mod

// DelRequest (RFC 4511 section 4.8): deletes a leaf entry.
struct del_params
{
	dn entry{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ModifyDNRequest (RFC 4511 section 4.9): renames an entry (new_rdn) and/or
// moves it under new_superior. To move without renaming, pass its current
// RDN (entry.rdns().front()).
struct modify_dn_params
{
	dn entry{};
	rdn new_rdn{};
	bool delete_old_rdn = true;// drop the old RDN's values from the entry
	std::optional<dn> new_superior{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// CompareRequest (RFC 4511 section 4.10).
struct compare_params
{
	dn entry{};
	std::string attribute{};
	std::string value{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ExtendedRequest (RFC 4511 section 4.12).
struct extended_params
{
	std::string name{};// requestName, an OID
	std::optional<std::string> value{};// requestValue, as encoded for that operation
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
	// Collect the IntermediateResponses (RFC 4511 section 4.13) the server
	// sends before the ExtendedResponse into extended_result::intermediates.
	// False: they are skipped unread.
	bool intermediate_responses = false;
};

// What a successful operation returns besides success: the controls of the
// server's response (e.g. a post-read entry, RFC 4527: find_post_read()).
struct response
{
	std::pmr::vector<control> controls{};
};

// An IntermediateResponse (RFC 4511 section 4.13: response_name and
// response_value, both optional) and the controls of its message, for a
// caller that asked for them (`intermediate_responses` in search_params and
// extended_params). Its meaning, and so the encoding of responseValue, is
// the extension's (e.g. RFC 4533's syncInfoValue); some extensions put their
// data in the controls instead. Allocator-aware like the message model
// (message.hpp): a plain copy uses the default resource, the
// allocator-extended copy the given one, assignment keeps the target's.
// Converting it to an intermediate_response (slicing) drops the controls.
struct intermediate : intermediate_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<control> controls{};

	intermediate() = default;
	explicit intermediate(const allocator_type &alloc) : intermediate_response(alloc), controls(alloc) {}
	// Takes the strings of `response` and `controls_` when they are on
	// `alloc`'s resource, else copies them onto it.
	intermediate(intermediate_response response, std::pmr::vector<control> controls_, const allocator_type &alloc = {})
	  : intermediate_response(std::move(response), alloc), controls(std::move(controls_), alloc)
	{}
	intermediate(const intermediate &) = default;
	intermediate(intermediate &&) noexcept = default;
	intermediate(const intermediate &other, const allocator_type &alloc)
	  : intermediate_response(other, alloc), controls(other.controls, alloc)
	{}
	intermediate(intermediate &&other, const allocator_type &alloc)
	  : intermediate_response(std::move(other), alloc), controls(std::move(other.controls), alloc)
	{}
	auto operator=(const intermediate &) -> intermediate & = default;
	auto operator=(intermediate &&) -> intermediate & = default;
	~intermediate() = default;

	friend auto operator==(const intermediate &, const intermediate &) -> bool = default;
};

struct extended_result
{
	std::optional<std::pmr::string> name{};// responseName
	std::optional<std::pmr::string> value{};// responseValue
	std::pmr::vector<control> controls{};
	// The IntermediateResponses received before the ExtendedResponse, in
	// order; empty unless extended_params::intermediate_responses is set.
	// Lost when the operation fails.
	std::pmr::vector<intermediate> intermediates{};
};

// RFC 4532 "Who am I?" extended operation.
inline constexpr std::string_view who_am_i_oid = "1.3.6.1.4.1.4203.1.11.3";

// RFC 3062 Password Modify extended operation.
inline constexpr std::string_view password_modify_oid = "1.3.6.1.4.1.4203.1.11.1";

struct password_modify_params
{
	// userIdentity: whose password, usually a DN (the server decides the
	// form). nullopt: the user this connection is bound as.
	std::optional<std::string> user{};
	// oldPasswd: servers usually require it when users change their own.
	std::optional<std::string> old_password{};
	// newPasswd. nullopt: the server generates one and returns it.
	std::optional<std::string> new_password{};
	request_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// LDAP_CAP_ACTIVE_DIRECTORY_OID: in the root DSE's supportedCapabilities of
// Active Directory and Samba AD domain controllers.
inline constexpr std::string_view active_directory_capability_oid = "1.2.840.113556.1.4.800";

}// namespace jhetz::ldap
