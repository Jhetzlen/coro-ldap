// Typed request controls (DESIGN.md section 3): what callers put in the
// `.controls` of a request, encoded to the wire-level ldap::control
// (message.hpp) when the request is sent.
//
//   co_await conn.search({
//       .base     = base,
//       .controls = {ldap::manage_dsa_it{}, ldap::control{"1.2.3.4", true, "raw"}},
//   });
//
// Each operation's params take its own list (search_controls,
// add_controls, ...): the raw control and the typed controls whose
// specification allows them on that operation (the table control_rule_of,
// below), so pre_read on an add or paged on a modify does not compile. A
// list shared by several operations is a request_controls, converted with
// controls_for<add_controls>(list), which fails at run time instead.
//
// ldap::control itself is the escape hatch for anything not typed here,
// allowed everywhere. It is not checked: a raw control whose OID is one of
// the typed ones (pre_read_oid on an add, ...) is sent as given.
// Controls the server returns stay wire-level (std::pmr::vector<control>,
// in connection::response, extended_result and search_stream::controls());
// find_paged(), find_sort_result(), find_vlv_response(), find_pre_read()
// and find_post_read() read the typed ones (and content_sync.hpp's find_sync_state() and
// find_sync_done() those of RFC 4533, whose sync_request is here too):
//
//   auto r = co_await conn.modify({.object = dn, .changes = ...,
//                                  .controls = {ldap::post_read{.attributes = {"modifyTimestamp"}}}});
//   if (r) if (auto e = ldap::find_post_read(r->controls); e && *e) use((*e)->find("modifyTimestamp"));
#pragma once

#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace jhetz::ldap {

// Simple Paged Results (RFC 2696, OID paged_results_oid): ask for at most
// `page_size` entries; `cookie` is empty for the first page and the
// server's cookie for the next ones. connection::search_paged() manages it.
struct paged
{
	std::int32_t page_size = 0;
	std::string cookie{};
	bool critical = false;
};

// ManageDsaIT (RFC 3296): treat referral objects as ordinary entries. No value.
inline constexpr std::string_view manage_dsa_it_oid = "2.16.840.1.113730.3.4.2";
struct manage_dsa_it
{
	bool critical = false;
};

// Relax Rules (draft-zeilenga-ldap-relax): let the update bend the
// server's schema and other data rules, e.g. set a NO-USER-MODIFICATION
// attribute such as createTimestamp or entryUUID when migrating entries;
// the server still decides who may (OpenLDAP: manage access, so in
// practice the rootdn). No value. Critical by default, as the draft
// specifies: a server that does not know the control then refuses the
// operation (unavailable_critical_extension) instead of applying the
// ordinary rules.
inline constexpr std::string_view relax_rules_oid = "1.3.6.1.4.1.4203.666.5.12";
struct relax_rules
{
	bool critical = true;
};

// Proxied Authorization (RFC 4370): run the operation as `authz_id`
// ("dn:<dn>", "u:<user>", or "" for anonymous). Always critical (RFC 4370
// section 3).
inline constexpr std::string_view proxied_authorization_oid = "2.16.840.1.113730.3.4.18";
struct proxied_authorization
{
	std::string authz_id{};
};

// Server Side Sorting (RFC 2891, OID sort_request_oid): sort the search's
// entries by `keys`, the first one most significant. RFC 2891 section 2
// says a server that supports the control but cannot sort SHOULD fail the
// search if it is critical and should return the entries unsorted if not,
// with a sort result control on the SearchResultDone, though scenario 6
// lets the server omit that control when the search fails or returns no
// entries; a server without sort support ignores a non-critical control
// and sends none. A server may accept only one key. Servers deviate:
// OpenLDAP 2.7's sssvlv fails an unsortable search with 18
// inappropriateMatching and no sort result even when not critical, and
// answers every multi-key sort with 2 protocolError ("decoding error") and
// no sort result, even when not critical (libldap's own requests too). So
// check the search's result, and treat find_sort_result() returning
// nullopt as "not known to be sorted". sssvlv also mixes up concurrent
// sorted paged searches on one connection (see connection::search_paged).
// Fails with encode_error, before anything is sent, if there are no keys or
// a key has no attribute.
struct sort_key
{
	std::string attribute{};// attributeType: an attribute description
	std::string ordering_rule{};// orderingRule [0]: a matching rule; empty = the attribute's ORDERING
	bool reverse = false;// reverseOrder [1]: descending
};
struct server_side_sort
{
	std::vector<sort_key> keys{};
	bool critical = false;
};

// Assertion (RFC 4528, OID assertion_oid): perform the operation only if
// `filter` matches the target entry (for a search: the base object), else
// fail with errc::assertion_failed (122). Critical by default: a server that
// does not know the control then refuses the operation
// (unavailable_critical_extension) instead of ignoring the condition. An
// empty filter fails with invalid_filter when encoded.
inline constexpr std::string_view assertion_oid = "1.3.6.1.1.12";
struct assertion
{
	ldap::filter filter{};
	bool critical = true;
};

// Pre-Read / Post-Read (RFC 4527, OIDs pre_read_oid / post_read_oid): return
// the target entry as it was before (pre_read: on a modify, delete or modify
// DN) / is after (post_read: on an add, modify or modify DN) the update, with
// the given attributes (as in a search: empty means all user attributes, "+"
// operational ones). There is no pre-read of an add or post-read of a delete.
// The entry comes back in a response control: find_pre_read / find_post_read.
struct pre_read
{
	std::vector<std::string> attributes{};
	bool critical = false;
};
struct post_read
{
	std::vector<std::string> attributes{};
	bool critical = false;
};

// Matched Values (RFC 3876, OID matched_values_oid): return, of the
// attributes a search returns, only the values that match at least one
// item of `values_return_filter` (the ValuesReturnFilter, RFC 3876 section
// 2), e.g. one member of a large group:
//
//   .controls = {ldap::matched_values{.values_return_filter = {attr("member") == member_dn}}}
//
// Each item is one simple filter: equality, substrings, >=, <=, present,
// approx or extensible match (SimpleFilterItem). RFC 3876 excludes and,
// or and not, and an extensible match with dnAttributes
// (SimpleMatchingAssertion has none); such an item, an empty one, or an
// empty list fails with invalid_filter (encode_error for the empty list)
// when encoded. parse_values_return_filter() reads the string form of RFC
// 3876 section 5, "((mail=*@example.org)(telephoneNumber=*))". The
// selection applies to the entries' values only, never to which entries
// match; per RFC 3876 section 2 an attribute with no matching value comes
// back with no values (OpenLDAP 2.7 leaves it out). typesOnly and the
// "1.1" attribute list make it a no-op. Non-critical by default: a server
// without it ignores it and returns every value (OpenLDAP supports it
// natively).
inline constexpr std::string_view matched_values_oid = "1.2.826.0.1.3344810.2.3";
struct matched_values
{
	std::vector<ldap::filter> values_return_filter{};
	bool critical = false;

	friend auto operator==(const matched_values &, const matched_values &) -> bool = default;
};

// The items of a ValuesReturnFilter in the string form of RFC 3876 section
// 5: "(" 1*simpleFilterItem ")", each item an RFC 4515 filter of the kinds
// matched_values takes, e.g. "((mail=*@example.org)(cn:caseExactMatch:=Jo))".
// A single item without the outer parentheses ("(mail=*)") is read as a
// list of one. Fails with invalid_filter: text that does not parse, an item
// RFC 3876 excludes (and, or, not, dnAttributes), or no item. The filters
// are allocated from `mr`.
[[nodiscard]] auto parse_values_return_filter(std::string_view text,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::vector<ldap::filter>>;

// The request control as a server reads it (for mock servers and tests):
// `critical` is the control's criticality. Fails with decode_error if `c`
// is not a matched values control, its value is missing or malformed, the
// list is empty, an item is not a SimpleFilterItem, or the items have more
// than max_filter_elements elements in all. The filters are allocated from
// `mr`.
[[nodiscard]] auto decode_matched_values(const control &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<matched_values>;

// Virtual List View (draft-ietf-ldapext-ldapv3-vlv-09, OID vlv_request_oid):
// return a window of a sorted search's entries, `before_count` entries
// before the target entry and `after_count` after it, for a UI scrolling
// through a large list. The search must also carry a server_side_sort
// (section 6.1), whose first key orders the list: without one the request
// fails with encode_error before anything is sent (a raw control with
// sort_request_oid counts). The target is
// - vlv_by_offset{.offset, .content_count}: the entry at offset / content
//   count of the list, offset 1 being the first entry and offset ==
//   content_count the last; content_count 0 means "the server's count"
//   (section 5);
// - vlv_greater_than_or_equal{.value}: the first entry whose primary sort
//   key is >= value in the sort order ("typedown").
// `context_id` is the contextID of the server's last response for this
// list, returned unchanged (nullopt if it sent none). The server answers
// with a VLV response control on the SearchResultDone (find_vlv_response):
// the target's position, its content count and, when the search fails with
// errc::virtual_list_view_error (76), why. search() drops those controls,
// so read the window with search_stream(), whose controls() keep them even
// after an error. OpenLDAP serves it with the sssvlv overlay, which keeps
// each list's state until the connection closes and, past
// sssvlv-maxperconn lists per connection (default 5), refuses a request
// without a contextID it knows with busy (51): send the contextID back.
// Fails with encode_error for a negative count or an offset below 1.
struct vlv_by_offset
{
	std::int32_t offset = 1;// INTEGER (1 .. maxInt)
	std::int32_t content_count = 0;// INTEGER (0 .. maxInt)

	friend auto operator==(const vlv_by_offset &, const vlv_by_offset &) -> bool = default;
};
struct vlv_greater_than_or_equal
{
	std::string value{};// AssertionValue, per the primary sort key's ORDERING rule

	friend auto operator==(const vlv_greater_than_or_equal &, const vlv_greater_than_or_equal &) -> bool = default;
};
struct virtual_list_view
{
	std::int32_t before_count = 0;// beforeCount
	std::int32_t after_count = 0;// afterCount
	std::variant<vlv_by_offset, vlv_greater_than_or_equal> target{};// byOffset [0] / greaterThanOrEqual [1]
	std::optional<std::string> context_id{};// contextID
	bool critical = false;

	friend auto operator==(const virtual_list_view &, const virtual_list_view &) -> bool = default;
};

// The request control as a server reads it (for mock servers and tests):
// `critical` is the control's criticality. Fails with decode_error if `c`
// is not a VLV request control or its value is missing or malformed (a
// count out of range, an unknown target).
[[nodiscard]] auto decode_virtual_list_view(const control &c) -> result<virtual_list_view>;

// Transaction Specification (RFC 5805 section 2.2, OID
// transaction_specification_oid): process this update (add, delete, modify,
// modify DN) as part of the transaction `identifier`, the identifier
// connection::start_transaction() returned. Always critical (section 2.2).
// The server answers the update at once with success (or the reason it
// refuses it) and defers the update until connection::end_transaction();
// its response controls (pre-read, post-read) come back then, in
// end_transaction_result::updates_controls. Proxied authorization does not
// go with it (section 4.4: put it on the Start Transaction request): a list
// with both fails with encode_error before anything is sent (a raw control
// with proxied_authorization_oid counts). ldap::transaction (transaction.hpp)
// attaches it for you. Password Modify (RFC 3062) is an update too, but
// extended_controls does not take it: send a raw control there.
struct transaction_specification
{
	std::string identifier{};

	friend auto operator==(const transaction_specification &, const transaction_specification &) -> bool = default;
};

// The control as a server reads it (for mock servers and tests). Fails with
// decode_error if `c` is not a transaction specification control, is not
// critical, or has no value.
[[nodiscard]] auto decode_transaction_specification(const control &c) -> result<transaction_specification>;

// ---------------------------------------------------------------- per-operation lists

// The request messages a typed control can go on, by RFC 4511 operation:
// searchRequest, addRequest, modifyRequest, modDNRequest, delRequest,
// compareRequest, extendedReq. Bind, unbind and abandon take no typed
// control here.
enum class operation_kind : std::uint8_t {
	search,
	add,
	modify,
	modify_dn,
	del,
	compare,
	extended,
};
// The number of operation_kind values: operation_set has a bit for each.
inline constexpr std::size_t operation_kind_count = std::to_underlying(operation_kind::extended) + 1;

// "search", "add", "modify", "modify DN", "delete", "compare", "extended
// operation": the operation as error contexts name it.
[[nodiscard]] constexpr auto operation_name(operation_kind op) noexcept -> std::string_view
{
	switch (op) {
	case operation_kind::search:
		return "search";
	case operation_kind::add:
		return "add";
	case operation_kind::modify:
		return "modify";
	case operation_kind::modify_dn:
		return "modify DN";
	case operation_kind::del:
		return "delete";
	case operation_kind::compare:
		return "compare";
	case operation_kind::extended:
		return "extended operation";
	}
	return "operation";
}

// A set of operation_kind, for the table below.
struct operation_set
{
	std::uint8_t bits = 0;

	static_assert(operation_kind_count <= std::numeric_limits<decltype(bits)>::digits,
	  "ldap::operation_set: widen bits for the new operation_kind");

	[[nodiscard]] constexpr auto contains(operation_kind op) const noexcept -> bool
	{
		return (bits & (1U << std::to_underlying(op))) != 0;
	}
};

// The set of the given operations.
template<std::same_as<operation_kind>... Op>
[[nodiscard]] constexpr auto operation_set_of(Op... op) noexcept -> operation_set
{
	return { .bits = static_cast<std::uint8_t>((0U | ... | (1U << std::to_underlying(op)))) };
}

// One row of the applicability table: the control's name in errors, the
// specification that sets where it applies, and the operations it applies
// to.
struct control_rule
{
	std::string_view name;
	std::string_view source;
	operation_set operations;
};

// The applicability table: where each typed request control may be sent,
// as its specification says. The per-operation lists below are checked
// against it at compile time, and controls_for() checks a shared
// request_controls against it at run time.
template<class T>
inline constexpr control_rule control_rule_of = [] {
	static_assert(sizeof(T) == 0,
	  "ldap::control_rule_of: no row in control_rule_of for this request control; add one citing its specification");
	return control_rule{};
}();

namespace detail {
	inline constexpr operation_set all_operations = operation_set_of(operation_kind::search,
	  operation_kind::add,
	  operation_kind::modify,
	  operation_kind::modify_dn,
	  operation_kind::del,
	  operation_kind::compare,
	  operation_kind::extended);
	// Every operation but the extended one.
	inline constexpr operation_set interrogation_and_update = operation_set_of(operation_kind::search,
	  operation_kind::add,
	  operation_kind::modify,
	  operation_kind::modify_dn,
	  operation_kind::del,
	  operation_kind::compare);
}// namespace detail

// The raw control: the caller knows where it applies.
template<>
inline constexpr control_rule control_rule_of<control> = { .name = "control",
	.source = "raw",
	.operations = detail::all_operations };
// RFC 2696 section 2: "included in the searchRequest and searchResultDone
// messages".
template<>
inline constexpr control_rule control_rule_of<paged> = { .name = "paged",
	.source = "RFC 2696 section 2",
	.operations = operation_set_of(operation_kind::search) };
// RFC 3296 section 3: "A client MAY specify the following control when
// issuing an add, compare, delete, modify, modifyDN, search request or an
// extended operation for which the control is defined." No extended
// operation typed here defines it (RFC 3062, RFC 4532 do not), so it is not
// on extended_controls; a raw control sends it on one that does.
template<>
inline constexpr control_rule control_rule_of<manage_dsa_it> = { .name = "manage_dsa_it",
	.source = "RFC 3296 section 3",
	.operations = detail::interrogation_and_update };
// draft-zeilenga-ldap-relax-03 section 2: "appropriate for all LDAP update
// requests, including add, delete, modify, and modifyDN".
template<>
inline constexpr control_rule control_rule_of<relax_rules> = { .name = "relax_rules",
	.source = "draft-zeilenga-ldap-relax-03 section 2",
	.operations =
	  operation_set_of(operation_kind::add, operation_kind::modify, operation_kind::modify_dn, operation_kind::del) };
// RFC 4370 section 3: "any search, compare, modify, add, delete, or modify
// Distinguished Name (DN) or extended operation request message", except
// an extension that changes authentication, authorization or data
// confidentiality such as StartTLS: connection::extended() refuses the
// StartTLS name (start_tls() takes no controls), so no typed control goes
// on it.
template<>
inline constexpr control_rule control_rule_of<proxied_authorization> = { .name = "proxied_authorization",
	.source = "RFC 4370 section 3",
	.operations = detail::all_operations };
// RFC 2891 section 1.1: "included in the searchRequest message".
template<>
inline constexpr control_rule control_rule_of<server_side_sort> = { .name = "server_side_sort",
	.source = "RFC 2891 section 1.1",
	.operations = operation_set_of(operation_kind::search) };
// RFC 4528 section 3: "appropriate for both LDAP interrogation and update
// operations [RFC4511], including Add, Compare, Delete, Modify, ModifyDN
// (rename), and Search." and "Other documents may specify how this
// control applies to other LDAP operations. In doing so, they must state
// how the target entry is determined." No extended operation typed here
// does (RFC 3062, RFC 4532 do not, and OpenLDAP rejects it there), so it
// is not on extended_controls; a raw control sends it on one that does.
template<>
inline constexpr control_rule control_rule_of<assertion> = { .name = "assertion",
	.source = "RFC 4528 section 3",
	.operations = detail::interrogation_and_update };
// RFC 4527 section 3.1: "appropriate for the modifyRequest, delRequest,
// and modDNRequest LDAP messages".
template<>
inline constexpr control_rule control_rule_of<pre_read> = { .name = "pre_read",
	.source = "RFC 4527 section 3.1",
	.operations = operation_set_of(operation_kind::modify, operation_kind::modify_dn, operation_kind::del) };
// RFC 4527 section 3.2: "appropriate for the addRequest, modifyRequest,
// and modDNRequest LDAP messages".
template<>
inline constexpr control_rule control_rule_of<post_read> = { .name = "post_read",
	.source = "RFC 4527 section 3.2",
	.operations = operation_set_of(operation_kind::add, operation_kind::modify, operation_kind::modify_dn) };
// RFC 4533 section 2.2: "only applicable to the SearchRequest Message".
template<>
inline constexpr control_rule control_rule_of<sync_request> = { .name = "sync_request",
	.source = "RFC 4533 section 2.2",
	.operations = operation_set_of(operation_kind::search) };

// RFC 3876 section 2: "It only has meaning for the Search operation, and
// SHOULD only be added to the Search operation by the client."
template<>
inline constexpr control_rule control_rule_of<matched_values> = { .name = "matched_values",
	.source = "RFC 3876 section 2",
	.operations = operation_set_of(operation_kind::search) };

// draft-ietf-ldapext-ldapv3-vlv-09 section 6.1: "This control is included
// in the SearchRequest message".
template<>
inline constexpr control_rule control_rule_of<virtual_list_view> = { .name = "virtual_list_view",
	.source = "draft-ietf-ldapext-ldapv3-vlv-09 section 6.1",
	.operations = operation_set_of(operation_kind::search) };

// RFC 5805 section 2.2: "appropriate for update requests including Add,
// Delete, Modify, and ModifyDN (Rename) requests [RFC4511], as well as the
// Password Modify requests [RFC3062]". Password Modify is an extended
// operation, and extended_controls is shared by every extended operation,
// so it is not there; a raw control sends it on one.
template<>
inline constexpr control_rule control_rule_of<transaction_specification> = { .name = "transaction_specification",
	.source = "RFC 5805 section 2.2",
	.operations =
	  operation_set_of(operation_kind::add, operation_kind::modify, operation_kind::modify_dn, operation_kind::del) };

// Whether control type T may be sent on `op` (the table above).
template<class T> [[nodiscard]] constexpr auto applies_to(operation_kind op) noexcept -> bool
{
	return control_rule_of<T>.operations.contains(op);
}

// Any typed control or a raw one: a shared list, to convert with
// controls_for() for an operation.
using request_control = std::variant<control,
  paged,
  manage_dsa_it,
  relax_rules,
  proxied_authorization,
  server_side_sort,
  assertion,
  pre_read,
  post_read,
  sync_request,
  matched_values,
  virtual_list_view,
  transaction_specification>;
using request_controls = std::vector<request_control>;

// A list of the controls `Op` takes: the raw control and the typed ones
// the table allows there, so a typed control sent where its specification
// does not allow it does not compile:
//
//   ldap::add_params{.controls = {ldap::pre_read{}}};// error: no add_controls from pre_read
//
// The named lists below derive from it so errors name them.
template<operation_kind Op, class... Typed> struct controls_of : std::vector<std::variant<control, Typed...>>
{
	using std::vector<std::variant<control, Typed...>>::vector;
	static constexpr operation_kind operation = Op;
};

struct search_controls
  : controls_of<operation_kind::search,
	  paged,
	  manage_dsa_it,
	  proxied_authorization,
	  server_side_sort,
	  assertion,
	  sync_request,
	  matched_values,
	  virtual_list_view>
{
	using controls_of::controls_of;
};
struct add_controls
  : controls_of<operation_kind::add,
	  manage_dsa_it,
	  relax_rules,
	  proxied_authorization,
	  assertion,
	  post_read,
	  transaction_specification>
{
	using controls_of::controls_of;
};
struct modify_controls
  : controls_of<operation_kind::modify,
	  manage_dsa_it,
	  relax_rules,
	  proxied_authorization,
	  assertion,
	  pre_read,
	  post_read,
	  transaction_specification>
{
	using controls_of::controls_of;
};
struct modify_dn_controls
  : controls_of<operation_kind::modify_dn,
	  manage_dsa_it,
	  relax_rules,
	  proxied_authorization,
	  assertion,
	  pre_read,
	  post_read,
	  transaction_specification>
{
	using controls_of::controls_of;
};
struct del_controls
  : controls_of<operation_kind::del,
	  manage_dsa_it,
	  relax_rules,
	  proxied_authorization,
	  assertion,
	  pre_read,
	  transaction_specification>
{
	using controls_of::controls_of;
};
struct compare_controls : controls_of<operation_kind::compare, manage_dsa_it, proxied_authorization, assertion>
{
	using controls_of::controls_of;
};
struct extended_controls : controls_of<operation_kind::extended, proxied_authorization>
{
	using controls_of::controls_of;
};

namespace detail {
	template<class T, class Variant> inline constexpr bool has_alternative = false;
	template<class T, class... A>
	inline constexpr bool has_alternative<T, std::variant<A...>> = (std::same_as<T, A> || ...);

	// List holds exactly the alternatives of request_control that the
	// table allows on List::operation.
	template<class List, class Full> inline constexpr bool matches_table = false;
	template<class List, class... All>
	inline constexpr bool matches_table<List, std::variant<All...>> =
	  ((applies_to<All>(List::operation) == has_alternative<All, typename List::value_type>) && ...);

	template<class List> inline constexpr bool within_request_control = false;
	template<operation_kind Op, class... Typed>
	inline constexpr bool within_request_control<controls_of<Op, Typed...>> =
	  (has_alternative<Typed, request_control> && ...);

	template<class List>
	concept operation_controls =
	  matches_table<List, request_control> && within_request_control<typename List::controls_of>;

	// encode_error "<name> is not valid on <operation> (<source>)", with
	// "an extended operation".
	[[nodiscard]] auto inapplicable_control(const control_rule &rule, operation_kind op) -> error;
}// namespace detail

static_assert(detail::operation_controls<search_controls>, "search_controls does not match the table");
static_assert(detail::operation_controls<add_controls>, "add_controls does not match the table");
static_assert(detail::operation_controls<modify_controls>, "modify_controls does not match the table");
static_assert(detail::operation_controls<modify_dn_controls>, "modify_dn_controls does not match the table");
static_assert(detail::operation_controls<del_controls>, "del_controls does not match the table");
static_assert(detail::operation_controls<compare_controls>, "compare_controls does not match the table");
static_assert(detail::operation_controls<extended_controls>, "extended_controls does not match the table");

// `controls` as the list of operation Ops::operation, for a list built
// once and reused: fails with encode_error ("pre_read is not valid on add
// (RFC 4527 section 3.1)") at the first control the operation does not
// take.
template<detail::operation_controls Ops>
[[nodiscard]] auto controls_for(const request_controls &controls) -> result<Ops>
{
	Ops out;
	out.reserve(controls.size());
	for (const auto &c : controls) {
		const bool taken = std::visit(
		  [&out](const auto &v) {
			  using T = std::remove_cvref_t<decltype(v)>;
			  if constexpr (detail::has_alternative<T, typename Ops::value_type>) {
				  out.emplace_back(v);
				  return true;
			  } else {
				  return false;
			  }
		  },
		  c);
		if (!taken) {
			return std::unexpected(std::visit(
			  [](const auto &v) {
				  return detail::inapplicable_control(
					control_rule_of<std::remove_cvref_t<decltype(v)>>, Ops::operation);
			  },
			  c));
		}
	}
	return out;
}

// ---------------------------------------------------------------- encoding

// The wire form of a control, on `mr`. Fail with encode_error for a
// negative page size, an invalid sort or sync mode, a matched values
// control without items, a negative VLV count or an offset below 1, invalid_filter for an empty (or too large)
// assertion filter or a matched values item RFC 3876 excludes.
[[nodiscard]] auto to_control(const control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const paged &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const manage_dsa_it &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const relax_rules &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const proxied_authorization &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
[[nodiscard]] auto to_control(const server_side_sort &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
[[nodiscard]] auto to_control(const assertion &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const pre_read &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const post_read &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const sync_request &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const matched_values &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<control>;
[[nodiscard]] auto to_control(const virtual_list_view &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
// Always critical (RFC 5805 section 2.2); the value is the identifier.
[[nodiscard]] auto to_control(const transaction_specification &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

namespace detail {
	// encode_error unless `wire` holds a sort request control: a list with a
	// virtual_list_view needs one (draft-ietf-ldapext-ldapv3-vlv-09 section
	// 6.1).
	[[nodiscard]] auto check_vlv_sort(const std::pmr::vector<control> &wire) -> result<void>;
	// encode_error if `wire` holds a proxied authorization control: a list
	// with a transaction_specification may not have one (RFC 5805 section
	// 4.4).
	[[nodiscard]] auto check_transaction_proxy(const std::pmr::vector<control> &wire) -> result<void>;

	// Whether a list holds a control of type T (false if it cannot).
	template<class T, class... A> [[nodiscard]] auto holds_any(const std::vector<std::variant<A...>> &controls) -> bool
	{
		if constexpr ((std::same_as<T, A> || ...)) {
			return std::ranges::any_of(controls, [](const auto &c) { return std::holds_alternative<T>(c); });
		} else {
			return false;
		}
	}
}// namespace detail

// Appends the wire form of every control of a list (an operation's, or
// request_controls) to `out`, on its resource; stops at the first that
// fails. A virtual_list_view without a sort request control (typed or raw)
// in `out` fails too, and so does a transaction_specification with a
// proxied authorization control (typed or raw) in `out`. Only a typed
// transaction_specification triggers that check: a raw control with
// transaction_specification_oid next to a proxied authorization control is
// sent unchecked.
template<class... Typed>
[[nodiscard]] auto append_controls(const std::vector<std::variant<control, Typed...>> &controls,
  std::pmr::vector<control> &out) -> result<void>
{
	const bool vlv = detail::holds_any<virtual_list_view>(controls);
	const bool transaction = detail::holds_any<transaction_specification>(controls);
	for (const auto &c : controls) {
		auto wire = std::visit([&out](const auto &v) { return to_control(v, out.get_allocator().resource()); }, c);
		if (!wire) {
			return std::unexpected(std::move(wire.error()));
		}
		out.push_back(std::move(*wire));
	}
	if (vlv) {
		if (auto ok = detail::check_vlv_sort(out); !ok) {
			return ok;
		}
	}
	if (transaction) {
		return detail::check_transaction_proxy(out);
	}
	return {};
}

// The paged results control among `controls` (e.g. a SearchResultDone's),
// nullopt if there is none, or decode_error if it is malformed.
[[nodiscard]] auto find_paged(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<paged_results>>;

// The sort result control among `controls` (a SearchResultDone's), nullopt
// if there is none, or decode_error if it is malformed. nullopt is a normal
// answer, even to a search that sent server_side_sort (see there): callers
// must handle it, as "not known to be sorted".
[[nodiscard]] auto find_sort_result(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<sort_result>>;

// The VLV response control among `controls` (a SearchResultDone's, kept
// by search_stream::controls() also when the search failed), nullopt if
// there is none, or decode_error if it is malformed.
[[nodiscard]] auto find_vlv_response(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<vlv_response>>;

// The entry of the pre-read response control (of a modify, delete or modify
// DN response) / post-read response control (of an add, modify or modify DN
// response) among `controls`, nullopt if there is none, or an error if it
// is malformed (decode_error, or message_too_large beyond decode_options'
// default element limit). The entry is allocated from `mr`.
[[nodiscard]] auto find_pre_read(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<entry>>;
[[nodiscard]] auto find_post_read(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<entry>>;

}// namespace jhetz::ldap
