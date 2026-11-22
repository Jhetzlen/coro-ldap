// Typed request controls, per-operation control lists and readers for the
// typed response controls (docs/API.md, "jhetz/ldap/controls.hpp").
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

// Simple Paged Results (RFC 2696).
struct paged
{
	std::int32_t page_size = 0;
	std::string cookie{};
	bool critical = false;
};

// ManageDsaIT (RFC 3296). No value.
inline constexpr std::string_view manage_dsa_it_oid = "2.16.840.1.113730.3.4.2";
struct manage_dsa_it
{
	bool critical = false;
};

// Relax Rules (draft-zeilenga-ldap-relax). No value; critical by default.
inline constexpr std::string_view relax_rules_oid = "1.3.6.1.4.1.4203.666.5.12";
struct relax_rules
{
	bool critical = true;
};

// Proxied Authorization (RFC 4370); always critical.
inline constexpr std::string_view proxied_authorization_oid = "2.16.840.1.113730.3.4.18";
struct proxied_authorization
{
	std::string authz_id{};
};

// Server Side Sorting (RFC 2891).
struct sort_key
{
	std::string attribute{};// attributeType
	std::string ordering_rule{};// orderingRule [0]; empty: the attribute's ORDERING
	bool reverse = false;// reverseOrder [1]
};
struct server_side_sort
{
	std::vector<sort_key> keys{};
	bool critical = false;
};

// Assertion (RFC 4528); critical by default.
inline constexpr std::string_view assertion_oid = "1.3.6.1.1.12";
struct assertion
{
	ldap::filter filter{};
	bool critical = true;
};

// Pre-Read / Post-Read (RFC 4527).
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

// Matched Values (RFC 3876).
inline constexpr std::string_view matched_values_oid = "1.2.826.0.1.3344810.2.3";
struct matched_values
{
	std::vector<ldap::filter> values_return_filter{};
	bool critical = false;

	friend auto operator==(const matched_values &, const matched_values &) -> bool = default;
};

// The string form of a ValuesReturnFilter (RFC 3876 section 5).
[[nodiscard]] auto parse_values_return_filter(std::string_view text,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::vector<ldap::filter>>;

// Virtual List View (draft-ietf-ldapext-ldapv3-vlv-09); needs a
// server_side_sort on the same search.
struct vlv_by_offset
{
	std::int32_t offset = 1;
	std::int32_t content_count = 0;

	friend auto operator==(const vlv_by_offset &, const vlv_by_offset &) -> bool = default;
};
struct vlv_greater_than_or_equal
{
	std::string value{};// AssertionValue, by the primary sort key's ORDERING rule

	friend auto operator==(const vlv_greater_than_or_equal &, const vlv_greater_than_or_equal &) -> bool = default;
};
struct virtual_list_view
{
	std::int32_t before_count = 0;
	std::int32_t after_count = 0;
	std::variant<vlv_by_offset, vlv_greater_than_or_equal> target{};// byOffset [0] / greaterThanOrEqual [1]
	std::optional<std::string> context_id{};
	bool critical = false;

	friend auto operator==(const virtual_list_view &, const virtual_list_view &) -> bool = default;
};

// Transaction Specification (RFC 5805 section 2.2); always critical.
struct transaction_specification
{
	std::string identifier{};

	friend auto operator==(const transaction_specification &, const transaction_specification &) -> bool = default;
};

// ---------------------------------------------------------------- per-operation lists

// The request messages a typed control can go on (RFC 4511 operations).
enum class operation_kind : std::uint8_t {
	search,
	add,
	modify,
	modify_dn,
	del,
	compare,
	extended,
};
inline constexpr std::size_t operation_kind_count = std::to_underlying(operation_kind::extended) + 1;

// The operation as error contexts name it.
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

template<std::same_as<operation_kind>... Op>
[[nodiscard]] constexpr auto operation_set_of(Op... op) noexcept -> operation_set
{
	return { .bits = static_cast<std::uint8_t>((0U | ... | (1U << std::to_underlying(op)))) };
}

// One row of the applicability table.
struct control_rule
{
	std::string_view name;
	std::string_view source;
	operation_set operations;
};

// The applicability table: where each typed request control may be sent,
// as its specification says.
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
	inline constexpr operation_set interrogation_and_update = operation_set_of(operation_kind::search,
	  operation_kind::add,
	  operation_kind::modify,
	  operation_kind::modify_dn,
	  operation_kind::del,
	  operation_kind::compare);
}// namespace detail

// The raw control: allowed everywhere.
template<>
inline constexpr control_rule control_rule_of<control> = { .name = "control",
	.source = "raw",
	.operations = detail::all_operations };
// RFC 2696 section 2.
template<>
inline constexpr control_rule control_rule_of<paged> = { .name = "paged",
	.source = "RFC 2696 section 2",
	.operations = operation_set_of(operation_kind::search) };
// RFC 3296 section 3; no typed extended operation defines it.
template<>
inline constexpr control_rule control_rule_of<manage_dsa_it> = { .name = "manage_dsa_it",
	.source = "RFC 3296 section 3",
	.operations = detail::interrogation_and_update };
// draft-zeilenga-ldap-relax-03 section 2: update requests.
template<>
inline constexpr control_rule control_rule_of<relax_rules> = { .name = "relax_rules",
	.source = "draft-zeilenga-ldap-relax-03 section 2",
	.operations =
	  operation_set_of(operation_kind::add, operation_kind::modify, operation_kind::modify_dn, operation_kind::del) };
// RFC 4370 section 3.
template<>
inline constexpr control_rule control_rule_of<proxied_authorization> = { .name = "proxied_authorization",
	.source = "RFC 4370 section 3",
	.operations = detail::all_operations };
// RFC 2891 section 1.1.
template<>
inline constexpr control_rule control_rule_of<server_side_sort> = { .name = "server_side_sort",
	.source = "RFC 2891 section 1.1",
	.operations = operation_set_of(operation_kind::search) };
// RFC 4528 section 3; no typed extended operation defines it.
template<>
inline constexpr control_rule control_rule_of<assertion> = { .name = "assertion",
	.source = "RFC 4528 section 3",
	.operations = detail::interrogation_and_update };
// RFC 4527 section 3.1.
template<>
inline constexpr control_rule control_rule_of<pre_read> = { .name = "pre_read",
	.source = "RFC 4527 section 3.1",
	.operations = operation_set_of(operation_kind::modify, operation_kind::modify_dn, operation_kind::del) };
// RFC 4527 section 3.2.
template<>
inline constexpr control_rule control_rule_of<post_read> = { .name = "post_read",
	.source = "RFC 4527 section 3.2",
	.operations = operation_set_of(operation_kind::add, operation_kind::modify, operation_kind::modify_dn) };
// RFC 4533 section 2.2.
template<>
inline constexpr control_rule control_rule_of<sync_request> = { .name = "sync_request",
	.source = "RFC 4533 section 2.2",
	.operations = operation_set_of(operation_kind::search) };

// RFC 3876 section 2.
template<>
inline constexpr control_rule control_rule_of<matched_values> = { .name = "matched_values",
	.source = "RFC 3876 section 2",
	.operations = operation_set_of(operation_kind::search) };

// draft-ietf-ldapext-ldapv3-vlv-09 section 6.1.
template<>
inline constexpr control_rule control_rule_of<virtual_list_view> = { .name = "virtual_list_view",
	.source = "draft-ietf-ldapext-ldapv3-vlv-09 section 6.1",
	.operations = operation_set_of(operation_kind::search) };

// RFC 5805 section 2.2; Password Modify takes it only as a raw control.
template<>
inline constexpr control_rule control_rule_of<transaction_specification> = { .name = "transaction_specification",
	.source = "RFC 5805 section 2.2",
	.operations =
	  operation_set_of(operation_kind::add, operation_kind::modify, operation_kind::modify_dn, operation_kind::del) };

template<class T> [[nodiscard]] constexpr auto applies_to(operation_kind op) noexcept -> bool
{
	return control_rule_of<T>.operations.contains(op);
}

// Any typed control or a raw one, for a list shared by several operations.
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

// The controls `Op` takes: the raw control and the typed ones the table
// allows there.
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

	// List holds exactly the alternatives the table allows on List::operation.
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

	// encode_error "<name> is not valid on <operation> (<source>)".
	[[nodiscard]] auto inapplicable_control(const control_rule &rule, operation_kind op) -> error;
}// namespace detail

static_assert(detail::operation_controls<search_controls>, "search_controls does not match the table");
static_assert(detail::operation_controls<add_controls>, "add_controls does not match the table");
static_assert(detail::operation_controls<modify_controls>, "modify_controls does not match the table");
static_assert(detail::operation_controls<modify_dn_controls>, "modify_dn_controls does not match the table");
static_assert(detail::operation_controls<del_controls>, "del_controls does not match the table");
static_assert(detail::operation_controls<compare_controls>, "compare_controls does not match the table");
static_assert(detail::operation_controls<extended_controls>, "extended_controls does not match the table");

// `controls` as the list of Ops::operation; encode_error at the first
// control the operation does not take.
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

// The wire form of a control, on `mr`.
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
[[nodiscard]] auto to_control(const transaction_specification &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;

namespace detail {
	// encode_error unless `wire` holds a sort request control.
	[[nodiscard]] auto check_vlv_sort(const std::pmr::vector<control> &wire) -> result<void>;
	// encode_error if `wire` holds a proxied authorization control.
	[[nodiscard]] auto check_transaction_proxy(const std::pmr::vector<control> &wire) -> result<void>;

	// Whether a list holds a control of type T.
	template<class T, class... A> [[nodiscard]] auto holds_any(const std::vector<std::variant<A...>> &controls) -> bool
	{
		if constexpr ((std::same_as<T, A> || ...)) {
			return std::ranges::any_of(controls, [](const auto &c) { return std::holds_alternative<T>(c); });
		} else {
			return false;
		}
	}
}// namespace detail

// Appends the wire form of every control of a list to `out`; stops at the
// first failure.
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

// The paged results control among `controls`; nullopt if absent.
[[nodiscard]] auto find_paged(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<paged_results>>;

// The sort result control among `controls`; nullopt if absent.
[[nodiscard]] auto find_sort_result(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<sort_result>>;

// The VLV response control among `controls`; nullopt if absent.
[[nodiscard]] auto find_vlv_response(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<vlv_response>>;

// The entry of the pre-read / post-read response control, allocated from
// `mr`; nullopt if absent.
[[nodiscard]] auto find_pre_read(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<entry>>;
[[nodiscard]] auto find_post_read(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<entry>>;

}// namespace jhetz::ldap
