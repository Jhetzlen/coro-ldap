// The requests of ldap::connection's operations as plain aggregates, the
// ldap::mod builders, what the operations return, and extended operation
// OIDs. Part of jhetz::ldap (the codec).
#pragma once

#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/timeout.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

// A dn with no default constructor, so a search names its base.
struct search_base : dn
{
	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): `.base = ldap::dn{...}`
	search_base(dn base) : dn(std::move(base)) {}
};

// A search; `base` is required. Values are validated when encoded.
struct search_params
{
	search_base base;// ldap::dn{} is the root DSE
	search_scope scope = search_scope::whole_subtree;
	ldap::filter filter = filters::attr("objectClass").present();
	// Descriptions, "*", "+" (RFC 3673) or "1.1"; empty: all user attributes.
	string_list attributes{};
	deref_aliases deref = deref_aliases::never;
	std::int32_t size_limit = 0;// 0: no limit requested
	std::chrono::seconds time_limit{ 0 };// sent to the server; 0: no limit requested
	bool types_only = false;
	search_controls controls{};
	// Client-side limit for the whole search; nullopt:
	// connection_options::operation_timeout.
	std::optional<std::chrono::milliseconds> timeout{};
	// Keep IntermediateResponses (RFC 4511 section 4.13) for next_item().
	bool intermediate_responses = false;
	// Overrides referral_options::follow_referrals for this request.
	std::optional<bool> follow_referrals{};
	// Overrides referral_options::follow_references for this request.
	std::optional<bool> follow_references{};
};

// The root DSE read (RFC 4512 section 5.1).
[[nodiscard]] inline auto root_dse(string_list attributes = { "*", "+" }) -> search_params
{
	return { .base = dn{}, .scope = search_scope::base_object, .attributes = std::move(attributes) };
}

// Where a referral URL came from.
enum class reference_kind : std::uint8_t {
	referral,// the referral field of an LDAPResult (RFC 4511 section 4.1.10)
	continuation_reference,// a SearchResultReference (section 4.5.3)
};

// What became of one URI a referral chase considered.
enum class referral_outcome : std::uint8_t {
	// Sent to the target and answered.
	followed,
	skipped_policy,// the connector returned null
	skipped_loop,// that server already got the same request in this chase
	limit_reached,// over max_hops or max_targets, or the timeout was spent
	unparseable,// cannot be followed: see failure
	failed,// the connector or the request failed: see failure
};

// One URI a chase considered, in the order it got to it.
struct referral_attempt
{
	std::string uri{};// as the server sent it
	reference_kind kind = reference_kind::referral;
	std::size_t depth = 1;// 1: returned by the origin's server
	referral_outcome outcome = referral_outcome::followed;
	std::optional<error> failure{};// unparseable and failed: why

	friend auto operator==(const referral_attempt &, const referral_attempt &) -> bool = default;
};

// A search run to its end: the entries, the URIs of the references not
// followed, the SearchResultDone's LDAPResult and controls, and what a
// referral chase did.
template<class Entries> struct basic_search_result
{
	Entries entries{};
	string_list references{};// one string per URI, as sent
	std::int32_t result_code = 0;
	std::pmr::string matched_dn{};
	std::pmr::string diagnostic_message{};
	std::pmr::vector<control> controls{};
	// At most referral_policy::max_attempts.
	std::vector<referral_attempt> referrals{};
	// URIs a chase considered that are not in `referrals`.
	std::size_t unlisted = 0;

	[[nodiscard]] auto is_success() const noexcept -> bool { return result_code == 0; }
	// result_code in result_category(), comparable with errc.
	[[nodiscard]] auto code() const noexcept -> std::error_code { return { result_code, result_category() }; }
	// resultCode success and no continuation reference left unfollowed.
	[[nodiscard]] auto is_complete() const noexcept -> bool { return is_success() && references.empty(); }

	friend auto operator==(const basic_search_result &, const basic_search_result &) -> bool = default;
};

using search_result = basic_search_result<std::pmr::vector<entry>>;
template<class T> using typed_search_result = basic_search_result<std::vector<T>>;

// AddRequest (RFC 4511 section 4.7); each attribute needs a value.
struct add_params
{
	dn entry{};
	std::pmr::vector<partial_attribute> attributes{};// {"cn", {"Jane Doe"}}, ...
	add_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ModifyRequest (RFC 4511 section 4.6): changes applied in order, atomically.
struct modify_params
{
	dn object{};
	std::pmr::vector<modify_change> changes{};
	modify_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

namespace mod {
	[[nodiscard]] auto add(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change;
	// Deletes the given values, or the whole attribute if none are given.
	[[nodiscard]] auto remove(std::string_view type, std::initializer_list<std::string_view> values = {})
	  -> modify_change;
	// Replaces all values (none: deletes the attribute if present).
	[[nodiscard]] auto replace(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change;
	template<string_range R> [[nodiscard]] auto add(std::string_view type, R &&values) -> modify_change
	{
		return { modify_operation::add, partial_attribute(type, std::forward<R>(values)) };
	}
	template<string_range R> [[nodiscard]] auto remove(std::string_view type, R &&values) -> modify_change
	{
		return { modify_operation::delete_, partial_attribute(type, std::forward<R>(values)) };
	}
	template<string_range R> [[nodiscard]] auto replace(std::string_view type, R &&values) -> modify_change
	{
		return { modify_operation::replace, partial_attribute(type, std::forward<R>(values)) };
	}
	// RFC 4525 Modify-Increment.
	[[nodiscard]] auto increment(std::string_view type, std::string_view delta = "1") -> modify_change;
}// namespace mod

// DelRequest (RFC 4511 section 4.8).
struct del_params
{
	dn entry{};
	del_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// ModifyDNRequest (RFC 4511 section 4.9): rename and/or move.
struct modify_dn_params
{
	dn entry{};
	rdn new_rdn{};
	bool delete_old_rdn = true;
	std::optional<dn> new_superior{};
	modify_dn_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// CompareRequest (RFC 4511 section 4.10).
struct compare_params
{
	dn entry{};
	std::string attribute{};
	std::string value{};
	compare_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
	// As search_params::follow_referrals.
	std::optional<bool> follow_referrals{};
};

// compareTrue / compareFalse as `value`, with the answering response's
// fields and what a referral chase did.
struct compare_result
{
	bool value = false;
	std::pmr::string matched_dn{};
	std::pmr::string diagnostic_message{};
	std::pmr::vector<control> controls{};
	std::vector<referral_attempt> referrals{};
	std::size_t unlisted = 0;

	friend auto operator==(const compare_result &, const compare_result &) -> bool = default;
};

// ExtendedRequest (RFC 4511 section 4.12).
struct extended_params
{
	std::string name{};// requestName
	std::optional<std::string> value{};// requestValue, as encoded for that operation
	extended_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
	// Collect IntermediateResponses into extended_result::intermediates.
	bool intermediate_responses = false;
};

// What a successful operation returns besides success (RFC 4511 section
// 4.1.9 fields and the response's controls).
struct response
{
	std::int32_t message_id = 0;
	std::pmr::string matched_dn{};// as sent
	std::pmr::string diagnostic_message{};// as sent; empty: none
	std::pmr::vector<control> controls{};
};

// An IntermediateResponse (RFC 4511 section 4.13) with its message's controls.
struct intermediate : intermediate_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<control> controls{};

	intermediate() = default;
	explicit intermediate(const allocator_type &alloc) : intermediate_response(alloc), controls(alloc) {}
	// Takes the strings when on `alloc`'s resource, else copies them onto it.
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
	// Empty unless extended_params::intermediate_responses is set.
	std::pmr::vector<intermediate> intermediates{};
};

// RFC 4532 "Who am I?".
inline constexpr std::string_view who_am_i_oid = "1.3.6.1.4.1.4203.1.11.3";

// RFC 3062 Password Modify.
inline constexpr std::string_view password_modify_oid = "1.3.6.1.4.1.4203.1.11.1";

struct password_modify_params
{
	// userIdentity; nullopt: the bound user.
	std::optional<std::string> user{};
	// oldPasswd
	std::optional<std::string> old_password{};
	// newPasswd; nullopt: the server generates one.
	std::optional<std::string> new_password{};
	extended_controls controls{};
	std::optional<std::chrono::milliseconds> timeout{};
};

// A successful End Transaction (RFC 5805 section 2.3): the updates' response
// controls by message id, and the response's own controls.
struct end_transaction_result
{
	std::pmr::vector<update_controls> updates_controls{};
	std::pmr::vector<control> controls{};

	// Null if the server returned none for that update.
	[[nodiscard]] auto find_update_controls(std::int32_t message_id) const noexcept
	  -> const std::pmr::vector<control> *;
};

namespace detail {
	// "search ou=people,dc=example,dc=org"; the DN sanitized and cut at 256 bytes.
	[[nodiscard]] auto op_context(std::string_view op, const dn &d) -> std::string;
}// namespace detail

}// namespace jhetz::ldap
