// Error types shared by the whole library (DESIGN.md section 5).
#pragma once

#include <expected>
#include <memory_resource>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace jhetz::ldap {

// RFC 4511 resultCode values (section 4.1.9 and Appendix A), numbers kept.
// No success (0): a successful result is the absence of an error.
enum class errc : int {
	operations_error = 1,
	protocol_error = 2,
	time_limit_exceeded = 3,
	size_limit_exceeded = 4,
	compare_false = 5,
	compare_true = 6,
	auth_method_not_supported = 7,
	stronger_auth_required = 8,
	// 9 reserved
	referral = 10,
	admin_limit_exceeded = 11,
	unavailable_critical_extension = 12,
	confidentiality_required = 13,
	sasl_bind_in_progress = 14,
	no_such_attribute = 16,
	undefined_attribute_type = 17,
	inappropriate_matching = 18,
	constraint_violation = 19,
	attribute_or_value_exists = 20,
	invalid_attribute_syntax = 21,
	// 22-31 unused
	no_such_object = 32,
	alias_problem = 33,
	invalid_dn_syntax = 34,
	// 35 reserved for undefined isLeaf
	alias_dereferencing_problem = 36,
	// 37-47 unused
	inappropriate_authentication = 48,
	invalid_credentials = 49,
	insufficient_access_rights = 50,
	busy = 51,
	unavailable = 52,
	unwilling_to_perform = 53,
	loop_detect = 54,
	// 55-63 unused
	naming_violation = 64,
	object_class_violation = 65,
	not_allowed_on_non_leaf = 66,
	not_allowed_on_rdn = 67,
	entry_already_exists = 68,
	object_class_mods_prohibited = 69,
	// 70 reserved for CLDAP
	affects_multiple_dsas = 71,
	// 72-75 and 77-79 unused
	other = 80,
	// Codes defined by extensions (RFC 4520 IANA registry):
	// draft-ietf-ldapext-ldapv3-vlv-09 section 6.2.1.
	virtual_list_view_error = 76,
	assertion_failed = 122,// RFC 4528
	// RFC 4533 section 3.8
	e_sync_refresh_required = 4096,
};

// Failures detected by the client itself; values are only ever appended.
enum class client_errc : int {
	decode_error = 1,// malformed BER / protocol data
	message_too_large,// declared size exceeds the configured maximum
	nesting_too_deep,// constructed elements nested beyond the limit
	unsupported_tag,// high-tag-number form (tag number >= 31)
	integer_overflow,// INTEGER / ENUMERATED does not fit in 64 bits
	invalid_filter,// RFC 4515 filter text could not be parsed
	missing_attribute,// required attribute absent from an entry
	too_many_values,// single-valued mapping got several values
	conversion_failed,// value_traits<T>::decode failed
	schema_mismatch,// runtime schema validation reported errors
	would_deadlock,// blocking call made from a sync::connection's I/O thread
	unexpected_tag,// well-formed element, but not the expected tag
	unsupported_operation,// LDAPMessage protocolOp this library does not know
	invalid_dn,// RFC 4514 DN text could not be parsed
	invalid_attribute,// not a valid attribute description (RFC 4512)
	encode_error,// value out of range for the LDAP message being encoded
	invalid_url,// RFC 4516 LDAP URL could not be parsed, or cannot be used to connect
	unexpected_response,// server message that does not answer the request in flight (id, operation)
	not_connected,// connection closed (unbind, close, or an earlier failure)
	operation_in_progress,// the connection is busy with another operation or an open search_stream
	unauthenticated_bind,// simple bind with a name and an empty password (RFC 4513 section 5.1.2)
	tls_required,// refused on a connection without TLS (or a SASL confidentiality layer)
	gssapi_failure,// a GSS-API (Kerberos) call failed during a SASL GSSAPI bind
	security_layer_required,// the server requires a SASL security layer (integrity, confidentiality)
	internal_error,// a library the client uses failed (OpenSSL, ICU), not the caller's input
	string_prep_failed,// RFC 4518 string preparation refused the value (ill-formed UTF-8, prohibited code point)
	// The connection closed before the request reached its writer: the server
	// never saw it. Matches cond::connection_lost.
	not_sent,
	// The SASL security layer asked for is not offered, or not usable here.
	// Matches cond::access_denied.
	security_layer_unavailable,
	// Refused while a SASL security layer is in effect. Matches no condition.
	security_layer_in_effect,
	// repository::update with a changed naming member. Matches
	// cond::invalid_input.
	naming_value_changed,
	// decode<T> on an entry with a ranged attribute (AD's member;range=0-1499).
	// Matches no condition.
	incomplete_values,
	// update_if's default guard on a member without an EQUALITY rule. Matches
	// cond::invalid_input.
	no_equality_rule,
	// A request held behind a bind that failed or did not complete: never
	// sent. Matches cond::auth_failed.
	bind_failed,
};

// Error conditions: what an error means across categories, Capy, system
// and TLS codes included (table: DESIGN.md section 5).
enum class cond : int {
	not_found = 1,// the entry (or attribute) does not exist
	auth_failed,// bad credentials, or an authentication method refused
	timeout,// a client deadline or the server's time limit
	canceled,// cancelled through a stop token
	connection_lost,// the connection closed or broke (or was never open)
	tls_failure,// TLS handshake or record layer failure
	protocol_error,// malformed or unexpected data from the peer
	busy_or_unavailable,// the server is busy, unavailable or unreachable: retry later or elsewhere
	access_denied,// not allowed with the current authorization
	already_exists,// the entry or value already exists
	invalid_input,// a request the client or the server rejected as malformed
};

auto result_category() noexcept -> const std::error_category &;// "ldap.result"
auto client_category() noexcept -> const std::error_category &;// "ldap.client"
auto cond_category() noexcept -> const std::error_category &;// "ldap.cond"

[[nodiscard]] inline auto make_error_code(errc e) noexcept -> std::error_code
{
	return { std::to_underlying(e), result_category() };
}

[[nodiscard]] inline auto make_error_code(client_errc e) noexcept -> std::error_code
{
	return { std::to_underlying(e), client_category() };
}

[[nodiscard]] inline auto make_error_condition(cond c) noexcept -> std::error_condition
{
	return { std::to_underlying(c), cond_category() };
}

// An error: its code plus what the server and the client said about it.
// Not allocator-aware: always on the default resource.
struct error
{
	std::error_code code{};
	// The server's LDAPResult fields, as sent; empty when none.
	std::pmr::string matched_dn{};
	std::pmr::string diagnostic_message{};
	std::pmr::vector<std::pmr::string> referrals{};// from a referral result
	std::pmr::string context{};// client-side path, e.g. "ber: integer at offset 12"

	// Everything above on one line, the server's text sanitized and cut at 256
	// bytes, at most 8 referrals.
	[[nodiscard]] auto message(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	friend auto operator==(const error &, const error &) -> bool = default;
};

template<class T> using result = std::expected<T, error>;

[[nodiscard]] inline auto make_error(std::error_code code, std::string_view context = {}) -> error
{
	error e;
	e.code = code;
	e.context.assign(context);
	return e;
}

// Shorthand for `return std::unexpected(make_error(...));`.
[[nodiscard]] inline auto fail(std::error_code code, std::string_view context = {}) -> std::unexpected<error>
{
	return std::unexpected(make_error(code, context));
}

namespace detail {
	// `e` with "prefix: " in front of its context.
	[[nodiscard]] auto with_context(error e, std::string_view prefix) -> error;
}// namespace detail

}// namespace jhetz::ldap

template<> struct std::is_error_code_enum<jhetz::ldap::errc> : std::true_type
{
};

template<> struct std::is_error_code_enum<jhetz::ldap::client_errc> : std::true_type
{
};

template<> struct std::is_error_condition_enum<jhetz::ldap::cond> : std::true_type
{
};
