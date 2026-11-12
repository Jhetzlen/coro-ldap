// Error types shared by the whole library (DESIGN.md section 5).
#pragma once

#include <expected>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace jhetz::ldap {

// RFC 4511 resultCode values (section 4.1.9 and Appendix A), numbers kept
// exactly so that `std::to_underlying(errc::invalid_credentials) == 49`.
//
// `success` (0) is deliberately not an enumerator: a std::error_code with
// value 0 means "no error", so a successful LDAP result is represented by the
// absence of an ldap::error, never by an error_code: the message layer maps
// resultCode 0 to a value, not an error. The category still describes value
// 0 as "success" for completeness.
//
// Some codes are not failures in every context (compare_false, compare_true,
// referral, sasl_bind_in_progress); they are listed so every resultCode a
// server can send has a name. Higher layers decide which ones become errors.
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
	// 72-75 and 77-79 unused (76, virtual_list_view_error, is an extension's, below)
	other = 80,
	// Codes defined by extensions (RFC 4520 IANA registry)
	// draft-ietf-ldapext-ldapv3-vlv-09 section 6.2.1: the search failed
	// because of its virtual_list_view control; the VLV response control
	// (find_vlv_response) says why.
	virtual_list_view_error = 76,
	assertion_failed = 122,// RFC 4528: the assertion control's filter did not match
	// RFC 4533 section 3.8: the server cannot continue the sync search; resend
	// it with the cookie of the result's Sync Done control (find_sync_done),
	// or with no cookie (a full reload) if there is none.
	e_sync_refresh_required = 4096,
};

// Failures detected by the client itself. Values start at 1 (0 is "no
// error"); new values are only ever appended so existing numbers stay stable.
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
	tls_required,// refused on a connection without TLS (channel binding; an AD password change without a SASL
				 // confidentiality layer either)
	gssapi_failure,// a GSS-API (Kerberos) call failed during a SASL GSSAPI bind
	security_layer_required,// the server requires a SASL security layer (integrity, confidentiality)
	internal_error,// a library the client uses failed (OpenSSL, ICU), not the caller's input
	string_prep_failed,// RFC 4518 string preparation refused the value (ill-formed UTF-8, prohibited code point)
	// The connection closed (or was closed) before the request was handed to
	// its writer: the server never saw it, so even an update may be retried
	// on another connection. Matches cond::connection_lost, like
	// not_connected.
	not_sent,
	// The server does not offer the SASL security layer asked for
	// (sasl_gssapi_options::security_layer, sasl_ntlm_options::
	// security_layer), or it cannot be used here (NTLM's over TLS). Matches
	// cond::access_denied.
	security_layer_unavailable,
	// Refused while a SASL security layer is in effect: StartTLS (TLS would
	// have to go below the layer, RFC 4513 section 5.2.1.6), or a second
	// layer. Matches no condition.
	security_layer_in_effect,
	// repository::update with a naming member that differs from the original's:
	// the entry would need a new DN (repository::rename). Matches
	// cond::invalid_input.
	naming_value_changed,
	// decode<T> on an entry holding a mapped attribute with a range option
	// (Active Directory's member;range=0-1499): the entry has only part of
	// its values (ldap::ad::read_all_values reads them all). Matches no
	// condition.
	incomplete_values,
	// repository::update_if with its default guard, schema_check on, on a struct
	// with a writable member whose attribute has no EQUALITY rule: an
	// assertion on it is always Undefined (RFC 4511 section 4.5.1.7), so
	// the server would answer assertionFailed every time. Matches
	// cond::invalid_input.
	no_equality_rule,
};

// Error conditions: what an error means, across categories (DESIGN.md
// section 5), so callers test meaning rather than exact codes:
//
//   if (r.error().code == ldap::cond::auth_failed) ...
//
// Each code maps to at most one condition; codes with no clear meaning for
// a caller (size_limit_exceeded, referral, other, ...) match none. The full
// table is in DESIGN.md section 5. Codes from outside this library are
// matched too: system codes through their generic condition
// (std::errc::timed_out, connection_reset, ...), Capy's by category name
// ("boost.capy": eof, stream_truncated; canceled and timeout through their
// generic conditions) and TLS errors by category ("corosio.openssl"), so
// this header needs neither Capy nor Corosio.
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
//
// Memory (DESIGN.md section 8): the strings are std::pmr containers, but error
// is deliberately not allocator-aware (no allocator_type). The library always
// builds errors on the default resource, never on a caller's arena, even when
// it fails while decoding into one: errors travel up the call stack and into
// logs, often after the arena of the failed operation was released, so they
// must not depend on it. Copies use the default resource too, as for any pmr
// container. Errors are the cold path, so the extra allocations do not matter.
struct error
{
	std::error_code code{};
	std::pmr::string diagnostic{};// server's diagnosticMessage, if any
	// matched_dn and referrals stay text, exactly as the server sent them
	// (DESIGN.md section 5): a server's matchedDN or referral URI may not
	// parse as ldap::dn / ldap::url, and an error must not lose it or fail to
	// be built. Parse on demand with dn::parse / url::parse. (dn.hpp and
	// url.hpp also depend on this header for result<T>.)
	std::optional<std::pmr::string> matched_dn{};// server's matchedDN, if any
	std::pmr::vector<std::pmr::string> referrals{};// from a referral result
	std::pmr::string context{};// client-side path, e.g. "ber: integer at offset 12"

	// Everything above, human readable, on one line. The server's text
	// (diagnostic, matched_dn, referrals) is shown sanitized, so a hostile
	// server cannot break the line or change how a log or terminal displays
	// it: valid UTF-8 is kept; control characters (C0, DEL, C1), bidi
	// controls, U+2028/U+2029 and ill-formed UTF-8 become U+FFFD; each string
	// is cut at 256 bytes on a character boundary ("..." marks the cut), and
	// at most 8 referrals are listed. The fields above keep the text exactly
	// as the server sent it.
	[[nodiscard]] auto message(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	friend auto operator==(const error &, const error &) -> bool = default;
};

template<class T> using result = std::expected<T, error>;

// Builds an error carrying only a code and a client-side context string.
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
	// `e` with `prefix` in front of its context ("prefix: context", or just
	// "prefix" for an empty one).
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
