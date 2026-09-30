// Error types shared by the whole library (DESIGN.md section 5).
#pragma once

#include <expected>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace jhetz::ldap {

// RFC 4511 resultCode values (section 4.1.9 and Appendix A), numbers kept
// exactly so that `static_cast<int>(errc::invalid_credentials) == 49`.
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
	// 72-79 unused
	other = 80,
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
	would_deadlock,// blocking call made from the client's I/O thread
	unexpected_tag,// well-formed element, but not the expected tag
	unsupported_operation,// LDAPMessage protocolOp this library does not know
	invalid_dn,// RFC 4514 DN text could not be parsed
	invalid_attribute,// not a valid attribute description (RFC 4512)
	encode_error,// value out of range for the LDAP message being encoded
	invalid_url,// RFC 4516 LDAP URL could not be parsed, or cannot be used to connect
};

const std::error_category &result_category() noexcept;// "ldap.result"
const std::error_category &client_category() noexcept;// "ldap.client"

inline std::error_code make_error_code(errc e) noexcept { return { static_cast<int>(e), result_category() }; }

inline std::error_code make_error_code(client_errc e) noexcept { return { static_cast<int>(e), client_category() }; }

struct error
{
	std::error_code code{};
	std::string diagnostic{};// server's diagnosticMessage, if any
	// TODO: becomes std::optional<ldap::dn> once the dn type exists.
	std::optional<std::string> matched_dn{};// server's matchedDN, if any
	// TODO: becomes std::vector<ldap::url> once the url type exists.
	std::vector<std::string> referrals{};// from a referral result
	std::string context{};// client-side path, e.g. "ber: integer at offset 12"

	// Everything above, human readable, on one line.
	std::string message() const;

	friend bool operator==(const error &, const error &) = default;
};

template<class T> using result = std::expected<T, error>;

// Builds an error carrying only a code and a client-side context string.
inline error make_error(std::error_code code, std::string context = {})
{
	error e;
	e.code = code;
	e.context = std::move(context);
	return e;
}

// Shorthand for `return std::unexpected(make_error(...));`.
inline std::unexpected<error> fail(std::error_code code, std::string context = {})
{
	return std::unexpected(make_error(code, std::move(context)));
}

}// namespace jhetz::ldap

template<> struct std::is_error_code_enum<jhetz::ldap::errc> : std::true_type
{
};

template<> struct std::is_error_code_enum<jhetz::ldap::client_errc> : std::true_type
{
};
