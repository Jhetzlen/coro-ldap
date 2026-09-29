// RFC 4511 LDAPMessage: a faithful wire model of every protocol operation
// (requests and responses, so a mock server can reuse it) and its BER codec.
//
// Field types: every LDAPDN, RelativeLDAPDN, LDAPString, LDAPOID,
// AttributeDescription and OCTET STRING of the wire format is a std::string
// here, holding the bytes exactly as sent (values may be binary). The
// validating vocabulary types (ldap::dn, ldap::attribute) belong to the API
// layer built on top: keeping them out of the wire model means a server that
// sends an odd DN or attribute name never breaks decoding.
//
// Decoding follows RFC 4511 section 4:
// - unknown elements at the end of a SEQUENCE are skipped (they must still be
//   well-formed BER); optional components are only recognized in their
//   defined order, so an out-of-order one counts as such an unknown element;
// - an unknown protocolOp fails with client_errc::unsupported_operation;
// - enumerations the model relies on (scope, derefAliases, modify operation)
//   and INTEGER ranges (message id, version, limits) are checked and fail
//   with decode_error, but unknown resultCode values are kept;
// - SEQUENCE OF / SET OF with SIZE (1..MAX) (referral, attribute values of
//   AddRequest, search references) are accepted when empty; an empty list is
//   the same as an absent one in this model;
// - nesting is bounded by ber::reader's depth limit, and nothing is allocated
//   from a length that was not checked against the input first.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace jhetz::ldap {

// MessageID ::= INTEGER (0 .. maxInt), maxInt = 2^31 - 1
inline constexpr std::int32_t max_int = 2'147'483'647;

// ---------------------------------------------------------------- shared parts

// LDAPResult (RFC 4511 section 4.1.9).
struct ldap_result
{
	std::int32_t result_code = 0;// RFC 4511 resultCode; unknown values are kept
	std::string matched_dn{};
	std::string diagnostic_message{};
	std::vector<std::string> referral{};// [3] Referral OPTIONAL; empty = absent

	bool is_success() const noexcept { return result_code == 0; }

	// The result as an ldap::error: code in result_category() (unknown codes
	// keep their number and get a generic message), diagnostic, matched DN
	// (when not empty), referral URIs and `context`. For a success result the
	// code is 0, i.e. "no error"; callers check is_success() first.
	error to_error(std::string context = {}) const;

	friend bool operator==(const ldap_result &, const ldap_result &) = default;
};

// Control (RFC 4511 section 4.1.11).
struct control
{
	std::string type{};// LDAPOID
	bool criticality = false;// DEFAULT FALSE: omitted from the encoding when false
	std::optional<std::string> value{};

	friend bool operator==(const control &, const control &) = default;
};

// PartialAttribute / Attribute (RFC 4511 section 4.1.7).
struct partial_attribute
{
	std::string type{};
	std::vector<std::string> values{};

	friend bool operator==(const partial_attribute &, const partial_attribute &) = default;
};

// AttributeValueAssertion (RFC 4511 section 4.1.8).
struct attribute_value_assertion
{
	std::string attribute_desc{};
	std::string assertion_value{};

	friend bool operator==(const attribute_value_assertion &, const attribute_value_assertion &) = default;
};

// ---------------------------------------------------------------- operations

struct simple_auth
{
	std::string password{};// [0] OCTET STRING
	friend bool operator==(const simple_auth &, const simple_auth &) = default;
};

struct sasl_auth
{
	std::string mechanism{};
	std::optional<std::string> credentials{};
	friend bool operator==(const sasl_auth &, const sasl_auth &) = default;
};

// [APPLICATION 0]. version is INTEGER (1 .. 127).
struct bind_request
{
	std::int32_t version = 3;
	std::string name{};
	std::variant<simple_auth, sasl_auth> authentication{};
	friend bool operator==(const bind_request &, const bind_request &) = default;
};

// [APPLICATION 1]
struct bind_response
{
	ldap_result result{};
	std::optional<std::string> server_sasl_creds{};// [7]
	friend bool operator==(const bind_response &, const bind_response &) = default;
};

// [APPLICATION 2] NULL
struct unbind_request
{
	friend bool operator==(const unbind_request &, const unbind_request &) = default;
};

// RFC 4511 lists 0-2 with an extension marker; 3 is subordinateSubtree
// (draft-sermersheim-ldap-subordinate-scope), which OpenLDAP and Active
// Directory implement. Other values are rejected.
enum class search_scope : std::int32_t {
	base_object = 0,
	single_level = 1,
	whole_subtree = 2,
	subordinate_subtree = 3
};

enum class deref_aliases : std::int32_t { never = 0, in_searching = 1, finding_base_obj = 2, always = 3 };

// [APPLICATION 3]. size_limit and time_limit are INTEGER (0 .. maxInt).
struct search_request
{
	std::string base_object{};
	search_scope scope = search_scope::base_object;
	deref_aliases deref = deref_aliases::never;
	std::int32_t size_limit = 0;
	std::int32_t time_limit = 0;
	bool types_only = false;
	// Canonical RFC 4515 text after decoding (see decode_filter); encoding
	// parses it and fails with invalid_filter if it is malformed.
	ldap::filter filter{ "(objectClass=*)" };
	std::vector<std::string> attributes{};
	friend bool operator==(const search_request &, const search_request &) = default;
};

// [APPLICATION 4]
struct search_result_entry
{
	std::string object_name{};
	std::vector<partial_attribute> attributes{};
	friend bool operator==(const search_result_entry &, const search_result_entry &) = default;
};

// [APPLICATION 5]
struct search_result_done
{
	ldap_result result{};
	friend bool operator==(const search_result_done &, const search_result_done &) = default;
};

// [APPLICATION 19] SEQUENCE OF URI
struct search_result_reference
{
	std::vector<std::string> uris{};
	friend bool operator==(const search_result_reference &, const search_result_reference &) = default;
};

// RFC 4511 add/delete/replace with an extension marker, plus increment (3,
// RFC 4525). Other values are rejected.
enum class modify_operation : std::int32_t { add = 0, delete_ = 1, replace = 2, increment = 3 };

struct modify_change
{
	modify_operation operation = modify_operation::add;
	partial_attribute modification{};
	friend bool operator==(const modify_change &, const modify_change &) = default;
};

// [APPLICATION 6]
struct modify_request
{
	std::string object{};
	std::vector<modify_change> changes{};
	friend bool operator==(const modify_request &, const modify_request &) = default;
};

// [APPLICATION 7]
struct modify_response
{
	ldap_result result{};
	friend bool operator==(const modify_response &, const modify_response &) = default;
};

// [APPLICATION 8]
struct add_request
{
	std::string entry{};
	std::vector<partial_attribute> attributes{};
	friend bool operator==(const add_request &, const add_request &) = default;
};

// [APPLICATION 9]
struct add_response
{
	ldap_result result{};
	friend bool operator==(const add_response &, const add_response &) = default;
};

// [APPLICATION 10] LDAPDN (primitive)
struct del_request
{
	std::string entry{};
	friend bool operator==(const del_request &, const del_request &) = default;
};

// [APPLICATION 11]
struct del_response
{
	ldap_result result{};
	friend bool operator==(const del_response &, const del_response &) = default;
};

// [APPLICATION 12]
struct modify_dn_request
{
	std::string entry{};
	std::string new_rdn{};
	bool delete_old_rdn = true;
	std::optional<std::string> new_superior{};// [0]
	friend bool operator==(const modify_dn_request &, const modify_dn_request &) = default;
};

// [APPLICATION 13]
struct modify_dn_response
{
	ldap_result result{};
	friend bool operator==(const modify_dn_response &, const modify_dn_response &) = default;
};

// [APPLICATION 14]
struct compare_request
{
	std::string entry{};
	attribute_value_assertion ava{};
	friend bool operator==(const compare_request &, const compare_request &) = default;
};

// [APPLICATION 15]. compare_true (6) / compare_false (5) are the normal outcomes.
struct compare_response
{
	ldap_result result{};
	friend bool operator==(const compare_response &, const compare_response &) = default;
};

// [APPLICATION 16] MessageID (primitive)
struct abandon_request
{
	std::int32_t message_id = 0;
	friend bool operator==(const abandon_request &, const abandon_request &) = default;
};

// [APPLICATION 23]
struct extended_request
{
	std::string request_name{};// [0] LDAPOID
	std::optional<std::string> request_value{};// [1]
	friend bool operator==(const extended_request &, const extended_request &) = default;
};

// [APPLICATION 24]. An unsolicited notification is an extended_response in a
// message with id 0 (RFC 4511 section 4.4), e.g. Notice of Disconnection
// with response_name notice_of_disconnection_oid.
struct extended_response
{
	ldap_result result{};
	std::optional<std::string> response_name{};// [10]
	std::optional<std::string> response_value{};// [11]
	friend bool operator==(const extended_response &, const extended_response &) = default;
};

// [APPLICATION 25]
struct intermediate_response
{
	std::optional<std::string> response_name{};// [0]
	std::optional<std::string> response_value{};// [1]
	friend bool operator==(const intermediate_response &, const intermediate_response &) = default;
};

inline constexpr std::string_view start_tls_oid = "1.3.6.1.4.1.1466.20037";
inline constexpr std::string_view notice_of_disconnection_oid = "1.3.6.1.4.1.1466.20036";

using protocol_op = std::variant<bind_request,
  bind_response,
  unbind_request,
  search_request,
  search_result_entry,
  search_result_done,
  search_result_reference,
  modify_request,
  modify_response,
  add_request,
  add_response,
  del_request,
  del_response,
  modify_dn_request,
  modify_dn_response,
  compare_request,
  compare_response,
  abandon_request,
  extended_request,
  extended_response,
  intermediate_response>;

// LDAPMessage (RFC 4511 section 4.2.1). `id` is 0 .. max_int; 0 is only
// meaningful for unsolicited notifications, which the decoder accepts.
struct message
{
	std::int32_t id = 0;
	protocol_op op{};
	std::vector<control> controls{};// [0] Controls OPTIONAL; empty = absent

	friend bool operator==(const message &, const message &) = default;
};

// ---------------------------------------------------------------- codec

// Encodes one LDAPMessage. Fails before writing anything with
// - invalid_filter if a search request's filter text is malformed;
// - encode_error for values the wire format cannot carry (negative message
//   id, limits or paged size; version outside 1..127; enum values outside the
//   ranges above). This keeps the invariant: if encode(m) succeeds,
//   decode(*encode(m)) == m.
result<std::vector<std::byte>> encode(const message &m);
result<void> encode(ber::writer &w, const message &m);

// Decodes exactly one LDAPMessage, as delimited by ber::complete_message_size;
// trailing bytes are an error (decode_error).
result<message> decode(std::span<const std::byte> one_complete_message);

// ---------------------------------------------------------------- typed controls

// Simple Paged Results (RFC 2696): realSearchControlValue.
inline constexpr std::string_view paged_results_oid = "1.2.840.113556.1.4.319";

struct paged_results
{
	std::int32_t size = 0;// INTEGER (0 .. maxInt): page size / result set estimate
	std::string cookie{};
	friend bool operator==(const paged_results &, const paged_results &) = default;
};

// Throws std::invalid_argument for a negative size (programming error).
control encode_paged_results(const paged_results &value, bool criticality = false);
// Fails with decode_error if `c` is not a paged results control or its value
// is missing or malformed (trailing bytes after the SEQUENCE included; unknown
// trailing SEQUENCE elements are skipped).
result<paged_results> decode_paged_results(const control &c);

}// namespace jhetz::ldap
