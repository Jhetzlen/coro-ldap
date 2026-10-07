// RFC 4511 LDAPMessage: a faithful wire model of every protocol operation
// (requests and responses, so a mock server can reuse it) and its BER codec.
//
// Field types: every LDAPDN, RelativeLDAPDN, LDAPString, LDAPOID,
// AttributeDescription and OCTET STRING of the wire format is a
// std::pmr::string here, holding the bytes exactly as sent (values may be
// binary); the search filter is an ldap::filter tree. The
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
// - SEQUENCE OF with SIZE (1..MAX) (referral, search references) is accepted
//   when empty; an empty list is the same as an absent one in this model.
//   Values of an AddRequest attribute or of a modify `add` change must not be
//   empty (SIZE (1..MAX), servers reject it): encode fails with encode_error,
//   decode with decode_error;
// - nesting is bounded by ber::reader's depth limit, filters by
//   filter_limits (depth and number of elements), and nothing is allocated
//   from a length that was not checked against the input first;
// - decode_options::from rejects operations the peer may not send.
//
// Memory (DESIGN.md section 8): every type here that owns strings is
// allocator-aware (std::pmr): it has allocator_type, get_allocator(), a
// constructor taking only an allocator, allocator-extended copy and move
// constructors, and assignment that keeps the target's resource (also for
// its std::optional and std::variant members). Containers of these types
// (std::pmr::vector<control>, ...) hand their resource to their elements.
// decode() allocates everything it returns from
// decode_options::memory (default: the default resource, i.e. the heap).
// - Lifetime rule: an object decoded into (or built on) a caller-supplied
//   resource, e.g. a per-response std::pmr::monotonic_buffer_resource, must
//   not outlive that resource. To keep it longer, copy it: a plain copy
//   allocates from the default resource. Objects decoded with default
//   options are always safe.
// - Assigning directly to an std::optional or std::variant member (not to
//   the whole object) follows the standard types' rules: engaging an empty
//   optional or switching the variant's alternative copies or moves the new
//   value with its own resource.
// - The value constructors (e.g. `control{"1.2.3", true}`) take string_views
//   and initializer lists and copy them into the given resource; nested
//   elements given as initializer lists are built on the default resource
//   first. Code that must not touch the default resource at all builds with
//   the allocator constructor and assigns the members.
// - The types have constructors, so they are not aggregates and designated
//   initializers do not work on them; the value constructors take the fields
//   in their declaration order (`message{1, del_request{"cn=x"}}`).
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace jhetz::ldap {

// MessageID ::= INTEGER (0 .. maxInt), maxInt = 2^31 - 1
inline constexpr std::int32_t max_int = 2'147'483'647;

using string_list = std::pmr::vector<std::pmr::string>;

// ---------------------------------------------------------------- shared parts

// LDAPResult (RFC 4511 section 4.1.9).
struct ldap_result
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::int32_t result_code = 0;// RFC 4511 resultCode; unknown values are kept
	std::pmr::string matched_dn{};
	std::pmr::string diagnostic_message{};
	string_list referral{};// [3] Referral OPTIONAL; empty = absent

	ldap_result() = default;
	explicit ldap_result(const allocator_type &alloc) : matched_dn(alloc), diagnostic_message(alloc), referral(alloc) {}
	ldap_result(std::int32_t result_code_,
	  std::string_view matched_dn_ = {},
	  std::string_view diagnostic_message_ = {},
	  std::initializer_list<std::string_view> referral_ = {},
	  const allocator_type &alloc = {});
	ldap_result(const ldap_result &) = default;
	ldap_result(ldap_result &&) noexcept = default;
	ldap_result(const ldap_result &other, const allocator_type &alloc);
	ldap_result(ldap_result &&other, const allocator_type &alloc);
	ldap_result &operator=(const ldap_result &) = default;
	ldap_result &operator=(ldap_result &&) = default;
	~ldap_result() = default;

	allocator_type get_allocator() const noexcept { return matched_dn.get_allocator(); }

	bool is_success() const noexcept { return result_code == 0; }

	// The result as an ldap::error (on the default resource): code in
	// result_category() (unknown codes keep their number and get a generic
	// message), diagnostic, matched DN (when not empty), referral URIs and
	// `context`. For a success result the code is 0, i.e. "no error"; callers
	// check is_success() first.
	error to_error(std::string_view context = {}) const;

	friend bool operator==(const ldap_result &, const ldap_result &) = default;
};

// Control (RFC 4511 section 4.1.11).
struct control
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string type{};// LDAPOID
	bool criticality = false;// DEFAULT FALSE: omitted from the encoding when false
	std::optional<std::pmr::string> value{};

	control() = default;
	explicit control(const allocator_type &alloc) : type(alloc) {}
	control(std::string_view type_,
	  bool criticality_ = false,
	  std::optional<std::string_view> value_ = {},
	  const allocator_type &alloc = {});
	control(const control &) = default;
	control(control &&) noexcept = default;
	control(const control &other, const allocator_type &alloc);
	control(control &&other, const allocator_type &alloc);
	control &operator=(const control &other);
	control &operator=(control &&other);
	~control() = default;

	allocator_type get_allocator() const noexcept { return type.get_allocator(); }

	friend bool operator==(const control &, const control &) = default;
};

// PartialAttribute / Attribute (RFC 4511 section 4.1.7).
struct partial_attribute
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string type{};
	string_list values{};

	partial_attribute() = default;
	explicit partial_attribute(const allocator_type &alloc) : type(alloc), values(alloc) {}
	partial_attribute(std::string_view type_,
	  std::initializer_list<std::string_view> values_ = {},
	  const allocator_type &alloc = {});
	partial_attribute(const partial_attribute &) = default;
	partial_attribute(partial_attribute &&) noexcept = default;
	partial_attribute(const partial_attribute &other, const allocator_type &alloc)
	  : type(other.type, alloc), values(other.values, alloc)
	{}
	partial_attribute(partial_attribute &&other, const allocator_type &alloc)
	  : type(std::move(other.type), alloc), values(std::move(other.values), alloc)
	{}
	partial_attribute &operator=(const partial_attribute &) = default;
	partial_attribute &operator=(partial_attribute &&) = default;
	~partial_attribute() = default;

	allocator_type get_allocator() const noexcept { return type.get_allocator(); }

	friend bool operator==(const partial_attribute &, const partial_attribute &) = default;
};

// AttributeValueAssertion (RFC 4511 section 4.1.8).
struct attribute_value_assertion
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string attribute_desc{};
	std::pmr::string assertion_value{};

	attribute_value_assertion() = default;
	explicit attribute_value_assertion(const allocator_type &alloc) : attribute_desc(alloc), assertion_value(alloc) {}
	attribute_value_assertion(std::string_view attribute_desc_,
	  std::string_view assertion_value_,
	  const allocator_type &alloc = {})
	  : attribute_desc(attribute_desc_, alloc), assertion_value(assertion_value_, alloc)
	{}
	attribute_value_assertion(const attribute_value_assertion &) = default;
	attribute_value_assertion(attribute_value_assertion &&) noexcept = default;
	attribute_value_assertion(const attribute_value_assertion &other, const allocator_type &alloc)
	  : attribute_desc(other.attribute_desc, alloc), assertion_value(other.assertion_value, alloc)
	{}
	attribute_value_assertion(attribute_value_assertion &&other, const allocator_type &alloc)
	  : attribute_desc(std::move(other.attribute_desc), alloc), assertion_value(std::move(other.assertion_value), alloc)
	{}
	attribute_value_assertion &operator=(const attribute_value_assertion &) = default;
	attribute_value_assertion &operator=(attribute_value_assertion &&) = default;
	~attribute_value_assertion() = default;

	allocator_type get_allocator() const noexcept { return attribute_desc.get_allocator(); }

	friend bool operator==(const attribute_value_assertion &, const attribute_value_assertion &) = default;
};

// An operation that is just an LDAPResult: SearchResultDone, ModifyResponse,
// AddResponse, DelResponse, ModifyDNResponse, CompareResponse (aliases
// below). `Tag` is the [APPLICATION n] number, which makes each a distinct type.
template<std::uint8_t Tag> struct result_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	ldap_result result{};

	result_response() = default;
	explicit result_response(const allocator_type &alloc) : result(alloc) {}
	result_response(const ldap_result &result_, const allocator_type &alloc = {}) : result(result_, alloc) {}
	result_response(ldap_result &&result_, const allocator_type &alloc = {}) : result(std::move(result_), alloc) {}
	result_response(const result_response &) = default;
	result_response(result_response &&) noexcept = default;
	result_response(const result_response &other, const allocator_type &alloc) : result(other.result, alloc) {}
	result_response(result_response &&other, const allocator_type &alloc) : result(std::move(other.result), alloc) {}
	result_response &operator=(const result_response &) = default;
	result_response &operator=(result_response &&) = default;
	~result_response() = default;

	allocator_type get_allocator() const noexcept { return result.get_allocator(); }

	friend bool operator==(const result_response &, const result_response &) = default;
};

// ---------------------------------------------------------------- operations

struct simple_auth
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string password{};// [0] OCTET STRING

	simple_auth() = default;
	explicit simple_auth(const allocator_type &alloc) : password(alloc) {}
	simple_auth(std::string_view password_, const allocator_type &alloc = {}) : password(password_, alloc) {}
	simple_auth(const simple_auth &) = default;
	simple_auth(simple_auth &&) noexcept = default;
	simple_auth(const simple_auth &other, const allocator_type &alloc) : password(other.password, alloc) {}
	simple_auth(simple_auth &&other, const allocator_type &alloc) : password(std::move(other.password), alloc) {}
	simple_auth &operator=(const simple_auth &) = default;
	simple_auth &operator=(simple_auth &&) = default;
	~simple_auth() = default;

	allocator_type get_allocator() const noexcept { return password.get_allocator(); }

	friend bool operator==(const simple_auth &, const simple_auth &) = default;
};

struct sasl_auth
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string mechanism{};
	std::optional<std::pmr::string> credentials{};

	sasl_auth() = default;
	explicit sasl_auth(const allocator_type &alloc) : mechanism(alloc) {}
	sasl_auth(std::string_view mechanism_,
	  std::optional<std::string_view> credentials_ = {},
	  const allocator_type &alloc = {});
	sasl_auth(const sasl_auth &) = default;
	sasl_auth(sasl_auth &&) noexcept = default;
	sasl_auth(const sasl_auth &other, const allocator_type &alloc);
	sasl_auth(sasl_auth &&other, const allocator_type &alloc);
	sasl_auth &operator=(const sasl_auth &other);
	sasl_auth &operator=(sasl_auth &&other);
	~sasl_auth() = default;

	allocator_type get_allocator() const noexcept { return mechanism.get_allocator(); }

	friend bool operator==(const sasl_auth &, const sasl_auth &) = default;
};

// [APPLICATION 0]. version is INTEGER (1 .. 127).
struct bind_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;
	using auth_type = std::variant<simple_auth, sasl_auth>;

	std::int32_t version = 3;
	std::pmr::string name{};
	auth_type authentication{};

	bind_request() = default;
	explicit bind_request(const allocator_type &alloc)
	  : name(alloc), authentication(std::in_place_type<simple_auth>, alloc)
	{}
	bind_request(std::int32_t version_,
	  std::string_view name_ = {},
	  auth_type authentication_ = {},
	  const allocator_type &alloc = {});
	bind_request(const bind_request &) = default;
	bind_request(bind_request &&) noexcept = default;
	bind_request(const bind_request &other, const allocator_type &alloc);
	bind_request(bind_request &&other, const allocator_type &alloc);
	bind_request &operator=(const bind_request &other);
	bind_request &operator=(bind_request &&other);
	~bind_request() = default;

	allocator_type get_allocator() const noexcept { return name.get_allocator(); }

	friend bool operator==(const bind_request &, const bind_request &) = default;
};

// [APPLICATION 1]
struct bind_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	ldap_result result{};
	std::optional<std::pmr::string> server_sasl_creds{};// [7]

	bind_response() = default;
	explicit bind_response(const allocator_type &alloc) : result(alloc) {}
	bind_response(const ldap_result &result_,
	  std::optional<std::string_view> server_sasl_creds_ = {},
	  const allocator_type &alloc = {});
	bind_response(const bind_response &) = default;
	bind_response(bind_response &&) noexcept = default;
	bind_response(const bind_response &other, const allocator_type &alloc);
	bind_response(bind_response &&other, const allocator_type &alloc);
	bind_response &operator=(const bind_response &other);
	bind_response &operator=(bind_response &&other);
	~bind_response() = default;

	allocator_type get_allocator() const noexcept { return result.get_allocator(); }

	friend bool operator==(const bind_response &, const bind_response &) = default;
};

// [APPLICATION 2] NULL. No strings, so not allocator-aware.
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
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string base_object{};
	search_scope scope = search_scope::base_object;
	deref_aliases deref = deref_aliases::never;
	std::int32_t size_limit = 0;
	std::int32_t time_limit = 0;
	bool types_only = false;
	// The filter tree, written to BER as is (no parsing when encoding).
	// Default: (objectClass=*). An empty filter fails to encode.
	ldap::filter filter = filters::attr("objectClass").present();
	string_list attributes{};

	search_request() = default;
	explicit search_request(const allocator_type &alloc);
	// Base, scope, filter and attributes; the other fields keep their defaults
	// and are set by name afterwards (no positional constructor for them:
	// size_limit and time_limit are adjacent int32_t and easy to swap).
	search_request(std::string_view base_object_,
	  search_scope scope_,
	  ldap::filter filter_,
	  std::initializer_list<std::string_view> attributes_ = {},
	  const allocator_type &alloc = {});
	search_request(const search_request &) = default;
	search_request(search_request &&) noexcept = default;
	search_request(const search_request &other, const allocator_type &alloc);
	search_request(search_request &&other, const allocator_type &alloc);
	search_request &operator=(const search_request &) = default;
	search_request &operator=(search_request &&) = default;
	~search_request() = default;

	allocator_type get_allocator() const noexcept { return base_object.get_allocator(); }

	friend bool operator==(const search_request &, const search_request &) = default;
};

// [APPLICATION 4]
struct search_result_entry
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string object_name{};
	std::pmr::vector<partial_attribute> attributes{};

	search_result_entry() = default;
	explicit search_result_entry(const allocator_type &alloc) : object_name(alloc), attributes(alloc) {}
	search_result_entry(std::string_view object_name_,
	  std::initializer_list<partial_attribute> attributes_ = {},
	  const allocator_type &alloc = {})
	  : object_name(object_name_, alloc), attributes(attributes_, alloc)
	{}
	search_result_entry(const search_result_entry &) = default;
	search_result_entry(search_result_entry &&) noexcept = default;
	search_result_entry(const search_result_entry &other, const allocator_type &alloc)
	  : object_name(other.object_name, alloc), attributes(other.attributes, alloc)
	{}
	search_result_entry(search_result_entry &&other, const allocator_type &alloc)
	  : object_name(std::move(other.object_name), alloc), attributes(std::move(other.attributes), alloc)
	{}
	search_result_entry &operator=(const search_result_entry &) = default;
	search_result_entry &operator=(search_result_entry &&) = default;
	~search_result_entry() = default;

	allocator_type get_allocator() const noexcept { return object_name.get_allocator(); }

	friend bool operator==(const search_result_entry &, const search_result_entry &) = default;
};

// [APPLICATION 5]
using search_result_done = result_response<5>;

// [APPLICATION 19] SEQUENCE OF URI
struct search_result_reference
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	string_list uris{};

	search_result_reference() = default;
	explicit search_result_reference(const allocator_type &alloc) : uris(alloc) {}
	// A string_list, not an initializer_list<string_view>: with the latter,
	// `search_result_reference{ { "a", "b" } }` would be one string_view made
	// from two unrelated pointers.
	search_result_reference(string_list uris_, const allocator_type &alloc = {}) : uris(std::move(uris_), alloc) {}
	search_result_reference(const search_result_reference &) = default;
	search_result_reference(search_result_reference &&) noexcept = default;
	search_result_reference(const search_result_reference &other, const allocator_type &alloc) : uris(other.uris, alloc)
	{}
	search_result_reference(search_result_reference &&other, const allocator_type &alloc)
	  : uris(std::move(other.uris), alloc)
	{}
	search_result_reference &operator=(const search_result_reference &) = default;
	search_result_reference &operator=(search_result_reference &&) = default;
	~search_result_reference() = default;

	allocator_type get_allocator() const noexcept { return uris.get_allocator(); }

	friend bool operator==(const search_result_reference &, const search_result_reference &) = default;
};

// RFC 4511 add/delete/replace with an extension marker, plus increment (3,
// RFC 4525). Other values are rejected.
enum class modify_operation : std::int32_t { add = 0, delete_ = 1, replace = 2, increment = 3 };

struct modify_change
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	modify_operation operation = modify_operation::add;
	partial_attribute modification{};

	modify_change() = default;
	explicit modify_change(const allocator_type &alloc) : modification(alloc) {}
	modify_change(modify_operation operation_, const partial_attribute &modification_, const allocator_type &alloc = {})
	  : operation(operation_), modification(modification_, alloc)
	{}
	modify_change(const modify_change &) = default;
	modify_change(modify_change &&) noexcept = default;
	modify_change(const modify_change &other, const allocator_type &alloc)
	  : operation(other.operation), modification(other.modification, alloc)
	{}
	modify_change(modify_change &&other, const allocator_type &alloc)
	  : operation(other.operation), modification(std::move(other.modification), alloc)
	{}
	modify_change &operator=(const modify_change &) = default;
	modify_change &operator=(modify_change &&) = default;
	~modify_change() = default;

	allocator_type get_allocator() const noexcept { return modification.get_allocator(); }

	friend bool operator==(const modify_change &, const modify_change &) = default;
};

// [APPLICATION 6]
struct modify_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string object{};
	std::pmr::vector<modify_change> changes{};

	modify_request() = default;
	explicit modify_request(const allocator_type &alloc) : object(alloc), changes(alloc) {}
	modify_request(std::string_view object_,
	  std::initializer_list<modify_change> changes_ = {},
	  const allocator_type &alloc = {})
	  : object(object_, alloc), changes(changes_, alloc)
	{}
	modify_request(const modify_request &) = default;
	modify_request(modify_request &&) noexcept = default;
	modify_request(const modify_request &other, const allocator_type &alloc)
	  : object(other.object, alloc), changes(other.changes, alloc)
	{}
	modify_request(modify_request &&other, const allocator_type &alloc)
	  : object(std::move(other.object), alloc), changes(std::move(other.changes), alloc)
	{}
	modify_request &operator=(const modify_request &) = default;
	modify_request &operator=(modify_request &&) = default;
	~modify_request() = default;

	allocator_type get_allocator() const noexcept { return object.get_allocator(); }

	friend bool operator==(const modify_request &, const modify_request &) = default;
};

// [APPLICATION 7]
using modify_response = result_response<7>;

// [APPLICATION 8]
struct add_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string entry{};
	std::pmr::vector<partial_attribute> attributes{};

	add_request() = default;
	explicit add_request(const allocator_type &alloc) : entry(alloc), attributes(alloc) {}
	add_request(std::string_view entry_,
	  std::initializer_list<partial_attribute> attributes_ = {},
	  const allocator_type &alloc = {})
	  : entry(entry_, alloc), attributes(attributes_, alloc)
	{}
	add_request(const add_request &) = default;
	add_request(add_request &&) noexcept = default;
	add_request(const add_request &other, const allocator_type &alloc)
	  : entry(other.entry, alloc), attributes(other.attributes, alloc)
	{}
	add_request(add_request &&other, const allocator_type &alloc)
	  : entry(std::move(other.entry), alloc), attributes(std::move(other.attributes), alloc)
	{}
	add_request &operator=(const add_request &) = default;
	add_request &operator=(add_request &&) = default;
	~add_request() = default;

	allocator_type get_allocator() const noexcept { return entry.get_allocator(); }

	friend bool operator==(const add_request &, const add_request &) = default;
};

// [APPLICATION 9]
using add_response = result_response<9>;

// [APPLICATION 10] LDAPDN (primitive)
struct del_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string entry{};

	del_request() = default;
	explicit del_request(const allocator_type &alloc) : entry(alloc) {}
	del_request(std::string_view entry_, const allocator_type &alloc = {}) : entry(entry_, alloc) {}
	del_request(const del_request &) = default;
	del_request(del_request &&) noexcept = default;
	del_request(const del_request &other, const allocator_type &alloc) : entry(other.entry, alloc) {}
	del_request(del_request &&other, const allocator_type &alloc) : entry(std::move(other.entry), alloc) {}
	del_request &operator=(const del_request &) = default;
	del_request &operator=(del_request &&) = default;
	~del_request() = default;

	allocator_type get_allocator() const noexcept { return entry.get_allocator(); }

	friend bool operator==(const del_request &, const del_request &) = default;
};

// [APPLICATION 11]
using del_response = result_response<11>;

// [APPLICATION 12]
struct modify_dn_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string entry{};
	std::pmr::string new_rdn{};
	bool delete_old_rdn = true;
	std::optional<std::pmr::string> new_superior{};// [0]

	modify_dn_request() = default;
	explicit modify_dn_request(const allocator_type &alloc) : entry(alloc), new_rdn(alloc) {}
	modify_dn_request(std::string_view entry_,
	  std::string_view new_rdn_,
	  bool delete_old_rdn_ = true,
	  std::optional<std::string_view> new_superior_ = {},
	  const allocator_type &alloc = {});
	modify_dn_request(const modify_dn_request &) = default;
	modify_dn_request(modify_dn_request &&) noexcept = default;
	modify_dn_request(const modify_dn_request &other, const allocator_type &alloc);
	modify_dn_request(modify_dn_request &&other, const allocator_type &alloc);
	modify_dn_request &operator=(const modify_dn_request &other);
	modify_dn_request &operator=(modify_dn_request &&other);
	~modify_dn_request() = default;

	allocator_type get_allocator() const noexcept { return entry.get_allocator(); }

	friend bool operator==(const modify_dn_request &, const modify_dn_request &) = default;
};

// [APPLICATION 13]
using modify_dn_response = result_response<13>;

// [APPLICATION 14]
struct compare_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string entry{};
	attribute_value_assertion ava{};

	compare_request() = default;
	explicit compare_request(const allocator_type &alloc) : entry(alloc), ava(alloc) {}
	compare_request(std::string_view entry_, const attribute_value_assertion &ava_, const allocator_type &alloc = {})
	  : entry(entry_, alloc), ava(ava_, alloc)
	{}
	compare_request(const compare_request &) = default;
	compare_request(compare_request &&) noexcept = default;
	compare_request(const compare_request &other, const allocator_type &alloc)
	  : entry(other.entry, alloc), ava(other.ava, alloc)
	{}
	compare_request(compare_request &&other, const allocator_type &alloc)
	  : entry(std::move(other.entry), alloc), ava(std::move(other.ava), alloc)
	{}
	compare_request &operator=(const compare_request &) = default;
	compare_request &operator=(compare_request &&) = default;
	~compare_request() = default;

	allocator_type get_allocator() const noexcept { return entry.get_allocator(); }

	friend bool operator==(const compare_request &, const compare_request &) = default;
};

// [APPLICATION 15]. compare_true (6) / compare_false (5) are the normal outcomes.
using compare_response = result_response<15>;

// [APPLICATION 16] MessageID (primitive). No strings, so not allocator-aware.
struct abandon_request
{
	std::int32_t message_id = 0;
	friend bool operator==(const abandon_request &, const abandon_request &) = default;
};

// [APPLICATION 23]
struct extended_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string request_name{};// [0] LDAPOID
	std::optional<std::pmr::string> request_value{};// [1]

	extended_request() = default;
	explicit extended_request(const allocator_type &alloc) : request_name(alloc) {}
	extended_request(std::string_view request_name_,
	  std::optional<std::string_view> request_value_ = {},
	  const allocator_type &alloc = {});
	extended_request(const extended_request &) = default;
	extended_request(extended_request &&) noexcept = default;
	extended_request(const extended_request &other, const allocator_type &alloc);
	extended_request(extended_request &&other, const allocator_type &alloc);
	extended_request &operator=(const extended_request &other);
	extended_request &operator=(extended_request &&other);
	~extended_request() = default;

	allocator_type get_allocator() const noexcept { return request_name.get_allocator(); }

	friend bool operator==(const extended_request &, const extended_request &) = default;
};

// [APPLICATION 24]. An unsolicited notification is an extended_response in a
// message with id 0 (RFC 4511 section 4.4), e.g. Notice of Disconnection
// with response_name notice_of_disconnection_oid.
struct extended_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	ldap_result result{};
	std::optional<std::pmr::string> response_name{};// [10]
	std::optional<std::pmr::string> response_value{};// [11]

	extended_response() = default;
	explicit extended_response(const allocator_type &alloc) : result(alloc) {}
	extended_response(const ldap_result &result_,
	  std::optional<std::string_view> response_name_ = {},
	  std::optional<std::string_view> response_value_ = {},
	  const allocator_type &alloc = {});
	extended_response(const extended_response &) = default;
	extended_response(extended_response &&) noexcept = default;
	extended_response(const extended_response &other, const allocator_type &alloc);
	extended_response(extended_response &&other, const allocator_type &alloc);
	extended_response &operator=(const extended_response &other);
	extended_response &operator=(extended_response &&other);
	~extended_response() = default;

	allocator_type get_allocator() const noexcept { return result.get_allocator(); }

	friend bool operator==(const extended_response &, const extended_response &) = default;
};

// [APPLICATION 25]
struct intermediate_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::optional<std::pmr::string> response_name{};// [0]
	std::optional<std::pmr::string> response_value{};// [1]

	intermediate_response() = default;
	explicit intermediate_response(const allocator_type &alloc) : alloc_(alloc) {}
	intermediate_response(std::optional<std::string_view> response_name_,
	  std::optional<std::string_view> response_value_ = {},
	  const allocator_type &alloc = {});
	intermediate_response(const intermediate_response &other);
	intermediate_response(intermediate_response &&) noexcept = default;
	intermediate_response(const intermediate_response &other, const allocator_type &alloc);
	intermediate_response(intermediate_response &&other, const allocator_type &alloc);
	intermediate_response &operator=(const intermediate_response &other);
	intermediate_response &operator=(intermediate_response &&other);
	~intermediate_response() = default;

	// Both members may be absent, so the resource is kept separately.
	allocator_type get_allocator() const noexcept { return alloc_; }

	friend bool operator==(const intermediate_response &a, const intermediate_response &b)
	{
		return a.response_name == b.response_name && a.response_value == b.response_value;
	}

  private:
	allocator_type alloc_{};
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
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::int32_t id = 0;
	protocol_op op{};
	std::pmr::vector<control> controls{};// [0] Controls OPTIONAL; empty = absent

	message() = default;
	explicit message(const allocator_type &alloc);
	message(std::int32_t id_,
	  protocol_op op_,
	  std::initializer_list<control> controls_ = {},
	  const allocator_type &alloc = {});
	message(const message &) = default;
	message(message &&) noexcept = default;
	message(const message &other, const allocator_type &alloc);
	message(message &&other, const allocator_type &alloc);
	message &operator=(const message &other);
	message &operator=(message &&other);
	~message() = default;

	allocator_type get_allocator() const noexcept { return controls.get_allocator(); }

	friend bool operator==(const message &, const message &) = default;
};

// ---------------------------------------------------------------- codec

// Encodes one LDAPMessage. Fails before writing anything with
// - invalid_filter if a search request's filter is empty or beyond the
//   default filter_limits (only possible for filters made by the builders);
// - encode_error for values the wire format cannot carry (negative message
//   id or limits; version outside 1..127; enum values outside the ranges
//   above; an AddRequest attribute or modify `add` change without values).
// The filter tree is written as is: encoding never parses text.
// If encode(m) succeeds, then
// - decode(*encode(m)) == m, exactly (filters included: decoding builds the
//   same tree);
// - encode(*decode(*encode(m))) == encode(m), byte for byte.
// The first overload returns the bytes in a vector allocated from `mr`; the
// second appends them to `w` (e.g. a reused writer, or one on an arena).
result<std::pmr::vector<std::byte>> encode(const message &m,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
result<void> encode(ber::writer &w, const message &m);

// Which side sent the message being decoded.
enum class origin {
	any,// both requests and responses (tests, tools)
	server,// responses only: what a client receives
	client,// requests only: what a server (or mock server) receives
};

struct decode_options
{
	// Operations the peer may not send fail with unsupported_operation before
	// they are decoded.
	origin from = origin::any;
	// ber::reader depth limit for the whole message.
	std::size_t max_depth = ber::reader::default_max_depth;
	// Limits for the filter of a search request.
	filter_limits filter{};
	// Everything the decoded message owns is allocated from here. With an
	// arena (e.g. a std::pmr::monotonic_buffer_resource per response), the
	// message must not outlive it; see the lifetime rule at the top. Errors
	// are always allocated from the default resource.
	std::pmr::memory_resource *memory = std::pmr::get_default_resource();
};

// Decodes exactly one LDAPMessage, as delimited by ber::complete_message_size;
// trailing bytes are an error (decode_error).
result<message> decode(std::span<const std::byte> one_complete_message, const decode_options &options = {});

// The messageID and the protocolOp tag of one complete PDU, read without
// decoding the rest or allocating: a multiplexed connection uses it to find
// the operation a response belongs to (and the resource to decode it into)
// before decoding. Only the outer SEQUENCE header, the id (0 .. maxInt) and
// the next tag are checked; decode() still validates everything.
struct message_header
{
	std::int32_t id = 0;
	ber::tag op{};// e.g. [APPLICATION 4] for a SearchResultEntry
};
result<message_header> peek_message_header(std::span<const std::byte> one_complete_message);

// ---------------------------------------------------------------- typed controls

// Simple Paged Results (RFC 2696): realSearchControlValue.
inline constexpr std::string_view paged_results_oid = "1.2.840.113556.1.4.319";

struct paged_results
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::int32_t size = 0;// INTEGER (0 .. maxInt): page size / result set estimate
	std::pmr::string cookie{};

	paged_results() = default;
	explicit paged_results(const allocator_type &alloc) : cookie(alloc) {}
	paged_results(std::int32_t size_, std::string_view cookie_ = {}, const allocator_type &alloc = {})
	  : size(size_), cookie(cookie_, alloc)
	{}
	paged_results(const paged_results &) = default;
	paged_results(paged_results &&) noexcept = default;
	paged_results(const paged_results &other, const allocator_type &alloc)
	  : size(other.size), cookie(other.cookie, alloc)
	{}
	paged_results(paged_results &&other, const allocator_type &alloc)
	  : size(other.size), cookie(std::move(other.cookie), alloc)
	{}
	paged_results &operator=(const paged_results &) = default;
	paged_results &operator=(paged_results &&) = default;
	~paged_results() = default;

	allocator_type get_allocator() const noexcept { return cookie.get_allocator(); }

	friend bool operator==(const paged_results &, const paged_results &) = default;
};

// Fails with encode_error for a negative size. The control is allocated
// from `mr`.
result<control> encode_paged_results(const paged_results &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
// Fails with decode_error if `c` is not a paged results control or its value
// is missing or malformed (trailing bytes after the SEQUENCE included; unknown
// trailing SEQUENCE elements are skipped). The result is allocated from `mr`.
result<paged_results> decode_paged_results(const control &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource());

}// namespace jhetz::ldap
