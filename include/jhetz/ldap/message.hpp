// RFC 4511 LDAPMessage: a wire model of every request and response, and its
// BER codec (decoding rules and memory: docs/API.md, "jhetz/ldap/message.hpp").
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

// MessageID ::= INTEGER (0 .. maxInt)
inline constexpr std::int32_t max_int = 2'147'483'647;

using string_list = std::pmr::vector<std::pmr::string>;

// ---------------------------------------------------------------- shared parts

// LDAPResult (RFC 4511 section 4.1.9).
struct ldap_result
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::int32_t result_code = 0;// unknown values are kept
	std::pmr::string matched_dn{};
	std::pmr::string diagnostic_message{};
	string_list referral{};// [3] Referral OPTIONAL; empty = absent

	ldap_result() = default;
	explicit ldap_result(const allocator_type &alloc) : matched_dn(alloc), diagnostic_message(alloc), referral(alloc) {}
	explicit ldap_result(std::int32_t result_code_) : ldap_result(result_code_, {}) {}
	ldap_result(std::int32_t result_code_,
	  std::string_view matched_dn_,
	  std::string_view diagnostic_message_ = {},
	  std::initializer_list<std::string_view> referral_ = {},
	  const allocator_type &alloc = {});
	ldap_result(const ldap_result &) = default;
	ldap_result(ldap_result &&) noexcept = default;
	ldap_result(const ldap_result &other, const allocator_type &alloc);
	ldap_result(ldap_result &&other, const allocator_type &alloc);
	auto operator=(const ldap_result &) -> ldap_result & = default;
	auto operator=(ldap_result &&) -> ldap_result & = default;
	~ldap_result() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return matched_dn.get_allocator(); }

	[[nodiscard]] auto is_success() const noexcept -> bool { return result_code == 0; }

	// The result as an ldap::error, with `context`; check is_success() first.
	[[nodiscard]] auto to_error(std::string_view context = {}) const -> error;

	friend auto operator==(const ldap_result &, const ldap_result &) -> bool = default;
};

// Control (RFC 4511 section 4.1.11).
struct control
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string type{};
	bool criticality = false;// DEFAULT FALSE
	std::optional<std::pmr::string> value{};

	control() = default;
	explicit control(const allocator_type &alloc) : type(alloc) {}
	explicit control(std::string_view type_) : control(type_, false) {}
	control(std::string_view type_,
	  bool criticality_,
	  std::optional<std::string_view> value_ = {},
	  const allocator_type &alloc = {});
	control(const control &) = default;
	control(control &&) noexcept = default;
	control(const control &other, const allocator_type &alloc);
	control(control &&other, const allocator_type &alloc);
	auto operator=(const control &other) -> control &;
	auto operator=(control &&other) -> control &;
	~control() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return type.get_allocator(); }

	friend auto operator==(const control &, const control &) -> bool = default;
};

// PartialAttribute / Attribute (RFC 4511 section 4.1.7).
struct partial_attribute
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string type{};
	string_list values{};

	partial_attribute() = default;
	explicit partial_attribute(const allocator_type &alloc) : type(alloc), values(alloc) {}
	explicit partial_attribute(std::string_view type_) : partial_attribute(type_, {}) {}
	partial_attribute(std::string_view type_,
	  std::initializer_list<std::string_view> values_,
	  const allocator_type &alloc = {});
	partial_attribute(const partial_attribute &) = default;
	partial_attribute(partial_attribute &&) noexcept = default;
	partial_attribute(const partial_attribute &other, const allocator_type &alloc)
	  : type(other.type, alloc), values(other.values, alloc)
	{}
	partial_attribute(partial_attribute &&other, const allocator_type &alloc)
	  : type(std::move(other.type), alloc), values(std::move(other.values), alloc)
	{}
	auto operator=(const partial_attribute &) -> partial_attribute & = default;
	auto operator=(partial_attribute &&) -> partial_attribute & = default;
	~partial_attribute() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return type.get_allocator(); }

	friend auto operator==(const partial_attribute &, const partial_attribute &) -> bool = default;
};

// AttributeValueAssertion (RFC 4511 section 4.1.8).
struct attribute_value_assertion
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string attribute_desc{};
	std::pmr::string assertion_value{};

	attribute_value_assertion() = default;
	explicit attribute_value_assertion(const allocator_type &alloc) : attribute_desc(alloc), assertion_value(alloc) {}
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
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
	auto operator=(const attribute_value_assertion &) -> attribute_value_assertion & = default;
	auto operator=(attribute_value_assertion &&) -> attribute_value_assertion & = default;
	~attribute_value_assertion() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return attribute_desc.get_allocator(); }

	friend auto operator==(const attribute_value_assertion &, const attribute_value_assertion &) -> bool = default;
};

// Application tag numbers of the protocolOp CHOICE (RFC 4511 section 4.2).
namespace detail::op_tag {
	inline constexpr std::uint8_t bind_request = 0;
	inline constexpr std::uint8_t bind_response = 1;
	inline constexpr std::uint8_t unbind_request = 2;
	inline constexpr std::uint8_t search_request = 3;
	inline constexpr std::uint8_t search_result_entry = 4;
	inline constexpr std::uint8_t search_result_done = 5;
	inline constexpr std::uint8_t modify_request = 6;
	inline constexpr std::uint8_t modify_response = 7;
	inline constexpr std::uint8_t add_request = 8;
	inline constexpr std::uint8_t add_response = 9;
	inline constexpr std::uint8_t del_request = 10;
	inline constexpr std::uint8_t del_response = 11;
	inline constexpr std::uint8_t modify_dn_request = 12;
	inline constexpr std::uint8_t modify_dn_response = 13;
	inline constexpr std::uint8_t compare_request = 14;
	inline constexpr std::uint8_t compare_response = 15;
	inline constexpr std::uint8_t abandon_request = 16;
	inline constexpr std::uint8_t search_result_reference = 19;
	inline constexpr std::uint8_t extended_request = 23;
	inline constexpr std::uint8_t extended_response = 24;
	inline constexpr std::uint8_t intermediate_response = 25;
}// namespace detail::op_tag

// An operation that is just an LDAPResult; `Tag` is its [APPLICATION n].
template<std::uint8_t Tag> struct result_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	ldap_result result{};

	result_response() = default;
	explicit result_response(const allocator_type &alloc) : result(alloc) {}
	explicit result_response(const ldap_result &result_, const allocator_type &alloc = {}) : result(result_, alloc) {}
	explicit result_response(ldap_result &&result_, const allocator_type &alloc = {})
	  : result(std::move(result_), alloc)
	{}
	result_response(const result_response &) = default;
	result_response(result_response &&) noexcept = default;
	result_response(const result_response &other, const allocator_type &alloc) : result(other.result, alloc) {}
	result_response(result_response &&other, const allocator_type &alloc) : result(std::move(other.result), alloc) {}
	auto operator=(const result_response &) -> result_response & = default;
	auto operator=(result_response &&) -> result_response & = default;
	~result_response() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return result.get_allocator(); }

	friend auto operator==(const result_response &, const result_response &) -> bool = default;
};

// ---------------------------------------------------------------- operations

struct simple_auth
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string password{};// [0] OCTET STRING

	simple_auth() = default;
	explicit simple_auth(const allocator_type &alloc) : password(alloc) {}
	explicit simple_auth(std::string_view password_, const allocator_type &alloc = {}) : password(password_, alloc) {}
	simple_auth(const simple_auth &) = default;
	simple_auth(simple_auth &&) noexcept = default;
	simple_auth(const simple_auth &other, const allocator_type &alloc) : password(other.password, alloc) {}
	simple_auth(simple_auth &&other, const allocator_type &alloc) : password(std::move(other.password), alloc) {}
	auto operator=(const simple_auth &) -> simple_auth & = default;
	auto operator=(simple_auth &&) -> simple_auth & = default;
	~simple_auth() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return password.get_allocator(); }

	friend auto operator==(const simple_auth &, const simple_auth &) -> bool = default;
};

struct sasl_auth
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string mechanism{};
	std::optional<std::pmr::string> credentials{};

	sasl_auth() = default;
	explicit sasl_auth(const allocator_type &alloc) : mechanism(alloc) {}
	explicit sasl_auth(std::string_view mechanism_) : sasl_auth(mechanism_, {}) {}
	sasl_auth(std::string_view mechanism_,
	  std::optional<std::string_view> credentials_,
	  const allocator_type &alloc = {});
	sasl_auth(const sasl_auth &) = default;
	sasl_auth(sasl_auth &&) noexcept = default;
	sasl_auth(const sasl_auth &other, const allocator_type &alloc);
	sasl_auth(sasl_auth &&other, const allocator_type &alloc);
	auto operator=(const sasl_auth &other) -> sasl_auth &;
	auto operator=(sasl_auth &&other) -> sasl_auth &;
	~sasl_auth() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return mechanism.get_allocator(); }

	friend auto operator==(const sasl_auth &, const sasl_auth &) -> bool = default;
};

// [APPLICATION 0]
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
	explicit bind_request(std::int32_t version_) : bind_request(version_, {}) {}
	bind_request(std::int32_t version_,
	  std::string_view name_,
	  auth_type authentication_ = {},
	  const allocator_type &alloc = {});
	bind_request(const bind_request &) = default;
	bind_request(bind_request &&) noexcept = default;
	bind_request(const bind_request &other, const allocator_type &alloc);
	bind_request(bind_request &&other, const allocator_type &alloc);
	auto operator=(const bind_request &other) -> bind_request &;
	auto operator=(bind_request &&other) -> bind_request &;
	~bind_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return name.get_allocator(); }

	friend auto operator==(const bind_request &, const bind_request &) -> bool = default;
};

// [APPLICATION 1]
struct bind_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	ldap_result result{};
	std::optional<std::pmr::string> server_sasl_creds{};// [7]

	bind_response() = default;
	explicit bind_response(const allocator_type &alloc) : result(alloc) {}
	explicit bind_response(const ldap_result &result_) : bind_response(result_, {}) {}
	bind_response(const ldap_result &result_,
	  std::optional<std::string_view> server_sasl_creds_,
	  const allocator_type &alloc = {});
	bind_response(const bind_response &) = default;
	bind_response(bind_response &&) noexcept = default;
	bind_response(const bind_response &other, const allocator_type &alloc);
	bind_response(bind_response &&other, const allocator_type &alloc);
	auto operator=(const bind_response &other) -> bind_response &;
	auto operator=(bind_response &&other) -> bind_response &;
	~bind_response() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return result.get_allocator(); }

	friend auto operator==(const bind_response &, const bind_response &) -> bool = default;
};

// [APPLICATION 2]
struct unbind_request
{
	friend auto operator==(const unbind_request &, const unbind_request &) -> bool = default;
};

// RFC 4511's 0-2, plus subordinateSubtree (3).
enum class search_scope : std::int32_t {
	base_object = 0,
	single_level = 1,
	whole_subtree = 2,
	subordinate_subtree = 3
};

enum class deref_aliases : std::int32_t { never = 0, in_searching = 1, finding_base_obj = 2, always = 3 };

// [APPLICATION 3]
struct search_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string base_object{};
	search_scope scope = search_scope::base_object;
	deref_aliases deref = deref_aliases::never;
	std::int32_t size_limit = 0;
	std::int32_t time_limit = 0;
	bool types_only = false;
	// Written to BER as is; an empty filter fails to encode.
	ldap::filter filter = filters::attr("objectClass").present();
	string_list attributes{};

	search_request() = default;
	explicit search_request(const allocator_type &alloc);
	// Base, scope, filter and attributes; the other fields are set by name.
	search_request(std::string_view base_object_,
	  search_scope scope_,
	  ldap::filter filter_,
	  std::initializer_list<std::string_view> attributes_ = {},
	  const allocator_type &alloc = {});
	search_request(const search_request &) = default;
	search_request(search_request &&) noexcept = default;
	search_request(const search_request &other, const allocator_type &alloc);
	search_request(search_request &&other, const allocator_type &alloc);
	auto operator=(const search_request &) -> search_request & = default;
	auto operator=(search_request &&) -> search_request & = default;
	~search_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return base_object.get_allocator(); }

	friend auto operator==(const search_request &, const search_request &) -> bool = default;
};

// [APPLICATION 4]
struct search_result_entry
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string object_name{};
	std::pmr::vector<partial_attribute> attributes{};

	search_result_entry() = default;
	explicit search_result_entry(const allocator_type &alloc) : object_name(alloc), attributes(alloc) {}
	explicit search_result_entry(std::string_view object_name_) : search_result_entry(object_name_, {}) {}
	search_result_entry(std::string_view object_name_,
	  std::initializer_list<partial_attribute> attributes_,
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
	auto operator=(const search_result_entry &) -> search_result_entry & = default;
	auto operator=(search_result_entry &&) -> search_result_entry & = default;
	~search_result_entry() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return object_name.get_allocator(); }

	friend auto operator==(const search_result_entry &, const search_result_entry &) -> bool = default;
};

// [APPLICATION 5]
using search_result_done = result_response<detail::op_tag::search_result_done>;

// [APPLICATION 19]; a reference without a URI is rejected.
struct search_result_reference
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	string_list uris{};

	search_result_reference() = default;
	explicit search_result_reference(const allocator_type &alloc) : uris(alloc) {}
	explicit search_result_reference(string_list uris_, const allocator_type &alloc = {})
	  : uris(std::move(uris_), alloc)
	{}
	search_result_reference(const search_result_reference &) = default;
	search_result_reference(search_result_reference &&) noexcept = default;
	search_result_reference(const search_result_reference &other, const allocator_type &alloc) : uris(other.uris, alloc)
	{}
	search_result_reference(search_result_reference &&other, const allocator_type &alloc)
	  : uris(std::move(other.uris), alloc)
	{}
	auto operator=(const search_result_reference &) -> search_result_reference & = default;
	auto operator=(search_result_reference &&) -> search_result_reference & = default;
	~search_result_reference() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return uris.get_allocator(); }

	friend auto operator==(const search_result_reference &, const search_result_reference &) -> bool = default;
};

// RFC 4511's add, delete, replace, plus increment (3, RFC 4525).
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
	auto operator=(const modify_change &) -> modify_change & = default;
	auto operator=(modify_change &&) -> modify_change & = default;
	~modify_change() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return modification.get_allocator(); }

	friend auto operator==(const modify_change &, const modify_change &) -> bool = default;
};

// [APPLICATION 6]
struct modify_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string object{};
	std::pmr::vector<modify_change> changes{};

	modify_request() = default;
	explicit modify_request(const allocator_type &alloc) : object(alloc), changes(alloc) {}
	explicit modify_request(std::string_view object_) : modify_request(object_, {}) {}
	modify_request(std::string_view object_,
	  std::initializer_list<modify_change> changes_,
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
	auto operator=(const modify_request &) -> modify_request & = default;
	auto operator=(modify_request &&) -> modify_request & = default;
	~modify_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return object.get_allocator(); }

	friend auto operator==(const modify_request &, const modify_request &) -> bool = default;
};

// [APPLICATION 7]
using modify_response = result_response<detail::op_tag::modify_response>;

// [APPLICATION 8]
struct add_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string entry{};
	std::pmr::vector<partial_attribute> attributes{};

	add_request() = default;
	explicit add_request(const allocator_type &alloc) : entry(alloc), attributes(alloc) {}
	explicit add_request(std::string_view entry_) : add_request(entry_, {}) {}
	add_request(std::string_view entry_,
	  std::initializer_list<partial_attribute> attributes_,
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
	auto operator=(const add_request &) -> add_request & = default;
	auto operator=(add_request &&) -> add_request & = default;
	~add_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return entry.get_allocator(); }

	friend auto operator==(const add_request &, const add_request &) -> bool = default;
};

// [APPLICATION 9]
using add_response = result_response<detail::op_tag::add_response>;

// [APPLICATION 10]
struct del_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string entry{};

	del_request() = default;
	explicit del_request(const allocator_type &alloc) : entry(alloc) {}
	explicit del_request(std::string_view entry_, const allocator_type &alloc = {}) : entry(entry_, alloc) {}
	del_request(const del_request &) = default;
	del_request(del_request &&) noexcept = default;
	del_request(const del_request &other, const allocator_type &alloc) : entry(other.entry, alloc) {}
	del_request(del_request &&other, const allocator_type &alloc) : entry(std::move(other.entry), alloc) {}
	auto operator=(const del_request &) -> del_request & = default;
	auto operator=(del_request &&) -> del_request & = default;
	~del_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return entry.get_allocator(); }

	friend auto operator==(const del_request &, const del_request &) -> bool = default;
};

// [APPLICATION 11]
using del_response = result_response<detail::op_tag::del_response>;

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
	auto operator=(const modify_dn_request &other) -> modify_dn_request &;
	auto operator=(modify_dn_request &&other) -> modify_dn_request &;
	~modify_dn_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return entry.get_allocator(); }

	friend auto operator==(const modify_dn_request &, const modify_dn_request &) -> bool = default;
};

// [APPLICATION 13]
using modify_dn_response = result_response<detail::op_tag::modify_dn_response>;

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
	auto operator=(const compare_request &) -> compare_request & = default;
	auto operator=(compare_request &&) -> compare_request & = default;
	~compare_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return entry.get_allocator(); }

	friend auto operator==(const compare_request &, const compare_request &) -> bool = default;
};

// [APPLICATION 15]
using compare_response = result_response<detail::op_tag::compare_response>;

// [APPLICATION 16]
struct abandon_request
{
	std::int32_t message_id = 0;
	friend auto operator==(const abandon_request &, const abandon_request &) -> bool = default;
};

// [APPLICATION 23]
struct extended_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string request_name{};// [0]
	std::optional<std::pmr::string> request_value{};// [1]

	extended_request() = default;
	explicit extended_request(const allocator_type &alloc) : request_name(alloc) {}
	explicit extended_request(std::string_view request_name_) : extended_request(request_name_, {}) {}
	extended_request(std::string_view request_name_,
	  std::optional<std::string_view> request_value_,
	  const allocator_type &alloc = {});
	extended_request(const extended_request &) = default;
	extended_request(extended_request &&) noexcept = default;
	extended_request(const extended_request &other, const allocator_type &alloc);
	extended_request(extended_request &&other, const allocator_type &alloc);
	auto operator=(const extended_request &other) -> extended_request &;
	auto operator=(extended_request &&other) -> extended_request &;
	~extended_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return request_name.get_allocator(); }

	friend auto operator==(const extended_request &, const extended_request &) -> bool = default;
};

// [APPLICATION 24]; with message id 0, an unsolicited notification.
struct extended_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	ldap_result result{};
	std::optional<std::pmr::string> response_name{};// [10]
	std::optional<std::pmr::string> response_value{};// [11]

	extended_response() = default;
	explicit extended_response(const allocator_type &alloc) : result(alloc) {}
	explicit extended_response(const ldap_result &result_) : extended_response(result_, {}) {}
	extended_response(const ldap_result &result_,
	  std::optional<std::string_view> response_name_,
	  std::optional<std::string_view> response_value_ = {},
	  const allocator_type &alloc = {});
	extended_response(const extended_response &) = default;
	extended_response(extended_response &&) noexcept = default;
	extended_response(const extended_response &other, const allocator_type &alloc);
	extended_response(extended_response &&other, const allocator_type &alloc);
	auto operator=(const extended_response &other) -> extended_response &;
	auto operator=(extended_response &&other) -> extended_response &;
	~extended_response() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return result.get_allocator(); }

	friend auto operator==(const extended_response &, const extended_response &) -> bool = default;
};

// [APPLICATION 25]
struct intermediate_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// NOLINTBEGIN(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)
	std::optional<std::pmr::string> response_name{};// [0]
	std::optional<std::pmr::string> response_value{};// [1]
	// NOLINTEND(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)

	intermediate_response() = default;
	explicit intermediate_response(const allocator_type &alloc) : alloc_(alloc) {}
	explicit intermediate_response(std::optional<std::string_view> response_name_)
	  : intermediate_response(response_name_, {})
	{}
	intermediate_response(std::optional<std::string_view> response_name_,
	  std::optional<std::string_view> response_value_,
	  const allocator_type &alloc = {});
	intermediate_response(const intermediate_response &other);
	intermediate_response(intermediate_response &&) noexcept = default;
	intermediate_response(const intermediate_response &other, const allocator_type &alloc);
	intermediate_response(intermediate_response &&other, const allocator_type &alloc);
	auto operator=(const intermediate_response &other) -> intermediate_response &;
	auto operator=(intermediate_response &&other) -> intermediate_response &;
	~intermediate_response() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return alloc_; }

	friend auto operator==(const intermediate_response &a, const intermediate_response &b) -> bool
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

// LDAPMessage (RFC 4511 section 4.2.1); id 0 for unsolicited notifications.
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
	auto operator=(const message &other) -> message &;
	auto operator=(message &&other) -> message &;
	~message() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return controls.get_allocator(); }

	friend auto operator==(const message &, const message &) -> bool = default;
};

// ---------------------------------------------------------------- codec

// Encodes one LDAPMessage into a vector on `mr`, or appends it to `w`.
// decode(encode(m)) == m for a response, and re-encoding is byte-identical.
[[nodiscard]] auto encode(const message &m, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<std::pmr::vector<std::byte>>;
[[nodiscard]] auto encode(ber::writer &w, const message &m) -> result<void>;

inline constexpr std::size_t default_max_elements = 1'000'000;

struct decode_options
{
	std::size_t max_depth = ber::reader::default_max_depth;
	// Strings one message may decode to; more fail with message_too_large.
	std::size_t max_elements = default_max_elements;
	// Everything the decoded message owns; errors use the default resource.
	std::pmr::memory_resource *memory = std::pmr::get_default_resource();
};

// Decodes exactly one LDAPMessage a server sends; trailing bytes are a
// decode_error, a request operation fails with unsupported_operation.
[[nodiscard]] auto decode(std::span<const std::byte> one_complete_message, const decode_options &options = {})
  -> result<message>;

// The messageID and protocolOp tag of one complete PDU, read without
// decoding the rest.
struct message_header
{
	std::int32_t id = 0;
	ber::tag op{};
};
[[nodiscard]] auto peek_message_header(std::span<const std::byte> one_complete_message) -> result<message_header>;

// ---------------------------------------------------------------- typed controls

// Simple Paged Results (RFC 2696).
inline constexpr std::string_view paged_results_oid = "1.2.840.113556.1.4.319";

struct paged_results
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::int32_t size = 0;// page size / result set estimate
	std::pmr::string cookie{};

	paged_results() = default;
	explicit paged_results(const allocator_type &alloc) : cookie(alloc) {}
	explicit paged_results(std::int32_t size_) : paged_results(size_, {}) {}
	paged_results(std::int32_t size_, std::string_view cookie_, const allocator_type &alloc = {})
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
	auto operator=(const paged_results &) -> paged_results & = default;
	auto operator=(paged_results &&) -> paged_results & = default;
	~paged_results() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return cookie.get_allocator(); }

	friend auto operator==(const paged_results &, const paged_results &) -> bool = default;
};

[[nodiscard]] auto encode_paged_results(const paged_results &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
[[nodiscard]] auto decode_paged_results(const control &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<paged_results>;

// Server Side Sorting (RFC 2891): the SortResult response control.
inline constexpr std::string_view sort_request_oid = "1.2.840.113556.1.4.473";
inline constexpr std::string_view sort_response_oid = "1.2.840.113556.1.4.474";

struct sort_result
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// sortResult; unknown values are kept.
	std::int32_t result_code = 0;
	// attributeType [0]; empty when absent.
	std::pmr::string attribute_type{};

	sort_result() = default;
	explicit sort_result(const allocator_type &alloc) : attribute_type(alloc) {}
	explicit sort_result(std::int32_t code_) : sort_result(code_, {}) {}
	sort_result(std::int32_t code_, std::string_view attribute_type_, const allocator_type &alloc = {})
	  : result_code(code_), attribute_type(attribute_type_, alloc)
	{}
	sort_result(const sort_result &) = default;
	sort_result(sort_result &&) noexcept = default;
	sort_result(const sort_result &other, const allocator_type &alloc)
	  : result_code(other.result_code), attribute_type(other.attribute_type, alloc)
	{}
	sort_result(sort_result &&other, const allocator_type &alloc)
	  : result_code(other.result_code), attribute_type(std::move(other.attribute_type), alloc)
	{}
	auto operator=(const sort_result &) -> sort_result & = default;
	auto operator=(sort_result &&) -> sort_result & = default;
	~sort_result() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return attribute_type.get_allocator(); }

	[[nodiscard]] auto is_success() const noexcept -> bool { return result_code == 0; }

	friend auto operator==(const sort_result &, const sort_result &) -> bool = default;
};

[[nodiscard]] auto decode_sort_result(const control &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<sort_result>;

// Virtual List View (draft-ietf-ldapext-ldapv3-vlv-09): the
// VirtualListViewResponse control.
inline constexpr std::string_view vlv_request_oid = "2.16.840.1.113730.3.4.9";
inline constexpr std::string_view vlv_response_oid = "2.16.840.1.113730.3.4.10";

struct vlv_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// NOLINTBEGIN(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)
	// targetPosition: 1 for the first entry.
	std::int32_t target_position = 0;
	// contentCount: the server's estimate.
	std::int32_t content_count = 0;
	// virtualListViewResult; unknown values are kept.
	std::int32_t result_code = 0;
	// contextID; nullopt when absent.
	std::optional<std::pmr::string> context_id{};
	// NOLINTEND(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)

	vlv_response() = default;
	explicit vlv_response(const allocator_type &alloc) : alloc_(alloc) {}
	vlv_response(std::int32_t target_position_,
	  std::int32_t content_count_,
	  std::int32_t result_code_ = 0,
	  std::optional<std::string_view> context_id_ = std::nullopt,
	  const allocator_type &alloc = {});
	vlv_response(const vlv_response &other);
	vlv_response(vlv_response &&) noexcept = default;
	vlv_response(const vlv_response &other, const allocator_type &alloc);
	vlv_response(vlv_response &&other, const allocator_type &alloc);
	auto operator=(const vlv_response &other) -> vlv_response &;
	auto operator=(vlv_response &&other) -> vlv_response &;
	~vlv_response() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return alloc_; }

	[[nodiscard]] auto is_success() const noexcept -> bool { return result_code == 0; }

	friend auto operator==(const vlv_response &a, const vlv_response &b) -> bool
	{
		return a.target_position == b.target_position && a.content_count == b.content_count
			   && a.result_code == b.result_code && a.context_id == b.context_id;
	}

  private:
	allocator_type alloc_{};
};

[[nodiscard]] auto decode_vlv_response(const control &c,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<vlv_response>;

// Pre-Read and Post-Read (RFC 4527): the response control carries the entry.
inline constexpr std::string_view pre_read_oid = "1.3.6.1.1.13.1";
inline constexpr std::string_view post_read_oid = "1.3.6.1.1.13.2";

// The entry of a pre-read or post-read response control.
[[nodiscard]] auto decode_read_entry(const control &c, const decode_options &options = {})
  -> result<search_result_entry>;

// ---------------------------------------------------------------- transactions (RFC 5805)

// Start Transaction, End Transaction and the Aborted Transaction Notice.
inline constexpr std::string_view start_transaction_oid = "1.3.6.1.1.21.1";
inline constexpr std::string_view transaction_specification_oid = "1.3.6.1.1.21.2";
inline constexpr std::string_view end_transaction_oid = "1.3.6.1.1.21.3";
inline constexpr std::string_view aborted_transaction_notice_oid = "1.3.6.1.1.21.4";

// txnEndReq (RFC 5805 section 2.3)
struct end_transaction_request
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	bool commit = true;// FALSE: abort
	std::pmr::string identifier{};

	end_transaction_request() = default;
	explicit end_transaction_request(const allocator_type &alloc) : identifier(alloc) {}
	end_transaction_request(bool commit_, std::string_view identifier_, const allocator_type &alloc = {})
	  : commit(commit_), identifier(identifier_, alloc)
	{}
	end_transaction_request(const end_transaction_request &) = default;
	end_transaction_request(end_transaction_request &&) noexcept = default;
	end_transaction_request(const end_transaction_request &other, const allocator_type &alloc)
	  : commit(other.commit), identifier(other.identifier, alloc)
	{}
	end_transaction_request(end_transaction_request &&other, const allocator_type &alloc)
	  : commit(other.commit), identifier(std::move(other.identifier), alloc)
	{}
	auto operator=(const end_transaction_request &) -> end_transaction_request & = default;
	auto operator=(end_transaction_request &&) -> end_transaction_request & = default;
	~end_transaction_request() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return identifier.get_allocator(); }

	friend auto operator==(const end_transaction_request &, const end_transaction_request &) -> bool = default;
};

[[nodiscard]] auto encode_end_transaction_request(const end_transaction_request &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> std::pmr::string;

// updateControls: an update's response controls and request message id.
struct update_controls
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::int32_t message_id = 0;
	std::pmr::vector<control> controls{};

	update_controls() = default;
	explicit update_controls(const allocator_type &alloc) : controls(alloc) {}
	explicit update_controls(std::int32_t message_id_) : message_id(message_id_) {}
	update_controls(std::int32_t message_id_,
	  std::initializer_list<control> controls_,
	  const allocator_type &alloc = {})
	  : message_id(message_id_), controls(controls_, alloc)
	{}
	update_controls(const update_controls &) = default;
	update_controls(update_controls &&) noexcept = default;
	update_controls(const update_controls &other, const allocator_type &alloc)
	  : message_id(other.message_id), controls(other.controls, alloc)
	{}
	update_controls(update_controls &&other, const allocator_type &alloc)
	  : message_id(other.message_id), controls(std::move(other.controls), alloc)
	{}
	auto operator=(const update_controls &) -> update_controls & = default;
	auto operator=(update_controls &&) -> update_controls & = default;
	~update_controls() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return controls.get_allocator(); }

	friend auto operator==(const update_controls &, const update_controls &) -> bool = default;
};

// txnEndRes (RFC 5805 section 2.3)
struct end_transaction_response
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// The update a non-success response is about.
	std::optional<std::int32_t> message_id{};
	// empty = absent
	std::pmr::vector<update_controls> updates_controls{};

	end_transaction_response() = default;
	explicit end_transaction_response(const allocator_type &alloc) : updates_controls(alloc) {}
	explicit end_transaction_response(std::optional<std::int32_t> message_id_) : message_id(message_id_) {}
	end_transaction_response(std::optional<std::int32_t> message_id_,
	  std::initializer_list<update_controls> updates_controls_,
	  const allocator_type &alloc = {})
	  : message_id(message_id_), updates_controls(updates_controls_, alloc)
	{}
	end_transaction_response(const end_transaction_response &) = default;
	end_transaction_response(end_transaction_response &&) noexcept = default;
	end_transaction_response(const end_transaction_response &other, const allocator_type &alloc)
	  : message_id(other.message_id), updates_controls(other.updates_controls, alloc)
	{}
	end_transaction_response(end_transaction_response &&other, const allocator_type &alloc)
	  : message_id(other.message_id), updates_controls(std::move(other.updates_controls), alloc)
	{}
	auto operator=(const end_transaction_response &) -> end_transaction_response & = default;
	auto operator=(end_transaction_response &&) -> end_transaction_response & = default;
	~end_transaction_response() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return updates_controls.get_allocator(); }

	friend auto operator==(const end_transaction_response &, const end_transaction_response &) -> bool = default;
};

[[nodiscard]] auto decode_end_transaction_response(std::string_view value, const decode_options &options = {})
  -> result<end_transaction_response>;

}// namespace jhetz::ldap
