// Runtime schema validation (DESIGN.md section 6): a lenient parser of the
// server's subschema (RFC 4512), and validate<T> checking a descriptor.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/mapping.hpp"

#include <array>
#include <cstddef>
#include <initializer_list>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace jhetz::ldap {

// RFC 4512 section 4.1.2 AttributeUsage.
enum class attribute_usage { user_applications, directory_operation, distributed_operation, dsa_operation };

struct attribute_type
{
	std::string oid{};
	std::vector<std::string> names{};
	std::optional<std::string> sup{};// name or OID
	// name or OID, as the server wrote it
	std::optional<std::string> equality{};
	std::optional<std::string> syntax{};// OID, {length} removed
	bool single_value = false;
	bool no_user_modification = false;
	attribute_usage usage = attribute_usage::user_applications;
};

// RFC 4512 section 4.1.1; STRUCTURAL when the definition gives none.
enum class object_class_kind { abstract, structural, auxiliary };

// RFC 4512 section 4.1.1, in its field order.
struct object_class_type
{
	std::string oid{};
	std::vector<std::string> names{};
	std::vector<std::string> sup{};
	object_class_kind kind = object_class_kind::structural;
	std::vector<std::string> must{};
	std::vector<std::string> may{};
};

// RFC 4512 section 4.1.6: the DIT content rule of a structural class.
struct dit_content_rule
{
	std::string oid{};// the structural object class's
	std::vector<std::string> names{};
	bool obsolete = false;// OBSOLETE: validate ignores it
	std::vector<std::string> aux{};
	std::vector<std::string> must{};
	std::vector<std::string> may{};
	std::vector<std::string> precluded{};// NOT
};

// One definition each; errors are decode_error with the reason.
[[nodiscard]] auto parse_attribute_type(std::string_view text) -> result<attribute_type>;
[[nodiscard]] auto parse_object_class(std::string_view text) -> result<object_class_type>;
[[nodiscard]] auto parse_dit_content_rule(std::string_view text) -> result<dit_content_rule>;

class server_schema;
namespace detail {
	[[nodiscard]] auto declares_equality(const server_schema &s) noexcept -> bool;
}// namespace detail

class server_schema
{
  public:
	server_schema() = default;
	// Unparseable definitions are skipped and counted.
	[[nodiscard]] static auto parse(std::span<const std::pmr::string> attribute_types,
	  std::span<const std::pmr::string> object_classes,
	  std::span<const std::pmr::string> dit_content_rules = {}) -> server_schema;

	// By any NAME (case-insensitive) or OID, options ignored; nullptr if unknown.
	[[nodiscard]] auto find_attribute(std::string_view name) const noexcept -> const attribute_type *;
	[[nodiscard]] auto find_object_class(std::string_view name) const noexcept -> const object_class_type *;
	// nullptr if the server publishes none.
	[[nodiscard]] auto find_dit_content_rule(std::string_view class_oid) const noexcept -> const dit_content_rule *;
	// The attribute's SYNTAX, or its supertypes'; nullptr if none. Points into
	// `a` or the schema.
	[[nodiscard]] auto syntax_of(const attribute_type &a) const noexcept -> const std::string *;
	auto syntax_of(const attribute_type &&) const -> const std::string * = delete;
	// The attribute's EQUALITY, or its supertypes'; nullptr if none.
	[[nodiscard]] auto equality_of(const attribute_type &a) const noexcept -> const std::string *;
	auto equality_of(const attribute_type &&) const -> const std::string * = delete;
	// Defined by the server but skipped because its SYNTAX is not a numeric OID.
	[[nodiscard]] auto skipped_for_syntax(std::string_view name) const noexcept -> bool;

	auto attribute_count() const noexcept -> std::size_t { return attributes_.size(); }
	auto object_class_count() const noexcept -> std::size_t { return classes_.size(); }
	auto dit_content_rule_count() const noexcept -> std::size_t { return rules_.size(); }
	auto skipped() const noexcept -> std::size_t { return skipped_; }

  private:
	std::vector<attribute_type> attributes_{};
	std::vector<object_class_type> classes_{};
	std::vector<dit_content_rule> rules_{};
	// Name / OID -> index; the first definition wins.
	using name_index = std::unordered_map<std::string, std::size_t, detail::ci_hash, detail::ci_equal>;
	name_index attribute_index_{};
	name_index class_index_{};
	name_index rule_index_{};// by OID only
	std::unordered_set<std::string, detail::ci_hash, detail::ci_equal> bad_syntax_{};
	std::size_t skipped_ = 0;
	bool declares_equality_ = false;

	friend auto detail::declares_equality(const server_schema &s) noexcept -> bool;
};

// ---------------------------------------------------------------- syntaxes

// Syntax OIDs (RFC 4517, RFC 4523, RFC 2252).
namespace syntax {
	inline constexpr const char *boolean = "1.3.6.1.4.1.1466.115.121.1.7";
	inline constexpr const char *dn = "1.3.6.1.4.1.1466.115.121.1.12";
	inline constexpr const char *generalized_time = "1.3.6.1.4.1.1466.115.121.1.24";
	inline constexpr const char *integer = "1.3.6.1.4.1.1466.115.121.1.27";
	inline constexpr const char *name_and_optional_uid = "1.3.6.1.4.1.1466.115.121.1.34";
	inline constexpr const char *numeric_string = "1.3.6.1.4.1.1466.115.121.1.36";
	inline constexpr const char *directory_string = "1.3.6.1.4.1.1466.115.121.1.15";
	// Binary syntaxes: octets, not UTF-8 text.
	inline constexpr const char *audio = "1.3.6.1.4.1.1466.115.121.1.4";
	inline constexpr const char *binary = "1.3.6.1.4.1.1466.115.121.1.5";
	inline constexpr const char *certificate = "1.3.6.1.4.1.1466.115.121.1.8";
	inline constexpr const char *certificate_list = "1.3.6.1.4.1.1466.115.121.1.9";
	inline constexpr const char *certificate_pair = "1.3.6.1.4.1.1466.115.121.1.10";
	inline constexpr const char *fax = "1.3.6.1.4.1.1466.115.121.1.23";
	inline constexpr const char *jpeg = "1.3.6.1.4.1.1466.115.121.1.28";
	inline constexpr const char *octet_string = "1.3.6.1.4.1.1466.115.121.1.40";
}// namespace syntax

// The syntaxes a value type accepts, for validate<T>; empty: any.
template<class T> struct value_syntaxes
{
	static auto get() -> std::span<const char *const>
	{
		if constexpr (requires { value_traits<T>::syntaxes; }) {
			static constexpr auto list = value_traits<T>::syntaxes;
			return std::span<const char *const>(std::data(list), std::size(list));
		} else {
			return {};
		}
	}
};

namespace detail {
	inline constexpr auto integer_syntaxes = std::to_array<const char *>({ syntax::integer, syntax::numeric_string });
	inline constexpr const char *large_integer_syntax = "1.2.840.113556.1.4.906";
	inline constexpr auto int64_syntaxes =
	  std::to_array<const char *>({ syntax::integer, syntax::numeric_string, large_integer_syntax });
	inline constexpr auto dn_syntaxes = std::to_array<const char *>({ syntax::dn, syntax::name_and_optional_uid });
	inline constexpr auto bool_syntaxes = std::to_array<const char *>({ syntax::boolean });
	inline constexpr auto time_syntaxes = std::to_array<const char *>({ syntax::generalized_time });
}// namespace detail

// Signed integers of 64 bits or more also read AD's Large Integer.
template<std::integral T>
	requires(!std::same_as<T, bool> && !detail::char_like<T>)
struct value_syntaxes<T>
{
	static auto get() -> std::span<const char *const>
	{
		if constexpr (std::signed_integral<T>
					  && std::numeric_limits<T>::digits >= std::numeric_limits<std::int64_t>::digits) {
			return detail::int64_syntaxes;
		} else {
			return detail::integer_syntaxes;
		}
	}
};
template<> struct value_syntaxes<bool>
{
	static auto get() -> std::span<const char *const> { return detail::bool_syntaxes; }
};
template<> struct value_syntaxes<dn>
{
	static auto get() -> std::span<const char *const> { return detail::dn_syntaxes; }
};
template<> struct value_syntaxes<std::chrono::sys_seconds>
{
	static auto get() -> std::span<const char *const> { return detail::time_syntaxes; }
};

// The syntaxes a value type refuses when value_syntaxes<T> is empty.
template<class T> struct value_rejected_syntaxes
{
	static auto get() -> std::span<const char *const> { return {}; }
};

namespace detail {
	inline constexpr auto binary_syntaxes = std::to_array<const char *>({ syntax::audio,
	  syntax::binary,
	  syntax::certificate,
	  syntax::certificate_list,
	  syntax::certificate_pair,
	  syntax::fax,
	  syntax::jpeg,
	  syntax::octet_string });
}// namespace detail

template<> struct value_rejected_syntaxes<std::string>
{
	static auto get() -> std::span<const char *const> { return detail::binary_syntaxes; }
};
template<> struct value_rejected_syntaxes<std::pmr::string>
{
	static auto get() -> std::span<const char *const> { return detail::binary_syntaxes; }
};

// ---------------------------------------------------------------- report

struct schema_issue
{
	enum class kind {
		unknown_object_class,// error
		unknown_attribute,// error
		// error, also when the syntax cannot be determined
		syntax_mismatch,
		writable_but_no_user_modification,// error
		single_member_multi_valued,// warning
		// warning
		must_attribute_not_mapped,
		// warning
		must_attribute_not_required,
		// warning
		unknown_superclass,
		// warning
		not_auxiliary,
		// warning
		attribute_not_allowed,
		// warning
		auxiliary_class_not_allowed,
		// warning
		not_primary_name,
		// warning
		no_equality_rule,
		// error
		duplicate_attribute,
	};
	kind what;
	std::string name;// the attribute or object class
	std::string detail;
	[[nodiscard]] auto is_error() const noexcept -> bool
	{
		return what != kind::single_member_multi_valued && what != kind::must_attribute_not_mapped
			   && what != kind::must_attribute_not_required && what != kind::unknown_superclass
			   && what != kind::not_auxiliary && what != kind::attribute_not_allowed
			   && what != kind::auxiliary_class_not_allowed && what != kind::not_primary_name
			   && what != kind::no_equality_rule;
	}
};

struct schema_report
{
	std::vector<schema_issue> issues{};
	// No errors (warnings allowed).
	[[nodiscard]] auto ok() const noexcept -> bool;
	// One issue per line: "error: attribute uidNumber: ..." / "warning: ...".
	[[nodiscard]] auto to_string() const -> std::string;
};

namespace detail {
	void check_field(const server_schema &s,
	  std::string_view name,
	  cardinality kind,
	  bool read_only,
	  std::span<const char *const> syntaxes,
	  std::span<const char *const> rejected,
	  schema_report &out);
	void check_object_class(const server_schema &s, std::string_view name, schema_report &out);
	void check_auxiliary_class(const server_schema &s, std::string_view name, schema_report &out);

	struct field_use
	{
		std::string_view name;
		cardinality kind;
		bool read_only;
	};
	void check_class_attributes(const server_schema &s,
	  std::span<const char *const> classes,
	  std::span<const field_use> fields,
	  schema_report &out);
	void
	  check_duplicate_attributes(const server_schema &s, std::span<const std::string_view> names, schema_report &out);
}// namespace detail

// Checks T's descriptor against the server's schema; lists every issue.
template<described T> [[nodiscard]] auto validate(const server_schema &s) -> schema_report
{
	schema_report out;
	for (const char *oc : detail::all_object_classes<T>) {
		detail::check_object_class(s, oc, out);
	}
	for (const char *oc : schema<T>.auxiliary.names) {
		detail::check_auxiliary_class(s, oc, out);
	}
	std::apply(
	  [&](const auto &...f) {
		  (detail::check_field(s,
			 f.name,
			 std::remove_cvref_t<decltype(f)>::kind,
			 f.read_only,
			 value_syntaxes<typename std::remove_cvref_t<decltype(f)>::element>::get(),
			 value_rejected_syntaxes<typename std::remove_cvref_t<decltype(f)>::element>::get(),
			 out),
			...);
	  },
	  schema<T>.fields);
	static constexpr auto names = detail::attribute_name_array<T>();
	detail::check_duplicate_attributes(s, names, out);
	if constexpr (schema<T>.classes.names.size() > 0) {
		const auto fields = std::apply(
		  [](const auto &...f) {
			  return std::array<detail::field_use, sizeof...(f)>{ detail::field_use{
				.name = f.name, .kind = std::remove_cvref_t<decltype(f)>::kind, .read_only = f.read_only }... };
		  },
		  schema<T>.fields);
		detail::check_class_attributes(s, detail::all_object_classes<T>, fields, out);
	}
	return out;
}

}// namespace jhetz::ldap
