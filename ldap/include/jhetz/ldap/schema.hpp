// Runtime schema validation (DESIGN.md section 6): the server's subschema
// (RFC 4512), parsed only as far as the checks need, and validate<T>,
// which checks a struct descriptor (mapping.hpp) against it.
//
//   ldap::result<ldap::server_schema> s = co_await conn.load_schema();
//   ldap::schema_report rep = ldap::validate<person>(*s);
//   if (!rep.ok()) std::puts(rep.to_string().c_str());   // every issue, not just the first
//
// Parsing keeps, for attributeTypes: the OID, every NAME, SUP, SYNTAX (the
// OID, without a {length}), SINGLE-VALUE and NO-USER-MODIFICATION; for
// objectClasses: the OID and every NAME. Everything else is skipped.
// Definitions that do not parse are skipped and counted, never fatal (the
// text comes from the server, so the parser must accept anything without
// harm: there is a fuzz target). Lenient where real servers are: quoted
// OIDs (Active Directory), keywords in any case, missing spaces before ')'.
// A definition whose OID is not a valid OID, or whose SYNTAX is not a
// numeric OID (RFC 4512 noidlen: no descriptor, no other text), is
// skipped; NAMEs that are not valid descriptors are dropped (they could
// never be looked up).
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/mapping.hpp"

#include <cstddef>
#include <initializer_list>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace jhetz::ldap {

struct attribute_type
{
	std::string oid{};
	std::vector<std::string> names{};
	std::optional<std::string> sup{};// supertype (name or OID)
	std::optional<std::string> syntax{};// syntax OID, {length} removed
	bool single_value = false;
	bool no_user_modification = false;
};

struct object_class_type
{
	std::string oid{};
	std::vector<std::string> names{};
};

// One definition each (an attributeTypes / objectClasses value); errors are
// decode_error with the reason.
[[nodiscard]] result<attribute_type> parse_attribute_type(std::string_view text);
[[nodiscard]] result<object_class_type> parse_object_class(std::string_view text);

class server_schema
{
  public:
	server_schema() = default;
	// From the attributeTypes and objectClasses values of a subschema
	// entry. Unparseable definitions are skipped (see skipped()).
	[[nodiscard]] static server_schema parse(std::span<const std::pmr::string> attribute_types,
	  std::span<const std::pmr::string> object_classes);

	// By any NAME (case-insensitive) or the OID; options ("cn;lang-en") are
	// ignored. nullptr if unknown. Case folds A-Z only (names and OIDs are
	// ASCII, RFC 4512 section 1.4). No allocation.
	[[nodiscard]] const attribute_type *find_attribute(std::string_view name) const noexcept;
	[[nodiscard]] const object_class_type *find_object_class(std::string_view name) const noexcept;
	// The attribute's SYNTAX, or its supertypes' (SUP followed, with a depth
	// limit against cycles); nullptr if none declares one. Points into the
	// schema: valid while it lives.
	[[nodiscard]] const std::string *syntax_of(const attribute_type &a) const noexcept;

	std::size_t attribute_count() const noexcept { return attributes_.size(); }
	std::size_t object_class_count() const noexcept { return classes_.size(); }
	// Definitions that did not parse.
	std::size_t skipped() const noexcept { return skipped_; }

  private:
	std::vector<attribute_type> attributes_{};
	std::vector<object_class_type> classes_{};
	// Name / OID (as the server spells it; the first definition wins) -> index.
	using name_index = std::unordered_map<std::string, std::size_t, detail::ci_hash, detail::ci_equal>;
	name_index attribute_index_{};
	name_index class_index_{};
	std::size_t skipped_ = 0;
};

// ---------------------------------------------------------------- syntaxes

// RFC 4517 syntax OIDs used by the built-in value_traits.
namespace syntax {
	inline constexpr const char *boolean = "1.3.6.1.4.1.1466.115.121.1.7";
	inline constexpr const char *dn = "1.3.6.1.4.1.1466.115.121.1.12";
	inline constexpr const char *generalized_time = "1.3.6.1.4.1.1466.115.121.1.24";
	inline constexpr const char *integer = "1.3.6.1.4.1.1466.115.121.1.27";
	inline constexpr const char *name_and_optional_uid = "1.3.6.1.4.1.1466.115.121.1.34";
	inline constexpr const char *numeric_string = "1.3.6.1.4.1.1466.115.121.1.36";
	inline constexpr const char *directory_string = "1.3.6.1.4.1.1466.115.121.1.15";
}// namespace syntax

// The syntaxes a value type accepts, for validate<T>. Empty: any (strings
// and binary values can hold whatever an attribute has). Specialize, or give
// value_traits<T> a `syntaxes` member (a range of const char*).
template<class T> struct value_syntaxes
{
	static std::span<const char *const> get()
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
	inline constexpr const char *integer_syntaxes[] = { syntax::integer, syntax::numeric_string };
	inline constexpr const char *dn_syntaxes[] = { syntax::dn, syntax::name_and_optional_uid };
	inline constexpr const char *bool_syntaxes[] = { syntax::boolean };
	inline constexpr const char *time_syntaxes[] = { syntax::generalized_time };
}// namespace detail

template<std::integral T>
	requires(!std::same_as<T, bool> && !detail::char_like<T>)
struct value_syntaxes<T>
{
	static std::span<const char *const> get() { return detail::integer_syntaxes; }
};
template<> struct value_syntaxes<bool>
{
	static std::span<const char *const> get() { return detail::bool_syntaxes; }
};
template<> struct value_syntaxes<dn>
{
	static std::span<const char *const> get() { return detail::dn_syntaxes; }
};
template<> struct value_syntaxes<std::chrono::sys_seconds>
{
	static std::span<const char *const> get() { return detail::time_syntaxes; }
};

// ---------------------------------------------------------------- report

struct schema_issue
{
	enum class kind {
		unknown_object_class,// error
		unknown_attribute,// error
		syntax_mismatch,// error
		writable_but_no_user_modification,// error
		single_member_multi_valued,// warning: only fails if an entry really has several values
	};
	kind what;
	std::string name;// the attribute or object class
	std::string detail;
	bool is_error() const noexcept { return what != kind::single_member_multi_valued; }
};

struct schema_report
{
	std::vector<schema_issue> issues{};
	// No errors (warnings allowed).
	bool ok() const noexcept;
	// One issue per line: "error: attribute uidNumber: ..." / "warning: ...".
	[[nodiscard]] std::string to_string() const;
};

namespace detail {
	void check_field(const server_schema &s,
	  std::string_view name,
	  cardinality kind,
	  bool read_only,
	  std::span<const char *const> syntaxes,
	  schema_report &out);
	void check_object_class(const server_schema &s, std::string_view name, schema_report &out);
}// namespace detail

// Checks T's descriptor against the server's schema; lists every issue.
template<described T> [[nodiscard]] schema_report validate(const server_schema &s)
{
	schema_report out;
	for (const char *oc : schema<T>.classes.names) detail::check_object_class(s, oc, out);
	std::apply(
	  [&](const auto &...f) {
		  (detail::check_field(s,
			 f.name,
			 std::remove_cvref_t<decltype(f)>::kind,
			 f.read_only,
			 value_syntaxes<typename std::remove_cvref_t<decltype(f)>::element>::get(),
			 out),
			...);
	  },
	  schema<T>.fields);
	return out;
}

}// namespace jhetz::ldap
