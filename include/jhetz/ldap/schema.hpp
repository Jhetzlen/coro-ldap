// Runtime schema validation (DESIGN.md section 6): the server's subschema
// (RFC 4512), parsed only as far as the checks need, and validate<T>,
// which checks a struct descriptor (mapping.hpp) against it.
//
//   ldap::result<ldap::server_schema> s = co_await conn.load_schema();
//   ldap::schema_report rep = ldap::validate<person>(*s);
//   if (!rep.ok()) std::puts(rep.to_string().c_str());   // every issue, not just the first
//
// Parsing keeps, for attributeTypes: the OID, every NAME, SUP, EQUALITY,
// SYNTAX (the OID, without a {length}), SINGLE-VALUE and
// NO-USER-MODIFICATION; for objectClasses: the OID, every NAME, SUP, the
// kind, MUST and MAY. Everything else is skipped.
// Definitions that do not parse are skipped and counted, never fatal (the
// text comes from the server, so the parser must accept anything without
// harm: there is a fuzz target). Lenient where real servers are: quoted
// OIDs (Active Directory), keywords in any case, missing spaces before ')'
// (and around a list's "$": RFC 4512 allows none, "(sn$cn)").
// A definition whose OID is not a valid OID, whose SYNTAX is not a numeric
// OID with an optional "{" digits "}" right after it (RFC 4512 noidlen: no
// descriptor, no space, no other text), or with a keyword that is not a
// keystring or X- extension name (a "{len}" spaced from the OID is one) is
// skipped (the names of those skipped for their SYNTAX are remembered, see
// skipped_for_syntax); NAMEs that are not valid descriptors are dropped
// (they could never be looked up), and so are SUP, MUST and MAY entries of
// an object class that are not oids (descriptors or numeric OIDs); neither
// counts in skipped(), which counts definitions. A definition that is not
// well-formed UTF-8 is skipped too: RFC 4512 qdstrings (NAME, DESC) are UTF-8 and the
// rest of the grammar is ASCII.
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

struct attribute_type
{
	std::string oid{};
	std::vector<std::string> names{};
	std::optional<std::string> sup{};// supertype (name or OID)
	// equality matching rule (name or OID, as the server wrote it); see
	// matching.hpp
	std::optional<std::string> equality{};
	std::optional<std::string> syntax{};// syntax OID, {length} removed
	bool single_value = false;
	bool no_user_modification = false;
};

// RFC 4512 section 4.1.1 ObjectClassDescription kind: STRUCTURAL when the
// definition gives none.
enum class object_class_kind { abstract, structural, auxiliary };

// RFC 4512 section 4.1.1, in its field order. sup, must and may hold the
// oids as the server wrote them (names or numeric OIDs).
struct object_class_type
{
	std::string oid{};
	std::vector<std::string> names{};
	std::vector<std::string> sup{};// superclasses
	object_class_kind kind = object_class_kind::structural;
	std::vector<std::string> must{};// required attribute types
	std::vector<std::string> may{};// allowed attribute types
};

// One definition each (an attributeTypes / objectClasses value); errors are
// decode_error with the reason.
[[nodiscard]] auto parse_attribute_type(std::string_view text) -> result<attribute_type>;
[[nodiscard]] auto parse_object_class(std::string_view text) -> result<object_class_type>;

class server_schema
{
  public:
	server_schema() = default;
	// From the attributeTypes and objectClasses values of a subschema
	// entry. Unparseable definitions are skipped (see skipped()).
	[[nodiscard]] static auto parse(std::span<const std::pmr::string> attribute_types,
	  std::span<const std::pmr::string> object_classes) -> server_schema;

	// By any NAME (case-insensitive) or the OID; options ("cn;lang-en") are
	// ignored. nullptr if unknown. Case folds A-Z only (names and OIDs are
	// ASCII, RFC 4512 section 1.4). No allocation.
	[[nodiscard]] auto find_attribute(std::string_view name) const noexcept -> const attribute_type *;
	[[nodiscard]] auto find_object_class(std::string_view name) const noexcept -> const object_class_type *;
	// The attribute's SYNTAX, or its supertypes' (SUP followed, with a depth
	// limit against cycles); nullptr if none declares one, or if a SUP on the
	// chain is not found (see skipped_for_syntax). Points into a (if it
	// declares SYNTAX itself) or the schema: valid while both live, so a
	// temporary attribute is rejected.
	[[nodiscard]] auto syntax_of(const attribute_type &a) const noexcept -> const std::string *;
	auto syntax_of(const attribute_type &&) const -> const std::string * = delete;
	// The attribute's EQUALITY matching rule, or its supertypes' (RFC 4512
	// section 4.1.2: a subtype without one inherits its supertype's), with
	// the same SUP walk as syntax_of; nullptr if none declares one or a SUP
	// is not found. Valid while a and the schema live.
	[[nodiscard]] auto equality_of(const attribute_type &a) const noexcept -> const std::string *;
	auto equality_of(const attribute_type &&) const -> const std::string * = delete;
	// An attribute type definition by this NAME or OID (options ignored)
	// parsed, but was skipped because its SYNTAX is not a numeric OID: the
	// server defines it, the library cannot use it. Case-insensitive, no
	// allocation.
	[[nodiscard]] auto skipped_for_syntax(std::string_view name) const noexcept -> bool;

	auto attribute_count() const noexcept -> std::size_t { return attributes_.size(); }
	auto object_class_count() const noexcept -> std::size_t { return classes_.size(); }
	// Definitions that did not parse.
	auto skipped() const noexcept -> std::size_t { return skipped_; }

  private:
	std::vector<attribute_type> attributes_{};
	std::vector<object_class_type> classes_{};
	// Name / OID (as the server spells it; the first definition wins) -> index.
	using name_index = std::unordered_map<std::string, std::size_t, detail::ci_hash, detail::ci_equal>;
	name_index attribute_index_{};
	name_index class_index_{};
	// The names and OIDs of attribute types skipped for their SYNTAX.
	std::unordered_set<std::string, detail::ci_hash, detail::ci_equal> bad_syntax_{};
	std::size_t skipped_ = 0;
};

// ---------------------------------------------------------------- syntaxes

// Syntax OIDs used by the built-in value_traits and value_syntaxes: RFC
// 4517, RFC 4523, RFC 2252 and Active Directory's Large Integer.
namespace syntax {
	inline constexpr const char *boolean = "1.3.6.1.4.1.1466.115.121.1.7";
	inline constexpr const char *dn = "1.3.6.1.4.1.1466.115.121.1.12";
	inline constexpr const char *generalized_time = "1.3.6.1.4.1.1466.115.121.1.24";
	inline constexpr const char *integer = "1.3.6.1.4.1.1466.115.121.1.27";
	inline constexpr const char *name_and_optional_uid = "1.3.6.1.4.1.1466.115.121.1.34";
	inline constexpr const char *numeric_string = "1.3.6.1.4.1.1466.115.121.1.36";
	inline constexpr const char *directory_string = "1.3.6.1.4.1.1466.115.121.1.15";
	// Active Directory's Large Integer / Interval (a signed 64-bit integer in
	// decimal): FILETIME dates such as accountExpires, intervals such as
	// maxPwdAge, and counters such as uSNChanged. See ad.hpp.
	inline constexpr const char *ad_large_integer = "1.2.840.113556.1.4.906";

	// Binary syntaxes: their values are octets, not UTF-8 text, so a string
	// member rejects them (value_rejected_syntaxes). Octet String, Fax and
	// JPEG are RFC 4517 (3.3.25, 3.3.12, 3.3.17); Certificate, Certificate
	// List and Certificate Pair are RFC 4523 (section 2); Audio and Binary
	// are RFC 2252 (section 4.3.2; RFC 4517 dropped them, servers still
	// declare them).
	inline constexpr const char *audio = "1.3.6.1.4.1.1466.115.121.1.4";
	inline constexpr const char *binary = "1.3.6.1.4.1.1466.115.121.1.5";
	inline constexpr const char *certificate = "1.3.6.1.4.1.1466.115.121.1.8";
	inline constexpr const char *certificate_list = "1.3.6.1.4.1.1466.115.121.1.9";
	inline constexpr const char *certificate_pair = "1.3.6.1.4.1.1466.115.121.1.10";
	inline constexpr const char *fax = "1.3.6.1.4.1.1466.115.121.1.23";
	inline constexpr const char *jpeg = "1.3.6.1.4.1.1466.115.121.1.28";
	inline constexpr const char *octet_string = "1.3.6.1.4.1.1466.115.121.1.40";
}// namespace syntax

// The syntaxes a value type accepts, for validate<T>. Empty: any (binary
// values can hold whatever an attribute has; strings take any syntax but
// those value_rejected_syntaxes lists). Specialize, or give value_traits<T>
// a `syntaxes` member (a range of const char*).
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
	inline constexpr auto int64_syntaxes =
	  std::to_array<const char *>({ syntax::integer, syntax::numeric_string, syntax::ad_large_integer });
	inline constexpr auto dn_syntaxes = std::to_array<const char *>({ syntax::dn, syntax::name_and_optional_uid });
	inline constexpr auto bool_syntaxes = std::to_array<const char *>({ syntax::boolean });
	inline constexpr auto time_syntaxes = std::to_array<const char *>({ syntax::generalized_time });
}// namespace detail

// Integers read INTEGER and NumericString; signed integers of 64 bits or
// more also read AD Large Integer, whose values (FILETIME dates, negative
// intervals) a narrower or unsigned type could not hold: a 32-bit or
// unsigned member on such an attribute is a syntax_mismatch.
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

// The syntaxes a value type refuses, for validate<T>: checked only when
// value_syntaxes<T> is empty (any syntax but these). Empty by default.
// Strings refuse the binary syntaxes: their values are not UTF-8 text, so a
// string member would fail to decode them (value_traits<std::string>); map
// such attributes (userPassword, jpegPhoto, userCertificate, ...) to
// ldap::binary.
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
		unknown_attribute,// error (also when its definition was skipped, see detail)
		// error; also when the syntax cannot be determined because a SUP on
		// the attribute's chain is not defined (or was skipped), or because
		// no definition on the chain declares a SYNTAX
		syntax_mismatch,
		writable_but_no_user_modification,// error
		single_member_multi_valued,// warning: only fails if an entry really has several values
		// warning: a MUST attribute of a declared object class or of one of
		// its superclasses that no member maps (add(dn, T) does not send it)
		must_attribute_not_mapped,
		// warning: a MUST attribute mapped only by std::optional, std::vector
		// or read_only members (add(dn, T) may not send it)
		must_attribute_not_required,
		// warning: a superclass (SUP) of a declared object class that is not
		// defined on the server: the MUSTs it would add are not checked
		unknown_superclass,
	};
	kind what;
	std::string name;// the attribute or object class
	std::string detail;
	[[nodiscard]] auto is_error() const noexcept -> bool
	{
		return what != kind::single_member_multi_valued && what != kind::must_attribute_not_mapped
			   && what != kind::must_attribute_not_required && what != kind::unknown_superclass;
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

	// What add(dn, T) does with one member, for check_must.
	struct field_use
	{
		std::string_view name;
		cardinality kind;
		bool read_only;
	};
	void check_must(const server_schema &s,
	  std::span<const char *const> classes,
	  std::span<const field_use> fields,
	  schema_report &out);
}// namespace detail

// Checks T's descriptor against the server's schema; lists every issue.
//
// With declared object classes, also checks their MUST attributes, and
// those of their superclasses (SUP followed, RFC 4512 section 2.4), against
// the members: each must be mapped by a required (T), writable member, or
// add(dn, T) may leave it out and the server refuse the entry
// (objectClassViolation). Those are warnings, never errors: the descriptor
// may be a read projection (search_as), the entry's RDN supplies its
// attribute values at add time (RFC 4511 section 4.7), and some servers fill
// MUSTs in themselves (Active Directory: objectCategory, instanceType,
// nTSecurityDescriptor). Not reported: objectClass (add sends the declared
// classes) and NO-USER-MODIFICATION attributes (a client must not send
// them, RFC 4511 section 4.7). Subtypes do not count (a cn member does not
// map a MUST name); attribute options do (cn;lang-en maps cn).
template<described T> [[nodiscard]] auto validate(const server_schema &s) -> schema_report
{
	schema_report out;
	for (const char *oc : schema<T>.classes.names) {
		detail::check_object_class(s, oc, out);
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
	if constexpr (schema<T>.classes.names.size() > 0) {
		const auto fields = std::apply(
		  [](const auto &...f) {
			  return std::array<detail::field_use, sizeof...(f)>{ detail::field_use{
				.name = f.name, .kind = std::remove_cvref_t<decltype(f)>::kind, .read_only = f.read_only }... };
		  },
		  schema<T>.fields);
		detail::check_must(s, schema<T>.classes.names, fields, out);
	}
	return out;
}

}// namespace jhetz::ldap
