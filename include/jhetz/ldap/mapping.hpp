// Typed mapping between directory entries and C++ structs (DESIGN.md
// section 4): a descriptor names the attribute of each member, value_traits
// converts values, and the member's type decides cardinality.
//
//   struct person {
//       std::string                 uid;        // required, single-valued
//       std::optional<std::string>  mail;       // optional
//       std::vector<ldap::dn>       member_of;  // multi-valued
//       std::chrono::sys_seconds    created{};  // GeneralizedTime
//   };
//
//   template<> constexpr auto jhetz::ldap::schema<person> = jhetz::ldap::describe(
//       jhetz::ldap::object_class("inetOrgPerson"),   // optional
//       jhetz::ldap::field<&person::uid>("uid"),
//       jhetz::ldap::field<&person::mail>("mail"),
//       jhetz::ldap::field<&person::member_of>("memberOf"),
//       jhetz::ldap::field<&person::created>("createTimestamp", jhetz::ldap::read_only));
//
//   ldap::result<person> p = ldap::decode<person>(entry);
//   co_await conn.search_as<person>({.base = base, .filter = f});
//   co_await conn.modify<person>(dn, {ldap::replace<&person::mail>("new@example.org")});
//   co_await conn.add(dn, person{...});
//   auto f = ldap::filters::field<&person::uid>() == "jdoe";
//
// Compile-time checks: attribute and object class names are validated; a
// member type without value_traits, a member of another struct, a change to
// a member that is not in the descriptor or is read_only, and a value whose
// type does not match the member all fail to compile.
//
// Member shapes:
//   T                 required, single value: missing_attribute if absent,
//                     too_many_values if the entry has several
//   std::optional<T>  optional, single value: too_many_values if several
//   std::vector<T>    zero or more values
// (std::vector<std::byte>, ldap::binary, is a single binary value; use
// std::vector<ldap::binary> for several.) A value that does not convert is
// conversion_failed. Errors name the entry and the attribute in their
// context: "entry uid=x,ou=people,dc=example,dc=org: attribute uidNumber:
// not an integer: \"12a\"".
//
// value_traits<T> is the extension point, like std::formatter:
//
//   template<> struct jhetz::ldap::value_traits<my_type> {
//       static ldap::result<my_type> decode(std::string_view raw);  // conversion_failed on bad input
//       static std::string encode(const my_type &v);
//   };
//
// Built in: std::string, std::pmr::string, integers (decimal, range
// checked), bool (TRUE / FALSE, RFC 4517), ldap::dn, ldap::binary,
// std::chrono::sys_seconds (GeneralizedTime, RFC 4517 section 3.3.13) and
// enums that have an ldap::enum_names table. ad.hpp adds Active Directory's
// FILETIME dates and intervals.
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace jhetz::ldap {

using binary = std::vector<std::byte>;

// ---------------------------------------------------------------- value_traits

// Undefined for types without a conversion: using one does not compile.
template<class T> struct value_traits;

template<class T>
concept mapped_value = requires(std::string_view raw, const T &v) {
	{ value_traits<T>::decode(raw) } -> std::same_as<result<T>>;
	{ value_traits<T>::encode(v) } -> std::convertible_to<std::string>;
};

namespace detail {
	// "not an integer: \"12a\"" (the value is quoted, sanitized and cut at 64
	// bytes, see append_sanitized in src/format_util.hpp).
	auto conversion_error(std::string_view what, std::string_view raw) -> error;
}// namespace detail

template<> struct value_traits<std::string>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<std::string> { return std::string(raw); }
	[[nodiscard]] static auto encode(const std::string &v) -> std::string { return v; }
};

template<> struct value_traits<std::pmr::string>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<std::pmr::string> { return std::pmr::string(raw); }
	[[nodiscard]] static auto encode(const std::pmr::string &v) -> std::string { return std::string(v); }
};

namespace detail {
	template<class T>
	concept char_like = std::same_as<T, char> || std::same_as<T, wchar_t> || std::same_as<T, char8_t>
						|| std::same_as<T, char16_t> || std::same_as<T, char32_t>;
}// namespace detail

// LDAP INTEGER syntax (RFC 4517 section 3.3.16): decimal, optional '-'.
template<std::integral T>
	requires(!std::same_as<T, bool> && !detail::char_like<T>)
struct value_traits<T>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<T>
	{
		T v{};
		const char *end = raw.data() + raw.size();
		// NOLINTNEXTLINE(bugprone-suspicious-stringview-data-usage): bounded by end, no terminator read
		const auto [p, ec] = std::from_chars(raw.data(), end, v);
		if (raw.empty() || ec != std::errc{} || p != end) {
			return std::unexpected(detail::conversion_error("not an integer", raw));
		}
		return v;
	}
	[[nodiscard]] static auto encode(T v) -> std::string { return std::to_string(v); }
};

// Boolean syntax (RFC 4517 section 3.3.3): exactly "TRUE" or "FALSE".
template<> struct value_traits<bool>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<bool>
	{
		if (raw == "TRUE") {
			return true;
		}
		if (raw == "FALSE") {
			return false;
		}
		return std::unexpected(detail::conversion_error("not TRUE or FALSE", raw));
	}
	// NOLINTNEXTLINE(modernize-use-string-view): value_traits::encode returns std::string (concept mapped_value)
	[[nodiscard]] static auto encode(bool v) -> std::string { return v ? "TRUE" : "FALSE"; }
};

template<> struct value_traits<dn>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<dn>;
	[[nodiscard]] static auto encode(const dn &v) -> std::string { return std::string(v.to_string()); }
};

template<> struct value_traits<binary>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<binary>
	{
		const auto *p = reinterpret_cast<const std::byte *>(raw.data());
		return binary(p, p + raw.size());
	}
	[[nodiscard]] static auto encode(const binary &v) -> std::string { return std::string(detail::as_text(v)); }
};

// GeneralizedTime (RFC 4517 section 3.3.13): decodes every form (minutes,
// seconds, fractions of the last unit, "Z" or an offset; fractions of a
// second are truncated), encodes as "YYYYMMDDHHMMSSZ". Years 0000-9999.
[[nodiscard]] auto parse_generalized_time(std::string_view text) -> result<std::chrono::sys_seconds>;
[[nodiscard]] auto format_generalized_time(std::chrono::sys_seconds t) -> result<std::string>;

template<> struct value_traits<std::chrono::sys_seconds>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<std::chrono::sys_seconds>
	{
		return parse_generalized_time(raw);
	}
	// A time outside years 0000-9999 cannot be written: throws
	// std::out_of_range (a programming error, like a bad DN literal).
	[[nodiscard]] static auto encode(std::chrono::sys_seconds v) -> std::string;
};

// Enums map to names through a table:
//
//   template<> constexpr auto jhetz::ldap::enum_names<color> = std::to_array<std::pair<color, std::string_view>>(
//       {{color::red, "red"}, {color::green, "green"}});
//
// Names are matched exactly; an unknown name is conversion_failed.
struct no_enum_names
{
};
template<class E> constexpr auto enum_names = no_enum_names{};

template<class E>
	requires std::is_enum_v<E> && (!std::same_as<std::remove_cvref_t<decltype(enum_names<E>)>, no_enum_names>)
struct value_traits<E>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<E>
	{
		for (const auto &[value, name] : enum_names<E>) {
			if (name == raw) {
				return value;
			}
		}
		return std::unexpected(detail::conversion_error("not a known name", raw));
	}
	[[nodiscard]] static auto encode(E v) -> std::string
	{
		for (const auto &[value, name] : enum_names<E>) {
			if (value == v) {
				return std::string(name);
			}
		}
		return std::to_string(std::to_underlying(v));// not in the table: its number
	}
};

// ---------------------------------------------------------------- shapes

enum class cardinality { required, optional, multiple };

namespace detail {
	template<class M> struct shape
	{
		using element = M;
		static constexpr cardinality kind = cardinality::required;
	};
	template<class E> struct shape<std::optional<E>>
	{
		using element = E;
		static constexpr cardinality kind = cardinality::optional;
	};
	template<class E>
		requires(!std::same_as<E, std::byte>)
	struct shape<std::vector<E>>
	{
		using element = E;
		static constexpr cardinality kind = cardinality::multiple;
	};

	template<class> struct member_pointer;
	template<class C, class M> struct member_pointer<M C::*>
	{
		using owner = C;
		using type = M;
	};
}// namespace detail

// ---------------------------------------------------------------- descriptor

struct read_only_t
{
	explicit constexpr read_only_t() = default;
};
// Read but never written: add() skips it, a change to it does not compile
// (operational attributes such as createTimestamp).
inline constexpr read_only_t read_only{};

template<auto Ptr> struct field
{
	using owner = detail::member_pointer<decltype(Ptr)>::owner;
	using member = detail::member_pointer<decltype(Ptr)>::type;
	using element = detail::shape<member>::element;
	static constexpr auto ptr = Ptr;
	static constexpr cardinality kind = detail::shape<member>::kind;
	static_assert(mapped_value<element>,
	  "ldap::field: no ldap::value_traits for this member's value type (specialize value_traits<T>)");

	const char *name;
	bool read_only = false;

	consteval explicit field(const char *name_) : name(name_) { check(); }
	consteval field(const char *name_, read_only_t) : name(name_), read_only(true) { check(); }

  private:
	consteval void check() const
	{
		if (!detail::is_attribute_description(name)) {
			// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
			throw "ldap::field: invalid attribute description";
		}
	}
};

template<std::size_t N> struct object_classes
{
	std::array<const char *, N> names{};
};

template<class... S> consteval auto object_class(S... names)
{
	object_classes<sizeof...(S)> out{ { names... } };
	for (const char *n : out.names) {
		if (!detail::is_oid(n)) {
			// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
			throw "ldap::object_class: invalid object class name";
		}
	}
	return out;
}

template<std::size_t N, class... F> struct descriptor
{
	using owner = std::tuple_element_t<0, std::tuple<F...>>::owner;
	object_classes<N> classes;
	std::tuple<F...> fields;
};

template<std::size_t N, class F0, class... F> consteval auto describe(object_classes<N> classes, F0 f0, F... f)
{
	static_assert((std::same_as<typename F0::owner, typename F::owner> && ...),
	  "ldap::describe: every field must be a member of the same struct");
	return descriptor<N, F0, F...>{ classes, { f0, f... } };
}
template<class F0, class... F> consteval auto describe(F0 f0, F... f)
{
	return describe(object_classes<0>{}, f0, f...);
}

// Specialize for each mapped struct (see the top of this header).
struct not_described
{
};
template<class T> constexpr auto schema = not_described{};

template<class T>
concept described = !std::same_as<std::remove_cvref_t<decltype(schema<T>)>, not_described>;

namespace detail {
	template<auto A, auto B> consteval auto same_member() -> bool
	{
		if constexpr (std::same_as<decltype(A), decltype(B)>) {
			return A == B;
		} else {
			return false;
		}
	}

	// Index of the field for member `Ptr` in its struct's descriptor.
	template<auto Ptr> consteval auto field_index() -> std::size_t
	{
		using C = member_pointer<decltype(Ptr)>::owner;
		static_assert(described<C>, "ldap: this struct has no ldap::schema<T> descriptor");
		using fields = std::remove_cvref_t<decltype(schema<C>.fields)>;
		constexpr std::size_t n = std::tuple_size_v<fields>;
		std::size_t index = n;
		[&]<std::size_t... I>(std::index_sequence<I...>) {
			(void)((same_member<std::tuple_element_t<I, fields>::ptr, Ptr>() ? (index = I, true) : false) || ...);
		}(std::make_index_sequence<n>{});
		return index;
	}

	template<auto Ptr> constexpr auto field_of() -> const auto &
	{
		using C = member_pointer<decltype(Ptr)>::owner;
		constexpr std::size_t i = field_index<Ptr>();
		static_assert(i < std::tuple_size_v<std::remove_cvref_t<decltype(schema<C>.fields)>>,
		  "ldap: this member is not listed in ldap::schema<T>");
		return std::get<i>(schema<C>.fields);
	}

	auto with_context(error e, std::string_view prefix) -> error;
}// namespace detail

// The attribute names of T's descriptor, in order (what search_as requests).
template<described T>
[[nodiscard]] auto attribute_names(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> string_list
{
	string_list out(mr);
	std::apply([&](const auto &...f) { (out.emplace_back(f.name), ...); }, schema<T>.fields);
	return out;
}

// The object classes of T's descriptor (empty if none were declared).
template<described T> [[nodiscard]] constexpr auto object_classes_of() -> std::span<const char *const>
{
	return schema<T>.classes.names;
}

// ---------------------------------------------------------------- decode / encode

namespace detail {
	// The values entry::find returned, or none when the attribute is absent.
	inline auto values_or_empty(const std::pmr::vector<std::pmr::string> *values) noexcept
	  -> std::span<const std::pmr::string>
	{
		return values == nullptr ? std::span<const std::pmr::string>{} : std::span(*values);
	}

	template<class F> auto decode_field(std::span<const std::pmr::string> values) -> result<typename F::member>
	{
		using E = F::element;
		using M = F::member;
		const std::size_t n = values.size();
		if constexpr (F::kind == cardinality::multiple) {
			M out;
			out.reserve(n);
			for (const std::pmr::string &value : values) {
				auto v = value_traits<E>::decode(value);
				if (!v) {
					return std::unexpected(std::move(v.error()));
				}
				out.push_back(std::move(*v));
			}
			return out;
		} else {
			if (n > 1) {
				return fail(client_errc::too_many_values, std::to_string(n) + " values");
			}
			if (n == 0) {
				if constexpr (F::kind == cardinality::optional) {
					return M{};
				} else {
					return fail(client_errc::missing_attribute);
				}
			}
			auto v = value_traits<E>::decode(values.front());
			if (!v) {
				return std::unexpected(std::move(v.error()));
			}
			return M(std::move(*v));
		}
	}

	auto entry_context(std::string_view dn, std::string_view attribute) -> std::string;
}// namespace detail

// Converts an entry to T (default-constructed, then every described member
// assigned). Attribute names match case-insensitively, options included
// (see entry::find).
template<described T> [[nodiscard]] auto decode(const entry &e) -> result<T>
{
	T out{};
	std::optional<error> failed;
	std::apply(
	  [&](const auto &...f) {
		  (
			[&] {
				if (failed) {
					return;
				}
				auto v =
				  detail::decode_field<std::remove_cvref_t<decltype(f)>>(detail::values_or_empty(e.find(f.name)));
				if (!v) {
					failed = detail::with_context(std::move(v.error()), detail::entry_context(e.dn, f.name));
					return;
				}
				out.*std::remove_cvref_t<decltype(f)>::ptr = std::move(*v);
			}(),
			...);
	  },
	  schema<T>.fields);
	if (failed) {
		return std::unexpected(std::move(*failed));
	}
	return out;
}

namespace detail {
	template<class F>
	void encode_field(const F &f, const typename F::member &m, std::pmr::vector<partial_attribute> &out)
	{
		using E = F::element;
		partial_attribute a(f.name, {}, out.get_allocator());
		if constexpr (F::kind == cardinality::multiple) {
			for (const auto &v : m) {
				a.values.emplace_back(value_traits<E>::encode(v));
			}
		} else if constexpr (F::kind == cardinality::optional) {
			if (m) {
				a.values.emplace_back(value_traits<E>::encode(*m));
			}
		} else {
			a.values.emplace_back(value_traits<E>::encode(m));
		}
		if (!a.values.empty()) {
			out.push_back(std::move(a));
		}
	}
}// namespace detail

// The attributes to add for `value`: every described member except
// read_only ones and empty optionals / vectors, plus objectClass with the
// descriptor's object classes when it declares some. Without declared
// object classes the descriptor must map objectClass itself.
template<described T>
[[nodiscard]] auto to_attributes(const T &value, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> std::pmr::vector<partial_attribute>
{
	constexpr auto &d = schema<T>;
	constexpr bool has_object_class_field =
	  std::apply([](const auto &...f) { return (detail::iequals(f.name, "objectClass") || ...); }, d.fields);
	static_assert(d.classes.names.size() > 0 || has_object_class_field,
	  "ldap::to_attributes / add: declare ldap::object_class(...) in the descriptor or map an objectClass member");
	std::pmr::vector<partial_attribute> out(mr);
	if constexpr (d.classes.names.size() > 0) {
		partial_attribute oc("objectClass", {}, out.get_allocator());
		for (const char *n : d.classes.names) {
			oc.values.emplace_back(n);
		}
		out.push_back(std::move(oc));
	}
	std::apply(
	  [&](const auto &...f) {
		  ((f.read_only ? void() : detail::encode_field(f, value.*std::remove_cvref_t<decltype(f)>::ptr, out)), ...);
	  },
	  d.fields);
	return out;
}

// ---------------------------------------------------------------- typed changes

// A ModifyRequest change for a member of T, built by ldap::add / remove /
// replace below; connection::modify<T> takes them.
template<class T> struct change
{
	modify_change wire;
};

namespace detail {
	template<class E, class V>
	concept range_of =
	  std::ranges::input_range<V> && std::same_as<std::remove_cvref_t<std::ranges::range_value_t<V>>, E>;

	// The values `v` stands for, for member `Ptr`: one element, an optional
	// element (0 or 1), or, for a multi-valued member, a range of elements.
	template<auto Ptr, class V> auto encode_values(const V &v) -> string_list
	{
		using F = std::remove_cvref_t<decltype(field_of<Ptr>())>;
		using E = F::element;
		string_list out;
		if constexpr (std::convertible_to<const V &, E>) {
			// NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay): a string literal converts to E
			// through its pointer
			out.emplace_back(value_traits<E>::encode(static_cast<E>(v)));
		} else if constexpr (std::same_as<std::remove_cvref_t<V>, std::optional<E>>) {
			if (v) {
				out.emplace_back(value_traits<E>::encode(*v));
			}
		} else if constexpr (range_of<E, V>) {
			static_assert(F::kind == cardinality::multiple, "ldap: several values for a single-valued member");
			for (const auto &x : v) {
				out.emplace_back(value_traits<E>::encode(x));
			}
		} else {
			static_assert(false, "ldap: the value's type does not match the member's type");
		}
		return out;
	}

	template<auto Ptr> consteval void check_writable()
	{
		static_assert(!field_of<Ptr>().read_only, "ldap: this member is read_only in ldap::schema<T>");
	}

	template<auto Ptr> using owner_of = member_pointer<decltype(Ptr)>::owner;

	template<auto Ptr> auto make_change(modify_operation op, string_list values) -> change<owner_of<Ptr>>
	{
		check_writable<Ptr>();
		partial_attribute a(field_of<Ptr>().name);
		a.values = std::move(values);
		return { modify_change(op, a) };
	}
}// namespace detail

// Replaces all values of the member's attribute with `v` (an element, an
// optional element — nullopt removes the attribute — or, for a vector
// member, a range of elements).
template<auto Ptr, class V> [[nodiscard]] auto replace(const V &v) -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::replace, detail::encode_values<Ptr>(v));
}

// Adds values (an element, or a range of elements for a vector member).
template<auto Ptr, class V> [[nodiscard]] auto add(const V &v) -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::add, detail::encode_values<Ptr>(v));
}

// Removes the whole attribute, or only the given values.
template<auto Ptr> [[nodiscard]] auto remove() -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::delete_, {});
}
template<auto Ptr, class V> [[nodiscard]] auto remove(const V &v) -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::delete_, detail::encode_values<Ptr>(v));
}

// ---------------------------------------------------------------- typed filters

namespace filters {

	// Filters on a described member, with values of its type:
	// `filters::field<&person::uid_number>() >= 1000`.
	template<auto Ptr> class typed_attr
	{
		using E = std::remove_cvref_t<decltype(detail::field_of<Ptr>())>::element;

	  public:
		[[nodiscard]] auto operator==(const E &v) const -> filter { return a() == value_traits<E>::encode(v); }
		[[nodiscard]] auto operator>=(const E &v) const -> filter { return a() >= value_traits<E>::encode(v); }
		[[nodiscard]] auto operator<=(const E &v) const -> filter { return a() <= value_traits<E>::encode(v); }
		[[nodiscard]] auto approx(const E &v) const -> filter { return a().approx(value_traits<E>::encode(v)); }
		[[nodiscard]] auto present() const -> filter { return a().present(); }

	  private:
		static auto a() -> attr { return attr(detail::field_of<Ptr>().name); }
	};

	template<auto Ptr> [[nodiscard]] auto field() -> typed_attr<Ptr> { return {}; }

}// namespace filters

// `(&(objectClass=c1)...(objectClass=cN) f)`, or `f` when T declares no
// object class: what search_as<T> sends.
template<described T> [[nodiscard]] auto narrow_filter(filter f) -> filter
{
	constexpr auto &names = schema<T>.classes.names;
	if constexpr (names.size() == 0) {
		return f;
	} else {
		filter out = filters::attr("objectClass") == names[0];
		for (std::size_t i = 1; i < names.size(); ++i) {
			out = std::move(out) && filters::attr("objectClass") == names[i];
		}
		return std::move(out) && std::move(f);
	}
}

}// namespace jhetz::ldap
