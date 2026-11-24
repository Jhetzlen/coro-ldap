// Typed mapping between entries and C++ structs: a descriptor names each
// member's attribute, value_traits converts values, the member type decides
// cardinality (docs/API.md, DESIGN.md section 4).
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

namespace detail {
	template<class T> using encode_result_t = decltype(value_traits<T>::encode(std::declval<const T &>()));

	template<class R>
	concept encode_return =
	  std::same_as<std::remove_cvref_t<R>, result<std::string>> || std::convertible_to<R, std::string>;
}// namespace detail

// encode returns std::string (or convertible) or result<std::string>.
template<class T>
concept mapped_value = requires(std::string_view raw, const T &v) {
	{ value_traits<T>::decode(raw) } -> std::same_as<result<T>>;
	{ value_traits<T>::encode(v) } -> detail::encode_return;
};

namespace detail {
	// value_traits<T>::encode(v) as a result, whichever form the trait returns.
	template<mapped_value T> [[nodiscard]] auto encode_value(const T &v) -> result<std::string>
	{
		if constexpr (std::same_as<std::remove_cvref_t<encode_result_t<T>>, result<std::string>>) {
			return value_traits<T>::encode(v);
		} else {
			std::string s = value_traits<T>::encode(v);
			return s;
		}
	}

	// "not an integer (3-octet value)": the value's length, not the value.
	auto conversion_error(std::string_view what, std::string_view raw) -> error;

	// conversion_failed "not valid UTF-8 (ill-formed sequence at offset N)".
	auto utf8_conversion_error(std::size_t offset) -> error;

	// The same text as encode_error.
	auto utf8_encode_error(std::size_t offset) -> error;

	// encode_error "value N is not in ldap::enum_names".
	auto enum_encode_error(std::intmax_t value) -> error;

	// `text`, or utf8_encode_error when it is not well-formed UTF-8.
	inline auto checked_utf8(std::string_view text) -> result<std::string>
	{
		if (const std::size_t bad = invalid_utf8_offset(text); bad != std::string_view::npos) {
			return std::unexpected(utf8_encode_error(bad));
		}
		return std::string(text);
	}
}// namespace detail

// Well-formed UTF-8 only, both ways; binary attributes map to ldap::binary.
template<> struct value_traits<std::string>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<std::string>
	{
		if (const std::size_t bad = detail::invalid_utf8_offset(raw); bad != std::string_view::npos) {
			return std::unexpected(detail::utf8_conversion_error(bad));
		}
		return std::string(raw);
	}
	[[nodiscard]] static auto encode(const std::string &v) -> result<std::string> { return detail::checked_utf8(v); }
};

template<> struct value_traits<std::pmr::string>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<std::pmr::string>
	{
		if (const std::size_t bad = detail::invalid_utf8_offset(raw); bad != std::string_view::npos) {
			return std::unexpected(detail::utf8_conversion_error(bad));
		}
		return std::pmr::string(raw);
	}
	[[nodiscard]] static auto encode(const std::pmr::string &v) -> result<std::string>
	{
		return detail::checked_utf8(v);
	}
};

namespace detail {
	template<class T>
	concept char_like = std::same_as<T, char> || std::same_as<T, wchar_t> || std::same_as<T, char8_t>
						|| std::same_as<T, char16_t> || std::same_as<T, char32_t>;
}// namespace detail

// INTEGER syntax (RFC 4517 section 3.3.16).
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

// Boolean syntax (RFC 4517 section 3.3.3): "TRUE" or "FALSE".
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
	// NOLINTNEXTLINE(modernize-use-string-view): mapped_value wants std::string or result<std::string>, not a view
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

// GeneralizedTime (RFC 4517 section 3.3.13): decodes every form, encodes
// "YYYYMMDDHHMMSSZ". Years 0000-9999.
[[nodiscard]] auto parse_generalized_time(std::string_view text) -> result<std::chrono::sys_seconds>;
[[nodiscard]] auto format_generalized_time(std::chrono::sys_seconds t) -> result<std::string>;

template<> struct value_traits<std::chrono::sys_seconds>
{
	[[nodiscard]] static auto decode(std::string_view raw) -> result<std::chrono::sys_seconds>
	{
		return parse_generalized_time(raw);
	}
	[[nodiscard]] static auto encode(std::chrono::sys_seconds v) -> result<std::string>
	{
		return format_generalized_time(v);
	}
};

// Enums map to names through an ldap::enum_names<E> table, matched exactly.
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
	[[nodiscard]] static auto encode(E v) -> result<std::string>
	{
		for (const auto &[value, name] : enum_names<E>) {
			if (value == v) {
				return std::string(name);
			}
		}
		return std::unexpected(detail::enum_encode_error(static_cast<std::intmax_t>(std::to_underlying(v))));
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
// Read but never written (operational attributes such as createTimestamp).
inline constexpr read_only_t read_only{};

template<auto Ptr> struct field
{
	using owner = detail::member_pointer<decltype(Ptr)>::owner;
	using member = detail::member_pointer<decltype(Ptr)>::type;
	using element = detail::shape<member>::element;
	static constexpr auto ptr = Ptr;
	static constexpr cardinality kind = detail::shape<member>::kind;
	static_assert(mapped_value<element>,
	  "ldap::field: this member's value type needs an ldap::value_traits<T> whose decode(std::string_view) "
	  "returns result<T> and whose encode(const T&) returns std::string or result<std::string>");

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

// Auxiliary object classes (RFC 4512 section 2.4.3): written and validated,
// not ANDed into a repository's search filter.
template<std::size_t N> struct auxiliary_classes
{
	std::array<const char *, N> names{};
};

template<class... S> consteval auto auxiliary_class(S... names)
{
	static_assert(sizeof...(S) > 0, "ldap::auxiliary_class: name at least one object class");
	auxiliary_classes<sizeof...(S)> out{ { names... } };
	for (const char *n : out.names) {
		if (!detail::is_oid(n)) {
			// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
			throw "ldap::auxiliary_class: invalid object class name";
		}
	}
	return out;
}

namespace detail {
	template<class> inline constexpr bool is_auxiliary_classes = false;
	template<std::size_t M> inline constexpr bool is_auxiliary_classes<auxiliary_classes<M>> = true;
}// namespace detail

template<std::size_t N, std::size_t M, class... F> struct descriptor
{
	using owner = std::tuple_element_t<0, std::tuple<F...>>::owner;
	object_classes<N> classes;
	auxiliary_classes<M> auxiliary;
	std::tuple<F...> fields;
};

template<std::size_t N, std::size_t M, class F0, class... F>
consteval auto describe(object_classes<N> classes, auxiliary_classes<M> auxiliary, F0 f0, F... f)
{
	static_assert(N > 0 || M == 0, "ldap::describe: auxiliary_class(...) needs object_class(...) right before it");
	static_assert(!detail::is_auxiliary_classes<F0> && (!detail::is_auxiliary_classes<F> && ...),
	  "ldap::describe: auxiliary_class(...) needs object_class(...) right before it");
	static_assert((std::same_as<typename F0::owner, typename F::owner> && ...),
	  "ldap::describe: every field must be a member of the same struct");
	return descriptor<N, M, F0, F...>{ classes, auxiliary, { f0, f... } };
}
template<std::size_t N, class F0, class... F> consteval auto describe(object_classes<N> classes, F0 f0, F... f)
{
	return describe(classes, auxiliary_classes<0>{}, f0, f...);
}
template<class F0, class... F> consteval auto describe(F0 f0, F... f)
{
	return describe(object_classes<0>{}, auxiliary_classes<0>{}, f0, f...);
}

// Specialize for each mapped struct.
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
}// namespace detail

// The attribute names of T's descriptor, in order.
template<described T>
[[nodiscard]] auto attribute_names(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> string_list
{
	string_list out(mr);
	std::apply([&](const auto &...f) { (out.emplace_back(f.name), ...); }, schema<T>.fields);
	return out;
}

namespace detail {
	template<described T> constexpr auto attribute_name_array()
	{
		return std::apply(
		  [](const auto &...f) { return std::array<std::string_view, sizeof...(f)>{ std::string_view(f.name)... }; },
		  schema<T>.fields);
	}
}// namespace detail

// Without the auxiliary ones.
template<described T> [[nodiscard]] constexpr auto object_classes_of() -> std::span<const char *const>
{
	return schema<T>.classes.names;
}

template<described T> [[nodiscard]] constexpr auto auxiliary_classes_of() -> std::span<const char *const>
{
	return schema<T>.auxiliary.names;
}

namespace detail {
	// The object classes, then the auxiliary ones: what add writes.
	template<described T>
	inline constexpr auto all_object_classes = [] {
		constexpr auto &d = schema<T>;
		std::array<const char *, d.classes.names.size() + d.auxiliary.names.size()> out{};
		std::size_t i = 0;
		for (const char *n : d.classes.names) {
			out[i++] = n;
		}
		for (const char *n : d.auxiliary.names) {
			out[i++] = n;
		}
		return out;
	}();
}// namespace detail

// ---------------------------------------------------------------- decode / encode

namespace detail {
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

	auto entry_context(std::string_view dn) -> std::string;
	auto entry_context(std::string_view dn, std::string_view attribute) -> std::string;

	// The error for an attribute of `e` that is `name` with a range option, if
	// any.
	auto ranged_values_error(const entry &e, std::string_view name) -> std::optional<error>;

	// client_errc::schema_mismatch for the first attribute of `e` that decode
	// would not read as one of `names`, if any.
	auto unrequested_attribute_error(const entry &e, std::span<const std::string_view> names) -> std::optional<error>;
}// namespace detail

// Converts an entry to T; incomplete_values for a mapped attribute with a
// range option (read it with ldap::ad::read_all_values).
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
				if (auto ranged = detail::ranged_values_error(e, f.name)) {
					failed = detail::with_context(std::move(*ranged), detail::entry_context(e.dn, f.name));
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
	// Appends the encoded `v` to `values`; false, with `failed` set, if it does
	// not encode.
	template<class E>
	auto append_encoded(const E &v,
	  std::string_view name,
	  std::pmr::vector<std::pmr::string> &values,
	  std::optional<error> &failed) -> bool
	{
		auto s = encode_value(v);
		if (!s) {
			failed = with_context(std::move(s.error()), std::string("attribute ").append(name));
			return false;
		}
		values.emplace_back(*s);
		return true;
	}

	template<class F>
	void encode_field(const F &f,
	  const typename F::member &m,
	  std::pmr::vector<partial_attribute> &out,
	  std::optional<error> &failed)
	{
		if (failed || f.read_only) {
			return;
		}
		partial_attribute a(f.name, {}, out.get_allocator());
		if constexpr (F::kind == cardinality::multiple) {
			for (const auto &v : m) {
				if (!append_encoded(v, f.name, a.values, failed)) {
					return;
				}
			}
		} else if constexpr (F::kind == cardinality::optional) {
			if (m && !append_encoded(*m, f.name, a.values, failed)) {
				return;
			}
		} else if (!append_encoded(m, f.name, a.values, failed)) {
			return;
		}
		if (!a.values.empty()) {
			out.push_back(std::move(a));
		}
	}
}// namespace detail

// The attributes to add for `value`: every described member but read_only
// ones and empty ones, plus objectClass when the descriptor declares classes.
template<described T>
[[nodiscard]] auto to_attributes(const T &value, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<std::pmr::vector<partial_attribute>>
{
	constexpr auto &d = schema<T>;
	constexpr bool has_object_class_field =
	  std::apply([](const auto &...f) { return (detail::iequals(f.name, "objectClass") || ...); }, d.fields);
	static_assert(d.classes.names.size() > 0 || has_object_class_field,
	  "ldap::to_attributes / add: declare ldap::object_class(...) in the descriptor or map an objectClass member");
	std::pmr::vector<partial_attribute> out(mr);
	if constexpr (d.classes.names.size() > 0) {
		partial_attribute oc("objectClass", {}, out.get_allocator());
		for (const char *n : detail::all_object_classes<T>) {
			oc.values.emplace_back(n);
		}
		out.push_back(std::move(oc));
	}
	std::optional<error> failed;
	std::apply(
	  [&](const auto &...f) {
		  (detail::encode_field(f, value.*std::remove_cvref_t<decltype(f)>::ptr, out, failed), ...);
	  },
	  d.fields);
	if (failed) {
		return std::unexpected(std::move(*failed));
	}
	return out;
}

// ---------------------------------------------------------------- typed changes

// A ModifyRequest change for a member of T; an encode error stays in `wire`.
template<class T> struct change
{
	result<modify_change> wire;
};

namespace detail {
	// For static_assert in a discarded if-constexpr branch.
	template<class> inline constexpr bool dependent_false = false;

	template<class E, class V>
	concept range_of =
	  std::ranges::input_range<V> && std::same_as<std::remove_cvref_t<std::ranges::range_value_t<V>>, E>;

	template<class E> auto append_value(const E &v, string_list &out) -> std::optional<error>
	{
		auto s = encode_value(v);
		if (!s) {
			return std::move(s.error());
		}
		out.emplace_back(*s);
		return std::nullopt;
	}

	// The values `v` stands for, for member `Ptr`.
	template<auto Ptr, class V> auto encode_values(const V &v) -> result<string_list>
	{
		using F = std::remove_cvref_t<decltype(field_of<Ptr>())>;
		using E = F::element;
		string_list out;
		std::optional<error> failed;
		if constexpr (std::convertible_to<const V &, E>) {
			// A string literal converts to E through its pointer.
			// NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
			failed = append_value(static_cast<E>(v), out);
		} else if constexpr (std::same_as<std::remove_cvref_t<V>, std::optional<E>>) {
			if (v) {
				failed = append_value(*v, out);
			}
		} else if constexpr (range_of<E, V>) {
			static_assert(F::kind == cardinality::multiple, "ldap: several values for a single-valued member");
			for (const auto &x : v) {
				failed = append_value(x, out);
				if (failed) {
					break;
				}
			}
		} else {
			static_assert(dependent_false<V>, "ldap: the value's type does not match the member's type");
		}
		if (failed) {
			return std::unexpected(std::move(*failed));
		}
		return out;
	}

	template<auto Ptr> consteval void check_writable()
	{
		static_assert(!field_of<Ptr>().read_only, "ldap: this member is read_only in ldap::schema<T>");
	}

	template<auto Ptr> using owner_of = member_pointer<decltype(Ptr)>::owner;

	// "replace mail": the context of a change's encode error.
	auto change_context(modify_operation op, std::string_view attribute) -> std::string;

	template<auto Ptr> auto make_change(modify_operation op, result<string_list> values) -> change<owner_of<Ptr>>
	{
		check_writable<Ptr>();
		if (!values) {
			return { std::unexpected(
			  with_context(std::move(values.error()), change_context(op, field_of<Ptr>().name))) };
		}
		partial_attribute a(field_of<Ptr>().name);
		a.values = std::move(*values);
		return { modify_change(op, a) };
	}
}// namespace detail

// Replaces all values (nullopt removes the attribute).
template<auto Ptr, class V> [[nodiscard]] auto replace(const V &v) -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::replace, detail::encode_values<Ptr>(v));
}

template<auto Ptr, class V> [[nodiscard]] auto add(const V &v) -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::add, detail::encode_values<Ptr>(v));
}

// Removes the whole attribute, or only the given values.
template<auto Ptr> [[nodiscard]] auto remove() -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::delete_, string_list{});
}
template<auto Ptr, class V> [[nodiscard]] auto remove(const V &v) -> change<detail::owner_of<Ptr>>
{
	return detail::make_change<Ptr>(modify_operation::delete_, detail::encode_values<Ptr>(v));
}

namespace detail {
	// The values of `values` not in `other`, each once, in order.
	auto values_not_in(const string_list &values, const string_list &other) -> string_list;

	// Appends the changes turning member `Ptr` of `before` into that of `after`
	// to `out`; false, with `failed` set, if a value does not encode.
	template<auto Ptr>
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters): before, then after, as diff
	auto append_diff(const owner_of<Ptr> &before,
	  const owner_of<Ptr> &after,
	  std::vector<change<owner_of<Ptr>>> &out,
	  std::optional<error> &failed) -> bool
	{
		using F = std::remove_cvref_t<decltype(field_of<Ptr>())>;
		auto from = encode_values<Ptr>(before.*Ptr);
		auto to = encode_values<Ptr>(after.*Ptr);
		if (!from || !to) {
			failed = with_context(
			  std::move(!from ? from.error() : to.error()), std::string("attribute ").append(field_of<Ptr>().name));
			return false;
		}
		if (*from == *to) {
			return true;
		}
		if constexpr (F::kind == cardinality::multiple) {
			auto removed = values_not_in(*from, *to);
			auto added = values_not_in(*to, *from);
			if constexpr (std::same_as<typename F::element, binary>) {
				if (!removed.empty() || !added.empty()) {
					out.push_back(make_change<Ptr>(modify_operation::replace, values_not_in(*to, string_list{})));
				}
			} else {
				if (!removed.empty()) {
					out.push_back(make_change<Ptr>(modify_operation::delete_, std::move(removed)));
				}
				if (!added.empty()) {
					out.push_back(make_change<Ptr>(modify_operation::add, std::move(added)));
				}
			}
		} else if (to->empty()) {
			out.push_back(make_change<Ptr>(modify_operation::delete_, string_list{}));
		} else {
			out.push_back(make_change<Ptr>(modify_operation::replace, std::move(*to)));
		}
		return true;
	}
}// namespace detail

// The changes turning `original` into `changed`, member by member; empty
// when nothing differs (rules: docs/API.md, repository update).
template<described T> [[nodiscard]] auto diff(const T &original, const T &changed) -> result<std::vector<change<T>>>
{
	std::vector<change<T>> out;
	std::optional<error> failed;
	std::apply(
	  [&](const auto &...f) {
		  (
			[&] {
				[[maybe_unused]] constexpr auto ptr = std::remove_cvref_t<decltype(f)>::ptr;
				if constexpr (!detail::field_of<ptr>().read_only) {
					return failed.has_value() || detail::append_diff<ptr>(original, changed, out, failed);
				} else {
					return true;
				}
			}(),
			...);
	  },
	  schema<T>.fields);
	if (failed) {
		return std::unexpected(std::move(*failed));
	}
	return out;
}

// ---------------------------------------------------------------- typed filters

namespace filters {

	// Filters on a described member, with values of its type; a value that does
	// not encode gives filter::failed() with the encode error.
	template<auto Ptr> class typed_attr
	{
		using E = std::remove_cvref_t<decltype(detail::field_of<Ptr>())>::element;

	  public:
		[[nodiscard]] auto operator==(const E &v) const -> filter
		{
			return make(v, [](std::string_view s) { return a() == s; });
		}
		[[nodiscard]] auto operator>=(const E &v) const -> filter
		{
			return make(v, [](std::string_view s) { return a() >= s; });
		}
		[[nodiscard]] auto operator<=(const E &v) const -> filter
		{
			return make(v, [](std::string_view s) { return a() <= s; });
		}
		[[nodiscard]] auto approx(const E &v) const -> filter
		{
			return make(v, [](std::string_view s) { return a().approx(s); });
		}
		[[nodiscard]] auto present() const -> filter { return a().present(); }

	  private:
		static auto a() -> attr { return attr(detail::field_of<Ptr>().name); }

		// build(encoded v), or filter::failed() when v does not encode.
		template<class Build> static auto make(const E &v, Build build) -> filter
		{
			auto s = detail::encode_value(v);
			if (!s) {
				return filter::failed(detail::with_context(
				  std::move(s.error()), std::string("filter ").append(detail::field_of<Ptr>().name)));
			}
			return build(*s);
		}
	};

	template<auto Ptr> [[nodiscard]] auto field() -> typed_attr<Ptr> { return {}; }

}// namespace filters

// `(&(objectClass=c1)...(objectClass=cN) f)`, or `f` when T declares no
// object class.
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

namespace detail {
	inline void and_into(filter &out, filter f) { out = out.empty() ? std::move(f) : std::move(out) && std::move(f); }

	// ANDs (a=v) for each value of member `Ptr` of `original` into `out`; false,
	// with `failed` set, if a value does not encode.
	template<auto Ptr>
	auto append_unchanged(const owner_of<Ptr> &original, filter &out, std::optional<error> &failed) -> bool
	{
		const filters::attr a(field_of<Ptr>().name);
		auto values = encode_values<Ptr>(original.*Ptr);
		if (!values) {
			failed = with_context(std::move(values.error()), std::string("attribute ").append(field_of<Ptr>().name));
			return false;
		}
		for (const auto &v : *values) {
			and_into(out, a == v);
		}
		return true;
	}
}// namespace detail

// A filter true of an entry that still has `original`'s values, for an
// Assertion control (RFC 4528); empty when `original` has no value.
template<described T> [[nodiscard]] auto unchanged_filter(const T &original) -> result<filter>
{
	static_assert(std::apply([](const auto &...f) { return (!f.read_only || ...); }, schema<T>.fields),
	  "ldap::unchanged_filter: every member is read_only");
	filter out;
	std::optional<error> failed;
	std::apply(
	  [&](const auto &...f) {
		  (
			[&] {
				[[maybe_unused]] constexpr auto ptr = std::remove_cvref_t<decltype(f)>::ptr;
				if constexpr (!detail::field_of<ptr>().read_only) {
					return failed.has_value() || detail::append_unchanged<ptr>(original, out, failed);
				} else {
					return true;
				}
			}(),
			...);
	  },
	  schema<T>.fields);
	if (failed) {
		return std::unexpected(std::move(*failed));
	}
	return out;
}

// (a=v) on one single-valued member of `original`, e.g. entryCSN; an empty
// optional fails with missing_attribute.
template<auto Ptr> [[nodiscard]] auto unchanged_filter(const detail::owner_of<Ptr> &original) -> result<filter>
{
	static_assert(std::remove_cvref_t<decltype(detail::field_of<Ptr>())>::kind != cardinality::multiple,
	  "ldap::unchanged_filter: a version member must be single-valued");
	const auto *name = detail::field_of<Ptr>().name;
	auto values = detail::encode_values<Ptr>(original.*Ptr);
	if (!values) {
		return std::unexpected(detail::with_context(std::move(values.error()), std::string("attribute ").append(name)));
	}
	if (values->empty()) {
		return std::unexpected(
		  detail::with_context(make_error(client_errc::missing_attribute), std::string("attribute ").append(name)));
	}
	return filters::attr(detail::field_of<Ptr>().name) == values->front();
}

}// namespace jhetz::ldap
