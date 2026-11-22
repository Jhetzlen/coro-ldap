// BER and control value helpers shared by the codecs.
#pragma once

#include "format_util.hpp"

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::detail {

// Control types a peer sent are shown in errors cut to this many bytes.
inline constexpr std::size_t max_shown_control_type = 64;

// Reads every remaining element: RFC 4511 section 4 has unrecognized
// trailing elements ignored, if well-formed.
inline auto skip_rest(ber::reader &r) -> result<void>
{
	while (!r.empty()) {
		if (auto e = r.read(); !e) {
			return std::unexpected(std::move(e.error()));
		}
	}
	return {};
}

// The next element has the class and number of `t`, in either form.
inline auto next_is(const ber::reader &r, ber::tag t) -> bool
{
	if (r.empty()) {
		return false;
	}
	auto p = r.peek_tag();
	return p && p->cls == t.cls && p->number == t.number;
}

// Enters the value's outer SEQUENCE; nothing may follow it.
inline auto enter_value(ber::reader &outer) -> result<ber::reader>
{
	auto s = outer.enter();
	if (!s) {
		return std::unexpected(std::move(s.error()));
	}
	if (auto done = outer.expect_end(); !done) {
		return std::unexpected(std::move(done.error()));
	}
	return s;
}

// The control's value bytes, once its type is `oid` and it has a value.
inline auto control_value(const control &c, std::string_view oid, std::string_view what)
  -> result<std::span<const std::byte>>
{
	if (c.type != oid) {
		std::string text = detail::format("{}: control type is ", what);
		detail::append_sanitized(text, c.type, max_shown_control_type);
		detail::format_to(text, ", not {}", oid);
		return fail(client_errc::decode_error, text);
	}
	if (!c.value) {
		return fail(client_errc::decode_error, detail::format("{}: control has no value", what));
	}
	return std::as_bytes(std::span(*c.value));
}

// A control whose value is the writer's bytes.
inline auto
  value_control(std::string_view oid, bool criticality, const ber::writer &w, const control::allocator_type &alloc)
	-> control
{
	return { oid, criticality, detail::as_text(w.bytes()), alloc };
}

// Prefixes an error from inside a control value with the control's name.
template<class T> auto in_control(result<T> r, std::string_view what) -> result<T>
{
	return std::move(r).transform_error([what](error e) {
		e.context.insert(0, e.context.empty() ? std::string(what) : detail::format("{}: ", what));
		return e;
	});
}

// The first control of type `oid`, decoded by `decode` (which returns a
// result<T>); nullopt if there is none.
template<class T, class Decode>
auto find_decoded(const std::pmr::vector<control> &controls, std::string_view oid, Decode decode)
  -> result<std::optional<T>>
{
	const auto it = std::ranges::find(controls, oid, &control::type);
	if (it == controls.end()) {
		return std::optional<T>{};
	}
	return decode(*it).transform([](T &&v) { return std::optional<T>(std::move(v)); });
}

// A BOOLEAN with a DEFAULT: `fallback` when absent.
inline auto read_flag(ber::reader &r, bool fallback) -> result<bool>
{
	if (!next_is(r, ber::tags::boolean)) {
		return fallback;
	}
	return r.read_boolean();
}

// An ENUMERATED among `allowed`, else decode_error naming `what`.
inline auto read_enum(ber::reader &r, std::span<const std::int64_t> allowed, std::string_view what)
  -> result<std::int64_t>
{
	const std::size_t offset = r.offset();
	auto copy = r;
	auto v = copy.read_enumerated();
	if (!v) {
		return std::unexpected(std::move(v.error()));
	}
	if (std::ranges::find(allowed, *v) == allowed.end()) {
		return fail(client_errc::decode_error, detail::format("unknown {} {} at offset {}", what, *v, offset));
	}
	r = copy;
	return *v;
}

// An INTEGER in [low, high].
inline auto read_bounded(ber::reader &r, std::int64_t low, std::int64_t high, const char *field) -> result<std::int64_t>
{
	const std::size_t offset = r.offset();
	auto v = r.read_integer();
	if (!v) {
		return std::unexpected(std::move(v.error()));
	}
	if (*v < low || *v > high) {
		return fail(client_errc::decode_error, detail::format("{} {} out of range at offset {}", field, *v, offset));
	}
	return *v;
}

inline constexpr std::string_view matched_values_name = "matched values";

// Whether `f` is a SimpleFilterItem (RFC 3876 section 2), else `code`;
// `index` is 0-based.
auto check_simple_item(const filter &f, std::size_t index, client_errc code) -> result<void>;

}// namespace jhetz::ldap::detail
