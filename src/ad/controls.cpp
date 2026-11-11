#include "jhetz/ldap/ad/controls.hpp"

#include "../format_util.hpp"

#include "jhetz/ldap/ber.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::ad {

namespace {

	constexpr std::size_t max_quoted_type = 64;

	auto bad(const char *what, std::string_view why) -> std::unexpected<error>
	{
		return fail(client_errc::decode_error, detail::format("{}: {}", what, why));
	}

	// The DirSync control's value bytes.
	auto expect_dirsync(const control &c, const char *what) -> result<std::span<const std::byte>>
	{
		if (c.type != dirsync_oid) {
			std::string context = detail::format("{}: control type is ", what);
			detail::append_sanitized(context, c.type, max_quoted_type);
			context += detail::format(", not {}", dirsync_oid);
			return fail(client_errc::decode_error, context);
		}
		if (!c.value) {
			return bad(what, "control has no value");
		}
		return std::as_bytes(std::span(*c.value));
	}

	template<class T> auto named(result<T> r, const char *what) -> result<T>
	{
		return std::move(r).transform_error([what](error e) {
			e.context.insert(0, e.context.empty() ? std::string(what) : std::string(what) + ": ");
			return e;
		});
	}

	// Enters the value's SEQUENCE; nothing may follow it.
	auto enter_value(ber::reader &outer) -> result<ber::reader>
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

	// RFC 4511 section 4: unrecognized trailing elements are ignored, if
	// well-formed.
	auto skip_rest(ber::reader &r) -> result<void>
	{
		while (!r.empty()) {
			if (auto e = r.read(); !e) {
				return std::unexpected(std::move(e.error()));
			}
		}
		return {};
	}

	// An INTEGER in [low, high].
	auto read_bounded(ber::reader &r, std::int64_t low, std::int64_t high, const char *field) -> result<std::int64_t>
	{
		const std::size_t offset = r.offset();
		auto v = r.read_integer();
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		if (*v < low || *v > high) {
			return fail(
			  client_errc::decode_error, detail::format("{} {} out of range at offset {}", field, *v, offset));
		}
		return *v;
	}

	constexpr auto int32_min = std::int64_t{ std::numeric_limits<std::int32_t>::min() };
	constexpr auto int32_max = std::int64_t{ std::numeric_limits<std::int32_t>::max() };
	constexpr auto uint32_max = std::int64_t{ std::numeric_limits<std::uint32_t>::max() };

	auto value_control(std::string_view oid, bool criticality, const ber::writer &w, std::pmr::memory_resource *mr)
	  -> control
	{
		return { oid, criticality, detail::as_text(w.bytes()), control::allocator_type(mr) };
	}

}// namespace

// ---------------------------------------------------------------- DirSync request

dirsync_request::operator control() const { return encode_dirsync_request(*this); }

auto encode_dirsync_request(const dirsync_request &value, std::pmr::memory_resource *mr) -> control
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(static_cast<std::int32_t>(std::to_underlying(value.flags)));
		s.integer(value.max_bytes);
		s.octet_string(value.cookie);
	});
	return value_control(dirsync_oid, value.critical, w, mr);
}

auto decode_dirsync_request(const control &c) -> result<dirsync_request>
{
	static constexpr const char *what = "DirSync request";
	auto value = expect_dirsync(c, what);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	const auto read = [&] -> result<dirsync_request> {
		ber::reader r(*value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto flags = read_bounded(*s, int32_min, uint32_max, "Flags");
		if (!flags) {
			return std::unexpected(std::move(flags.error()));
		}
		auto max_bytes = read_bounded(*s, int32_min, int32_max, "MaxBytes");
		if (!max_bytes) {
			return std::unexpected(std::move(max_bytes.error()));
		}
		auto cookie = s->read_octet_string();
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return dirsync_request{ .flags = static_cast<dirsync_flags>(static_cast<std::uint32_t>(*flags)),
			.max_bytes = static_cast<std::int32_t>(*max_bytes),
			.cookie = std::string(detail::as_text(*cookie)),
			.critical = c.criticality };
	};
	return named(read(), what);
}

// ---------------------------------------------------------------- DirSync response

auto encode_dirsync_response(const dirsync_response &value, bool criticality, std::pmr::memory_resource *mr) -> control
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(value.more_results ? 1 : 0);
		s.integer(value.unused);
		s.octet_string(value.cookie_server);
	});
	return value_control(dirsync_oid, criticality, w, mr);
}

auto decode_dirsync_response(const control &c) -> result<dirsync_response>
{
	static constexpr const char *what = "DirSync response";
	auto value = expect_dirsync(c, what);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	const auto read = [&] -> result<dirsync_response> {
		ber::reader r(*value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto more = read_bounded(*s, int32_min, uint32_max, "MoreResults");
		if (!more) {
			return std::unexpected(std::move(more.error()));
		}
		auto unused = read_bounded(*s, int32_min, int32_max, "unused");
		if (!unused) {
			return std::unexpected(std::move(unused.error()));
		}
		auto cookie = s->read_octet_string();
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return dirsync_response{ .more_results = *more != 0,
			.unused = static_cast<std::int32_t>(*unused),
			.cookie_server = std::string(detail::as_text(*cookie)) };
	};
	return named(read(), what);
}

auto find_dirsync_response(const std::pmr::vector<control> &controls) -> result<std::optional<dirsync_response>>
{
	const auto it = std::ranges::find(controls, dirsync_oid, &control::type);
	if (it == controls.end()) {
		return std::optional<dirsync_response>{};
	}
	return decode_dirsync_response(*it).transform(
	  [](dirsync_response &&v) { return std::optional<dirsync_response>(std::move(v)); });
}

}// namespace jhetz::ldap::ad
