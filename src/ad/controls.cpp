#include "jhetz/ldap/ad/controls.hpp"

#include "../control_util.hpp"
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

using detail::control_value;
using detail::enter_value;
using detail::in_control;
using detail::read_bounded;
using detail::skip_rest;
using detail::value_control;

namespace {

	constexpr auto int32_min = std::int64_t{ std::numeric_limits<std::int32_t>::min() };
	constexpr auto int32_max = std::int64_t{ std::numeric_limits<std::int32_t>::max() };
	constexpr auto uint32_max = std::int64_t{ std::numeric_limits<std::uint32_t>::max() };

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

// ---------------------------------------------------------------- DirSync response

auto decode_dirsync_response(const control &c) -> result<dirsync_response>
{
	static constexpr const char *what = "DirSync response";
	auto value = control_value(c, dirsync_oid, what);
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
	return in_control(read(), what);
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
