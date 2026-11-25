// The request controls a server reads and the response controls it writes.
#include "jhetz/ldap/testing/server_codec.hpp"

#include "control_util.hpp"
#include "format_util.hpp"

#include "jhetz/ldap/ber.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>

namespace jhetz::ldap::testing {

using detail::check_simple_item;
using detail::control_value;
using detail::enter_value;
using detail::in_control;
using detail::matched_values_name;
using detail::next_is;
using detail::read_bounded;
using detail::read_enum;
using detail::read_flag;
using detail::skip_rest;
using detail::value_control;

namespace {

	// Filter CHOICE tag of extensibleMatch, and MatchingRuleAssertion's
	// dnAttributes tag (RFC 4511 section 4.5.1).
	constexpr std::uint8_t extensible_match_tag = 9;
	constexpr std::uint8_t dn_attributes_tag = 4;

	constexpr std::string_view vlv_name = "virtual list view";

	// The next element is an extensibleMatch with a dnAttributes field.
	auto has_dn_attributes_field(ber::reader r) -> bool
	{
		constexpr ber::tag extensible = ber::context(extensible_match_tag, true);
		const auto t = r.peek_tag();
		if (!t || t->cls != extensible.cls || t->number != extensible.number || !t->constructed) {
			return false;
		}
		auto inner = r.enter(extensible);
		if (!inner) {
			return false;// decode_filter reports it
		}
		while (!inner->empty()) {
			auto e = inner->read();
			if (!e) {
				return false;
			}
			if (e->t.cls == ber::tag_class::context && e->t.number == dn_attributes_tag) {
				return true;
			}
		}
		return false;
	}

	auto read_matched_values(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<matched_values>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		matched_values out;
		std::size_t elements = 0;
		while (!s->empty()) {
			// The items share one element budget, as one filter would.
			const filter_limits limits{ .max_depth = max_filter_depth, .max_elements = max_filter_elements - elements };
			const std::size_t at = s->offset();
			if (has_dn_attributes_field(*s)) {
				return fail(client_errc::decode_error,
				  detail::format("item {} is an extensible match with dnAttributes, not a simple filter item (RFC "
								 "3876 section 2) at offset {}",
					out.values_return_filter.size() + 1,
					at));
			}
			auto f = decode_filter(*s, limits, mr);
			if (!f) {
				return std::unexpected(std::move(f.error()));
			}
			if (auto ok = check_simple_item(*f, out.values_return_filter.size(), client_errc::decode_error); !ok) {
				ok.error().context += detail::format(" at offset {}", at);
				return std::unexpected(std::move(ok.error()));
			}
			elements += f->elements();
			out.values_return_filter.push_back(std::move(*f));
			if (elements >= max_filter_elements && !s->empty()) {
				return fail(client_errc::decode_error,
				  detail::format("more than {} filter elements at offset {}", max_filter_elements, s->offset()));
			}
		}
		if (out.values_return_filter.empty()) {
			return fail(client_errc::decode_error, "no filter items");
		}
		return out;
	}

	// An INTEGER in lo..maxInt.
	auto read_count(ber::reader &r, std::int64_t lo, std::string_view what) -> result<std::int32_t>
	{
		const std::size_t at = r.offset();
		auto v = r.read_integer();
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		if (*v < lo || *v > max_int) {
			return fail(client_errc::decode_error,
			  detail::format("{} {} outside {}..{} at offset {}", what, *v, lo, max_int, at));
		}
		return static_cast<std::int32_t>(*v);
	}

	auto read_vlv(std::span<const std::byte> value) -> result<virtual_list_view>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		virtual_list_view out;
		auto before = read_count(*s, 0, "beforeCount");
		if (!before) {
			return std::unexpected(std::move(before.error()));
		}
		auto after = read_count(*s, 0, "afterCount");
		if (!after) {
			return std::unexpected(std::move(after.error()));
		}
		out.before_count = *before;
		out.after_count = *after;
		if (next_is(*s, ber::context(0, true))) {
			auto by = s->enter(ber::context(0, true));
			if (!by) {
				return std::unexpected(std::move(by.error()));
			}
			auto offset = read_count(*by, 1, "offset");
			if (!offset) {
				return std::unexpected(std::move(offset.error()));
			}
			auto count = read_count(*by, 0, "contentCount");
			if (!count) {
				return std::unexpected(std::move(count.error()));
			}
			if (auto done = skip_rest(*by); !done) {
				return std::unexpected(std::move(done.error()));
			}
			out.target = vlv_by_offset{ .offset = *offset, .content_count = *count };
		} else if (next_is(*s, ber::context(1))) {
			auto v = s->read_octet_string(ber::context(1));
			if (!v) {
				return std::unexpected(std::move(v.error()));
			}
			out.target = vlv_greater_than_or_equal{ .value = std::string(detail::as_text(*v)) };
		} else {
			return fail(client_errc::decode_error,
			  detail::format("target: expected [CONTEXT 0] or [CONTEXT 1] at offset {}", s->offset()));
		}
		if (next_is(*s, ber::tags::octet_string)) {
			auto id = s->read_octet_string();
			if (!id) {
				return std::unexpected(std::move(id.error()));
			}
			out.context_id = std::string(detail::as_text(*id));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

	constexpr std::array<std::int64_t, 2> mode_values = { std::to_underlying(sync_mode::refresh_only),
		std::to_underlying(sync_mode::refresh_and_persist) };

}// namespace

auto decode_matched_values(const control &c, std::pmr::memory_resource *mr) -> result<matched_values>
{
	auto value = control_value(c, matched_values_oid, matched_values_name);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	auto out = in_control(read_matched_values(*value, mr), matched_values_name);
	if (out) {
		out->critical = c.criticality;
	}
	return out;
}

auto decode_virtual_list_view(const control &c) -> result<virtual_list_view>
{
	auto value = control_value(c, vlv_request_oid, vlv_name);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	auto out = in_control(read_vlv(*value), vlv_name);
	if (out) {
		out->critical = c.criticality;
	}
	return out;
}

auto decode_transaction_specification(const control &c) -> result<transaction_specification>
{
	constexpr std::string_view name = "transaction specification";
	auto value = control_value(c, transaction_specification_oid, name);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	if (!c.criticality) {
		return fail(
		  client_errc::decode_error, detail::format("{}: control is not critical (RFC 5805 section 2.2)", name));
	}
	return transaction_specification{ .identifier = std::string(detail::as_text(*value)) };
}

// ---------------------------------------------------------------- content synchronization (RFC 4533)

auto decode_sync_request(const control &c) -> result<sync_request>
{
	static constexpr std::string_view what = "sync request";
	auto value = control_value(c, sync_request_oid, what);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	const auto read = [&] -> result<sync_request> {
		ber::reader r(*value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto mode = read_enum(*s, mode_values, "mode");
		if (!mode) {
			return std::unexpected(std::move(mode.error()));
		}
		std::optional<std::string> cookie;
		if (next_is(*s, ber::tags::octet_string)) {
			auto bytes = s->read_octet_string();
			if (!bytes) {
				return std::unexpected(std::move(bytes.error()));
			}
			cookie.emplace(detail::as_text(*bytes));
		}
		auto reload = read_flag(*s, false);
		if (!reload) {
			return std::unexpected(std::move(reload.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return sync_request{ .mode = static_cast<sync_mode>(*mode),
			.cookie = std::move(cookie),
			.reload_hint = *reload,
			.critical = c.criticality };
	};
	return in_control(read(), what);
}

auto encode_sync_state(const sync_state &value, bool criticality, std::pmr::memory_resource *mr) -> result<control>
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.enumerated(std::to_underlying(value.state));
		s.octet_string(std::span<const std::byte>(value.entry_uuid.bytes));
		if (value.cookie) {
			s.octet_string(*value.cookie);
		}
	});
	return value_control(sync_state_oid, criticality, w, mr);
}

auto encode_sync_done(const sync_done &value, bool criticality, std::pmr::memory_resource *mr) -> result<control>
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		if (value.cookie) {
			s.octet_string(*value.cookie);
		}
		if (value.refresh_deletes) {
			s.boolean(true);
		}
	});
	return value_control(sync_done_oid, criticality, w, mr);
}

auto encode_sync_info(const sync_info &value, std::pmr::memory_resource *mr) -> result<intermediate_response>
{
	const auto number = std::to_underlying(value.type);
	if (number > std::to_underlying(sync_info_type::sync_id_set)) {
		return fail(client_errc::encode_error, detail::format("sync info: unknown type {}", number));
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	if (value.type == sync_info_type::new_cookie) {
		if (!value.cookie) {
			return fail(client_errc::encode_error, "sync info: newcookie without a cookie");
		}
		w.octet_string(*value.cookie, ber::context(number));
	} else {
		w.constructed(ber::context(number, true), [&](ber::writer &s) {
			if (value.cookie) {
				s.octet_string(*value.cookie);
			}
			if (value.type == sync_info_type::sync_id_set) {
				if (value.refresh_deletes) {
					s.boolean(true);
				}
				s.constructed(ber::tags::set, [&](ber::writer &set) {
					for (const auto &u : value.sync_uuids) {
						set.octet_string(std::span<const std::byte>(u.bytes));
					}
				});
			} else if (!value.refresh_done) {
				s.boolean(false);
			}
		});
	}
	return intermediate_response(sync_info_oid, detail::as_text(w.bytes()), intermediate_response::allocator_type(mr));
}

// ---------------------------------------------------------------- DirSync (MS-ADTS 3.1.1.3.4.1.3)

namespace ad {

	using ldap::ad::dirsync_flags;
	using ldap::ad::dirsync_oid;
	using ldap::ad::dirsync_request;
	using ldap::ad::dirsync_response;

	namespace {

		constexpr auto int32_min = std::int64_t{ std::numeric_limits<std::int32_t>::min() };
		constexpr auto int32_max = std::int64_t{ std::numeric_limits<std::int32_t>::max() };
		constexpr auto uint32_max = std::int64_t{ std::numeric_limits<std::uint32_t>::max() };

	}// namespace

	auto decode_dirsync_request(const control &c) -> result<dirsync_request>
	{
		static constexpr const char *what = "DirSync request";
		auto value = control_value(c, dirsync_oid, what);
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
		return in_control(read(), what);
	}


	auto encode_dirsync_response(const dirsync_response &value, bool criticality, std::pmr::memory_resource *mr)
	  -> control
	{
		ber::writer w{ ber::writer::allocator_type(mr) };
		w.constructed(ber::tags::sequence, [&](ber::writer &s) {
			s.integer(value.more_results ? 1 : 0);
			s.integer(value.unused);
			s.octet_string(value.cookie_server);
		});
		return value_control(dirsync_oid, criticality, w, mr);
	}

}// namespace ad

}// namespace jhetz::ldap::testing
