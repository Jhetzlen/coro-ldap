// The Content Synchronization controls and Sync Info Message (RFC 4533
// section 2): content_sync.hpp.
#include "jhetz/ldap/content_sync.hpp"

#include "control_util.hpp"
#include "format_util.hpp"
#include "pmr_util.hpp"

#include "jhetz/ldap/ber.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace jhetz::ldap {

using detail::assign_optional;
using detail::control_value;
using detail::enter_value;
using detail::find_decoded;
using detail::in_control;
using detail::next_is;
using detail::optional_string;
using detail::optional_with;
using detail::read_enum;
using detail::read_flag;
using detail::skip_rest;
using detail::value_control;

// ---------------------------------------------------------------- allocator-aware members

sync_state::sync_state(sync_state_type state_,
  const sync_uuid &entry_uuid_,
  std::optional<std::string_view> cookie_,
  const allocator_type &alloc)
  : state(state_), entry_uuid(entry_uuid_), cookie(optional_string(cookie_, alloc)), alloc_(alloc)
{}

// A plain copy uses the default resource, like the pmr containers.
sync_state::sync_state(const sync_state &other) : sync_state(other, allocator_type{}) {}

sync_state::sync_state(const sync_state &other, const allocator_type &alloc)
  : state(other.state), entry_uuid(other.entry_uuid), cookie(optional_with(other.cookie, alloc)), alloc_(alloc)
{}

sync_state::sync_state(sync_state &&other, const allocator_type &alloc)
  : state(other.state), entry_uuid(other.entry_uuid), cookie(optional_with(std::move(other.cookie), alloc)),
	alloc_(alloc)
{}

auto sync_state::operator=(const sync_state &other) -> sync_state &
{
	if (this == &other) {
		return *this;
	}
	state = other.state;
	entry_uuid = other.entry_uuid;
	assign_optional(cookie, other.cookie, alloc_);
	return *this;
}

auto sync_state::operator=(sync_state &&other) -> sync_state &
{
	if (this == &other) {
		return *this;
	}
	state = other.state;
	entry_uuid = other.entry_uuid;
	assign_optional(cookie, std::move(other.cookie), alloc_);
	return *this;
}

sync_done::sync_done(std::optional<std::string_view> cookie_, bool refresh_deletes_, const allocator_type &alloc)
  : cookie(optional_string(cookie_, alloc)), refresh_deletes(refresh_deletes_), alloc_(alloc)
{}

sync_done::sync_done(const sync_done &other) : sync_done(other, allocator_type{}) {}

sync_done::sync_done(const sync_done &other, const allocator_type &alloc)
  : cookie(optional_with(other.cookie, alloc)), refresh_deletes(other.refresh_deletes), alloc_(alloc)
{}

sync_done::sync_done(sync_done &&other, const allocator_type &alloc)
  : cookie(optional_with(std::move(other.cookie), alloc)), refresh_deletes(other.refresh_deletes), alloc_(alloc)
{}

auto sync_done::operator=(const sync_done &other) -> sync_done &
{
	if (this == &other) {
		return *this;
	}
	assign_optional(cookie, other.cookie, alloc_);
	refresh_deletes = other.refresh_deletes;
	return *this;
}

auto sync_done::operator=(sync_done &&other) -> sync_done &
{
	if (this == &other) {
		return *this;
	}
	assign_optional(cookie, std::move(other.cookie), alloc_);
	refresh_deletes = other.refresh_deletes;
	return *this;
}

sync_info::sync_info(sync_info_type type_, std::optional<std::string_view> cookie_, const allocator_type &alloc)
  : type(type_), cookie(optional_string(cookie_, alloc)), sync_uuids(alloc)
{}

sync_info::sync_info(const sync_info &other) : sync_info(other, allocator_type{}) {}

sync_info::sync_info(const sync_info &other, const allocator_type &alloc)
  : type(other.type), cookie(optional_with(other.cookie, alloc)), refresh_done(other.refresh_done),
	refresh_deletes(other.refresh_deletes), sync_uuids(other.sync_uuids, alloc)
{}

sync_info::sync_info(sync_info &&other, const allocator_type &alloc)
  : type(other.type), cookie(optional_with(std::move(other.cookie), alloc)), refresh_done(other.refresh_done),
	refresh_deletes(other.refresh_deletes), sync_uuids(std::move(other.sync_uuids), alloc)
{}

auto sync_info::operator=(const sync_info &other) -> sync_info &
{
	if (this == &other) {
		return *this;
	}
	type = other.type;
	assign_optional(cookie, other.cookie, get_allocator());
	refresh_done = other.refresh_done;
	refresh_deletes = other.refresh_deletes;
	sync_uuids = other.sync_uuids;
	return *this;
}

auto sync_info::operator=(sync_info &&other) -> sync_info &
{
	if (this == &other) {
		return *this;
	}
	type = other.type;
	assign_optional(cookie, std::move(other.cookie), get_allocator());
	refresh_done = other.refresh_done;
	refresh_deletes = other.refresh_deletes;
	sync_uuids = std::move(other.sync_uuids);
	return *this;
}

auto to_string(const sync_uuid &uuid) -> std::string
{
	// 8-4-4-4-12 hex digits: a dash before octets 4, 6, 8 and 10.
	static constexpr std::array<std::size_t, 4> dash_before = { 4, 6, 8, 10 };
	static constexpr std::size_t text_size = (2 * sync_uuid_size) + dash_before.size();
	std::string out;
	out.reserve(text_size);
	for (std::size_t i = 0; i < uuid.bytes.size(); ++i) {
		if (std::ranges::contains(dash_before, i)) {
			out += '-';
		}
		detail::append_hex_octet(out, std::to_integer<unsigned char>(uuid.bytes[i]));
	}
	return out;
}

namespace {

	// ---------------------------------------------------------------- helpers

	auto bad(std::string_view what, std::string_view why) -> std::unexpected<error>
	{
		return fail(client_errc::decode_error, detail::format("{}: {}", what, why));
	}

	// cookie syncCookie OPTIONAL (an OCTET STRING).
	auto read_cookie(ber::reader &r, std::pmr::memory_resource *mr) -> result<std::optional<std::pmr::string>>
	{
		if (!next_is(r, ber::tags::octet_string)) {
			return std::optional<std::pmr::string>{};
		}
		return r.read_string(ber::tags::octet_string, mr).transform([](std::pmr::string &&s) {
			return std::optional<std::pmr::string>(std::move(s));
		});
	}

	// syncUUID ::= OCTET STRING (SIZE(16))
	auto read_uuid(ber::reader &r) -> result<sync_uuid>
	{
		const std::size_t offset = r.offset();
		auto copy = r;
		auto bytes = copy.read_octet_string();
		if (!bytes) {
			return std::unexpected(std::move(bytes.error()));
		}
		if (bytes->size() != sync_uuid_size) {
			return fail(client_errc::decode_error,
			  detail::format("syncUUID of {} octets, not {}, at offset {}", bytes->size(), sync_uuid_size, offset));
		}
		r = copy;
		sync_uuid out;
		std::ranges::copy(*bytes, out.bytes.begin());
		return out;
	}

	constexpr std::array<std::int64_t, 2> mode_values = { std::to_underlying(sync_mode::refresh_only),
		std::to_underlying(sync_mode::refresh_and_persist) };
	constexpr std::array<std::int64_t, 4> state_values = { std::to_underlying(sync_state_type::present),
		std::to_underlying(sync_state_type::add),
		std::to_underlying(sync_state_type::modify),
		std::to_underlying(sync_state_type::del) };

}// namespace

// ---------------------------------------------------------------- Sync Request

// syncRequestValue ::= SEQUENCE { mode ENUMERATED { refreshOnly (1),
//   refreshAndPersist (3) }, cookie syncCookie OPTIONAL,
//   reloadHint BOOLEAN DEFAULT FALSE }
auto encode_sync_request(const sync_request &value, std::pmr::memory_resource *mr) -> result<control>
{
	if (!std::ranges::contains(mode_values, std::to_underlying(value.mode))) {
		return fail(
		  client_errc::encode_error, detail::format("sync request: unknown mode {}", std::to_underlying(value.mode)));
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.enumerated(std::to_underlying(value.mode));
		if (value.cookie) {
			s.octet_string(*value.cookie);
		}
		if (value.reload_hint) {
			s.boolean(true);
		}
	});
	return value_control(sync_request_oid, value.critical, w, mr);
}

// ---------------------------------------------------------------- Sync State

// syncStateValue ::= SEQUENCE { state ENUMERATED { present (0), add (1),
//   modify (2), delete (3) }, entryUUID syncUUID, cookie syncCookie OPTIONAL }
auto decode_sync_state(const control &c, std::pmr::memory_resource *mr) -> result<sync_state>
{
	static constexpr std::string_view what = "sync state";
	auto value = control_value(c, sync_state_oid, what);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	const auto read = [&] -> result<sync_state> {
		ber::reader r(*value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto state = read_enum(*s, state_values, "state");
		if (!state) {
			return std::unexpected(std::move(state.error()));
		}
		auto uuid = read_uuid(*s);
		if (!uuid) {
			return std::unexpected(std::move(uuid.error()));
		}
		auto cookie = read_cookie(*s, mr);
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		sync_state out{ sync_state::allocator_type(mr) };
		out.state = static_cast<sync_state_type>(*state);
		out.entry_uuid = *uuid;
		out.cookie = std::move(*cookie);
		return out;
	};
	return in_control(read(), what);
}

auto find_sync_state(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<sync_state>>
{
	return find_decoded<sync_state>(
	  controls, sync_state_oid, [mr](const control &c) { return decode_sync_state(c, mr); });
}

// ---------------------------------------------------------------- Sync Done

// syncDoneValue ::= SEQUENCE { cookie syncCookie OPTIONAL,
//   refreshDeletes BOOLEAN DEFAULT FALSE }
auto decode_sync_done(const control &c, std::pmr::memory_resource *mr) -> result<sync_done>
{
	static constexpr std::string_view what = "sync done";
	auto value = control_value(c, sync_done_oid, what);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	const auto read = [&] -> result<sync_done> {
		ber::reader r(*value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto cookie = read_cookie(*s, mr);
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		auto deletes = read_flag(*s, false);
		if (!deletes) {
			return std::unexpected(std::move(deletes.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		sync_done out{ sync_done::allocator_type(mr) };
		out.cookie = std::move(*cookie);
		out.refresh_deletes = *deletes;
		return out;
	};
	return in_control(read(), what);
}

auto find_sync_done(const std::pmr::vector<control> &controls, std::pmr::memory_resource *mr)
  -> result<std::optional<sync_done>>
{
	return find_decoded<sync_done>(controls, sync_done_oid, [mr](const control &c) { return decode_sync_done(c, mr); });
}

// ---------------------------------------------------------------- Sync Info Message

// syncInfoValue ::= CHOICE {
//   newcookie      [0] syncCookie,
//   refreshDelete  [1] SEQUENCE { cookie syncCookie OPTIONAL, refreshDone BOOLEAN DEFAULT TRUE },
//   refreshPresent [2] SEQUENCE { cookie syncCookie OPTIONAL, refreshDone BOOLEAN DEFAULT TRUE },
//   syncIdSet      [3] SEQUENCE { cookie syncCookie OPTIONAL, refreshDeletes BOOLEAN DEFAULT FALSE,
//                                 syncUUIDs SET OF syncUUID } }
// (implicit tags, as everywhere in LDAP).
namespace {

	auto read_sync_info(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<sync_info>
	{
		ber::reader r(value);
		auto t = r.peek_tag();
		if (!t) {
			return std::unexpected(std::move(t.error()));
		}
		if (t->cls != ber::tag_class::context || t->number > std::to_underlying(sync_info_type::sync_id_set)) {
			return fail(client_errc::decode_error,
			  detail::format("unknown syncInfoValue alternative {} at offset 0", ber::to_string(*t)));
		}
		sync_info out{ sync_info::allocator_type(mr) };
		out.type = static_cast<sync_info_type>(t->number);
		if (out.type == sync_info_type::new_cookie) {
			auto cookie = r.read_string(ber::context(0), mr);
			if (!cookie) {
				return std::unexpected(std::move(cookie.error()));
			}
			out.cookie = std::move(*cookie);
			if (auto done = r.expect_end(); !done) {
				return std::unexpected(std::move(done.error()));
			}
			return out;
		}
		auto s = r.enter(ber::context(t->number, true));
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		if (auto done = r.expect_end(); !done) {
			return std::unexpected(std::move(done.error()));
		}
		auto cookie = read_cookie(*s, mr);
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		out.cookie = std::move(*cookie);
		if (out.type == sync_info_type::sync_id_set) {
			auto deletes = read_flag(*s, false);
			if (!deletes) {
				return std::unexpected(std::move(deletes.error()));
			}
			out.refresh_deletes = *deletes;
			auto set = s->enter(ber::tags::set);
			if (!set) {
				return std::unexpected(std::move(set.error()));
			}
			while (!set->empty()) {
				auto u = read_uuid(*set);
				if (!u) {
					return std::unexpected(std::move(u.error()));
				}
				out.sync_uuids.push_back(*u);
			}
		} else {
			auto refresh_done = read_flag(*s, true);
			if (!refresh_done) {
				return std::unexpected(std::move(refresh_done.error()));
			}
			out.refresh_done = *refresh_done;
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

}// namespace

auto decode_sync_info(const intermediate_response &i, std::pmr::memory_resource *mr) -> result<sync_info>
{
	static constexpr std::string_view what = "sync info";
	if (i.response_name != sync_info_oid) {
		std::string context = "sync info: responseName is ";
		if (i.response_name) {
			detail::append_sanitized(context, *i.response_name, 64);
		} else {
			context += "absent";
		}
		context += detail::format(", not {}", sync_info_oid);
		return fail(client_errc::decode_error, context);
	}
	if (!i.response_value) {
		return bad(what, "no responseValue");
	}
	return in_control(read_sync_info(std::as_bytes(std::span(*i.response_value)), mr), what);
}

}// namespace jhetz::ldap
