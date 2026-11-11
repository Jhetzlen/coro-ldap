// Active Directory's controls: request controls as raw ldap::control
// values that go in any operation's `.controls`, and the DirSync control's
// codec (its request and response values).
//
//   co_await conn.search({
//       .base     = ldap::dn{ "DC=example,DC=org" },
//       .filter   = ldap::filters::attr("isDeleted") == "TRUE",
//       .controls = { ldap::ad::show_deleted{} },
//   });
#pragma once

#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"

#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::ad {

// LDAP_SERVER_SHOW_DELETED_OID (MS-ADTS 3.1.1.3.4.1.14): searches include
// deleted objects (tombstones and, with the Recycle Bin, deleted-objects),
// those with isDeleted TRUE, usually under CN=Deleted Objects of their
// naming context. No value. Critical by default: a server that does not
// know the control refuses the operation (unavailable_critical_extension)
// instead of leaving the deleted objects out.
inline constexpr std::string_view show_deleted_oid = "1.2.840.113556.1.4.417";
struct show_deleted
{
	bool critical = true;

	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): goes in `.controls` lists as is
	operator control() const { return { show_deleted_oid, critical }; }
};

// LDAP_SERVER_NOTIFICATION_OID (MS-ADTS 3.1.1.3.4.1.9): the search never
// ends; the server sends an entry each time an object in scope changes (no
// initial content, no cookie). AD takes it with the filter
// (objectClass=*) and a base or one-level scope, and allows a few at once
// per connection (MaxNotificationPerConn, 5 by default).
// notification_search() builds such a search. No value. Critical by
// default: a server without it refuses the search instead of running it
// as a plain one.
inline constexpr std::string_view notification_oid = "1.2.840.113556.1.4.528";
struct notification
{
	bool critical = true;

	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): goes in `.controls` lists as is
	operator control() const { return { notification_oid, critical }; }
};

// The search a change notification needs, for search_stream(): `base` and
// `scope` (base_object or single_level), the filter (objectClass=*), the
// `attributes` each changed entry is sent with, the notification control,
// and no client timeout (ldap::no_timeout): it runs until the stream is
// destroyed or its stop token is set. On an ldap::client, open it on a
// lease (acquire()): client::search_stream() returns at the search's first
// message, which here is the first change.
//
//   auto s = co_await conn.search_stream(ldap::ad::notification_search(ldap::dn{"CN=Users,DC=example,DC=org"},
//       ldap::search_scope::single_level, {"description"}));
//   while (auto e = co_await s->next()) { if (!*e) break; changed(**e); }
[[nodiscard]] inline auto notification_search(dn base,
  search_scope scope = search_scope::base_object,
  string_list attributes = {}) -> search_params
{
	return { .base = std::move(base),
		.scope = scope,
		.filter = filters::attr("objectClass").present(),
		.attributes = std::move(attributes),
		.controls = { notification{} },
		.timeout = no_timeout };
}

// ---------------------------------------------------------------- DirSync (MS-ADTS 3.1.1.3.4.1.3)

// LDAP_SERVER_DIRSYNC_OID: a search that returns the objects (and, of them,
// the attributes) changed since the cookie, the request and the response
// control alike. ad/dirsync.hpp runs the polling.
inline constexpr std::string_view dirsync_oid = "1.2.840.113556.1.4.841";

// DirSyncRequestValue's Flags.
enum class dirsync_flags : std::uint32_t {
	none = 0,
	// LDAP_DIRSYNC_OBJECT_SECURITY: without the Replicating Directory
	// Changes right, return only what the caller may read.
	object_security = 0x0000'0001,
	// LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER: parents before their children.
	ancestors_first_order = 0x0000'0800,
	// LDAP_DIRSYNC_PUBLIC_DATA_ONLY: no secret attributes.
	public_data_only = 0x0000'2000,
	// LDAP_DIRSYNC_INCREMENTAL_VALUES: of a changed linked multi-valued
	// attribute (member), only the values added (as `member;range=1-1`)
	// and removed (as `member;range=0-0`), not all of them.
	incremental_values = 0x8000'0000,
};

[[nodiscard]] constexpr auto operator|(dirsync_flags a, dirsync_flags b) noexcept -> dirsync_flags
{
	return dirsync_flags(std::to_underlying(a) | std::to_underlying(b));
}
[[nodiscard]] constexpr auto operator&(dirsync_flags a, dirsync_flags b) noexcept -> dirsync_flags
{
	return dirsync_flags(std::to_underlying(a) & std::to_underlying(b));
}
[[nodiscard]] constexpr auto has(dirsync_flags flags, dirsync_flags bits) noexcept -> bool
{
	return (flags & bits) == bits;
}

// The MaxBytes System.DirectoryServices.Protocols' DirSyncRequestControl
// sends by default.
inline constexpr std::int32_t dirsync_default_max_bytes = 1'048'576;

// DirSyncRequestValue ::= SEQUENCE { Flags integer, MaxBytes integer,
// Cookie OCTET STRING }. `cookie` empty starts from nothing (every object
// in scope); else the CookieServer of the last response. Flags is sent as
// the signed 32-bit INTEGER AD reads (incremental_values is negative).
// Critical by default: a server without DirSync refuses the search
// (unavailable_critical_extension) instead of returning everything.
struct dirsync_request
{
	dirsync_flags flags = dirsync_flags::none;
	std::int32_t max_bytes = dirsync_default_max_bytes;
	std::string cookie{};
	bool critical = true;

	friend auto operator==(const dirsync_request &, const dirsync_request &) -> bool = default;

	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): goes in `.controls` lists as is
	operator control() const;
};

// The request control, allocated from `mr`. Every value is encodable.
[[nodiscard]] auto encode_dirsync_request(const dirsync_request &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> control;
// The request control as a server reads it (for mock servers and tests):
// `critical` is the control's criticality. Flags is read as a signed or an
// unsigned 32-bit value. Fails with decode_error if `c` is not a DirSync
// control, has no value, or its value is malformed (a number outside 32
// bits, MaxBytes outside the signed range); unknown trailing elements are
// skipped.
[[nodiscard]] auto decode_dirsync_request(const control &c) -> result<dirsync_request>;

// DirSyncResponseValue ::= SEQUENCE { MoreResults INTEGER, unused INTEGER,
// CookieServer OCTET STRING }. `more_results`: not every change was
// returned, search again with `cookie_server` at once. `cookie_server` is
// the cookie for the next search, opaque octets.
struct dirsync_response
{
	bool more_results = false;
	std::int32_t unused = 0;
	std::string cookie_server{};

	friend auto operator==(const dirsync_response &, const dirsync_response &) -> bool = default;
};

// The response control (for mock servers and tests), MoreResults 1 or 0.
[[nodiscard]] auto encode_dirsync_response(const dirsync_response &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> control;
// MoreResults is true for any non-zero value. Fails with decode_error as
// decode_dirsync_request does.
[[nodiscard]] auto decode_dirsync_response(const control &c) -> result<dirsync_response>;
// The DirSync response among a SearchResultDone's controls: nullopt
// without one, decode_error for a malformed one.
[[nodiscard]] auto find_dirsync_response(const std::pmr::vector<control> &controls)
  -> result<std::optional<dirsync_response>>;

}// namespace jhetz::ldap::ad
