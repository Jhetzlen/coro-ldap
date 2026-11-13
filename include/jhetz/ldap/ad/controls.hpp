// Active Directory's request controls as raw ldap::control values, and the
// DirSync control's codec.
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

// LDAP_SERVER_SHOW_DELETED_OID (MS-ADTS 3.1.1.3.4.1.14): include deleted
// objects. No value; critical by default.
inline constexpr std::string_view show_deleted_oid = "1.2.840.113556.1.4.417";
struct show_deleted
{
	bool critical = true;

	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): goes in `.controls` lists as is
	operator control() const { return { show_deleted_oid, critical }; }
};

// LDAP_SERVER_NOTIFICATION_OID (MS-ADTS 3.1.1.3.4.1.9): an entry per change,
// never ending. No value; critical by default.
inline constexpr std::string_view notification_oid = "1.2.840.113556.1.4.528";
struct notification
{
	bool critical = true;

	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): goes in `.controls` lists as is
	operator control() const { return { notification_oid, critical }; }
};

// The search a change notification needs, for search_stream(); on a client,
// open it on a lease.
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

// LDAP_SERVER_DIRSYNC_OID, the request and response control alike.
inline constexpr std::string_view dirsync_oid = "1.2.840.113556.1.4.841";

// DirSyncRequestValue's Flags.
enum class dirsync_flags : std::uint32_t {
	none = 0,
	// LDAP_DIRSYNC_OBJECT_SECURITY: only what the caller may read.
	object_security = 0x0000'0001,
	// LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER
	ancestors_first_order = 0x0000'0800,
	// LDAP_DIRSYNC_PUBLIC_DATA_ONLY
	public_data_only = 0x0000'2000,
	// LDAP_DIRSYNC_INCREMENTAL_VALUES: only the linked values added
	// (`member;range=1-1`) and removed (`member;range=0-0`).
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

// System.DirectoryServices.Protocols' default MaxBytes.
inline constexpr std::int32_t dirsync_default_max_bytes = 1'048'576;

// DirSyncRequestValue; an empty `cookie` starts from nothing. Critical by
// default.
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

[[nodiscard]] auto encode_dirsync_request(const dirsync_request &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> control;
// The request control as a server reads it (mock servers, tests).
[[nodiscard]] auto decode_dirsync_request(const control &c) -> result<dirsync_request>;

// DirSyncResponseValue.
struct dirsync_response
{
	bool more_results = false;
	std::int32_t unused = 0;
	std::string cookie_server{};

	friend auto operator==(const dirsync_response &, const dirsync_response &) -> bool = default;
};

// For mock servers and tests.
[[nodiscard]] auto encode_dirsync_response(const dirsync_response &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> control;
[[nodiscard]] auto decode_dirsync_response(const control &c) -> result<dirsync_response>;
// nullopt without one.
[[nodiscard]] auto find_dirsync_response(const std::pmr::vector<control> &controls)
  -> result<std::optional<dirsync_response>>;

}// namespace jhetz::ldap::ad
