// RFC 4533 content synchronization ("syncrepl") codecs: the Sync Request,
// Sync State and Sync Done controls and the Sync Info Message (docs/API.md,
// DESIGN.md section 7). Names, field order and defaults are RFC 4533's.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

inline constexpr std::string_view sync_request_oid = "1.3.6.1.4.1.4203.1.9.1.1";
inline constexpr std::string_view sync_state_oid = "1.3.6.1.4.1.4203.1.9.1.2";
inline constexpr std::string_view sync_done_oid = "1.3.6.1.4.1.4203.1.9.1.3";
// The responseName of the Sync Info Message (RFC 4533 section 2.5).
inline constexpr std::string_view sync_info_oid = "1.3.6.1.4.1.4203.1.9.1.4";

inline constexpr std::size_t sync_uuid_size = 16;

// syncUUID: an entry's entryUUID (RFC 4530) in its 16 octets.
struct sync_uuid
{
	std::array<std::byte, sync_uuid_size> bytes{};

	friend auto operator==(const sync_uuid &, const sync_uuid &) -> bool = default;
};

// The RFC 4122 text form, lowercase hex.
[[nodiscard]] auto to_string(const sync_uuid &uuid) -> std::string;

// ---------------------------------------------------------------- Sync Request (section 2.2)

// syncRequestValue's mode (0 unused, 2 reserved).
enum class sync_mode : std::uint8_t {
	refresh_only = 1,// the current content, then a Sync Done
	refresh_and_persist = 3,// the current content, then every change, until abandoned
};

// The request control (search only); critical by default.
struct sync_request
{
	sync_mode mode = sync_mode::refresh_only;
	std::optional<std::string> cookie{};
	bool reload_hint = false;
	bool critical = true;

	friend auto operator==(const sync_request &, const sync_request &) -> bool = default;
};

// encode_error for an unknown mode.
[[nodiscard]] auto encode_sync_request(const sync_request &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
// The request control as a server reads it (mock servers, tests).
[[nodiscard]] auto decode_sync_request(const control &c) -> result<sync_request>;

// ---------------------------------------------------------------- Sync State (section 2.3)

enum class sync_state_type : std::uint8_t {
	present = 0,// unchanged since the cookie
	add = 1,// added, or new to the search's scope
	modify = 2,// modified
	del = 3,// deleted, or out of the scope (only the DN is sent)
};

// The Sync State control of an entry or reference.
struct sync_state
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// NOLINTBEGIN(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)
	sync_state_type state = sync_state_type::present;
	sync_uuid entry_uuid{};
	std::optional<std::pmr::string> cookie{};
	// NOLINTEND(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)

	sync_state() = default;
	explicit sync_state(const allocator_type &alloc) : alloc_(alloc) {}
	sync_state(sync_state_type state_,
	  const sync_uuid &entry_uuid_,
	  std::optional<std::string_view> cookie_ = std::nullopt,
	  const allocator_type &alloc = {});
	sync_state(const sync_state &other);
	sync_state(sync_state &&) noexcept = default;
	sync_state(const sync_state &other, const allocator_type &alloc);
	sync_state(sync_state &&other, const allocator_type &alloc);
	auto operator=(const sync_state &other) -> sync_state &;
	auto operator=(sync_state &&other) -> sync_state &;
	~sync_state() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return alloc_; }

	friend auto operator==(const sync_state &a, const sync_state &b) -> bool
	{
		return a.state == b.state && a.entry_uuid == b.entry_uuid && a.cookie == b.cookie;
	}

  private:
	allocator_type alloc_{};
};

// For mock servers and tests.
[[nodiscard]] auto encode_sync_state(const sync_state &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
[[nodiscard]] auto decode_sync_state(const control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<sync_state>;
// nullopt if absent.
[[nodiscard]] auto find_sync_state(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<sync_state>>;

// ---------------------------------------------------------------- Sync Done (section 2.4)

// The Sync Done control of the SearchResultDone.
struct sync_done
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// NOLINTBEGIN(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)
	std::optional<std::pmr::string> cookie{};
	bool refresh_deletes = false;
	// NOLINTEND(misc-non-private-member-variables-in-classes,cppcoreguidelines-non-private-member-variables-in-classes)

	sync_done() = default;
	explicit sync_done(const allocator_type &alloc) : alloc_(alloc) {}
	explicit sync_done(std::optional<std::string_view> cookie_,
	  bool refresh_deletes_ = false,
	  const allocator_type &alloc = {});
	sync_done(const sync_done &other);
	sync_done(sync_done &&) noexcept = default;
	sync_done(const sync_done &other, const allocator_type &alloc);
	sync_done(sync_done &&other, const allocator_type &alloc);
	auto operator=(const sync_done &other) -> sync_done &;
	auto operator=(sync_done &&other) -> sync_done &;
	~sync_done() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return alloc_; }

	friend auto operator==(const sync_done &a, const sync_done &b) -> bool
	{
		return a.cookie == b.cookie && a.refresh_deletes == b.refresh_deletes;
	}

  private:
	allocator_type alloc_{};
};

// For mock servers and tests.
[[nodiscard]] auto encode_sync_done(const sync_done &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
[[nodiscard]] auto decode_sync_done(const control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<sync_done>;
// nullopt if absent.
[[nodiscard]] auto find_sync_done(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<sync_done>>;

// ---------------------------------------------------------------- Sync Info Message (section 2.5)

// The syncInfoValue CHOICE alternative; the values are its context tags.
enum class sync_info_type : std::uint8_t {
	new_cookie = 0,// newcookie [0]
	refresh_delete = 1,// refreshDelete [1]: the end of a delete-mode refresh phase
	refresh_present = 2,// refreshPresent [2]: the end of a present-mode refresh phase
	sync_id_set = 3,// syncIdSet [3]: entries deleted or present, by entryUUID
};

// A Sync Info Message, one struct for every alternative; members an
// alternative lacks keep their defaults.
struct sync_info
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	sync_info_type type = sync_info_type::new_cookie;
	std::optional<std::pmr::string> cookie{};
	bool refresh_done = true;
	bool refresh_deletes = false;
	std::pmr::vector<sync_uuid> sync_uuids{};

	sync_info() = default;
	explicit sync_info(const allocator_type &alloc) : sync_uuids(alloc) {}
	explicit sync_info(sync_info_type type_,
	  std::optional<std::string_view> cookie_ = std::nullopt,
	  const allocator_type &alloc = {});
	sync_info(const sync_info &other);
	sync_info(sync_info &&) noexcept = default;
	sync_info(const sync_info &other, const allocator_type &alloc);
	sync_info(sync_info &&other, const allocator_type &alloc);
	auto operator=(const sync_info &other) -> sync_info &;
	auto operator=(sync_info &&other) -> sync_info &;
	~sync_info() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return sync_uuids.get_allocator(); }

	friend auto operator==(const sync_info &, const sync_info &) -> bool = default;
};

// For mock servers and tests.
[[nodiscard]] auto encode_sync_info(const sync_info &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<intermediate_response>;
// decode_error unless `i` is a well-formed Sync Info Message.
[[nodiscard]] auto decode_sync_info(const intermediate_response &i,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<sync_info>;

}// namespace jhetz::ldap
