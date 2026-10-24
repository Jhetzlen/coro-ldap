// The LDAP Content Synchronization Operation (RFC 4533, "syncrepl"): the
// Sync Request control a client puts on a search, the Sync State and Sync
// Done controls the server returns with each entry and with the
// SearchResultDone, and the Sync Info Message, an IntermediateResponse.
// Part of jhetz::ldap (the codec). The search itself is an ordinary
// search_stream read with next_item() (search_stream.hpp, DESIGN.md
// section 7, "Content synchronization"):
//
//   auto s = co_await conn.search_stream({
//       .base     = base,
//       .controls = {ldap::sync_request{.mode = ldap::sync_mode::refresh_and_persist, .cookie = saved}},
//       .timeout  = ldap::no_timeout,          // persist runs until stopped
//       .intermediate_responses = true,        // the Sync Info Messages
//   });
//   ...
//       auto i = co_await s->next_item();
//       if (auto *e = std::get_if<ldap::search_entry>(&**i)) {
//           auto state = ldap::find_sync_state(e->controls);   // present / add / modify / delete
//       } else if (auto *m = std::get_if<ldap::intermediate>(&**i)) {
//           auto info = ldap::decode_sync_info(*m);           // new cookie, end of refresh, ...
//       }
//   ...
//   auto done = ldap::find_sync_done(s->controls());          // refreshOnly: the final cookie
//
// After a present-mode refresh (a Sync Done or refreshPresent with
// refresh_deletes false), the entries not reported present are gone.
// A search that ends with errc::e_sync_refresh_required (RFC 4533 section
// 3.8) is resent with the cookie of find_sync_done(s->controls()) (the
// stream keeps an error result's controls) if it has one, else with no
// cookie: a full reload that replaces the local copy.
//
// Names, field order and defaults are RFC 4533's (section 2). Encoders
// leave out the fields equal to their DEFAULT; decoders accept them either
// way, and skip unknown trailing SEQUENCE elements as RFC 4511 section 4
// allows elsewhere. Cookies are opaque octets, absent and empty kept
// apart.
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

// The size of a syncUUID in octets.
inline constexpr std::size_t sync_uuid_size = 16;

// syncUUID ::= OCTET STRING (SIZE(16)): an entry's entryUUID (RFC 4530) in
// its 16 octets.
struct sync_uuid
{
	std::array<std::byte, sync_uuid_size> bytes{};

	friend auto operator==(const sync_uuid &, const sync_uuid &) -> bool = default;
};

// The RFC 4122 text form, as the entryUUID attribute reads
// ("597ae2f6-16a6-1027-98f4-d28b5365dc14", lowercase hex).
[[nodiscard]] auto to_string(const sync_uuid &uuid) -> std::string;

// ---------------------------------------------------------------- Sync Request (section 2.2)

// syncRequestValue's mode (0 unused, 2 reserved).
enum class sync_mode : std::uint8_t {
	refresh_only = 1,// the current content, then the search ends with a Sync Done
	refresh_and_persist = 3,// the current content, then every change, until abandoned
};

// The request control, for search_params::controls (a request_control,
// controls.hpp). `cookie` is the one the server last sent (Sync State,
// Sync Info or Sync Done), to resume from there; nullopt starts from
// nothing (the whole content). `reload_hint` (reloadHint, DEFAULT FALSE)
// asks for the full content when the cookie is too old for an incremental
// refresh, instead of an e-syncRefreshRequired error (errc 4096). RFC 4533
// lets the control be critical or not; critical by default here, so a
// server without content synchronization refuses the search
// (unavailable_critical_extension) instead of running it as a plain one.
struct sync_request
{
	sync_mode mode = sync_mode::refresh_only;
	std::optional<std::string> cookie{};
	bool reload_hint = false;
	bool critical = true;

	friend auto operator==(const sync_request &, const sync_request &) -> bool = default;
};

// Fails with encode_error for a mode other than refresh_only or
// refresh_and_persist. Allocated from `mr`. to_control() calls it.
[[nodiscard]] auto encode_sync_request(const sync_request &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
// The request control as a server reads it (for mock servers and tests):
// `critical` is the control's criticality. Fails with decode_error if `c`
// is not a Sync Request control or its value is missing or malformed.
[[nodiscard]] auto decode_sync_request(const control &c) -> result<sync_request>;

// ---------------------------------------------------------------- Sync State (section 2.3)

// syncStateValue's state: what an entry (or reference) of the sync search
// stands for.
enum class sync_state_type : std::uint8_t {
	present = 0,// unchanged since the cookie (refresh phase, present mode)
	add = 1,// added, or new to the search's scope
	modify = 2,// modified (the entry carries its new content)
	del = 3,// deleted, or out of the search's scope (only the DN is sent)
};

// The Sync State control of a SearchResultEntry (or SearchResultReference).
// Allocator-aware like the message model.
struct sync_state
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// The RFC fields are the API, public as in the other message types; the
	// private allocator only remembers the resource, which absent optional
	// members cannot carry.
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

// The control as a server sends it (for mock servers and tests); never
// fails today. Allocated from `mr`.
[[nodiscard]] auto encode_sync_state(const sync_state &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
// Fails with decode_error if `c` is not a Sync State control or its value
// is missing or malformed (an unknown state, an entryUUID not of 16
// octets). Allocated from `mr`.
[[nodiscard]] auto decode_sync_state(const control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<sync_state>;
// The Sync State control among `controls` (a search_entry's or
// search_reference's), nullopt if there is none, or decode_error if it is
// malformed.
[[nodiscard]] auto find_sync_state(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<sync_state>>;

// ---------------------------------------------------------------- Sync Done (section 2.4)

// The Sync Done control of the SearchResultDone: the cookie to resume
// from, and whether the refresh used delete mode (refresh_deletes: the
// deleted entries were sent as such) or present mode (false: entries not
// sent as present are gone).
struct sync_done
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// The RFC fields are the API, public as in the other message types; the
	// private allocator only remembers the resource, which absent optional
	// members cannot carry.
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

// The control as a server sends it (for mock servers and tests); never
// fails today. Allocated from `mr`.
[[nodiscard]] auto encode_sync_done(const sync_done &value,
  bool criticality = false,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<control>;
// Fails with decode_error if `c` is not a Sync Done control or its value is
// missing or malformed. Allocated from `mr`.
[[nodiscard]] auto decode_sync_done(const control &c, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> result<sync_done>;
// The Sync Done control among `controls` (search_stream::controls()),
// nullopt if there is none, or decode_error if it is malformed.
[[nodiscard]] auto find_sync_done(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<std::optional<sync_done>>;

// ---------------------------------------------------------------- Sync Info Message (section 2.5)

// Which alternative of the syncInfoValue CHOICE; the values are its
// context tags.
enum class sync_info_type : std::uint8_t {
	new_cookie = 0,// newcookie [0]: just a new cookie
	refresh_delete = 1,// refreshDelete [1]: the end of a delete-mode refresh phase
	refresh_present = 2,// refreshPresent [2]: the end of a present-mode refresh phase
	sync_id_set = 3,// syncIdSet [3]: entries deleted (refresh_deletes) or present, by entryUUID
};

// A Sync Info Message, one struct for every alternative: the members a
// type does not have keep their defaults (and are not encoded).
// - new_cookie: `cookie` (required).
// - refresh_delete, refresh_present: `cookie` (OPTIONAL), `refresh_done`
//   (refreshDone, DEFAULT TRUE). False: another refresh phase follows, in
//   either mode (RFC 4533 section 3.3.2: refreshOnly ends a present phase
//   followed by a delete phase with a refreshPresent whose refreshDone is
//   false). True in refreshAndPersist: the refresh stage is over and the
//   persist stage begins (section 3.4.1).
// - sync_id_set: `cookie` (OPTIONAL), `refresh_deletes` (refreshDeletes,
//   DEFAULT FALSE: true lists deleted entries, false present ones), and
//   `sync_uuids` (syncUUIDs, a SET: the order is not significant).
// Allocator-aware like the message model.
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

// The IntermediateResponse (responseName sync_info_oid) as a server sends
// it (for mock servers and tests). Fails with encode_error for a
// new_cookie without a cookie or an unknown type. Allocated from `mr`.
[[nodiscard]] auto encode_sync_info(const sync_info &value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<intermediate_response>;
// Fails with decode_error if `i` is not a Sync Info Message (another or no
// responseName, no responseValue) or its value is malformed: an unknown
// CHOICE alternative, trailing bytes, an entryUUID not of 16 octets.
// Allocated from `mr`. An ldap::intermediate (operations.hpp) is one.
[[nodiscard]] auto decode_sync_info(const intermediate_response &i,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<sync_info>;

}// namespace jhetz::ldap
