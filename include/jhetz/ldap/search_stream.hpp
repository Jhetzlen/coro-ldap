// ldap::search_stream: the entries of one search, read one at a time
// (connection::search_stream). Part of jhetz::ldap_net.
//
//   auto s = co_await conn.search_stream({.base = base, .filter = f});
//   if (!s) return s.error();
//   while (true) {
//       ldap::result<std::optional<ldap::entry>> e = co_await s->next();
//       if (!e) return e.error();   // transport, protocol or server error
//       if (!*e) break;             // SearchResultDone with success
//       use(**e);
//   }
//
// next_item() reads the same search message by message, in the order the
// server sent them, each with its message's controls (RFC 4533's Sync State
// control on every entry and reference, ...): a search_entry, a
// search_reference, or an IntermediateResponse (RFC 4511 section 4.13: RFC
// 4533's syncInfo, ...) when the search was sent with
// search_params::intermediate_responses:
//
//   auto s = co_await conn.search_stream({.base = base, .intermediate_responses = true});
//   ...
//       ldap::result<std::optional<ldap::search_stream::item>> i = co_await s->next_item();
//       if (!i) return i.error();
//       if (!*i) break;
//       if (auto *e = std::get_if<ldap::search_entry>(&**i)) use(*e, e->controls);
//       else if (auto *r = std::get_if<ldap::search_reference>(&**i)) on_reference(r->uris, r->controls);
//       else on_intermediate(std::get<ldap::intermediate>(**i));
//
// RFC 4533 content synchronization reads a search sent with a
// sync_request control this way: content_sync.hpp decodes the controls and
// intermediates. A refreshAndPersist search never ends by itself: send it
// with search_params::timeout = ldap::no_timeout, and stop it with a stop
// token or by destroying the stream.
//
// Memory: entries are decoded into the search's resource and queued there
// until next() or next_item() takes them; the queue is not bounded and
// does not slow the server down (see connection.hpp), so a reader that
// falls behind lets it grow. On a std::pmr::monotonic_buffer_resource
// nothing is freed until the arena goes, so a long-lived (persist) search
// grows without bound there: use the default resource or a pool for it.
// references() also keeps every reference for the stream's life.
//
// next() and next_item() may be mixed on one stream: each reads the next
// message. next() drops what it cannot return (the controls of an entry, an
// intermediate); references go to references() either way.
//
// Move-only. A default-constructed stream fails with
// client_errc::not_connected. The stream must not be destroyed or moved
// while its next() or next_item() is suspended; a second call of either
// while one is suspended fails with client_errc::operation_in_progress.
#pragma once

#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>

#include <memory_resource>
#include <optional>
#include <utility>
#include <variant>

namespace jhetz::ldap {

class connection;

// A SearchResultEntry (RFC 4511 section 4.5.2) as an ldap::entry, with the
// controls of its message. Allocator-aware like entry. Converting it to
// an entry (slicing) drops the controls.
struct search_entry : entry
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<control> controls{};

	search_entry() = default;
	explicit search_entry(const allocator_type &alloc) : entry(alloc), controls(alloc) {}
	// Takes the strings of `e` and `controls_` when they are on `alloc`'s
	// resource, else copies them onto it.
	search_entry(entry e, std::pmr::vector<control> controls_, const allocator_type &alloc = {})
	  : entry(std::move(e), alloc), controls(std::move(controls_), alloc)
	{}
	search_entry(const search_entry &) = default;
	search_entry(search_entry &&) noexcept = default;
	search_entry(const search_entry &other, const allocator_type &alloc)
	  : entry(other, alloc), controls(other.controls, alloc)
	{}
	search_entry(search_entry &&other, const allocator_type &alloc)
	  : entry(std::move(other), alloc), controls(std::move(other.controls), alloc)
	{}
	auto operator=(const search_entry &) -> search_entry & = default;
	auto operator=(search_entry &&) -> search_entry & = default;
	~search_entry() = default;

	friend auto operator==(const search_entry &, const search_entry &) -> bool = default;
};

// A SearchResultReference (RFC 4511 section 4.5.3): its URIs as sent, with
// the controls of its message. Allocator-aware like the message model.
// Converting it to a search_result_reference (slicing) drops the controls.
struct search_reference : search_result_reference
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<control> controls{};

	search_reference() = default;
	explicit search_reference(const allocator_type &alloc) : search_result_reference(alloc), controls(alloc) {}
	// Takes the strings of `r` and `controls_` when they are on `alloc`'s
	// resource, else copies them onto it.
	search_reference(search_result_reference r, std::pmr::vector<control> controls_, const allocator_type &alloc = {})
	  : search_result_reference(std::move(r), alloc), controls(std::move(controls_), alloc)
	{}
	search_reference(const search_reference &) = default;
	search_reference(search_reference &&) noexcept = default;
	search_reference(const search_reference &other, const allocator_type &alloc)
	  : search_result_reference(other, alloc), controls(other.controls, alloc)
	{}
	search_reference(search_reference &&other, const allocator_type &alloc)
	  : search_result_reference(std::move(other), alloc), controls(std::move(other.controls), alloc)
	{}
	auto operator=(const search_reference &) -> search_reference & = default;
	auto operator=(search_reference &&) -> search_reference & = default;
	~search_reference() = default;

	friend auto operator==(const search_reference &, const search_reference &) -> bool = default;
};

class search_stream
{
  public:
	search_stream() noexcept = default;
	search_stream(search_stream &&other) noexcept;
	auto operator=(search_stream &&other) noexcept -> search_stream &;
	search_stream(const search_stream &) = delete;
	auto operator=(const search_stream &) -> search_stream & = delete;
	// Unfinished: the search is abandoned.
	~search_stream();

	// The next entry, nullopt at the end (SearchResultDone with success), or
	// an error: the server's result code (the connection stays usable), a
	// cancellation or timeout (the search is abandoned, the connection stays
	// usable) or a connection failure. After the end or an error, next()
	// returns the same again without I/O. Drops the controls of the entries;
	// references go to references(), IntermediateResponses are skipped.
	auto next() -> boost::capy::task<result<std::optional<entry>>>;

	// What next_item() yields: one search message with its controls, decoded
	// into the search's memory resource. An intermediate only when the
	// search was sent with search_params::intermediate_responses.
	// std::variant is not allocator-aware: a std::pmr::vector<item> does not
	// propagate its resource, and copies land on the default resource.
	using item = std::variant<search_entry, search_reference, intermediate>;
	// As next(), but yields every message before the SearchResultDone, in
	// the order received: entries and references with their controls, and
	// the IntermediateResponses if asked for. A reference is also appended
	// to references(), so that holds every reference whichever call read it.
	auto next_item() -> boost::capy::task<result<std::optional<item>>>;

	// True once the SearchResultDone (or an error) was read.
	[[nodiscard]] auto done() const noexcept -> bool;
	// URIs of the SearchResultReference messages read so far (by next() or
	// next_item()), in order, as sent (one string per URI). They are not
	// chased; reference_urls() parses them.
	[[nodiscard]] auto references() const noexcept -> const string_list &;
	// references() parsed as LDAP URLs; URIs that do not parse are left out.
	[[nodiscard]] auto reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::vector<url>;
	// Controls of the SearchResultDone (e.g. paged results, or the sort
	// result: find_sort_result()), once done().
	[[nodiscard]] auto controls() const noexcept -> const std::pmr::vector<control> &;

	struct state;// defined in src/connection/search.hpp

  private:
	friend class connection;

	explicit search_stream(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
};

}// namespace jhetz::ldap
