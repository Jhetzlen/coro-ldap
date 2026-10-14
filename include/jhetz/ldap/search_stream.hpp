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
// Move-only. A default-constructed stream fails with
// client_errc::not_connected. The stream must not be destroyed or moved
// while its next() is suspended; a second next() while one is suspended
// fails with client_errc::operation_in_progress.
#pragma once

#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>

#include <memory_resource>
#include <optional>

namespace jhetz::ldap {

class connection;
class paged_search;

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
	// returns the same again without I/O.
	auto next() -> boost::capy::task<result<std::optional<entry>>>;

	// True once the SearchResultDone (or an error) was read.
	auto done() const noexcept -> bool;
	// URIs of the SearchResultReference messages received so far, in order,
	// as sent (one string per URI). They are not chased; reference_urls()
	// parses them.
	auto references() const noexcept -> const string_list &;
	// references() parsed as LDAP URLs; URIs that do not parse are left out.
	[[nodiscard]] auto reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::vector<url>;
	// Controls of the SearchResultDone (e.g. paged results, or the sort
	// result: find_sort_result()), once done().
	auto controls() const noexcept -> const std::pmr::vector<control> &;

	struct state;// defined in src/connection/search.hpp

  private:
	friend class connection;
	friend class paged_search;

	explicit search_stream(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
};

}// namespace jhetz::ldap
