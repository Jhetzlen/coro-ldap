// ldap::search_paged and ldap::paged_search: the entries of a paged search
// (Simple Paged Results, RFC 2696), across pages, on a connection or on a
// client's pool. Part of jhetz::ldap_net.
//
//   auto pages = co_await ldap::search_paged(conn, {.base = base, .filter = f}, 100);
//   if (!pages) return pages.error();
//   while (true) {
//       ldap::result<std::optional<ldap::entry>> e = co_await pages->next();
//       if (!e) return e.error();
//       if (!*e) break;
//       use(**e);
//   }
//
// Each page is one connection::search_stream() (the same task, on the
// connection's shared state) with the paged control (RFC 2696) and the
// cookie the previous page ended with. Used like
// search_stream. Move-only; the same rules as search_stream apply.
//
// Destroyed before its end, it stops the search on the server: the current
// page's search is abandoned if it is still running, then the server's
// paging state is released (RFC 2696 section 3: the same search with page
// size 0 and the last cookie the server returned, which is the current
// page's if it already ended, else the previous page's). This is best
// effort and never waits: the release is queued like an AbandonRequest, and
// its answer is read and dropped. Until it arrives, for as long as a page
// would be waited for (search_params::timeout, else
// connection_options::operation_timeout; no limit without either),
// outstanding() counts it and start_tls() waits for it; past that deadline
// a late answer is still dropped (see connection::start_tls for one that
// comes during StartTLS). Nothing is released after the last page (empty
// cookie), after an error that ended the search (the server's result, a
// malformed paged results control, a closed connection), while the first
// page is running (no cookie yet: only the abandon), during a StartTLS
// exchange, or once the connection is closed. A page that timed out or was
// cancelled, or a next page that could not be sent, leaves the paged_search
// done with the last cookie kept, and its destruction releases the state.
// Like search_stream, it must be destroyed on the connection's executor, or
// its cleanup is posted there (connection.hpp "Threading").
#pragma once

#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>

namespace jhetz::ldap {

class connection;
class client;

namespace detail {
	struct paged_access;
}

class paged_search
{
  public:
	paged_search() noexcept = default;
	paged_search(paged_search &&other) noexcept;
	auto operator=(paged_search &&other) noexcept -> paged_search &;
	paged_search(const paged_search &) = delete;
	auto operator=(const paged_search &) -> paged_search & = delete;
	~paged_search();

	// The next entry, nullopt after the last page, or an error (the
	// search's, or a malformed paged results control: decode_error). Like
	// search_stream::next(), it drops the controls of the entries and the
	// IntermediateResponses (search_params::intermediate_responses is
	// ignored: they are decoded and dropped); there is no next_item(): read
	// the pages with search_stream and a paged control of your own for those.
	auto next() -> boost::capy::task<result<std::optional<entry>>>;

	[[nodiscard]] auto done() const noexcept -> bool;
	// Pages requested so far (1 after search_paged()).
	[[nodiscard]] auto pages() const noexcept -> std::size_t;
	// References of every page so far, in order.
	[[nodiscard]] auto references() const noexcept -> const string_list &;
	[[nodiscard]] auto reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::vector<url>;
	// Controls of the last SearchResultDone, once done().
	[[nodiscard]] auto controls() const noexcept -> const std::pmr::vector<control> &;

	struct state;// defined in src/connection/paged_search.cpp

  private:
	friend struct detail::paged_access;

	explicit paged_search(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
};

// A search of `c` in pages of `page_size` entries: the first page is
// requested here, and when a page ends, the next one is requested with the
// server's cookie, until the cookie is empty. A paged control already in
// `request.controls` (typed, or raw with paged_results_oid) is replaced. A
// server that ignores the (non-critical) control returns everything as one
// page, which works the same. Each page is one search on the wire, with its
// own message id and its own `request.timeout`. A page size that is not
// positive fails with encode_error before anything is sent. Several may run
// at once on one connection (RFC 2696 section 3), but servers may limit
// that: OpenLDAP keeps one paged search per connection and refuses the next
// page of any but the one whose page it answered last (unwilling_to_perform
// or protocol_error, depending on the cookies' entry order), and with
// server_side_sort (its sssvlv overlay) it answers any next page with the
// latest sorted paged search's entries instead, which the client cannot
// detect. Give each concurrent paged search its own connection there.
// The paged_search keeps the connection's shared state, as a search_stream
// does: `c` may be moved or destroyed meanwhile (destroying it closes the
// connection; next() then fails with not_connected).
auto search_paged(connection &c,
  search_params request,
  std::int32_t page_size,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<paged_search>>;

// As above, on one connection of `c`'s pool: a shared lease (acquire())
// that the paged_search holds until it is destroyed, since the cookies are
// bound to that connection. Returns once the first page has a first message
// or has ended; when it fails before that with cond::connection_lost
// (client_errc::not_sent included), it is requested once more, on a new
// lease. Any other error, an acquire() failure included, is returned as is,
// a page ended with another result code than success is reported by
// next(), and next()'s errors are never retried. The paged_search may
// outlive `c`: the client's destruction closes the connection, and next()
// then fails with not_connected.
auto search_paged(client &c,
  search_params request,
  std::int32_t page_size,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<paged_search>>;

}// namespace jhetz::ldap
