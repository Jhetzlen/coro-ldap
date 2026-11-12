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
// Each page is one connection::search_stream() with the paged control and
// the previous page's cookie. Used like search_stream; move-only, with the
// same rules.
//
// Destroyed before its end, it abandons the current page if still running
// and releases the server's paging state (RFC 2696 section 3: page size 0
// with the last cookie received), best effort and without waiting. Until its
// answer arrives or its deadline passes (search_params::timeout, else
// connection_options::operation_timeout), outstanding() counts it and
// start_tls() waits for it; a late answer is dropped. Nothing is released
// after the last page, after an error that ended the search, during the
// first page, during StartTLS, or once the connection is closed. A page that
// timed out or was cancelled, or a next page that could not be sent, leaves
// the paged_search done with the last cookie, released on destruction. It
// must be destroyed on the connection's executor, or its cleanup is posted
// there (connection.hpp "Threading").
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

// The default bound on the pages of one paged search.
inline constexpr std::size_t search_paged_default_max_pages = 10000;

// A search of `c` in pages of `page_size` entries: each page is requested
// with the previous page's cookie until the cookie is empty, at most
// `max_pages` pages (the default is about a million entries at a page size
// of 100). A paged control already in `request.controls` is replaced. A
// server ignoring the control returns everything as one page. Each page has
// its own message id and `request.timeout`; `request.timeout` bounds each
// page, not the search. A page size that is not positive fails with
// encode_error, and a max_pages of 0 with std::errc::invalid_argument,
// before anything is sent. When page `max_pages` ends with a cookie,
// next() fails with std::errc::value_too_large (the paging state is
// released on destruction): the cookie is the server's opaque state (RFC
// 2696 section 3) and a server may return the same one for every page, so
// the bound, not a repeated cookie, ends a search that does not. OpenLDAP allows one paged search per
// connection (it refuses another's next page with unwilling_to_perform or
// protocol_error) and, with server_side_sort (sssvlv), silently answers with
// the latest sorted paged search's entries: give each concurrent paged
// search its own connection there. The paged_search keeps the connection's
// shared state: `c` may be moved or destroyed meanwhile (destroying it
// closes the connection; next() then fails with not_connected).
auto search_paged(connection &c,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages = search_paged_default_max_pages,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<paged_search>>;

// As above, on one shared lease of `c`'s pool, held by the paged_search
// until destroyed (the cookies are bound to that connection). A page size
// that is not positive, or a max_pages of 0, fails before any acquire. Returns
// once the first page has a first message or has ended; a failure before
// that is retried once as client::search_stream() retries. Other errors (an
// acquire() failure included) are returned as is, a page's non-success
// result is reported by next(), and next()'s errors are never retried. The
// task does not refer to `c`; the paged_search may outlive it (its
// connection is then closed and next() fails with not_connected). Referrals
// are never chased: request.follow_referrals is ignored.
auto search_paged(client &c,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages = search_paged_default_max_pages,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<paged_search>>;

}// namespace jhetz::ldap
