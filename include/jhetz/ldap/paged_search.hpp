// ldap::paged_search: the entries of a paged search (Simple Paged Results,
// RFC 2696), across pages (connection::search_paged). Part of
// jhetz::ldap_net.
//
// Used like search_stream. Move-only; the same rules as search_stream
// apply.
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
// a late answer is still dropped (see connection::start_tls for one that comes during
// StartTLS). Nothing is released after the last page (empty cookie), after
// an error that ended the search (the server's result, a malformed paged
// results control, a closed connection), while the first page is running
// (no cookie yet: only the abandon), during a StartTLS exchange, or once
// the connection is closed. A page that timed out or was cancelled, or a
// next page that could not be sent, leaves the paged_search done with the
// last cookie kept, and its destruction releases the state. Like
// search_stream, it must be destroyed on the connection's executor.
#pragma once

#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/task.hpp>

#include <cstddef>
#include <memory_resource>
#include <optional>

namespace jhetz::ldap {

class connection;

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
	// search's, or a malformed paged results control: decode_error).
	auto next() -> boost::capy::task<result<std::optional<entry>>>;

	auto done() const noexcept -> bool;
	// Pages requested so far (1 after search_paged()).
	auto pages() const noexcept -> std::size_t;
	// References of every page so far, in order.
	auto references() const noexcept -> const string_list &;
	[[nodiscard]] auto reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::vector<url>;
	// Controls of the last SearchResultDone, once done().
	auto controls() const noexcept -> const std::pmr::vector<control> &;

	struct state;// defined in src/connection/paged_search.cpp

  private:
	friend class connection;

	explicit paged_search(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
};

}// namespace jhetz::ldap
