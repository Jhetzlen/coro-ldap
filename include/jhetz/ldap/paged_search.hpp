// ldap::search_paged and ldap::paged_search: the entries of a Simple Paged
// Results search (RFC 2696) across pages, used like a search_stream;
// destroyed early, it releases the server's paging state (docs/API.md).
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

	// The next entry, nullopt after the last page, or an error; drops entry
	// controls and IntermediateResponses.
	auto next() -> boost::capy::task<result<std::optional<entry>>>;

	[[nodiscard]] auto done() const noexcept -> bool;
	// 1 after search_paged().
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

inline constexpr std::size_t search_paged_default_max_pages = 10000;

// A search of `c` in pages of `page_size` entries, at most `max_pages`
// pages; `request.timeout` bounds each page.
auto search_paged(connection &c,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages = search_paged_default_max_pages,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<paged_search>>;

// As above, on one shared lease of `c`'s pool, held until destroyed; the
// first page is retried as client::search_stream() is.
auto search_paged(client &c,
  search_params request,
  std::int32_t page_size,
  std::size_t max_pages = search_paged_default_max_pages,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<paged_search>>;

}// namespace jhetz::ldap
