// ldap::search_stream: the entries (or, with next_item(), every message) of
// one search, read one at a time (docs/API.md, connection.hpp section).
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

// A SearchResultEntry (RFC 4511 section 4.5.2) with its message's controls.
struct search_entry : entry
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<control> controls{};

	search_entry() = default;
	explicit search_entry(const allocator_type &alloc) : entry(alloc), controls(alloc) {}
	// Takes the strings when on `alloc`'s resource, else copies them onto it.
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

// A SearchResultReference (RFC 4511 section 4.5.3) with its message's
// controls.
struct search_reference : search_result_reference
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::vector<control> controls{};

	search_reference() = default;
	explicit search_reference(const allocator_type &alloc) : search_result_reference(alloc), controls(alloc) {}
	// Takes the strings when on `alloc`'s resource, else copies them onto it.
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

	// The next entry, nullopt at the end, or an error; then the same again.
	auto next() -> boost::capy::task<result<std::optional<entry>>>;

	// One search message with its controls.
	using item = std::variant<search_entry, search_reference, intermediate>;
	// As next(), every message before the SearchResultDone, in order.
	auto next_item() -> boost::capy::task<result<std::optional<item>>>;

	[[nodiscard]] auto done() const noexcept -> bool;
	// URIs of the references read so far, as sent; not chased.
	[[nodiscard]] auto references() const noexcept -> const string_list &;
	// references() parsed as LDAP URLs; URIs that do not parse are left out.
	[[nodiscard]] auto reference_urls(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::vector<url>;
	// Controls of the SearchResultDone, once done().
	[[nodiscard]] auto controls() const noexcept -> const std::pmr::vector<control> &;

	struct state;// defined in src/connection/search.hpp

  private:
	friend class connection;

	explicit search_stream(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;
};

}// namespace jhetz::ldap
