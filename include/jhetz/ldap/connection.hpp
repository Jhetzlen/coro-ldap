// ldap::connection: an LDAP session over a net::transport with multiplexed
// operations. Contracts (errors, cancellation, memory, threading, handles):
// docs/API.md, "jhetz/ldap/connection.hpp".
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/cancel.hpp"
#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/connection_options.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/operations.hpp"
#include "jhetz/ldap/paged_search.hpp"
#include "jhetz/ldap/run.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/search_stream.hpp"
#include "jhetz/ldap/transaction.hpp"
#include "jhetz/ldap/url.hpp"

#include <boost/capy/ex/strand.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

class connection;

namespace detail {
	struct test_access;
	// For ldap::client: `hook` runs once on the executor when the connection
	// closes; replaces an earlier hook.
	void set_close_hook(connection &c, std::move_only_function<void() noexcept> hook) noexcept;
	// For ldap::client: open, and no unbind() under way.
	[[nodiscard]] auto accepts_requests(const connection &c) noexcept -> bool;

	// A counted reference to the connection's state; defined where Core is
	// complete (src/connection/core.hpp).
	template<class Core> class counted_ref
	{
	  public:
		counted_ref() noexcept = default;
		explicit counted_ref(Core *p) noexcept;
		counted_ref(const counted_ref &o) noexcept;
		counted_ref(counted_ref &&o) noexcept;
		auto operator=(const counted_ref &) -> counted_ref & = delete;
		auto operator=(counted_ref &&o) noexcept -> counted_ref &;
		~counted_ref();

		[[nodiscard]] auto get() const noexcept -> Core * { return p_; }
		auto operator->() const noexcept -> Core * { return p_; }
		auto operator*() const noexcept -> Core & { return *p_; }
		explicit operator bool() const noexcept { return p_ != nullptr; }

	  private:
		Core *p_ = nullptr;
	};
}// namespace detail

class connection
{
  public:
	using executor_type = boost::capy::strand<boost::corosio::io_context::executor_type>;

	// Not connected.
	connection() noexcept = default;
	// Runs LDAP over an open transport whose I/O runs on `ioc`.
	connection(boost::corosio::io_context &ioc,
	  net::transport t,
	  const connection_options &options = {},
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource());
	// Another handle on the same session.
	connection(const connection &other) noexcept;
	connection(connection &&other) noexcept;
	auto operator=(const connection &other) noexcept -> connection &;
	auto operator=(connection &&other) noexcept -> connection &;
	~connection();

	[[nodiscard]] auto is_open() const noexcept -> bool;
	// "ldap://127.0.0.1:389"; empty if never connected.
	[[nodiscard]] auto name() const noexcept -> std::string_view;
	[[nodiscard]] auto executor() const noexcept -> executor_type;
	// Requests waiting for a response, paged search releases included.
	[[nodiscard]] auto outstanding() const noexcept -> std::size_t;
	// True while TLS protects the open connection.
	[[nodiscard]] auto is_tls() const noexcept -> bool;
	// The SASL security layer (RFC 4422 section 3.7) in effect; none otherwise.
	[[nodiscard]] auto security_layer() const noexcept -> sasl_protection;
	// The server's certificate (DER); empty unless is_tls().
	[[nodiscard]] auto peer_certificate() const noexcept -> std::span<const std::byte>;
	// The TLS channel bindings (RFC 5056); empty unless is_tls().
	[[nodiscard]] auto channel_bindings() const noexcept -> ldap::channel_bindings;
	// Bind exchanges begun, whatever their outcome.
	[[nodiscard]] auto bind_count() const noexcept -> std::uint64_t;

	// Simple bind (RFC 4511 section 4.2, RFC 4513 section 5.1); a copy of
	// *this on success.
	auto simple_bind(dn name, std::string password) -> boost::capy::task<result<connection>>;

	// SASL bind (RFC 4513 section 5.2); a copy of *this on success.
	auto sasl_bind(sasl_mechanism &mechanism, dn name = {}) -> boost::capy::task<result<connection>>;

	// Runs a search to its end; entries are allocated from `mr`.
	auto search(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<search_result>>;

	// A stream of the search's entries, each decoded into `mr`.
	auto search_stream(search_params request, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  -> boost::capy::task<result<ldap::search_stream>>;

	auto add(add_params request) -> boost::capy::task<result<response>>;
	auto modify(modify_params request) -> boost::capy::task<result<response>>;
	auto del(del_params request) -> boost::capy::task<result<response>>;
	auto modify_dn(modify_dn_params request) -> boost::capy::task<result<response>>;
	auto compare(compare_params request) -> boost::capy::task<result<compare_result>>;
	auto extended(extended_params request) -> boost::capy::task<result<extended_result>>;

	// StartTLS (RFC 4511 section 4.14): upgrades a plain ldap:// connection;
	// a copy of *this on success.
	auto start_tls(net::tls_options options = {}, std::optional<std::chrono::milliseconds> timeout = std::nullopt)
	  -> boost::capy::task<result<connection>>;

	// Sends an UnbindRequest and closes (RFC 4511 section 4.3).
	auto unbind() -> boost::capy::task<result<void>>;

	// Closes at once, without an UnbindRequest.
	void close() noexcept;

	class core;

  private:
	friend class ldap::search_stream;
	friend struct detail::test_access;
	friend void detail::set_close_hook(connection &, std::move_only_function<void() noexcept>) noexcept;
	friend auto detail::accepts_requests(const connection &) noexcept -> bool;

	// A new handle on `self` once `body` succeeds, else its error.
	static auto returning_handle(detail::counted_ref<core> self, boost::capy::task<result<void>> body)
	  -> boost::capy::task<result<connection>>;

	// Shared state kept alive by operations, streams and transactions.
	detail::counted_ref<core> core_;
};

namespace detail {
	using core_ref = counted_ref<connection::core>;
}// namespace detail

// Opens a connection to `u` (net::connect); nothing is sent.
auto connect(boost::corosio::io_context &ioc,
  url u,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<connection>>;

// As above, from the URL text.
auto connect(boost::corosio::io_context &ioc,
  std::string_view text,
  connection_options options = {},
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> boost::capy::task<result<connection>>;

}// namespace jhetz::ldap
