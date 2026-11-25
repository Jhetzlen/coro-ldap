// The byte stream under an LDAP connection: TCP, TLS over TCP, a Unix
// socket or any capy::Stream, read and written through a capy::any_stream
// (docs/API.md, DESIGN.md sections 7 and 8).
#pragma once

#include "jhetz/ldap/channel_binding.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <boost/capy/concept/stream.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/task.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::net {

class transport
{
  public:
	enum class kind : std::uint8_t {
		none,// default-constructed or moved-from
		tcp,
		local,
		custom,
	};

	transport() noexcept;
	transport(transport &&) noexcept;
	auto operator=(transport &&) noexcept -> transport &;
	transport(const transport &) = delete;
	auto operator=(const transport &) -> transport & = delete;
	~transport();

	// Takes ownership of any capy::Stream; `name` is used in error contexts.
	template<boost::capy::Stream S>
	// NOLINTNEXTLINE(performance-unnecessary-value-param): false positive, `stream` is moved into the block below
	[[nodiscard]] static auto wrap(S stream,
	  std::string_view name = "custom stream",
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> transport
	{
		transport t = make(kind::custom, name, mr);
		std::pmr::polymorphic_allocator<S> alloc(mr);
		custom_ops ops{};
		ops.destroy = [](void *s, std::pmr::memory_resource *r) noexcept {
			std::pmr::polymorphic_allocator<S>(r).delete_object(static_cast<S *>(s));
		};
		if constexpr (requires(S &s) { s.close(); }) {
			ops.close = [](void *s) noexcept { static_cast<S *>(s)->close(); };
		}
		if constexpr (requires(S &s) { s.cancel(); }) {
			ops.cancel = [](void *s) noexcept { static_cast<S *>(s)->cancel(); };
		}
		S *p = alloc.template new_object<S>(std::move(stream));
		t.set_custom(p, ops);// owns p from here
		t.stream() = boost::capy::any_stream(p);
		return t;
	}

	// Precondition: kind() != kind::none.
	auto stream() noexcept -> boost::capy::any_stream &;
	// The SASL security layer under the PDUs; none without one.
	[[nodiscard]] auto security_layer() const noexcept -> sasl_protection;

	[[nodiscard]] auto type() const noexcept -> kind;
	[[nodiscard]] auto is_tls() const noexcept -> bool;
	[[nodiscard]] auto is_open() const noexcept -> bool;
	// "ldap://127.0.0.1:389", "ldapi://%2Frun%2Fldapi", or wrap()'s name.
	[[nodiscard]] auto name() const noexcept -> const std::pmr::string &;
	// The URL's host (the socket path for ldapi://); empty for wrap()ped streams.
	[[nodiscard]] auto host() const noexcept -> const std::pmr::string &;

	// DER; empty unless is_tls().
	[[nodiscard]] auto peer_certificate() const noexcept -> std::span<const std::byte>;
	// Empty unless is_tls().
	[[nodiscard]] auto channel_bindings() const noexcept -> ldap::channel_bindings;

	// Cancels pending operations; the connection stays open.
	void cancel() noexcept;
	// Closes at once (no TLS close_notify). Idempotent.
	void close() noexcept;

	// Graceful close: TLS close_notify, then the peer's within `timeout`.
	auto shutdown(std::optional<std::chrono::milliseconds> timeout) -> boost::capy::task<result<void>>;

	struct layers;// defined in src/net/transport_layers.hpp

  private:
	friend struct transport_access;

	static auto make(kind k, std::string_view name, std::pmr::memory_resource *mr) -> transport;
	void destroy() noexcept;
	struct custom_ops
	{
		void (*destroy)(void *, std::pmr::memory_resource *) noexcept = nullptr;
		void (*close)(void *) noexcept = nullptr;
		void (*cancel)(void *) noexcept = nullptr;
	};
	void set_custom(void *stream, custom_ops ops) noexcept;

	// The socket, TLS stream and stream views, at a stable address.
	layers *layers_ = nullptr;
};

}// namespace jhetz::ldap::net
