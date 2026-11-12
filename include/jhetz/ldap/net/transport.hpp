// Byte transport under an LDAP connection (DESIGN.md sections 7 and 8).
//
// A `net::transport` is the one stream the connection layer reads and writes,
// whatever is below it:
//
//   kind::tcp     ldap://   a Corosio tcp_socket
//   kind::tcp     ldaps://  an openssl_stream over that tcp_socket (is_tls())
//   kind::local   ldapi://  a Corosio local_stream_socket (Unix domain socket)
//   kind::custom            any capy::Stream, e.g. capy::test::stream in tests
//
// Reads and writes go through stream(), a capy::any_stream (Capy's type-erased
// ReadStream + WriteStream), so code above never depends on the concrete
// stream type. Build one with net::connect() (net/connect.hpp) or, for tests
// and custom streams, transport::wrap().
//
// Ownership: the transport owns the socket, the TLS layer (if any) and the
// type-erased view in one block allocated from the memory resource given to
// connect() or wrap() (default: the default resource), so their addresses
// stay stable when the transport moves. name() lives on the same resource.
// Corosio's and Capy's internals still allocate with operator new.
//
// StartTLS (net::start_tls in connect.hpp) requires type() == kind::tcp,
// !is_tls(), no operation in flight and an empty read_buffer (bytes received
// before the handshake are untrusted, CVE-2011-0411). It builds a
// reference-mode openssl_stream over the owned socket, as ldaps:// does, runs
// the handshake with net::tls_options, and re-points stream() at it.
//
// Ending a connection: close() is immediate (for TLS, no close_notify).
// shutdown() sends close_notify and waits, within a bound, for the peer's
// before closing (RFC 5246 section 7.2.1); connection::unbind() uses it.
//
// Threading: at most one read and one write in flight, all on the executor
// of the io_context the transport was created on. Destroying a transport
// with an operation in flight is undefined: close() or cancel() and let it
// finish. Moving one with an operation in flight is undefined too, like
// destroying it; moving an idle one is fine.
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
#include <memory>
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
		none,// default-constructed or moved-from: no stream
		tcp,
		local,
		custom,
	};

	// An empty transport (kind::none, is_open() == false).
	transport() noexcept;
	transport(transport &&) noexcept;
	auto operator=(transport &&) noexcept -> transport &;
	transport(const transport &) = delete;
	auto operator=(const transport &) -> transport & = delete;
	~transport();

	// Takes ownership of any capy::Stream (kind::custom), stored with the
	// transport's block on `mr`. `name` is used in error contexts ("read
	// <name>: ..."). close() and cancel() call the stream's own close() and
	// cancel() if it has them (a tcp_socket, capy::test::stream's close());
	// a stream without close() cannot be closed by the transport, but
	// is_open() turns false after close() either way.
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

	// The stream to read from and write to (TLS-decrypted for ldaps; the
	// SASL security layer's plaintext once one is installed, see
	// security_layer()). Precondition: kind() != kind::none.
	auto stream() noexcept -> boost::capy::any_stream &;
	// The SASL security layer (RFC 4422 section 3.7) under the PDUs, which
	// connection::sasl_bind installs when a mechanism negotiated one: from
	// then on stream() wraps what is written and unwraps what is read, in
	// buffers framed by a four-octet length. none without one.
	[[nodiscard]] auto security_layer() const noexcept -> sasl_protection;

	[[nodiscard]] auto type() const noexcept -> kind;
	[[nodiscard]] auto is_tls() const noexcept -> bool;
	// False for an empty transport and after close().
	[[nodiscard]] auto is_open() const noexcept -> bool;
	// Where it is connected, for error messages: "ldap://127.0.0.1:389",
	// "ldapi://%2Frun%2Fldapi", or the name given to wrap().
	[[nodiscard]] auto name() const noexcept -> const std::pmr::string &;
	// The URL's host for transports from net::connect() (the socket path for
	// ldapi://); empty for wrap()ped streams. StartTLS verifies against it.
	[[nodiscard]] auto host() const noexcept -> const std::pmr::string &;

	// The server's certificate (DER), as received in the TLS handshake;
	// empty when !is_tls(). A view into the transport's block: valid while
	// the transport (or the one it was moved to) lives, until a StartTLS
	// handshake is redone.
	[[nodiscard]] auto peer_certificate() const noexcept -> std::span<const std::byte>;
	// The TLS channel bindings of the connection (channel_binding.hpp),
	// computed once the handshake succeeded; empty when !is_tls(). Views
	// valid as long as peer_certificate()'s. tls-exporter stays here after
	// an authentication used it; connection::sasl_bind withholds it then
	// (RFC 9266 section 4.1).
	[[nodiscard]] auto channel_bindings() const noexcept -> ldap::channel_bindings;

	// Cancels pending operations; they complete with an error comparing equal
	// to boost::capy::cond::canceled. The connection stays open.
	void cancel() noexcept;
	// Closes the socket (no TLS close_notify is sent). Pending operations
	// complete with an error; later reads and writes fail. Idempotent.
	void close() noexcept;

	// Graceful close. TLS: sends close_notify and waits for the peer's, at
	// most `timeout` (nullopt: no limit), then close(). The result is the
	// TLS shutdown's: success when the peer answered, an error comparing
	// equal to boost::capy::cond::timeout when it did not in time, or the
	// transport error (capy::error::stream_truncated when the peer closed
	// without close_notify). Plain TCP, ldapi and custom streams: close()
	// and success. A stop request ends the wait (capy::cond::canceled). The
	// transport is closed in every case. No write may be in flight; a read may (Corosio's rule).
	auto shutdown(std::optional<std::chrono::milliseconds> timeout) -> boost::capy::task<result<void>>;

	struct layers;// defined in src/net/transport_layers.hpp (used by connect)

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

	// One block whose socket, reference-mode TLS stream and stream views
	// point at each other, so its address must not change when the
	// transport moves; allocated from the resource it records.
	layers *layers_ = nullptr;
};

}// namespace jhetz::ldap::net
