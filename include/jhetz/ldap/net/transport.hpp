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
// type-erased view, in one block allocated from the memory resource given to
// connect() or wrap() (default: the default resource), so their addresses stay
// stable when the transport itself is moved (the TLS layer and the view point
// into it). name() lives on the same resource. Corosio's and Capy's own
// internals (socket state, the any_stream's cached awaitables, the OpenSSL
// session) still allocate with operator new.
//
// StartTLS (step 7, net::start_tls in connect.hpp): the plain tcp_socket is
// a separate member for this. start_tls() requires type() ==
// kind::tcp, !is_tls(), no operation in flight, and an empty read_buffer
// (bytes that arrived after the StartTLS response were sent before the TLS
// handshake and must not be trusted; the plaintext injection bug class of
// CVE-2011-0411). It then constructs an openssl_stream in *reference* mode
// over the owned socket (`openssl_stream(&socket, ctx)`), runs the client
// handshake with the same verification rules as ldaps:// (net::tls_options),
// and re-points stream() at the TLS layer. The socket is never moved, so
// nothing referring to it is invalidated. ldaps:// already uses exactly this
// layering (reference-mode TLS over the owned socket), so StartTLS reuses
// the ldaps:// handshake code: detail::make_tls_setup() and
// detail::tls_handshake() in src/net/tls.hpp.
//
// Ending a connection: close() is immediate (the socket goes away; for TLS no
// close_notify alert is sent, so the peer sees a truncated stream).
// shutdown() is the graceful variant: for TLS it sends close_notify and
// waits, within a bound, for the peer's before closing (RFC 5246 section
// 7.2.1; RFC 4511 section 4.13 for StartTLS). connection::unbind() uses it.
//
// Threading (Capy/Corosio rules): at most one read and one write may be in
// flight at a time, and all operations must run on the executor of the
// io_context the transport was created on. Destroying a transport with an
// operation in flight is undefined: close() or cancel() and let it finish.
// Moving one is fine, the parts stay where they are.
#pragma once

#include "jhetz/ldap/error.hpp"

#include <boost/capy/concept/stream.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/task.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
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

	// The stream to read from and write to (TLS-decrypted for ldaps).
	// Precondition: kind() != kind::none.
	auto stream() noexcept -> boost::capy::any_stream &;

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

	struct impl;// defined in src/net/transport_impl.hpp (used by connect)

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

	impl *impl_ = nullptr;// allocated from the resource it records
};

}// namespace jhetz::ldap::net
