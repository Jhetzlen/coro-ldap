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
// Threading (Capy/Corosio rules): at most one read and one write may be in
// flight at a time, and all operations must run on the executor of the
// io_context the transport was created on. Destroying a transport with an
// operation in flight is undefined: close() or cancel() and let it finish.
// Moving one is fine, the parts stay where they are.
#pragma once

#include <boost/capy/concept/stream.hpp>
#include <boost/capy/io/any_stream.hpp>

#include <cstdint>
#include <memory>
#include <memory_resource>
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
	transport &operator=(transport &&) noexcept;
	transport(const transport &) = delete;
	transport &operator=(const transport &) = delete;
	~transport();

	// Takes ownership of any capy::Stream (kind::custom). `name` is used in
	// error contexts ("read <name>: ..."). close() and cancel() do nothing on
	// a custom stream; the stream's own means of closing apply.
	template<boost::capy::Stream S>
	static transport wrap(S stream,
	  std::string_view name = "custom stream",
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	{
		transport t = make(kind::custom, name, mr);
		t.set_custom(boost::capy::any_stream(std::move(stream)));
		return t;
	}

	// The stream to read from and write to (TLS-decrypted for ldaps).
	// Precondition: kind() != kind::none.
	boost::capy::any_stream &stream() noexcept;

	kind type() const noexcept;
	bool is_tls() const noexcept;
	// False for an empty transport and after close().
	bool is_open() const noexcept;
	// Where it is connected, for error messages: "ldap://127.0.0.1:389",
	// "ldapi://%2Frun%2Fldapi", or the name given to wrap().
	const std::pmr::string &name() const noexcept;
	// The URL's host for transports from net::connect() (the socket path for
	// ldapi://); empty for wrap()ped streams. StartTLS verifies against it.
	const std::pmr::string &host() const noexcept;

	// Cancels pending operations; they complete with an error comparing equal
	// to boost::capy::cond::canceled. The connection stays open.
	void cancel() noexcept;
	// Closes the socket (no TLS close_notify is sent). Pending operations
	// complete with an error; later reads and writes fail. Idempotent.
	void close() noexcept;

	struct impl;// defined in src/net/transport_impl.hpp (used by connect)

  private:
	friend struct transport_access;

	static transport make(kind k, std::string_view name, std::pmr::memory_resource *mr);
	void destroy() noexcept;
	void set_custom(boost::capy::any_stream s);

	impl *impl_ = nullptr;// allocated from the resource it records
};

}// namespace jhetz::ldap::net
