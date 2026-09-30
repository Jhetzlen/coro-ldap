// Reading and writing whole LDAPMessages on a transport: the bridge between
// the byte stream (net::transport) and the message codec (message.hpp) that
// the connection layer (step 5) builds on.
//
// Framing: ber::declared_message_size tells from the header alone how long
// the next PDU is. A PDU that does not start with a SEQUENCE tag, or declares
// more than read_options::max_message_size bytes, is rejected as soon as its
// first (resp. length) octets arrive, before any of its body is read. Each
// read_some gets all the free space of the buffer, which is made to hold at
// least the rest of the current PDU once its header is in (the buffer grows
// once for it), and min_read bytes in all before that. Several PDUs arriving
// in one read are all kept for the following calls.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/net/transport.hpp"

#include <boost/capy/task.hpp>

#include <cstddef>
#include <memory_resource>
#include <span>
#include <vector>

namespace jhetz::ldap::net {

struct read_options
{
	// Largest accepted PDU (header + body). A larger declared length fails
	// with client_errc::message_too_large before the body is read. The
	// default is 16 MiB; see DESIGN.md "Open questions" for why a lower
	// value or per-entry limits may be preferable.
	std::size_t max_message_size = ber::default_max_message_size;
	// Passed to decode(). A client must keep origin::server: a server may
	// not send request operations (for example search filters).
	// decode.memory is the resource the message is decoded into (default:
	// the default resource); with a per-response arena the message must not
	// outlive the arena (see message.hpp).
	decode_options decode{ .from = origin::server };
};

// Bytes received but not consumed yet. One per transport, kept across
// read_message() calls: a read may deliver the start of the next PDU (or
// several PDUs), which stays here for the next call.
//
// Memory is bounded: the buffer grows only to hold one PDU whose header has
// arrived (at most max_message_size), or min_read bytes, whichever is larger,
// and gives memory above shrink_threshold back once it is empty. The bytes
// live in a std::pmr::vector on the resource given to the constructor (default:
// the default resource), so buffers can be pooled.
class read_buffer
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	static constexpr std::size_t min_read = std::size_t{ 16 } * 1024;
	static constexpr std::size_t shrink_threshold = std::size_t{ 1024 } * 1024;

	read_buffer() = default;
	explicit read_buffer(const allocator_type &alloc) : buf_(alloc) {}

	allocator_type get_allocator() const noexcept { return buf_.get_allocator(); }

	// Unconsumed bytes (e.g. to check that nothing follows a StartTLS
	// response before the TLS handshake).
	std::span<const std::byte> data() const noexcept { return std::span(buf_).subspan(begin_, end_ - begin_); }
	std::size_t size() const noexcept { return end_ - begin_; }
	bool empty() const noexcept { return begin_ == end_; }
	std::size_t capacity() const noexcept { return buf_.size(); }
	void clear() noexcept { begin_ = end_ = 0; }

	// All free space after the data, at least `n` bytes (compacting, or
	// growing to max(size() + n, min_read)).
	std::span<std::byte> prepare(std::size_t n);
	// Marks `n` bytes of the prepare()d space as data.
	void commit(std::size_t n) noexcept { end_ += n; }
	// Drops `n` bytes from the front of the data.
	void consume(std::size_t n) noexcept;

  private:
	std::pmr::vector<std::byte> buf_{};// size() is the capacity; data in [begin_, end_)
	std::size_t begin_ = 0;
	std::size_t end_ = 0;
};

// Returns the next complete LDAPMessage from `t`, reading as needed and
// leaving any bytes after it in `buf`.
//
// Errors (context "read <transport name>: ..."). After any error the caller
// must drop the connection:
// - the transport's error_code for I/O failures. The peer closing the
//   connection gives boost::capy::error::eof, or cond::stream_truncated for
//   a TLS peer that skips close_notify; between PDUs both read "connection
//   closed" (the latter "... (without TLS close_notify)"), inside a PDU
//   "connection closed after N of M bytes of a PDU" or "... inside a PDU
//   header";
// - message_too_large, decode_error (not a SEQUENCE, bad length) from the
//   header, before the body is read. Nothing is consumed, so every later
//   call fails the same way: the stream cannot be re-framed;
// - decode() errors for a complete PDU. Only here is the bad PDU consumed,
//   so a later call would start at the next PDU; the peer is still broken
//   or hostile, so drop the connection anyway;
// - canceled / timeout if the awaiting coroutine is stopped.
// `t` and `buf` must outlive the task (normal when it is co_awaited at once).
boost::capy::task<result<message>> read_message(transport &t, read_buffer &buf, read_options options = {});

// Encodes `m` and writes all of it. Encoding errors are returned before
// anything is written. Only one write may be in flight on a transport. `m`
// must outlive the task.
// The first overload encodes into a buffer allocated from `mr` for this
// call; the second clears `w` and encodes into it, so one writer (on any
// resource) can be reused for every message of a connection, like
// read_buffer. `w` must outlive the task and not be used until it is done.
boost::capy::task<result<void>>
  write_message(transport &t, const message &m, std::pmr::memory_resource *mr = std::pmr::get_default_resource());
boost::capy::task<result<void>> write_message(transport &t, const message &m, ber::writer &w);

// Writes already encoded bytes (e.g. one or more PDUs from encode()).
boost::capy::task<result<void>> write_bytes(transport &t, std::span<const std::byte> bytes);

}// namespace jhetz::ldap::net
