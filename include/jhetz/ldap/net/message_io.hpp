// Reading and writing whole LDAPMessages on a transport.
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
	// Largest accepted PDU; a larger declared length fails before the body is
	// read.
	std::size_t max_message_size = ber::default_max_message_size;
	// A client keeps origin::server.
	decode_options decode{ .from = origin::server };
};

// Bytes received but not consumed yet, kept across read_message() calls;
// grows to one PDU at most.
class read_buffer
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	static constexpr std::size_t min_read = std::size_t{ 16 } * 1024;
	static constexpr std::size_t shrink_threshold = std::size_t{ 1024 } * 1024;

	read_buffer() = default;
	explicit read_buffer(const allocator_type &alloc) : buf_(alloc) {}

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return buf_.get_allocator(); }

	[[nodiscard]] auto data() const noexcept -> std::span<const std::byte>
	{
		return std::span(buf_).subspan(begin_, end_ - begin_);
	}
	[[nodiscard]] auto size() const noexcept -> std::size_t { return end_ - begin_; }
	[[nodiscard]] auto empty() const noexcept -> bool { return begin_ == end_; }
	[[nodiscard]] auto capacity() const noexcept -> std::size_t { return buf_.size(); }
	void clear() noexcept { begin_ = end_ = 0; }

	// All free space after the data, at least `n` bytes.
	auto prepare(std::size_t n) -> std::span<std::byte>;
	void commit(std::size_t n) noexcept { end_ += n; }
	void consume(std::size_t n) noexcept;

  private:
	std::pmr::vector<std::byte> buf_{};// size() is the capacity; data in [begin_, end_)
	std::size_t begin_ = 0;
	std::size_t end_ = 0;
};

// The next complete LDAPMessage from `t`; bytes after it stay in `buf`.
// After any error the connection must be dropped.
auto read_message(transport &t, read_buffer &buf, read_options options = {}) -> boost::capy::task<result<message>>;

// Reads until a complete PDU is at the front of `buf` and returns its size,
// consuming and decoding nothing.
auto read_frame(transport &t, read_buffer &buf, std::size_t max_message_size) -> boost::capy::task<result<std::size_t>>;

// Encodes `m` (into a buffer on `mr`, or into `w`) and writes all of it.
auto write_message(transport &t, const message &m, std::pmr::memory_resource *mr = std::pmr::get_default_resource())
  -> boost::capy::task<result<void>>;
auto write_message(transport &t, const message &m, ber::writer &w) -> boost::capy::task<result<void>>;

auto write_bytes(transport &t, std::span<const std::byte> bytes) -> boost::capy::task<result<void>>;

}// namespace jhetz::ldap::net
