#include "jhetz/ldap/net/message_io.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/write.hpp>

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap::net {
namespace {

	error with_context(error e, const std::string &prefix)
	{
		e.context = e.context.empty() ? prefix : prefix + ": " + e.context;
		return e;
	}

	std::string hex_byte(std::byte b)
	{
		constexpr char digits[] = "0123456789abcdef";
		const auto v = std::to_integer<unsigned>(b);
		return { '0', 'x', digits[v >> 4], digits[v & 0xFu] };
	}

}// namespace

std::span<std::byte> read_buffer::prepare(std::size_t n)
{
	const std::size_t used = end_ - begin_;
	if (buf_.size() - end_ < n) {
		if (buf_.size() - used >= n) {
			// Enough room once the consumed prefix is dropped.
			std::memmove(buf_.data(), buf_.data() + begin_, used);
		} else {
			// What is needed, at least min_read: read_message asks for the
			// rest of the current PDU, so the buffer never exceeds one PDU
			// (or min_read) and grows at most once per PDU.
			std::pmr::vector<std::byte> bigger(std::max(used + n, min_read), buf_.get_allocator());
			if (used != 0) std::memcpy(bigger.data(), buf_.data() + begin_, used);
			buf_.swap(bigger);
		}
		begin_ = 0;
		end_ = used;
	}
	return std::span(buf_).subspan(end_);
}

void read_buffer::consume(std::size_t n) noexcept
{
	begin_ += std::min(n, end_ - begin_);
	if (begin_ != end_) return;
	begin_ = end_ = 0;
	if (buf_.size() > shrink_threshold) { std::pmr::vector<std::byte>(buf_.get_allocator()).swap(buf_); }
}

capy::task<result<message>> read_message(transport &t, read_buffer &buf, read_options options)
{
	std::string where = "read ";
	where += t.name();
	while (true) {
		const auto data = buf.data();
		std::size_t want = read_buffer::min_read;
		std::optional<std::size_t> declared;
		if (!data.empty()) {
			// LDAPMessage is a SEQUENCE: reject anything else from its first
			// octet instead of reading a body of up to max_message_size.
			if (data[0] != std::byte{ 0x30 })
				co_return fail(client_errc::decode_error,
				  where + ": PDU starts with " + hex_byte(data[0]) + ", not a SEQUENCE (0x30)");
			auto size = ber::declared_message_size(data, options.max_message_size);
			if (!size) co_return std::unexpected(with_context(std::move(size.error()), where));
			declared = *size;
			if (declared && data.size() >= *declared) {
				// TODO(4b): decode_options gets a memory resource; then the
				// connection layer decodes each response into an arena.
				auto m = decode(data.first(*declared), options.decode);
				buf.consume(*declared);
				if (!m) co_return std::unexpected(with_context(std::move(m.error()), where));
				co_return m;
			}
			// Room for exactly the rest of this PDU (or, while its header is
			// incomplete, for min_read bytes in all): asking for more would
			// reallocate on every short read near the end of a PDU. Free
			// space beyond it is still used, for the next PDUs.
			want = declared ? *declared - data.size() : read_buffer::min_read - data.size();
		}

		const auto space = buf.prepare(want);
		auto [ec, n] = co_await t.stream().read_some(capy::mutable_buffer(space.data(), space.size()));
		buf.commit(n);
		// A read into a non-empty buffer transfers at least one byte unless it
		// fails; treat a stream that breaks that rule as closed, not as a loop.
		if (!ec && n == 0) ec = capy::error::eof;
		if (!ec) continue;
		if (n != 0 && ec == capy::cond::eof) continue;// use the bytes; eof again on the next read

		std::string context = where;
		if (ec == capy::cond::eof) {
			const std::size_t have = buf.size();
			if (have == 0)
				context += ": connection closed";
			else if (declared)
				context += ": connection closed after " + std::to_string(have) + " of " + std::to_string(*declared)
						   + " bytes of a PDU";
			else
				context += ": connection closed inside a PDU header";
		}
		co_return fail(ec, std::move(context));
	}
}

capy::task<result<void>> write_bytes(transport &t, std::span<const std::byte> bytes)
{
	auto [ec, n] = co_await capy::write(t.stream(), capy::const_buffer(bytes.data(), bytes.size()));
	if (ec) {
		std::string context = "write ";
		context += t.name();
		if (n != 0) context += " (" + std::to_string(n) + " of " + std::to_string(bytes.size()) + " bytes written)";
		co_return fail(ec, std::move(context));
	}
	co_return result<void>{};
}

capy::task<result<void>> write_message(transport &t, const message &m)
{
	auto bytes = encode(m);
	if (!bytes) co_return std::unexpected(with_context(std::move(bytes.error()), "write " + std::string(t.name())));
	co_return co_await write_bytes(t, *bytes);
}

}// namespace jhetz::ldap::net
