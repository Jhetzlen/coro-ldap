#include "jhetz/ldap/net/message_io.hpp"

#include "../format_util.hpp"
#include "sasl_layer.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/write.hpp>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap::net {
namespace {

	auto with_context(error e, std::string_view prefix) -> error
	{
		if (e.context.empty()) {
			e.context.assign(prefix);
		} else {
			e.context.insert(0, ": ");
			e.context.insert(0, prefix);
		}
		return e;
	}

	auto hex_byte(std::byte b) -> std::string
	{
		constexpr std::string_view digits = "0123456789abcdef";
		const auto v = std::to_integer<unsigned>(b);
		return { '0', 'x', digits[v >> 4], digits[v & ldap::detail::nibble_mask] };
	}

}// namespace

auto read_buffer::prepare(std::size_t n) -> std::span<std::byte>
{
	const std::size_t used = end_ - begin_;
	if (buf_.size() - end_ < n) {
		if (buf_.size() - used >= n) {
			// Enough room once the consumed prefix is dropped.
			std::memmove(buf_.data(), buf_.data() + begin_, used);
		} else {
			// Grows to what is needed, at least min_read.
			std::pmr::vector<std::byte> bigger(std::max(used + n, min_read), buf_.get_allocator());
			if (used != 0) {
				std::memcpy(bigger.data(), buf_.data() + begin_, used);
			}
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
	if (begin_ != end_) {
		return;
	}
	begin_ = end_ = 0;
	if (buf_.size() > shrink_threshold) {
		std::pmr::vector<std::byte>(buf_.get_allocator()).swap(buf_);
	}
}

auto read_frame(transport &t, read_buffer &buf, std::size_t max_message_size) -> capy::task<result<std::size_t>>
{
	std::string where = "read ";
	where += t.name();
	while (true) {
		const auto data = buf.data();
		std::size_t want = read_buffer::min_read;
		std::optional<std::size_t> declared;
		if (!data.empty()) {
			// LDAPMessage is a SEQUENCE: reject anything else from its first octet.
			if (data[0] != ber::identifier_octet(ber::tags::sequence)) {
				co_return fail(client_errc::decode_error,
				  where + ": PDU starts with " + hex_byte(data[0]) + ", not a SEQUENCE (0x30)");
			}
			auto size = ber::declared_message_size(data, max_message_size);
			if (!size) {
				co_return std::unexpected(with_context(std::move(size.error()), where));
			}
			declared = *size;
			if (declared && data.size() >= *declared) {
				co_return *declared;
			}
			// Room for exactly the rest of this PDU (or min_read while its header is
			// incomplete).
			want = declared ? *declared - data.size() : read_buffer::min_read - data.size();
		}

		const auto space = buf.prepare(want);
		auto [ec, n] = co_await t.stream().read_some(capy::mutable_buffer(space.data(), space.size()));
		buf.commit(n);
		// A read into a non-empty buffer transfers at least one byte unless it
		// fails; treat a stream that breaks that rule as closed, not as a loop.
		if (!ec && n == 0) {
			ec = capy::error::eof;
		}
		if (!ec) {
			continue;
		}
		// eof, or stream_truncated (no TLS close_notify): a close between PDUs, a
		// truncation inside one.
		const bool closed = ec == capy::cond::eof || ec == capy::cond::stream_truncated;
		if (n != 0 && closed) {
			continue;// use the bytes; the close shows again on the next read
		}

		std::string context = where;
		if (const auto layer = detail::security_layer_read_error(t); !layer.empty()) {
			context += ": ";
			context += layer;
		} else if (closed) {
			const std::size_t have = buf.size();
			if (have == 0) {
				context +=
				  ec == capy::cond::eof ? ": connection closed" : ": connection closed (without TLS close_notify)";
			} else if (declared) {
				ldap::detail::format_to(context, ": connection closed after {} of {} bytes of a PDU", have, *declared);
			} else {
				context += ": connection closed inside a PDU header";
			}
		}
		co_return fail(ec, std::move(context));
	}
}

auto read_message(transport &t, read_buffer &buf, read_options options) -> capy::task<result<message>>
{
	auto size = co_await read_frame(t, buf, options.max_message_size);
	if (!size) {
		co_return std::unexpected(std::move(size.error()));
	}
	// Allocated from options.decode.memory (e.g. a per-response arena of the
	// connection layer).
	auto m = decode(buf.data().first(*size), options.decode);
	buf.consume(*size);
	if (!m) {
		co_return std::unexpected(with_context(std::move(m.error()), ldap::detail::format("read {}", t.name())));
	}
	co_return m;
}

auto write_bytes(transport &t, std::span<const std::byte> bytes) -> capy::task<result<void>>
{
	auto [ec, n] = co_await capy::write(t.stream(), capy::const_buffer(bytes.data(), bytes.size()));
	if (ec) {
		std::string context = "write ";
		context += t.name();
		if (n != 0) {
			ldap::detail::format_to(context, " ({} of {} bytes written)", n, bytes.size());
		}
		if (const auto layer = detail::security_layer_write_error(t); !layer.empty()) {
			context += ": ";
			context += layer;
		}
		co_return fail(ec, std::move(context));
	}
	co_return result<void>{};
}

auto write_message(transport &t, const message &m, std::pmr::memory_resource *mr) -> capy::task<result<void>>
{
	auto bytes = encode(m, mr);
	if (!bytes) {
		co_return std::unexpected(with_context(std::move(bytes.error()), ldap::detail::format("write {}", t.name())));
	}
	co_return co_await write_bytes(t, *bytes);
}

auto write_message(transport &t, const message &m, ber::writer &w) -> capy::task<result<void>>
{
	w.clear();
	if (auto e = encode(w, m); !e) {
		co_return std::unexpected(with_context(std::move(e.error()), ldap::detail::format("write {}", t.name())));
	}
	co_return co_await write_bytes(t, w.bytes());
}

}// namespace jhetz::ldap::net
