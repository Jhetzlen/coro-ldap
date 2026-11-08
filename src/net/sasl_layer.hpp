// Internal: the SASL security layer stream (RFC 4422 section 3.7) that
// connection::sasl_bind puts between the LDAP PDUs and the transport's
// stream once a mechanism negotiated integrity or confidentiality
// (sasl.hpp, sasl_security_layer). transport::stream() then returns it, so
// read_frame, write_bytes and everything above them are unchanged.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/net/transport.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/buffers/buffer_copy.hpp>
#include <boost/capy/concept/const_buffer_sequence.hpp>
#include <boost/capy/concept/mutable_buffer_sequence.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/results.hpp>
#include <boost/capy/task.hpp>

#include <algorithm>
#include <cstddef>
#include <memory>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace jhetz::ldap::net::detail {

// The length field before each protected buffer: four octets, network
// byte order (RFC 4422 section 3.7).
inline constexpr std::size_t sasl_length_size = 4;

// A capy::Stream over `inner` (the transport's stream, above TLS if any, RFC
// 4513 section 5.2.1.6). write_some() protects at most max_wrap_input()
// octets into one buffer, writes it whole after its length, and reports the
// plaintext octets taken (none if the buffer was not written whole); a
// max_wrap_input() of 0 fails with client_errc::encode_error. read_some()
// delivers plaintext, unwrapping whole buffers; a length above
// max_received() fails with client_errc::message_too_large before the buffer
// is read. Unwrapped bytes survive a cancelled read. One read and one write
// may be in flight at once.
//
// Errors are error codes; the context of the last read and write failure
// that came from the layer is kept in last_read_error() and
// last_write_error() (empty when the inner stream's error says it all).
class sasl_layer_stream
{
  public:
	sasl_layer_stream(boost::capy::any_stream &inner,
	  std::unique_ptr<sasl_security_layer> layer,
	  std::pmr::memory_resource *mr);

	// Bytes read from the inner stream before the layer took effect (those
	// after the final BindResponse): the start of the protected stream.
	void feed(std::span<const std::byte> bytes);

	template<boost::capy::MutableBufferSequence MB>
	auto read_some(MB buffers) -> boost::capy::task<boost::capy::results<std::size_t>>
	{
		read_error_.clear();
		if (boost::capy::buffer_size(buffers) == 0) {
			co_return { std::error_code{}, 0 };
		}
		auto [ec] = co_await fill();
		if (ec) {
			co_return { ec, 0 };
		}
		const auto n = boost::capy::buffer_copy(
		  buffers, boost::capy::const_buffer(plain_.data() + plain_pos_, plain_.size() - plain_pos_));
		plain_pos_ += n;
		co_return { std::error_code{}, n };
	}

	template<boost::capy::ConstBufferSequence CB>
	auto write_some(CB buffers) -> boost::capy::task<boost::capy::results<std::size_t>>
	{
		write_error_.clear();
		const std::size_t size = boost::capy::buffer_size(buffers);
		const std::size_t n = std::min(size, layer_->max_wrap_input());
		if (n == 0) {
			if (size != 0) {
				co_return { refuse_empty_wrap(), 0 };
			}
			co_return { std::error_code{}, 0 };
		}
		staged_.resize(n);
		boost::capy::buffer_copy(boost::capy::mutable_buffer(staged_.data(), n), buffers, n);
		if (auto ec = protect(); ec) {
			co_return { ec, 0 };
		}
		auto [ec] = co_await flush();
		co_return { ec, ec ? 0 : n };
	}

	[[nodiscard]] auto protection() const noexcept -> sasl_protection { return layer_->protection(); }
	[[nodiscard]] auto last_read_error() const noexcept -> const std::string & { return read_error_; }
	[[nodiscard]] auto last_write_error() const noexcept -> const std::string & { return write_error_; }

  private:
	// Until plaintext is waiting: reads and unwraps buffers.
	auto fill() -> boost::capy::task<boost::capy::results<>>;
	// Wraps staged_ into out_, with its length.
	auto protect() -> std::error_code;
	// Writes out_ whole.
	auto flush() -> boost::capy::task<boost::capy::results<>>;
	// A layer that takes no plaintext (max_wrap_input() 0): encode_error.
	auto refuse_empty_wrap() -> std::error_code;
	// Unwraps the buffer at the front of in_ if it is complete; whether it
	// was. Fails on an oversized length or an unwrap error.
	auto unwrap_front(bool &done) -> std::error_code;

	boost::capy::any_stream *inner_;
	std::unique_ptr<sasl_security_layer> layer_;
	read_buffer in_;// received, not yet unwrapped
	std::pmr::vector<std::byte> plain_;// unwrapped, delivered up to plain_pos_
	std::size_t plain_pos_ = 0;
	std::pmr::vector<std::byte> staged_;// the plaintext of the write in flight
	std::pmr::vector<std::byte> out_;// its protected buffer, length first
	std::string read_error_;
	std::string write_error_;
};

// Installs `layer` on `t` (RFC 4513 section 5.2.1.4: from the first octet
// after the final BindResponse): the bytes already in `buf` past that
// response move into the layer, `buf` is emptied, and t.stream() returns
// the layer from now on. A write in flight keeps the stream it started on.
// client_errc::security_layer_in_effect if `t` has a layer already.
auto install_security_layer(transport &t, read_buffer &buf, std::unique_ptr<sasl_security_layer> layer) -> result<void>;

// The context of the last read's or write's failure on `t`, when it came
// from the layer (empty: none, or no layer).
auto security_layer_read_error(const transport &t) noexcept -> std::string_view;
auto security_layer_write_error(const transport &t) noexcept -> std::string_view;

}// namespace jhetz::ldap::net::detail
