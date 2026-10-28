#include "sasl_layer.hpp"

#include "../format_util.hpp"
#include "transport_impl.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/write.hpp>

#include <algorithm>
#include <cstdint>
#include <utility>

namespace capy = boost::capy;

namespace jhetz::ldap::net::detail {
namespace {

	// What one read of the inner stream asks for at least: a buffer's rest,
	// or this much while its length is incomplete.
	constexpr std::size_t read_chunk = std::size_t{ 16 } * 1024;

	constexpr unsigned byte_bits = 8;
	constexpr std::uint64_t max_length = 0xffff'ffff;

	auto read_length(std::span<const std::byte> b) noexcept -> std::uint32_t
	{
		std::uint32_t v = 0;
		for (std::size_t i = 0; i < sasl_length_size; ++i) {
			v = (v << byte_bits) | std::to_integer<std::uint32_t>(b[i]);
		}
		return v;
	}

}// namespace

sasl_layer_stream::sasl_layer_stream(capy::any_stream &inner,
  std::unique_ptr<sasl_security_layer> layer,
  std::pmr::memory_resource *mr)
  : inner_(&inner), layer_(std::move(layer)), in_(mr), plain_(mr), staged_(mr), out_(mr)
{}

void sasl_layer_stream::feed(std::span<const std::byte> bytes) { in_.insert(in_.end(), bytes.begin(), bytes.end()); }

auto sasl_layer_stream::unwrap_front(bool &done) -> std::error_code
{
	done = false;
	if (in_.size() < sasl_length_size) {
		return {};
	}
	const std::size_t length = read_length(in_);
	if (length > layer_->max_received()) {
		error_ = ldap::detail::format("SASL security layer: a protected buffer of {} bytes, more than the {} accepted",
		  length,
		  layer_->max_received());
		return client_errc::message_too_large;
	}
	if (in_.size() - sasl_length_size < length) {
		return {};
	}
	plain_.clear();
	plain_pos_ = 0;
	auto r = layer_->unwrap(std::span(in_).subspan(sasl_length_size, length), plain_);
	in_.erase(in_.begin(), in_.begin() + static_cast<std::ptrdiff_t>(sasl_length_size + length));
	if (!r) {
		error_ = "SASL security layer: ";
		error_ += r.error().context;
		return r.error().code;
	}
	done = true;
	return {};
}

auto sasl_layer_stream::fill() -> capy::io_task<>
{
	while (plain_pos_ == plain_.size()) {
		bool done = false;
		if (auto ec = unwrap_front(done); ec) {
			co_return { ec };
		}
		if (done) {
			continue;// an empty buffer delivers nothing: the next one
		}
		std::size_t want = read_chunk;
		if (in_.size() >= sasl_length_size) {
			want = std::max(want, sasl_length_size + read_length(in_) - in_.size());
		}
		const std::size_t had = in_.size();
		in_.resize(had + want);
		auto [ec, n] = co_await inner_->read_some(capy::mutable_buffer(in_.data() + had, want));
		in_.resize(had + n);
		if (n != 0) {
			continue;// use the bytes; an error shows again on the next read
		}
		if (!ec) {
			ec = capy::error::eof;// a read into a non-empty buffer that transfers nothing
		}
		co_return { ec };
	}
	co_return { std::error_code{} };
}

auto sasl_layer_stream::protect() -> std::error_code
{
	out_.assign(sasl_length_size, std::byte{ 0 });
	if (auto r = layer_->wrap(staged_, out_); !r) {
		error_ = "SASL security layer: ";
		error_ += r.error().context;
		return r.error().code;
	}
	const std::uint64_t length = out_.size() - sasl_length_size;
	if (length > max_length) {
		error_ = "SASL security layer: a protected buffer too large for its length field";
		return client_errc::encode_error;
	}
	for (std::size_t i = 0; i < sasl_length_size; ++i) {
		out_[sasl_length_size - 1 - i] = static_cast<std::byte>((length >> (i * byte_bits)) & 0xffU);
	}
	return {};
}

auto sasl_layer_stream::flush() -> capy::io_task<>
{
	auto [ec, n] = co_await capy::write(*inner_, capy::const_buffer(out_.data(), out_.size()));
	(void)n;
	co_return { ec };
}

auto install_security_layer(transport &t, read_buffer &buf, std::unique_ptr<sasl_security_layer> layer) -> result<void>
{
	auto &im = transport_access::get(t);
	if (im.sasl_layer) {
		return fail(client_errc::security_layer_in_effect, "a SASL security layer is in effect already");
	}
	im.sasl_layer.emplace(im.stream, std::move(layer), im.mr);
	try {
		im.sasl_layer->feed(buf.data());
		im.layered = capy::any_stream(&*im.sasl_layer);
	} catch (...) {
		im.sasl_layer.reset();
		throw;
	}
	buf.clear();
	return {};
}

auto security_layer_error(const transport &t) noexcept -> std::string_view
{
	if (t.type() == transport::kind::none) {
		return {};
	}
	const auto &im = transport_access::get(t);
	return im.sasl_layer ? std::string_view(im.sasl_layer->last_error()) : std::string_view();
}

}// namespace jhetz::ldap::net::detail
