#include "transport_layers.hpp"

#include "deadline.hpp"

#include <string>

#include <utility>

namespace jhetz::ldap::net {

transport::transport() noexcept = default;

transport::transport(transport &&other) noexcept : layers_(std::exchange(other.layers_, nullptr)) {}

auto transport::operator=(transport &&other) noexcept -> transport &
{
	if (this != &other) {
		destroy();
		layers_ = std::exchange(other.layers_, nullptr);
	}
	return *this;
}

transport::~transport() { destroy(); }

void transport::destroy() noexcept
{
	if (layers_ == nullptr) {
		return;
	}
	layers *im = std::exchange(layers_, nullptr);
	std::pmr::polymorphic_allocator<layers> alloc(im->mr);
	alloc.delete_object(im);
}

auto transport::make(kind k, std::string_view name, std::pmr::memory_resource *mr) -> transport
{
	transport t;
	std::pmr::polymorphic_allocator<layers> alloc(mr);
	t.layers_ = alloc.new_object<layers>(mr);
	t.layers_->type = k;
	t.layers_->name = name;
	return t;
}

void transport::set_custom(void *stream, custom_ops ops) noexcept
{
	layers_->custom = stream;
	layers_->custom_ops = ops;
}

auto transport::stream() noexcept -> boost::capy::any_stream &
{
	return layers_->sasl_layer ? layers_->layered : layers_->stream;
}

auto transport::security_layer() const noexcept -> sasl_protection
{
	return layers_ != nullptr && layers_->sasl_layer ? layers_->sasl_layer->protection() : sasl_protection::none;
}

auto transport::type() const noexcept -> transport::kind { return layers_ ? layers_->type : kind::none; }

auto transport::is_tls() const noexcept -> bool { return layers_ != nullptr && layers_->tls.has_value(); }

auto transport::peer_certificate() const noexcept -> std::span<const std::byte>
{
	if (!is_tls()) {
		return {};
	}
	return layers_->peer_certificate;
}

auto transport::channel_bindings() const noexcept -> ldap::channel_bindings
{
	if (!is_tls()) {
		return {};
	}
	return {
		.tls_server_end_point = layers_->tls_server_end_point,
		.tls_exporter = layers_->tls_exporter,
		.default_type = layers_->default_channel_binding,
	};
}

auto transport::is_open() const noexcept -> bool
{
	if (!layers_) {
		return false;
	}
	switch (layers_->type) {
	case kind::tcp:
		return layers_->tcp && layers_->tcp->is_open();
	case kind::local:
		return layers_->local && layers_->local->is_open();
	case kind::custom:
		return layers_->stream.has_value() && !layers_->custom_closed;
	case kind::none:
		break;
	}
	return false;
}

auto transport::endpoint() const noexcept -> const std::pmr::string &
{
	static const std::pmr::string none("no transport", std::pmr::new_delete_resource());
	return layers_ ? layers_->name : none;
}

auto transport::host() const noexcept -> const std::pmr::string &
{
	static const std::pmr::string none(std::pmr::new_delete_resource());
	return layers_ ? layers_->host : none;
}

void transport::cancel() noexcept
{
	if (!layers_) {
		return;
	}
	if (layers_->tcp) {
		layers_->tcp->cancel();
	}
	if (layers_->local) {
		layers_->local->cancel();
	}
	if (layers_->custom && layers_->custom_ops.cancel) {
		layers_->custom_ops.cancel(layers_->custom);
	}
}

void transport::close() noexcept
{
	if (!layers_) {
		return;
	}
	if (layers_->tcp) {
		layers_->tcp->close();
	}
	if (layers_->local) {
		layers_->local->close();
	}
	if (layers_->custom && !layers_->custom_closed) {
		layers_->custom_closed = true;
		if (layers_->custom_ops.close) {
			layers_->custom_ops.close(layers_->custom);
		}
	}
}

auto transport::shutdown(std::optional<std::chrono::milliseconds> timeout) -> boost::capy::task<result<void>>
{
	if (layers_ == nullptr || !layers_->tls || !is_open()) {
		close();
		co_return result<void>{};
	}
	const detail::deadline_t deadline = detail::deadline_after(timeout);
	auto [ec] = co_await detail::bounded(layers_->tls->shutdown(), deadline);
	close();
	if (ec) {
		co_return fail(ec, "tls shutdown " + std::string(layers_->name));
	}
	co_return result<void>{};
}

}// namespace jhetz::ldap::net
