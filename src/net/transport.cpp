#include "transport_impl.hpp"

#include "deadline.hpp"

#include <string>

#include <utility>

namespace jhetz::ldap::net {

transport::transport() noexcept = default;

transport::transport(transport &&other) noexcept : impl_(std::exchange(other.impl_, nullptr)) {}

transport &transport::operator=(transport &&other) noexcept
{
	if (this != &other) {
		destroy();
		impl_ = std::exchange(other.impl_, nullptr);
	}
	return *this;
}

transport::~transport() { destroy(); }

void transport::destroy() noexcept
{
	if (impl_ == nullptr) {
		return;
	}
	impl *im = std::exchange(impl_, nullptr);
	if (im->custom != nullptr) {
		im->stream = {};// refers to the custom stream
		im->custom_ops.destroy(im->custom, im->mr);
	}
	std::pmr::polymorphic_allocator<impl> alloc(im->mr);
	alloc.delete_object(im);
}

transport transport::make(kind k, std::string_view name, std::pmr::memory_resource *mr)
{
	transport t;
	std::pmr::polymorphic_allocator<impl> alloc(mr);
	t.impl_ = alloc.new_object<impl>(mr);
	t.impl_->type = k;
	t.impl_->name = name;
	return t;
}

void transport::set_custom(void *stream, custom_ops ops) noexcept
{
	impl_->custom = stream;
	impl_->custom_ops = ops;
}

boost::capy::any_stream &transport::stream() noexcept { return impl_->stream; }

transport::kind transport::type() const noexcept { return impl_ ? impl_->type : kind::none; }

bool transport::is_tls() const noexcept { return impl_ && impl_->tls.has_value(); }

bool transport::is_open() const noexcept
{
	if (!impl_) {
		return false;
	}
	switch (impl_->type) {
	case kind::tcp:
		return impl_->tcp && impl_->tcp->is_open();
	case kind::local:
		return impl_->local && impl_->local->is_open();
	case kind::custom:
		return impl_->stream.has_value() && !impl_->custom_closed;
	case kind::none:
		break;
	}
	return false;
}

const std::pmr::string &transport::name() const noexcept
{
	static const std::pmr::string none("no transport", std::pmr::new_delete_resource());
	return impl_ ? impl_->name : none;
}

const std::pmr::string &transport::host() const noexcept
{
	static const std::pmr::string none(std::pmr::new_delete_resource());
	return impl_ ? impl_->host : none;
}

void transport::cancel() noexcept
{
	if (!impl_) {
		return;
	}
	if (impl_->tcp) {
		impl_->tcp->cancel();
	}
	if (impl_->local) {
		impl_->local->cancel();
	}
	if (impl_->custom && impl_->custom_ops.cancel) {
		impl_->custom_ops.cancel(impl_->custom);
	}
}

void transport::close() noexcept
{
	if (!impl_) {
		return;
	}
	if (impl_->tcp) {
		impl_->tcp->close();
	}
	if (impl_->local) {
		impl_->local->close();
	}
	if (impl_->custom && !impl_->custom_closed) {
		impl_->custom_closed = true;
		if (impl_->custom_ops.close) {
			impl_->custom_ops.close(impl_->custom);
		}
	}
}

boost::capy::task<result<void>> transport::shutdown(std::optional<std::chrono::milliseconds> timeout)
{
	if (impl_ == nullptr || !impl_->tls || !is_open()) {
		close();
		co_return result<void>{};
	}
	detail::deadline_t deadline;
	if (timeout) {
		deadline = detail::clock::now() + *timeout;
	}
	auto [ec] = co_await detail::bounded(impl_->tls->shutdown(), deadline);
	close();
	if (ec) {
		co_return fail(ec, "tls shutdown " + std::string(impl_->name));
	}
	co_return result<void>{};
}

}// namespace jhetz::ldap::net
