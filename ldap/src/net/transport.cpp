#include "transport_impl.hpp"

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
	if (impl_ == nullptr) return;
	std::pmr::polymorphic_allocator<impl> alloc(impl_->mr);
	alloc.delete_object(std::exchange(impl_, nullptr));
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

void transport::set_custom(boost::capy::any_stream s) { impl_->stream = std::move(s); }

boost::capy::any_stream &transport::stream() noexcept { return impl_->stream; }

transport::kind transport::type() const noexcept { return impl_ ? impl_->type : kind::none; }

bool transport::is_tls() const noexcept { return impl_ && impl_->tls.has_value(); }

bool transport::is_open() const noexcept
{
	if (!impl_) return false;
	switch (impl_->type) {
	case kind::tcp:
		return impl_->tcp && impl_->tcp->is_open();
	case kind::local:
		return impl_->local && impl_->local->is_open();
	case kind::custom:
		return impl_->stream.has_value();
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
	if (!impl_) return;
	if (impl_->tcp) impl_->tcp->cancel();
	if (impl_->local) impl_->local->cancel();
}

void transport::close() noexcept
{
	if (!impl_) return;
	if (impl_->tcp) impl_->tcp->close();
	if (impl_->local) impl_->local->close();
}

}// namespace jhetz::ldap::net
