#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/connect.hpp"

#include "../format_util.hpp"
#include "impl.hpp"

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {

std::string detail::op_context(std::string_view op, const dn &d)
{
	if (d.empty()) return detail::format("{} \"\"", op);
	std::string text = detail::format("{} ", op);
	detail::append_sanitized(text, d.to_string(), 256);// as mapping's entry_context
	return text;
}

using detail::impl_ref;
using detail::no_connection;

// ---------------------------------------------------------------- connection

void detail::set_next_message_id(connection &c, std::int32_t id) noexcept { c.impl_->next_id = id; }

connection::connection(corosio::io_context &ioc,
  net::transport t,
  const connection_options &options,
  std::pmr::memory_resource *mr)
{
	std::pmr::polymorphic_allocator<> alloc(mr);
	impl_ = alloc.new_object<impl>(ioc, std::move(t), options, mr);
}

connection::connection(connection &&other) noexcept : impl_(std::exchange(other.impl_, nullptr)) {}

connection &connection::operator=(connection &&other) noexcept
{
	if (this != &other) {
		connection old(std::move(*this));
		impl_ = std::exchange(other.impl_, nullptr);
	}
	return *this;
}

connection::~connection()
{
	if (impl_ == nullptr) return;
	close();
	impl_->release();
}

bool connection::is_open() const noexcept { return impl_ != nullptr && impl_->open; }

std::string_view connection::name() const noexcept
{
	if (impl_ == nullptr) return {};
	return impl_->transport.name();
}

connection::executor_type connection::executor() const noexcept { return impl_->ex; }

std::size_t connection::outstanding() const noexcept { return impl_ == nullptr ? 0 : impl_->outstanding(); }

bool connection::is_tls() const noexcept { return impl_ != nullptr && impl_->is_tls(); }

void connection::close() noexcept
{
	if (impl_ == nullptr) return;
	// Without memory for the error's text, operations fail with
	// not_enough_memory instead.
	error closed;
	try {
		closed = make_error(client_errc::not_connected, "connection closed");
	} catch (const std::bad_alloc &) {
		closed = impl::out_of_memory();
	}
	impl_->shut(std::move(closed), false);
	impl_->transport.close();// also ends a TLS shutdown that unbind() is waiting for
}

capy::task<result<void>> connection::unbind()
{
	const std::string context = "unbind";
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	const impl_ref self(impl_);
	if (!self->open || self->unbinding) co_return std::unexpected(self->not_connected(context));
	// Nothing may be sent while a BindRequest is outstanding (RFC 4511
	// section 4.2.1), or during StartTLS until its response is received and
	// the handshake done (section 4.14.1), an UnbindRequest included: just
	// close, before anything is changed (StartTLS then fails with
	// not_connected). Refusing instead would leave the session the caller
	// wants ended open.
	if (self->binding || self->upgrading) {
		self->shut(make_error(client_errc::not_connected, "connection closed"), false);
		co_return result<void>{};
	}

	// Outstanding operations are abandoned by the unbind (RFC 4511 section 4.3).
	self->abandon_all_for_unbind();
	message request{ 0, unbind_request{} };
	if (auto r = self->submit(request, nullptr, context); !r) co_return r;
	// Nothing may follow the UnbindRequest (RFC 4511 section 4.3): an
	// operation, StartTLS or unbind() started while the writer finishes
	// fails with not_connected.
	self->unbinding = true;
	// Wait for the writer, even if this task is cancelled: closing first
	// would cut the UnbindRequest off.
	co_await self->wait_write_idle();
	std::optional<error> failed = self->failure;
	self->shut(make_error(client_errc::not_connected, "connection closed"), false, false);
	// TLS: close_notify, after the reader has stopped (it would otherwise
	// read the peer's close_notify itself). Best effort and bounded: the
	// unbind is complete whatever the peer does.
	if (!failed && self->transport.is_tls() && self->transport.is_open()) {
		co_await self->wait_reader_idle();
		(void)co_await self->transport.shutdown(self->tls_shutdown_timeout);
	}
	self->transport.close();
	if (failed) co_return std::unexpected(detail::with_context(std::move(*failed), context));
	co_return result<void>{};
}

// ---------------------------------------------------------------- connect

capy::task<result<connection>>
  connect(corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)
{
	if (options.start_tls && u.scheme() != url_scheme::ldap)
		co_return fail(client_errc::invalid_url,
		  detail::format(
			"connect {}: start_tls needs an ldap:// URL (ldaps:// and ldapi:// are not upgraded)", u.to_string()));
	auto t = co_await net::connect(ioc,
	  std::move(u),
	  net::connect_options{ .timeout = options.timeout,
		.tls = options.tls,
		.attempt_delay = options.attempt_delay,
		.tcp_no_delay = options.tcp_no_delay },
	  mr);
	if (!t) co_return std::unexpected(std::move(t.error()));
	connection c(ioc, std::move(*t), options, mr);
	if (options.start_tls) {
		if (auto r = co_await c.start_tls(options.tls, options.timeout); !r)
			co_return std::unexpected(std::move(r.error()));
	}
	co_return std::move(c);
}

namespace {

	capy::task<result<connection>> connect_failed(error e) { co_return std::unexpected(std::move(e)); }

}// namespace

capy::task<result<connection>>
  connect(corosio::io_context &ioc, std::string_view text, connection_options options, std::pmr::memory_resource *mr)
{
	// Not a coroutine: `text` is parsed now, so the task does not refer to it.
	auto u = url::parse(text, mr);
	if (!u) return connect_failed(std::move(u.error()));
	return connect(ioc, std::move(*u), std::move(options), mr);
}

}// namespace jhetz::ldap
