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
	if (d.empty()) {
		return detail::format("{} \"\"", op);
	}
	std::string text = detail::format("{} ", op);
	detail::append_sanitized(text, d.to_string(), 256);// as mapping's entry_context
	return text;
}

using detail::impl_ref;
using detail::no_connection;

// ---------------------------------------------------------------- connection

void detail::set_next_message_id(connection &c, std::int32_t id) noexcept { c.impl_->set_next_message_id(id); }

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
	if (impl_ == nullptr) {
		return;
	}
	close();
	impl_->release();
}

bool connection::is_open() const noexcept { return impl_ != nullptr && impl_->is_open(); }

std::string_view connection::name() const noexcept
{
	if (impl_ == nullptr) {
		return {};
	}
	return impl_->transport().name();
}

connection::executor_type connection::executor() const noexcept { return impl_->executor(); }

std::size_t connection::outstanding() const noexcept { return impl_ == nullptr ? 0 : impl_->outstanding(); }

bool connection::is_tls() const noexcept { return impl_ != nullptr && impl_->is_tls(); }

void connection::close() noexcept
{
	if (impl_ != nullptr) {
		impl_->close();
	}
}

capy::task<result<void>> connection::unbind()
{
	const std::string context = "unbind";
	if (impl_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	const impl_ref self(impl_);
	if (!self->accepts_requests()) {
		co_return std::unexpected(self->not_connected(context));
	}
	// Nothing may be sent while a BindRequest is outstanding (RFC 4511
	// section 4.2.1), or during StartTLS until its response is received and
	// the handshake done (section 4.14.1), an UnbindRequest included: just
	// close, before anything is changed (StartTLS then fails with
	// not_connected). Refusing instead would leave the session the caller
	// wants ended open.
	if (self->exchange_in_progress()) {
		self->shut(make_error(client_errc::not_connected, "connection closed"), false);
		co_return result<void>{};
	}

	// Outstanding operations are abandoned by the unbind (RFC 4511 section
	// 4.3), and nothing may follow the UnbindRequest. An exception (the
	// writer's frame, finish_unbind's, its wait's) closes the connection
	// before it propagates, as for StartTLS: left open, it would stay
	// "closing (unbind)" until close(). Later operations fail naming
	// not_enough_memory for a bad_alloc, the abort otherwise (no other
	// exception is known to escape today: defensive).
	std::optional<error> failed;
	try {
		if (auto r = self->send_unbind(context); !r) {
			co_return r;
		}
		failed = co_await self->finish_unbind();
	} catch (const std::bad_alloc &) {
		self->shut_out_of_memory();
		self->close();// the transport, if finish_unbind had shut the connection already
		throw;
	} catch (...) {
		try {// the message's allocation may fail too
			self->shut(
			  make_error(client_errc::not_connected, "connection closed: unbind aborted by an exception"), true);
		} catch (const std::bad_alloc &) {
			self->shut_out_of_memory();
		}
		self->close();
		throw;
	}
	if (failed) {
		co_return std::unexpected(detail::with_context(std::move(*failed), context));
	}
	co_return result<void>{};
}

// ---------------------------------------------------------------- connect

capy::task<result<connection>>
  connect(corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)
{
	if (options.start_tls && u.scheme() != url_scheme::ldap) {
		co_return fail(client_errc::invalid_url,
		  detail::format(
			"connect {}: start_tls needs an ldap:// URL (ldaps:// and ldapi:// are not upgraded)", u.to_string()));
	}
	auto t = co_await net::connect(ioc,
	  std::move(u),
	  net::connect_options{ .timeout = options.timeout,
		.tls = options.tls,
		.attempt_delay = options.attempt_delay,
		.tcp_no_delay = options.tcp_no_delay },
	  mr);
	if (!t) {
		co_return std::unexpected(std::move(t.error()));
	}
	connection c(ioc, std::move(*t), options, mr);
	if (options.start_tls) {
		if (auto r = co_await c.start_tls(options.tls, options.timeout); !r) {
			co_return std::unexpected(std::move(r.error()));
		}
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
	if (!u) {
		return connect_failed(std::move(u.error()));
	}
	return connect(ioc, std::move(*u), std::move(options), mr);
}

}// namespace jhetz::ldap
