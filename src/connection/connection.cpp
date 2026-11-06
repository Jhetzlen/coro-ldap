#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/connect.hpp"

#include "../format_util.hpp"
#include "core.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory_resource>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {

auto detail::op_context(std::string_view op, const dn &d) -> std::string
{
	if (d.empty()) {
		return detail::format("{} \"\"", op);
	}
	std::string text = detail::format("{} ", op);
	detail::append_sanitized(text, d.to_string(), 256);// as mapping's entry_context
	return text;
}

using detail::core_ref;
using detail::no_connection;

// ---------------------------------------------------------------- connection

// NOLINTNEXTLINE(misc-const-correctness): it changes the connection's state, through core_
void detail::set_next_message_id(connection &c, std::int32_t id) noexcept { c.core_->set_next_message_id(id); }

// NOLINTNEXTLINE(misc-const-correctness): it changes the connection's state, through core_
void detail::set_close_hook(connection &c, std::move_only_function<void() noexcept> hook) noexcept
{
	if (c.core_ != nullptr) {
		c.core_->set_close_hook(std::move(hook));
	}
}

auto detail::accepts_requests(const connection &c) noexcept -> bool
{
	return c.core_ != nullptr && c.core_->accepts_requests();
}

connection::connection(corosio::io_context &ioc,
  net::transport t,
  const connection_options &options,
  std::pmr::memory_resource *mr)
{
	std::pmr::polymorphic_allocator<> alloc(mr);
	core_ = alloc.new_object<core>(ioc, std::move(t), options, mr);
}

connection::connection(connection &&other) noexcept : core_(std::exchange(other.core_, nullptr)) {}

auto connection::operator=(connection &&other) noexcept -> connection &
{
	if (this != &other) {
		const connection old(std::move(*this));
		core_ = std::exchange(other.core_, nullptr);
	}
	return *this;
}

connection::~connection()
{
	if (core_ == nullptr) {
		return;
	}
	close();
	core_->release();
}

auto connection::is_open() const noexcept -> bool { return core_ != nullptr && core_->is_open(); }

auto connection::name() const noexcept -> std::string_view
{
	if (core_ == nullptr) {
		return {};
	}
	return core_->transport().name();
}

auto connection::executor() const noexcept -> connection::executor_type { return core_->executor(); }

auto connection::outstanding() const noexcept -> std::size_t { return core_ == nullptr ? 0 : core_->outstanding(); }

auto connection::bind_count() const noexcept -> std::uint64_t { return core_ == nullptr ? 0 : core_->bind_count(); }

auto connection::is_tls() const noexcept -> bool { return core_ != nullptr && core_->is_tls(); }

auto connection::security_layer() const noexcept -> sasl_protection
{
	return core_ == nullptr ? sasl_protection::none : core_->security_layer();
}

auto connection::peer_certificate() const noexcept -> std::span<const std::byte>
{
	if (!is_tls()) {
		return {};
	}
	return core_->transport().peer_certificate();
}

auto connection::channel_bindings() const noexcept -> ldap::channel_bindings
{
	if (!is_tls()) {
		return {};
	}
	return core_->transport().channel_bindings();
}

void connection::close() noexcept
{
	if (core_ != nullptr) {
		core_->close();
	}
}

auto connection::unbind() -> capy::task<result<void>>
{
	const std::string context = "unbind";
	if (core_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	const core_ref self(core_);
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

auto connect(corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)
  -> capy::task<result<connection>>
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

	auto connect_failed(error e) -> capy::task<result<connection>> { co_return std::unexpected(std::move(e)); }

}// namespace

auto connect(corosio::io_context &ioc, std::string_view text, connection_options options, std::pmr::memory_resource *mr)
  -> capy::task<result<connection>>
{
	// Not a coroutine: `text` is parsed now, so the task does not refer to it.
	auto u = url::parse(text, mr);
	if (!u) {
		return connect_failed(std::move(u.error()));
	}
	return connect(ioc, std::move(*u), std::move(options), mr);
}

}// namespace jhetz::ldap
