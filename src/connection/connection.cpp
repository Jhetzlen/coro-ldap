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

using detail::core_ref;
using detail::no_connection;

// ---------------------------------------------------------------- connection

// NOLINTNEXTLINE(misc-const-correctness): it changes the connection's state, through core_
void detail::set_next_message_id(connection &c, std::int32_t id) noexcept { c.core_->set_next_message_id(id); }

// NOLINTNEXTLINE(misc-const-correctness): it changes the connection's state, through core_
void detail::set_close_hook(connection &c, std::move_only_function<void() noexcept> hook) noexcept
{
	if (c.core_) {
		detail::run_on_strand(
		  *c.core_, [self = c.core_, h = std::move(hook)] mutable noexcept { self->set_close_hook(std::move(h)); });
	}
}

auto detail::accepts_requests(const connection &c) noexcept -> bool
{
	return c.core_ && c.core_->published_accepts_requests();
}

connection::connection(corosio::io_context &ioc,
  net::transport t,
  const connection_options &options,
  std::pmr::memory_resource *mr)
{
	std::pmr::polymorphic_allocator<> alloc(mr);
	core_ = core_ref(alloc.new_object<core>(executor_type(ioc.get_executor()), std::move(t), options, mr));
	core_->add_handle();
}

connection::connection(const connection &other) noexcept : core_(other.core_)
{
	if (core_) {
		core_->add_handle();
	}
}

connection::connection(connection &&other) noexcept = default;

// The handle replaced is released through `old`'s destructor.
auto connection::operator=(const connection &other) noexcept -> connection &
{
	connection old(other);
	std::swap(core_, old.core_);
	return *this;
}

auto connection::operator=(connection &&other) noexcept -> connection &
{
	connection old(std::move(other));
	std::swap(core_, old.core_);
	return *this;
}

connection::~connection()
{
	if (core_ && core_->release_handle()) {
		close();
	}
}

auto connection::is_open() const noexcept -> bool { return core_ && core_->published_open(); }

auto connection::name() const noexcept -> std::string_view
{
	if (!core_) {
		return {};
	}
	return core_->transport().name();
}

auto connection::executor() const noexcept -> connection::executor_type { return core_->executor(); }

auto connection::outstanding() const noexcept -> std::size_t { return !core_ ? 0 : core_->published_outstanding(); }

auto connection::bind_count() const noexcept -> std::uint64_t { return !core_ ? 0 : core_->published_bind_count(); }

auto connection::is_tls() const noexcept -> bool { return core_ && core_->published_tls(); }

auto connection::security_layer() const noexcept -> sasl_protection
{
	return !core_ ? sasl_protection::none : core_->published_security_layer();
}

// The TLS data are set before is_tls() first reports true (release /
// acquire) and never change while it does.
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
	if (core_) {
		core_->request_close();
	}
}

namespace {

	auto unbind_impl(core_ref self) -> capy::task<result<void>>
	{
		const std::string context = "unbind";
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		if (!self->accepts_requests()) {
			co_return std::unexpected(self->not_connected(context));
		}
		// During a bind or StartTLS nothing may be sent (RFC 4511 sections 4.2.1,
		// 4.14.1): just close.
		if (self->exchange_in_progress()) {
			self->shut(make_error(client_errc::not_connected, "connection closed"), false);
			co_return result<void>{};
		}

		// An exception closes the connection before it propagates.
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

}// namespace

auto connection::unbind() -> capy::task<result<void>> { return detail::on_strand(core_, unbind_impl(core_)); }

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
	// Not a coroutine: `text` is parsed now.
	auto u = url::parse(text, mr);
	if (!u) {
		return connect_failed(std::move(u.error()));
	}
	return connect(ioc, std::move(*u), std::move(options), mr);
}

}// namespace jhetz::ldap
