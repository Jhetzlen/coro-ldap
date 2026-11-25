#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/connect.hpp"

#include "../format_util.hpp"
#include "core.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>

#include <chrono>
#include <new>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::deadline_after;
using detail::core_ref;
using detail::no_connection;
using detail::op_index;
using detail::pending_op;

// ---------------------------------------------------------------- StartTLS

namespace {

	auto start_tls_impl(core_ref self, net::tls_options options, std::optional<std::chrono::milliseconds> timeout)
	  -> capy::task<result<void>>
	{
		const std::string context = "start tls";
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		// Waits for the answers still due (RFC 4513 section 3.1.1), then checks
		// again.
		const auto wait_deadline = deadline_after(timeout ? timeout : self->default_timeout());
		while (true) {
			if (auto r = self->check_start_tls(context); !r) {
				co_return r;
			}
			// Checked before the wait too, so misuse fails at once.
			if (self->transport().type() != net::transport::kind::tcp || self->transport().is_tls()) {
				co_return fail(std::make_error_code(std::errc::invalid_argument),
				  context + ": needs a plain TCP connection (not ldaps://, ldapi:// or a custom stream)");
			}
			if (self->answers_due() == 0) {
				break;
			}
			const auto [ec, left] = co_await self->wait_due_answers(wait_deadline);
			// Nothing was sent; the connection is usable.
			if (ec) {
				co_return fail(ec,
				  detail::format("{} (waiting for the answer{} to {} paged search release{})",
					context,
					left == 1 ? "" : "s",
					left,
					left == 1 ? "" : "s"));
			}
		}

		// Already stopped: not sent.
		if ((co_await capy::this_coro::stop_token).stop_requested()) {
			co_return fail(capy::error::canceled, context);
		}
		message request{ 0, extended_request(start_tls_oid) };
		pending_op p(self->mr(), false, op_index<extended_response>);
		if (auto r = self->submit(request, &p, context); !r) {
			co_return r;
		}
		const auto upgrade = self->upgrade_scope();
		{
			const auto reg = detail::registration(*self, p);
			// A budget of its own: the wait may have used most of the first one,
			// and giving up on StartTLS closes the connection.
			auto m =
			  co_await self->next_response(p, deadline_after(timeout ? timeout : self->default_timeout()), context);
			if (!m) {
				co_return std::unexpected(std::move(m.error()));
			}
			const auto &x = std::get<extended_response>(m->op);
			if (!x.result.is_success()) {
				co_return std::unexpected(x.result.to_error(context));// still usable, in clear
			}
		}

		// From here on an exception closes the connection before it propagates.
		result<void> r;
		try {
			// The reader and writer must be idle: the handshake reads and writes
			// the socket itself. Not cancellable: they stop promptly on their own.
			co_await self->wait_io_idle();
			if (!self->is_open()) {
				co_return std::unexpected(self->not_connected(context));
			}
			r = co_await self->tls_handshake(std::move(options), timeout ? timeout : self->default_timeout());
		} catch (const std::bad_alloc &) {
			self->shut_out_of_memory();
			throw;
		} catch (...) {
			try {// the message's allocation may fail too
				self->shut(
				  make_error(client_errc::not_connected, "connection closed: StartTLS aborted by an exception"), true);
			} catch (const std::bad_alloc &) {
				self->shut_out_of_memory();
			}
			throw;
		}
		// Closed meanwhile (unbind(), close()).
		if (!self->is_open()) {
			co_return std::unexpected(self->not_connected(context));
		}
		if (!r) {
			// Injected bytes or a failed handshake: the stream cannot be trusted.
			error e = std::move(r.error());
			self->shut(e, true);
			co_return std::unexpected(std::move(e));
		}
		co_return result<void>{};
	}

}// namespace

auto connection::start_tls(net::tls_options options, std::optional<std::chrono::milliseconds> timeout)
  -> capy::task<result<connection>>
{
	const core_ref self(core_);
	return returning_handle(self, detail::on_strand(self, start_tls_impl(self, std::move(options), timeout)));
}

}// namespace jhetz::ldap
