#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/connect.hpp"

#include "../format_util.hpp"
#include "impl.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>

#include <chrono>
#include <cstddef>
#include <new>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

namespace capy = boost::capy;

namespace jhetz::ldap {

using detail::deadline_after;
using detail::impl_ref;
using detail::no_connection;
using detail::op_index;
using detail::pending_op;
using detail::registration;

// ---------------------------------------------------------------- StartTLS

capy::task<result<void>> connection::start_tls(net::tls_options options,
  std::optional<std::chrono::milliseconds> timeout)
{
	std::string context = "start tls";
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	// StartTLS may only be sent once every response is received (RFC 4513
	// section 3.1.1). Operations are refused; the answers still due to
	// released paged searches are waited for (they are certain, or given
	// up on at their own deadline), within `timeout`. The checks are made
	// again after the wait: an operation started meanwhile is refused as
	// if start_tls had been called then, and so is an unbind() (which
	// zeroes the answers due without waking this wait until it closes).
	const auto wait_deadline = deadline_after(timeout ? timeout : self->default_timeout);
	while (true) {
		if (!self->open || self->unbinding) co_return std::unexpected(self->not_connected(context));
		if (self->upgrading)
			co_return fail(client_errc::operation_in_progress, context + " during an earlier StartTLS");
		if (self->binding) co_return fail(client_errc::operation_in_progress, context + " during a bind");
		if (const std::size_t n = self->requests_waiting(); n != 0)
			co_return fail(client_errc::operation_in_progress,
			  detail::format("{} with {} {} outstanding", context, n, n == 1 ? "request" : "requests"));
		// Checked before the wait too, so misuse fails at once.
		if (self->transport.type() != net::transport::kind::tcp || self->transport.is_tls())
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": needs a plain TCP connection (not ldaps://, ldapi:// or a custom stream)");
		if (self->answers_due() == 0) break;
		const auto [ec, left] = co_await self->wait_due_answers(wait_deadline);
		// Cancelled or timed out: nothing was sent, the connection is usable.
		if (ec)
			co_return fail(ec,
			  detail::format("{} (waiting for the answer{} to {} paged search release{})",
				context,
				left == 1 ? "" : "s",
				left,
				left == 1 ? "" : "s"));
	}

	// The ExtendedRequest; nothing else may be sent until it is answered
	// and the handshake is done (RFC 4511 section 4.14.1).
	// Given up on already: not sent, since it could only be given up on by
	// closing the connection.
	if ((co_await capy::this_coro::stop_token).stop_requested()) co_return fail(capy::error::canceled, context);
	message request{ 0, extended_request(start_tls_oid) };
	pending_op p(self->mr, false, op_index<extended_response>);
	if (auto r = self->submit(request, &p, context); !r) co_return r;
	self->upgrading = true;
	struct clear_upgrading
	{
		connection::impl &c;
		~clear_upgrading() { c.upgrading = false; }
	} clear{ *self };
	{
		registration reg(*self, p);
		// A budget of its own: the wait may have used most of the first one,
		// and giving up on StartTLS closes the connection.
		auto m = co_await self->next_response(p, deadline_after(timeout ? timeout : self->default_timeout), context);
		if (!m) co_return std::unexpected(std::move(m.error()));
		const auto &x = std::get<extended_response>(m->op);
		if (!x.result.is_success()) co_return std::unexpected(x.result.to_error(context));// still usable, in clear
	}

	// From here on the server expects a handshake, so the session cannot go
	// on in clear (RFC 4511 section 4.14.1): an exception (this wait's frames,
	// the handshake's setup or the handshake; net::start_tls then closed the
	// transport) closes the connection before it propagates. Later
	// operations fail naming not_enough_memory for a bad_alloc, the abort
	// otherwise (no other exception is known to escape today: defensive).
	result<void> r;
	try {
		// The reader and writer must be idle: the handshake reads and writes
		// the socket itself. Not cancellable: they stop promptly on their own.
		co_await self->wait_io_idle();
		if (!self->open) co_return std::unexpected(self->not_connected(context));
		r = co_await net::start_tls(self->transport, self->buf, std::move(options), timeout);
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
	// Closed meanwhile (unbind(), close()): the handshake failed because of
	// that, or ended over a closed transport; say so, as for the steps above.
	if (!self->open) co_return std::unexpected(self->not_connected(context));
	if (!r) {
		// Injected bytes or a failed handshake: the stream cannot be trusted.
		error e = std::move(r.error());
		self->shut(e, true);
		co_return std::unexpected(std::move(e));
	}
	// RFC 4513 section 3.1.5: what was learnt about the server in clear
	// (possibly from an attacker) is discarded; the schema is read again.
	self->knowledge.forget();
	co_return result<void>{};
}

}// namespace jhetz::ldap
