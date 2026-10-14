#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/message_io.hpp"

#include "connection/impl.hpp"
#include "format_util.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/frame_allocator.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/timeout.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <exception>
#include <iterator>
#include <memory>
#include <memory_resource>
#include <new>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <variant>

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

using detail::clock;
using detail::deadline_after;
using detail::impl_ref;
using detail::intermediate_response_tag;
using detail::no_connection;
using detail::op_context;
using detail::op_index;
using detail::op_name;
using detail::op_names;
using detail::pending_op;
using detail::registration;
using detail::same_tag;
using detail::search_result_done_tag;

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
		if (const std::size_t n = self->pending.size(); n != 0)
			co_return fail(client_errc::operation_in_progress,
			  detail::format("{} with {} {} outstanding", context, n, n == 1 ? "request" : "requests"));
		// Checked before the wait too, so misuse fails at once.
		if (self->transport.type() != net::transport::kind::tcp || self->transport.is_tls())
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": needs a plain TCP connection (not ldaps://, ldapi:// or a custom stream)");
		const std::size_t due = self->due_answers;
		if (due == 0) break;
		// Something must read the answers and expire their deadlines: if
		// send_unanswered() could not start the reader or the due watcher
		// (bad_alloc), nothing else may (a throw here is this task's).
		self->start_reader();
		if (!self->watching && self->next_due_deadline()) self->start_due_watcher();
		std::error_code ec;
		if (wait_deadline) {
			auto [e] = co_await corosio::timeout(self->due_idle.wait(), *wait_deadline);
			ec = e;
		} else {
			auto [e] = co_await self->due_idle.wait();
			ec = e;
		}
		// The wait's timeout may run before the due watcher expires an
		// answer whose deadline passed at the same time: expire those here
		// (only those past their own deadline), and check again if none is
		// left. A stop gives canceled, not timeout.
		std::size_t left = due;
		if (ec == capy::cond::timeout) {
			self->expire_due(clock::now());
			left = self->due_answers;
			if (left == 0) continue;
		}
		// Cancelled or timed out: nothing was sent, the connection is usable.
		// A stop reports the count waited for, not due_answers: the last
		// answer may have come meanwhile, and "0 releases" would say nothing.
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
		co_await capy::run(std::stop_token{})([](connection::impl &c) -> capy::task<void> {
			(void)co_await c.write_idle.wait();
			(void)co_await c.reader_idle.wait();
		}(*self));
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
	auto waiting = std::move(self->pending);
	self->pending.clear();
	for (auto &[id, op] : waiting) {
		op->registered = false;
		op->finished = true;
		op->ready.set();// they fail with not_connected ("connection closed")
	}
	// The answers still due are not read either. due_idle stays clear until
	// shut() below: a StartTLS waiting for them then fails with
	// not_connected instead of being sent after the UnbindRequest (as does
	// one whose wait times out meanwhile: `unbinding`).
	for (auto &a : self->abandoned) a.due = false;
	self->due_answers = 0;
	self->due_changed.set();// the due watcher ends
	self->stop_reader_if_idle();
	message request{ 0, unbind_request{} };
	if (auto r = self->submit(request, nullptr, context); !r) co_return r;
	// Nothing may follow the UnbindRequest (RFC 4511 section 4.3): an
	// operation, StartTLS or unbind() started while the writer finishes
	// fails with not_connected.
	self->unbinding = true;
	// Wait for the writer, even if this task is cancelled: closing first
	// would cut the UnbindRequest off.
	{
		auto [ec] = co_await capy::run(std::stop_token{})(
		  [](connection::impl &c) -> capy::task<capy::io_result<>> { co_return co_await c.write_idle.wait(); }(*self));
		(void)ec;
	}
	std::optional<error> failed = self->failure;
	self->shut(make_error(client_errc::not_connected, "connection closed"), false, false);
	// TLS: close_notify, after the reader has stopped (it would otherwise
	// read the peer's close_notify itself). Best effort and bounded: the
	// unbind is complete whatever the peer does.
	if (!failed && self->transport.is_tls() && self->transport.is_open()) {
		(void)co_await capy::run(std::stop_token{})(
		  [](connection::impl &c) -> capy::task<capy::io_result<>> { co_return co_await c.reader_idle.wait(); }(*self));
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
