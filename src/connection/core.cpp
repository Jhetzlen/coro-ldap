#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/message_io.hpp"

#include "../format_util.hpp"
#include "../net/sasl_layer.hpp"
#include "core.hpp"

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
#include <iterator>
#include <memory_resource>
#include <new>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {

using detail::clock;
using detail::core_ref;
using detail::op_index;
using detail::pending_op;

namespace {

	constexpr std::array<std::string_view, 21> op_names{ "BindRequest",
		"BindResponse",
		"UnbindRequest",
		"SearchRequest",
		"SearchResultEntry",
		"SearchResultDone",
		"SearchResultReference",
		"ModifyRequest",
		"ModifyResponse",
		"AddRequest",
		"AddResponse",
		"DelRequest",
		"DelResponse",
		"ModifyDNRequest",
		"ModifyDNResponse",
		"CompareRequest",
		"CompareResponse",
		"AbandonRequest",
		"ExtendedRequest",
		"ExtendedResponse",
		"IntermediateResponse" };
	static_assert(std::variant_size_v<protocol_op> == op_names.size());

	auto op_name(const protocol_op &op) noexcept -> std::string_view { return op_names[op.index()]; }

	// RFC 4511 protocolOp tags of the responses the reader recognizes before
	// decoding.
	constexpr ber::tag search_result_done_tag = ber::application(5, true);
	constexpr ber::tag intermediate_response_tag = ber::application(25, true);

	auto same_tag(ber::tag a, ber::tag b) noexcept -> bool { return a.cls == b.cls && a.number == b.number; }

	// Abandoned requests whose late responses are still dropped. Older ones
	// are forgotten: a response for them would then be unexpected.
	constexpr std::size_t max_abandoned = 1024;

}// namespace

// ---------------------------------------------------------------- state

connection::core::core(executor_type strand,
  net::transport t,
  const connection_options &options,
  std::pmr::memory_resource *memory)
  : ex(std::move(strand)), mr_(memory), transport_(std::move(t)), buf(memory),
	max_message_size(options.max_message_size), max_elements(options.max_elements),
	default_timeout_(options.operation_timeout), tls_shutdown_timeout(options.tls_shutdown_timeout), pending(memory),
	abandoned(memory), outbox(memory), held(memory), scratch(memory)
{
	write_idle.set();
	reader_idle.set();
	bind_idle.set();
	due_idle.set();
	publish();
}

void connection::core::publish() noexcept
{
	if (!open) {
		open_snapshot.store(false, std::memory_order_release);
	}
	outstanding_snapshot.store(outstanding(), std::memory_order_relaxed);
	binds_snapshot.store(binds_begun, std::memory_order_relaxed);
	layer_snapshot.store(security_layer(), std::memory_order_release);
	tls_snapshot.store(is_tls(), std::memory_order_release);
	accepting_snapshot.store(accepts_requests(), std::memory_order_release);
}

void connection::core::request_close() noexcept
{
	open_snapshot.store(false, std::memory_order_release);
	detail::run_on_strand(*this, [self = core_ref(this)] noexcept { self->close(); });
}

// ---------------------------------------------------------------- failure

auto connection::core::copy_error(const error &e) noexcept -> error
{
	try {
		return e;
	} catch (const std::bad_alloc &) {
		return out_of_memory();
	}
}

auto connection::core::unsent_error(const error &e) noexcept -> error
{
	error u = copy_error(e);
	// An allocation failure stays one (DESIGN.md section 7: the operations
	// fail with not_enough_memory, what was to be sent is lost).
	if (u.code != std::errc::not_enough_memory) {
		u.code = client_errc::not_sent;
	}
	return u;
}

auto connection::core::out_of_memory() noexcept -> error
{
	error e;
	e.code = std::make_error_code(std::errc::not_enough_memory);
	return e;
}

void connection::core::shut(const error &e, bool remember, bool close_transport) noexcept
{
	if (!open) {
		return;
	}
	open = false;
	if (remember) {
		failure = copy_error(e);
	}
	if (close_transport) {
		transport_.close();
	}
	outbox.clear();
	held.clear();
	abandoned.clear();
	due_answers = 0;
	due_idle.set();// a StartTLS waiting for them fails with not_connected
	due_changed.set();// the due watcher ends
	auto waiting = std::move(pending);
	pending.clear();
	for (auto &[id, p] : waiting) {
		p->registered = false;
		p->finished = true;
		p->failure = p->sent ? copy_error(e) : unsent_error(e);
		p->ready.set();
	}
	if (reading) {
		reader_stop.request_stop();
	}
	publish();
	if (close_hook) {
		auto hook = std::exchange(close_hook, nullptr);
		hook();
	}
}

void connection::core::shut_out_of_memory() noexcept { shut(out_of_memory(), true); }

auto connection::core::not_connected(std::string_view context) const -> error
{
	std::string text(context);
	if (failure) {
		text += ": connection closed by an earlier error: ";
		text += failure->message();
	} else if (open && unbinding) {
		text += ": connection closing (unbind)";
	} else {
		text += ": connection closed";
	}
	return make_error(client_errc::not_connected, text);
}

auto connection::core::not_sent(std::string_view context) const -> error
{
	error e = not_connected(context);
	e.code = client_errc::not_sent;
	return e;
}

void connection::core::close() noexcept
{
	// Without memory for the error's text, operations fail with
	// not_enough_memory instead.
	error closed;
	try {
		closed = make_error(client_errc::not_connected, "connection closed");
	} catch (const std::bad_alloc &) {
		closed = out_of_memory();
	}
	shut(closed, false);
	transport_.close();// also ends a TLS shutdown that unbind() is waiting for
}

// ---------------------------------------------------------------- tasks

auto connection::core::new_task(capy::task<void> (*body)(core *)) -> capy::task<void>
{
	struct frame_allocator_scope
	{
		std::pmr::memory_resource *saved = capy::get_current_frame_allocator();
		explicit frame_allocator_scope(std::pmr::memory_resource *mr) noexcept
		{
			capy::set_current_frame_allocator(mr);
		}
		frame_allocator_scope(const frame_allocator_scope &) = delete;
		auto operator=(const frame_allocator_scope &) -> frame_allocator_scope & = delete;
		~frame_allocator_scope() { capy::set_current_frame_allocator(saved); }
	};
	const frame_allocator_scope scope(ex.context().get_frame_allocator());
	return body(this);
}

// ---------------------------------------------------------------- writer

auto connection::core::writer(core *self) -> capy::task<void>
{
	const frame_ref ref(self);
	try {
		while (self->open && !self->outbox.empty()) {
			auto [id, bytes] = std::move(self->outbox.front());
			self->outbox.pop_front();
			if (const auto p = self->pending.find(id); p != self->pending.end()) {
				p->second->sent = true;
			}
			auto w = co_await net::write_bytes(self->transport_, bytes);
			if (!w) {
				self->shut(w.error(), true);
			}
		}
	} catch (const std::bad_alloc &) {
		self->shut_out_of_memory();
	}
	self->writing = false;
	self->write_idle.set();
}

void connection::core::enqueue(std::int32_t id, std::pmr::vector<std::byte> bytes)
{
	if (writing) {
		outbox.push_back({ .id = id, .bytes = std::move(bytes) });
		return;
	}
	auto task = new_task(&writer);
	outbox.push_back({ .id = id, .bytes = std::move(bytes) });
	writing = true;
	write_idle.clear();
	add_ref();// released by the writer
	// No stop token: a PDU is always written whole (a cancelled write
	// would leave half a PDU on the wire).
	capy::run_async(ex)(std::move(task));
}

auto connection::core::free_id() const -> std::int32_t
{
	std::int32_t id = next_id;
	if (!wrapped) {
		return id;// ids so far only increased: none is in use
	}
	const auto in_use = [this](std::int32_t i) {
		return pending.contains(i) || std::ranges::contains(abandoned, i, &abandoned_req::id);
	};
	while (in_use(id)) {
		id = id == max_int ? 1 : id + 1;
	}
	return id;
}

auto connection::core::submit(message &m, pending_op *p, std::string_view context) -> result<void>
{
	if (!open || unbinding) {
		return std::unexpected(not_sent(context));
	}
	if (upgrading && !std::holds_alternative<abandon_request>(m.op)) {
		return fail(client_errc::operation_in_progress, std::string(context) + " during StartTLS");
	}
	m.id = free_id();
	auto bytes = encode(m, mr_);
	if (!bytes) {
		return std::unexpected(detail::with_context(std::move(bytes.error()), context));
	}
	if (m.id == max_int) {
		wrapped = true;
	}
	next_id = m.id == max_int ? 1 : m.id + 1;
	const bool bind = std::holds_alternative<bind_request>(m.op);
	if (p != nullptr) {
		const auto *x = std::get_if<extended_request>(&m.op);
		p->abandonable = !bind && (x == nullptr || x->request_name != start_tls_oid);
		p->id = m.id;
		pending.emplace(m.id, p);
		p->registered = true;
		publish();
	}
	try {
		if (p != nullptr) {
			start_reader();
		}
		if (binding && !bind) {
			held.push_back({ .id = m.id, .bytes = std::move(*bytes) });
		} else {
			enqueue(m.id, std::move(*bytes));
		}
	} catch (...) {
		// `p` (in the caller's frame) must not stay registered: its
		// request is not sent.
		if (p != nullptr) {
			pending.erase(m.id);
			p->registered = false;
			stop_reader_if_idle();
			publish();
		}
		throw;
	}
	return {};
}

void connection::core::release_held() noexcept
{
	try {
		while (open && !held.empty()) {
			enqueue(held.front().id, std::move(held.front().bytes));
			held.pop_front();
		}
	} catch (const std::bad_alloc &) {
		shut_out_of_memory();
	}
	held.clear();
}

void connection::core::abandon(pending_op &p) noexcept
{
	if (!p.registered) {
		return;
	}
	p.registered = false;
	p.finished = true;
	pending.erase(p.id);
	stop_reader_if_idle();
	publish();
	if (!open) {
		return;
	}
	try {
		if (!p.abandonable) {
			shut(make_error(client_errc::not_connected,
				   "connection closed: a Bind or StartTLS request cannot be abandoned (RFC 4511 section 4.11)"),
			  true);
			return;
		}
		// Held by a bind exchange, so never sent: nothing to tell the server.
		const auto h = std::ranges::find(held, p.id, &held_request::id);
		if (h != held.end()) {
			held.erase(h);
			return;
		}
		abandoned.push_back({ .id = p.id, .search = p.search });
		trim_abandoned();
		message m{ 0, abandon_request{ p.id } };
		(void)submit(m, nullptr, "abandon");// cannot fail to encode
	} catch (const std::bad_alloc &) {
		shut_out_of_memory();
	}
}

void connection::core::send_unanswered(message &m,
  bool search,
  std::optional<clock::time_point> deadline,
  std::string_view context)
{
	// Listed before `m` is queued, like abandon(): nothing may fail after
	// that, or its answer would match no request. Id 0 is never a
	// request's. submit returns an error, or throws, only with nothing
	// queued, so the entry is still last then. It may start the writer
	// inline, whose failed write runs shut() inside it, which clears the
	// list: hence the guarded pop_back() on a throw, and the !open check
	// after it. If starting the reader or the due watcher below throws,
	// the request is sent and its answer still counted as due: the next
	// reader started reads it, and its deadline is applied once a due
	// watcher runs again (StartTLS's wait starts both).
	abandoned.push_back({ .id = 0, .search = search });
	try {
		if (!submit(m, nullptr, context)) {
			abandoned.pop_back();
			return;
		}
	} catch (...) {
		if (!abandoned.empty()) {
			abandoned.pop_back();
		}
		throw;
	}
	if (!open) {
		return;
	}
	abandoned.back().id = m.id;
	abandoned.back().due = true;
	abandoned.back().deadline = deadline;
	++due_answers;
	due_updated();
	trim_abandoned();
	start_reader();
	if (deadline) {
		start_due_watcher();
	}
}

void connection::core::forget_abandoned(const std::pmr::deque<abandoned_req>::iterator &a)
{
	const bool due = a->due;
	if (due) {
		--due_answers;
	}
	abandoned.erase(a);
	if (due) {
		due_updated();
	}
	stop_reader_if_idle();
}

void connection::core::trim_abandoned()
{
	if (abandoned.size() <= max_abandoned) {
		return;
	}
	const auto a = std::ranges::find(abandoned.begin(), std::prev(abandoned.end()), false, &abandoned_req::due);
	forget_abandoned(a != std::prev(abandoned.end()) ? a : abandoned.begin());
}

void connection::core::due_updated()
{
	publish();
	if (due_answers == 0) {
		due_idle.set();
	} else {
		due_idle.clear();
	}
	due_changed.set();
}

// ---------------------------------------------------------------- due answers

void connection::core::start_due_watcher()
{
	if (watching) {
		due_changed.set();// recomputes its next deadline
		return;
	}
	auto task = new_task(&due_watcher);
	watching = true;
	add_ref();// released by the watcher
	capy::run_async(ex)(std::move(task));
}

auto connection::core::next_due_deadline() const -> std::optional<clock::time_point>
{
	std::optional<clock::time_point> next;
	for (const auto &a : abandoned) {
		if (a.due && a.deadline && (!next || *a.deadline < *next)) {
			next = a.deadline;
		}
	}
	return next;
}

void connection::core::expire_due(clock::time_point now)
{
	bool changed = false;
	for (auto &a : abandoned) {
		if (!a.due || !a.deadline || *a.deadline > now) {
			continue;
		}
		a.due = false;
		--due_answers;
		changed = true;
	}
	if (!changed) {
		return;
	}
	due_updated();
	stop_reader_if_idle();
}

auto connection::core::due_watcher(core *self) -> capy::task<void>
{
	const frame_ref ref(self);
	try {
		while (self->open) {
			const auto next = self->next_due_deadline();
			if (!next) {
				break;
			}
			if (clock::now() < *next) {
				self->due_changed.clear();
				(void)co_await corosio::timeout(self->due_changed.wait(), *next);
				continue;// a change, or the deadline: look again
			}
			self->expire_due(clock::now());
		}
	} catch (const std::bad_alloc &) {
		self->shut_out_of_memory();
	}
	self->watching = false;
}

auto connection::core::outstanding() const noexcept -> std::size_t { return pending.size() + due_answers; }

auto connection::core::wait_due_answers(std::optional<clock::time_point> deadline)
  -> capy::task<connection::core::due_wait>
{
	const std::size_t due = due_answers;
	// Something must read the answers and expire their deadlines: if
	// send_unanswered() could not start the reader or the due watcher
	// (bad_alloc), nothing else may (a throw here is the caller's).
	start_reader();
	if (!watching && next_due_deadline()) {
		start_due_watcher();
	}
	std::error_code ec;
	if (deadline) {
		auto [e] = co_await corosio::timeout(due_idle.wait(), *deadline);
		ec = e;
	} else {
		auto [e] = co_await due_idle.wait();
		ec = e;
	}
	// The wait's timeout may run before the due watcher expires an
	// answer whose deadline passed at the same time: expire those here
	// (only those past their own deadline), and check again if none is
	// left. A stop gives canceled, not timeout.
	std::size_t left = due;
	if (ec == capy::cond::timeout) {
		expire_due(clock::now());
		left = due_answers;
		if (left == 0) {
			co_return due_wait{};
		}
	}
	// A stop reports the count waited for, not due_answers: the last
	// answer may have come meanwhile, and "0 releases" would say nothing.
	co_return due_wait{ .ec = ec, .left = left };
}

// ---------------------------------------------------------------- StartTLS

auto connection::core::check_start_tls(std::string_view context) const -> result<void>
{
	if (!accepts_requests()) {
		return std::unexpected(not_sent(context));
	}
	if (upgrading) {
		return fail(client_errc::operation_in_progress, std::string(context) + " during an earlier StartTLS");
	}
	if (binding) {
		return fail(client_errc::operation_in_progress, std::string(context) + " during a bind");
	}
	if (transport_.security_layer() != sasl_protection::none) {
		return fail(client_errc::security_layer_in_effect,
		  std::string(context)
			+ " with a SASL security layer in effect (TLS would have to go below it, RFC 4513 section 5.2.1.6)");
	}
	if (const std::size_t n = requests_waiting(); n != 0) {
		return fail(client_errc::operation_in_progress,
		  detail::format("{} with {} {} outstanding", context, n, n == 1 ? "request" : "requests"));
	}
	return {};
}

auto connection::core::tls_handshake(net::tls_options options, std::optional<std::chrono::milliseconds> timeout)
  -> capy::task<result<void>>
{
	return net::start_tls(transport_, buf, std::move(options), timeout);
}

// ---------------------------------------------------------------- unbind

void connection::core::abandon_all_for_unbind()
{
	auto waiting = std::move(pending);
	pending.clear();
	for (auto &[id, op] : waiting) {
		op->registered = false;
		op->finished = true;
		op->ready.set();// they fail with not_connected ("connection closed")
	}
	// The answers still due are not read either. due_idle stays clear until
	// unbind() calls shut(): a StartTLS waiting for them then fails with
	// not_connected instead of being sent after the UnbindRequest (as does
	// one whose wait times out meanwhile: `unbinding`).
	for (auto &a : abandoned) {
		a.due = false;
	}
	due_answers = 0;
	due_changed.set();// the due watcher ends
	stop_reader_if_idle();
	publish();
}

auto connection::core::send_unbind(std::string_view context) -> result<void>
{
	abandon_all_for_unbind();
	message request{ 0, unbind_request{} };
	if (auto r = submit(request, nullptr, context); !r) {
		return r;
	}
	unbinding = true;
	publish();
	return {};
}

auto connection::core::finish_unbind() -> capy::task<std::optional<error>>
{
	co_await wait_write_idle();
	std::optional<error> failed = failure;
	shut(make_error(client_errc::not_connected, "connection closed"), false, false);
	// TLS: close_notify, after the reader has stopped (it would otherwise
	// read the peer's close_notify itself). Best effort and bounded: the
	// unbind is complete whatever the peer does.
	if (!failed && transport_.is_tls() && transport_.is_open()) {
		co_await wait_reader_idle();
		(void)co_await transport_.shutdown(tls_shutdown_timeout);
	}
	transport_.close();
	co_return failed;
}

// ---------------------------------------------------------------- idle

auto connection::core::wait_io_idle() -> capy::task<void>
{
	co_await capy::run(std::stop_token{})([](core &c) -> capy::task<void> {
		(void)co_await c.write_idle.wait();
		(void)co_await c.reader_idle.wait();
	}(*this));
}

auto connection::core::wait_write_idle() -> capy::task<void>
{
	(void)co_await capy::run(std::stop_token{})(
	  [](core &c) -> capy::task<capy::results<>> { co_return co_await c.write_idle.wait(); }(*this));
}

auto connection::core::wait_reader_idle() -> capy::task<void>
{
	(void)co_await capy::run(std::stop_token{})(
	  [](core &c) -> capy::task<capy::results<>> { co_return co_await c.reader_idle.wait(); }(*this));
}

// ---------------------------------------------------------------- reader

void connection::core::start_reader()
{
	if (reading) {
		return;// a reader that is stopping restarts itself if needed
	}
	std::stop_source stop;
	auto task = new_task(&reader);
	reading = true;
	reader_idle.clear();
	reader_stop = std::move(stop);
	add_ref();// released by the reader
	capy::run_async(ex, reader_stop.get_token())(std::move(task));
}

void connection::core::stop_reader_if_idle()
{
	if (outstanding() == 0 && reading) {
		reader_stop.request_stop();
	}
}

auto connection::core::reader(core *self) -> capy::task<void>
{
	const frame_ref ref(self);
	try {
		while (self->open && self->outstanding() != 0) {
			auto size = co_await net::read_frame(self->transport_, self->buf, self->max_message_size);
			if (!size) {
				// Stopped because nothing is outstanding (bytes already
				// received stay in buf), or a real failure.
				if (size.error().code == capy::cond::canceled && self->open) {
					break;
				}
				self->shut(size.error(), true);
				break;
			}
			self->route(*size);
		}
	} catch (const std::bad_alloc &) {
		self->shut_out_of_memory();// a response may be lost
	}
	self->reading = false;
	self->reader_idle.set();
	// Stopped while an operation was being registered: start afresh,
	// with a new stop token. If it cannot start, nothing would read the
	// responses: closed.
	try {
		if (self->open && self->outstanding() != 0) {
			self->start_reader();
		}
	} catch (const std::bad_alloc &) {
		self->shut_out_of_memory();
	}
}

auto connection::core::unexpected(std::string_view text) -> error
{
	return make_error(client_errc::unexpected_response, detail::format("read {}: {}", transport_.name(), text));
}

void connection::core::route(std::size_t size)
{
	const auto bytes = buf.data().first(size);
	auto h = peek_message_header(bytes);
	if (!h) {
		buf.consume(size);
		shut(detail::with_context(std::move(h.error()), detail::format("read {}", transport_.name())), true);
		return;
	}
	if (h->id == 0) {
		notification(bytes);
		buf.consume(size);
		return;
	}
	if (const auto it = pending.find(h->id); it != pending.end()) {
		pending_op &p = *it->second;
		if (!p.intermediates && same_tag(h->op, intermediate_response_tag)) {
			buf.consume(size);// skipped, not decoded
			return;
		}
		auto m = decode(bytes, { .from = origin::server, .max_elements = max_elements, .memory = p.mr });
		buf.consume(size);
		if (!m) {
			shut(detail::with_context(std::move(m.error()), detail::format("read {}", transport_.name())), true);
			return;
		}
		const std::size_t index = m->op.index();
		const bool final = index == p.expect;
		const bool streamed =
		  (p.search && (index == op_index<search_result_entry> || index == op_index<search_result_reference>))
		  || (p.intermediates && index == op_index<intermediate_response>);
		if (!final && !streamed) {
			shut(unexpected(detail::format("{} with message id {} in response to a {}",
				   op_name(m->op),
				   h->id,
				   p.search ? std::string_view("SearchRequest") : op_names[p.expect - 1])),
			  true);
			return;
		}
		if (final && index == op_index<bind_response> && armed_layer && !take_armed_layer(*m)) {
			return;
		}
		p.queue.push_back(std::move(*m));
		if (final) {
			p.finished = true;
			p.registered = false;
			pending.erase(it);
			stop_reader_if_idle();
			publish();
		}
		p.ready.set();
		return;
	}
	buf.consume(size);
	const auto a = std::ranges::find(abandoned, h->id, &abandoned_req::id);
	if (a != abandoned.end()) {
		// A late response to an abandoned request: dropped. Only a final
		// response is its last: the search's SearchResultDone, or the
		// response to another request. IntermediateResponses (any request)
		// and a search's entries and references may come before it.
		if (same_tag(h->op, intermediate_response_tag)) {
			return;
		}
		if (!a->search || same_tag(h->op, search_result_done_tag)) {
			forget_abandoned(a);
		}
		return;
	}
	shut(unexpected(detail::format("message with id {}, which matches no outstanding request", h->id)), true);
}

auto connection::core::take_armed_layer(const message &m) -> bool
{
	auto layer = std::move(armed_layer);
	if (!std::get<bind_response>(m.op).result.is_success()) {
		return true;
	}
	if (auto r = net::detail::install_security_layer(transport_, buf, std::move(layer)); !r) {
		shut(detail::with_context(std::move(r.error()), detail::format("read {}", transport_.name())), true);
		return false;
	}
	publish();
	return true;
}

void connection::core::notification(std::span<const std::byte> bytes)
{
	std::optional<error> fatal;
	{
		auto m = decode(bytes, { .from = origin::server, .max_elements = max_elements, .memory = &scratch });
		if (!m) {
			fatal = detail::with_context(std::move(m.error()), detail::format("read {}", transport_.name()));
		} else if (const auto *x = std::get_if<extended_response>(&m->op); x == nullptr) {
			fatal = unexpected(std::string(op_name(m->op)) + " with message id 0");
		} else if (x->response_name && *x->response_name == notice_of_disconnection_oid) {
			error e = x->result.to_error("notice of disconnection");
			if (x->result.is_success()) {
				e.code = errc::unavailable;// "success" is no error code
			}
			fatal = std::move(e);
		}
		// Other extended responses with id 0 are ignored.
	}
	scratch.release();
	if (fatal) {
		shut(*fatal, true);
	}
}

auto connection::core::make_stream(search_stream::state *s) noexcept -> ldap::search_stream
{
	return ldap::search_stream(s);
}

auto connection::core::make_paged(paged_search::state *s) noexcept -> ldap::paged_search
{
	return ldap::paged_search(s);
}

// ---------------------------------------------------------------- waiting

auto connection::core::next_response(pending_op &p, std::optional<clock::time_point> deadline, std::string_view context)
  -> capy::task<result<message>>
{
	while (p.queue.empty() && !p.finished) {
		p.ready.clear();
		std::error_code ec;
		if (deadline) {
			auto [e] = co_await corosio::timeout(p.ready.wait(), *deadline);
			ec = e;
		} else {
			auto [e] = co_await p.ready.wait();
			ec = e;
		}
		if (!ec) {
			continue;
		}
		// Cancelled or timed out before the response came.
		if (!p.queue.empty() || p.finished) {
			break;// it came anyway: use it
		}
		const bool was_open = open;
		abandon(p);
		// The code says canceled or timed out; the context adds what
		// became of the request.
		std::string text(context);
		if (was_open) {
			text += p.abandonable ? " (abandoned)" : " (connection closed)";
		}
		co_return fail(ec, text);
	}
	if (!p.queue.empty()) {
		message m = std::move(p.queue.front());// same resource: moved, not copied
		p.queue.pop_front();
		co_return m;
	}
	if (p.failure) {
		co_return std::unexpected(detail::with_context(*p.failure, context));
	}
	co_return std::unexpected(not_connected(context));// closed by close() or unbind()
}

// ---------------------------------------------------------------- binds

auto connection::core::begin_bind(core_ref c, std::string_view context) -> capy::task<result<void>>
{
	while (c->binding) {
		auto [ec] = co_await c->bind_idle.wait();
		if (ec) {
			co_return fail(ec, context);
		}
	}
	// The analyzer does not model the promise's construction: Capy's env_ is
	// nullptr-initialised and set by the awaiting caller before the first resume.
	// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
	if ((co_await capy::this_coro::stop_token).stop_requested()) {
		co_return fail(capy::error::canceled, context);
	}
	c->binding = true;
	++c->binds_begun;
	c->publish();
	c->bind_idle.clear();
	co_return result<void>{};
}

connection::core::bind_scope::~bind_scope()
{
	c_->armed_layer.reset();
	c_->binding = false;
	c_->bind_idle.set();
	c_->release_held();
}

// ---------------------------------------------------------------- requests

namespace detail {

	auto request_response(core_ref self,
	  message request,
	  std::size_t expect,
	  std::string context,
	  std::optional<std::chrono::milliseconds> timeout,
	  std::pmr::vector<intermediate> *intermediates) -> capy::task<result<message>>
	{
		if (!std::holds_alternative<bind_request>(request.op)
			// The analyzer does not model the promise's construction: Capy's env_ is
			// nullptr-initialised and set by the awaiting caller before the first resume.
			// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
			&& (co_await capy::this_coro::stop_token).stop_requested()) {
			co_return fail(capy::error::canceled, context);
		}
		pending_op p(self->mr(), false, expect);
		p.intermediates = intermediates != nullptr;
		if (auto r = self->submit(request, &p, context); !r) {
			co_return std::unexpected(std::move(r.error()));
		}
		const auto reg = detail::registration(*self, p);
		const auto deadline = deadline_after(timeout ? timeout : self->default_timeout());
		while (true) {
			auto m = co_await self->next_response(p, deadline, context);
			if (!m || intermediates == nullptr || !std::holds_alternative<intermediate_response>(m->op)) {
				co_return m;
			}
			// On the vector's resource (uses-allocator construction).
			intermediates->emplace_back(std::move(std::get<intermediate_response>(m->op)), std::move(m->controls));
		}
	}

}// namespace detail

}// namespace jhetz::ldap
