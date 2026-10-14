#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/message_io.hpp"

#include "connection/sasl_offload.hpp"
#include "format_util.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/frame_allocator.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/detail/scheduler.hpp>
#include <boost/corosio/timeout.hpp>

#include <algorithm>
#include <array>
#include <charconv>
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

namespace detail {

	inline constexpr std::array<std::string_view, 21> op_names{ "BindRequest",
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

	std::string_view op_name(const protocol_op &op) noexcept { return op_names[op.index()]; }

	template<class T, class... Ts> consteval std::size_t index_in(const std::variant<Ts...> *)
	{
		constexpr bool same[] = { std::is_same_v<T, Ts>... };
		for (std::size_t i = 0; i < sizeof...(Ts); ++i)
			if (same[i]) return i;
		return sizeof...(Ts);
	}
	template<class T> inline constexpr std::size_t op_index = index_in<T>(static_cast<const protocol_op *>(nullptr));

	// RFC 4511 protocolOp tags of the responses the reader recognizes before
	// decoding.
	inline constexpr ber::tag search_result_done_tag = ber::application(5, true);
	inline constexpr ber::tag intermediate_response_tag = ber::application(25, true);

	bool same_tag(ber::tag a, ber::tag b) noexcept { return a.cls == b.cls && a.number == b.number; }

	using clock = std::chrono::steady_clock;

	std::optional<clock::time_point> deadline_after(std::optional<std::chrono::milliseconds> d)
	{
		if (!d) return std::nullopt;
		return clock::now() + *d;
	}

}// namespace detail

using detail::clock;
using detail::deadline_after;
using detail::intermediate_response_tag;
using detail::op_context;
using detail::op_index;
using detail::op_name;
using detail::op_names;
using detail::same_tag;
using detail::search_result_done_tag;

namespace {

	// Abandoned requests whose late responses are still dropped. Older ones
	// are forgotten: a response for them would then be unexpected.
	constexpr std::size_t max_abandoned = 1024;

}// namespace

// ---------------------------------------------------------------- state

namespace detail {

	// One outstanding request: registered with the connection by message id
	// while it waits for responses. Lives in the operation's coroutine frame
	// (bind) or in a search_stream's state.
	struct pending_op
	{
		explicit pending_op(std::pmr::memory_resource *mr_, bool search_, std::size_t expect_)
		  : mr(mr_), search(search_), expect(expect_), queue(mr_)
		{}
		pending_op(const pending_op &) = delete;
		pending_op &operator=(const pending_op &) = delete;

		std::pmr::memory_resource *mr;// responses are decoded into this
		bool search;// many responses, until a SearchResultDone
		std::size_t expect;// protocol_op index of the (final) response
		std::int32_t id = 0;
		bool registered = false;
		// False for Bind and StartTLS, which cannot be abandoned (RFC 4511
		// section 4.11): giving up on them closes the connection instead.
		bool abandonable = true;
		std::pmr::deque<message> queue;// on mr, so messages move in without a copy
		bool finished = false;// final response queued, or failed / abandoned
		std::optional<error> failure{};// connection failure (without op context)
		capy::async_event ready{};// set while queue is non-empty or finished
	};

}// namespace detail

using detail::pending_op;

struct connection::impl
{
	impl(corosio::io_context &ioc, net::transport t, const connection_options &options, std::pmr::memory_resource *mr_)
	  : ex(ioc.get_executor()), mr(mr_), transport(std::move(t)), buf(mr_), max_message_size(options.max_message_size),
		max_elements(options.max_elements), default_timeout(options.operation_timeout),
		tls_shutdown_timeout(options.tls_shutdown_timeout), pending(mr_), abandoned(mr_), outbox(mr_), held(mr_),
		scratch(mr_)
	{
		schema_mode = options.schema_check;
		password_mode = options.password_method;
		write_idle.set();
		reader_idle.set();
		bind_idle.set();
		due_idle.set();
	}

	corosio::io_context::executor_type ex;
	std::pmr::memory_resource *mr;
	std::size_t refs = 1;
	net::transport transport;
	net::read_buffer buf;
	std::size_t max_message_size;
	std::size_t max_elements;
	std::optional<std::chrono::milliseconds> default_timeout;
	std::optional<std::chrono::milliseconds> tls_shutdown_timeout;
	std::int32_t next_id = 1;
	bool wrapped = false;// next_id went past maxInt: ids may be in use
	bool open = true;
	// unbind() sent its UnbindRequest and waits for the writer: still open,
	// but nothing more may be sent (RFC 4511 section 4.3).
	bool unbinding = false;
	std::optional<error> failure{};// why the connection closed, if it failed
	std::pmr::unordered_map<std::int32_t, pending_op *> pending;
	struct abandoned_req
	{
		std::int32_t id;
		bool search;
		// Sent by send_unanswered: an answer is certain (an abandoned
		// request may or may not be answered), until `deadline`, after
		// which it is no longer waited for (but still dropped if it comes).
		bool due = false;
		std::optional<clock::time_point> deadline{};
	};
	std::pmr::deque<abandoned_req> abandoned;
	// Entries of `abandoned` that are `due`: requests still to be answered
	// although nothing waits for them. Counted as outstanding, so StartTLS
	// waits for their answers (RFC 4513 section 3.1.1), and read by the
	// reader, which runs while there are any.
	std::size_t due_answers = 0;
	capy::async_event due_idle{};// set while due_answers is 0 (shut sets it after unbind)
	// The due watcher: runs while a due answer has a deadline, and stops
	// counting it once that passes. Woken by `due_changed` when the due
	// answers change.
	bool watching = false;
	capy::async_event due_changed{};
	// Writer: PDUs waiting to be written, in order.
	std::pmr::deque<std::pmr::vector<std::byte>> outbox;
	bool writing = false;
	capy::async_event write_idle{};// set while the writer is not running
	// A bind exchange (every step of a SASL bind) is in progress: other
	// requests are held until it ends, since nothing may be sent while a
	// BindRequest is outstanding (RFC 4511 section 4.2.1).
	bool binding = false;
	capy::async_event bind_idle{};// set while `binding` is false
	struct held_request
	{
		std::int32_t id;
		std::pmr::vector<std::byte> bytes;
	};
	std::pmr::deque<held_request> held;
	// Reader: runs while `pending` is not empty or answers are due.
	bool reading = false;
	std::stop_source reader_stop{};
	capy::async_event reader_idle{};// set while the reader is not running
	// StartTLS in progress: no other request may be sent (RFC 4511 4.14.1),
	// and is_tls() is false (the TLS layer is set before the handshake).
	bool upgrading = false;
	// schema_check::on_first_use: the loaded schema and the types checked.
	ldap::schema_check schema_mode = ldap::schema_check::off;
	std::shared_ptr<const server_schema> schema{};
	std::vector<std::type_index> schema_checked{};
	// change_password / reset_password: the connection's default method, and
	// the one the root DSE advertised (password_method::automatic), once read.
	ldap::password_method password_mode = ldap::password_method::automatic;
	std::optional<ldap::password_method> advertised_password_method{};
	// Unsolicited notifications are decoded here, then released.
	std::pmr::monotonic_buffer_resource scratch;

	// ---------------------------------------------------------------- refs

	void add_ref() noexcept { ++refs; }
	void release() noexcept
	{
		if (--refs != 0) return;
		std::pmr::polymorphic_allocator<> alloc(mr);
		alloc.delete_object(this);
	}

	// Held by the writer and reader frames, so the state is released even
	// if a frame is destroyed without finishing (io_context destroyed).
	struct frame_ref
	{
		impl *p;
		explicit frame_ref(impl *p_) noexcept : p(p_) {}
		frame_ref(const frame_ref &) = delete;
		frame_ref &operator=(const frame_ref &) = delete;
		~frame_ref() { p->release(); }
	};

	// ---------------------------------------------------------------- failure

	// A copy of `e`, or if there is no memory for it, an out_of_memory():
	// for paths that must not throw.
	static error copy_error(const error &e) noexcept
	{
		try {
			return e;
		} catch (const std::bad_alloc &) {
			return out_of_memory();
		}
	}

	// not_enough_memory without a context, so building and copying it
	// allocates nothing; operations add their own.
	static error out_of_memory() noexcept
	{
		error e;
		e.code = std::make_error_code(std::errc::not_enough_memory);
		return e;
	}

	// Closes the transport and fails every outstanding operation with `e`
	// (they add their own context). `remember`: later operations name it.
	// `close_transport` false: the caller closes it (unbind, after the TLS
	// shutdown). Never throws: destructors and the detached tasks call it.
	void shut(error e, bool remember, bool close_transport = true) noexcept
	{
		if (!open) return;
		open = false;
		if (remember) failure = copy_error(e);
		if (close_transport) transport.close();
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
			p->failure = copy_error(e);
			p->ready.set();
		}
		if (reading) reader_stop.request_stop();
	}

	// An allocation failed where no exception may go: in a destructor (an
	// AbandonRequest, the requests a bind held) or a detached task (the
	// writer, the reader, the due watcher). What was to be sent or read is
	// lost, so the connection cannot go on: it is closed, and its
	// operations fail with not_enough_memory instead of waiting for what
	// never comes.
	void shut_out_of_memory() noexcept { shut(out_of_memory(), true); }

	error not_connected(std::string_view context) const
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

	// ---------------------------------------------------------------- tasks

	// The frame of a detached task (writer, reader, due watcher), from the
	// executor's frame allocator as capy::run_async would use. Made before
	// the caller sets its flags: a bad_alloc then leaves no flag set without
	// its task. (capy::run_async allocates its own frame before the task's;
	// a task frame failing there would leak it, and its work guard.)
	// Known limitations, outside this library, where an allocation failing
	// ends the program, whatever the caller catches:
	// - capy::run_async allocates its own frame (the trampoline) in a
	//   noexcept constructor;
	// - corosio::timeout builds its timer (and grows the timer heap) and
	//   starts its timeout coroutine (a frame) in await_suspend, which
	//   capy's task calls from a noexcept wrapper (transform_awaiter): the
	//   due watcher, next_response and start_tls's wait for due answers
	//   with a deadline, and net::detail::bounded (connect, TLS handshake
	//   and shutdown with a deadline). Its awaitable's std::stop_source,
	//   made when the co_await is evaluated (before await_suspend), throws
	//   bad_alloc normally: caught by the due watcher, propagated by the
	//   others.
	capy::task<void> new_task(capy::task<void> (*body)(impl *))
	{
		struct frame_allocator_scope
		{
			std::pmr::memory_resource *saved = capy::get_current_frame_allocator();
			explicit frame_allocator_scope(std::pmr::memory_resource *mr) noexcept
			{
				capy::set_current_frame_allocator(mr);
			}
			frame_allocator_scope(const frame_allocator_scope &) = delete;
			frame_allocator_scope &operator=(const frame_allocator_scope &) = delete;
			~frame_allocator_scope() { capy::set_current_frame_allocator(saved); }
		};
		const frame_allocator_scope scope(ex.context().get_frame_allocator());
		return body(this);
	}

	// ---------------------------------------------------------------- writer

	// A bad_alloc in a detached task would end the program (run_async's
	// default handler): each catches its own and closes the connection.
	static capy::task<void> writer(impl *self)
	{
		const frame_ref ref(self);
		try {
			while (self->open && !self->outbox.empty()) {
				auto bytes = std::move(self->outbox.front());
				self->outbox.pop_front();
				auto w = co_await net::write_bytes(self->transport, bytes);
				if (!w) self->shut(std::move(w.error()), true);
			}
		} catch (const std::bad_alloc &) {
			self->shut_out_of_memory();
		}
		self->writing = false;
		self->write_idle.set();
	}

	// Queues `bytes` and starts the writer if it is not running. A throw
	// (bad_alloc) queues nothing and changes nothing.
	void enqueue(std::pmr::vector<std::byte> bytes)
	{
		if (writing) {
			outbox.push_back(std::move(bytes));
			return;
		}
		auto task = new_task(&writer);
		outbox.push_back(std::move(bytes));
		writing = true;
		write_idle.clear();
		add_ref();// released by the writer
		// No stop token: a PDU is always written whole (a cancelled write
		// would leave half a PDU on the wire).
		capy::run_async(ex)(std::move(task));
	}

	// The next message id the server cannot still be servicing (RFC 4511
	// section 4.1.1): after wrapping at maxInt, ids of outstanding or
	// recently abandoned requests are skipped.
	std::int32_t free_id() const
	{
		std::int32_t id = next_id;
		if (!wrapped) return id;// ids so far only increased: none is in use
		auto in_use = [this](std::int32_t i) {
			return pending.contains(i) || std::ranges::contains(abandoned, i, &abandoned_req::id);
		};
		while (in_use(id)) id = id == max_int ? 1 : id + 1;
		return id;
	}

	// Gives `m` the next free message id, encodes it and queues it for the
	// writer. If `p` is given it is registered under that id first (its
	// response may arrive before the write completes). If encoding fails
	// nothing is sent and the id is not used up. On a throw (bad_alloc)
	// nothing is queued and `p` is not registered (the id is used up).
	result<void> submit(message &m, pending_op *p, std::string_view context)
	{
		if (!open || unbinding) return std::unexpected(not_connected(context));
		if (upgrading && !std::holds_alternative<abandon_request>(m.op))
			return fail(client_errc::operation_in_progress, std::string(context) + " during StartTLS");
		m.id = free_id();
		auto bytes = encode(m, mr);
		if (!bytes) return std::unexpected(detail::with_context(std::move(bytes.error()), context));
		if (m.id == max_int) wrapped = true;
		next_id = m.id == max_int ? 1 : m.id + 1;
		const bool bind = std::holds_alternative<bind_request>(m.op);
		if (p != nullptr) {
			const auto *x = std::get_if<extended_request>(&m.op);
			p->abandonable = !bind && (x == nullptr || x->request_name != start_tls_oid);
			p->id = m.id;
			pending.emplace(m.id, p);
			p->registered = true;
		}
		try {
			if (p != nullptr) start_reader();
			if (binding && !bind)
				held.push_back({ m.id, std::move(*bytes) });
			else
				enqueue(std::move(*bytes));
		} catch (...) {
			// `p` (in the caller's frame) must not stay registered: its
			// request is not sent.
			if (p != nullptr) {
				pending.erase(m.id);
				p->registered = false;
				stop_reader_if_idle();
			}
			throw;
		}
		return {};
	}

	// The bind exchange ended: sends the requests it held, in order. Called
	// from a destructor: if one cannot be queued, the connection is closed
	// (the held requests fail with not_enough_memory).
	void release_held() noexcept
	{
		try {
			while (open && !held.empty()) {
				enqueue(std::move(held.front().bytes));
				held.pop_front();
			}
		} catch (const std::bad_alloc &) {
			shut_out_of_memory();
		}
		held.clear();
	}

	// Stops waiting for `p`'s responses and tells the server (best effort).
	// Called from destructors: if the AbandonRequest cannot be built or
	// queued, the connection is closed (a late response would then match
	// no request).
	void abandon(pending_op &p) noexcept
	{
		if (!p.registered) return;
		p.registered = false;
		p.finished = true;
		pending.erase(p.id);
		stop_reader_if_idle();
		if (!open) return;
		try {
			if (!p.abandonable) {
				shut(make_error(client_errc::not_connected,
					   "connection closed: a Bind or StartTLS request cannot be abandoned (RFC 4511 section 4.11)"),
				  true);
				return;
			}
			// Held by a bind exchange, so never sent: nothing to tell the server.
			auto h = std::ranges::find(held, p.id, &held_request::id);
			if (h != held.end()) {
				held.erase(h);
				return;
			}
			abandoned.push_back({ p.id, p.search });
			trim_abandoned();
			message m{ 0, abandon_request{ p.id } };
			(void)submit(m, nullptr, "abandon");// cannot fail to encode
		} catch (const std::bad_alloc &) {
			shut_out_of_memory();
		}
	}

	// Sends `m` without waiting for an answer: its responses are dropped like
	// late responses to an abandoned request. `m` must be a request that is
	// always answered: the answer is counted as `due` until it arrives or
	// `deadline` passes, and a reader is started to read it. Best effort:
	// nothing is sent if the connection is closed or cannot send `m` now.
	// Never suspends.
	void send_unanswered(message &m, bool search, std::optional<clock::time_point> deadline, std::string_view context)
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
		abandoned.push_back({ 0, search });
		try {
			if (!submit(m, nullptr, context)) {
				abandoned.pop_back();
				return;
			}
		} catch (...) {
			if (!abandoned.empty()) abandoned.pop_back();
			throw;
		}
		if (!open) return;
		abandoned.back().id = m.id;
		abandoned.back().due = true;
		abandoned.back().deadline = deadline;
		++due_answers;
		due_updated();
		trim_abandoned();
		start_reader();
		if (deadline) start_due_watcher();
	}

	// Forgets an abandoned request: a later response for it is unexpected.
	void forget_abandoned(std::pmr::deque<abandoned_req>::iterator a)
	{
		const bool due = a->due;
		if (due) --due_answers;
		abandoned.erase(a);
		if (due) due_updated();
		stop_reader_if_idle();
	}

	// Forgets an abandoned request if there are too many: the oldest whose
	// answer is not due (those are the least likely to still come), else
	// the oldest. Never the one just added.
	void trim_abandoned()
	{
		if (abandoned.size() <= max_abandoned) return;
		auto a = std::ranges::find(abandoned.begin(), std::prev(abandoned.end()), false, &abandoned_req::due);
		forget_abandoned(a != std::prev(abandoned.end()) ? a : abandoned.begin());
	}

	// due_answers changed: wakes a StartTLS waiting for 0, and the due
	// watcher.
	void due_updated()
	{
		if (due_answers == 0)
			due_idle.set();
		else
			due_idle.clear();
		due_changed.set();
	}

	// ---------------------------------------------------------------- due answers

	void start_due_watcher()
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

	// The earliest deadline of a due answer, if any has one.
	std::optional<clock::time_point> next_due_deadline() const
	{
		std::optional<clock::time_point> next;
		for (const auto &a : abandoned)
			if (a.due && a.deadline && (!next || *a.deadline < *next)) next = a.deadline;
		return next;
	}

	// Due answers whose deadline passed are no longer waited for: their
	// entries stay (a late answer is still dropped), but they are not
	// counted, so StartTLS proceeds and the reader can stop.
	void expire_due(clock::time_point now)
	{
		bool changed = false;
		for (auto &a : abandoned) {
			if (!a.due || !a.deadline || *a.deadline > now) continue;
			a.due = false;
			--due_answers;
			changed = true;
		}
		if (!changed) return;
		due_updated();
		stop_reader_if_idle();
	}

	// Sleeps until the next deadline of a due answer (or a change), then
	// expires what is past. Ends when no due answer has a deadline, so an
	// idle connection holds no timer and `io_context::run()` can return.
	// No stop token: it ends on its own when the due answers do (or when
	// the connection closes).
	// Its only allocations are corosio::timeout's. The catch sees the one
	// made when the co_await is evaluated: the awaitable's std::stop_source
	// (its shared state, from the global operator new). The timer, the
	// timer heap's growth and the timeout coroutine's frame are made in an
	// await_suspend that capy calls from a noexcept wrapper, so one of
	// those failing ends the program (a known limitation, see new_task).
	static capy::task<void> due_watcher(impl *self)
	{
		const frame_ref ref(self);
		try {
			while (self->open) {
				const auto next = self->next_due_deadline();
				if (!next) break;
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

	// Requests still to be answered: those waited for, and `due` answers.
	std::size_t outstanding() const noexcept { return pending.size() + due_answers; }

	// ---------------------------------------------------------------- reader

	void start_reader()
	{
		if (reading) return;// a reader that is stopping restarts itself if needed
		std::stop_source stop;
		auto task = new_task(&reader);
		reading = true;
		reader_idle.clear();
		reader_stop = std::move(stop);
		add_ref();// released by the reader
		capy::run_async(ex, reader_stop.get_token())(std::move(task));
	}

	void stop_reader_if_idle()
	{
		if (outstanding() == 0 && reading) reader_stop.request_stop();
	}

	static capy::task<void> reader(impl *self)
	{
		const frame_ref ref(self);
		try {
			while (self->open && self->outstanding() != 0) {
				auto size = co_await net::read_frame(self->transport, self->buf, self->max_message_size);
				if (!size) {
					// Stopped because nothing is outstanding (bytes already
					// received stay in buf), or a real failure.
					if (size.error().code == capy::cond::canceled && self->open) break;
					self->shut(std::move(size.error()), true);
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
			if (self->open && self->outstanding() != 0) self->start_reader();
		} catch (const std::bad_alloc &) {
			self->shut_out_of_memory();
		}
	}

	error unexpected(std::string text)
	{
		return make_error(client_errc::unexpected_response, detail::format("read {}: {}", transport.name(), text));
	}

	// Delivers the PDU at the front of buf (`size` bytes) and consumes it.
	void route(std::size_t size)
	{
		const auto bytes = buf.data().first(size);
		auto h = peek_message_header(bytes);
		if (!h) {
			buf.consume(size);
			shut(detail::with_context(std::move(h.error()), detail::format("read {}", transport.name())), true);
			return;
		}
		if (h->id == 0) {
			notification(bytes);
			buf.consume(size);
			return;
		}
		if (auto it = pending.find(h->id); it != pending.end()) {
			pending_op &p = *it->second;
			if (same_tag(h->op, intermediate_response_tag)) {
				buf.consume(size);// skipped, not decoded
				return;
			}
			auto m = decode(bytes, { .from = origin::server, .max_elements = max_elements, .memory = p.mr });
			buf.consume(size);
			if (!m) {
				shut(detail::with_context(std::move(m.error()), detail::format("read {}", transport.name())), true);
				return;
			}
			const std::size_t index = m->op.index();
			const bool final = index == p.expect;
			const bool streamed =
			  p.search && (index == op_index<search_result_entry> || index == op_index<search_result_reference>);
			if (!final && !streamed) {
				shut(unexpected(detail::format("{} with message id {} in response to a {}",
					   op_name(m->op),
					   h->id,
					   p.search ? std::string_view("SearchRequest") : op_names[p.expect - 1])),
				  true);
				return;
			}
			p.queue.push_back(std::move(*m));
			if (final) {
				p.finished = true;
				p.registered = false;
				pending.erase(it);
				stop_reader_if_idle();
			}
			p.ready.set();
			return;
		}
		buf.consume(size);
		auto a = std::ranges::find(abandoned, h->id, &abandoned_req::id);
		if (a != abandoned.end()) {
			// A late response to an abandoned request: dropped. The search's
			// SearchResultDone (or any response to another request) is its
			// last.
			if (!a->search || same_tag(h->op, search_result_done_tag)) forget_abandoned(a);
			return;
		}
		shut(unexpected(detail::format("message with id {}, which matches no outstanding request", h->id)), true);
	}

	// An unsolicited notification (message id 0, RFC 4511 section 4.4).
	void notification(std::span<const std::byte> bytes)
	{
		std::optional<error> fatal;
		{
			auto m = decode(bytes, { .from = origin::server, .max_elements = max_elements, .memory = &scratch });
			if (!m) {
				fatal = detail::with_context(std::move(m.error()), detail::format("read {}", transport.name()));
			} else if (const auto *x = std::get_if<extended_response>(&m->op); x == nullptr) {
				fatal = unexpected(std::string(op_name(m->op)) + " with message id 0");
			} else if (x->response_name && *x->response_name == notice_of_disconnection_oid) {
				error e = x->result.to_error("notice of disconnection");
				if (x->result.is_success()) e.code = errc::unavailable;// "success" is no error code
				fatal = std::move(e);
			}
			// Other extended responses with id 0 are ignored.
		}
		scratch.release();
		if (fatal) shut(std::move(*fatal), true);
	}

	// search_stream / paged_search constructors are private.
	static ldap::search_stream make_stream(search_stream::state *s) noexcept { return ldap::search_stream(s); }
	static ldap::paged_search make_paged(paged_search::state *s) noexcept { return ldap::paged_search(s); }

	// ---------------------------------------------------------------- waiting

	// The next response for `p`, waiting until `deadline` at most. On
	// cancellation or timeout `p` is abandoned. Errors carry `context`.
	capy::task<result<message>>
	  next_response(pending_op &p, std::optional<clock::time_point> deadline, std::string_view context)
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
			if (!ec) continue;
			// Cancelled or timed out before the response came.
			if (!p.queue.empty() || p.finished) break;// it came anyway: use it
			const bool was_open = open;
			abandon(p);
			// The code says canceled or timed out; the context adds what
			// became of the request.
			std::string text(context);
			if (was_open) text += p.abandonable ? " (abandoned)" : " (connection closed)";
			co_return fail(ec, text);
		}
		if (!p.queue.empty()) {
			message m = std::move(p.queue.front());// same resource: moved, not copied
			p.queue.pop_front();
			co_return m;
		}
		if (p.failure) co_return std::unexpected(detail::with_context(*p.failure, context));
		co_return std::unexpected(not_connected(context));// closed by close() or unbind()
	}
};

namespace detail {

	// A counted reference to the connection state.
	class impl_ref
	{
	  public:
		impl_ref() noexcept = default;
		explicit impl_ref(connection::impl *p) noexcept : p_(p)
		{
			if (p_ != nullptr) p_->add_ref();
		}
		impl_ref(const impl_ref &o) noexcept : impl_ref(o.p_) {}
		impl_ref(impl_ref &&o) noexcept : p_(std::exchange(o.p_, nullptr)) {}
		impl_ref &operator=(impl_ref o) noexcept
		{
			std::swap(p_, o.p_);
			return *this;
		}
		~impl_ref()
		{
			if (p_ != nullptr) p_->release();
		}
		connection::impl *operator->() const noexcept { return p_; }
		connection::impl &operator*() const noexcept { return *p_; }
		explicit operator bool() const noexcept { return p_ != nullptr; }

	  private:
		connection::impl *p_ = nullptr;
	};

	// Abandons `p` if the operation's task is destroyed (or returns early)
	// while the request is still outstanding.
	struct registration
	{
		connection::impl &c;
		pending_op &p;
		registration(connection::impl &c_, pending_op &p_) noexcept : c(c_), p(p_) {}
		registration(const registration &) = delete;
		registration &operator=(const registration &) = delete;
		~registration() { c.abandon(p); }
	};

}// namespace detail

using detail::impl_ref;
using detail::registration;

namespace {

	error no_connection(std::string_view context) { return make_error(client_errc::not_connected, context); }

	// Waits until no other bind exchange is in progress (binds are
	// serialized), then marks this one as in progress; bind_exchange ends it.
	// A bind already given up on is not sent: a bind cannot be abandoned, so
	// sending it would only close the connection. The stop is checked after
	// the wait, right before the bind is sent: a stop that comes once
	// bind_idle.set() has claimed the waiter, but before it resumes, does
	// not cancel the wait.
	capy::task<result<void>> begin_bind(impl_ref c, std::string_view context)
	{
		while (c->binding) {
			auto [ec] = co_await c->bind_idle.wait();
			if (ec) co_return fail(ec, context);
		}
		if ((co_await capy::this_coro::stop_token).stop_requested()) co_return fail(capy::error::canceled, context);
		c->binding = true;
		c->bind_idle.clear();
		co_return result<void>{};
	}

	// Ends the bind exchange begun by begin_bind() and sends the requests
	// it held.
	struct bind_exchange
	{
		impl_ref c;
		explicit bind_exchange(impl_ref c_) noexcept : c(std::move(c_)) {}
		bind_exchange(const bind_exchange &) = delete;
		bind_exchange &operator=(const bind_exchange &) = delete;
		~bind_exchange()
		{
			c->binding = false;
			c->bind_idle.set();
			c->release_held();
		}
	};

}// namespace

// ---------------------------------------------------------------- search_stream state

struct search_stream::state
{
	state(connection::impl *c, std::pmr::memory_resource *entries, std::string context_)
	  : conn(c), op(entries, true, op_index<search_result_done>), context(std::move(context_))
	{}

	impl_ref conn;
	pending_op op;
	std::string context;// "search <base>"
	std::optional<clock::time_point> deadline{};
	bool in_next = false;
	bool finished = false;
	std::optional<error> error_{};
	string_list references{};
	std::pmr::vector<control> controls{};
};

namespace {

	search_stream::state *new_state(connection::impl &c, std::pmr::memory_resource *entries, std::string context)
	{
		std::pmr::polymorphic_allocator<> alloc(c.mr);
		return alloc.new_object<search_stream::state>(&c, entries, std::move(context));
	}

	void delete_state(search_stream::state *s) noexcept
	{
		if (s == nullptr) return;
		s->conn->abandon(s->op);
		impl_ref keep = s->conn;// the state lives on the connection's resource
		std::pmr::polymorphic_allocator<> alloc(keep->mr);
		alloc.delete_object(s);
	}

}// namespace

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

// Describes the open connection: false after close(), unbind() or a failure,
// even though the closed transport still holds its TLS layer. False during
// start_tls() too: the TLS layer is in place before its handshake runs.
bool connection::is_tls() const noexcept { return is_open() && !impl_->upgrading && impl_->transport.is_tls(); }

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

namespace detail {

	// One request with one response (everything but search): sends it,
	// waits for the response of index `expect` and returns it. `self` keeps
	// the state alive across the suspension. One whose stop token is set
	// already is not sent (sending it would only abandon it at once, and an
	// update might be applied): it fails with capy::error::canceled. Binds
	// are checked by begin_bind() instead: a later step of a SASL exchange
	// is sent, since the server waits for it (abandoning it then closes the
	// connection).
	capy::task<result<message>> request_response(impl_ref self,
	  message request,
	  std::size_t expect,
	  std::string context,
	  std::optional<std::chrono::milliseconds> timeout)
	{
		if (!std::holds_alternative<bind_request>(request.op)
			&& (co_await capy::this_coro::stop_token).stop_requested())
			co_return fail(capy::error::canceled, context);
		pending_op p(self->mr, false, expect);
		if (auto r = self->submit(request, &p, context); !r) co_return std::unexpected(std::move(r.error()));
		registration reg(*self, p);
		co_return co_await self->next_response(p, deadline_after(timeout ? timeout : self->default_timeout), context);
	}

}// namespace detail

using detail::request_response;

namespace {

	// Ends a SASL exchange the client gives up on while the server waits for
	// its next step: until then the server refuses other operations (RFC
	// 4511 section 4.2.1). An anonymous simple bind aborts it. A
	// BindResponse ends the exchange, even a refusal (a server that disallows
	// anonymous binds): the connection is then anonymous and stays open. The
	// exception is saslBindInProgress, which cannot answer a simple bind (RFC
	// 4511 section 4.2.2), and the server may still be in the exchange, so
	// the connection is closed. Without a response (timeout, stop, transport
	// error) the connection is already closed: a bind cannot be abandoned.
	capy::task<void> abort_sasl(impl_ref self, const std::string &context)
	{
		message request(std::pmr::polymorphic_allocator<>(self->mr));
		request.op = bind_request(3, {}, simple_auth(std::string_view(), self->mr), self->mr);
		auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
		if (!m) co_return;
		const auto &r = std::get<bind_response>(m->op);// checked by the reader
		if (r.result.result_code != std::to_underlying(errc::sasl_bind_in_progress)) co_return;
		std::string text = context + ": connection closed: the SASL exchange could not be aborted: ";
		text += "saslBindInProgress in answer to a simple bind";
		self->shut(make_error(client_errc::unexpected_response, text), true);
	}

	// The ldap_result of a response, whatever the operation.
	const ldap_result &result_of(const message &m)
	{
		return std::visit(
		  [](const auto &op) -> const ldap_result & {
			  if constexpr (requires { op.result; })
				  return op.result;
			  else
				  throw std::logic_error("ldap: response without an LDAPResult");// the reader checked the operation
		  },
		  m.op);
	}

	// A response that only carries an LDAPResult: success gives its
	// controls, anything else the error.
	result<response> to_response(result<message> m, std::string_view context)
	{
		if (!m) return std::unexpected(std::move(m.error()));
		const ldap_result &r = result_of(*m);
		if (!r.is_success()) return std::unexpected(r.to_error(context));
		response out;
		out.controls.assign(m->controls.begin(), m->controls.end());
		return out;
	}

	// Builds a message whose controls are `controls` (encoded on `mr`).
	result<message> with_controls(protocol_op op,
	  const request_controls &controls,
	  std::pmr::memory_resource *mr,
	  std::string_view context)
	{
		message m{ std::pmr::polymorphic_allocator<>(mr) };
		m.op = std::move(op);
		if (auto c = append_controls(controls, m.controls); !c)
			return std::unexpected(detail::with_context(std::move(c.error()), context));
		return m;
	}

}// namespace

namespace detail {

	// The SearchRequest for `p`, validated (errors carry `context`).
	result<message> search_message(connection::impl &c, const search_params &p, const std::string &context)
	{
		const auto seconds = p.time_limit.count();
		if (seconds < 0 || seconds > max_int)
			return fail(client_errc::encode_error,
			  detail::format("{}: time_limit of {} s is outside 0 .. 2^31-1", context, seconds));

		const std::pmr::polymorphic_allocator<> alloc(c.mr);
		search_request wire(alloc);
		wire.base_object = p.base.to_string(c.mr);
		wire.scope = p.scope;
		wire.deref = p.deref;
		wire.size_limit = p.size_limit;
		wire.time_limit = static_cast<std::int32_t>(seconds);
		wire.types_only = p.types_only;
		wire.filter = p.filter;
		wire.attributes.assign(p.attributes.begin(), p.attributes.end());
		return with_controls(std::move(wire), p.controls, c.mr, context);
	}

	// Validates and sends a search; returns its stream. Never suspends.
	// `stop` is the awaiting task's stop token: if it is set already, the
	// search is not sent and fails with capy::error::canceled.
	result<ldap::search_stream>
	  start_search(connection::impl &c, search_params &p, std::pmr::memory_resource *mr, const std::stop_token &stop)
	{
		std::string context = op_context("search", p.base);
		auto request = search_message(c, p, context);
		if (!request) return std::unexpected(std::move(request.error()));
		if (stop.stop_requested()) return fail(capy::error::canceled, context);

		auto *state = new_state(c, mr, context);
		ldap::search_stream s = connection::impl::make_stream(state);
		state->deadline = deadline_after(p.timeout ? p.timeout : c.default_timeout);
		if (auto r = c.submit(*request, &state->op, context); !r) return std::unexpected(std::move(r.error()));
		return s;
	}

}// namespace detail

using detail::search_message;
using detail::start_search;

capy::task<result<void>> connection::simple_bind(dn name, std::string password)
{
	std::string context = op_context("bind", name);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	if (!name.empty() && password.empty())
		co_return fail(client_errc::unauthenticated_bind, context + ": empty password (RFC 4513 section 5.1.2)");
	impl_ref self(impl_);// `this` may be moved from while suspended
	if (auto b = co_await begin_bind(self, context); !b) co_return std::unexpected(std::move(b.error()));
	const bind_exchange exchange{ self };
	message request(std::pmr::polymorphic_allocator<>(self->mr));
	request.op = bind_request(3, name.to_string(self->mr), simple_auth(password, self->mr), self->mr);
	auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
	if (!m) co_return std::unexpected(std::move(m.error()));
	const auto &r = std::get<bind_response>(m->op);// checked by the reader
	if (!r.result.is_success()) co_return std::unexpected(r.result.to_error(context));
	co_return result<void>{};
}

capy::task<result<void>> connection::sasl_bind(sasl_mechanism &mechanism, dn name)
{
	std::string context = "sasl bind ";
	context += mechanism.name();
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	if (auto b = co_await begin_bind(self, context); !b) co_return std::unexpected(std::move(b.error()));
	const bind_exchange exchange{ self };
	constexpr int max_steps = 32;
	sasl_bind_context bind_context;
	if (self->transport.type() == net::transport::kind::tcp) bind_context.host = self->transport.host();
	bind_context.can_offload = !corosio::detail::get_scheduler(self->ex.context()).scheduler_locking_disabled();
	mechanism.prepare(bind_context);
	result<std::optional<std::string>> creds;
	if (auto work = mechanism.offload_start())
		creds = co_await detail::run_offloaded(self->ex, self->default_timeout, std::move(work));
	else
		creds = mechanism.start();
	for (int step = 0;; ++step) {
		if (!creds || step == max_steps) {
			auto e = creds ? make_error(client_errc::unexpected_response,
							   detail::format("{}: still in progress after {} steps", context, max_steps))
						   : detail::with_context(std::move(creds.error()), context);
			// Past the first step the server answered saslBindInProgress:
			// abort the exchange before the held requests are sent.
			if (step > 0) co_await abort_sasl(self, context);
			co_return std::unexpected(std::move(e));
		}
		message request(std::pmr::polymorphic_allocator<>(self->mr));
		std::optional<std::string_view> c;
		if (*creds) c = **creds;
		request.op = bind_request(3, name.to_string(self->mr), sasl_auth(mechanism.name(), c, self->mr), self->mr);
		auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
		if (!m) co_return std::unexpected(std::move(m.error()));
		const auto &r = std::get<bind_response>(m->op);
		std::optional<std::string_view> server_creds;
		if (r.server_sasl_creds) server_creds = *r.server_sasl_creds;
		if (r.result.is_success()) {
			if (auto done = mechanism.complete(server_creds); !done) {
				// The server considers the connection bound, the client does
				// not (e.g. SCRAM could not authenticate the server): close
				// it rather than leave it bound to an identity nobody vouched for.
				auto e = detail::with_context(std::move(done.error()), context);
				self->shut(e, true);
				co_return std::unexpected(std::move(e));
			}
			co_return result<void>{};
		}
		if (r.result.result_code != std::to_underlying(errc::sasl_bind_in_progress))
			co_return std::unexpected(r.result.to_error(context));
		if (auto work = mechanism.offload_step(server_creds))
			creds = co_await detail::run_offloaded(self->ex, self->default_timeout, std::move(work));
		else
			creds = mechanism.step(server_creds);
	}
}

capy::task<result<ldap::search_stream>> connection::search_stream(search_params p, std::pmr::memory_resource *mr)
{
	if (impl_ == nullptr) co_return std::unexpected(no_connection(op_context("search", p.base)));
	co_return start_search(*impl_, p, mr, co_await capy::this_coro::stop_token);
}

capy::task<result<std::pmr::vector<entry>>> connection::search(search_params request, std::pmr::memory_resource *mr)
{
	auto s = co_await search_stream(std::move(request), mr);
	if (!s) co_return std::unexpected(std::move(s.error()));
	std::pmr::vector<entry> out(mr);
	while (true) {
		auto e = co_await s->next();
		if (!e) co_return std::unexpected(std::move(e.error()));
		if (!*e) break;
		out.push_back(std::move(**e));
	}
	co_return out;
}

// ---------------------------------------------------------------- other operations

namespace mod {

	namespace {
		modify_change change(modify_operation op, std::string_view type, std::initializer_list<std::string_view> values)
		{
			return modify_change(op, partial_attribute(type, values));
		}
	}// namespace

	modify_change add(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::add, type, values);
	}
	modify_change remove(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::delete_, type, values);
	}
	modify_change replace(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::replace, type, values);
	}
	modify_change increment(std::string_view type, std::string_view delta)
	{
		return change(modify_operation::increment, type, { delta });
	}

}// namespace mod

capy::task<result<response>> connection::add(add_params p)
{
	std::string context = op_context("add", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr);
	add_request op(alloc);
	op.entry = p.entry.to_string(self->mr);
	op.attributes.assign(p.attributes.begin(), p.attributes.end());
	auto request = with_controls(std::move(op), p.controls, self->mr, context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<add_response>, context, p.timeout), context);
}

namespace detail {

	capy::task<result<response>> modify_impl(impl_ref self, modify_params p, std::string context)
	{
		const std::pmr::polymorphic_allocator<> alloc(self->mr);
		modify_request op(alloc);
		op.object = p.object.to_string(self->mr);
		op.changes.assign(p.changes.begin(), p.changes.end());
		auto request = with_controls(std::move(op), p.controls, self->mr, context);
		if (!request) co_return std::unexpected(std::move(request.error()));
		co_return to_response(
		  co_await request_response(self, std::move(*request), op_index<modify_response>, context, p.timeout), context);
	}

}// namespace detail

using detail::modify_impl;

capy::task<result<response>> connection::modify(modify_params p)
{
	std::string context = op_context("modify", p.object);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	co_return co_await modify_impl(impl_ref(impl_), std::move(p), std::move(context));
}

capy::task<result<response>> connection::del(del_params p)
{
	std::string context = op_context("delete", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	auto request = with_controls(del_request(p.entry.to_string(self->mr), std::pmr::polymorphic_allocator<>(self->mr)),
	  p.controls,
	  self->mr,
	  context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<del_response>, context, p.timeout), context);
}

capy::task<result<response>> connection::modify_dn(modify_dn_params p)
{
	std::string context = op_context("modify DN", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	if (p.new_rdn.avas.empty()) co_return fail(client_errc::invalid_dn, context + ": empty new RDN");
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr);
	modify_dn_request op(alloc);
	op.entry = p.entry.to_string(self->mr);
	op.new_rdn = dn{}.child(p.new_rdn).to_string(self->mr);// an RDN prints as a one-RDN DN
	op.delete_old_rdn = p.delete_old_rdn;
	if (p.new_superior) op.new_superior = p.new_superior->to_string(self->mr);
	auto request = with_controls(std::move(op), p.controls, self->mr, context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<modify_dn_response>, context, p.timeout), context);
}

capy::task<result<bool>> connection::compare(compare_params p)
{
	std::string context = op_context("compare", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr);
	auto request = with_controls(
	  compare_request(p.entry.to_string(self->mr), attribute_value_assertion(p.attribute, p.value, alloc), alloc),
	  p.controls,
	  self->mr,
	  context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	auto m = co_await request_response(self, std::move(*request), op_index<compare_response>, context, p.timeout);
	if (!m) co_return std::unexpected(std::move(m.error()));
	const ldap_result &r = result_of(*m);
	if (r.result_code == std::to_underlying(errc::compare_true)) co_return true;
	if (r.result_code == std::to_underlying(errc::compare_false)) co_return false;
	co_return std::unexpected(r.to_error(context));// success (0) is not a valid answer either
}

namespace detail {

	capy::task<result<extended_result>> extended_impl(impl_ref self, extended_params p)
	{
		std::string context = "extended operation " + p.name;
		const std::pmr::polymorphic_allocator<> alloc(self->mr);
		std::optional<std::string_view> value;
		if (p.value) value = *p.value;
		auto request = with_controls(extended_request(p.name, value, alloc), p.controls, self->mr, context);
		if (!request) co_return std::unexpected(std::move(request.error()));
		auto m = co_await request_response(self, std::move(*request), op_index<extended_response>, context, p.timeout);
		if (!m) co_return std::unexpected(std::move(m.error()));
		auto &x = std::get<extended_response>(m->op);
		if (!x.result.is_success()) co_return std::unexpected(x.result.to_error(context));
		extended_result out;
		if (x.response_name) out.name.emplace(*x.response_name);
		if (x.response_value) out.value.emplace(*x.response_value);
		out.controls.assign(m->controls.begin(), m->controls.end());
		co_return out;
	}

}// namespace detail

using detail::extended_impl;

capy::task<result<extended_result>> connection::extended(extended_params p)
{
	if (impl_ == nullptr) co_return std::unexpected(no_connection("extended operation " + p.name));
	co_return co_await extended_impl(impl_ref(impl_), std::move(p));
}

capy::task<result<std::string>> connection::who_am_i(request_controls controls)
{
	auto r = co_await extended({ .name = std::string(who_am_i_oid), .controls = std::move(controls) });
	if (!r) co_return std::unexpected(std::move(r.error()));
	co_return r->value ? std::string(*r->value) : std::string();
}

namespace {

	// PasswdModifyRequestValue ::= SEQUENCE { userIdentity [0], oldPasswd [1],
	// newPasswd [2] } (all OCTET STRING OPTIONAL). nullopt when all are
	// absent: the requestValue is then left out (RFC 3062 section 2).
	std::optional<std::string> encode_password_modify(const password_modify_params &p)
	{
		if (!p.user && !p.old_password && !p.new_password) return std::nullopt;
		ber::writer w;
		w.constructed(ber::tags::sequence, [&](ber::writer &s) {
			if (p.user) s.octet_string(*p.user, ber::context(0));
			if (p.old_password) s.octet_string(*p.old_password, ber::context(1));
			if (p.new_password) s.octet_string(*p.new_password, ber::context(2));
		});
		return std::string(detail::as_text(w.bytes()));
	}

	// PasswdModifyResponseValue ::= SEQUENCE { genPasswd [0] OCTET STRING
	// OPTIONAL }; unknown trailing elements are ignored.
	result<std::optional<std::string>> decode_password_modify(std::string_view value)
	{
		ber::reader r(std::as_bytes(std::span(value)));
		auto s = r.enter();
		if (!s) return std::unexpected(std::move(s.error()));
		if (auto end = r.expect_end(); !end) return std::unexpected(std::move(end.error()));
		std::optional<std::string> generated;
		if (!s->empty()) {
			auto t = s->peek_tag();
			if (t && t->cls == ber::tag_class::context && t->number == 0) {
				auto g = s->read_octet_string(ber::context(0));
				if (!g) return std::unexpected(std::move(g.error()));
				generated.emplace(detail::as_text(*g));
			}
		}
		return generated;
	}

}// namespace

namespace detail {

	// `context` names the operation in errors, instead of "extended
	// operation <oid>".
	capy::task<result<std::optional<std::string>>>
	  password_modify_impl(impl_ref self, password_modify_params p, std::string context)
	{
		extended_params request{ .name = std::string(password_modify_oid),
			.value = encode_password_modify(p),
			.controls = std::move(p.controls),
			.timeout = p.timeout };
		auto r = co_await extended_impl(std::move(self), std::move(request));
		if (!r) {
			error e = std::move(r.error());
			const std::string generic = detail::format("extended operation {}", password_modify_oid);
			if (std::string_view(e.context).starts_with(generic)) e.context.replace(0, generic.size(), context);
			co_return std::unexpected(std::move(e));
		}
		if (!r->value) co_return std::optional<std::string>{};
		auto generated = decode_password_modify(*r->value);
		if (!generated)
			co_return std::unexpected(detail::with_context(std::move(generated.error()), context + ": response value"));
		co_return std::move(*generated);
	}

}// namespace detail

using detail::password_modify_impl;

capy::task<result<std::optional<std::string>>> connection::password_modify(password_modify_params p)
{
	std::string context = "password modify";
	if (p.user) {// usually a DN, often the server's: as op_context
		context += ' ';
		detail::append_sanitized(context, *p.user, 256);
	}
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	co_return co_await password_modify_impl(impl_ref(impl_), std::move(p), std::move(context));
}

// ---------------------------------------------------------------- schema

namespace detail {

	// The one entry of a base-scope search (nullopt if none came back).
	capy::task<result<std::optional<entry>>> read_one(impl_ref self, search_params p)
	{
		auto s = start_search(*self, p, std::pmr::get_default_resource(), co_await capy::this_coro::stop_token);
		if (!s) co_return std::unexpected(std::move(s.error()));
		std::optional<entry> found;
		while (true) {
			auto e = co_await s->next();
			if (!e) co_return std::unexpected(std::move(e.error()));
			if (!*e) co_return found;
			if (!found) found = std::move(**e);
		}
	}

}// namespace detail

using detail::read_one;

namespace {

	capy::task<result<server_schema>> load_schema_impl(impl_ref self)
	{
		const std::string context = "load schema";
		auto root =
		  co_await read_one(self, { .scope = search_scope::base_object, .attributes = { "subschemaSubentry" } });
		if (!root) co_return std::unexpected(detail::with_context(std::move(root.error()), context));
		std::string where = "cn=Subschema";
		if (*root)
			if (const auto *v = (*root)->find("subschemaSubentry"); v != nullptr && !v->empty())
				where = std::string(v->front());
		// `where` is the server's text: quoted sanitized (a DN, as entry_context).
		auto quoted = [&where](std::string text) {
			detail::append_sanitized(text, where, 256);
			return text;
		};
		auto base = dn::parse(where);
		if (!base)
			co_return fail(
			  client_errc::invalid_dn, quoted(context + ": the root DSE names an invalid subschemaSubentry: "));
		auto sub = co_await read_one(self,
		  { .base = std::move(*base),
			.scope = search_scope::base_object,
			.filter = filters::attr("objectClass") == "subschema",
			.attributes = { "attributeTypes", "objectClasses" } });
		if (!sub) co_return std::unexpected(detail::with_context(std::move(sub.error()), context));
		if (!*sub) co_return fail(errc::no_such_object, quoted(context + ": no subschema entry at "));
		static const std::pmr::vector<std::pmr::string> none;
		const auto *types = (*sub)->find("attributeTypes");
		const auto *classes = (*sub)->find("objectClasses");
		co_return server_schema::parse(types ? *types : none, classes ? *classes : none);
	}

}// namespace

capy::task<result<server_schema>> connection::load_schema()
{
	if (impl_ == nullptr) co_return std::unexpected(no_connection("load schema"));
	co_return co_await load_schema_impl(impl_ref(impl_));
}

capy::task<result<void>> connection::check_schema(std::type_index type,
  schema_report (*validate_type)(const server_schema &))
{
	if (impl_ == nullptr || impl_->schema_mode == ldap::schema_check::off) co_return result<void>{};
	impl_ref self(impl_);
	if (std::ranges::contains(self->schema_checked, type)) co_return result<void>{};
	if (!self->schema) {
		auto s = co_await load_schema_impl(self);
		if (!s) co_return std::unexpected(std::move(s.error()));
		self->schema = std::make_shared<const server_schema>(std::move(*s));
	}
	const schema_report report = validate_type(*self->schema);
	if (!report.ok())
		co_return fail(
		  client_errc::schema_mismatch, detail::format("schema check of {}:\n{}", type.name(), report.to_string()));
	self->schema_checked.push_back(type);
	co_return result<void>{};
}

// ---------------------------------------------------------------- password changes

namespace {

	// How to choose the method when the root DSE does not tell.
	constexpr std::string_view choose_password_method =
	  "choose the method with connection_options::password_method or the method argument "
	  "(ldap::password_method::rfc3062 or active_directory)";

	// password_method::automatic: what the root DSE advertises, RFC 3062
	// first. Errors are prefixed with `context`.
	capy::task<result<ldap::password_method>> advertised_password_method(impl_ref self, const std::string &context)
	{
		auto root = co_await read_one(self,
		  { .scope = search_scope::base_object, .attributes = { "supportedExtension", "supportedCapabilities" } });
		if (!root)
			co_return std::unexpected(detail::with_context(std::move(root.error()),
			  detail::format("{}: reading the root DSE to pick the method failed ({} to skip it)",
				context,
				choose_password_method)));
		const auto lists = [&root](std::string_view type, std::string_view oid) {
			const auto *values = *root ? (*root)->find(type) : nullptr;
			return values != nullptr && std::ranges::contains(*values, oid);
		};
		if (lists("supportedExtension", password_modify_oid)) co_return ldap::password_method::rfc3062;
		if (lists("supportedCapabilities", active_directory_capability_oid))
			co_return ldap::password_method::active_directory;
		co_return fail(client_errc::no_password_method,
		  detail::format("{}: the root DSE advertises neither the RFC 3062 password modify extension nor Active "
						 "Directory (it may be hidden by access controls): {}, or call password_modify()",
			context,
			choose_password_method));
	}

	// Active Directory starts its diagnosticMessage with the Win32 error in
	// hex ("0000052D: Constraint violation - ..."): the common ones of a
	// password change, explained ("" for the others).
	std::string_view ad_password_explanation(std::string_view diagnostic)
	{
		if (diagnostic.size() < 9 || diagnostic[8] != ':') return {};
		unsigned code = 0;
		const auto [end, ec] = std::from_chars(diagnostic.data(), diagnostic.data() + 8, code, 16);
		if (ec != std::errc{} || end != diagnostic.data() + 8) return {};
		switch (code) {
		case 0x5:// ERROR_ACCESS_DENIED
			return "not allowed to set this user's password";
		case 0x56:// ERROR_INVALID_PASSWORD
			return "the old password is wrong";
		case 0x52D:// ERROR_PASSWORD_RESTRICTION
			return "the new password does not meet the password policy (length, complexity, history or minimum "
				   "age)";
		case 0x775:// ERROR_ACCOUNT_LOCKED_OUT
			return "the account is locked out";
		default:
			return {};
		}
	}

	// password_method::active_directory: a ModifyRequest of unicodePwd.
	capy::task<result<void>> ad_set_password(impl_ref self,
	  const dn &user,
	  const std::optional<std::string> &old_password,
	  const std::string &new_password,
	  const std::string &context)
	{
		if (user.empty()) co_return fail(client_errc::invalid_dn, context + ": Active Directory needs the user's DN");
		// As is_tls(); a closed connection fails with not_connected below.
		if (self->open && (self->upgrading || !self->transport.is_tls()))
			co_return fail(client_errc::tls_required,
			  context + ": Active Directory sets unicodePwd only over TLS (ldaps:// or start_tls())");
		auto new_value = ad_password_value(new_password);
		if (!new_value) co_return std::unexpected(detail::with_context(std::move(new_value.error()), context));
		modify_params p{ .object = user };
		if (old_password) {
			auto old_value = ad_password_value(*old_password);
			if (!old_value) co_return std::unexpected(detail::with_context(std::move(old_value.error()), context));
			p.changes.push_back(mod::remove("unicodePwd", { *old_value }));
			p.changes.push_back(mod::add("unicodePwd", { *new_value }));
		} else {
			p.changes.push_back(mod::replace("unicodePwd", { *new_value }));
		}
		auto r = co_await modify_impl(std::move(self), std::move(p), context + ": modify unicodePwd");
		if (r) co_return result<void>{};
		error e = std::move(r.error());
		if (const auto text = ad_password_explanation(e.diagnostic); !text.empty())
			e.context +=
			  detail::format(": {} (Active Directory error {})", text, std::string_view(e.diagnostic).substr(0, 8));
		co_return std::unexpected(std::move(e));
	}

	// change_password (with `old_password`) and reset_password.
	capy::task<result<void>> set_password(impl_ref self,
	  std::string context,
	  dn user,
	  std::optional<std::string> old_password,
	  std::string new_password,
	  std::optional<ldap::password_method> method)
	{
		if (new_password.empty())
			co_return fail(std::make_error_code(std::errc::invalid_argument), context + ": empty new password");
		if (old_password && old_password->empty())
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": empty old password (reset_password() sets one without it)");
		ldap::password_method m = method.value_or(self->password_mode);
		if (m == ldap::password_method::automatic) {
			if (!self->advertised_password_method) {
				auto found = co_await advertised_password_method(self, context);
				if (!found) co_return std::unexpected(std::move(found.error()));
				self->advertised_password_method = *found;
			}
			m = *self->advertised_password_method;
		}
		if (m == ldap::password_method::active_directory)
			co_return co_await ad_set_password(std::move(self), user, old_password, new_password, context);
		password_modify_params p{ .old_password = std::move(old_password), .new_password = std::move(new_password) };
		if (!user.empty()) p.user = std::string(user.to_string());
		auto r = co_await password_modify_impl(std::move(self), std::move(p), context + ": password modify (RFC 3062)");
		if (!r) co_return std::unexpected(std::move(r.error()));
		co_return result<void>{};
	}

}// namespace

capy::task<result<void>> connection::change_password(dn user,
  std::string old_password,
  std::string new_password,
  std::optional<ldap::password_method> method)
{
	std::string context = op_context("change password", user);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	co_return co_await set_password(
	  impl_ref(impl_), std::move(context), std::move(user), std::move(old_password), std::move(new_password), method);
}

capy::task<result<void>>
  connection::reset_password(dn user, std::string new_password, std::optional<ldap::password_method> method)
{
	std::string context = op_context("reset password", user);
	if (impl_ == nullptr) co_return std::unexpected(no_connection(context));
	co_return co_await set_password(
	  impl_ref(impl_), std::move(context), std::move(user), std::nullopt, std::move(new_password), method);
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
	self->schema.reset();
	self->schema_checked.clear();
	self->advertised_password_method.reset();
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

// ---------------------------------------------------------------- search_stream

search_stream::search_stream(search_stream &&other) noexcept : state_(std::exchange(other.state_, nullptr)) {}

search_stream &search_stream::operator=(search_stream &&other) noexcept
{
	if (this != &other) {
		delete_state(state_);
		state_ = std::exchange(other.state_, nullptr);
	}
	return *this;
}

search_stream::~search_stream() { delete_state(state_); }

bool search_stream::done() const noexcept { return state_ == nullptr || state_->finished; }

const string_list &search_stream::references() const noexcept
{
	static const string_list none;
	return state_ == nullptr ? none : state_->references;
}

const std::pmr::vector<control> &search_stream::controls() const noexcept
{
	static const std::pmr::vector<control> none;
	return state_ == nullptr ? none : state_->controls;
}

capy::task<result<std::optional<entry>>> search_stream::next()
{
	if (state_ == nullptr) co_return std::unexpected(no_connection("search"));
	state &s = *state_;// stable: the stream must not be moved while next() runs
	if (s.finished) {
		if (s.error_) co_return std::unexpected(*s.error_);
		co_return std::optional<entry>{};
	}
	if (s.in_next)
		co_return fail(
		  client_errc::operation_in_progress, s.context + " during an earlier next() on this search_stream");
	s.in_next = true;
	struct reset
	{
		bool &flag;
		~reset() { flag = false; }
	} r{ s.in_next };

	const impl_ref conn = s.conn;
	while (true) {
		auto m = co_await conn->next_response(s.op, s.deadline, s.context);
		if (!m) {
			s.finished = true;
			s.error_ = m.error();
			co_return std::unexpected(std::move(m.error()));
		}
		if (auto *e = std::get_if<search_result_entry>(&m->op))
			co_return std::optional<entry>(entry::from(std::move(*e)));// on the stream's resource, no copy
		if (auto *ref = std::get_if<search_result_reference>(&m->op)) {
			s.references.append_range(ref->uris);
			continue;
		}
		const auto &d = std::get<search_result_done>(m->op);// checked by the reader
		s.finished = true;
		s.controls.assign(m->controls.begin(), m->controls.end());
		if (!d.result.is_success()) {
			s.error_ = d.result.to_error(s.context);
			co_return std::unexpected(*s.error_);
		}
		co_return std::optional<entry>{};
	}
}

std::pmr::vector<url> search_stream::reference_urls(std::pmr::memory_resource *mr) const
{
	return url::parse_list(references(), mr);
}

// ---------------------------------------------------------------- paged_search

struct paged_search::state
{
	impl_ref conn;
	search_params params;
	std::int32_t page_size;
	std::pmr::memory_resource *mr;
	ldap::search_stream current{};
	std::size_t pages = 0;
	bool finished = false;
	std::optional<error> error_{};
	string_list references{};
	std::pmr::vector<control> controls{};
	// The last cookie the server returned: its paging state, to release if
	// the search stops early. Empty before the first page ends, after the
	// last one, and after an error that ended the search on the server.
	std::string cookie{};

	void set_page_control(std::int32_t size, std::string page_cookie)
	{
		auto &cs = params.controls;
		std::erase_if(cs, [](const request_control &c) {
			return std::holds_alternative<paged>(c)
				   || (std::holds_alternative<control>(c) && std::get<control>(c).type == paged_results_oid);
		});
		cs.push_back(paged{ .page_size = size, .cookie = std::move(page_cookie) });
	}

	// Sends the search for the next page (cookie empty for the first);
	// not sent if `stop` (the awaiting task's) is set already.
	result<void> request_page(std::string page_cookie, const std::stop_token &stop)
	{
		set_page_control(page_size, std::move(page_cookie));
		auto s = start_search(*conn, params, mr, stop);
		if (!s) return std::unexpected(std::move(s.error()));
		current = std::move(*s);
		++pages;
		return {};
	}

	// The paging state the server holds now: `cookie`, or the current
	// page's own if its SearchResultDone was already received (the page
	// ended, next() has not read it yet).
	std::string server_cookie() const
	{
		if (current.state_ == nullptr) return cookie;
		const auto &q = current.state_->op.queue;
		if (q.empty() || !std::holds_alternative<search_result_done>(q.back().op)) return cookie;
		if (!std::get<search_result_done>(q.back().op).result.is_success()) return {};
		auto pr = find_paged(q.back().controls);
		if (!pr || !*pr) return {};
		return std::string((*pr)->cookie);
	}

	// Stopped before its end (destroyed): abandons the current page, then
	// releases the server's paging state (RFC 2696 section 3: page size 0
	// and the last cookie). Best effort and never suspends: the release is
	// sent without waiting for its answer, which is dropped. Nothing is sent
	// if the connection is closed or in StartTLS (a bind holds it until the
	// bind ends, like any request).
	void stop() noexcept
	{
		std::string last;
		try {
			last = finished ? cookie : server_cookie();
		} catch (...) {// out of memory: the release is best effort
		}
		current = ldap::search_stream{};// abandons the page if it is still running
		finished = true;
		cookie.clear();
		try {
			if (last.empty() || !conn->open) return;
			set_page_control(0, std::move(last));
			const std::string context = op_context("search", params.base) + " (paged results release)";
			auto request = search_message(*conn, params, context);
			// Its answer is waited for as long as a page would be.
			const auto timeout = params.timeout ? params.timeout : conn->default_timeout;
			if (request) conn->send_unanswered(*request, true, deadline_after(timeout), context);
		} catch (...) {// out of memory: the release is best effort
		}
	}
};

capy::task<result<ldap::paged_search>>
  connection::search_paged(search_params p, std::int32_t page_size, std::pmr::memory_resource *mr)
{
	if (impl_ == nullptr) co_return std::unexpected(no_connection(op_context("search", p.base)));
	if (page_size <= 0)
		co_return fail(client_errc::encode_error,
		  detail::format("{}: page size {} is not positive", op_context("search", p.base), page_size));
	std::pmr::polymorphic_allocator<> alloc(impl_->mr);
	auto *st = alloc.new_object<paged_search::state>(
	  paged_search::state{ impl_ref(impl_), std::move(p), page_size, mr, {}, 0, false, {}, {}, {}, {} });
	ldap::paged_search out = connection::impl::make_paged(st);
	if (auto r = st->request_page({}, co_await capy::this_coro::stop_token); !r)
		co_return std::unexpected(std::move(r.error()));
	co_return std::move(out);
}

namespace {

	void delete_paged(paged_search::state *s) noexcept
	{
		if (s == nullptr) return;
		s->stop();
		impl_ref keep = s->conn;
		std::pmr::polymorphic_allocator<> alloc(keep->mr);
		alloc.delete_object(s);
	}

}// namespace

paged_search::paged_search(paged_search &&other) noexcept : state_(std::exchange(other.state_, nullptr)) {}

paged_search &paged_search::operator=(paged_search &&other) noexcept
{
	if (this != &other) {
		delete_paged(state_);
		state_ = std::exchange(other.state_, nullptr);
	}
	return *this;
}

paged_search::~paged_search() { delete_paged(state_); }

bool paged_search::done() const noexcept { return state_ == nullptr || state_->finished; }

std::size_t paged_search::pages() const noexcept { return state_ == nullptr ? 0 : state_->pages; }

const string_list &paged_search::references() const noexcept
{
	static const string_list none;
	return state_ == nullptr ? none : state_->references;
}

std::pmr::vector<url> paged_search::reference_urls(std::pmr::memory_resource *mr) const
{
	return url::parse_list(references(), mr);
}

const std::pmr::vector<control> &paged_search::controls() const noexcept
{
	static const std::pmr::vector<control> none;
	return state_ == nullptr ? none : state_->controls;
}

capy::task<result<std::optional<entry>>> paged_search::next()
{
	if (state_ == nullptr) co_return std::unexpected(no_connection("search"));
	state &s = *state_;
	if (s.finished) {
		if (s.error_) co_return std::unexpected(*s.error_);
		co_return std::optional<entry>{};
	}
	// `ended`: the error ended the search on the server (an error result,
	// a malformed answer, a closed connection), so there is nothing to
	// release. A cancelled or timed-out page was only abandoned, and a page
	// request that could not be sent was never seen: the server may still
	// hold the paging state of `cookie`, which the destructor releases.
	// Decided by capy::cond, not ldap::cond::timeout: that also matches the
	// server's timeLimitExceeded, which ended the search on the server.
	auto finish = [&s](error e, bool ended = true) -> result<std::optional<entry>> {
		if (ended && e.code != capy::cond::canceled && e.code != capy::cond::timeout) s.cookie.clear();
		s.finished = true;
		s.error_ = e;
		return std::unexpected(std::move(e));
	};
	while (true) {
		const std::size_t seen = s.current.references().size();
		auto e = co_await s.current.next();
		const auto &refs = s.current.references();
		s.references.insert(s.references.end(), refs.begin() + static_cast<std::ptrdiff_t>(seen), refs.end());
		if (!e) co_return finish(std::move(e.error()));
		if (*e) co_return std::move(*e);
		// The page ended: the next one, if the server gave a cookie.
		s.controls = s.current.controls();
		auto pr = find_paged(s.controls);
		if (!pr) co_return finish(detail::with_context(std::move(pr.error()), op_context("search", s.params.base)));
		s.cookie = *pr ? std::string((*pr)->cookie) : std::string();
		if (s.cookie.empty()) {
			s.finished = true;
			co_return std::optional<entry>{};
		}
		if (auto r = s.request_page(s.cookie, co_await capy::this_coro::stop_token); !r)
			co_return finish(std::move(r.error()), false);
	}
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
