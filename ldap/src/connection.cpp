#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/message_io.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/corosio/timeout.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <memory>
#include <memory_resource>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <variant>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {
namespace {

	// Contexts are built as std::string (cold path) and copied into the
	// error, which lives on the default resource.
	error with_context(error e, std::string_view prefix)
	{
		if (e.context.empty()) {
			e.context.assign(prefix);
		} else {
			e.context.insert(0, ": ");
			e.context.insert(0, prefix);
		}
		return e;
	}

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

	std::string_view op_name(const protocol_op &op) noexcept { return op_names[op.index()]; }

	template<class T, class... Ts> consteval std::size_t index_in(const std::variant<Ts...> *)
	{
		constexpr bool same[] = { std::is_same_v<T, Ts>... };
		for (std::size_t i = 0; i < sizeof...(Ts); ++i)
			if (same[i]) return i;
		return sizeof...(Ts);
	}
	template<class T> constexpr std::size_t op_index = index_in<T>(static_cast<const protocol_op *>(nullptr));

	// RFC 4511 protocolOp tags of the responses the reader recognizes before
	// decoding.
	constexpr ber::tag search_result_done_tag = ber::application(5, true);
	constexpr ber::tag intermediate_response_tag = ber::application(25, true);

	bool same_tag(ber::tag a, ber::tag b) noexcept { return a.cls == b.cls && a.number == b.number; }

	// "search ou=people,dc=example,dc=org", `search ""` for the root DSE.
	std::string op_context(std::string_view op, const dn &d)
	{
		std::string out(op);
		out += ' ';
		if (d.empty())
			out += "\"\"";
		else
			out += d.to_string();
		return out;
	}

	using clock = std::chrono::steady_clock;

	std::optional<clock::time_point> deadline_after(std::optional<std::chrono::milliseconds> d)
	{
		if (!d) return std::nullopt;
		return clock::now() + *d;
	}

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
	// StartTLS in progress: no other request may be sent (RFC 4511 4.14.1).
	bool upgrading = false;
	// schema_check::on_first_use: the loaded schema and the types checked.
	ldap::schema_check schema_mode = ldap::schema_check::off;
	std::shared_ptr<const server_schema> schema{};
	std::vector<std::type_index> schema_checked{};
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

	// Closes the transport and fails every outstanding operation with `e`
	// (they add their own context). `remember`: later operations name it.
	// `close_transport` false: the caller closes it (unbind, after the TLS
	// shutdown).
	void shut(error e, bool remember, bool close_transport = true)
	{
		if (!open) return;
		open = false;
		if (remember) failure = e;
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
			p->failure = e;
			p->ready.set();
		}
		if (reading) reader_stop.request_stop();
	}

	error not_connected(std::string_view context) const
	{
		std::string text(context);
		if (failure) {
			text += ": connection closed by an earlier error: ";
			text += failure->message();
		} else {
			text += ": connection closed";
		}
		return make_error(client_errc::not_connected, text);
	}

	// ---------------------------------------------------------------- writer

	static capy::task<void> writer(impl *self)
	{
		const frame_ref ref(self);
		while (self->open && !self->outbox.empty()) {
			auto bytes = std::move(self->outbox.front());
			self->outbox.pop_front();
			auto w = co_await net::write_bytes(self->transport, bytes);
			if (!w) self->shut(std::move(w.error()), true);
		}
		self->writing = false;
		self->write_idle.set();
	}

	void enqueue(std::pmr::vector<std::byte> bytes)
	{
		outbox.push_back(std::move(bytes));
		if (writing) return;
		writing = true;
		write_idle.clear();
		add_ref();// released by the writer
		// No stop token: a PDU is always written whole (a cancelled write
		// would leave half a PDU on the wire).
		capy::run_async(ex)(writer(this));
	}

	// The next message id the server cannot still be servicing (RFC 4511
	// section 4.1.1): after wrapping at maxInt, ids of outstanding or
	// recently abandoned requests are skipped.
	std::int32_t free_id() const
	{
		std::int32_t id = next_id;
		if (!wrapped) return id;// ids so far only increased: none is in use
		auto in_use = [this](std::int32_t i) {
			return pending.contains(i) || std::any_of(abandoned.begin(), abandoned.end(), [i](const abandoned_req &r) {
				return r.id == i;
			});
		};
		while (in_use(id)) id = id == max_int ? 1 : id + 1;
		return id;
	}

	// Gives `m` the next free message id, encodes it and queues it for the
	// writer. If `p` is given it is registered under that id first (its
	// response may arrive before the write completes). If encoding fails
	// nothing is sent and the id is not used up.
	result<void> submit(message &m, pending_op *p, std::string_view context)
	{
		if (!open) return std::unexpected(not_connected(context));
		if (upgrading && !std::holds_alternative<abandon_request>(m.op))
			return fail(client_errc::operation_in_progress, std::string(context) + " during StartTLS");
		m.id = free_id();
		auto bytes = encode(m, mr);
		if (!bytes) return std::unexpected(with_context(std::move(bytes.error()), context));
		if (m.id == max_int) wrapped = true;
		next_id = m.id == max_int ? 1 : m.id + 1;
		const bool bind = std::holds_alternative<bind_request>(m.op);
		if (p != nullptr) {
			const auto *x = std::get_if<extended_request>(&m.op);
			p->abandonable = !bind && (x == nullptr || x->request_name != start_tls_oid);
			p->id = m.id;
			p->registered = true;
			pending.emplace(m.id, p);
			start_reader();
		}
		if (binding && !bind) {
			held.push_back({ m.id, std::move(*bytes) });
			return {};
		}
		enqueue(std::move(*bytes));
		return {};
	}

	// The bind exchange ended: sends the requests it held, in order.
	void release_held()
	{
		while (open && !held.empty()) {
			enqueue(std::move(held.front().bytes));
			held.pop_front();
		}
		held.clear();
	}

	// Stops waiting for `p`'s responses and tells the server (best effort).
	void abandon(pending_op &p)
	{
		if (!p.registered) return;
		p.registered = false;
		p.finished = true;
		pending.erase(p.id);
		stop_reader_if_idle();
		if (!open) return;
		if (!p.abandonable) {
			shut(make_error(client_errc::not_connected,
				   "connection closed: a Bind or StartTLS request cannot be abandoned (RFC 4511 section 4.11)"),
			  true);
			return;
		}
		// Held by a bind exchange, so never sent: nothing to tell the server.
		auto h = std::find_if(held.begin(), held.end(), [&](const held_request &r) { return r.id == p.id; });
		if (h != held.end()) {
			held.erase(h);
			return;
		}
		abandoned.push_back({ p.id, p.search });
		trim_abandoned();
		message m{ 0, abandon_request{ p.id } };
		(void)submit(m, nullptr, "abandon");// cannot fail to encode
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
		// request's. submit returns an error only before queueing, so the
		// entry is still last then. It may start the writer inline, whose
		// failed write runs shut() inside it, which clears the list: hence
		// the guarded pop_back() on a throw, and the !open check after it.
		// A throw after queueing leaves the bytes unsent (the writer is
		// wedged, coro_http_client-46q), so no answer can come for them.
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
		auto a =
		  std::find_if(abandoned.begin(), std::prev(abandoned.end()), [](const abandoned_req &r) { return !r.due; });
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
		watching = true;
		add_ref();// released by the watcher
		capy::run_async(ex)(due_watcher(this));
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
	static capy::task<void> due_watcher(impl *self)
	{
		const frame_ref ref(self);
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
		self->watching = false;
	}

	// Requests still to be answered: those waited for, and `due` answers.
	std::size_t outstanding() const noexcept { return pending.size() + due_answers; }

	// ---------------------------------------------------------------- reader

	void start_reader()
	{
		if (reading) return;// a reader that is stopping restarts itself if needed
		reading = true;
		reader_idle.clear();
		reader_stop = std::stop_source{};
		add_ref();// released by the reader
		capy::run_async(ex, reader_stop.get_token())(reader(this));
	}

	void stop_reader_if_idle()
	{
		if (outstanding() == 0 && reading) reader_stop.request_stop();
	}

	static capy::task<void> reader(impl *self)
	{
		const frame_ref ref(self);
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
		self->reading = false;
		self->reader_idle.set();
		// Stopped while an operation was being registered: start afresh,
		// with a new stop token.
		if (self->open && self->outstanding() != 0) self->start_reader();
	}

	error unexpected(std::string text)
	{
		return make_error(client_errc::unexpected_response, "read " + std::string(transport.name()) + ": " + text);
	}

	// Delivers the PDU at the front of buf (`size` bytes) and consumes it.
	void route(std::size_t size)
	{
		const auto bytes = buf.data().first(size);
		auto h = peek_message_header(bytes);
		if (!h) {
			buf.consume(size);
			shut(with_context(std::move(h.error()), "read " + std::string(transport.name())), true);
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
				shut(with_context(std::move(m.error()), "read " + std::string(transport.name())), true);
				return;
			}
			const std::size_t index = m->op.index();
			const bool final = index == p.expect;
			const bool streamed =
			  p.search && (index == op_index<search_result_entry> || index == op_index<search_result_reference>);
			if (!final && !streamed) {
				shut(unexpected(std::string(op_name(m->op)) + " with message id " + std::to_string(h->id)
								+ " in response to a "
								+ (p.search ? "SearchRequest" : std::string(op_names[p.expect - 1]))),
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
		auto a =
		  std::find_if(abandoned.begin(), abandoned.end(), [&](const abandoned_req &r) { return r.id == h->id; });
		if (a != abandoned.end()) {
			// A late response to an abandoned request: dropped. The search's
			// SearchResultDone (or any response to another request) is its
			// last.
			if (!a->search || same_tag(h->op, search_result_done_tag)) forget_abandoned(a);
			return;
		}
		shut(unexpected("message with id " + std::to_string(h->id) + ", which matches no outstanding request"), true);
	}

	// An unsolicited notification (message id 0, RFC 4511 section 4.4).
	void notification(std::span<const std::byte> bytes)
	{
		std::optional<error> fatal;
		{
			auto m = decode(bytes, { .from = origin::server, .max_elements = max_elements, .memory = &scratch });
			if (!m) {
				fatal = with_context(std::move(m.error()), "read " + std::string(transport.name()));
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
		if (p.failure) co_return std::unexpected(with_context(*p.failure, context));
		co_return std::unexpected(not_connected(context));// closed by close() or unbind()
	}
};

namespace {

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

	error not_connected(std::string_view context) { return make_error(client_errc::not_connected, context); }

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

bool connection::is_tls() const noexcept { return impl_ != nullptr && impl_->transport.is_tls(); }

void connection::close() noexcept
{
	if (impl_ == nullptr) return;
	impl_->shut(make_error(client_errc::not_connected, "connection closed"), false);
	impl_->transport.close();// also ends a TLS shutdown that unbind() is waiting for
}

namespace {

	// One request with one response (everything but search): sends it,
	// waits for the response of index `expect` and returns it. `self` keeps
	// the state alive across the suspension.
	capy::task<result<message>> request_response(impl_ref self,
	  message request,
	  std::size_t expect,
	  std::string context,
	  std::optional<std::chrono::milliseconds> timeout)
	{
		pending_op p(self->mr, false, expect);
		if (auto r = self->submit(request, &p, context); !r) co_return std::unexpected(std::move(r.error()));
		registration reg(*self, p);
		co_return co_await self->next_response(p, deadline_after(timeout ? timeout : self->default_timeout), context);
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
			return std::unexpected(with_context(std::move(c.error()), context));
		return m;
	}

	// The SearchRequest for `p`, validated (errors carry `context`).
	result<message> search_message(connection::impl &c, const search_params &p, const std::string &context)
	{
		const auto seconds = p.time_limit.count();
		if (seconds < 0 || seconds > max_int)
			return fail(client_errc::encode_error,
			  context + ": time_limit of " + std::to_string(seconds) + " s is outside 0 .. 2^31-1");

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
	result<ldap::search_stream> start_search(connection::impl &c, search_params &p, std::pmr::memory_resource *mr)
	{
		std::string context = op_context("search", p.base);
		auto request = search_message(c, p, context);
		if (!request) return std::unexpected(std::move(request.error()));

		auto *state = new_state(c, mr, context);
		ldap::search_stream s = connection::impl::make_stream(state);
		state->deadline = deadline_after(p.timeout ? p.timeout : c.default_timeout);
		if (auto r = c.submit(*request, &state->op, context); !r) return std::unexpected(std::move(r.error()));
		return s;
	}

}// namespace

capy::task<result<void>> connection::simple_bind(dn name, std::string password)
{
	std::string context = op_context("bind", name);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
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
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	impl_ref self(impl_);
	if (auto b = co_await begin_bind(self, context); !b) co_return std::unexpected(std::move(b.error()));
	const bind_exchange exchange{ self };
	constexpr int max_steps = 32;
	auto creds = mechanism.start();
	for (int step = 0;; ++step) {
		if (!creds) co_return std::unexpected(detail::with_context(std::move(creds.error()), context));
		if (step == max_steps)
			co_return fail(client_errc::unexpected_response,
			  context + ": still in progress after " + std::to_string(max_steps) + " steps");
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
		if (r.result.result_code != static_cast<int>(errc::sasl_bind_in_progress))
			co_return std::unexpected(r.result.to_error(context));
		creds = mechanism.step(server_creds);
	}
}

capy::task<result<ldap::search_stream>> connection::search_stream(search_params p, std::pmr::memory_resource *mr)
{
	if (impl_ == nullptr) co_return std::unexpected(not_connected(op_context("search", p.base)));
	co_return start_search(*impl_, p, mr);
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
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
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

capy::task<result<response>> connection::modify(modify_params p)
{
	std::string context = op_context("modify", p.object);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	impl_ref self(impl_);
	const std::pmr::polymorphic_allocator<> alloc(self->mr);
	modify_request op(alloc);
	op.object = p.object.to_string(self->mr);
	op.changes.assign(p.changes.begin(), p.changes.end());
	auto request = with_controls(std::move(op), p.controls, self->mr, context);
	if (!request) co_return std::unexpected(std::move(request.error()));
	co_return to_response(
	  co_await request_response(self, std::move(*request), op_index<modify_response>, context, p.timeout), context);
}

capy::task<result<response>> connection::del(del_params p)
{
	std::string context = op_context("delete", p.entry);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
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
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
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
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
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
	if (r.result_code == static_cast<int>(errc::compare_true)) co_return true;
	if (r.result_code == static_cast<int>(errc::compare_false)) co_return false;
	co_return std::unexpected(r.to_error(context));// success (0) is not a valid answer either
}

capy::task<result<extended_result>> connection::extended(extended_params p)
{
	std::string context = "extended operation " + p.name;
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	impl_ref self(impl_);
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
		const auto &bytes = w.bytes();
		return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
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
				generated.emplace(reinterpret_cast<const char *>(g->data()), g->size());
			}
		}
		return generated;
	}

}// namespace

capy::task<result<std::optional<std::string>>> connection::password_modify(password_modify_params p)
{
	std::string context = "password modify";
	if (p.user) context += " " + *p.user;
	extended_params request{ .name = std::string(password_modify_oid),
		.value = encode_password_modify(p),
		.controls = std::move(p.controls),
		.timeout = p.timeout };
	auto r = co_await extended(std::move(request));
	if (!r) {
		// "extended operation <oid>..." names the operation by its OID; say
		// what it is instead.
		error e = std::move(r.error());
		const std::string generic = "extended operation " + std::string(password_modify_oid);
		if (std::string_view(e.context).starts_with(generic)) e.context.replace(0, generic.size(), context);
		co_return std::unexpected(std::move(e));
	}
	if (!r->value) co_return std::optional<std::string>{};
	auto generated = decode_password_modify(*r->value);
	if (!generated)
		co_return std::unexpected(detail::with_context(std::move(generated.error()), context + ": response value"));
	co_return std::move(*generated);
}

// ---------------------------------------------------------------- schema

namespace {

	// The one entry of a base-scope search (nullopt if none came back).
	capy::task<result<std::optional<entry>>> read_one(impl_ref self, search_params p)
	{
		auto s = start_search(*self, p, std::pmr::get_default_resource());
		if (!s) co_return std::unexpected(std::move(s.error()));
		std::optional<entry> found;
		while (true) {
			auto e = co_await s->next();
			if (!e) co_return std::unexpected(std::move(e.error()));
			if (!*e) co_return found;
			if (!found) found = std::move(**e);
		}
	}

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
		auto base = dn::parse(where);
		if (!base)
			co_return fail(
			  client_errc::invalid_dn, context + ": the root DSE names an invalid subschemaSubentry: " + where);
		auto sub = co_await read_one(self,
		  { .base = std::move(*base),
			.scope = search_scope::base_object,
			.filter = filters::attr("objectClass") == "subschema",
			.attributes = { "attributeTypes", "objectClasses" } });
		if (!sub) co_return std::unexpected(detail::with_context(std::move(sub.error()), context));
		if (!*sub) co_return fail(errc::no_such_object, context + ": no subschema entry at " + where);
		static const std::pmr::vector<std::pmr::string> none;
		const auto *types = (*sub)->find("attributeTypes");
		const auto *classes = (*sub)->find("objectClasses");
		co_return server_schema::parse(types ? *types : none, classes ? *classes : none);
	}

}// namespace

capy::task<result<server_schema>> connection::load_schema()
{
	if (impl_ == nullptr) co_return std::unexpected(not_connected("load schema"));
	co_return co_await load_schema_impl(impl_ref(impl_));
}

capy::task<result<void>> connection::check_schema(std::type_index type,
  schema_report (*validate_type)(const server_schema &))
{
	if (impl_ == nullptr || impl_->schema_mode == ldap::schema_check::off) co_return result<void>{};
	impl_ref self(impl_);
	if (std::find(self->schema_checked.begin(), self->schema_checked.end(), type) != self->schema_checked.end())
		co_return result<void>{};
	if (!self->schema) {
		auto s = co_await load_schema_impl(self);
		if (!s) co_return std::unexpected(std::move(s.error()));
		self->schema = std::make_shared<const server_schema>(std::move(*s));
	}
	const schema_report report = validate_type(*self->schema);
	if (!report.ok())
		co_return fail(
		  client_errc::schema_mismatch, "schema check of " + std::string(type.name()) + ":\n" + report.to_string());
	self->schema_checked.push_back(type);
	co_return result<void>{};
}

// ---------------------------------------------------------------- StartTLS

capy::task<result<void>> connection::start_tls(net::tls_options options,
  std::optional<std::chrono::milliseconds> timeout)
{
	std::string context = "start tls";
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	impl_ref self(impl_);
	// StartTLS may only be sent once every response is received (RFC 4513
	// section 3.1.1). Operations are refused; the answers still due to
	// released paged searches are waited for (they are certain, or given
	// up on at their own deadline), within `timeout`. The checks are made
	// again after the wait: an operation started meanwhile is refused as
	// if start_tls had been called then.
	const auto wait_deadline = deadline_after(timeout ? timeout : self->default_timeout);
	while (true) {
		if (!self->open) co_return std::unexpected(self->not_connected(context));
		if (self->upgrading)
			co_return fail(client_errc::operation_in_progress, context + " during an earlier StartTLS");
		if (self->binding) co_return fail(client_errc::operation_in_progress, context + " during a bind");
		if (const std::size_t n = self->pending.size(); n != 0)
			co_return fail(client_errc::operation_in_progress,
			  context + " with " + std::to_string(n) + (n == 1 ? " request" : " requests") + " outstanding");
		// Checked before the wait too, so misuse fails at once.
		if (self->transport.type() != net::transport::kind::tcp || self->transport.is_tls())
			co_return fail(std::make_error_code(std::errc::invalid_argument),
			  context + ": needs a plain TCP connection (not ldaps://, ldapi:// or a custom stream)");
		const std::size_t due = self->due_answers;
		if (due == 0) break;
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
		if (ec)
			co_return fail(ec,
			  context + " (waiting for the answer" + (left == 1 ? "" : "s") + " to " + std::to_string(left)
				+ " paged search release" + (left == 1 ? ")" : "s)"));
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

	// The reader and writer must be idle: the handshake reads and writes
	// the socket itself. Not cancellable: they stop promptly on their own.
	co_await capy::run(std::stop_token{})([](connection::impl &c) -> capy::task<void> {
		(void)co_await c.write_idle.wait();
		(void)co_await c.reader_idle.wait();
	}(*self));
	if (!self->open) co_return std::unexpected(self->not_connected(context));

	auto r = co_await net::start_tls(self->transport, self->buf, std::move(options), timeout);
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
	co_return result<void>{};
}

capy::task<result<void>> connection::unbind()
{
	const std::string context = "unbind";
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	const impl_ref self(impl_);
	if (!self->open) co_return std::unexpected(self->not_connected(context));
	// Nothing may be sent while a BindRequest is outstanding (RFC 4511
	// section 4.2.1), an UnbindRequest included: just close.
	if (self->binding) {
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
	// not_connected instead of being sent after the UnbindRequest.
	for (auto &a : self->abandoned) a.due = false;
	self->due_answers = 0;
	self->due_changed.set();// the due watcher ends
	self->stop_reader_if_idle();
	message request{ 0, unbind_request{} };
	if (auto r = self->submit(request, nullptr, context); !r) co_return r;
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
	if (failed) co_return std::unexpected(with_context(std::move(*failed), context));
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
	if (state_ == nullptr) co_return std::unexpected(not_connected("search"));
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
			for (auto &uri : ref->uris) s.references.emplace_back(uri);
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

	// Sends the search for the next page (cookie empty for the first).
	result<void> request_page(std::string page_cookie)
	{
		set_page_control(page_size, std::move(page_cookie));
		auto s = start_search(*conn, params, mr);
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
	if (impl_ == nullptr) co_return std::unexpected(not_connected(op_context("search", p.base)));
	if (page_size <= 0)
		co_return fail(client_errc::encode_error,
		  op_context("search", p.base) + ": page size " + std::to_string(page_size) + " is not positive");
	std::pmr::polymorphic_allocator<> alloc(impl_->mr);
	auto *st = alloc.new_object<paged_search::state>(
	  paged_search::state{ impl_ref(impl_), std::move(p), page_size, mr, {}, 0, false, {}, {}, {}, {} });
	ldap::paged_search out = connection::impl::make_paged(st);
	if (auto r = st->request_page({}); !r) co_return std::unexpected(std::move(r.error()));
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
	if (state_ == nullptr) co_return std::unexpected(not_connected("search"));
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
		if (!pr) co_return finish(with_context(std::move(pr.error()), op_context("search", s.params.base)));
		s.cookie = *pr ? std::string((*pr)->cookie) : std::string();
		if (s.cookie.empty()) {
			s.finished = true;
			co_return std::optional<entry>{};
		}
		if (auto r = s.request_page(s.cookie); !r) co_return finish(std::move(r.error()), false);
	}
}

// ---------------------------------------------------------------- connect

capy::task<result<connection>>
  connect(corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)
{
	if (options.start_tls && u.scheme() != url_scheme::ldap)
		co_return fail(client_errc::invalid_url,
		  "connect " + std::string(u.to_string())
			+ ": start_tls needs an ldap:// URL (ldaps:// and ldapi:// are not upgraded)");
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

}// namespace jhetz::ldap
