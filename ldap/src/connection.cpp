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
#include <deque>
#include <memory_resource>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
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
		default_timeout(options.operation_timeout), pending(mr_), abandoned(mr_), outbox(mr_), scratch(mr_)
	{
		write_idle.set();
	}

	corosio::io_context::executor_type ex;
	std::pmr::memory_resource *mr;
	std::size_t refs = 1;
	net::transport transport;
	net::read_buffer buf;
	std::size_t max_message_size;
	std::optional<std::chrono::milliseconds> default_timeout;
	std::int32_t next_id = 1;
	bool open = true;
	std::optional<error> failure{};// why the connection closed, if it failed
	std::pmr::unordered_map<std::int32_t, pending_op *> pending;
	struct abandoned_req
	{
		std::int32_t id;
		bool search;
	};
	std::pmr::deque<abandoned_req> abandoned;
	// Writer: PDUs waiting to be written, in order.
	std::pmr::deque<std::pmr::vector<std::byte>> outbox;
	bool writing = false;
	capy::async_event write_idle{};// set while the writer is not running
	// Reader: runs while `pending` is not empty.
	bool reading = false;
	std::stop_source reader_stop{};
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
	void shut(error e, bool remember)
	{
		if (!open) return;
		open = false;
		if (remember) failure = e;
		transport.close();
		outbox.clear();
		abandoned.clear();
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

	// Gives `m` the next message id, encodes it and queues it for the
	// writer. If `p` is given it is registered under that id first (its
	// response may arrive before the write completes). If encoding fails
	// nothing is sent and the id is not used up.
	result<void> submit(message &m, pending_op *p, std::string_view context)
	{
		if (!open) return std::unexpected(not_connected(context));
		m.id = next_id;
		auto bytes = encode(m, mr);
		if (!bytes) return std::unexpected(with_context(std::move(bytes.error()), context));
		next_id = m.id == max_int ? 1 : m.id + 1;
		if (p != nullptr) {
			p->id = m.id;
			p->registered = true;
			pending.emplace(m.id, p);
			start_reader();
		}
		enqueue(std::move(*bytes));
		return {};
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
		abandoned.push_back({ p.id, p.search });
		if (abandoned.size() > max_abandoned) abandoned.pop_front();
		message m{ 0, abandon_request{ p.id } };
		(void)submit(m, nullptr, "abandon");// cannot fail to encode
	}

	// ---------------------------------------------------------------- reader

	void start_reader()
	{
		if (reading) return;// a reader that is stopping restarts itself if needed
		reading = true;
		reader_stop = std::stop_source{};
		add_ref();// released by the reader
		capy::run_async(ex, reader_stop.get_token())(reader(this));
	}

	void stop_reader_if_idle()
	{
		if (pending.empty() && reading) reader_stop.request_stop();
	}

	static capy::task<void> reader(impl *self)
	{
		const frame_ref ref(self);
		while (self->open && !self->pending.empty()) {
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
		// Stopped while an operation was being registered: start afresh,
		// with a new stop token.
		if (self->open && !self->pending.empty()) self->start_reader();
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
			auto m = decode(bytes, { .from = origin::server, .memory = p.mr });
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
			if (!a->search || same_tag(h->op, search_result_done_tag)) abandoned.erase(a);
			return;
		}
		shut(unexpected("message with id " + std::to_string(h->id) + ", which matches no outstanding request"), true);
	}

	// An unsolicited notification (message id 0, RFC 4511 section 4.4).
	void notification(std::span<const std::byte> bytes)
	{
		std::optional<error> fatal;
		{
			auto m = decode(bytes, { .from = origin::server, .memory = &scratch });
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
			abandon(p);
			std::string text(context);
			text += ec == capy::cond::timeout ? ": timed out" : ": canceled";
			if (open) text += " (abandoned)";
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

	error not_connected(std::string_view context)
	{
		return make_error(client_errc::not_connected, std::string(context) + ": not connected");
	}

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

std::size_t connection::outstanding() const noexcept { return impl_ == nullptr ? 0 : impl_->pending.size(); }

void connection::close() noexcept
{
	if (impl_ == nullptr) return;
	impl_->shut(make_error(client_errc::not_connected, "connection closed"), false);
}

capy::task<result<void>> connection::simple_bind(dn name, std::string password)
{
	const std::string context = op_context("bind", name);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	if (!name.empty() && password.empty())
		co_return fail(client_errc::unauthenticated_bind, context + ": empty password (RFC 4513 section 5.1.2)");
	const impl_ref self(impl_);// `this` may be moved from while suspended

	message request(std::pmr::polymorphic_allocator<>(self->mr));
	request.op = bind_request(3, name.to_string(self->mr), simple_auth(password, self->mr), self->mr);
	pending_op p(self->mr, false, op_index<bind_response>);
	if (auto r = self->submit(request, &p, context); !r) co_return r;
	registration reg(*self, p);

	auto m = co_await self->next_response(p, deadline_after(self->default_timeout), context);
	if (!m) co_return std::unexpected(std::move(m.error()));
	const auto &r = std::get<bind_response>(m->op);// checked by the reader
	if (!r.result.is_success()) co_return std::unexpected(r.result.to_error(context));
	co_return result<void>{};
}

capy::task<result<ldap::search_stream>> connection::search_stream(search_params p, std::pmr::memory_resource *mr)
{
	std::string context = op_context("search", p.base);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	const impl_ref self(impl_);
	const auto seconds = p.time_limit.count();
	if (seconds < 0 || seconds > max_int)
		co_return fail(client_errc::encode_error,
		  context + ": time_limit of " + std::to_string(seconds) + " s is outside 0 .. 2^31-1");

	const std::pmr::polymorphic_allocator<> alloc(self->mr);
	search_request wire(alloc);
	wire.base_object = p.base.to_string(self->mr);
	wire.scope = p.scope;
	wire.deref = p.deref;
	wire.size_limit = p.size_limit;
	wire.time_limit = static_cast<std::int32_t>(seconds);
	wire.types_only = p.types_only;
	wire.filter = std::move(p.filter);
	wire.attributes.assign(p.attributes.begin(), p.attributes.end());
	message request(alloc);
	request.op = std::move(wire);
	request.controls.assign(p.controls.begin(), p.controls.end());

	ldap::search_stream s(new_state(*self, mr, context));
	s.state_->deadline = deadline_after(p.timeout ? p.timeout : self->default_timeout);
	if (auto r = self->submit(request, &s.state_->op, context); !r) co_return std::unexpected(std::move(r.error()));
	co_return std::move(s);
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

capy::task<result<void>> connection::unbind()
{
	const std::string context = "unbind";
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	const impl_ref self(impl_);
	if (!self->open) co_return std::unexpected(self->not_connected(context));

	// Outstanding operations are abandoned by the unbind (RFC 4511 section 4.3).
	auto waiting = std::move(self->pending);
	self->pending.clear();
	for (auto &[id, op] : waiting) {
		op->registered = false;
		op->finished = true;
		op->ready.set();// they fail with not_connected ("connection closed")
	}
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
	self->shut(make_error(client_errc::not_connected, "connection closed"), false);
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
		  client_errc::operation_in_progress, s.context + ": next() is already running on this search_stream");
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

// ---------------------------------------------------------------- connect

capy::task<result<connection>>
  connect(corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)
{
	auto t = co_await net::connect(ioc,
	  std::move(u),
	  net::connect_options{ .timeout = options.timeout, .tls = options.tls, .tcp_no_delay = options.tcp_no_delay },
	  mr);
	if (!t) co_return std::unexpected(std::move(t.error()));
	co_return connection(ioc, std::move(*t), options, mr);
}

}// namespace jhetz::ldap
