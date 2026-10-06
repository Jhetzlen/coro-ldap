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
#include <memory_resource>
#include <span>
#include <stdexcept>
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

	// Validates and sends a search; returns its stream. Never suspends.
	result<ldap::search_stream> start_search(connection::impl &c, search_params &p, std::pmr::memory_resource *mr)
	{
		std::string context = op_context("search", p.base);
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
		auto request = with_controls(std::move(wire), p.controls, c.mr, context);
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
	message request(std::pmr::polymorphic_allocator<>(self->mr));
	request.op = bind_request(3, name.to_string(self->mr), simple_auth(password, self->mr), self->mr);
	auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
	if (!m) co_return std::unexpected(std::move(m.error()));
	const auto &r = std::get<bind_response>(m->op);// checked by the reader
	if (!r.result.is_success()) co_return std::unexpected(r.result.to_error(context));
	co_return result<void>{};
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

	// Sends the search for the next page (cookie empty for the first).
	result<void> request_page(std::string cookie)
	{
		auto &cs = params.controls;
		std::erase_if(cs, [](const request_control &c) {
			return std::holds_alternative<paged>(c)
				   || (std::holds_alternative<control>(c) && std::get<control>(c).type == paged_results_oid);
		});
		cs.push_back(paged{ .page_size = page_size, .cookie = std::move(cookie) });
		auto s = start_search(*conn, params, mr);
		if (!s) return std::unexpected(std::move(s.error()));
		current = std::move(*s);
		++pages;
		return {};
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
	  paged_search::state{ impl_ref(impl_), std::move(p), page_size, mr, {}, 0, false, {}, {}, {} });
	ldap::paged_search out = connection::impl::make_paged(st);
	if (auto r = st->request_page({}); !r) co_return std::unexpected(std::move(r.error()));
	co_return std::move(out);
}

namespace {

	void delete_paged(paged_search::state *s) noexcept
	{
		if (s == nullptr) return;
		impl_ref keep = s->conn;
		std::pmr::polymorphic_allocator<> alloc(keep->mr);
		alloc.delete_object(s);// its current stream abandons its search
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
	auto finish = [&s](error e) -> result<std::optional<entry>> {
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
		if (!*pr || (*pr)->cookie.empty()) {
			s.finished = true;
			co_return std::optional<entry>{};
		}
		if (auto r = s.request_page(std::string((*pr)->cookie)); !r) co_return finish(std::move(r.error()));
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
