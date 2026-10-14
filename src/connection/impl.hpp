// Internal: the state of a connection (connection::impl), shared by its
// operations, and the helpers they share. Coroutine helpers are only
// declared here: each is defined once, the core (impl's members, binds'
// serialization, request_response) in core.cpp, the rest in the module of
// the operations that use them (operations.cpp, password.cpp).
#pragma once

#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/message_io.hpp"

#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace jhetz::ldap {

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

	inline std::string_view op_name(const protocol_op &op) noexcept { return op_names[op.index()]; }

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

	inline bool same_tag(ber::tag a, ber::tag b) noexcept { return a.cls == b.cls && a.number == b.number; }

	using clock = std::chrono::steady_clock;

	inline std::optional<clock::time_point> deadline_after(std::optional<std::chrono::milliseconds> d)
	{
		if (!d) return std::nullopt;
		return clock::now() + *d;
	}

	// The error of an operation on a default-constructed or moved-from
	// object (connection, search_stream, paged_search).
	inline error no_connection(std::string_view context) { return make_error(client_errc::not_connected, context); }

}// namespace detail

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
		boost::capy::async_event ready{};// set while queue is non-empty or finished
	};

}// namespace detail

struct connection::impl
{
	impl(boost::corosio::io_context &ioc,
	  net::transport t,
	  const connection_options &options,
	  std::pmr::memory_resource *mr_);

	boost::corosio::io_context::executor_type ex;
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
	std::pmr::unordered_map<std::int32_t, detail::pending_op *> pending;
	struct abandoned_req
	{
		std::int32_t id;
		bool search;
		// Sent by send_unanswered: an answer is certain (an abandoned
		// request may or may not be answered), until `deadline`, after
		// which it is no longer waited for (but still dropped if it comes).
		bool due = false;
		std::optional<detail::clock::time_point> deadline{};
	};
	std::pmr::deque<abandoned_req> abandoned;
	// Entries of `abandoned` that are `due`: requests still to be answered
	// although nothing waits for them. Counted as outstanding, so StartTLS
	// waits for their answers (RFC 4513 section 3.1.1), and read by the
	// reader, which runs while there are any.
	std::size_t due_answers = 0;
	boost::capy::async_event due_idle{};// set while due_answers is 0 (shut sets it after unbind)
	// The due watcher: runs while a due answer has a deadline, and stops
	// counting it once that passes. Woken by `due_changed` when the due
	// answers change.
	bool watching = false;
	boost::capy::async_event due_changed{};
	// Writer: PDUs waiting to be written, in order.
	std::pmr::deque<std::pmr::vector<std::byte>> outbox;
	bool writing = false;
	boost::capy::async_event write_idle{};// set while the writer is not running
	// A bind exchange (every step of a SASL bind) is in progress: other
	// requests are held until it ends, since nothing may be sent while a
	// BindRequest is outstanding (RFC 4511 section 4.2.1).
	bool binding = false;
	boost::capy::async_event bind_idle{};// set while `binding` is false
	struct held_request
	{
		std::int32_t id;
		std::pmr::vector<std::byte> bytes;
	};
	std::pmr::deque<held_request> held;
	// Reader: runs while `pending` is not empty or answers are due.
	bool reading = false;
	std::stop_source reader_stop{};
	boost::capy::async_event reader_idle{};// set while the reader is not running
	// StartTLS in progress: no other request may be sent (RFC 4511 4.14.1),
	// and is_tls() is false (the TLS layer is set before the handshake).
	bool upgrading = false;
	// What the connection knows about the server: the modes set by the
	// options, and the caches filled from the server's answers.
	struct server_knowledge
	{
		// schema_check::on_first_use: the loaded schema and the types checked.
		ldap::schema_check schema_mode = ldap::schema_check::off;
		std::shared_ptr<const server_schema> schema{};
		std::vector<std::type_index> schema_checked{};
		// change_password / reset_password: the connection's default method, and
		// the one the root DSE advertised (password_method::automatic), once read.
		ldap::password_method password_mode = ldap::password_method::automatic;
		std::optional<ldap::password_method> advertised_password_method{};

		// Discards what was learnt from the server (the modes are kept).
		void forget() noexcept
		{
			schema.reset();
			schema_checked.clear();
			advertised_password_method.reset();
		}
	};
	server_knowledge knowledge{};
	// Unsolicited notifications are decoded here, then released.
	std::pmr::monotonic_buffer_resource scratch;

	// ---------------------------------------------------------------- refs

	// Inline: impl_ref copies call them from every module.
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
	static error copy_error(const error &e) noexcept;

	// not_enough_memory without a context, so building and copying it
	// allocates nothing; operations add their own.
	static error out_of_memory() noexcept;

	// Closes the transport and fails every outstanding operation with `e`
	// (they add their own context). `remember`: later operations name it.
	// `close_transport` false: the caller closes it (unbind, after the TLS
	// shutdown). Never throws: destructors and the detached tasks call it.
	void shut(error e, bool remember, bool close_transport = true) noexcept;

	// An allocation failed where no exception may go: in a destructor (an
	// AbandonRequest, the requests a bind held) or a detached task (the
	// writer, the reader, the due watcher). What was to be sent or read is
	// lost, so the connection cannot go on: it is closed, and its
	// operations fail with not_enough_memory instead of waiting for what
	// never comes.
	void shut_out_of_memory() noexcept;

	error not_connected(std::string_view context) const;

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
	boost::capy::task<void> new_task(boost::capy::task<void> (*body)(impl *));

	// ---------------------------------------------------------------- writer

	// A bad_alloc in a detached task would end the program (run_async's
	// default handler): each catches its own and closes the connection.
	static boost::capy::task<void> writer(impl *self);

	// Queues `bytes` and starts the writer if it is not running. A throw
	// (bad_alloc) queues nothing and changes nothing.
	void enqueue(std::pmr::vector<std::byte> bytes);

	// The next message id the server cannot still be servicing (RFC 4511
	// section 4.1.1): after wrapping at maxInt, ids of outstanding or
	// recently abandoned requests are skipped.
	std::int32_t free_id() const;

	// Gives `m` the next free message id, encodes it and queues it for the
	// writer. If `p` is given it is registered under that id first (its
	// response may arrive before the write completes). If encoding fails
	// nothing is sent and the id is not used up. On a throw (bad_alloc)
	// nothing is queued and `p` is not registered (the id is used up).
	result<void> submit(message &m, detail::pending_op *p, std::string_view context);

	// The bind exchange ended: sends the requests it held, in order. Called
	// from a destructor: if one cannot be queued, the connection is closed
	// (the held requests fail with not_enough_memory).
	void release_held() noexcept;

	// Stops waiting for `p`'s responses and tells the server (best effort).
	// Called from destructors: if the AbandonRequest cannot be built or
	// queued, the connection is closed (a late response would then match
	// no request).
	void abandon(detail::pending_op &p) noexcept;

	// Sends `m` without waiting for an answer: its responses are dropped like
	// late responses to an abandoned request. `m` must be a request that is
	// always answered: the answer is counted as `due` until it arrives or
	// `deadline` passes, and a reader is started to read it. Best effort:
	// nothing is sent if the connection is closed or cannot send `m` now.
	// Never suspends.
	void send_unanswered(message &m,
	  bool search,
	  std::optional<detail::clock::time_point> deadline,
	  std::string_view context);

	// Forgets an abandoned request: a later response for it is unexpected.
	void forget_abandoned(std::pmr::deque<abandoned_req>::iterator a);

	// Forgets an abandoned request if there are too many: the oldest whose
	// answer is not due (those are the least likely to still come), else
	// the oldest. Never the one just added.
	void trim_abandoned();

	// due_answers changed: wakes a StartTLS waiting for 0, and the due
	// watcher.
	void due_updated();

	// ---------------------------------------------------------------- due answers

	void start_due_watcher();

	// The earliest deadline of a due answer, if any has one.
	std::optional<detail::clock::time_point> next_due_deadline() const;

	// Due answers whose deadline passed are no longer waited for: their
	// entries stay (a late answer is still dropped), but they are not
	// counted, so StartTLS proceeds and the reader can stop.
	void expire_due(detail::clock::time_point now);

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
	static boost::capy::task<void> due_watcher(impl *self);

	// Requests still to be answered: those waited for, and `due` answers.
	std::size_t outstanding() const noexcept;

	// Requests waited for (registered operations), without the due answers.
	std::size_t requests_waiting() const noexcept { return pending.size(); }

	// Answers still due to requests nothing waits for (send_unanswered).
	std::size_t answers_due() const noexcept { return due_answers; }

	// What wait_due_answers() ended with: no error (woken, or timed out with
	// nothing left: check again), or the error and the answers it leaves.
	struct due_wait
	{
		std::error_code ec{};
		std::size_t left = 0;
	};

	// StartTLS's wait for the answers due (answers_due() != 0), until
	// `deadline` at most: starts the reader and the due watcher if they are
	// not running, waits for due_idle, and on a timeout expires the answers
	// past their own deadline. `left` is the count waited for, or after a
	// timeout the count still due. A throw (bad_alloc) is the caller's.
	boost::capy::task<due_wait> wait_due_answers(std::optional<detail::clock::time_point> deadline);

	// Describes the open connection: false after close(), unbind() or a
	// failure, even though the closed transport still holds its TLS layer.
	// False during start_tls() too: the TLS layer is in place before its
	// handshake runs.
	bool is_tls() const noexcept { return open && !upgrading && transport.is_tls(); }

	// ---------------------------------------------------------------- unbind

	// unbind(): every outstanding operation is abandoned with the session
	// (RFC 4511 section 4.3), and the answers due are no longer waited for,
	// without closing the connection (the UnbindRequest is still to be sent).
	void abandon_all_for_unbind();

	// ---------------------------------------------------------------- idle

	// Waits until the writer, then the reader, is idle; and each alone. Not
	// cancellable (they run under an empty stop token): the writer and the
	// reader stop promptly on their own, and a PDU is written whole.
	boost::capy::task<void> wait_io_idle();
	boost::capy::task<void> wait_write_idle();
	boost::capy::task<void> wait_reader_idle();

	// ---------------------------------------------------------------- reader

	void start_reader();

	void stop_reader_if_idle();

	static boost::capy::task<void> reader(impl *self);

	error unexpected(std::string text);

	// Delivers the PDU at the front of buf (`size` bytes) and consumes it.
	void route(std::size_t size);

	// An unsolicited notification (message id 0, RFC 4511 section 4.4).
	void notification(std::span<const std::byte> bytes);

	// search_stream / paged_search constructors are private.
	static ldap::search_stream make_stream(search_stream::state *s) noexcept;
	static ldap::paged_search make_paged(paged_search::state *s) noexcept;

	// ---------------------------------------------------------------- waiting

	// The next response for `p`, waiting until `deadline` at most. On
	// cancellation or timeout `p` is abandoned. Errors carry `context`.
	boost::capy::task<result<message>>
	  next_response(detail::pending_op &p, std::optional<detail::clock::time_point> deadline, std::string_view context);
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

	// Waits until no other bind exchange is in progress (binds are
	// serialized), then marks this one as in progress; bind_exchange ends it.
	// A bind already given up on is not sent: a bind cannot be abandoned, so
	// sending it would only close the connection. The stop is checked after
	// the wait, right before the bind is sent: a stop that comes once
	// bind_idle.set() has claimed the waiter, but before it resumes, does
	// not cancel the wait.
	boost::capy::task<result<void>> begin_bind(impl_ref c, std::string_view context);

	// Ends the bind exchange begun by begin_bind() and sends the requests
	// it held.
	struct bind_exchange
	{
		impl_ref c;
		explicit bind_exchange(impl_ref c_) noexcept : c(std::move(c_)) {}
		bind_exchange(const bind_exchange &) = delete;
		bind_exchange &operator=(const bind_exchange &) = delete;
		~bind_exchange();
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


	// One request with one response (everything but search): sends it,
	// waits for the response of index `expect` and returns it. `self` keeps
	// the state alive across the suspension. One whose stop token is set
	// already is not sent (sending it would only abandon it at once, and an
	// update might be applied): it fails with capy::error::canceled. Binds
	// are checked by begin_bind() instead: a later step of a SASL exchange
	// is sent, since the server waits for it (abandoning it then closes the
	// connection).
	boost::capy::task<result<message>> request_response(impl_ref self,
	  message request,
	  std::size_t expect,
	  std::string context,
	  std::optional<std::chrono::milliseconds> timeout);

	// Builds a message whose controls are `controls` (encoded on `mr`).
	result<message> with_controls(protocol_op op,
	  const request_controls &controls,
	  std::pmr::memory_resource *mr,
	  std::string_view context);

	boost::capy::task<result<response>> modify_impl(impl_ref self, modify_params p, std::string context);

	boost::capy::task<result<extended_result>> extended_impl(impl_ref self, extended_params p);

	// `context` names the operation in errors, instead of "extended
	// operation <oid>".
	boost::capy::task<result<std::optional<std::string>>>
	  password_modify_impl(impl_ref self, password_modify_params p, std::string context);

}// namespace detail

}// namespace jhetz::ldap
