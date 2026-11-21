// connection::core, a connection's state behind the operations, and the
// helpers they share.
#pragma once

#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/message_io.hpp"

#include "../net/deadline.hpp"
#include "../scope_util.hpp"
#include "../strand_util.hpp"

#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace jhetz::ldap {

namespace detail {

	template<class T, class... Ts> consteval auto index_in(const std::variant<Ts...> *) -> std::size_t
	{
		constexpr std::array<bool, sizeof...(Ts)> same{ std::is_same_v<T, Ts>... };
		for (std::size_t i = 0; i < sizeof...(Ts); ++i) {
			if (same[i]) {
				return i;
			}
		}
		return sizeof...(Ts);
	}
	template<class T> inline constexpr std::size_t op_index = index_in<T>(static_cast<const protocol_op *>(nullptr));

	using clock = std::chrono::steady_clock;

	// No deadline for nullopt or a timeout too large for the clock
	// (ldap::no_timeout).
	inline auto deadline_after(std::optional<std::chrono::milliseconds> d) -> std::optional<clock::time_point>
	{
		return net::detail::deadline_after(d);
	}

	// The error of an operation on a default-constructed or moved-from
	// object (connection, search_stream, paged_search).
	inline auto no_connection(std::string_view context) -> error
	{
		return make_error(client_errc::not_connected, context);
	}

}// namespace detail

// ---------------------------------------------------------------- state

namespace detail {

	// One outstanding request, registered by message id while it waits for
	// responses.
	struct pending_op
	{
		explicit pending_op(std::pmr::memory_resource *mr_, bool search_, std::size_t expect_)
		  : mr(mr_), search(search_), expect(expect_), queue(mr_)
		{}
		pending_op(const pending_op &) = delete;
		pending_op(pending_op &&) = delete;
		auto operator=(const pending_op &) -> pending_op & = delete;
		auto operator=(pending_op &&) -> pending_op & = delete;
		~pending_op() = default;

		std::pmr::memory_resource *mr;// responses are decoded into this
		bool search;// many responses, until a SearchResultDone
		std::size_t expect;// protocol_op index of the (final) response
		std::int32_t id = 0;
		bool registered = false;
		// False for Bind and StartTLS (RFC 4511 section 4.11): giving up on them
		// closes the connection.
		bool abandonable = true;
		// Queue the IntermediateResponses too (decoded on mr); false: the
		// reader skips them unread.
		bool intermediates = false;
		std::pmr::deque<message> queue;// on mr, so messages move in without a copy
		bool finished = false;// final response queued, or failed / abandoned
		// The writer took the request's bytes; false while queued or held by a
		// bind (a closing failure then gives not_sent).
		bool sent = false;
		// Why the request failed without a response to queue.
		std::optional<error> failure{};
		boost::capy::async_event ready{};// set while queue is non-empty or finished
	};

}// namespace detail

// The multiplexing core; its members keep the invariants (message ids,
// writer, reader, due answers, bind and StartTLS exclusions).
// NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding): grouped by concern, see above
class connection::core
{
  public:
	core(executor_type strand, net::transport t, const connection_options &options, std::pmr::memory_resource *memory);

	// ---------------------------------------------------------------- refs

	// Inline: core_ref copies call them from every module, on any thread.
	void add_ref() noexcept { refs.fetch_add(1, std::memory_order_relaxed); }
	void release() noexcept
	{
		if (refs.fetch_sub(1, std::memory_order_acq_rel) != 1) {
			return;
		}
		std::pmr::polymorphic_allocator<> alloc(mr_);
		alloc.delete_object(this);
	}

	// The ldap::connection handles on this state (a subset of refs).
	// release_handle() is true for the last one.
	void add_handle() noexcept { handles.fetch_add(1, std::memory_order_relaxed); }
	[[nodiscard]] auto release_handle() noexcept -> bool
	{
		return handles.fetch_sub(1, std::memory_order_acq_rel) == 1;
	}

	// ---------------------------------------------------------------- configuration

	auto executor() const noexcept -> const executor_type & { return ex; }
	auto mr() const noexcept -> std::pmr::memory_resource * { return mr_; }
	auto transport() const noexcept -> const net::transport & { return transport_; }
	auto default_timeout() const noexcept -> std::optional<std::chrono::milliseconds> { return default_timeout_; }

	// Tests only (detail::set_next_message_id): the id the next request gets,
	// to reach maxInt without sending 2^31 requests.
	void set_next_message_id(std::int32_t id) noexcept { next_id = id; }

	// detail::set_close_hook: `hook` runs once, when shut() closes the connection.
	void set_close_hook(std::move_only_function<void() noexcept> hook) noexcept { close_hook = std::move(hook); }

	// ---------------------------------------------------------------- snapshots

	// Snapshots for the accessors on any thread.
	auto published_open() const noexcept -> bool { return open_snapshot.load(std::memory_order_acquire); }
	auto published_accepts_requests() const noexcept -> bool
	{
		return published_open() && accepting_snapshot.load(std::memory_order_acquire);
	}
	auto published_tls() const noexcept -> bool
	{
		return published_open() && tls_snapshot.load(std::memory_order_acquire);
	}
	auto published_security_layer() const noexcept -> sasl_protection
	{
		return published_open() ? layer_snapshot.load(std::memory_order_acquire) : sasl_protection::none;
	}
	auto published_outstanding() const noexcept -> std::size_t
	{
		return published_open() ? outstanding_snapshot.load(std::memory_order_relaxed) : 0;
	}
	auto published_bind_count() const noexcept -> std::uint64_t
	{
		return binds_snapshot.load(std::memory_order_relaxed);
	}

	// Updates the snapshots: called on the strand after each change.
	void publish() noexcept;

	// At once on the strand, else posted to it.
	void request_close() noexcept;

	// ---------------------------------------------------------------- state

	auto is_open() const noexcept -> bool { return open; }

	// Requests may still be sent: open, and no UnbindRequest queued.
	auto accepts_requests() const noexcept -> bool { return open && !unbinding; }

	// A bind or a StartTLS exchange is in progress: nothing else may be
	// sent until it ends (RFC 4511 sections 4.2.1 and 4.14.1).
	auto exchange_in_progress() const noexcept -> bool { return binding || upgrading; }

	// False after close(), unbind() or a failure, and during start_tls().
	auto is_tls() const noexcept -> bool { return open && !upgrading && transport_.is_tls(); }

	// The channel bindings for a new authentication, without tls-exporter once
	// one used it, and the mark that one did.
	auto authentication_channel_bindings() const noexcept -> ldap::channel_bindings;
	void mark_tls_exporter_used() noexcept;

	// A password may not be sent: plain TCP with no confidentiality layer,
	// and connection_options::allow_cleartext_passwords is off.
	auto refuses_cleartext_password() const noexcept -> bool
	{
		return !allow_cleartext_passwords_ && transport_.type() == net::transport::kind::tcp && !transport_.is_tls()
			   && transport_.security_layer() != sasl_protection::confidentiality;
	}

	// The SASL security layer in effect (connection::security_layer()).
	auto security_layer() const noexcept -> sasl_protection
	{
		return open ? transport_.security_layer() : sasl_protection::none;
	}
	// `layer` takes effect if the next BindResponse is a success.
	void arm_security_layer(std::unique_ptr<sasl_security_layer> layer) noexcept { armed_layer = std::move(layer); }
	void disarm_security_layer() noexcept { armed_layer.reset(); }

	// Requests still to be answered: those waited for, and `due` answers.
	auto outstanding() const noexcept -> std::size_t;

	// Bind exchanges begun (connection::bind_count()).
	auto bind_count() const noexcept -> std::uint64_t { return binds_begun; }

	// Answers still due to requests nothing waits for (send_unanswered).
	auto answers_due() const noexcept -> std::size_t { return due_answers; }

	// ---------------------------------------------------------------- failure

	// Closes the transport and fails every outstanding operation with `e`.
	// `remember`: later operations name it. Never throws.
	void shut(const error &e, bool remember, bool close_transport = true) noexcept;

	// An allocation failed where no exception may go: closes the connection,
	// its operations failing with not_enough_memory.
	void shut_out_of_memory() noexcept;

	auto not_connected(std::string_view context) const -> error;
	// not_connected's error with client_errc::not_sent.
	auto not_sent(std::string_view context) const -> error;

	// connection::close(): shuts the connection ("connection closed") and
	// closes the transport, which also ends a TLS shutdown unbind() waits for.
	void close() noexcept;

	// ---------------------------------------------------------------- requests

	// Gives `m` the next free message id, registers `p` under it, encodes and
	// queues it. On failure nothing is queued.
	auto submit(message &m, detail::pending_op *p, std::string_view context) -> result<void>;

	// Stops waiting for `p`'s responses and sends an AbandonRequest; closes the
	// connection if that cannot be queued.
	void abandon(detail::pending_op &p) noexcept;

	// Sends `m` without waiting for its answer, counted as due until it
	// arrives or `deadline` passes. Best effort; never suspends.
	void send_unanswered(message &m,
	  bool search,
	  std::optional<detail::clock::time_point> deadline,
	  std::string_view context);

	// The next response for `p`, waiting until `deadline` at most. On
	// cancellation or timeout `p` is abandoned. Errors carry `context`.
	auto next_response(detail::pending_op &p,
	  std::optional<detail::clock::time_point> deadline,
	  std::string_view context) -> boost::capy::task<result<message>>;

	// The state of `c` (null for a default-constructed or moved-from one).
	static auto of(const connection &c) noexcept -> core * { return c.core_.get(); }

	// search_stream / transaction constructors are private.
	static auto make_stream(search_stream::state *s) noexcept -> ldap::search_stream;
	// A stream's state (null for a default-constructed or moved-from one).
	static auto stream_state(ldap::search_stream &s) noexcept -> search_stream::state * { return s.state_; }
	static auto stream_state(const ldap::search_stream &s) noexcept -> const search_stream::state * { return s.state_; }
	static auto make_transaction(transaction::state *s) noexcept -> ldap::transaction { return ldap::transaction(s); }

	// ---------------------------------------------------------------- binds

	// Waits until no other bind exchange is in progress, then marks this one;
	// bind_scope ends it. A bind already stopped is not sent.
	static auto begin_bind(detail::core_ref c, std::string_view context) -> boost::capy::task<result<void>>;

	// Ends the bind exchange begun by begin_bind(): sends the requests it
	// held after a successful bind, fails them otherwise. Defined after
	// detail::core_ref.
	class bind_scope;

	// ---------------------------------------------------------------- StartTLS

	// Fails unless StartTLS may be sent now (RFC 4513 section 3.1.1).
	auto check_start_tls(std::string_view context) const -> result<void>;

	// What wait_due_answers() ended with: no error (woken, or timed out with
	// nothing left: check again), or the error and the answers it leaves.
	struct due_wait
	{
		std::error_code ec{};
		std::size_t left = 0;
	};

	// Waits for the answers due until `deadline`; `left` is the count still
	// due.
	auto wait_due_answers(std::optional<detail::clock::time_point> deadline) -> boost::capy::task<due_wait>;

	// While the guard lives no other request may be sent and is_tls() is false.
	[[nodiscard]] auto upgrade_scope() noexcept
	{
		upgrading = true;
		publish();
		return detail::scope_exit{ [this] noexcept {
			upgrading = false;
			publish();
		} };
	}

	// Waits until the writer, then the reader, is idle. Not cancellable.
	auto wait_io_idle() -> boost::capy::task<void>;

	// The TLS handshake over the transport, once the reader and writer are
	// idle (wait_io_idle): net::start_tls, with the bytes already read.
	auto tls_handshake(net::tls_options options, std::optional<std::chrono::milliseconds> timeout)
	  -> boost::capy::task<result<void>>;

	// ---------------------------------------------------------------- unbind

	// Queues the UnbindRequest, abandoning every outstanding operation; nothing
	// may follow it.
	auto send_unbind(std::string_view context) -> result<void>;

	// Waits for the writer, shuts the connection, sends close_notify and
	// closes the transport; the failure that closed it first, if any.
	auto finish_unbind() -> boost::capy::task<std::optional<error>>;

  private:
	executor_type ex;
	std::pmr::memory_resource *mr_;
	std::atomic<std::size_t> refs = 0;
	std::atomic<std::size_t> handles = 0;
	std::atomic<bool> open_snapshot = true;
	std::atomic<bool> accepting_snapshot = true;
	std::atomic<bool> tls_snapshot = false;
	std::atomic<sasl_protection> layer_snapshot = sasl_protection::none;
	std::atomic<std::size_t> outstanding_snapshot = 0;
	std::atomic<std::uint64_t> binds_snapshot = 0;
	net::transport transport_;
	net::read_buffer buf;
	std::size_t max_message_size;
	std::size_t max_elements;
	std::optional<std::chrono::milliseconds> default_timeout_;
	bool allow_cleartext_passwords_;
	std::optional<std::chrono::milliseconds> tls_shutdown_timeout;
	std::int32_t next_id = 1;
	std::move_only_function<void() noexcept> close_hook{};// set_close_hook
	bool wrapped = false;// next_id went past maxInt: ids may be in use
	bool open = true;
	// unbind() sent its UnbindRequest and waits for the writer: still open,
	// but nothing more may be sent (RFC 4511 section 4.3).
	bool unbinding = false;
	std::optional<error> failure{};// why the connection closed, if it failed
	std::pmr::unordered_map<std::int32_t, detail::pending_op *> pending;
	struct abandoned_req
	{
		std::int32_t id{};
		bool search{};
		// Sent by send_unanswered: an answer is certain, waited for until
		// `deadline`.
		bool due = false;
		std::optional<detail::clock::time_point> deadline{};
	};
	std::pmr::deque<abandoned_req> abandoned;
	// Entries of `abandoned` that are `due`, counted as outstanding.
	std::size_t due_answers = 0;
	boost::capy::async_event due_idle{};// set while due_answers is 0 (shut sets it after unbind)
	// The due watcher runs while a due answer has a deadline.
	bool watching = false;
	boost::capy::async_event due_changed{};
	// Writer: PDUs waiting to be written, in order, each with its message id
	// (the writer marks the pending_op of that id as sent when it takes it).
	struct queued_pdu
	{
		std::int32_t id;
		std::pmr::vector<std::byte> bytes;
	};
	std::pmr::deque<queued_pdu> outbox;
	bool writing = false;
	boost::capy::async_event write_idle{};// set while the writer is not running
	// A bind exchange is in progress: other requests are held.
	bool binding = false;
	std::uint64_t binds_begun = 0;// bind exchanges begun (sent), whatever their outcome
	boost::capy::async_event bind_idle{};// set while `binding` is false
	struct held_request
	{
		std::int32_t id;
		std::pmr::vector<std::byte> bytes;
		bool abandon = false;// an AbandonRequest: sent whatever the bind's outcome
	};
	std::pmr::deque<held_request> held;
	// Reader: runs while `pending` is not empty or answers are due.
	bool reading = false;
	std::stop_source reader_stop{};
	boost::capy::async_event reader_idle{};// set while the reader is not running
	// StartTLS in progress (upgrade_scope()).
	bool upgrading = false;
	// arm_security_layer(): installed by route() on the next successful
	// BindResponse.
	std::unique_ptr<sasl_security_layer> armed_layer{};
	// Unsolicited notifications and late answers to abandoned searches are
	// decoded here, then released.
	std::pmr::monotonic_buffer_resource scratch;

	// Held by the writer and reader frames, so the state is released even
	// if a frame is destroyed without finishing (io_context destroyed).
	struct frame_ref
	{
		core *p;
		explicit frame_ref(core *p_) noexcept : p(p_) {}
		frame_ref(const frame_ref &) = delete;
		auto operator=(const frame_ref &) -> frame_ref & = delete;
		~frame_ref() { p->release(); }
	};

	// ---------------------------------------------------------------- failure

	// A copy of `e`, or out_of_memory() if it cannot be made. Never throws.
	static auto copy_error(const error &e) noexcept -> error;

	// A copy of `e` with client_errc::not_sent; an allocation failure stays
	// not_enough_memory.
	static auto unsent_error(const error &e) noexcept -> error;

	// not_enough_memory without a context, so building and copying it
	// allocates nothing; operations add their own.
	static auto out_of_memory() noexcept -> error;

	// ---------------------------------------------------------------- tasks

	// The frame of a detached task (writer, reader, due watcher), from the
	// executor's frame allocator; made before the caller sets its flags.
	auto new_task(boost::capy::task<void> (*body)(core *)) -> boost::capy::task<void>;

	// ---------------------------------------------------------------- writer

	// Each detached task catches its own bad_alloc and closes the connection.
	static auto writer(core *self) -> boost::capy::task<void>;

	// Queues `bytes` and starts the writer if needed; a throw changes nothing.
	void enqueue(std::int32_t id, std::pmr::vector<std::byte> bytes);

	// The next message id not outstanding or recently abandoned (RFC 4511
	// section 4.1.1).
	auto free_id() const -> std::int32_t;

	// Sends the requests the bind held, in order; closes the connection if one
	// cannot be queued.
	void release_held() noexcept;

	// Fails the requests the bind held with client_errc::bind_failed naming
	// `bind_error` (null: the bind did not complete), without sending them;
	// AbandonRequests are still sent.
	void fail_held(const error *bind_error) noexcept;

	// Forgets an abandoned request: a later response for it is unexpected.
	void forget_abandoned(const std::pmr::deque<abandoned_req>::iterator &a);

	// Forgets the oldest abandoned request whose answer is not due, else the
	// oldest, never the one just added.
	void trim_abandoned();

	// due_answers changed: wakes a StartTLS waiting for 0, and the due
	// watcher.
	void due_updated();

	// ---------------------------------------------------------------- due answers

	void start_due_watcher();

	// The earliest deadline of a due answer, if any has one.
	auto next_due_deadline() const -> std::optional<detail::clock::time_point>;

	// Due answers past their deadline are no longer counted (late answers are
	// still dropped).
	void expire_due(detail::clock::time_point now);

	// Sleeps until the next due deadline (or a change), then expires what is
	// past; ends when no due answer has a deadline.
	static auto due_watcher(core *self) -> boost::capy::task<void>;

	// Requests waited for (registered operations), without the due answers.
	auto requests_waiting() const noexcept -> std::size_t { return pending.size(); }

	// ---------------------------------------------------------------- unbind

	// Abandons every outstanding operation and stops waiting for the answers
	// due, without closing the connection.
	void abandon_all_for_unbind();

	// ---------------------------------------------------------------- idle

	// Waits until the writer, or the reader, is idle (see wait_io_idle).
	auto wait_write_idle() -> boost::capy::task<void>;
	auto wait_reader_idle() -> boost::capy::task<void>;

	// ---------------------------------------------------------------- reader

	void start_reader();

	void stop_reader_if_idle();

	static auto reader(core *self) -> boost::capy::task<void>;

	auto unexpected(std::string_view text) -> error;

	// Delivers the PDU at the front of buf (`size` bytes) and consumes it.
	void route(std::size_t size);

	// Installs the armed security layer if `m` is a successful BindResponse,
	// else drops it; false if the connection was shut.
	auto take_armed_layer(const message &m) -> bool;

	// Whether the PDU `bytes` is a failed ExtendedResponse without a
	// responseName (decoded in scratch).
	auto is_refusal(std::span<const std::byte> bytes) -> bool;

	// An unsolicited notification (message id 0, RFC 4511 section 4.4).
	void notification(std::span<const std::byte> bytes);
};

namespace detail {

	template<class Core> counted_ref<Core>::counted_ref(Core *p) noexcept : p_(p)
	{
		if (p_ != nullptr) {
			p_->add_ref();
		}
	}
	template<class Core> counted_ref<Core>::counted_ref(const counted_ref &o) noexcept : counted_ref(o.p_) {}
	template<class Core> counted_ref<Core>::counted_ref(counted_ref &&o) noexcept : p_(std::exchange(o.p_, nullptr)) {}
	template<class Core> auto counted_ref<Core>::operator=(counted_ref &&o) noexcept -> counted_ref &
	{
		counted_ref moved(std::move(o));
		std::swap(p_, moved.p_);
		return *this;
	}
	template<class Core> counted_ref<Core>::~counted_ref()
	{
		if (p_ != nullptr) {
			p_->release();
		}
	}

}// namespace detail

namespace detail {

	// Runs `body` on the connection's strand (on_strand in strand_util.hpp);
	// a null `self` (no connection) runs it inline.
	template<class T> auto on_strand(const core_ref &self, boost::capy::task<T> body) -> boost::capy::task<T>
	{
		if (!self) {
			return body;
		}
		return detail::on_strand(self->executor(), std::move(body));
	}

	// Runs `f` on `c`'s strand (run_on_strand in strand_util.hpp).
	template<class F> void run_on_strand(connection::core &c, F f) noexcept
	{
		detail::run_on_strand(c.executor(), std::move(f));
	}

}// namespace detail

class connection::core::bind_scope
{
  public:
	explicit bind_scope(detail::core_ref c) noexcept : c_(std::move(c)) {}
	bind_scope(const bind_scope &) = delete;
	auto operator=(const bind_scope &) -> bind_scope & = delete;
	~bind_scope();

	// Records the exchange's outcome and returns it; without one the bind
	// counts as failed.
	auto end(result<void> r) noexcept -> result<void>;

  private:
	detail::core_ref c_;
	bool succeeded_ = false;
	std::optional<error> failure_{};
};

namespace detail {

	// Abandons `p` when the guard goes out of scope.
	[[nodiscard]] inline auto registration(connection::core &c, pending_op &p) noexcept
	{
		return scope_exit{ [&c, &p] noexcept { c.abandon(p); } };
	}

	// Sends a request and returns its response of index `expect`; with
	// `intermediates`, the IntermediateResponses before it are appended. Not
	// sent if the stop token is already set.
	auto request_response(core_ref self,
	  message request,
	  std::size_t expect,
	  std::string context,
	  std::optional<std::chrono::milliseconds> timeout,
	  std::pmr::vector<intermediate> *intermediates = nullptr) -> boost::capy::task<result<message>>;

	// A message of `op` carrying `controls`, already encoded on `mr`.
	auto with_controls(protocol_op op, std::pmr::vector<control> controls, std::pmr::memory_resource *mr) -> message;

	// A message of `op` with `controls` encoded on `mr`.
	template<class List>
	auto build_request(protocol_op op, const List &controls, std::pmr::memory_resource *mr, std::string_view context)
	  -> result<message>
	{
		std::pmr::vector<control> wire(mr);
		if (auto c = append_controls(controls, wire); !c) {
			return std::unexpected(detail::with_context(std::move(c.error()), context));
		}
		return with_controls(std::move(op), std::move(wire), mr);
	}

	// The update operations once the connection is known (core_ != nullptr);
	// `context` names the operation in errors.
	auto add_impl(core_ref self, add_params request, std::string context) -> boost::capy::task<result<response>>;
	auto modify_impl(core_ref self, modify_params request, std::string context) -> boost::capy::task<result<response>>;
	auto del_impl(core_ref self, del_params request, std::string context) -> boost::capy::task<result<response>>;
	auto modify_dn_impl(core_ref self, modify_dn_params request, std::string context)
	  -> boost::capy::task<result<response>>;

	auto extended_impl(core_ref self, extended_params request) -> boost::capy::task<result<extended_result>>;

}// namespace detail

}// namespace jhetz::ldap
