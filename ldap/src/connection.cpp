#include "jhetz/ldap/connection.hpp"

#include "jhetz/ldap/net/message_io.hpp"

#include <boost/capy/error.hpp>

#include <array>
#include <memory_resource>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace capy = boost::capy;

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

	std::string_view op_name(const protocol_op &op) noexcept
	{
		static constexpr std::array<std::string_view, 21> names{ "BindRequest",
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
		static_assert(std::variant_size_v<protocol_op> == names.size());
		return names[op.index()];
	}

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

}// namespace

// ---------------------------------------------------------------- state

struct connection::impl
{
	impl(net::transport t, std::size_t max_message_size_, std::pmr::memory_resource *mr_)
	  : mr(mr_), transport(std::move(t)), buf(mr_), writer(mr_), max_message_size(max_message_size_), scratch(mr_)
	{}

	std::pmr::memory_resource *mr;
	net::transport transport;
	net::read_buffer buf;
	ber::writer writer;
	std::size_t max_message_size;
	std::int32_t next_id = 1;
	bool open = true;
	std::optional<error> failure{};// why the connection closed, if it failed
	bool in_io = false;// an operation (or next()) is suspended
	ldap::search_stream *stream = nullptr;// the open search_stream, if any
	std::optional<std::int32_t> drain_id{};// search of a stream destroyed early
	// Responses that are not returned to the caller (bind responses,
	// drained search results) are decoded here and released after each.
	std::pmr::monotonic_buffer_resource scratch;

	// Closes the transport and remembers why; returns `e`.
	error close_with(error e)
	{
		if (open) {
			open = false;
			failure = e;
			transport.close();
		}
		drain_id.reset();
		return e;
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

	// Checks that a new operation may start now.
	result<void> check_ready(std::string_view context) const
	{
		if (!open) return std::unexpected(not_connected(context));
		if (in_io)
			return fail(client_errc::operation_in_progress,
			  std::string(context) + ": another operation of this connection is suspended");
		if (stream != nullptr)
			return fail(client_errc::operation_in_progress,
			  std::string(context) + ": a search_stream of this connection is still open");
		return {};
	}

	// Gives `m` the next message id, encodes it and writes it. If encoding
	// fails nothing is sent, the id is not used up and the connection stays
	// usable; a write error closes the connection. Returns the id.
	capy::task<result<std::int32_t>> send(message &m, std::string_view context)
	{
		m.id = next_id;
		writer.clear();
		if (auto e = encode(writer, m); !e) co_return std::unexpected(with_context(std::move(e.error()), context));
		next_id = m.id == max_int ? 1 : m.id + 1;
		if (auto w = co_await net::write_bytes(transport, writer.bytes()); !w)
			co_return std::unexpected(close_with(with_context(std::move(w.error()), context)));
		co_return m.id;
	}

	// The next message for request `id`, decoded into `memory`. Handles
	// unsolicited notifications and skips IntermediateResponses; any failure
	// closes the connection.
	capy::task<result<message>> read_response(std::int32_t id, std::string context, std::pmr::memory_resource *memory)
	{
		const net::read_options options{ .max_message_size = max_message_size,
			.decode = { .from = origin::server, .memory = memory } };
		while (true) {
			{
				auto m = co_await net::read_message(transport, buf, options);
				if (!m) co_return std::unexpected(close_with(with_context(std::move(m.error()), context)));
				if (m->id == 0) {
					// Unsolicited notification (RFC 4511 section 4.4).
					const auto *x = std::get_if<extended_response>(&m->op);
					if (x == nullptr)
						co_return std::unexpected(close_with(make_error(client_errc::unexpected_response,
						  context + ": " + std::string(op_name(m->op)) + " with message id 0")));
					if (x->response_name && *x->response_name == notice_of_disconnection_oid) {
						error e = x->result.to_error(context + ": notice of disconnection");
						if (x->result.is_success()) e.code = errc::unavailable;// "success" is no error code
						co_return std::unexpected(close_with(std::move(e)));
					}
				} else if (m->id != id) {
					co_return std::unexpected(close_with(make_error(client_errc::unexpected_response,
					  context + ": " + std::string(op_name(m->op)) + " with message id " + std::to_string(m->id)
						+ ", expected " + std::to_string(id))));
				} else if (!std::holds_alternative<intermediate_response>(m->op)) {
					co_return m;
				}
			}
			// Skipped (other unsolicited notifications, IntermediateResponse).
			// If it was decoded into scratch, release that now, so a server
			// cannot grow the arena without bound.
			if (memory == &scratch) scratch.release();
		}
	}

	error unexpected_op(const message &m, std::string_view context, std::string_view request)
	{
		return close_with(make_error(client_errc::unexpected_response,
		  std::string(context) + ": " + std::string(op_name(m.op)) + " in response to a " + std::string(request)));
	}

	// Reads and drops the rest of a search whose stream was destroyed.
	capy::task<result<void>> drain(std::string_view context)
	{
		while (drain_id) {
			bool done = false;
			{
				auto m =
				  co_await read_response(*drain_id, std::string(context) + ": discarding an earlier search", &scratch);
				if (!m) co_return std::unexpected(std::move(m.error()));
				if (std::holds_alternative<search_result_done>(m->op))
					done = true;
				else if (!std::holds_alternative<search_result_entry>(m->op)
						 && !std::holds_alternative<search_result_reference>(m->op))
					co_return std::unexpected(unexpected_op(*m, context, "SearchRequest"));
			}
			scratch.release();
			if (done) drain_id.reset();
		}
		co_return result<void>{};
	}

	capy::task<result<void>> bind(message request, std::string context)
	{
		if (auto d = co_await drain(context); !d) co_return d;
		auto id = co_await send(request, context);
		if (!id) co_return std::unexpected(std::move(id.error()));
		result<void> out{};
		{
			auto m = co_await read_response(*id, context, &scratch);
			if (!m) co_return std::unexpected(std::move(m.error()));
			const auto *r = std::get_if<bind_response>(&m->op);
			if (r == nullptr) co_return std::unexpected(unexpected_op(*m, context, "BindRequest"));
			if (!r->result.is_success()) out = std::unexpected(r->result.to_error(context));
		}
		scratch.release();
		co_return out;
	}

	capy::task<result<std::int32_t>> start_search(message request, std::string context)
	{
		if (auto d = co_await drain(context); !d) co_return std::unexpected(std::move(d.error()));
		co_return co_await send(request, context);
	}

	// Reads until the next entry of `s` or the end of its search.
	capy::task<result<std::optional<entry>>> search_step(ldap::search_stream &s)
	{
		const std::string context(s.context_);
		while (true) {
			auto m = co_await read_response(s.id_, context, s.mr_);
			if (!m) co_return std::unexpected(std::move(m.error()));
			if (auto *e = std::get_if<search_result_entry>(&m->op))
				co_return std::optional<entry>(entry::from(std::move(*e)));// on s.mr_, no copy
			if (auto *ref = std::get_if<search_result_reference>(&m->op)) {
				for (auto &uri : ref->uris) s.references_.emplace_back(uri);
				continue;
			}
			auto *d = std::get_if<search_result_done>(&m->op);
			if (d == nullptr) co_return std::unexpected(unexpected_op(*m, context, "SearchRequest"));
			stream = nullptr;// the search is over: the connection is free
			s.finished_ = true;
			s.controls_.assign(m->controls.begin(), m->controls.end());
			if (!d->result.is_success()) {
				s.error_ = d->result.to_error(context);
				co_return std::unexpected(*s.error_);
			}
			co_return std::optional<entry>{};
		}
	}
};

namespace {

	// Marks the connection busy while an operation is suspended. If the
	// operation's task is destroyed before the operation finished (clean is
	// never set), the connection's state is unknown (a request may be
	// unanswered, a PDU half read), so it is closed.
	struct busy_guard
	{
		connection::impl &c;
		bool clean = false;

		explicit busy_guard(connection::impl &c_) : c(c_) { c.in_io = true; }
		busy_guard(const busy_guard &) = delete;
		busy_guard &operator=(const busy_guard &) = delete;
		~busy_guard()
		{
			c.in_io = false;
			if (!clean && c.open)
				c.close_with(make_error(capy::error::canceled, "an operation was interrupted before it finished"));
		}
	};

	error not_connected(std::string_view context)
	{
		return make_error(client_errc::not_connected, std::string(context) + ": not connected");
	}

}// namespace

// ---------------------------------------------------------------- connection

connection::connection(net::transport t, const connection_options &options, std::pmr::memory_resource *mr)
{
	std::pmr::polymorphic_allocator<> alloc(mr);
	impl_ = alloc.new_object<impl>(std::move(t), options.max_message_size, mr);
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
	if (impl_->stream != nullptr) impl_->stream->detach();
	impl_->transport.close();
	std::pmr::polymorphic_allocator<> alloc(impl_->mr);
	alloc.delete_object(impl_);
}

bool connection::is_open() const noexcept { return impl_ != nullptr && impl_->open; }

std::string_view connection::name() const noexcept
{
	if (impl_ == nullptr) return {};
	return impl_->transport.name();
}

void connection::close() noexcept
{
	if (impl_ == nullptr || !impl_->open) return;
	impl_->open = false;
	impl_->drain_id.reset();
	impl_->transport.close();
}

capy::task<result<void>> connection::simple_bind(dn name, std::string password)
{
	const std::string context = op_context("bind", name);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	if (!name.empty() && password.empty())
		co_return fail(client_errc::unauthenticated_bind, context + ": empty password (RFC 4513 section 5.1.2)");
	if (auto r = impl_->check_ready(context); !r) co_return r;

	message request(std::pmr::polymorphic_allocator<>(impl_->mr));
	request.op = bind_request(3, name.to_string(impl_->mr), simple_auth(password, impl_->mr), impl_->mr);
	busy_guard g(*impl_);
	auto r = co_await impl_->bind(std::move(request), context);
	g.clean = true;
	co_return r;
}

capy::task<result<ldap::search_stream>> connection::search_stream(search_params p, std::pmr::memory_resource *mr)
{
	const std::string context = op_context("search", p.base);
	if (impl_ == nullptr) co_return std::unexpected(not_connected(context));
	if (auto r = impl_->check_ready(context); !r) co_return std::unexpected(std::move(r.error()));
	const auto seconds = p.time_limit.count();
	if (seconds < 0 || seconds > max_int)
		co_return fail(client_errc::encode_error,
		  context + ": time_limit of " + std::to_string(seconds) + " s is outside 0 .. 2^31-1");

	const std::pmr::polymorphic_allocator<> alloc(impl_->mr);
	search_request wire(alloc);
	wire.base_object = p.base.to_string(impl_->mr);
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

	busy_guard g(*impl_);
	auto id = co_await impl_->start_search(std::move(request), context);
	g.clean = true;
	if (!id) co_return std::unexpected(std::move(id.error()));
	ldap::search_stream s(impl_, *id, std::pmr::string(context), mr);
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
	if (impl_ == nullptr || !impl_->open)
		co_return std::unexpected(impl_ == nullptr ? not_connected(context) : impl_->not_connected(context));
	if (impl_->in_io)
		co_return fail(
		  client_errc::operation_in_progress, context + ": another operation of this connection is suspended");

	message request{ 0, unbind_request{} };
	busy_guard g(*impl_);
	auto r = co_await impl_->send(request, context);
	g.clean = true;
	close();
	if (!r) co_return std::unexpected(std::move(r.error()));
	co_return result<void>{};
}

// ---------------------------------------------------------------- search_stream

search_stream::search_stream(connection::impl *conn,
  std::int32_t id,
  std::pmr::string context,
  std::pmr::memory_resource *mr)
  : conn_(conn), id_(id), mr_(mr), context_(std::move(context))
{
	conn_->stream = this;
}

search_stream::search_stream(search_stream &&other) noexcept
  : conn_(std::exchange(other.conn_, nullptr)), id_(other.id_), mr_(other.mr_), finished_(other.finished_),
	error_(std::move(other.error_)), context_(std::move(other.context_)), references_(std::move(other.references_)),
	controls_(std::move(other.controls_))
{
	if (conn_ != nullptr && conn_->stream == &other) conn_->stream = this;
}

search_stream &search_stream::operator=(search_stream &&other) noexcept
{
	if (this != &other) {
		search_stream old(std::move(*this));// finishes this stream's search as the destructor would
		conn_ = std::exchange(other.conn_, nullptr);
		id_ = other.id_;
		mr_ = other.mr_;
		finished_ = other.finished_;
		error_ = std::move(other.error_);
		context_ = std::move(other.context_);
		references_ = std::move(other.references_);
		controls_ = std::move(other.controls_);
		if (conn_ != nullptr && conn_->stream == &other) conn_->stream = this;
	}
	return *this;
}

search_stream::~search_stream()
{
	if (conn_ == nullptr || conn_->stream != this) return;
	conn_->stream = nullptr;
	// Its remaining responses are still coming: the next operation drops them.
	if (conn_->open) conn_->drain_id = id_;
}

void search_stream::detach() noexcept { conn_ = nullptr; }

capy::task<result<std::optional<entry>>> search_stream::next()
{
	if (finished_) {
		if (error_) co_return std::unexpected(*error_);
		co_return std::optional<entry>{};
	}
	if (conn_ == nullptr || !conn_->open || conn_->stream != this) {
		// Connection destroyed, closed (unbind, close, failure) meanwhile.
		error e = conn_ == nullptr ? not_connected(context_) : conn_->not_connected(context_);
		if (conn_ != nullptr && conn_->stream == this) conn_->stream = nullptr;
		finished_ = true;
		error_ = e;
		co_return std::unexpected(std::move(e));
	}
	if (conn_->in_io)
		co_return fail(client_errc::operation_in_progress,
		  std::string(context_) + ": another operation of this connection is suspended");

	busy_guard g(*conn_);
	auto r = co_await conn_->search_step(*this);
	g.clean = true;
	if (!r && !finished_) {
		// A connection failure (the server's own errors set finished_ already).
		if (conn_->stream == this) conn_->stream = nullptr;
		finished_ = true;
		error_ = r.error();
	}
	co_return r;
}

// ---------------------------------------------------------------- connect

capy::task<result<connection>>
  connect(boost::corosio::io_context &ioc, url u, connection_options options, std::pmr::memory_resource *mr)
{
	auto t = co_await net::connect(ioc,
	  std::move(u),
	  net::connect_options{
		.timeout = options.timeout, .tls = std::move(options.tls), .tcp_no_delay = options.tcp_no_delay },
	  mr);
	if (!t) co_return std::unexpected(std::move(t.error()));
	co_return connection(std::move(*t), options, mr);
}

}// namespace jhetz::ldap
