#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "impl.hpp"
#include "sasl_offload.hpp"

#include <boost/corosio/detail/scheduler.hpp>

#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap {

using detail::begin_bind;
using detail::bind_exchange;
using detail::impl_ref;
using detail::no_connection;
using detail::op_context;
using detail::op_index;
using detail::request_response;

// ---------------------------------------------------------------- binds

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

}// namespace

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

}// namespace jhetz::ldap
