#include "jhetz/ldap/connection.hpp"

#include "../format_util.hpp"
#include "../net/channel_binding.hpp"
#include "../net/transport_layers.hpp"
#include "core.hpp"
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

using detail::core_ref;
using detail::no_connection;
using detail::op_context;
using detail::op_index;
using detail::request_response;

// ---------------------------------------------------------------- binds

auto connection::core::authentication_channel_bindings() const noexcept -> ldap::channel_bindings
{
	return net::detail::authentication_channel_bindings(net::transport_access::get(transport_));
}

void connection::core::mark_tls_exporter_used() noexcept
{
	net::transport_access::get(transport_).tls_exporter_used = true;
}

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
	auto abort_sasl(core_ref self, const std::string &context) -> capy::task<void>
	{
		// The anonymous bind's success installs no layer the exchange negotiated.
		self->disarm_security_layer();
		message request(std::pmr::polymorphic_allocator<>(self->mr()));
		request.op = bind_request(3, {}, simple_auth(std::string_view(), self->mr()), self->mr());
		auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
		if (!m) {
			co_return;
		}
		const auto &r = std::get<bind_response>(m->op);// checked by the reader
		if (r.result.result_code != std::to_underlying(errc::sasl_bind_in_progress)) {
			co_return;
		}
		std::string text = context + ": connection closed: the SASL exchange could not be aborted: ";
		text += "saslBindInProgress in answer to a simple bind";
		self->shut(make_error(client_errc::unexpected_response, text), true);
	}

	// After a step: the layer the exchange negotiated, if this step's
	// BindRequest is its last, takes effect with that request's success.
	// One layer at a time.
	auto arm_security_layer(connection::core &c, sasl_mechanism &mechanism) -> result<void>
	{
		auto layer = mechanism.take_security_layer();
		if (layer == nullptr) {
			return {};
		}
		if (c.security_layer() != sasl_protection::none) {
			return fail(client_errc::security_layer_in_effect,
			  "the exchange negotiated a SASL security layer while one is in effect (only one is supported)");
		}
		c.arm_security_layer(std::move(layer));
		return {};
	}

}// namespace

auto connection::simple_bind(dn name, std::string password) -> capy::task<result<void>>
{
	const std::string context = op_context("bind", name);
	if (core_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	if (!name.empty() && password.empty()) {
		co_return fail(client_errc::unauthenticated_bind, context + ": empty password (RFC 4513 section 5.1.2)");
	}
	core_ref self(core_);// `this` may be moved from while suspended
	if (auto b = co_await core::begin_bind(self, context); !b) {
		co_return std::unexpected(std::move(b.error()));
	}
	const core::bind_scope exchange{ self };
	message request(std::pmr::polymorphic_allocator<>(self->mr()));
	request.op = bind_request(3, name.to_string(self->mr()), simple_auth(password, self->mr()), self->mr());
	auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
	if (!m) {
		co_return std::unexpected(std::move(m.error()));
	}
	const auto &r = std::get<bind_response>(m->op);// checked by the reader
	if (!r.result.is_success()) {
		co_return std::unexpected(r.result.to_error(context));
	}
	co_return result<void>{};
}

auto connection::sasl_bind(sasl_mechanism &mechanism, dn name) -> capy::task<result<void>>
{
	std::string context = "sasl bind ";
	context += mechanism.name();
	if (core_ == nullptr) {
		co_return std::unexpected(no_connection(context));
	}
	core_ref self(core_);
	if (auto b = co_await core::begin_bind(self, context); !b) {
		co_return std::unexpected(std::move(b.error()));
	}
	const core::bind_scope exchange{ self };
	constexpr int max_steps = 32;
	sasl_bind_context bind_context;
	if (self->transport().type() == net::transport::kind::tcp) {
		bind_context.host = self->transport().host();
	}
	bind_context.can_offload = !corosio::detail::get_scheduler(self->executor().context()).scheduler_locking_disabled();
	if (self->is_tls()) {
		bind_context.tls = true;
		bind_context.bindings = self->authentication_channel_bindings();
		bind_context.peer_certificate = self->transport().peer_certificate();
	}
	mechanism.prepare(bind_context);
	result<std::optional<std::string>> creds;
	if (auto work = mechanism.offload_start()) {
		creds = co_await detail::run_offloaded(self->executor(), self->default_timeout(), std::move(work));
	} else {
		creds = mechanism.start();
	}
	// RFC 9266 section 4.1: tls-exporter serves one authentication on the
	// connection, this one, whatever its outcome; later binds go without.
	if (creds && mechanism.channel_binding_used() == channel_binding_type::tls_exporter
		&& !bind_context.bindings.tls_exporter.empty()) {
		self->mark_tls_exporter_used();
	}
	for (int step = 0;; ++step) {
		// Not at the limit: these credentials are never sent, and abort_sasl's
		// anonymous bind must not install their layer.
		if (creds && step < max_steps) {
			if (auto armed = arm_security_layer(*self, mechanism); !armed) {
				creds = std::unexpected(std::move(armed.error()));
			}
		}
		if (!creds || step == max_steps) {
			auto e = creds ? make_error(client_errc::unexpected_response,
							   detail::format("{}: still in progress after {} steps", context, max_steps))
						   : detail::with_context(std::move(creds.error()), context);
			// Past the first step the server answered saslBindInProgress:
			// abort the exchange before the held requests are sent.
			if (step > 0) {
				co_await abort_sasl(self, context);
			}
			co_return std::unexpected(std::move(e));
		}
		message request(std::pmr::polymorphic_allocator<>(self->mr()));
		std::optional<std::string_view> c;
		if (*creds) {
			c = **creds;
		}
		request.op =
		  bind_request(3, name.to_string(self->mr()), sasl_auth(mechanism.name(), c, self->mr()), self->mr());
		auto m = co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
		if (!m) {
			co_return std::unexpected(std::move(m.error()));
		}
		const auto &r = std::get<bind_response>(m->op);
		std::optional<std::string_view> server_creds;
		if (r.server_sasl_creds) {
			server_creds = *r.server_sasl_creds;
		}
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
		if (r.result.result_code != std::to_underlying(errc::sasl_bind_in_progress)) {
			co_return std::unexpected(r.result.to_error(context));
		}
		if (auto work = mechanism.offload_step(server_creds)) {
			creds = co_await detail::run_offloaded(self->executor(), self->default_timeout(), std::move(work));
		} else {
			creds = mechanism.step(server_creds);
		}
	}
}

}// namespace jhetz::ldap
