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
	// Aborts a SASL exchange with an anonymous simple bind (RFC 4511 section
	// 4.2.1); a saslBindInProgress answer closes the connection.
	auto abort_sasl(core_ref self, const std::string &context) -> capy::task<void>
	{
		// The anonymous bind's success installs no layer the exchange negotiated.
		self->disarm_security_layer();
		message request(std::pmr::polymorphic_allocator<>(self->mr()));
		request.op = bind_request(3, {}, simple_auth());
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

	// Arms the layer this step negotiated, if its BindRequest is the last.
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

namespace {

	auto simple_bind_exchange(core_ref self, const dn &name, const std::string &password, const std::string &context)
	  -> capy::task<result<void>>
	{
		if (!password.empty() && self->refuses_cleartext_password()) {
			co_return fail(client_errc::tls_required,
			  context + ": the password would be sent in clear (use ldaps://, start_tls() or "
						"connection_options::allow_cleartext_passwords)");
		}
		message request(std::pmr::polymorphic_allocator<>(self->mr()));
		request.op = bind_request(3, name.to_string(), simple_auth(password));
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

	auto simple_bind_impl(core_ref self, dn name, std::string password) -> capy::task<result<void>>
	{
		const detail::scope_exit wipe{ [&password] noexcept { detail::wipe_string(password); } };
		const std::string context = op_context("bind", name);
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		if (!name.empty() && password.empty()) {
			co_return fail(client_errc::unauthenticated_bind, context + ": empty password (RFC 4513 section 5.1.2)");
		}
		if (auto b = co_await connection::core::begin_bind(self, context); !b) {
			co_return std::unexpected(std::move(b.error()));
		}
		connection::core::bind_scope exchange{ self };
		co_return exchange.end(co_await simple_bind_exchange(self, name, password, context));
	}

	auto sasl_bind_exchange(core_ref self, sasl_mechanism &mechanism, const dn &name, const std::string &context)
	  -> capy::task<result<void>>
	{
		constexpr int max_steps = 32;
		sasl_bind_context bind_context;
		if (self->transport().type() == net::transport::kind::tcp) {
			bind_context.host = self->transport().host();
		}
		bind_context.can_offload =
		  !corosio::detail::get_scheduler(self->executor().context()).scheduler_locking_disabled();
		if (self->is_tls()) {
			bind_context.tls = true;
			bind_context.bindings = self->authentication_channel_bindings();
			bind_context.peer_certificate = self->transport().peer_certificate();
		}
		mechanism.prepare(bind_context);
		result<std::optional<std::string>> creds;
		if (auto work = mechanism.offload_start()) {
			creds = co_await detail::run_offloaded(
			  self->executor().get_inner_executor(), self->default_timeout(), std::move(work));
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
			// Below the limit only: these credentials are sent.
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
				// aborts the exchange.
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
			request.op = bind_request(3, name.to_string(), sasl_auth(mechanism.name(), c));
			auto m =
			  co_await request_response(self, std::move(request), op_index<bind_response>, context, std::nullopt);
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
					// The server considers the connection bound, the client does not: close it.
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
				creds = co_await detail::run_offloaded(
				  self->executor().get_inner_executor(), self->default_timeout(), std::move(work));
			} else {
				creds = mechanism.step(server_creds);
			}
		}
	}

	auto sasl_bind_impl(core_ref self, sasl_mechanism &mechanism, dn name) -> capy::task<result<void>>
	{
		std::string context = "sasl bind ";
		context += mechanism.name();
		if (!self) {
			co_return std::unexpected(no_connection(context));
		}
		if (auto b = co_await connection::core::begin_bind(self, context); !b) {
			co_return std::unexpected(std::move(b.error()));
		}
		connection::core::bind_scope exchange{ self };
		co_return exchange.end(co_await sasl_bind_exchange(self, mechanism, name, context));
	}

}// namespace

auto connection::simple_bind(dn name, std::string password) -> capy::task<result<void>>
{
	const core_ref self(core_);
	return detail::on_strand(self, simple_bind_impl(self, std::move(name), std::move(password)));
}

auto connection::sasl_bind(sasl_mechanism &mechanism, dn name) -> capy::task<result<void>>
{
	const core_ref self(core_);
	return detail::on_strand(self, sasl_bind_impl(self, mechanism, std::move(name)));
}

}// namespace jhetz::ldap
