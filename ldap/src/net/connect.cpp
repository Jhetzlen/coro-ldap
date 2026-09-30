#include "jhetz/ldap/net/connect.hpp"

#include "deadline.hpp"
#include "tls.hpp"
#include "transport_impl.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/socket_option.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap::net {
namespace {

	using detail::bounded;
	using detail::clock;
	using detail::deadline_t;

	// Error contexts are std::string (ldap::error is a step 3 type).
	std::string str(std::string_view s) { return std::string(s); }

	std::string to_text(const corosio::endpoint &ep)
	{
		const auto addr = ep.address().to_string();
		return ep.is_v6() ? "[" + addr + "]:" + std::to_string(ep.port()) : addr + ":" + std::to_string(ep.port());
	}

	// "<target>: <stage>", plus the budget when the stage ran out of time.
	std::string stage_context(const std::string &target,
	  std::string_view stage,
	  std::error_code ec,
	  std::optional<std::chrono::milliseconds> timeout)
	{
		std::string out = target;
		out += ": ";
		out += stage;
		if (ec == capy::cond::timeout && timeout)
			out += ": gave up after the " + std::to_string(timeout->count()) + " ms connect timeout";
		return out;
	}

	// ---------------------------------------------------------------- resolve

	// Shared by connect() and the detached lookup, which may outlive it.
	struct resolve_state
	{
		std::mutex mutex{};
		bool done = false;
		std::error_code ec{};
		std::vector<corosio::endpoint> endpoints{};
		corosio::resolver *resolver = nullptr;// set while the lookup runs
		capy::async_waker waker{};// wake() may be called from any thread
	};

	// Owns the resolver, so connect() can return on timeout while
	// getaddrinfo is still running on Corosio's pool thread (it cannot be
	// interrupted). The late result is stored and dropped with the state.
	capy::task<void>
	  resolve_detached(corosio::io_context &ioc, std::string host, std::string port, std::shared_ptr<resolve_state> st)
	{
		corosio::resolver resolver(ioc);
		{
			std::lock_guard lock(st->mutex);
			st->resolver = &resolver;
		}
		auto [ec, endpoints] = co_await resolver.resolve(host, port, corosio::resolve_flags::numeric_service);
		{
			std::lock_guard lock(st->mutex);
			st->resolver = nullptr;
			st->done = true;
			st->ec = ec;
			st->endpoints = std::move(endpoints);
		}
		st->waker.wake();
	}

	// Resolves with a deadline that holds even while getaddrinfo blocks.
	capy::task<capy::io_result<std::vector<corosio::endpoint>>>
	  resolve_bounded(corosio::io_context &ioc, std::string host, std::string port, deadline_t deadline)
	{
		auto st = std::make_shared<resolve_state>();
		capy::run_async(ioc.get_executor())(resolve_detached(ioc, std::move(host), std::move(port), st));
		auto [wec] = co_await bounded(st->waker.wait(), deadline);
		std::lock_guard lock(st->mutex);
		if (st->done) co_return { st->ec, std::move(st->endpoints) };
		// Timed out or cancelled: stop waiting. Cancelling the resolver
		// completes the detached task at once; getaddrinfo itself finishes
		// later on its thread and its result is dropped by Corosio.
		if (st->resolver != nullptr) st->resolver->cancel();
		co_return { wec ? wec : make_error_code(capy::error::canceled), {} };
	}

	// ---------------------------------------------------------------- deadlines

	// No deadline for nullopt, or for a timeout so large that now + timeout
	// would overflow the clock.
	deadline_t make_deadline(std::optional<std::chrono::milliseconds> timeout, clock::time_point now)
	{
		if (!timeout) return std::nullopt;
		const auto room = std::chrono::duration_cast<std::chrono::milliseconds>(clock::time_point::max() - now);
		if (*timeout >= room) return std::nullopt;
		return now + *timeout;
	}

	// Budget for one TCP attempt: min(remaining, max(remaining / left, 1 s)).
	deadline_t attempt_deadline(deadline_t overall, std::size_t addresses_left)
	{
		if (!overall) return std::nullopt;
		const auto now = clock::now();
		if (*overall <= now) return overall;
		const auto remaining = *overall - now;
		const auto share = remaining / static_cast<long>(addresses_left);
		const clock::duration floor = std::chrono::seconds(1);
		return now + std::min(remaining, std::max(share, floor));
	}

	bool has_control_character(std::string_view host, url_scheme scheme)
	{
		for (std::size_t i = 0; i < host.size(); ++i) {
			const auto c = static_cast<unsigned char>(host[i]);
			const bool abstract_socket = scheme == url_scheme::ldapi && i == 0 && c == 0;
			if ((c < 0x20 || c == 0x7F) && !abstract_socket) return true;
		}
		return false;
	}

}// namespace

capy::task<result<transport>>
  connect(corosio::io_context &ioc, url u, connect_options options, std::pmr::memory_resource *mr)
{
	const auto start = clock::now();
	const std::string server = str(to_string(u.scheme())) + "://" + str(u.authority());
	const std::string target = "connect " + server;

	if (u.host().empty())
		co_return fail(client_errc::invalid_url, target + ": the URL names no host (or, for ldapi, no socket path)");
	for (const auto &e : u.extensions())
		if (e.critical)
			co_return fail(client_errc::invalid_url, target + ": unsupported critical extension " + str(e.type));
	// Decoded hosts may hold any byte. getaddrinfo, OpenSSL's host name check
	// and sockaddr_un stop at a NUL, so "evil%00.example.org" would silently
	// become "evil". Only a leading NUL is meaningful: a Linux abstract socket.
	if (has_control_character(u.host(), u.scheme()))
		co_return fail(client_errc::invalid_url, target + ": control character in the host");

	if (options.timeout && options.timeout->count() <= 0)
		co_return fail(make_error_code(capy::error::timeout),
		  target + ": the connect timeout (" + std::to_string(options.timeout->count()) + " ms) is not positive");
	const deadline_t deadline = make_deadline(options.timeout, start);

	// ---- ldapi://
	if (u.scheme() == url_scheme::ldapi) {
		if (u.host().size() > corosio::local_endpoint::max_path_length)
			co_return fail(std::make_error_code(std::errc::filename_too_long),
			  target + ": socket path longer than " + std::to_string(corosio::local_endpoint::max_path_length)
				+ " bytes");
		transport t = transport_access::make(transport::kind::local, server, mr);
		auto &im = transport_access::get(t);
		im.local.emplace(ioc);
		auto [ec] = co_await bounded(im.local->connect(corosio::local_endpoint(u.host())), deadline);
		if (ec) co_return fail(ec, stage_context(target, "connect " + str(u.host()), ec, options.timeout));
		im.stream = capy::any_stream(&*im.local);
		co_return t;
	}

	// ---- ldaps://: TLS settings first, so configuration errors (missing CA
	// file, unparsable certificate, cert without key) fail before any
	// network traffic.
	std::optional<detail::tls_setup> tls;
	if (u.scheme() == url_scheme::ldaps) {
		auto setup = detail::make_tls_setup(options.tls);
		if (!setup) {
			auto e = std::move(setup.error());
			e.context = target + ": " + e.context;
			co_return std::unexpected(std::move(e));
		}
		tls.emplace(std::move(*setup));
	}

	// ---- ldap:// and ldaps://: resolve
	auto [rec, endpoints] = co_await resolve_bounded(ioc, str(u.host()), std::to_string(u.port_or_default()), deadline);
	if (rec) co_return fail(rec, stage_context(target, "resolve " + str(u.host()), rec, options.timeout));
	if (endpoints.empty())
		co_return fail(std::make_error_code(std::errc::no_such_device_or_address),
		  target + ": resolve " + str(u.host()) + ": no address");

	// ---- TCP: each address in turn, until one accepts
	transport t = transport_access::make(transport::kind::tcp, server, mr);
	auto &im = transport_access::get(t);
	im.tcp.emplace(ioc);
	std::error_code last;
	std::string last_endpoint;
	bool connected = false;
	for (std::size_t i = 0; i < endpoints.size(); ++i) {
		if (im.tcp->is_open()) im.tcp->close();
		last_endpoint = to_text(endpoints[i]);
		auto [ec] = co_await bounded(im.tcp->connect(endpoints[i]), attempt_deadline(deadline, endpoints.size() - i));
		if (!ec) {
			connected = true;
			break;
		}
		last = ec;
		if (ec == capy::cond::canceled) break;// stopped by the caller
		if (deadline && clock::now() >= *deadline) {
			last = make_error_code(capy::error::timeout);// the whole budget, not just this attempt's share
			break;
		}
	}
	if (!connected) {
		std::string stage = "tcp connect " + last_endpoint;
		if (endpoints.size() > 1) stage += " (last of " + std::to_string(endpoints.size()) + " addresses)";
		co_return fail(last, stage_context(target, stage, last, options.timeout));
	}
	if (options.tcp_no_delay) {
		try {
			im.tcp->set_option(corosio::socket_option::no_delay(true));
		} catch (const std::system_error &e) {
			co_return fail(e.code(), target + ": set TCP_NODELAY");
		}
	}

	if (u.scheme() == url_scheme::ldap) {
		im.stream = capy::any_stream(&*im.tcp);
		co_return t;
	}

	// ---- ldaps://: TLS client handshake over the owned socket
	auto hs = co_await detail::tls_handshake(im, u.host(), options.tls, std::move(*tls), deadline);
	if (!hs) {
		auto e = std::move(hs.error());
		e.context = stage_context(target, e.context, e.code, options.timeout);
		co_return std::unexpected(std::move(e));
	}
	co_return t;
}

}// namespace jhetz::ldap::net
