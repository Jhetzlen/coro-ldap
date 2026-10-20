#include "jhetz/ldap/net/connect.hpp"

#include "../format_util.hpp"
#include "deadline.hpp"
#include "happy_eyeballs.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "tls.hpp"
#include "transport_impl.hpp"

#include <boost/capy/cond.hpp>
#include <boost/capy/error.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/async_waker.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/when_any.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/local_endpoint.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace jhetz::ldap::net {

auto detail::interleave_families(std::vector<corosio::endpoint> in) -> std::vector<corosio::endpoint>
{
	if (in.empty()) {
		return in;
	}
	const bool first_v6 = in.front().is_v6();
	std::vector<corosio::endpoint> preferred;
	std::vector<corosio::endpoint> other;
	std::vector<corosio::endpoint> out;
	for (auto &ep : in) {
		(ep.is_v6() == first_v6 ? preferred : other).push_back(ep);
	}
	out.reserve(in.size());
	for (std::size_t i = 0; i < std::max(preferred.size(), other.size()); ++i) {
		if (i < preferred.size()) {
			out.push_back(preferred[i]);
		}
		if (i < other.size()) {
			out.push_back(other[i]);
		}
	}
	return out;
}

namespace {

	using detail::bounded;
	using detail::clock;
	using detail::deadline_t;

	// Contexts are built as std::string (cold path) and copied into the
	// error, which lives on the default resource.
	auto str(std::string_view s) -> std::string { return std::string(s); }

	auto to_text(const corosio::endpoint &ep) -> std::string
	{
		const auto addr = ep.address().to_string();
		return ep.is_v6() ? ldap::detail::format("[{}]:{}", addr, ep.port())
						  : ldap::detail::format("{}:{}", addr, ep.port());
	}

	// "<target>: <stage>", plus the budget when the stage ran out of time.
	auto stage_context(const std::string &target,
	  std::string_view stage,
	  std::error_code ec,
	  std::optional<std::chrono::milliseconds> timeout) -> std::string
	{
		std::string out = target;
		out += ": ";
		out += stage;
		if (ec == capy::cond::timeout && timeout) {
			ldap::detail::format_to(out, ": gave up after the {} ms connect timeout", timeout->count());
		}
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
	auto
	  resolve_detached(corosio::io_context &ioc, std::string host, std::string port, std::shared_ptr<resolve_state> st)
		-> capy::task<void>
	{
		std::error_code ec{};
		std::vector<corosio::endpoint> endpoints{};
		try {
			corosio::resolver resolver(ioc);
			{
				std::scoped_lock lock(st->mutex);
				st->resolver = &resolver;
			}
			auto [rec, found] = co_await resolver.resolve(host, port, corosio::resolve_flags::numeric_service);
			{
				std::scoped_lock lock(st->mutex);
				st->resolver = nullptr;
			}
			ec = rec;
			endpoints = std::move(found);
		} catch (...) {
			// Never leave connect() waiting (it may have no deadline).
			{
				std::scoped_lock lock(st->mutex);
				st->resolver = nullptr;
			}
			ec = std::make_error_code(std::errc::not_enough_memory);
			endpoints.clear();
		}
		{
			std::scoped_lock lock(st->mutex);
			st->done = true;
			st->ec = ec;
			st->endpoints = std::move(endpoints);
		}
		st->waker.wake();
	}

	// Resolves with a deadline that holds even while getaddrinfo blocks.
	auto resolve_bounded(corosio::io_context &ioc, std::string host, std::string port, deadline_t deadline)
	  -> capy::task<capy::io_result<std::vector<corosio::endpoint>>>
	{
		auto st = std::make_shared<resolve_state>();
		capy::run_async(ioc.get_executor())(resolve_detached(ioc, std::move(host), std::move(port), st));
		auto [wec] = co_await bounded(st->waker.wait(), deadline);
		std::scoped_lock lock(st->mutex);
		if (st->done) {
			co_return { st->ec, std::move(st->endpoints) };
		}
		// Timed out or cancelled: stop waiting and return now. Cancelling the
		// resolver only marks the lookup; Corosio completes it (and so the
		// detached task) when getaddrinfo returns on its thread, and the late
		// result is dropped with the shared state.
		if (st->resolver != nullptr) {
			st->resolver->cancel();
		}
		co_return { wec ? wec : make_error_code(capy::error::canceled), {} };
	}

	// ---------------------------------------------------------------- deadlines

	// No deadline for nullopt, or for a timeout so large that now + timeout
	// would overflow the clock.
	auto make_deadline(std::optional<std::chrono::milliseconds> timeout, clock::time_point now) -> deadline_t
	{
		if (!timeout) {
			return std::nullopt;
		}
		const auto room = std::chrono::duration_cast<std::chrono::milliseconds>(clock::time_point::max() - now);
		if (*timeout >= room) {
			return std::nullopt;
		}
		return now + *timeout;
	}

	// ---------------------------------------------------------------- Happy Eyeballs

	// Shared by the attempts of one connect(), which outlives them (when_any
	// waits for every child). Attempt i starts once attempt i-1 has failed
	// or has been running for attempt_delay, whichever comes first.
	struct race_state
	{
		race_state(corosio::io_context &ioc, std::vector<corosio::endpoint> eps, deadline_t d, clock::duration delay)
		  : endpoints(std::move(eps)), started(std::make_unique<capy::async_event[]>(endpoints.size())),
			failed(std::make_unique<capy::async_event[]>(endpoints.size())), start_times(endpoints.size()), deadline(d),
			attempt_delay(delay)
		{
			sockets.reserve(endpoints.size());
			for (std::size_t i = 0; i < endpoints.size(); ++i) {
				sockets.emplace_back(ioc);
			}
		}

		std::vector<corosio::endpoint> endpoints;
		std::vector<corosio::tcp_socket> sockets;
		std::unique_ptr<capy::async_event[]> started;
		std::unique_ptr<capy::async_event[]> failed;
		std::vector<clock::time_point> start_times;
		deadline_t deadline;
		clock::duration attempt_delay;
		// The attempt that failed last, for the error message.
		std::error_code last{};
		std::size_t last_index = 0;
		std::size_t attempted = 0;
		bool canceled = false;// a wait or connect was stopped by the caller
	};

	auto wait_for(capy::async_event &e) -> capy::task<capy::io_result<>> { co_return co_await e.wait(); }

	// One connection attempt of the race; succeeds only if it connected.
	auto attempt(race_state &st, std::size_t i) -> capy::task<capy::io_result<>>
	{
		const auto give_up = [&st, i](std::error_code ec) -> capy::io_result<> {
			if (ec == capy::cond::canceled) {
				st.canceled = true;
			}
			st.failed[i].set();
			st.started[i].set();// never leave the next attempt waiting
			return { ec };
		};
		if (i > 0) {
			// Attempt i-1 sets `started` before it suspends, so this wait
			// is short; then race its failure against the attempt delay.
			if (auto [ec] = co_await wait_for(st.started[i - 1]); ec) {
				co_return give_up(ec);
			}
			deadline_t until = st.start_times[i - 1] + st.attempt_delay;
			if (st.deadline && *st.deadline < *until) {
				until = st.deadline;
			}
			auto [ec] = co_await bounded(wait_for(st.failed[i - 1]), until);
			if (ec && ec != capy::cond::timeout) {
				co_return give_up(ec);
			}
			if (st.deadline && clock::now() >= *st.deadline) {
				co_return give_up(make_error_code(capy::error::timeout));
			}
		}
		st.start_times[i] = clock::now();
		st.started[i].set();
		++st.attempted;
		auto [ec] = co_await bounded(st.sockets[i].connect(st.endpoints[i]), st.deadline);
		if (ec) {
			if (ec != capy::cond::canceled) {
				st.last = ec;
				st.last_index = i;
			}
			co_return give_up(ec);
		}
		co_return {};
	}

	// "<what> <text>", with `text` (a decoded host or socket path, or the
	// encoded URL) sanitized and cut as op_context quotes a DN: the URL is
	// often a server's (a referral), and its decoded host may hold C1 or
	// bidi controls, U+2028 or ill-formed UTF-8 (has_control_character only
	// rejects C0 and DEL). Valid non-ASCII (an IDN's U-labels) is kept.
	auto quoted(std::string_view what, std::string_view text) -> std::string
	{
		std::string out(what);
		out += ' ';
		ldap::detail::append_sanitized(out, text, 256);
		return out;
	}

	auto has_control_character(std::string_view host, url_scheme scheme) -> bool
	{
		for (std::size_t i = 0; i < host.size(); ++i) {
			const auto c = static_cast<unsigned char>(host[i]);
			const bool abstract_socket = scheme == url_scheme::ldapi && i == 0 && c == 0;
			if ((c < 0x20 || c == 0x7F) && !abstract_socket) {
				return true;
			}
		}
		return false;
	}

}// namespace

auto connect(corosio::io_context &ioc, url u, connect_options options, std::pmr::memory_resource *mr)
  -> capy::task<result<transport>>
{
	const auto start = clock::now();
	const std::string server = str(to_string(u.scheme())) + "://" + str(u.authority());
	const std::string target = quoted("connect", server);

	if (u.host().empty()) {
		co_return fail(client_errc::invalid_url, target + ": the URL names no host (or, for ldapi, no socket path)");
	}
	for (const auto &e : u.extensions()) {
		if (e.critical) {
			co_return fail(client_errc::invalid_url, target + ": unsupported critical extension " + str(e.type));
		}
	}
	// Decoded hosts may hold any byte. getaddrinfo, OpenSSL's host name check
	// and sockaddr_un stop at a NUL, so "evil%00.example.org" would silently
	// become "evil". Only a leading NUL is meaningful: a Linux abstract socket.
	if (has_control_character(u.host(), u.scheme())) {
		co_return fail(client_errc::invalid_url, target + ": control character in the host");
	}

	if (options.timeout && options.timeout->count() <= 0) {
		co_return fail(make_error_code(capy::error::timeout),
		  ldap::detail::format("{}: the connect timeout ({} ms) is not positive", target, options.timeout->count()));
	}
	const deadline_t deadline = make_deadline(options.timeout, start);

	// ---- ldapi://
	if (u.scheme() == url_scheme::ldapi) {
		if (u.host().size() > corosio::local_endpoint::max_path_length) {
			co_return fail(std::make_error_code(std::errc::filename_too_long),
			  ldap::detail::format(
				"{}: socket path longer than {} bytes", target, corosio::local_endpoint::max_path_length));
		}
		transport t = transport_access::make(transport::kind::local, server, mr);
		auto &im = transport_access::get(t);
		im.host = u.host();
		im.local.emplace(ioc);
		auto [ec] = co_await bounded(im.local->connect(corosio::local_endpoint(u.host())), deadline);
		if (ec) {
			co_return fail(ec, stage_context(target, quoted("connect", u.host()), ec, options.timeout));
		}
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
			e.context.insert(0, target + ": ");
			co_return std::unexpected(std::move(e));
		}
		tls.emplace(std::move(*setup));
	}

	// ---- ldap:// and ldaps://: resolve
	auto [rec, endpoints] = co_await resolve_bounded(ioc, str(u.host()), std::to_string(u.port_or_default()), deadline);
	if (rec) {
		co_return fail(rec, stage_context(target, quoted("resolve", u.host()), rec, options.timeout));
	}
	if (endpoints.empty()) {
		co_return fail(
		  std::make_error_code(std::errc::no_such_device_or_address), target + ": " + quoted("resolve", u.host()));
	}

	// ---- TCP: Happy Eyeballs (RFC 8305), staggered attempts over every
	// address, the first to connect wins and the others are cancelled
	race_state race(ioc,
	  detail::interleave_families(std::move(endpoints)),
	  deadline,
	  std::max<clock::duration>(options.attempt_delay, clock::duration::zero()));
	std::vector<capy::task<capy::io_result<>>> attempts;
	attempts.reserve(race.endpoints.size());
	for (std::size_t i = 0; i < race.endpoints.size(); ++i) {
		attempts.push_back(attempt(race, i));
	}
	auto winner = co_await capy::when_any(std::move(attempts));
	if (winner.index() == 0) {
		std::error_code ec = race.last;
		const bool timed_out = deadline && clock::now() >= *deadline;
		if (timed_out) {
			ec = make_error_code(capy::error::timeout);// the whole budget
		} else if (race.canceled || !ec) {
			ec = make_error_code(capy::error::canceled);// stopped by the caller
		}
		std::string stage = "tcp connect " + to_text(race.endpoints[race.last_index]);
		if (race.endpoints.size() > 1) {
			ldap::detail::format_to(stage, " ({} of {} addresses tried)", race.attempted, race.endpoints.size());
		}
		co_return fail(ec, stage_context(target, stage, ec, options.timeout));
	}

	transport t = transport_access::make(transport::kind::tcp, server, mr);
	auto &im = transport_access::get(t);
	im.host = u.host();
	im.tcp.emplace(std::move(race.sockets[std::get<1>(winner)]));
	if (options.tcp_no_delay) {
		try {
			im.tcp->set_option(corosio::socket_option::no_delay(true));
		} catch (const std::system_error &e) {
			co_return fail(e.code(), target + ": set TCP_NODELAY");
		}
	}

	if (!tls) {// ldap://: TLS settings are made for ldaps:// only
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

auto start_tls(transport &t,
  const read_buffer &pending,
  tls_options options,
  std::optional<std::chrono::milliseconds> timeout) -> capy::task<result<void>>
{
	std::string context = "start tls ";
	context += t.name();
	if (t.type() != transport::kind::tcp || t.is_tls() || !t.is_open()) {
		co_return fail(
		  std::make_error_code(std::errc::invalid_argument), context + ": needs an open plain TCP transport");
	}
	if (!pending.empty()) {
		co_return fail(client_errc::decode_error,
		  ldap::detail::format("{}: {} bytes arrived before the TLS handshake (refused: they were not protected)",
			context,
			pending.size()));
	}
	auto prefixed = [&context](error e) {
		e.context.insert(0, context + (e.context.empty() ? "" : ": "));
		return std::unexpected(std::move(e));
	};
	auto setup = detail::make_tls_setup(options);
	if (!setup) {
		co_return prefixed(std::move(setup.error()));
	}
	auto &im = transport_access::get(t);
	deadline_t deadline;
	if (timeout) {
		deadline = detail::clock::now() + *timeout;
	}
	try {
		auto hs = co_await detail::tls_handshake(im, im.host, options, std::move(*setup), deadline);
		if (!hs) {
			co_return prefixed(std::move(hs.error()));
		}
	} catch (...) {
		// bad_alloc in the handshake's setup or the handshake: the peer
		// expects a handshake now (or is in the middle of one), so the
		// session cannot go on in clear; closed, as for a failed handshake.
		t.close();
		throw;
	}
	co_return result<void>{};
}

}// namespace jhetz::ldap::net
