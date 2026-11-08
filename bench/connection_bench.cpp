// Connection round-trip benchmark: CompareRequests over a Unix socket pair
// to an in-process server that answers each at once, on an io_context run
// by one thread. Measures the cost per operation of the connection's
// machinery (submit, writer, reader, routing, the executor hops):
//   1. sequential, awaited from a task of the io_context's executor;
//   2. sequential, awaited from a task of connection::executor();
//   3. `window` tasks of the io_context's executor at once, each running
//      its share of the operations one after another.
// Reports the best and median time per operation of several runs.
//
//   jhetz_ldap_connection_bench [operations=20000] [window=64] [runs=9]
//
// Built with -DJHETZ_LDAP_BUILD_BENCH=ON and JHETZ_LDAP_BUILD_NET (not part
// of ctest); use an optimized build without sanitizers.
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/net/transport.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/local_connect_pair.hpp>
#include <boost/corosio/local_stream_socket.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <print>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

using clock = std::chrono::steady_clock;

constexpr int compare_true = 6;

struct socket_ref
{
	corosio::local_stream_socket *s;
	template<capy::MutableBufferSequence MB> auto read_some(MB buffers) { return s->read_some(buffers); }
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers) { return s->write_some(buffers); }
};

// Answers every CompareRequest with compareTrue until the client hangs up.
auto serve(net::transport t) -> capy::task<void>
{
	net::read_buffer buf;
	const net::read_options as_server{ .decode = { .from = ldap::origin::client } };
	while (true) {
		auto r = co_await net::read_message(t, buf, as_server);
		if (!r || !std::holds_alternative<ldap::compare_request>(r->op)) {
			co_return;
		}
		auto bytes = ldap::encode(ldap::message{ r->id, ldap::compare_response{ ldap::ldap_result{ compare_true } } });
		if (!bytes || !co_await net::write_bytes(t, *bytes)) {
			co_return;
		}
	}
}

auto compare_params() -> ldap::compare_params
{
	return { .entry = ldap::dn{ "uid=a,ou=people,dc=example,dc=org" }, .attribute = "uid", .value = "a" };
}

auto compares(ldap::connection &c, std::size_t n) -> capy::task<bool>
{
	const auto params = compare_params();
	for (std::size_t i = 0; i < n; ++i) {
		auto r = co_await c.compare(params);
		if (!r || !*r) {
			co_return false;
		}
	}
	co_return true;
}

struct window_state
{
	std::size_t running = 0;
	bool ok = true;
	capy::async_event done{};
};

auto window_worker(ldap::connection &c, std::size_t n, window_state &w) -> capy::task<void>
{
	if (!co_await compares(c, n)) {
		w.ok = false;
	}
	if (--w.running == 0) {
		w.done.set();
	}
}

auto windowed(const corosio::io_context &ioc, ldap::connection &c, std::size_t n, std::size_t window)
  -> capy::task<bool>
{
	window_state w{ .running = window };
	for (std::size_t i = 0; i < window; ++i) {
		capy::run_async(ioc.get_executor())(window_worker(c, n / window, w));
	}
	(void)co_await w.done.wait();
	co_return w.ok;
}

struct timings
{
	std::vector<double> ns_per_op{};
	bool ok = true;

	void add(clock::duration d, std::size_t ops)
	{
		ns_per_op.push_back(static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(d).count())
							/ static_cast<double>(ops));
	}
	void print(std::string_view mode)
	{
		std::ranges::sort(ns_per_op);
		std::println("{:<44} best {:8.0f} ns/op   median {:8.0f} ns/op{}",
		  mode,
		  ns_per_op.front(),
		  ns_per_op[ns_per_op.size() / 2],
		  ok ? "" : "   (FAILED)");
	}
};

struct results
{
	timings outside;
	timings inside;
	timings window;
};

auto drive(const corosio::io_context &ioc,
  ldap::connection &c,
  corosio::local_stream_socket &server,
  std::size_t ops,
  std::size_t window,
  int runs,
  results &out) -> capy::task<void>
{
	for (int run = 0; run < runs; ++run) {
		auto start = clock::now();
		out.outside.ok = co_await compares(c, ops) && out.outside.ok;
		out.outside.add(clock::now() - start, ops);

		start = clock::now();
		out.inside.ok = co_await capy::run(c.executor())(compares(c, ops)) && out.inside.ok;
		out.inside.add(clock::now() - start, ops);

		start = clock::now();
		out.window.ok = co_await windowed(ioc, c, ops, window) && out.window.ok;
		out.window.add(clock::now() - start, (ops / window) * window);
	}
	c.close();
	server.close();
}

auto arg(int argc, char *const *argv, int i, std::size_t fallback) -> std::size_t
{
	if (i >= argc) {
		return fallback;
	}
	return std::strtoull(argv[i], nullptr, 10);// NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
}

}// namespace

// NOLINTNEXTLINE(bugprone-exception-escape): a benchmark, terminating on an exception is fine
auto main(int argc, char *const *argv) -> int
{
	constexpr std::size_t default_ops = 20000;
	constexpr std::size_t default_window = 64;
	constexpr std::size_t default_runs = 9;
	const std::size_t ops = arg(argc, argv, 1, default_ops);
	const std::size_t window = std::max<std::size_t>(arg(argc, argv, 2, default_window), 1);
	const int runs = static_cast<int>(std::max<std::size_t>(arg(argc, argv, 3, default_runs), 1));

	corosio::io_context ioc;
	corosio::local_stream_socket client(ioc);
	corosio::local_stream_socket server(ioc);
	if (corosio::connect_pair(client, server)) {
		std::println(stderr, "connect_pair failed");
		return EXIT_FAILURE;
	}
	ldap::connection c(ioc, net::transport::wrap(socket_ref{ &client }, "bench"));
	results out;
	capy::run_async(ioc.get_executor())(serve(net::transport::wrap(socket_ref{ &server }, "server")));
	capy::run_async(ioc.get_executor())(drive(ioc, c, server, ops, window, runs, out));
	ioc.run();

	std::println("{} CompareRequests per run, {} runs, one thread", ops, runs);
	out.outside.print("sequential, from the io_context's executor");
	out.inside.print("sequential, from connection::executor()");
	out.window.print(std::format("{} tasks at once", window));
	return out.outside.ok && out.inside.ok && out.window.ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
