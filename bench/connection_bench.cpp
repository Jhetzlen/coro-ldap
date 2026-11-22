// Connection round-trip benchmark: CompareRequests to an in-process server
// over a Unix socket pair, sequential and windowed.
//   jhetz_ldap_connection_bench [operations=20000] [window=64] [runs=9]
#include "socket_pair.hpp"

#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run.hpp>

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

// Answers every CompareRequest with compareTrue until the client hangs up.
auto serve(net::transport t) -> capy::task<void>
{
	ldap::result<std::pmr::vector<std::byte>> bytes;
	co_await ldap::bench::serve_each<ldap::compare_request>(
	  std::move(t), [&bytes](const ldap::message &r) -> const std::pmr::vector<std::byte> * {
		  bytes = ldap::encode(ldap::message{ r.id, ldap::compare_response{ ldap::ldap_result{ compare_true } } });
		  return bytes ? &*bytes : nullptr;
	  });
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
		if (!r || !r->value) {
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

}// namespace

// NOLINTNEXTLINE(bugprone-exception-escape): a benchmark, terminating on an exception is fine
auto main(int argc, char *const *argv) -> int
{
	constexpr std::size_t default_ops = 20000;
	constexpr std::size_t default_window = 64;
	constexpr std::size_t default_runs = 9;
	const std::size_t ops = ldap::bench::arg(argc, argv, 1, default_ops);
	const std::size_t window = std::max<std::size_t>(ldap::bench::arg(argc, argv, 2, default_window), 1);
	const int runs = static_cast<int>(std::max<std::size_t>(ldap::bench::arg(argc, argv, 3, default_runs), 1));

	results out;
	if (!ldap::bench::run_pair(serve, [&](const corosio::io_context &ioc, ldap::connection &c, auto &server) {
			return drive(ioc, c, server, ops, window, runs, out);
		})) {
		return EXIT_FAILURE;
	}

	std::println("{} CompareRequests per run, {} runs, one thread", ops, runs);
	out.outside.print("sequential, from the io_context's executor");
	out.inside.print("sequential, from connection::executor()");
	out.window.print(std::format("{} tasks at once", window));
	return out.outside.ok && out.inside.ok && out.window.ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
