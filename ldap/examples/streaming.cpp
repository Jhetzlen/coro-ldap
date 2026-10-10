// Large results: streaming, paging, size and time limits, timeouts and
// cancellation.
//
//   jhetz_ldap_example_streaming [URL]
//
// Settings come from the environment (the first argument overrides the URL):
//
//   LDAP_URL       ldap://localhost
//   LDAP_BIND_DN   cn=admin,dc=example,dc=org   (empty: stay anonymous)
//   LDAP_PASSWORD  secret
//   LDAP_BASE      dc=example,dc=org
//
// connection::search() collects every entry before returning. For results
// that do not fit comfortably in memory, search_stream() hands them out one
// at a time as they arrive, and search_paged() also asks the server for
// them in pages (RFC 2696), which servers often require past a size limit.
// Every operation can be bounded by a client-side timeout, or cancelled
// through the stop token of the task awaiting it; in both cases the
// operation is abandoned on the server and the connection stays usable.
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <optional>
#include <stop_token>
#include <string>
#include <utility>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

template<class... Args> void println(std::FILE *f, std::format_string<Args...> fmt, Args &&...args)
{
	std::string line = std::format(fmt, std::forward<Args>(args)...);
	line += '\n';
	std::fwrite(line.data(), 1, line.size(), f);
}

std::string setting(const char *name, const char *fallback)
{
	const char *v = std::getenv(name);
	return v != nullptr ? v : fallback;
}

// Reads a search_stream or a paged_search (same interface) to its end and
// prints the first few DNs. next() gives an entry, nullopt at the end, or
// an error. Only one next() may be outstanding per stream.
template<class Stream> capy::task<void> drain(const char *label, Stream &s)
{
	std::size_t count = 0;
	while (true) {
		ldap::result<std::optional<ldap::entry>> e = co_await s.next();
		if (!e) {
			println(stdout, "{}: stopped after {} entries: {}", label, count, e.error().message());
			co_return;
		}
		if (!*e) break;// SearchResultDone: the search succeeded
		if (count < 2) println(stdout, "{}: {}", label, (*e)->dn);
		++count;
	}
	// Continuation references (other servers holding part of the subtree)
	// are collected, not chased.
	for (const auto &ref : s.references()) println(stdout, "{}: reference {}", label, ref);
	println(stdout, "{}: {} entries", label, count);
}

capy::task<int> run(corosio::io_context &ioc, std::string url_text)
{
	auto u = ldap::url::parse(url_text);
	auto base = ldap::dn::parse(setting("LDAP_BASE", "dc=example,dc=org"));
	if (!u || !base) {
		println(stderr, "bad URL or LDAP_BASE");
		co_return 2;
	}
	auto c = co_await ldap::connect(ioc, std::move(*u));
	if (!c) {
		println(stderr, "connect: {}", c.error().message());
		co_return 1;
	}
	if (const std::string who = setting("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"); !who.empty()) {
		auto name = ldap::dn::parse(who);
		if (!name) {
			println(stderr, "LDAP_BIND_DN: {}", name.error().message());
			co_return 2;
		}
		if (auto b = co_await c->simple_bind(std::move(*name), setting("LDAP_PASSWORD", "secret")); !b) {
			println(stderr, "bind: {}", b.error().message());
			co_return 1;
		}
	}

	// ---- streaming: entries one at a time, memory bounded by what you keep.
	// (Pass a std::pmr::memory_resource* as the second argument to decode
	// the entries into an arena of your own.)
	{
		auto s = co_await c->search_stream({ .base = *base, .attributes = { "1.1" } });// "1.1": DNs only
		if (!s) {
			println(stderr, "search_stream: {}", s.error().message());
			co_return 1;
		}
		co_await drain("stream", *s);
	}// a stream destroyed before its end abandons its search

	// ---- paging: the same, but the server sends at most 100 entries per
	// request; the next page is requested when the current one is used up.
	{
		auto s = co_await c->search_paged({ .base = *base, .attributes = { "1.1" } }, 100);
		if (!s) {
			println(stderr, "search_paged: {}", s.error().message());
			co_return 1;
		}
		co_await drain("paged", *s);
		println(stdout, "paged: {} pages", s->pages());
	}

	// ---- server-side limits, sent with the request: at most 5 entries and
	// 10 seconds. Past the size limit the server ends the search with
	// sizeLimitExceeded: search() then fails as a whole, while a stream has
	// already delivered the first 5 entries.
	{
		ldap::search_params limited{ .base = *base, .attributes = { "1.1" }, .size_limit = 5 };
		limited.time_limit = std::chrono::seconds(10);
		auto all = co_await c->search(limited);
		if (!all && all.error().code == ldap::errc::size_limit_exceeded)
			println(stdout, "search with size_limit 5: {}", all.error().code.message());
		auto s = co_await c->search_stream(std::move(limited));
		if (s) co_await drain("limited stream", *s);
	}

	// ---- client-side timeout: .timeout bounds the whole operation (also
	// set for every operation by connection_options::operation_timeout).
	// On expiry the search fails with cond::timeout and is abandoned.
	auto quick = co_await c->search({ .base = *base, .timeout = std::chrono::milliseconds(1) });
	if (quick)
		println(stdout, "1 ms timeout: the server was faster ({} entries)", quick->size());
	else if (quick.error().code == ldap::cond::timeout)
		println(stdout, "1 ms timeout: timed out, as it may");
	else
		println(stderr, "1 ms timeout: {}", quick.error().message());

	// ---- cancellation: every operation honours the stop token of the task
	// awaiting it. capy::run(token)(task) awaits a task with a given token;
	// here a second task requests the stop as soon as the search waits for
	// its answer. In a real program the request comes from elsewhere: a
	// "Cancel" button, a signal handler, a parent task giving up.
	std::stop_source stop;
	capy::run_async(ioc.get_executor())([](std::stop_source &s) -> capy::task<void> {
		s.request_stop();
		co_return;
	}(stop));
	auto cancelled = co_await capy::run(stop.get_token())(c->search({ .base = *base }));
	if (!cancelled && cancelled.error().code == ldap::cond::canceled)
		println(stdout, "cancelled search: {}", cancelled.error().message());
	else
		println(stderr, "cancelled search: unexpected outcome");

	// The connection is still fine after a timeout or a cancellation.
	auto me = co_await c->who_am_i();
	println(stdout, "still connected, as \"{}\"", me ? *me : std::string(me.error().message()));

	if (auto r = co_await c->unbind(); !r) println(stderr, "unbind: {}", r.error().message());
	co_return 0;
}

}// namespace

int main(int argc, char **argv)
{
	std::string url = argc > 1 ? argv[1] : setting("LDAP_URL", "ldap://localhost");
	corosio::io_context ioc;
	int status = 1;
	capy::run_async(
	  ioc.get_executor(),
	  [&status](int s) { status = s; },
	  [](std::exception_ptr e) {
		  try {
			  std::rethrow_exception(e);
		  } catch (const std::exception &x) {
			  println(stderr, "exception: {}", x.what());
		  }
	  })(run(ioc, std::move(url)));
	ioc.run();
	return status;
}
