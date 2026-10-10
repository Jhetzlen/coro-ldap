// The blocking API: ldap::sync::client, shared by several threads, without
// coroutines.
//
//   jhetz_ldap_example_sync_threads [URL]
//
// Settings come from the environment (the first argument overrides the URL):
//
//   LDAP_URL       ldap://localhost
//   LDAP_BIND_DN   cn=admin,dc=example,dc=org
//   LDAP_PASSWORD  secret
//   LDAP_BASE      dc=example,dc=org
//
// A sync::client owns an io_context and one I/O thread. Each method runs the
// matching ldap::connection operation there and waits for it, with the same
// parameter, result and error types as the async API. Any number of threads
// may call it at once: their requests are multiplexed on one connection.
// (Calling it from code running on its own I/O thread would wait for
// itself; that fails with client_errc::would_deadlock instead.)
#include "jhetz/ldap/sync.hpp"

#include <cstdio>
#include <cstdlib>
#include <format>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;

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
	return v != nullptr && *v != '\0' ? v : fallback;
}

}// namespace

int main(int argc, char **argv)
{
	auto u = ldap::url::parse(argc > 1 ? argv[1] : setting("LDAP_URL", "ldap://localhost"));
	auto base = ldap::dn::parse(setting("LDAP_BASE", "dc=example,dc=org"));
	auto admin = ldap::dn::parse(setting("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"));
	if (!u || !base || !admin) {
		println(stderr, "bad URL, LDAP_BASE or LDAP_BIND_DN");
		return 2;
	}

	// connection_options as for ldap::connect (timeouts, TLS, StartTLS, ...).
	ldap::connection_options options;
	options.operation_timeout = std::chrono::seconds(10);
	ldap::sync::client client(options);

	if (auto r = client.connect(std::move(*u)); !r) {
		println(stderr, "connect: {}", r.error().message());
		return 1;
	}
	if (auto r = client.simple_bind(*admin, setting("LDAP_PASSWORD", "secret")); !r) {
		println(stderr, "bind: {}", r.error().message());
		return 1;
	}

	// Four workers, each looking up a few users. The calls block the calling
	// thread only; all of them share the one connection.
	std::mutex out;// keeps the lines of one lookup together
	std::vector<std::thread> workers;
	for (int t = 0; t < 4; ++t) {
		workers.emplace_back([&, t] {
			for (int i = 0; i < 3; ++i) {
				const std::string uid = std::format("user{:03}", t * 3 + i);
				auto found = client.search({
				  .base = *base,
				  .filter = ldap::filters::attr("uid") == uid,
				  .attributes = { "cn", "mail" },
				});
				std::lock_guard lock(out);
				if (!found) {
					println(stderr, "thread {}: {}: {}", t, uid, found.error().message());
					continue;
				}
				if (found->empty()) {
					println(stdout, "thread {}: {}: not found", t, uid);
					continue;
				}
				const ldap::entry &e = found->front();
				const auto *mail = e.find("mail");
				println(
				  stdout, "thread {}: {} -> {} ({})", t, uid, e.dn, mail && !mail->empty() ? (*mail)[0] : "no mail");
			}
		});
	}
	for (auto &w : workers) w.join();

	// Every other operation is there too, typed ones included
	// (client.search_as<T>, client.modify<T>, client.add(dn, value)).
	if (auto me = client.who_am_i())
		println(stdout, "bound as \"{}\"", *me);
	else
		println(stderr, "who_am_i: {}", me.error().message());

	// The destructor would close the connection too, without telling the
	// server; unbind() ends the session properly.
	if (auto r = client.unbind(); !r) println(stderr, "unbind: {}", r.error().message());
	return 0;
}
