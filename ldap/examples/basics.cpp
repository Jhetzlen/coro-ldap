// Async basics: connect, bind, search with a typed filter, read the entries,
// unbind, and handle errors.
//
//   jhetz_ldap_example_basics [URL]
//
// Settings come from the environment (the first argument overrides the URL);
// the defaults suit a local OpenLDAP set up for dc=example,dc=org:
//
//   LDAP_URL       ldap://localhost
//   LDAP_BIND_DN   cn=admin,dc=example,dc=org
//   LDAP_PASSWORD  secret
//   LDAP_BASE      dc=example,dc=org
//
// Every operation is a coroutine (capy::task) returning ldap::result<T>,
// which is std::expected<T, ldap::error>: expected failures (a wrong
// password, a missing entry, a server that is down) are values to test, not
// exceptions. main() runs the coroutine on a Corosio io_context.
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

// std::println is not in libstdc++ 13 (the oldest supported GCC).
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

// What an ldap::error holds. message() puts it all on one line for logs;
// code that reacts to an error looks at the parts.
void print_error(std::string_view what, const ldap::error &e, std::FILE *out = stderr)
{
	println(out, "{}: {}", what, e.message());
	// The code keeps its category: "ldap.result" for the server's result
	// codes (ldap::errc), "ldap.client" for the client's own checks
	// (ldap::client_errc), "system" or a TLS category for the network.
	println(out, "  code:       {} {} ({})", e.code.category().name(), e.code.value(), e.code.message());
	if (!e.diagnostic.empty()) println(out, "  diagnostic: {}", e.diagnostic);// the server's own words
	if (e.matched_dn) println(out, "  matched DN: {}", *e.matched_dn);// deepest entry the server found
	if (!e.context.empty()) println(out, "  context:    {}", e.context);// what the client was doing
}

capy::task<int> run(corosio::io_context &ioc, std::string url_text)
{
	// Parsing never throws either: a bad URL or DN is an error value.
	auto u = ldap::url::parse(url_text);
	auto base = ldap::dn::parse(setting("LDAP_BASE", "dc=example,dc=org"));
	auto admin = ldap::dn::parse(setting("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"));
	if (!u || !base || !admin) {
		print_error("bad setting", !u ? u.error() : !base ? base.error() : admin.error());
		co_return 2;
	}

	ldap::connection_options options;
	options.timeout = std::chrono::seconds(5);// resolve + TCP (+ TLS for ldaps://)
	options.operation_timeout = std::chrono::seconds(10);// each operation, unless it sets its own
	auto c = co_await ldap::connect(ioc, std::move(*u), options);
	if (!c) {
		print_error("connect", c.error());
		// Conditions (ldap::cond) group codes by meaning across categories:
		// connection_refused (system), a TLS failure and errc::unavailable
		// (LDAP) can all be tested without knowing where they came from.
		if (c.error().code == ldap::cond::busy_or_unavailable || c.error().code == ldap::cond::connection_lost
			|| c.error().code == ldap::cond::timeout)
			println(stderr, "is an LDAP server listening at {}?", url_text);
		co_return 1;
	}
	println(stdout, "connected to {}", c->name());

	// A wrong password is an ordinary result. The connection stays usable
	// (as anonymous) and can bind again.
	if (auto b = co_await c->simple_bind(*admin, "not the password"); !b) {
		if (b.error().code == ldap::cond::auth_failed)
			println(stdout, "wrong password refused, as expected: {}", b.error().code.message());
		else
			print_error("bind with a wrong password", b.error());
	}
	if (auto b = co_await c->simple_bind(*admin, setting("LDAP_PASSWORD", "secret")); !b) {
		print_error("bind", b.error());
		co_return 1;
	}

	// Filters are built as trees by ldap::filters, never by pasting text:
	// values are kept unescaped and escaped only when printed, so user input
	// cannot change a filter's meaning. (filter::raw parses RFC 4515 text.)
	using ldap::filters::attr;
	ldap::filter f = attr("objectClass") == "inetOrgPerson" && attr("uid").starts_with("user00")
					 && !attr("mail").ends_with("@example.com");
	println(stdout, "filter: {}", f.to_string());
	println(stdout, "a value with special characters: {}", (attr("cn") == "a*b (c)").to_string());

	// search_params is an aggregate: name what you need, the rest defaults
	// (whole subtree, filter (objectClass=*), all user attributes, no limits).
	auto entries = co_await c->search({
	  .base = *base,
	  .scope = ldap::search_scope::whole_subtree,
	  .filter = std::move(f),
	  .attributes = { "cn", "mail" },
	});
	if (!entries) {
		print_error("search", entries.error());
		co_return 1;
	}
	println(stdout, "{} entries", entries->size());
	for (const ldap::entry &e : *entries) {
		println(stdout, "{}", e.dn);
		// find() looks an attribute up case-insensitively; nullptr if absent.
		if (const auto *mail = e.find("MAIL"))
			for (const auto &v : *mail) println(stdout, "  mail: {}", v);
		// Or walk every attribute, in the order the server sent them.
		for (const ldap::attribute_values &a : e.attributes)
			if (a.type.name() != "mail") println(stdout, "  {}: {} value(s)", a.type.name(), a.values.size());
	}

	// A search below an entry that does not exist fails with noSuchObject:
	// the condition is cond::not_found, and matched_dn tells how far the
	// server got. A server error fails this operation only.
	auto missing = co_await c->search({
	  .base = base->child(ldap::dn{ "ou=no-such-unit" }.rdns().front()),
	  .scope = ldap::search_scope::base_object,
	});
	if (!missing && missing.error().code == ldap::cond::not_found)
		print_error("search of a missing entry (expected)", missing.error(), stdout);
	else if (!missing)
		print_error("search of a missing entry", missing.error());

	// Unbind ends the session politely; destroying the connection without it
	// just closes the socket.
	if (auto r = co_await c->unbind(); !r) print_error("unbind", r.error());
	co_return 0;
}

}// namespace

int main(int argc, char **argv)
{
	std::string url = argc > 1 ? argv[1] : setting("LDAP_URL", "ldap://localhost");
	corosio::io_context ioc;
	int status = 1;
	// Starts the coroutine on the io_context; the handlers receive its
	// result, or an exception (only for programming errors and allocation
	// failures: LDAP errors are values).
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
	ioc.run();// returns once nothing is left to do
	return status;
}
