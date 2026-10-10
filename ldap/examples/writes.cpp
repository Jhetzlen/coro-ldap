// Writing: add, modify, compare, rename and move, delete, and what their
// failures look like.
//
//   jhetz_ldap_example_writes [URL]
//
// Settings come from the environment (the first argument overrides the URL):
//
//   LDAP_URL       ldap://localhost
//   LDAP_BIND_DN   cn=admin,dc=example,dc=org   (needs write access)
//   LDAP_PASSWORD  secret
//   LDAP_BASE      dc=example,dc=org
//
// It works on uid=example-writes,<base> and ou=example-archive,<base>,
// removes them first if an earlier run left them, and deletes them at the end.
//
// Every write returns ldap::result<ldap::response>: success carries the
// response controls (usually none), anything else is an ldap::error whose
// code is the server's result code (ldap::errc) and which also matches an
// ldap::cond condition (already_exists, not_found, access_denied, ...).
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
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
	return v != nullptr && *v != '\0' ? v : fallback;
}

// Prints the outcome of one step; false if it failed.
template<class T> bool report(const char *step, const ldap::result<T> &r)
{
	if (r)
		println(stdout, "{}: ok", step);
	else
		println(stderr, "{}: {}", step, r.error().message());
	return r.has_value();
}

// The RDN of a DN literal (checked at compile time), e.g. to build
// <child>,<base> with dn::child.
ldap::rdn rdn_of(ldap::dn::literal text) { return ldap::dn(text).rdns().front(); }

capy::task<int> run(corosio::io_context &ioc, std::string url_text)
{
	auto u = ldap::url::parse(url_text);
	auto base = ldap::dn::parse(setting("LDAP_BASE", "dc=example,dc=org"));
	auto admin = ldap::dn::parse(setting("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"));
	if (!u || !base || !admin) {
		println(stderr, "bad URL, LDAP_BASE or LDAP_BIND_DN");
		co_return 2;
	}
	auto c = co_await ldap::connect(ioc, std::move(*u));
	if (!c) {
		println(stderr, "connect: {}", c.error().message());
		co_return 1;
	}
	if (auto b = co_await c->simple_bind(*admin, setting("LDAP_PASSWORD", "secret")); !b) {
		println(stderr, "bind: {}", b.error().message());
		co_return 1;
	}

	const ldap::dn entry = base->child(rdn_of("uid=example-writes"));
	const ldap::dn archive = base->child(rdn_of("ou=example-archive"));
	const ldap::dn renamed = archive.child(rdn_of("uid=example-renamed"));
	// Leftovers of an interrupted run; "no such object" is fine here.
	for (const ldap::dn *d : { &renamed, &entry, &archive })
		if (auto r = co_await c->del({ .entry = *d }); !r && r.error().code != ldap::cond::not_found)
			println(stderr, "cleanup: {}", r.error().message());

	// ---- add: every attribute with at least one value, objectClass included.
	auto added = co_await c->add({
	  .entry = entry,
	  .attributes = {
		{ "objectClass", { "inetOrgPerson" } },
		{ "uid", { "example-writes" } },
		{ "cn", { "Example Writer" } },
		{ "sn", { "Writer" } },
		{ "telephoneNumber", { "+1 555 0100" } },
	  },
	});
	if (!report("add", added)) co_return 1;

	// Adding it again fails with entryAlreadyExists.
	auto again = co_await c->add({ .entry = entry, .attributes = { { "objectClass", { "inetOrgPerson" } } } });
	if (!again && again.error().code == ldap::cond::already_exists)
		println(stdout, "add again: refused as expected ({})", again.error().code.message());

	// ---- modify: changes applied in order, all or nothing.
	auto modified = co_await c->modify({
	  .object = entry,
	  .changes = {
		ldap::mod::add("mail", { "writer@example.org", "old@example.org" }),
		ldap::mod::remove("mail", { "old@example.org" }),// just this value
		ldap::mod::replace("description", { "written by the example" }),// all values
		ldap::mod::remove("telephoneNumber"),// the whole attribute
	  },
	});
	if (!report("modify", modified)) co_return 1;

	// One failing change fails the whole request: the description below is
	// not changed, because the mail value already exists.
	auto atomic = co_await c->modify({
	  .object = entry,
	  .changes = {
		ldap::mod::replace("description", { "never stored" }),
		ldap::mod::add("mail", { "writer@example.org" }),
	  },
	});
	if (!atomic) println(stdout, "modify with a duplicate value: refused ({})", atomic.error().code.message());

	// ---- compare: result<bool>, compareTrue / compareFalse mapped to a bool.
	for (const char *value : { "written by the example", "never stored" }) {
		auto same = co_await c->compare({ .entry = entry, .attribute = "description", .value = value });
		if (same) println(stdout, "compare description = \"{}\": {}", value, *same);
	}

	// ---- modify_dn: rename (new RDN) and move (new superior) in one request.
	if (!report("add container",
		  co_await c->add({ .entry = archive,
			.attributes = { { "objectClass", { "organizationalUnit" } }, { "ou", { "example-archive" } } } })))
		co_return 1;
	auto moved = co_await c->modify_dn({
	  .entry = entry,
	  .new_rdn = renamed.rdns().front(),
	  .delete_old_rdn = true,// drop uid=example-writes from the entry's values
	  .new_superior = archive,
	});
	if (!report("rename and move", moved)) co_return 1;

	// ---- delete: only leaves. The container still has a child.
	auto non_leaf = co_await c->del({ .entry = archive });
	if (!non_leaf) println(stdout, "delete container: refused ({})", non_leaf.error().code.message());
	report("delete entry", co_await c->del({ .entry = renamed }));
	report("delete container", co_await c->del({ .entry = archive }));

	// The old name is gone: cond::not_found.
	auto gone = co_await c->del({ .entry = entry });
	if (!gone && gone.error().code == ldap::cond::not_found) println(stdout, "delete old name: not found, as expected");

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
