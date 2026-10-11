// Typed mapping: a C++ struct described once with ldap::schema<T>, then
// added, searched and modified with typed values instead of strings.
//
//   jhetz_ldap_example_mapping [URL]
//
// Settings come from the environment (the first argument overrides the URL):
//
//   LDAP_URL       ldap://localhost
//   LDAP_BIND_DN   cn=admin,dc=example,dc=org   (needs write access)
//   LDAP_PASSWORD  secret
//   LDAP_BASE      dc=example,dc=org
//
// It creates uid=example-mapping,<base> (an inetOrgPerson), changes it and
// deletes it again; an entry left by an interrupted run is removed first.
//
// With connection_options::schema_check = schema_check::on_first_use, the
// first typed operation on `person` reads the server's schema and checks the
// struct against it (unknown attributes, a member type that cannot hold the
// attribute's syntax, a writable member on a server-maintained attribute):
// a mismatch fails that operation with client_errc::schema_mismatch and a
// report, instead of surprising errors later.
#include "jhetz/ldap/mapping.hpp"
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

// The member type decides cardinality: T is required and single-valued,
// std::optional<T> optional, std::vector<T> any number of values. Values
// convert through ldap::value_traits<T> (strings, integers, bool, ldap::dn,
// binary, std::chrono::sys_seconds as GeneralizedTime, enums with names).
struct person
{
	std::string uid;
	std::string cn;
	std::string sn;
	std::optional<std::string> mail;
	std::vector<std::string> phones;
	std::optional<ldap::dn> manager;
	std::chrono::sys_seconds created{};
};

}// namespace

// The descriptor: which attribute each member maps to, and the object class
// (used for objectClass when adding, and to narrow searches). Names are
// checked at compile time; read_only members are read but never written.
template<>
constexpr auto ldap::schema<person> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::cn>("cn"),
  ldap::field<&person::sn>("sn"),
  ldap::field<&person::mail>("mail"),
  ldap::field<&person::phones>("telephoneNumber"),
  ldap::field<&person::manager>("manager"),
  ldap::field<&person::created>("createTimestamp", ldap::read_only));

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

void print_person(const person &p)
{
	println(stdout, "  {}: cn {}, sn {}, created {}", p.uid, p.cn, p.sn, p.created);
	println(stdout, "    mail:    {}", p.mail.value_or("-"));
	for (const auto &phone : p.phones) println(stdout, "    phone:   {}", phone);
	if (p.manager) println(stdout, "    manager: {}", p.manager->to_string());
}

// search_as<person> requests exactly the descriptor's attributes and adds
// (objectClass=inetOrgPerson) to the filter. The typed filter builder takes
// values of the member's type.
capy::task<bool> show(ldap::connection &c, const ldap::dn &base)
{
	auto people = co_await c.search_as<person>({
	  .base = base,
	  .filter = ldap::filters::field<&person::uid>() == "example-mapping",
	});
	if (!people) {
		println(stderr, "search_as: {}", people.error().message());
		co_return false;
	}
	for (const person &p : *people) print_person(p);
	co_return true;
}

capy::task<int> run(corosio::io_context &ioc, std::string url_text)
{
	auto u = ldap::url::parse(url_text);
	auto base = ldap::dn::parse(setting("LDAP_BASE", "dc=example,dc=org"));
	auto admin = ldap::dn::parse(setting("LDAP_BIND_DN", "cn=admin,dc=example,dc=org"));
	if (!u || !base || !admin) {
		println(stderr, "bad URL, LDAP_BASE or LDAP_BIND_DN");
		co_return 2;
	}

	ldap::connection_options options;
	options.schema_check = ldap::schema_check::on_first_use;// optional; off by default
	auto c = co_await ldap::connect(ioc, std::move(*u), options);
	if (!c) {
		println(stderr, "connect: {}", c.error().message());
		co_return 1;
	}
	if (auto b = co_await c->simple_bind(*admin, setting("LDAP_PASSWORD", "secret")); !b) {
		println(stderr, "bind: {}", b.error().message());
		co_return 1;
	}

	const ldap::dn entry = base->child(ldap::rdn{ "uid=example-mapping" });
	if (auto r = co_await c->del({ .entry = entry }); !r && r.error().code != ldap::cond::not_found)
		println(stderr, "cleanup: {}", r.error().message());

	// add(dn, value): objectClass from the descriptor, then every member
	// except read_only ones and empty optionals / vectors.
	const person jane{
		.uid = "example-mapping",
		.cn = "Jane Doe",
		.sn = "Doe",
		.mail = "jane@example.org",
		.phones = { "+1 555 0100" },
		.manager = *admin,
		.created = {},// read_only: never sent
	};
	if (auto r = co_await c->add(entry, jane); !r) {
		// With schema_check on, a struct that does not fit the server's
		// schema fails here, with the report in the error's context.
		println(stderr, "add: {}", r.error().message());
		co_return 1;
	}
	println(stdout, "added:");
	if (!co_await show(*c, *base)) co_return 1;

	// Typed changes: replace / add / remove<&T::member>(value). A member
	// that is not described, is read_only, or a value of the wrong type
	// does not compile. They are applied in order, atomically.
	auto m = co_await c->modify<person>(entry,
	  {
		ldap::replace<&person::mail>("jane.doe@example.org"),
		ldap::add<&person::phones>(std::vector<std::string>{ "+1 555 0101", "+1 555 0102" }),
		ldap::remove<&person::phones>("+1 555 0100"),
		ldap::remove<&person::manager>(),// the whole attribute
	  });
	if (!m) {
		println(stderr, "modify: {}", m.error().message());
		co_return 1;
	}
	println(stdout, "modified:");
	if (!co_await show(*c, *base)) co_return 1;

	// The untyped API works on the same entry; ldap::decode<T> converts any
	// ldap::entry (from search() or search_stream) on demand.
	auto raw = co_await c->search({ .base = entry, .scope = ldap::search_scope::base_object, .attributes = { "*" } });
	if (raw && !raw->empty()) {
		auto p = ldap::decode<person>(raw->front());
		// Fails: createTimestamp is operational, so "*" did not return it,
		// and the member is required. The error names entry and attribute.
		if (!p) println(stdout, "decode without createTimestamp (expected): {}", p.error().message());
	}

	if (auto r = co_await c->del({ .entry = entry }); !r) println(stderr, "delete: {}", r.error().message());
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
