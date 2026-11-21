#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <format>
#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;

constexpr int operations = 10'000;
constexpr int window = 64;

struct in_flight
{
	int count = 0;
	capy::async_event changed{};
};

auto add_modify_delete(ldap::connection &c, in_flight &running, int i) -> capy::task<>
{
	auto uid = std::format("bulk{:05}", i);
	const auto who = *ldap::dn::parse(std::format("uid={},ou=people,dc=example,dc=org", uid));
	auto added = co_await c.add({
	  .entry = who,
	  .attributes = { { "objectClass", { "inetOrgPerson" } },
		{ "uid", { uid } },
		{ "cn", { uid } },
		{ "sn", { "Bulk" } } },
	});
	if (!added) {
		std::cerr << uid << ": " << added.error().message() << '\n';
	} else {
		const auto modified =
		  co_await c.modify({ .object = who, .changes = { ldap::mod::replace("sn", { "Changed" }) } });
		const auto deleted = co_await c.del({ .entry = who });
		std::cout << uid << ": " << (modified && deleted ? "done" : "modify or delete failed") << '\n';
	}
	--running.count;
	running.changed.set();
}

auto example(boost::corosio::io_context &ioc, std::string text) -> capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text, { .allow_cleartext_passwords = true });
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	in_flight running;
	for (int i = 0; i < operations || running.count > 0;) {
		if (i < operations && running.count < window) {
			++running.count;
			capy::run_async(ioc.get_executor())(add_modify_delete(*c, running, i++));
			continue;
		}
		running.changed.clear();
		co_await running.changed.wait();
	}
	if (auto unbound = co_await c->unbind(); !unbound) {
		std::cerr << unbound.error().message() << '\n';
		co_return 1;
	}
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	boost::corosio::io_context ioc;
	return ldap::run(ioc, example(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
}
