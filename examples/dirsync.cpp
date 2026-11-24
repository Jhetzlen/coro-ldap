#include "jhetz/ldap/ad/dirsync.hpp"
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/when_any.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/signal_set.hpp>

#include <chrono>
#include <csignal>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto bound = co_await c->simple_bind(ldap::dn{ "cn=sync,cn=Users,dc=example,dc=org" }, "secret");
	if (!bound) {
		std::cerr << bound.error().message() << '\n';
		co_return 1;
	}
	std::ifstream saved("dirsync.cookie", std::ios::binary);
	ldap::ad::dirsync_request options{ .flags = ldap::ad::dirsync_flags::object_security,
		.cookie = { std::istreambuf_iterator<char>(saved), {} } };
	const ldap::search_params domain{ .base = ldap::dn{ "dc=example,dc=org" } };
	boost::corosio::signal_set stop(ioc, SIGINT, SIGTERM);
	constexpr std::size_t signalled = 1;
	do {
		auto changes = co_await ldap::ad::dirsync(*c, domain, options);
		if (!changes) {
			std::cerr << changes.error().message() << '\n';
			co_return 1;
		}
		for (const auto &entry : changes->entries) {
			std::cout << (entry.find("isDeleted") != nullptr ? "deleted " : "changed ") << entry.dn << '\n';
		}
		options.cookie = std::move(changes->cookie);
		std::ofstream("dirsync.cookie", std::ios::binary) << options.cookie;
	} while ((co_await boost::capy::when_any(stop.wait(), boost::corosio::delay(std::chrono::seconds(30)))).index()
			 != signalled);
	std::cout << "stopped\n";
	co_return 0;
}

auto main(int argc, char *const *argv) -> int
{
	return ldap::run(example, argc > 1 ? argv[1] : "ldaps://dc1.example.org");
}
