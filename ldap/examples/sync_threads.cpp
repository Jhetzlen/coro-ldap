// The blocking API: one ldap::sync::client shared by several threads.
//   jhetz_ldap_example_sync_threads [ldap://localhost]
#include "jhetz/ldap/sync.hpp"

#include <format>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ldap = jhetz::ldap;

static int fail(const ldap::error &e)
{
	std::cerr << e.message() << '\n';
	return 1;
}

int main(int argc, char **argv)
{
	auto u = ldap::url::parse(argc > 1 ? argv[1] : "ldap://localhost");
	if (!u) return fail(u.error());
	ldap::sync::client client;// runs the connection on its own I/O thread
	if (auto r = client.connect(*u); !r) return fail(r.error());
	if (auto r = client.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret"); !r) return fail(r.error());

	// The threads' requests are multiplexed on the one connection.
	std::mutex out;
	std::vector<std::jthread> threads;
	for (int t = 0; t < 4; ++t)
		threads.emplace_back([&, t] {
			auto found = client.search({
			  .base = ldap::dn{ "dc=example,dc=org" },
			  .filter = ldap::filters::attr("uid") == std::format("user{:03}", t),
			  .attributes = { "cn" },
			});
			std::lock_guard lock(out);
			if (!found)
				std::cerr << found.error().message() << '\n';
			else
				for (const ldap::entry &e : *found) std::cout << "thread " << t << ": " << e.dn << '\n';
		});
	threads.clear();// joins
	(void)client.unbind();
}
