#include "jhetz/ldap/sync.hpp"

#include <iostream>
#include <string>

namespace ldap = jhetz::ldap;

auto main(int argc, char *const *argv) -> int
{
	auto mail = ldap::sync::connect(argc > 1 ? argv[1] : "ldap://localhost", { .start_tls = true })
				  .and_then([](ldap::sync::connection c) {
					  return c.simple_bind(ldap::dn{ "cn=admin,dc=example,dc=org" }, "secret");
				  })
				  .and_then([](ldap::sync::connection c) {
					  return c.search({
						.base = ldap::dn{ "ou=people,dc=example,dc=org" },
						.filter = ldap::filters::attr("uid") == "jdoe",
						.attributes = { "mail" },
					  });
				  })
				  .transform([](const ldap::search_result &r) {
					  const auto *values = r.entries.empty() ? nullptr : r.entries.front().find("mail");
					  return values == nullptr || values->empty() ? std::string{} : std::string(values->front());
				  })
				  .or_else([](const ldap::error &e) -> ldap::result<std::string> {
					  std::cerr << e.message() << '\n';
					  return std::unexpected(e);
				  });
	if (!mail) {
		return 1;
	}
	std::cout << *mail << '\n';
}
