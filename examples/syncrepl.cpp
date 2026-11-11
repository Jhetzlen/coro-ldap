#include "jhetz/ldap/connection.hpp"

#include <boost/corosio/io_context.hpp>

#include <array>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace ldap = jhetz::ldap;

auto example(boost::corosio::io_context &ioc, std::string text) -> boost::capy::task<int>
{
	auto c = co_await ldap::connect(ioc, text);
	if (!c) {
		std::cerr << c.error().message() << '\n';
		co_return 1;
	}
	auto changes = co_await c->search_stream({
	  .base = ldap::dn{ "ou=people,dc=example,dc=org" },
	  .controls = { ldap::sync_request{ .mode = ldap::sync_mode::refresh_and_persist } },
	  .timeout = ldap::no_timeout,
	  .intermediate_responses = true,
	});
	if (!changes) {
		std::cerr << changes.error().message() << '\n';
		co_return 1;
	}
	constexpr std::array<std::string_view, 4> states = { "present", "add", "modify", "delete" };
	for (;;) {
		auto item = co_await changes->next_item();
		if (!item || !*item) {
			std::cerr << (item ? "search ended" : item.error().message()) << '\n';
			co_return 1;
		}
		if (const auto *entry = std::get_if<ldap::search_entry>(&**item)) {
			auto state = ldap::find_sync_state(entry->controls);
			if (state && *state) {
				std::cout << states[std::to_underlying((*state)->state)] << ' ' << entry->dn << '\n';
			}
		}
	}
}

auto main(int argc, char *const *argv) -> int
{
	boost::corosio::io_context ioc;
	return ldap::run(ioc, example(ioc, argc > 1 ? argv[1] : "ldap://localhost"));
}
