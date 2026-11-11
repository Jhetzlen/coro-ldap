#include "common.hpp"
struct gadget
{
	std::string cn;
	std::vector<std::string> versions;
};
template<>
constexpr auto ldap::schema<gadget> =
  ldap::describe(ldap::field<&gadget::cn>("cn"), ldap::field<&gadget::versions>("description"));
auto main() -> int { return ldap::unchanged_filter<&gadget::versions>(gadget{}).has_value() ? 0 : 1; }
