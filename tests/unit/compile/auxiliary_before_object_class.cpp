#include "common.hpp"
struct gadget
{
	std::string cn;
};
template<>
constexpr auto ldap::mapping<gadget> =
  ldap::describe(ldap::auxiliary_class("posixAccount"), ldap::object_class("person"), ldap::field<&gadget::cn>("cn"));
auto main() -> int { return static_cast<int>(ldap::attribute_names<gadget>().size()); }
