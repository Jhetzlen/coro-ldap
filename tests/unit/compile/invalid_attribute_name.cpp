#include "common.hpp"
struct thing
{
	std::string name;
};
template<> constexpr auto ldap::mapping<thing> = ldap::describe(ldap::field<&thing::name>("not valid!"));
auto main() -> int {}
