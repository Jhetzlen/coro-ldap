#include "common.hpp"
struct opaque
{
};
struct holder
{
	opaque o;
};
template<> constexpr auto ldap::mapping<holder> = ldap::describe(ldap::field<&holder::o>("o"));
auto main() -> int {}
