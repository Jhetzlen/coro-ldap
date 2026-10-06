#include "common.hpp"
struct opaque
{
};
struct holder
{
	opaque o;
};
template<> constexpr auto ldap::schema<holder> = ldap::describe(ldap::field<&holder::o>("o"));
int main() {}
