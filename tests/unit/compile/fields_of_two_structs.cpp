#include "common.hpp"
constexpr auto mixed = ldap::describe(ldap::field<&person::uid>("uid"), ldap::field<&device::cn>("cn"));
auto main() -> int {}
