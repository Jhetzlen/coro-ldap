#include "common.hpp"
auto main() -> int { std::vector<ldap::change<person>> changes{ ldap::replace<&device::cn>("x") }; }
