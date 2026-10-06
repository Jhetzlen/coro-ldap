#include "common.hpp"
int main() { std::vector<ldap::change<person>> changes{ ldap::replace<&device::cn>("x") }; }
