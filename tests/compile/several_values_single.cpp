#include "common.hpp"
auto main() -> int { (void)ldap::replace<&person::uid>(std::vector<std::string>{ "a", "b" }); }
