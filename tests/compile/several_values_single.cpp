#include "common.hpp"
int main() { (void)ldap::replace<&person::uid>(std::vector<std::string>{ "a", "b" }); }
