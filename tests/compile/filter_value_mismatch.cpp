#include "common.hpp"
auto main() -> int { (void)(ldap::filters::field<&person::uid_number>() == "x"); }
