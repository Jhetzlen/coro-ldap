#include "common.hpp"
auto main() -> int { (void)ldap::replace<&person::created>(std::chrono::sys_seconds{}); }
