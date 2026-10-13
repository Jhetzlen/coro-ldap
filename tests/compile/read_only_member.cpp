#include "common.hpp"
int main() { (void)ldap::replace<&person::created>(std::chrono::sys_seconds{}); }
