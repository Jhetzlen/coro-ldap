#include "common.hpp"
int main() { (void)(ldap::filters::field<&person::uid_number>() == "x"); }
