#include "jhetz/ldap/url.hpp"
namespace ldap = jhetz::ldap;
const ldap::url server{ "ldap://ldap.example.org/dc=example,dc=org" };
auto main() -> int {}
