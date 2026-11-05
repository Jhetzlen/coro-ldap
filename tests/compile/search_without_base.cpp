#include "jhetz/ldap/operations.hpp"
// search_params::base has no default.
auto main() -> int { (void)jhetz::ldap::search_params{ .scope = jhetz::ldap::search_scope::base_object }; }
