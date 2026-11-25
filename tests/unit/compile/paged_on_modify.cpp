#include "jhetz/ldap/operations.hpp"
// RFC 2696 section 2: search only.
auto main() -> int { (void)jhetz::ldap::modify_params{ .controls = { jhetz::ldap::paged{ .page_size = 10 } } }; }
