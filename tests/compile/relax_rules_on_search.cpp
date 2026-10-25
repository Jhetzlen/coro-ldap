#include "jhetz/ldap/operations.hpp"
// draft-zeilenga-ldap-relax-03 section 2: update operations only.
auto main() -> int { (void)jhetz::ldap::search_params{ .controls = { jhetz::ldap::relax_rules{} } }; }
