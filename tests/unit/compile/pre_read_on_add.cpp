#include "jhetz/ldap/operations.hpp"
// RFC 4527 section 3.1: no pre-read of an add.
auto main() -> int { (void)jhetz::ldap::add_params{ .controls = { jhetz::ldap::pre_read{} } }; }
