#include "jhetz/ldap/operations.hpp"
// RFC 4527 section 3.2: no post-read of a delete.
auto main() -> int { (void)jhetz::ldap::del_params{ .controls = { jhetz::ldap::post_read{} } }; }
