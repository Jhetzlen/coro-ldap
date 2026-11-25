#include "jhetz/ldap/operations.hpp"
// RFC 4528 section 3: no extended operation typed here defines it.
auto main() -> int { (void)jhetz::ldap::extended_params{ .controls = { jhetz::ldap::assertion{} } }; }
