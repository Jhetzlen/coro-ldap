#include "jhetz/ldap/operations.hpp"
// RFC 5805 section 2.2: update requests only.
auto main() -> int { (void)jhetz::ldap::search_params{ .controls = { jhetz::ldap::transaction_specification{} } }; }
