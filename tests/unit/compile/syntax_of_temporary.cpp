// syntax_of may point into its argument, so a temporary is rejected.
#include "jhetz/ldap/schema.hpp"

namespace ldap = jhetz::ldap;

auto main() -> int
{
	ldap::server_schema s;
	return s.syntax_of(ldap::attribute_type{}) != nullptr;
}
