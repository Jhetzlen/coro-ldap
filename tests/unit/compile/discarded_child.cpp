// dn::child() returns the new DN and leaves `base` unchanged, so a discarded
// result is a bug: [[nodiscard]] must make the compiler warn.
#include "jhetz/ldap/dn.hpp"

namespace ldap = jhetz::ldap;

auto main() -> int
{
	const ldap::dn base{ "ou=people,dc=example,dc=org" };
	base.child(ldap::rdn{ "uid=jdoe" });
}
