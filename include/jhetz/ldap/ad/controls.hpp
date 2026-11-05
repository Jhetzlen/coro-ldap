// Active Directory's request controls, as raw ldap::control values that go
// in any operation's `.controls`.
//
//   co_await conn.search({
//       .base     = ldap::dn{ "DC=example,DC=org" },
//       .filter   = ldap::filters::attr("isDeleted") == "TRUE",
//       .controls = { ldap::ad::show_deleted{} },
//   });
#pragma once

#include "jhetz/ldap/message.hpp"

#include <string_view>

namespace jhetz::ldap::ad {

// LDAP_SERVER_SHOW_DELETED_OID (MS-ADTS 3.1.1.3.4.1.14): searches include
// deleted objects (tombstones and, with the Recycle Bin, deleted-objects),
// those with isDeleted TRUE, usually under CN=Deleted Objects of their
// naming context. No value. Critical by default: a server that does not
// know the control refuses the operation (unavailable_critical_extension)
// instead of leaving the deleted objects out.
inline constexpr std::string_view show_deleted_oid = "1.2.840.113556.1.4.417";
struct show_deleted
{
	bool critical = true;

	// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor): goes in `.controls` lists as is
	operator control() const { return { show_deleted_oid, critical }; }
};

}// namespace jhetz::ldap::ad
