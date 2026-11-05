// Active Directory recognised from the root DSE (the entry of a base search
// of "" that requests supportedCapabilities).
#pragma once

#include "jhetz/ldap/entry.hpp"

#include <string_view>

namespace jhetz::ldap::ad {

// LDAP_CAP_ACTIVE_DIRECTORY_OID: listed by Active Directory Domain Services
// and Samba AD domain controllers.
inline constexpr std::string_view ds_capability_oid = "1.2.840.113556.1.4.800";
// LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID: listed by Active Directory Lightweight
// Directory Services (formerly ADAM).
inline constexpr std::string_view lds_capability_oid = "1.2.840.113556.1.4.1851";

enum class edition {
	none,// neither capability listed
	ds,// ds_capability_oid listed (Samba AD too)
	lds,// lds_capability_oid listed, ds_capability_oid not
};

// The edition the root DSE's supportedCapabilities lists. A root DSE read
// without supportedCapabilities, or hidden by access controls, gives none.
[[nodiscard]] auto edition_of(const entry &root_dse) noexcept -> edition;

// edition_of(root_dse) != edition::none.
[[nodiscard]] auto is_active_directory(const entry &root_dse) noexcept -> bool;

}// namespace jhetz::ldap::ad
