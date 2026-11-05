// Active Directory's own attribute syntax OIDs.
#pragma once

namespace jhetz::ldap::ad {

// Large Integer / Interval: a signed 64-bit integer in decimal. FILETIME
// dates such as accountExpires, intervals such as maxPwdAge, and counters
// such as uSNChanged (ad/filetime.hpp). The core's signed integers of 64
// bits or more accept it in validate<T> (schema.hpp).
inline constexpr const char *large_integer_syntax = "1.2.840.113556.1.4.906";

}// namespace jhetz::ldap::ad
