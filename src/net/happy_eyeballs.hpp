// Internal: address ordering for Happy Eyeballs (RFC 8305), used by
// connect.cpp and unit-tested on its own.
#pragma once

#include <boost/corosio/endpoint.hpp>

#include <vector>

namespace jhetz::ldap::net::detail {

// RFC 8305 section 4: alternates the families, starting with the first
// address's; order within a family is kept.
auto interleave_families(std::vector<boost::corosio::endpoint> in) -> std::vector<boost::corosio::endpoint>;

}// namespace jhetz::ldap::net::detail
