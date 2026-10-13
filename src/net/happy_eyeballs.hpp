// Internal: address ordering for Happy Eyeballs (RFC 8305), used by
// connect.cpp and unit-tested on its own.
#pragma once

#include <boost/corosio/endpoint.hpp>

#include <vector>

namespace jhetz::ldap::net::detail {

// RFC 8305 section 4: alternates the address families, starting with the
// family of the first address (getaddrinfo already sorted them by RFC 6724
// preference); within a family the order is kept.
std::vector<boost::corosio::endpoint> interleave_families(std::vector<boost::corosio::endpoint> in);

}// namespace jhetz::ldap::net::detail
