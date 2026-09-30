// Internal: the two halves of encode_filter, so a search request can check its
// filter before anything is written, then write it.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/filter.hpp"

namespace jhetz::ldap::detail {

// invalid_filter if `f` is empty or beyond `limits`.
result<void> check_filter(const filter &f, const filter_limits &limits);

// Tree -> BER. Precondition: check_filter succeeded (it bounds the recursion).
void write_filter(ber::writer &w, const filter &f);

}// namespace jhetz::ldap::detail
