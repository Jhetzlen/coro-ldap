// Internal: parsed form of a filter, shared by filter.cpp and message.cpp so a
// search request can check its filter before anything is written.
#pragma once

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap::detail {

enum class filter_kind {
	and_,
	or_,
	not_,
	equality,
	substrings,
	greater_or_equal,
	less_or_equal,
	present,
	approx,
	extensible
};

struct filter_node
{
	filter_kind kind = filter_kind::present;
	std::string attr;// attribute description (extensible: type, may be empty)
	std::string value;// assertion value / matchValue
	std::string rule;// extensible: matchingRule, may be empty
	bool dn_attributes = false;// extensible
	std::optional<std::string> initial;// substrings
	std::vector<std::string> any;// substrings
	std::optional<std::string> final_;// substrings
	std::vector<filter_node> children;// and / or: any number; not: exactly one
};

// RFC 4515 text -> tree (invalid_filter on error).
result<filter_node> parse_filter(std::string_view text);

// Tree -> BER; cannot fail.
void write_filter(ber::writer &w, const filter_node &node);

}// namespace jhetz::ldap::detail
