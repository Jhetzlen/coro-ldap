// Untyped search result entry (DESIGN.md section 4, "exploring unknown data").
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/message.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

struct attribute_values
{
	attribute type{};
	std::vector<std::string> values{};// raw bytes, possibly binary

	friend bool operator==(const attribute_values &, const attribute_values &) = default;
};

// DN text plus attributes in the order the server sent them. The DN is kept
// as text (servers may send DNs ldap::dn::parse rejects); attribute names are
// kept as sent (attribute::unchecked), compared case-insensitively.
struct entry
{
	std::string dn{};
	std::vector<attribute_values> attributes{};

	// Values of `type` (case-insensitive, options included: `cn;lang-en` is
	// not `cn`), or nullptr if the entry has no such attribute. An attribute
	// present without values (typesOnly searches) gives an empty vector.
	const std::vector<std::string> *find(std::string_view type) const noexcept;
	const std::vector<std::string> *find(const attribute &type) const noexcept { return find(type.name()); }

	// Attributes with the same description (compared case-insensitively) are
	// merged, keeping the first spelling and the order of first appearance.
	static entry from(search_result_entry e);

	friend bool operator==(const entry &, const entry &) = default;
};

}// namespace jhetz::ldap
