// Untyped search result entry (DESIGN.md section 4, "exploring unknown data").
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/message.hpp"

#include <initializer_list>
#include <memory_resource>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

// Memory: attribute_values and entry are allocator-aware (std::pmr), like the
// message model: a plain copy uses the default resource, the
// allocator-extended copy the given one, assignment keeps the target's.
struct attribute_values
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	attribute type{};
	std::pmr::vector<std::pmr::string> values{};// raw bytes, possibly binary

	attribute_values() = default;
	explicit attribute_values(const allocator_type &alloc) : type(alloc), values(alloc) {}
	attribute_values(const attribute &type_,
	  std::initializer_list<std::string_view> values_,
	  const allocator_type &alloc = {});
	attribute_values(const attribute_values &) = default;
	attribute_values(attribute_values &&) noexcept = default;
	attribute_values(const attribute_values &other, const allocator_type &alloc)
	  : type(other.type, alloc), values(other.values, alloc)
	{}
	attribute_values(attribute_values &&other, const allocator_type &alloc)
	  : type(std::move(other.type), alloc), values(std::move(other.values), alloc)
	{}
	attribute_values &operator=(const attribute_values &) = default;
	attribute_values &operator=(attribute_values &&) = default;
	~attribute_values() = default;

	allocator_type get_allocator() const noexcept { return values.get_allocator(); }

	friend bool operator==(const attribute_values &, const attribute_values &) = default;
};

// DN text plus attributes in the order the server sent them. The DN is kept
// as text (servers may send DNs ldap::dn::parse rejects); attribute names are
// kept as sent (attribute::unchecked), compared case-insensitively.
struct entry
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	std::pmr::string dn{};
	std::pmr::vector<attribute_values> attributes{};

	entry() = default;
	explicit entry(const allocator_type &alloc) : dn(alloc), attributes(alloc) {}
	entry(const entry &) = default;
	entry(entry &&) noexcept = default;
	entry(const entry &other, const allocator_type &alloc) : dn(other.dn, alloc), attributes(other.attributes, alloc) {}
	entry(entry &&other, const allocator_type &alloc)
	  : dn(std::move(other.dn), alloc), attributes(std::move(other.attributes), alloc)
	{}
	entry &operator=(const entry &) = default;
	entry &operator=(entry &&) = default;
	~entry() = default;

	allocator_type get_allocator() const noexcept { return dn.get_allocator(); }

	// Values of `type` (case-insensitive, options included: `cn;lang-en` is
	// not `cn`), or nullptr if the entry has no such attribute. An attribute
	// present without values (typesOnly searches) gives an empty vector.
	[[nodiscard]] const std::pmr::vector<std::pmr::string> *find(std::string_view type) const noexcept;
	[[nodiscard]] const std::pmr::vector<std::pmr::string> *find(const attribute &type) const noexcept
	{
		return find(type.name());
	}

	// Attributes with the same description (compared case-insensitively) are
	// merged, keeping the first spelling and the order of first appearance.
	// The entry takes the strings of `e` and is allocated from e's resource
	// (so an entry made from a message decoded into an arena lives in it too).
	[[nodiscard]] static entry from(search_result_entry e);

	friend bool operator==(const entry &, const entry &) = default;
};

}// namespace jhetz::ldap
