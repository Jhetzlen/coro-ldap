// Untyped search result entry (DESIGN.md section 4).
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/dn.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"

#include <initializer_list>
#include <memory_resource>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

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
	auto operator=(const attribute_values &) -> attribute_values & = default;
	auto operator=(attribute_values &&) -> attribute_values & = default;
	~attribute_values() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return values.get_allocator(); }

	friend auto operator==(const attribute_values &, const attribute_values &) -> bool = default;
};

// DN text plus attributes in the order the server sent them, names kept as
// sent.
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
	auto operator=(const entry &) -> entry & = default;
	auto operator=(entry &&) -> entry & = default;
	~entry() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return dn.get_allocator(); }

	// Values of `type` (case-insensitive, options compared as a set), or
	// nullptr.
	[[nodiscard]] auto find(std::string_view type) const noexcept -> const std::pmr::vector<std::pmr::string> *;
	[[nodiscard]] auto find(const attribute &type) const noexcept -> const std::pmr::vector<std::pmr::string> *
	{
		return find(type.name());
	}

	// dn::parse(dn, mr).
	[[nodiscard]] auto parsed_dn(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> result<ldap::dn>;

	// Takes the strings of `e`, on its resource; merges attributes with the
	// same description.
	[[nodiscard]] static auto from(search_result_entry e) -> entry;

	friend auto operator==(const entry &, const entry &) -> bool = default;
};

}// namespace jhetz::ldap
