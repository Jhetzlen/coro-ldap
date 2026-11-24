#include "jhetz/ldap/entry.hpp"

#include <algorithm>
#include <ranges>
#include <unordered_map>
#include <utility>

namespace jhetz::ldap {

attribute_values::attribute_values(const attribute &type_,
  std::initializer_list<std::string_view> values_,
  const allocator_type &alloc)
  : type(type_, alloc), values(values_.begin(), values_.end(), alloc)
{}

auto entry::find(std::string_view type) const noexcept -> const std::pmr::vector<std::pmr::string> *
{
	const bool has_options = type.contains(';');
	const auto it = std::ranges::find_if(attributes, [&](const attribute_values &a) {
		return has_options ? detail::same_description(a.type.name(), type) : detail::iequals(a.type.name(), type);
	});
	return it == attributes.end() ? nullptr : &it->values;
}

auto entry::parsed_dn(std::pmr::memory_resource *mr) const -> result<ldap::dn> { return ldap::dn::parse(dn, mr); }

auto entry::from(search_result_entry e) -> entry
{
	const allocator_type alloc = e.get_allocator();
	entry out(alloc);
	out.dn = std::move(e.object_name);
	// Reserved up front, so the attribute names the index points into never move.
	out.attributes.reserve(e.attributes.size());
	// Index by description, on the entry's resource.
	std::pmr::unordered_map<std::string_view, std::size_t, detail::ci_hash, detail::ci_equal> index(alloc);
	for (auto &pa : e.attributes) {
		const auto it = index.find(pa.type);
		if (it == index.end()) {
			auto &a = out.attributes.emplace_back();
			a.type = attribute::unchecked(std::move(pa.type));
			a.values = std::move(pa.values);
			index.emplace(std::string_view(a.type.name()), out.attributes.size() - 1);
		} else {
			out.attributes[it->second].values.append_range(pa.values | std::views::as_rvalue);
		}
	}
	return out;
}

}// namespace jhetz::ldap
