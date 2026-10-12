#include "jhetz/ldap/entry.hpp"

#include <iterator>
#include <unordered_map>
#include <utility>

namespace jhetz::ldap {

attribute_values::attribute_values(const attribute &type_,
  std::initializer_list<std::string_view> values_,
  const allocator_type &alloc)
  : type(type_, alloc), values(alloc)
{
	values.reserve(values_.size());
	for (auto v : values_) values.emplace_back(v);
}

const std::pmr::vector<std::pmr::string> *entry::find(std::string_view type) const noexcept
{
	for (const auto &a : attributes)
		if (detail::iequals(a.type.name(), type)) return &a.values;
	return nullptr;
}

entry entry::from(search_result_entry e)
{
	const allocator_type alloc = e.get_allocator();
	entry out(alloc);
	out.dn = std::move(e.object_name);
	// Reserved up front, so the attribute names the index points into never move.
	out.attributes.reserve(e.attributes.size());
	// Index by description, so a server sending many attributes cannot make
	// this quadratic. Temporary, on the entry's resource.
	std::pmr::unordered_map<std::string_view, std::size_t, detail::ci_hash, detail::ci_equal> index(alloc);
	for (auto &pa : e.attributes) {
		const auto it = index.find(pa.type);
		if (it == index.end()) {
			auto &a = out.attributes.emplace_back();
			a.type = attribute::unchecked(std::move(pa.type));
			a.values = std::move(pa.values);
			index.emplace(std::string_view(a.type.name()), out.attributes.size() - 1);
		} else {
			auto &values = out.attributes[it->second].values;
			values.insert(
			  values.end(), std::make_move_iterator(pa.values.begin()), std::make_move_iterator(pa.values.end()));
		}
	}
	return out;
}

}// namespace jhetz::ldap
