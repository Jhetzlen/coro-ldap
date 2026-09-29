#include "jhetz/ldap/entry.hpp"

#include <iterator>
#include <unordered_map>
#include <utility>

namespace jhetz::ldap {

const std::vector<std::string> *entry::find(std::string_view type) const noexcept
{
	for (const auto &a : attributes)
		if (detail::iequals(a.type.name(), type)) return &a.values;
	return nullptr;
}

entry entry::from(search_result_entry e)
{
	entry out;
	out.dn = std::move(e.object_name);
	out.attributes.reserve(e.attributes.size());
	// Index by description, so a server sending many attributes cannot make
	// this quadratic.
	std::unordered_map<attribute, std::size_t> index;
	for (auto &pa : e.attributes) {
		attribute type = attribute::unchecked(std::move(pa.type));
		const auto [it, inserted] = index.try_emplace(type, out.attributes.size());
		if (inserted) {
			out.attributes.push_back(attribute_values{ std::move(type), std::move(pa.values) });
		} else {
			auto &values = out.attributes[it->second].values;
			values.insert(
			  values.end(), std::make_move_iterator(pa.values.begin()), std::make_move_iterator(pa.values.end()));
		}
	}
	return out;
}

}// namespace jhetz::ldap
