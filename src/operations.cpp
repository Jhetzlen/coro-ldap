// The ldap::mod builders and end_transaction_result's lookup
// (operations.hpp): part of the codec.
#include "jhetz/ldap/operations.hpp"

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <string_view>

namespace jhetz::ldap::mod {

namespace {
	auto change(modify_operation op, std::string_view type, std::initializer_list<std::string_view> values)
	  -> modify_change
	{
		return { op, partial_attribute(type, values) };
	}
}// namespace

auto add(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change
{
	return change(modify_operation::add, type, values);
}
auto remove(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change
{
	return change(modify_operation::delete_, type, values);
}
auto replace(std::string_view type, std::initializer_list<std::string_view> values) -> modify_change
{
	return change(modify_operation::replace, type, values);
}
auto increment(std::string_view type, std::string_view delta) -> modify_change
{
	return change(modify_operation::increment, type, { delta });
}

}// namespace jhetz::ldap::mod

namespace jhetz::ldap {

auto end_transaction_result::find_update_controls(std::int32_t message_id) const noexcept
  -> const std::pmr::vector<control> *
{
	const auto it = std::ranges::find(updates_controls, message_id, &update_controls::message_id);
	return it == updates_controls.end() ? nullptr : &it->controls;
}

}// namespace jhetz::ldap
