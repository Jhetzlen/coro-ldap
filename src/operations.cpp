// The ldap::mod builders (operations.hpp): part of the codec, they only
// build message.hpp's modify_change.
#include "jhetz/ldap/operations.hpp"

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
