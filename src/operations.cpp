// The ldap::mod builders (operations.hpp): part of the codec, they only
// build message.hpp's modify_change.
#include "jhetz/ldap/operations.hpp"

#include <initializer_list>
#include <string_view>

namespace jhetz::ldap {

namespace mod {

	namespace {
		modify_change change(modify_operation op, std::string_view type, std::initializer_list<std::string_view> values)
		{
			return modify_change(op, partial_attribute(type, values));
		}
	}// namespace

	modify_change add(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::add, type, values);
	}
	modify_change remove(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::delete_, type, values);
	}
	modify_change replace(std::string_view type, std::initializer_list<std::string_view> values)
	{
		return change(modify_operation::replace, type, values);
	}
	modify_change increment(std::string_view type, std::string_view delta)
	{
		return change(modify_operation::increment, type, { delta });
	}

}// namespace mod

}// namespace jhetz::ldap
