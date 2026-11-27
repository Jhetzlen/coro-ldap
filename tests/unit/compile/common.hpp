// Shared by the compile tests: each file must fail to compile with the
// expected diagnostic, except ok.cpp.
#pragma once

#include "jhetz/ldap/mapping.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace ldap = jhetz::ldap;

struct person
{
	std::string uid;
	std::optional<std::string> mail;
	std::vector<ldap::dn> member_of;
	int uid_number = 0;
	std::chrono::sys_seconds created{};
	std::string not_described;
};

template<>
constexpr auto ldap::mapping<person> = ldap::describe(ldap::object_class("inetOrgPerson"),
  ldap::field<&person::uid>("uid"),
  ldap::field<&person::mail>("mail"),
  ldap::field<&person::member_of>("memberOf"),
  ldap::field<&person::uid_number>("uidNumber"),
  ldap::field<&person::created>("createTimestamp", ldap::read_only));

struct device
{
	std::string cn;
};

template<> constexpr auto ldap::mapping<device> = ldap::describe(ldap::field<&device::cn>("cn"));
