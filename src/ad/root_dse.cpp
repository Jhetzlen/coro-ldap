#include "jhetz/ldap/ad/root_dse.hpp"

#include <algorithm>

namespace jhetz::ldap::ad {

auto edition_of(const entry &root_dse) noexcept -> edition
{
	const auto *capabilities = root_dse.find("supportedCapabilities");
	if (capabilities == nullptr) {
		return edition::none;
	}
	if (std::ranges::contains(*capabilities, ds_capability_oid)) {
		return edition::ds;
	}
	if (std::ranges::contains(*capabilities, lds_capability_oid)) {
		return edition::lds;
	}
	return edition::none;
}

auto is_active_directory(const entry &root_dse) noexcept -> bool { return edition_of(root_dse) != edition::none; }

}// namespace jhetz::ldap::ad
