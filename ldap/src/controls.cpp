#include "jhetz/ldap/controls.hpp"

#include "jhetz/ldap/ber.hpp"

#include <type_traits>
#include <utility>

namespace jhetz::ldap {

result<control> to_control(const request_control &c, std::pmr::memory_resource *mr)
{
	return std::visit(
	  [mr](const auto &v) -> result<control> {
		  using T = std::decay_t<decltype(v)>;
		  const control::allocator_type alloc(mr);
		  if constexpr (std::is_same_v<T, control>) {
			  return control(v, alloc);
		  } else if constexpr (std::is_same_v<T, paged>) {
			  return encode_paged_results(paged_results(v.page_size, v.cookie, alloc), v.critical, mr);
		  } else if constexpr (std::is_same_v<T, manage_dsa_it>) {
			  return control(manage_dsa_it_oid, v.critical, std::nullopt, alloc);
		  } else {
			  static_assert(std::is_same_v<T, proxied_authorization>);
			  // controlValue is the authzId itself, not BER (RFC 4370 section 3).
			  return control(proxied_authorization_oid, true, v.authz_id, alloc);
		  }
	  },
	  c);
}

result<void> append_controls(const request_controls &controls, std::pmr::vector<control> &out)
{
	for (const auto &c : controls) {
		auto wire = to_control(c, out.get_allocator().resource());
		if (!wire) return std::unexpected(std::move(wire.error()));
		out.push_back(std::move(*wire));
	}
	return {};
}

result<std::optional<paged_results>> find_paged(const std::pmr::vector<control> &controls,
  std::pmr::memory_resource *mr)
{
	for (const auto &c : controls) {
		if (c.type != paged_results_oid) continue;
		auto p = decode_paged_results(c, mr);
		if (!p) return std::unexpected(std::move(p.error()));
		return std::optional<paged_results>(std::move(*p));
	}
	return std::optional<paged_results>{};
}

}// namespace jhetz::ldap
