// Internal: allocator-aware copies and assignments of std::optional and
// std::variant members, which the standard types do not do themselves (an
// empty optional has no allocator to keep; a variant switching alternatives
// constructs the new one without the owner's allocator).
#pragma once

#include <memory>
#include <memory_resource>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace jhetz::ldap::detail {

using pmr_alloc = std::pmr::polymorphic_allocator<>;

// A copy (or move, for an rvalue) of `src` whose contents use `alloc`.
template<class Opt> auto optional_with(Opt &&src, const pmr_alloc &alloc)
{
	using T = typename std::remove_cvref_t<Opt>::value_type;
	if (!src) {
		return std::optional<T>{};
	}
	return std::optional<T>(std::in_place, std::make_obj_using_allocator<T>(alloc, *std::forward<Opt>(src)));
}

// dst = src, constructing a newly engaged value with `alloc`.
template<class T, class Opt> void assign_optional(std::optional<T> &dst, Opt &&src, const pmr_alloc &alloc)
{
	if (!src) {
		dst.reset();
	} else if (dst) {
		*dst = *std::forward<Opt>(src);// the value's own assignment keeps its resource
	} else {
		dst.emplace(std::make_obj_using_allocator<T>(alloc, *std::forward<Opt>(src)));
	}
}

// A copy (or move) of `src` whose alternative uses `alloc`.
template<class Var> std::remove_cvref_t<Var> variant_with(Var &&src, const pmr_alloc &alloc)
{
	using V = std::remove_cvref_t<Var>;
	return std::visit(
	  [&](auto &&x) -> V {
		  using T = std::remove_cvref_t<decltype(x)>;
		  return V(std::in_place_type<T>, std::make_obj_using_allocator<T>(alloc, std::forward<decltype(x)>(x)));
	  },
	  std::forward<Var>(src));
}

// dst = src, constructing a new alternative with `alloc`.
template<class... T, class Var> void assign_variant(std::variant<T...> &dst, Var &&src, const pmr_alloc &alloc)
{
	std::visit(
	  [&](auto &&x) {
		  using U = std::remove_cvref_t<decltype(x)>;
		  if (auto *d = std::get_if<U>(&dst)) {
			  *d = std::forward<decltype(x)>(x);
		  } else {
			  dst.template emplace<U>(std::make_obj_using_allocator<U>(alloc, std::forward<decltype(x)>(x)));
		  }
	  },
	  std::forward<Var>(src));
}

// Copy of `s` on `alloc` (string_view -> std::pmr::string, optional aware).
inline std::optional<std::pmr::string> optional_string(std::optional<std::string_view> s, const pmr_alloc &alloc)
{
	if (!s) {
		return std::nullopt;
	}
	return std::optional<std::pmr::string>(std::in_place, *s, alloc);
}

}// namespace jhetz::ldap::detail
