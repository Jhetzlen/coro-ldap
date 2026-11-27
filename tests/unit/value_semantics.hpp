// Value semantics of the allocator-aware types: a plain copy goes to the
// default resource, a move keeps the source's, an allocator-extended one
// uses the given resource, and assignment keeps the target's.
#pragma once

#include "counting_resource.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory_resource>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace jhetz::ldap::test {

using resources = std::vector<std::pmr::memory_resource *>;

inline auto mr(const std::pmr::string &s) -> std::pmr::memory_resource * { return s.get_allocator().resource(); }

// Resources of the members that get_allocator() does not stand for (optional
// members, nested elements). The default: none.
struct no_members
{
	template<class T> auto operator()(const T &) const -> resources { return {}; }
};

template<class T, class Members> void check_on(const T &x, std::pmr::memory_resource *r, const Members &members)
{
	CHECK(x.get_allocator().resource() == r);
	for (auto *m : members(x)) {
		CHECK(m == r);
	}
}

// Runs every construction and assignment of T on `sample` (long strings,
// engaged optionals).
template<class T, class Members = no_members> void check_value_semantics(const T &sample, Members members = {})
{
	using alloc_t = T::allocator_type;
	const T empty{};
	counting_resource heap;// the default resource while the operations run
	counting_resource ra;
	counting_resource rb;
	counting_resource rs;// sources that die before their targets
	const alloc_t a(&ra);
	const alloc_t b(&rb);
	scoped_default_resource guard(&heap);

	// Allocator-extended copy.
	const T src(sample, a);
	CHECK(src == sample);
	check_on(src, &ra, members);
	const T copy_b(src, b);
	CHECK(copy_b == sample);
	check_on(copy_b, &rb, members);

	// Allocator-extended move, on the same resource and on another one.
	T tmp(src, a);
	const T moved_same(std::move(tmp), a);
	CHECK(moved_same == sample);
	check_on(moved_same, &ra, members);
	// The moved-from object is still usable: assigned to, it holds the value.
	tmp = src;
	CHECK(tmp == sample);
	check_on(tmp, &ra, members);
	std::optional<T> moved_other;
	{
		T s(src, alloc_t(&rs));
		moved_other.emplace(std::move(s), b);
		s = src;
		CHECK(s == sample);
		check_on(s, &rs, members);
	}
	CHECK(*moved_other == sample);
	check_on(*moved_other, &rb, members);

	// Copy assignment keeps the target's resource: into empty optional members,
	// into engaged ones, from itself, and back to empty.
	T target(b);
	target = src;
	CHECK(target == sample);
	check_on(target, &rb, members);
	target = src;
	CHECK(target == sample);
	check_on(target, &rb, members);
	const T &alias = target;
	target = alias;
	CHECK(target == sample);
	check_on(target, &rb, members);
	target = T(a);
	CHECK(target == empty);
	CHECK(target.get_allocator().resource() == &rb);

	// Move assignment from another resource copies into the target's.
	T moved_into(b);
	{
		T s(src, alloc_t(&rs));
		moved_into = std::move(s);
	}
	CHECK(moved_into == sample);
	check_on(moved_into, &rb, members);
	{
		T s(src, alloc_t(&rs));
		moved_into = std::move(s);// into engaged optional members
	}
	CHECK(moved_into == sample);
	check_on(moved_into, &rb, members);
	moved_into = T(a);
	CHECK(moved_into == empty);
	CHECK(moved_into.get_allocator().resource() == &rb);

	// Nothing kept memory of a dead source, nothing went to the default resource.
	CHECK(rs.outstanding_count() == 0);
	CHECK(heap.allocations() == 0);

	// A plain copy goes to the default resource, a plain move keeps the source's.
	const T plain(src);
	CHECK(plain == sample);
	check_on(plain, &heap, members);
	T to_move(src, a);
	const T plain_moved(std::move(to_move));
	CHECK(plain_moved == sample);
	check_on(plain_moved, &ra, members);
}

}// namespace jhetz::ldap::test
