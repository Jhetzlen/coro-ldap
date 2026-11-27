// A memory resource that counts what goes through it, to show that
// allocator-aware types really allocate from the resource they are given.
#pragma once

#include <cstddef>
#include <memory_resource>

namespace jhetz::ldap::test {

class counting_resource final : public std::pmr::memory_resource
{
  public:
	explicit counting_resource(std::pmr::memory_resource *upstream = std::pmr::new_delete_resource()) noexcept
	  : upstream_(upstream)
	{}

	[[nodiscard]] auto allocations() const noexcept -> std::size_t { return allocations_; }
	[[nodiscard]] auto bytes() const noexcept -> std::size_t { return bytes_; }
	[[nodiscard]] auto outstanding_count() const noexcept -> std::size_t { return outstanding_; }

  private:
	auto do_allocate(std::size_t n, std::size_t align) -> void * override
	{
		void *p = upstream_->allocate(n, align);
		++allocations_;
		bytes_ += n;
		outstanding_ += n;
		return p;
	}
	void do_deallocate(void *p, std::size_t n, std::size_t align) override
	{
		outstanding_ -= n;
		upstream_->deallocate(p, n, align);
	}
	[[nodiscard]] auto do_is_equal(const std::pmr::memory_resource &other) const noexcept -> bool override
	{
		return this == &other;
	}

	std::pmr::memory_resource *upstream_;
	std::size_t allocations_ = 0;
	std::size_t bytes_ = 0;
	std::size_t outstanding_ = 0;
};

// Installs `r` as the default resource for the scope of the object.
class scoped_default_resource
{
  public:
	explicit scoped_default_resource(std::pmr::memory_resource *r) noexcept : old_(std::pmr::set_default_resource(r)) {}
	scoped_default_resource(const scoped_default_resource &) = delete;
	auto operator=(const scoped_default_resource &) -> scoped_default_resource & = delete;
	~scoped_default_resource() { std::pmr::set_default_resource(old_); }

  private:
	std::pmr::memory_resource *old_;
};

}// namespace jhetz::ldap::test
