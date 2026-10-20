// Internal: a scope guard that runs a cleanup when it goes out of scope.
#pragma once

#include <type_traits>
#include <utility>

namespace jhetz::ldap::detail {

// Calls `f` on destruction unless release() was called first. Neither
// copyable nor movable: the guard stays where it was declared.
template<class F> class scope_exit
{
  public:
	explicit scope_exit(F f) noexcept(std::is_nothrow_move_constructible_v<F>) : f_(std::move(f)) {}
	scope_exit(const scope_exit &) = delete;
	scope_exit(scope_exit &&) = delete;
	auto operator=(const scope_exit &) -> scope_exit & = delete;
	auto operator=(scope_exit &&) -> scope_exit & = delete;
	~scope_exit()
	{
		if (active_) {
			f_();
		}
	}

	// The cleanup will not run.
	void release() noexcept { active_ = false; }

  private:
	F f_;
	bool active_ = true;
};

}// namespace jhetz::ldap::detail
