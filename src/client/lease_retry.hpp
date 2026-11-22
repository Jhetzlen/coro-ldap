// Internal: an operation on a shared lease, retried once on another lease.
#pragma once

#include "jhetz/ldap/client.hpp"
#include "jhetz/ldap/error.hpp"

#include <boost/capy/task.hpp>

#include <string_view>
#include <system_error>
#include <utility>

namespace jhetz::ldap::detail {

template<class T> struct chase_result;

// Retires `failed`'s connection after its failure `code` (and avoids its
// server if it answered busy or unavailable), returns `failed`, and acquires
// another lease.
auto reacquire(lease failed, std::error_code code) -> boost::capy::task<result<lease>>;

template<class T> auto lease_outcome(result<T> &r) -> result<T> & { return r; }
template<class T> auto lease_outcome(chase_result<T> &r) -> result<T> & { return r.value; }

// `op` on the lease `first` gives; after a failure for which `retry(outcome)`
// holds, once more on another lease. `acquire_context` prefixes an acquire
// failure's context when not empty.
template<class T, class Retry, class Op>
auto retry_once_on_lease(boost::capy::task<result<lease>> first,
  Retry retry,
  Op op,
  std::string_view acquire_context = {}) -> boost::capy::task<result<T>>
{
	auto held = co_await std::move(first);
	for (bool retried = false;; retried = true) {
		if (!held) {
			if (acquire_context.empty()) {
				co_return std::unexpected(std::move(held.error()));
			}
			co_return std::unexpected(with_context(std::move(held.error()), acquire_context));
		}
		auto r = co_await op(*held);
		auto &v = lease_outcome(r);
		if (v || retried || !retry(r)) {
			co_return std::move(v);
		}
		held = co_await reacquire(std::move(*held), v.error().code);
	}
}

}// namespace jhetz::ldap::detail
