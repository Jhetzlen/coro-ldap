// Internal: runs a SASL mechanism's offloaded step (sasl_work) on a thread
// of its own, for connection::sasl_bind.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/sasl.hpp"

#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>

#include <chrono>
#include <optional>
#include <string>

namespace jhetz::ldap::detail {

// Runs `work` on a thread of its own and waits for its result, within
// `timeout` and the stop token. Fails with std::errc::operation_not_supported
// unless the io_context of `ex` is in locking_mode::safe. Errors are without
// the bind's context (sasl_bind adds it).
auto run_offloaded(boost::corosio::io_context::executor_type ex,
  std::optional<std::chrono::milliseconds> timeout,
  sasl_work work) -> boost::capy::task<result<std::optional<std::string>>>;

}// namespace jhetz::ldap::detail
