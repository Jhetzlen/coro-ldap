// RFC 5805 transactions: ldap::transaction, and the two extended operations
// and the transaction_specification control it is built on (docs/API.md).
#pragma once

#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <string>
#include <string_view>

namespace jhetz::ldap {

class connection;

using commit_result = end_transaction_result;

// The raw extended operations: Start Transaction returns the identifier,
// End Transaction settles it. Updates need transaction_specification{id}.
auto start_transaction(connection &conn, extended_controls controls = {}) -> boost::capy::task<result<std::string>>;
auto end_transaction(connection &conn, std::string identifier, bool commit = true)
  -> boost::capy::task<result<end_transaction_result>>;

class transaction
{
  public:
	// Sends Start Transaction (after the answers still due) and returns the
	// started transaction.
	static auto begin(connection &conn, extended_controls controls = {}) -> boost::capy::task<result<transaction>>;

	// Not started: every operation fails with client_errc::not_connected.
	transaction() noexcept = default;
	transaction(transaction &&other) noexcept;
	auto operator=(transaction &&other) noexcept -> transaction &;
	transaction(const transaction &) = delete;
	auto operator=(const transaction &) -> transaction & = delete;
	// Still open on the server: queues an abort without waiting.
	~transaction();

	// Empty if not started.
	[[nodiscard]] auto identifier() const noexcept -> std::string_view;
	// Started and neither committed nor aborted.
	[[nodiscard]] auto is_open() const noexcept -> bool;

	// The update operations with a transaction_specification control appended.
	auto add(add_params request) -> boost::capy::task<result<update_result>>;
	auto modify(modify_params request) -> boost::capy::task<result<update_result>>;
	auto del(del_params request) -> boost::capy::task<result<update_result>>;
	auto modify_dn(modify_dn_params request) -> boost::capy::task<result<update_result>>;

	// End Transaction with commit TRUE; operation_in_progress while an update
	// awaits its answer.
	auto commit() -> boost::capy::task<result<commit_result>>;
	// End Transaction with commit FALSE.
	auto abort() -> boost::capy::task<result<void>>;

	struct state;// defined in src/connection/transaction.cpp

  private:
	friend class connection;
	explicit transaction(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;// owned; allocated from the connection's resource
};

}// namespace jhetz::ldap
