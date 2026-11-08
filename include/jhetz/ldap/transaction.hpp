// LDAP transactions (RFC 5805): a group of updates applied all together or
// not at all. Part of jhetz::ldap_net.
//
//   auto t = co_await conn.begin_transaction();         // Start Transaction
//   if (!t) ...                                          // e.g. not supported
//   auto a = co_await t->add({.entry = jdoe, .attributes = ...,
//                             .controls = {ldap::post_read{.attributes = {"entryUUID"}}}});
//   auto m = co_await t->modify({.object = group, .changes = {ldap::mod::add("member", {jdoe_text})}});
//   if (!a || !m) { co_await t->abort(); ... }
//   auto done = co_await t->commit();                     // End Transaction (commit)
//   if (!done) ...                                        // nothing applied; the context names the update
//   if (const auto *c = done->find_update_controls(a->message_id)) ldap::find_post_read(*c);
//
// ldap::transaction is a thin helper over connection::start_transaction(),
// end_transaction() and the transaction_specification control
// (controls.hpp). The server answers each update at once: success if it took
// it into the transaction (deferred), else the refusal, which leaves the
// transaction open (commit without it, or abort). An Aborted Transaction
// Notice (RFC 5805 section 3.3) is ignored; the next update or the commit
// then fails with the server's error.
//
// Settling: commit() and abort() end the transaction whatever their outcome;
// afterwards its operations fail with std::errc::invalid_argument. Await
// every update first: with one in flight, commit() fails with
// client_errc::operation_in_progress and the transaction stays open. A
// transaction destroyed while the server may hold it (open, or a commit() or
// abort() left unanswered) queues an abort without waiting, best effort
// (nothing is sent on a closed connection or during StartTLS). An update
// that timed out or was cancelled may or may not be in the transaction:
// abort then. A commit whose answer is lost has an unknown outcome. A bind
// or unbind aborts every transaction of the connection (RFC 5805 section
// 3.5); transactions do not nest; the server may allow one per connection
// (OpenLDAP does).
//
// Threading and lifetime: as the connection's (connection.hpp); a
// transaction keeps the connection's state alive and must outlive the tasks
// of its own operations. Move-only.
#pragma once

#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/operations.hpp"

#include <boost/capy/task.hpp>

#include <string_view>

namespace jhetz::ldap {

class connection;

// What transaction::commit() returns: the updates' response controls, found
// by their response::message_id.
using commit_result = end_transaction_result;

// Not [[nodiscard]] as a class: begin_transaction() returns it inside a
// result, which is [[nodiscard]] on its own.
class transaction
{
  public:
	// Not started: every operation fails with client_errc::not_connected.
	transaction() noexcept = default;
	transaction(transaction &&other) noexcept;
	auto operator=(transaction &&other) noexcept -> transaction &;
	transaction(const transaction &) = delete;
	auto operator=(const transaction &) -> transaction & = delete;
	// Not ended on the server (see above): aborts it without waiting.
	~transaction();

	// The transaction identifier the server returned; empty if not started.
	[[nodiscard]] auto identifier() const noexcept -> std::string_view;
	// Started and neither committed nor aborted.
	[[nodiscard]] auto is_open() const noexcept -> bool;

	// The connection's update operations with a transaction_specification
	// control appended to `request.controls` (which must not carry one:
	// encode_error), as part of this transaction. A request that also
	// carries proxied_authorization fails with encode_error before anything
	// is sent (RFC 5805 section 4.4: put it on begin_transaction()). Success
	// means the server took the update into the transaction; its response
	// controls come with commit(). Errors as connection::add() and the others.
	auto add(add_params request) -> boost::capy::task<result<response>>;
	auto modify(modify_params request) -> boost::capy::task<result<response>>;
	auto del(del_params request) -> boost::capy::task<result<response>>;
	auto modify_dn(modify_dn_params request) -> boost::capy::task<result<response>>;

	// End Transaction with commit TRUE: every update the server took is
	// applied, or none. Fails with client_errc::operation_in_progress,
	// sending nothing and leaving the transaction open, while an update of
	// this transaction is still awaiting its answer. A refusal is the server's result code with the
	// context "commit transaction", followed when the server names the
	// update at fault (txnEndRes.messageID) by ": update message N (add
	// uid=jdoe,...)", the operation this transaction sent with that id.
	auto commit() -> boost::capy::task<result<commit_result>>;
	// End Transaction with commit FALSE: the server drops the updates.
	auto abort() -> boost::capy::task<result<void>>;

	struct state;// defined in src/connection/transaction.cpp

  private:
	friend class connection;
	explicit transaction(state *s) noexcept : state_(s) {}

	state *state_ = nullptr;// owned; allocated from the connection's resource
};

}// namespace jhetz::ldap
