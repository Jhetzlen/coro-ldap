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
// ldap::transaction is a thin helper over the connection's primitives
// (connection::start_transaction(), end_transaction() and the
// transaction_specification control, controls.hpp), which may be used
// directly instead. Each update it sends carries the transaction
// specification control; the server answers it at once, with success if it
// takes the update into the transaction (the update itself is deferred) or
// with the reason it refuses it, which is returned and leaves the
// transaction open: commit without it, or abort. RFC 5805 section 3.3: if
// the server gives up on the transaction it sends an Aborted Transaction
// Notice, which this library does not route (it is ignored like other
// unsolicited notifications): the next update or the commit then fails
// with the server's error.
//
// Settling: commit() and abort() end the transaction, whatever their
// outcome; afterwards its operations fail with std::errc::invalid_argument.
// A transaction destroyed while still open is aborted: an End Transaction
// (abort) is queued without waiting for its answer, which is dropped (best
// effort, as when a paged search is released: nothing is sent if the
// connection is closed or in StartTLS). An update that timed out or was
// cancelled may or may not be part of the transaction (its abandon is best
// effort): abort then, rather than commit an unknown set of updates. A
// commit whose answer is lost (connection failure, timeout, cancellation)
// has an unknown outcome: re-read the entries if it matters. RFC 5805
// section 3.5: a bind or unbind aborts every transaction of the connection
// on the server; transactions do not nest. The server may support one
// transaction per connection at a time (OpenLDAP does).
//
// Threading and lifetime: as the connection's (connection.hpp); a
// transaction keeps the connection's state alive, and must outlive the tasks
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

class [[nodiscard]] transaction
{
  public:
	// Not started: every operation fails with client_errc::not_connected.
	transaction() noexcept = default;
	transaction(transaction &&other) noexcept;
	auto operator=(transaction &&other) noexcept -> transaction &;
	transaction(const transaction &) = delete;
	auto operator=(const transaction &) -> transaction & = delete;
	// Still open: aborts it without waiting (see above).
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
	// applied, or none. A refusal is the server's result code with the
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
