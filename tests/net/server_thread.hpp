// An in-process LDAP server on loopback TCP on its own thread, answering
// requests as they come.
#pragma once

#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <atomic>
#include <span>
#include <string>
#include <thread>
#include <variant>

namespace jhetz::ldap::test {

// Answers bind (49 for "wrong"), search (two entries), add, modify, delete,
// who am I, until the client leaves; ignores abandons.
inline auto serve_session(net::transport t, std::atomic<int> &requests) -> capy::task<void>
{
	net::read_buffer buf;
	while (true) {
		auto r = co_await net::read_message(t, buf, as_server);
		if (!r || std::holds_alternative<ldap::unbind_request>(r->op)) {
			co_return;
		}
		++requests;
		std::string out;
		if (const auto *b = std::get_if<ldap::bind_request>(&r->op)) {
			const auto *pw = std::get_if<ldap::simple_auth>(&b->authentication);
			out = bytes_of(bind_resp(r->id, pw != nullptr && pw->password == "wrong" ? 49 : 0));
		} else if (const auto *s = std::get_if<ldap::search_request>(&r->op)) {
			const std::string base(s->base_object);
			out = bytes_of(entry_msg_for(*s, r->id, "uid=x," + base, "X"))
				  + bytes_of(entry_msg_for(*s, r->id, "uid=y," + base, "Y")) + bytes_of(done_msg(r->id));
		} else if (std::holds_alternative<ldap::add_request>(r->op)) {
			out = bytes_of(ldap::message{ r->id, ldap::add_response{ ldap::ldap_result{ 0 } } });
		} else if (std::holds_alternative<ldap::modify_request>(r->op)) {
			out = bytes_of(ldap::message{ r->id, ldap::modify_response{ ldap::ldap_result{ 0 } } });
		} else if (std::holds_alternative<ldap::del_request>(r->op)) {
			out = bytes_of(ldap::message{ r->id, ldap::del_response{ ldap::ldap_result{ 0 } } });
		} else if (std::holds_alternative<ldap::modify_dn_request>(r->op)) {
			out = bytes_of(ldap::message{ r->id, ldap::modify_dn_response{ ldap::ldap_result{ 0 } } });
		} else if (std::holds_alternative<ldap::extended_request>(r->op)) {
			out = bytes_of(
			  ldap::message{ r->id, ldap::extended_response{ ldap::ldap_result{ 0 }, std::nullopt, "dn:cn=me" } });
		} else {
			continue;
		}
		if (auto w = co_await net::write_bytes(t, std::as_bytes(std::span(out))); !w) {
			co_return;
		}
	}
}

inline auto accept_loop(corosio::io_context &ioc, corosio::tcp_acceptor &acc, std::atomic<int> &requests)
  -> capy::task<void>
{
	while (true) {
		auto [ec, peer] = co_await acc.accept();
		if (ec) {
			co_return;
		}
		capy::run_async(ioc.get_executor())(serve_session(net::transport::wrap(std::move(peer), "server"), requests));
	}
}

// The server, on its own thread.
struct server_thread
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 64 };
	std::atomic<int> requests{ 0 };
	std::thread thread;

	server_thread()
	{
		capy::run_async(ioc.get_executor())(accept_loop(ioc, acc, requests));
		thread = std::thread([this] { ioc.run(); });
	}
	// The accept loop ends when the acceptor closes (on the server thread);
	// sessions end when their client hangs up. Then run() returns.
	~server_thread()
	{
		capy::run_async(ioc.get_executor())([](corosio::tcp_acceptor &a) -> capy::task<void> {
			a.close();
			co_return;
		}(acc));
		thread.join();
	}
	auto url() const -> ldap::url
	{
		return *ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
	}
};

}// namespace jhetz::ldap::test
