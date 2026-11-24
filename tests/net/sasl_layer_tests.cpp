// SASL security layers with a made-up layer: the framing on the transport,
// and sasl_bind installing the layer after the successful BindResponse.
#include "../../src/connection/referral_chase_impl.hpp"
#include "../../src/net/sasl_layer.hpp"
#include "../counting_resource.hpp"
#include "jhetz/ldap/ad/password.hpp"
#include "jhetz/ldap/connection.hpp"
#include "jhetz/ldap/net/connect.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "jhetz/ldap/repository.hpp"
#include "jhetz/ldap/sasl.hpp"
#include "jhetz/ldap/sync.hpp"
#include "jhetz/ldap/sync_repository.hpp"
#include "jhetz/ldap/testing/message_io.hpp"
#include "mock_ldap.hpp"
#include "net_test_support.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/read.hpp>
#include <boost/capy/test/stream.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
using namespace jhetz::ldap::test;
using Catch::Matchers::ContainsSubstring;

namespace {

constexpr auto marker = std::byte{ 0xa5 };
constexpr auto xor_key = std::byte{ 0x5a };

// Wraps a buffer as the marker followed by the bytes XORed with the key;
// unwrap checks the marker. Counts its calls.
class xor_layer final : public ldap::sasl_security_layer
{
  public:
	struct counts
	{
		int wraps = 0;
		int unwraps = 0;
		std::vector<std::size_t> wrapped_sizes{};
	};

	explicit xor_layer(std::size_t max_wrap_input = std::size_t{ 1 } << 20,
	  std::size_t max_received = std::size_t{ 1 } << 20,
	  std::shared_ptr<counts> c = std::make_shared<counts>(),
	  ldap::sasl_protection level = ldap::sasl_protection::integrity)
	  : max_wrap_input_(max_wrap_input), max_received_(max_received), counts_(std::move(c)), level_(level)
	{}

	[[nodiscard]] auto protection() const noexcept -> ldap::sasl_protection override { return level_; }
	[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return max_wrap_input_; }
	[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return max_received_; }
	[[nodiscard]] auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
	  -> ldap::result<void> override
	{
		++counts_->wraps;
		counts_->wrapped_sizes.push_back(plaintext.size());
		out.push_back(marker);
		for (auto b : plaintext) {
			out.push_back(b ^ xor_key);
		}
		return {};
	}
	[[nodiscard]] auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
	  -> ldap::result<void> override
	{
		++counts_->unwraps;
		if (buffer.empty() || buffer[0] != marker) {
			return ldap::fail(ldap::client_errc::decode_error, "bad marker");
		}
		out.reserve(out.size() + buffer.size() - 1);
		for (auto b : buffer.subspan(1)) {
			out.push_back(b ^ xor_key);
		}
		return {};
	}

  private:
	std::size_t max_wrap_input_;
	std::size_t max_received_;
	std::shared_ptr<counts> counts_;
	ldap::sasl_protection level_;
};

// A protected buffer of `plaintext` as xor_layer writes it, after its length.
auto frame(std::string_view plaintext) -> std::string
{
	const std::size_t n = plaintext.size() + 1;
	std::string out{
		static_cast<char>(n >> 24), static_cast<char>(n >> 16), static_cast<char>(n >> 8), static_cast<char>(n)
	};
	out += static_cast<char>(marker);
	for (char c : plaintext) {
		out += static_cast<char>(static_cast<std::byte>(c) ^ xor_key);
	}
	return out;
}

auto as_bytes(const std::string &s) -> std::span<const std::byte> { return std::as_bytes(std::span(s)); }

// A one-step mechanism whose exchange negotiates an xor_layer.
class layer_mechanism final : public ldap::sasl_mechanism
{
  public:
	std::size_t max_wrap_input = std::size_t{ 1 } << 20;
	std::shared_ptr<xor_layer::counts> counts = std::make_shared<xor_layer::counts>();
	bool negotiates = true;
	bool endless = false;// every step answers and negotiates a layer
	ldap::sasl_protection level = ldap::sasl_protection::integrity;

	[[nodiscard]] auto name() const noexcept -> std::string_view override { return "X-LAYER"; }
	auto start() -> ldap::result<std::optional<std::string>> override
	{
		pending = negotiates;
		return std::optional<std::string>("hi");
	}
	auto step(std::optional<std::string_view>) -> ldap::result<std::optional<std::string>> override
	{
		if (!endless) {
			return ldap::fail(ldap::client_errc::unexpected_response, "one step");
		}
		pending = negotiates;
		return std::optional<std::string>("more");
	}
	auto take_security_layer() -> std::unique_ptr<ldap::sasl_security_layer> override
	{
		if (!std::exchange(pending, false)) {
			return nullptr;
		}
		return std::make_unique<xor_layer>(max_wrap_input, std::size_t{ 1 } << 20, counts, level);
	}
	[[nodiscard]] auto channel_binding_used() const noexcept -> std::optional<ldap::channel_binding_type> override
	{
		return std::nullopt;
	}

	bool pending = false;// start() ran: the next take_security_layer() gives one
};

auto sasl_ok(std::int32_t id) -> ldap::message
{
	return ldap::message{ id, ldap::bind_response{ ldap::ldap_result{ 0 } } };
}

// Two transports over a socket pair, the client's with an xor_layer.
struct layered_pair
{
	corosio::io_context ioc{};
	socket_pair sockets{ ioc };
	net::transport client = net::transport::wrap(socket_ref{ &sockets.client }, "client");
	net::transport server = net::transport::wrap(socket_ref{ &sockets.server }, "server");
	net::read_buffer client_buf{};
	net::read_buffer server_buf{};
	std::shared_ptr<xor_layer::counts> counts = std::make_shared<xor_layer::counts>();

	explicit layered_pair(std::size_t max_wrap_input = 1 << 20, std::size_t max_received = 1 << 20)
	{
		auto r = net::detail::install_security_layer(
		  client, client_buf, std::make_unique<xor_layer>(max_wrap_input, max_received, counts));
		REQUIRE(r.has_value());
	}
	layered_pair(const layered_pair &) = delete;
	auto operator=(const layered_pair &) -> layered_pair & = delete;
	~layered_pair()
	{
		sockets.client.close();
		sockets.server.close();
		drive(ioc);
	}

	// Reads exactly `n` raw bytes on the server's end.
	auto read_raw(std::size_t n) -> std::string
	{
		return finish(ioc, [](net::transport &t, std::size_t want) -> capy::task<std::string> {
			std::string out(want, '\0');
			auto [ec, k] = co_await capy::read(t.stream(), capy::mutable_buffer(out.data(), out.size()));
			if (ec) {
				throw std::system_error(ec, "server read");
			}
			out.resize(k);
			co_return out;
		}(server, n));
	}
	void write_raw(const std::string &bytes)
	{
		auto w = finish(ioc, net::write_bytes(server, as_bytes(bytes)));
		REQUIRE(w.has_value());
	}
};

}// namespace

TEST_CASE("sasl layer: outgoing PDUs are wrapped and framed", "[net][sasl][sasl_layer]")
{
	const auto pdu = bytes_of(bind_request_msg(1));
	REQUIRE(pdu.size() > 25);

	SECTION("one buffer when the PDU fits")
	{
		layered_pair p;
		REQUIRE(finish(p.ioc, net::write_bytes(p.client, as_bytes(pdu))).has_value());
		CHECK(p.read_raw(pdu.size() + 5) == frame(pdu));
		CHECK(p.counts->wraps == 1);
		CHECK(p.client.security_layer() == ldap::sasl_protection::integrity);
	}
	SECTION("cut to the peer's maximum")
	{
		layered_pair p(10);
		REQUIRE(finish(p.ioc, net::write_bytes(p.client, as_bytes(pdu))).has_value());
		std::string expected;
		for (std::size_t at = 0; at < pdu.size(); at += 10) {
			expected += frame(std::string_view(pdu).substr(at, 10));
		}
		CHECK(p.read_raw(expected.size()) == expected);
		CHECK(std::cmp_equal(p.counts->wraps, (pdu.size() + 9) / 10));
		for (auto n : p.counts->wrapped_sizes) {
			CHECK(n <= 10);
		}
	}
	SECTION("a layer that takes no plaintext fails the write instead of looping")
	{
		layered_pair p(0);
		auto w = finish(p.ioc, net::write_bytes(p.client, as_bytes(pdu)));
		REQUIRE_FALSE(w.has_value());
		CHECK(w.error().code == ldap::client_errc::encode_error);
		CHECK(std::string(w.error().context)
			  == "write client: SASL security layer: the layer takes no plaintext (max_wrap_input() is 0)");
		CHECK(p.counts->wraps == 0);
	}
}

TEST_CASE("sasl layer: incoming buffers are unwrapped", "[net][sasl][sasl_layer]")
{
	const auto one = bytes_of(bind_response_msg(1, "first"));
	const auto two = bytes_of(bind_response_msg(2, "second"));

	SECTION("two PDUs in one buffer")
	{
		layered_pair p;
		p.write_raw(frame(one + two));
		CHECK(finish(p.ioc, net::read_message(p.client, p.client_buf)) == bind_response_msg(1, "first"));
		CHECK(finish(p.ioc, net::read_message(p.client, p.client_buf)) == bind_response_msg(2, "second"));
		CHECK(p.counts->unwraps == 1);
	}
	SECTION("one PDU over several buffers, an empty one among them, written a byte at a time")
	{
		layered_pair p;
		const std::string wire = frame(one.substr(0, 3)) + frame("") + frame(one.substr(3));
		outcome<ldap::result<ldap::message>> read;
		spawn(p.ioc, net::read_message(p.client, p.client_buf), read);
		for (char c : wire) {
			p.write_raw(std::string(1, c));
		}
		drive_until(p.ioc, [&read] { return read.done(); });
		CHECK(read.get() == bind_response_msg(1, "first"));
		CHECK(p.counts->unwraps == 3);
	}
	SECTION("bytes read before the layer took effect are its start")
	{
		corosio::io_context ioc;
		socket_pair sockets(ioc);
		auto client = net::transport::wrap(socket_ref{ &sockets.client }, "client");
		net::read_buffer buf;
		const std::string first = frame(one);
		const std::string bytes = first.substr(0, 7);
		std::span<std::byte> space = buf.prepare(bytes.size());
		std::ranges::copy(as_bytes(bytes), space.begin());
		buf.commit(bytes.size());
		REQUIRE(net::detail::install_security_layer(client, buf, std::make_unique<xor_layer>()).has_value());
		CHECK(buf.empty());
		auto server = net::transport::wrap(socket_ref{ &sockets.server }, "server");
		REQUIRE(finish(ioc, net::write_bytes(server, as_bytes(first.substr(7)))).has_value());
		CHECK(finish(ioc, net::read_message(client, buf)) == bind_response_msg(1, "first"));
		// A second layer is refused.
		auto again = net::detail::install_security_layer(client, buf, std::make_unique<xor_layer>());
		REQUIRE_FALSE(again.has_value());
		CHECK(again.error().code == ldap::client_errc::security_layer_in_effect);
		sockets.client.close();
		sockets.server.close();
		drive(ioc);
	}
}

TEST_CASE("sasl layer: a big buffer read in small pieces grows the read buffer once", "[net][sasl][sasl_layer]")
{
	// TCP-sized reads of a 64 KiB buffer: the read buffer grows once.
	corosio::io_context ioc;
	ldap::test::counting_resource counting;
	auto [a, b] = capy::test::make_stream_pair();
	constexpr std::size_t segment = 1448;
	a.set_max_read_size(segment);
	auto client = net::transport::wrap(std::move(a), "client", &counting);
	net::read_buffer buf;
	REQUIRE(net::detail::install_security_layer(client, buf, std::make_unique<xor_layer>()).has_value());
	const std::string plaintext(std::size_t{ 64 } * 1024, 'p');
	b.provide(frame(plaintext));

	const auto allocations = counting.allocations();
	const auto bytes = counting.bytes();
	auto got = run_task(ioc, [](net::transport &t, std::size_t want) -> capy::task<std::string> {
		std::string out(want, '\0');
		auto [ec, n] = co_await capy::read(t.stream(), capy::mutable_buffer(out.data(), out.size()));
		if (ec) {
			throw std::system_error(ec, "read");
		}
		out.resize(n);
		co_return out;
	}(client, plaintext.size()));
	CHECK(got == plaintext);
	// The read buffer's first 16 KiB, its one growth, the plaintext.
	CHECK(counting.allocations() - allocations <= 3);
	CHECK(counting.bytes() - bytes < 2 * (plaintext.size() + net::read_buffer::min_read));
}

TEST_CASE("sasl layer: a cancelled read keeps the partial buffer", "[net][sasl][sasl_layer]")
{
	// A whole buffer and half of the next arrive before the reader stops, the
	// rest after.
	const auto pdu = bytes_of(bind_response_msg(1, "first"));
	const std::string second = frame(std::string_view(pdu).substr(3));
	const std::size_t half = second.size() / 2;
	layered_pair p;
	std::stop_source stop;
	outcome<ldap::result<ldap::message>> cancelled;
	spawn(p.ioc, stop.get_token(), net::read_message(p.client, p.client_buf), cancelled);
	p.write_raw(frame(std::string_view(pdu).substr(0, 3)) + second.substr(0, half));
	while (p.ioc.poll() != 0) {}// the reader parks inside the second buffer
	p.ioc.restart();
	CHECK(p.counts->unwraps == 1);
	stop.request_stop();
	drive_until(p.ioc, [&cancelled] { return cancelled.done(); });
	REQUIRE_FALSE(cancelled.get().has_value());
	CHECK(cancelled.get().error().code == capy::cond::canceled);
	p.write_raw(second.substr(half));
	CHECK(finish(p.ioc, net::read_message(p.client, p.client_buf)) == bind_response_msg(1, "first"));
	CHECK(p.counts->unwraps == 2);
}

TEST_CASE("sasl layer: a write failure keeps its own context", "[net][sasl][sasl_layer]")
{
	// A read's layer error does not annotate a later write failure; a cut
	// buffer counts no plaintext.
	layered_pair p(1 << 20, 100);
	p.write_raw(std::string("\x00\x00\x00\x65", 4));
	auto r = finish(p.ioc, net::read_message(p.client, p.client_buf));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::message_too_large);

#ifdef _WIN32
	// 64 buffers fill the pair; the failure falls between two of them.
	const std::string big(std::size_t{ 1 } << 26, 'x');
#else
	const std::string big(std::size_t{ 1 } << 20, 'x');
#endif
	outcome<ldap::result<void>> write;
	spawn(p.ioc, net::write_bytes(p.client, as_bytes(big)), write);
	while (p.ioc.poll() != 0) {}// the writer parks on a full socket
	p.ioc.restart();
	REQUIRE_FALSE(write.done());
	CHECK(p.read_raw(16).size() == 16);
	p.sockets.server.close();
	drive_until(p.ioc, [&write] { return write.done(); });
	REQUIRE_FALSE(write.get().has_value());
	const std::string context(write.get().error().context);
	CHECK_THAT(context, !ContainsSubstring("accepted"));
#ifdef _WIN32
	CHECK_THAT(context, Catch::Matchers::StartsWith("write client ("));
	CHECK_THAT(context, Catch::Matchers::EndsWith(" of 67108864 bytes written)"));
#else
	CHECK_THAT(
	  context, Catch::Matchers::StartsWith("write client: SASL security layer: a protected buffer cut after "));
	CHECK_THAT(context, ContainsSubstring(" of its 1048581 octets"));
#endif
}

TEST_CASE("sasl layer: an oversized or broken buffer fails the read", "[net][sasl][sasl_layer]")
{
	SECTION("a length above the maximum, refused before its body")
	{
		layered_pair p(1 << 20, 100);
		p.write_raw(std::string("\x00\x00\x00\x65", 4));// 101, and no body
		auto r = finish(p.ioc, net::read_message(p.client, p.client_buf));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::message_too_large);
		CHECK(std::string(r.error().context)
			  == "read client: SASL security layer: a protected buffer of 101 bytes, more than the 100 accepted");
		CHECK(p.counts->unwraps == 0);
	}
	SECTION("the maximum itself is accepted")
	{
		layered_pair p(1 << 20, 100);
		const auto pdu = bytes_of(bind_response_msg(1, std::string(70, 'x')));
		const auto wire = frame(pdu);
		REQUIRE(wire.size() - 4 <= 100);
		p.write_raw(wire);
		CHECK(finish(p.ioc, net::read_message(p.client, p.client_buf)).has_value());
	}
	SECTION("a buffer the layer refuses")
	{
		layered_pair p;
		p.write_raw(std::string("\x00\x00\x00\x02\x01\x02", 6));
		auto r = finish(p.ioc, net::read_message(p.client, p.client_buf));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::decode_error);
		CHECK(std::string(r.error().context) == "read client: SASL security layer: bad marker");
	}
	SECTION("the connection closed inside a buffer")
	{
		layered_pair p;
		p.write_raw(frame("abc").substr(0, 5));
		p.sockets.server.close();
		auto r = finish(p.ioc, net::read_message(p.client, p.client_buf));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::eof);
	}
}

namespace {

// A layer whose wrap always fails.
class refusing_layer final : public ldap::sasl_security_layer
{
  public:
	[[nodiscard]] auto protection() const noexcept -> ldap::sasl_protection override
	{
		return ldap::sasl_protection::integrity;
	}
	[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return 1024; }
	[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return 1024; }
	[[nodiscard]] auto wrap(std::span<const std::byte>, std::pmr::vector<std::byte> &) -> ldap::result<void> override
	{
		return ldap::fail(ldap::client_errc::encode_error, "wrap refused");
	}
	[[nodiscard]] auto unwrap(std::span<const std::byte>, std::pmr::vector<std::byte> &) -> ldap::result<void> override
	{
		return ldap::fail(ldap::client_errc::decode_error, "unwrap refused");
	}
};

auto accept_and_close(corosio::tcp_acceptor &acc) -> capy::task<void>
{
	auto [ec, peer] = co_await acc.accept();
	peer.close();
}

}// namespace

TEST_CASE("sasl layer: a buffer the layer cannot wrap fails the write", "[net][sasl][sasl_layer]")
{
	corosio::io_context ioc;
	socket_pair sockets(ioc);
	auto client = net::transport::wrap(socket_ref{ &sockets.client }, "client");
	net::read_buffer buf;
	REQUIRE(net::detail::install_security_layer(client, buf, std::make_unique<refusing_layer>()).has_value());
	auto w = finish(ioc, net::write_bytes(client, as_bytes(std::string("abc"))));
	REQUIRE_FALSE(w.has_value());
	CHECK(w.error().code == ldap::client_errc::encode_error);
	CHECK(std::string(w.error().context) == "write client: SASL security layer: wrap refused");
	CHECK(net::detail::security_layer_write_error(client) == "SASL security layer: wrap refused");
	sockets.client.close();
	sockets.server.close();
	drive(ioc);
}

TEST_CASE("sasl layer: no layer errors on an empty transport", "[net][sasl][sasl_layer]")
{
	const net::transport none;
	CHECK(net::detail::security_layer_read_error(none).empty());
	CHECK(net::detail::security_layer_write_error(none).empty());
}

TEST_CASE("sasl layer: net::start_tls is refused over a layer", "[net][sasl][sasl_layer][starttls]")
{
	corosio::io_context ioc;
	corosio::tcp_acceptor acc(ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1);
	outcome<void> server;
	spawn(ioc, accept_and_close(acc), server);
	auto u = ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
	REQUIRE(u.has_value());
	auto t = finish(ioc, net::connect(ioc, *u));
	REQUIRE(t.has_value());
	net::read_buffer buf;
	REQUIRE(net::detail::install_security_layer(*t, buf, std::make_unique<xor_layer>()).has_value());
	auto r = finish(ioc, net::start_tls(*t, buf, {}));
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == ldap::client_errc::security_layer_in_effect);
	CHECK_THAT(std::string(r.error().context),
	  Catch::Matchers::StartsWith("start tls ldap://127.0.0.1:")
		&& ContainsSubstring(": a SASL security layer is in effect"));
	CHECK(t->is_open());
	t->close();
	drive(ioc);
}

namespace {

// The server's side of a bind installing the xor_layer: answers it (with
// `extra` in the same write), installs the layer, answers one search.
auto serve_layered_bind(net::transport t, std::string extra, std::string &error) -> capy::task<void>
{
	net::read_buffer buf;
	auto bind = co_await ldap::testing::read_message(t, buf, as_server);
	if (!bind) {
		error = "bind read: " + std::string(bind.error().message());
		co_return;
	}
	const std::string reply = bytes_of(sasl_ok(bind->id)) + extra;
	if (auto w = co_await net::write_bytes(t, as_bytes(reply)); !w) {
		error = "bind write";
		co_return;
	}
	if (auto l = net::detail::install_security_layer(t, buf, std::make_unique<xor_layer>()); !l) {
		error = "install";
		co_return;
	}
	auto search = co_await ldap::testing::read_message(t, buf, as_server);
	if (!search) {
		error = "search read: " + std::string(search.error().message());
		co_return;
	}
	for (const auto &m : { entry_msg(search->id, "uid=jdoe,ou=people,dc=example,dc=org", "J"), done_msg(search->id) }) {
		if (auto w = co_await net::write_message(t, m); !w) {
			error = "search write";
			co_return;
		}
	}
}

}// namespace

TEST_CASE("sasl layer: sasl_bind installs the negotiated layer", "[net][sasl][sasl_layer]")
{
	mock_ldap m;
	std::string error;
	layer_mechanism mech;

	SECTION("after the success, for every later PDU; a search held behind the bind goes wrapped")
	{
		// An unsolicited extended response (ignored) right behind the
		// BindResponse, wrapped: the first octet after it is protected.
		const auto notice = bytes_of(ldap::message{ 0, ldap::extended_response{ ldap::ldap_result{ 0 }, "1.2.3.4" } });
		outcome<void> server;
		spawn(m.ioc, serve_layered_bind(m.server_end(), frame(notice), error), server);
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
		outcome<ldap::result<void>> bind;
		spawn(m.ioc, m.conn.sasl_bind(mech), bind);
		outcome<ldap::result<ldap::search_result>> search;
		spawn(m.ioc, m.conn.search(people_search()), search);
		drive_until(m.ioc, [&] { return server.done() && search.done(); });
		REQUIRE(bind.get().has_value());
		REQUIRE(search.get().has_value());
		CHECK(search.get()->entries.size() == 1);
		CHECK(error.empty());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::integrity);
		CHECK(mech.counts->wraps >= 1);// the search
		CHECK(mech.counts->unwraps >= 2);// the notice, the entry and done

		// StartTLS would have to go below the layer.
		auto tls = finish(m.ioc, m.conn.start_tls());
		REQUIRE_FALSE(tls.has_value());
		CHECK(tls.error().code == ldap::client_errc::security_layer_in_effect);
		CHECK_THAT(std::string(tls.error().context), ContainsSubstring("RFC 4513 section 5.2.1.6"));
		// A second layer is refused before anything is sent.
		layer_mechanism second;
		auto again = finish(m.ioc, m.conn.sasl_bind(second));
		REQUIRE_FALSE(again.has_value());
		CHECK(again.error().code == ldap::client_errc::security_layer_in_effect);
		CHECK(m.conn.is_open());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::integrity);
	}
	SECTION("a refused bind installs nothing")
	{
		m.serve({ answer({ bind_resp(1, 49) }), answer({ done_msg(2) }) });
		auto r = finish(m.ioc, m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::errc::invalid_credentials);
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
		// The next PDUs go unprotected: the scripted server reads them as is.
		CHECK(finish(m.ioc, m.conn.search(people_search())).has_value());
		m.check_server();
		CHECK(mech.counts->wraps == 0);
	}
	SECTION("an exchange given up after the last step installs nothing")
	{
		// The 33rd credentials are never sent: the aborting anonymous bind
		// succeeds, the connection stays unprotected.
		mech.endless = true;
		std::vector<step> script;
		constexpr std::int32_t steps = 32;
		for (std::int32_t id = 1; id <= steps; ++id) {
			script.push_back(answer({ bind_resp(id, 14) }));
		}
		script.push_back(answer({ bind_resp(steps + 1) }));
		script.push_back(answer({ done_msg(steps + 2) }));
		m.serve(std::move(script));
		auto r = finish(m.ioc, m.conn.sasl_bind(mech));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::unexpected_response);
		CHECK_THAT(std::string(r.error().context), ContainsSubstring("still in progress after 32 steps"));
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
		CHECK(finish(m.ioc, m.conn.search(people_search())).has_value());
		m.check_server();
		CHECK(mech.counts->wraps == 0);
	}
	SECTION("a mechanism that negotiates no layer installs nothing")
	{
		mech.negotiates = false;
		m.serve({ answer({ sasl_ok(1) }), answer({ done_msg(2) }) });
		REQUIRE(finish(m.ioc, m.conn.sasl_bind(mech)).has_value());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::none);
		CHECK(finish(m.ioc, m.conn.search(people_search())).has_value());
		m.check_server();
	}
	SECTION("an outgoing PDU larger than the server's maximum goes in several buffers")
	{
		mech.max_wrap_input = 16;
		outcome<void> server;
		spawn(m.ioc, serve_layered_bind(m.server_end(), "", error), server);
		REQUIRE(finish(m.ioc, m.conn.sasl_bind(mech)).has_value());
		auto s = finish(m.ioc, m.conn.search(people_search()));
		REQUIRE(s.has_value());
		CHECK(error.empty());
		CHECK(mech.counts->wraps > 1);
		for (auto n : mech.counts->wrapped_sizes) {
			CHECK(n <= 16);
		}
		drive_until(m.ioc, [&] { return server.done(); });
	}
}

namespace {

// A SASL bind answered with success, then the layer `level`; with
// `modify`, a ModifyRequest read and answered through it.
auto serve_layered_modify(net::transport t,
  ldap::sasl_protection level,
  bool modify,
  std::vector<ldap::message> &received,
  std::string &error) -> capy::task<void>
{
	net::read_buffer buf;
	auto bind = co_await ldap::testing::read_message(t, buf, as_server);
	if (!bind) {
		error = "bind read: " + std::string(bind.error().message());
		co_return;
	}
	if (auto w = co_await net::write_message(t, sasl_ok(bind->id)); !w) {
		error = "bind write";
		co_return;
	}
	if (auto l = net::detail::install_security_layer(t,
		  buf,
		  std::make_unique<xor_layer>(
			std::size_t{ 1 } << 20, std::size_t{ 1 } << 20, std::make_shared<xor_layer::counts>(), level));
	  !l) {
		error = "install";
		co_return;
	}
	if (!modify) {
		co_return;
	}
	auto request = co_await ldap::testing::read_message(t, buf, as_server);
	if (!request) {
		error = "modify read: " + std::string(request.error().message());
		co_return;
	}
	received.push_back(*request);
	if (auto w =
		  co_await net::write_message(t, ldap::message{ request->id, ldap::modify_response{ ldap::ldap_result{ 0 } } });
	  !w) {
		error = "modify write";
	}
}

}// namespace

TEST_CASE("sasl layer: an Active Directory password change needs confidentiality", "[net][sasl][sasl_layer][ad]")
{
	const ldap::dn jdoe{ "uid=jdoe,ou=people,dc=example,dc=org" };
	mock_ldap m;
	std::string error;
	std::vector<ldap::message> received;
	layer_mechanism mech;
	SECTION("confidentiality: sent through the layer")
	{
		mech.level = ldap::sasl_protection::confidentiality;
		outcome<void> server;
		spawn(m.ioc, serve_layered_modify(m.server_end(), mech.level, true, received, error), server);
		REQUIRE(finish(m.ioc, m.conn.sasl_bind(mech)).has_value());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::confidentiality);
		CHECK_FALSE(m.conn.is_tls());
		CHECK(ldap::detail::origin_protected(m.conn));
		auto r = finish(m.ioc, ldap::ad::reset_password(m.conn, jdoe, "New-S3cret"));
		CHECK(r.has_value());
		drive_until(m.ioc, [&] { return server.done(); });
		CHECK(error.empty());
		REQUIRE(received.size() == 1);
		CHECK(std::holds_alternative<ldap::modify_request>(received[0].op));
		CHECK(mech.counts->wraps >= 1);
	}
	SECTION("integrity only: refused before sending")
	{
		outcome<void> server;
		spawn(m.ioc, serve_layered_modify(m.server_end(), mech.level, false, received, error), server);
		REQUIRE(finish(m.ioc, m.conn.sasl_bind(mech)).has_value());
		CHECK(m.conn.security_layer() == ldap::sasl_protection::integrity);
		CHECK_FALSE(ldap::detail::origin_protected(m.conn));
		drive_until(m.ioc, [&] { return server.done(); });
		auto r = finish(m.ioc, ldap::ad::change_password(m.conn, jdoe, "Old-S3cret", "New-S3cret"));
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == ldap::client_errc::tls_required);
		CHECK(mech.counts->wraps == 0);
		CHECK(error.empty());
		CHECK(m.conn.is_open());
	}
}

namespace {

struct card
{
	std::string cn;
};

}// namespace

template<>
constexpr auto ldap::schema<card> = ldap::describe(ldap::object_class("person"), ldap::field<&card::cn>("cn"));

namespace {

// Answers a layered SASL bind and searches, logging each request ("layer "
// for those read through the layer) until the client hangs up.
auto serve_schema_and_layer(net::transport t, std::vector<std::string> &log, std::string &error) -> capy::task<void>
{
	net::read_buffer buf;
	std::string prefix;
	while (true) {
		auto req = co_await ldap::testing::read_message(t, buf, as_server);
		if (!req || std::holds_alternative<ldap::unbind_request>(req->op)) {
			co_return;
		}
		if (std::holds_alternative<ldap::bind_request>(req->op)) {
			log.push_back(prefix + "bind");
			if (auto w = co_await net::write_message(t, sasl_ok(req->id)); !w) {
				error = "bind write";
				co_return;
			}
			if (auto l = net::detail::install_security_layer(t, buf, std::make_unique<xor_layer>()); !l) {
				error = "install";
				co_return;
			}
			prefix = "layer ";
			continue;
		}
		const auto *search = std::get_if<ldap::search_request>(&req->op);
		if (search == nullptr) {
			error = "unexpected request";
			co_return;
		}
		ldap::message found{ req->id, ldap::search_result_entry{} };
		if (search->base_object.empty()) {
			log.push_back(prefix + "root DSE");
			found.op = ldap::search_result_entry{ "", { { "subschemaSubentry", { "cn=Subschema" } } } };
		} else if (search->base_object == "cn=Subschema") {
			log.push_back(prefix + "subschema");
			found.op = ldap::search_result_entry{ "cn=Subschema",
				{ { "attributeTypes", { "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )" } },
				  { "objectClasses", { "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )" } } } };
		} else {
			log.push_back(prefix + "search");
			found = entry_msg_for(*search, req->id, "cn=a,dc=example,dc=org", "a");
		}
		for (const auto &m : { found, done_msg(req->id) }) {
			if (auto w = co_await net::write_message(t, m); !w) {
				error = "search write";
				co_return;
			}
		}
	}
}

const std::vector<std::string>
  checked_twice{ "root DSE", "subschema", "search", "bind", "layer root DSE", "layer subschema", "layer search" };

// serve_schema_and_layer for one TCP client, on its own thread.
struct layer_server_thread
{
	corosio::io_context ioc{};
	corosio::tcp_acceptor acc{ ioc, corosio::endpoint(corosio::ipv4_address::loopback(), 0), 1 };
	std::vector<std::string> log{};
	std::string error{};
	std::thread thread{};

	layer_server_thread()
	{
		capy::run_async(ioc.get_executor())([](layer_server_thread &s) -> capy::task<void> {
			auto [ec, peer] = co_await s.acc.accept();
			s.acc.close();
			if (!ec) {
				co_await serve_schema_and_layer(net::transport::wrap(std::move(peer), "server"), s.log, s.error);
			}
		}(*this));
		thread = std::thread([this] { ioc.run(); });
	}
	layer_server_thread(const layer_server_thread &) = delete;
	auto operator=(const layer_server_thread &) -> layer_server_thread & = delete;
	~layer_server_thread() { join(); }

	auto url() const -> ldap::url
	{
		return *ldap::url::parse("ldap://127.0.0.1:" + std::to_string(acc.local_endpoint().port()));
	}
	// Once the client hung up: the server's thread ends.
	void join()
	{
		if (thread.joinable()) {
			thread.join();
		}
	}
};

}// namespace

TEST_CASE("RFC 4513 5.2.1.6: a repository's schema check is made again after a SASL security layer",
  "[net][sasl][sasl_layer][rfc][schema][repository]")
{
	SECTION("ldap::repository on an ldap::connection")
	{
		mock_ldap m;
		std::vector<std::string> log;
		std::string error;
		outcome<void> server;
		spawn(m.ioc, serve_schema_and_layer(m.server_end(), log, error), server);
		ldap::repository cards(m.conn,
		  ldap::dn{ "dc=example,dc=org" },
		  ldap::named_by<&card::cn>,
		  { .schema_check = ldap::schema_check::on_first_use });
		REQUIRE(m.run(cards.search()).has_value());
		layer_mechanism mech;
		REQUIRE(m.run(m.conn.sasl_bind(mech)).has_value());
		REQUIRE(m.conn.security_layer() == ldap::sasl_protection::integrity);
		auto r = m.run(cards.search());
		REQUIRE(r.has_value());
		CHECK(r->entries.size() == 1);
		CHECK(m.run(m.conn.unbind()).has_value());
		drive_until(m.ioc, [&server] { return server.done(); });
		CHECK(error.empty());
		CHECK(log == checked_twice);
	}
	SECTION("ldap::repository on a sync::connection")
	{
		layer_server_thread srv;
		{
			auto opened = ldap::sync::connect(srv.url(), { .timeout = std::chrono::seconds(10) });
			REQUIRE(opened.has_value());
			auto &c = *opened;
			ldap::repository cards(c,
			  ldap::dn{ "dc=example,dc=org" },
			  ldap::named_by<&card::cn>,
			  { .schema_check = ldap::schema_check::on_first_use });
			REQUIRE(cards.search().has_value());
			layer_mechanism mech;
			REQUIRE(c.sasl_bind(mech).has_value());
			REQUIRE(c.security_layer() == ldap::sasl_protection::integrity);
			auto r = cards.get("a");
			REQUIRE(r.has_value());
			CHECK(r->has_value());
		}
		srv.join();
		CHECK(srv.error.empty());
		CHECK(srv.log == checked_twice);
	}
}
