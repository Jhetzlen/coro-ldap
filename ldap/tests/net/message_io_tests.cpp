// read_message / write_message against Capy's in-memory test streams.
#include "../counting_resource.hpp"
#include "jhetz/ldap/net/message_io.hpp"
#include "net_test_support.hpp"

#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/test/stream.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <limits>
#include <memory>
#include <memory_resource>
#include <string>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
namespace net = jhetz::ldap::net;
namespace capy = boost::capy;
namespace corosio = boost::corosio;
using namespace jhetz::ldap::test;
using ldap::client_errc;

namespace {

// Forwards to a capy::test::stream and records the buffer size of every
// read_some, to check that reads are large and counted.
struct recording_stream
{
	capy::test::stream inner;
	std::shared_ptr<std::vector<std::size_t>> reads;

	template<capy::MutableBufferSequence MB> auto read_some(MB buffers)
	{
		reads->push_back(capy::buffer_size(buffers));
		return inner.read_some(buffers);
	}
	template<capy::ConstBufferSequence CB> auto write_some(CB buffers) { return inner.write_some(buffers); }
};

// A client transport over one end of a stream pair; `peer` is the server end
// (peer.provide() makes bytes readable by the client, peer.close() ends them).
struct mock
{
	corosio::io_context ioc{};
	net::transport client{};
	std::optional<capy::test::stream> peer{};
	std::shared_ptr<std::vector<std::size_t>> reads = std::make_shared<std::vector<std::size_t>>();
	net::read_buffer buf;

	explicit mock(std::size_t max_read = std::numeric_limits<std::size_t>::max(),
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource())
	  : buf(mr)
	{
		auto [a, b] = capy::test::make_stream_pair();
		a.set_max_read_size(max_read);
		client = net::transport::wrap(recording_stream{ std::move(a), reads }, "mock");
		peer.emplace(std::move(b));
	}

	ldap::result<ldap::message> read(net::read_options options = {})
	{
		return run(ioc, net::read_message(client, buf, options));
	}
};

}// namespace

TEST_CASE("read_message: one PDU per read", "[net][read_message]")
{
	mock m;
	m.peer->provide(bytes_of(bind_response_msg(1, "hello")));
	auto r = m.read();
	REQUIRE(r.has_value());
	CHECK(*r == bind_response_msg(1, "hello"));
	CHECK(m.buf.empty());
	REQUIRE(m.reads->size() == 1);
	CHECK(m.reads->front() >= net::read_buffer::min_read);// one large read, not per byte
}

TEST_CASE("read_message: PDUs split across arbitrary read boundaries", "[net][read_message]")
{
	const std::size_t chunk = GENERATE(std::size_t{ 1 }, 2u, 3u, 5u, 7u, 13u, 64u, 1000u);
	mock m(chunk);
	std::vector<ldap::message> sent;
	std::string wire;
	for (int i = 1; i <= 5; ++i) {
		sent.push_back(bind_response_msg(i, std::string(static_cast<std::size_t>(i) * 150, 'x')));
		wire += bytes_of(sent.back());
	}
	m.peer->provide(wire);
	for (const auto &expected : sent) {
		auto r = m.read();
		INFO("chunk " << chunk << ", message " << expected.id);
		REQUIRE(r.has_value());
		CHECK(*r == expected);
	}
	CHECK(m.buf.empty());
	// The stream hands out `chunk` bytes per read, but every read offers all
	// the free space of the first min_read buffer (these PDUs all fit in it):
	// the reader never asks byte by byte by itself.
	for (auto n : *m.reads) CHECK(n >= net::read_buffer::min_read - wire.size());
	CHECK(m.buf.capacity() == net::read_buffer::min_read);
	CHECK(m.reads->size() == (wire.size() + chunk - 1) / chunk);
}

TEST_CASE("read_message: several PDUs in one read are kept for later calls", "[net][read_message]")
{
	mock m;
	const auto a = bind_response_msg(1), b = bind_response_msg(2, "two"), c = bind_response_msg(3, "three");
	m.peer->provide(bytes_of(a) + bytes_of(b) + bytes_of(c));
	auto ra = m.read();
	REQUIRE(ra.has_value());
	CHECK(*ra == a);
	CHECK(m.buf.size() == bytes_of(b).size() + bytes_of(c).size());
	auto rb = m.read();
	auto rc = m.read();
	REQUIRE(rb.has_value());
	REQUIRE(rc.has_value());
	CHECK(*rb == b);
	CHECK(*rc == c);
	CHECK(m.reads->size() == 1);// the later two came from the buffer
	CHECK(m.buf.empty());
}

TEST_CASE("read_message: leftover bytes of the next PDU", "[net][read_message]")
{
	mock m;
	const auto first = bind_response_msg(1), second = bind_response_msg(2, std::string(500, 'y'));
	const auto second_bytes = bytes_of(second);
	m.peer->provide(bytes_of(first) + second_bytes.substr(0, 100));
	auto r1 = m.read();
	REQUIRE(r1.has_value());
	CHECK(*r1 == first);
	CHECK(m.buf.size() == 100);
	m.peer->provide(second_bytes.substr(100));
	auto r2 = m.read();
	REQUIRE(r2.has_value());
	CHECK(*r2 == second);
	CHECK(m.buf.empty());
}

TEST_CASE("read_message: oversized PDU rejected from its header", "[net][read_message]")
{
	SECTION("default 16 MiB limit")
	{
		mock m;
		// SEQUENCE with a 4-octet length of 16 MiB: 6 header bytes, no body.
		m.peer->provide(std::string("\x30\x84\x01\x00\x00\x00", 6));
		auto r = m.read();// would wait forever for the body if it were not rejected
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::message_too_large);
		CHECK(r.error().context.starts_with("read mock: ber: declared message size 16777222"));
		CHECK(m.reads->size() == 1);
	}
	SECTION("configured limit, length split across reads")
	{
		mock m(1);
		m.peer->provide(std::string("\x30\x82\x01\x00", 4));// 260 bytes declared
		auto r = m.read({ .max_message_size = 200 });
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == client_errc::message_too_large);
		CHECK(m.reads->size() == 4);// header only
	}
	SECTION("at the limit is accepted")
	{
		mock m;
		const auto msg = bind_response_msg(7, std::string(300, 'z'));
		const auto wire = bytes_of(msg);
		m.peer->provide(wire);
		auto r = m.read({ .max_message_size = wire.size() });
		REQUIRE(r.has_value());
		CHECK(*r == msg);
	}
}

TEST_CASE("read_message: garbage rejected from the first octet", "[net][read_message]")
{
	mock m;
	m.peer->provide(std::string("\x04\x84\x00\xff\xff\xff", 6));
	auto r = m.read();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::decode_error);
	CHECK(r.error().context == "read mock: PDU starts with 0x04, not a SEQUENCE (0x30)");

	mock n;
	n.peer->provide(std::string("\x30\x80", 2));// indefinite length
	auto r2 = n.read();
	REQUIRE_FALSE(r2.has_value());
	CHECK(r2.error().code == client_errc::decode_error);
}

TEST_CASE("read_message: end of stream", "[net][read_message]")
{
	SECTION("between PDUs")
	{
		mock m;
		m.peer->provide(bytes_of(bind_response_msg(1)));
		m.peer->close();
		REQUIRE(m.read().has_value());
		auto r = m.read();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::eof);
		CHECK(r.error().context == "read mock: connection closed");
	}
	SECTION("in the middle of a PDU")
	{
		mock m(3);
		const auto wire = bytes_of(bind_response_msg(1, "abcdef"));
		m.peer->provide(wire.substr(0, 10));
		m.peer->close();
		auto r = m.read();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::eof);
		CHECK(r.error().context
			  == "read mock: connection closed after 10 of " + std::to_string(wire.size()) + " bytes of a PDU");
	}
	SECTION("inside the header")
	{
		mock m;
		m.peer->provide(std::string("\x30\x84\x00", 3));
		m.peer->close();
		auto r = m.read();
		REQUIRE_FALSE(r.has_value());
		CHECK(r.error().code == capy::cond::eof);
		CHECK(r.error().context == "read mock: connection closed inside a PDU header");
	}
}

TEST_CASE("read_message: request operations from the server are rejected", "[net][read_message]")
{
	mock m;
	m.peer->provide(bytes_of(bind_request_msg(1)) + bytes_of(bind_response_msg(2)));
	auto r = m.read();
	REQUIRE_FALSE(r.has_value());
	CHECK(r.error().code == client_errc::unsupported_operation);
	CHECK(r.error().context.starts_with("read mock: "));
	// The bad PDU was consumed; the stream stays framed.
	auto next = m.read();
	REQUIRE(next.has_value());
	CHECK(*next == bind_response_msg(2));

	// A server-side reader accepts requests and rejects responses.
	mock s;
	s.peer->provide(bytes_of(bind_request_msg(1)) + bytes_of(bind_response_msg(2)));
	const net::read_options as_server{ .decode = { .from = ldap::origin::client } };
	auto req = s.read(as_server);
	REQUIRE(req.has_value());
	CHECK(*req == bind_request_msg(1));
	CHECK(s.read(as_server).error().code == client_errc::unsupported_operation);
}

TEST_CASE("read_message: large PDUs and buffer bounds", "[net][read_message]")
{
	mock m(64 * 1024);
	// A 3 MiB search entry followed by a small message.
	ldap::message big{ .id = 5,
		.op = ldap::search_result_entry{ .object_name = "cn=big",
		  .attributes = { { .type = "data", .values = { std::string(3 * 1024 * 1024, 'q') } } } } };
	const auto wire = bytes_of(big);
	m.peer->provide(wire + bytes_of(bind_response_msg(6)));
	auto r = m.read();
	REQUIRE(r.has_value());
	CHECK(*r == big);
	// Once the header is in, the buffer is sized for exactly the rest of the
	// PDU, so nothing of the next one was read, and once empty the large
	// allocation is released.
	CHECK(m.buf.empty());
	CHECK(m.buf.capacity() == 0);
	CHECK(m.reads->size() == 1 + (wire.size() - net::read_buffer::min_read + 64 * 1024 - 1) / (64 * 1024));
	auto small = m.read();
	REQUIRE(small.has_value());
	CHECK(*small == bind_response_msg(6));
	CHECK(m.buf.capacity() == net::read_buffer::min_read);
}

TEST_CASE("read_buffer bookkeeping", "[net][read_message]")
{
	net::read_buffer b;
	CHECK(b.empty());
	auto space = b.prepare(10);
	REQUIRE(space.size() >= 10);
	space[0] = std::byte{ 1 };
	space[1] = std::byte{ 2 };
	space[2] = std::byte{ 3 };
	b.commit(3);
	CHECK(b.size() == 3);
	b.consume(1);
	CHECK(b.size() == 2);
	CHECK(b.data()[0] == std::byte{ 2 });
	// Compaction keeps the data.
	auto more = b.prepare(b.capacity());
	CHECK(more.size() >= b.capacity() - 2);
	CHECK(b.data()[0] == std::byte{ 2 });
	CHECK(b.data()[1] == std::byte{ 3 });
	b.consume(100);
	CHECK(b.empty());
}

TEST_CASE("write_message and write_bytes", "[net][write_message]")
{
	corosio::io_context ioc;
	auto [a, b] = capy::test::make_stream_pair();
	auto client = net::transport::wrap(std::move(a), "client");
	auto server = net::transport::wrap(std::move(b), "server");

	REQUIRE(run(ioc, net::write_message(client, bind_request_msg(1))).has_value());
	const auto two = bytes_of(bind_request_msg(2)) + bytes_of(bind_request_msg(3));
	const std::vector<std::byte> raw(
	  reinterpret_cast<const std::byte *>(two.data()), reinterpret_cast<const std::byte *>(two.data()) + two.size());
	REQUIRE(run(ioc, net::write_bytes(client, raw)).has_value());

	net::read_buffer buf;
	const net::read_options as_server{ .decode = { .from = ldap::origin::client } };
	for (int id = 1; id <= 3; ++id) {
		auto r = run(ioc, net::read_message(server, buf, as_server));
		REQUIRE(r.has_value());
		CHECK(*r == bind_request_msg(id));
	}

	// Encoding errors come back before anything is written.
	auto bad = run(ioc, net::write_message(client, ldap::message{ .id = -1, .op = ldap::unbind_request{} }));
	REQUIRE_FALSE(bad.has_value());
	CHECK(bad.error().code == client_errc::encode_error);
	CHECK(bad.error().context.starts_with("write client: "));
	CHECK(buf.empty());
}

TEST_CASE("transport basics", "[net][transport]")
{
	net::transport empty;
	CHECK(empty.type() == net::transport::kind::none);
	CHECK_FALSE(empty.is_open());
	CHECK_FALSE(empty.is_tls());
	CHECK(empty.name() == "no transport");
	empty.close();// harmless
	empty.cancel();

	auto [a, b] = capy::test::make_stream_pair();
	auto t = net::transport::wrap(std::move(a), "x");
	CHECK(t.type() == net::transport::kind::custom);
	CHECK(t.is_open());
	CHECK(t.name() == "x");
	net::transport moved = std::move(t);
	CHECK(moved.is_open());
	CHECK(moved.name() == "x");
	CHECK_FALSE(t.is_open());// NOLINT(bugprone-use-after-move): moved-from is empty
}

TEST_CASE("read_buffer allocates from the given memory resource", "[net][read_message][pmr]")
{
	using jhetz::ldap::test::counting_resource;
	using jhetz::ldap::test::scoped_default_resource;

	SECTION("supplied resource")
	{
		counting_resource counting;
		{
			mock m(std::numeric_limits<std::size_t>::max(), &counting);
			CHECK(m.buf.get_allocator().resource() == &counting);
			const auto big = bind_response_msg(1, std::string(100'000, 'b'));
			m.peer->provide(bytes_of(big) + bytes_of(bind_response_msg(2)));
			auto r = m.read();
			REQUIRE(r.has_value());
			CHECK(*r == big);
			CHECK(counting.bytes() >= bytes_of(big).size());
			REQUIRE(m.read().has_value());
			CHECK(counting.outstanding() == m.buf.capacity());// the buffer is all that lives there
		}
		CHECK(counting.outstanding() == 0);
	}
	SECTION("the buffer grows once per larger PDU, even in tiny reads")
	{
		counting_resource counting;
		mock m(7, &counting);
		for (int i = 1; i <= 3; ++i) m.peer->provide(bytes_of(bind_response_msg(i, std::string(40'000, 'a'))));
		for (int i = 1; i <= 3; ++i) REQUIRE(m.read().has_value());
		CHECK(counting.allocations() == 2);// min_read, then one PDU
		CHECK(m.buf.capacity() == bytes_of(bind_response_msg(1, std::string(40'000, 'a'))).size());
	}
	SECTION("default resource by default")
	{
		counting_resource as_default;
		scoped_default_resource d(&as_default);
		net::read_buffer b;
		CHECK(b.get_allocator().resource() == &as_default);
		b.prepare(10);
		CHECK(as_default.allocations() == 1);
		CHECK(as_default.outstanding() == net::read_buffer::min_read);// never less than min_read
	}
	SECTION("fixed arena without fallback")
	{
		// Every buffer allocation must come from the arena: its upstream throws.
		std::vector<std::byte> storage(128 * 1024);
		std::pmr::monotonic_buffer_resource arena(storage.data(), storage.size(), std::pmr::null_memory_resource());
		mock m(7, &arena);
		for (int i = 1; i <= 3; ++i) m.peer->provide(bytes_of(bind_response_msg(i, std::string(40'000, 'a'))));
		for (int i = 1; i <= 3; ++i) {
			auto r = m.read();
			REQUIRE(r.has_value());
			CHECK(r->id == i);
		}
	}
}
