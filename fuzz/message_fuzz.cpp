// libFuzzer target for the LDAPMessage codec (also driven by
// message_fuzz_replay).
//
// For any input it must not crash, and if the input decodes as a message:
// - it encodes (the decoder only accepts what the encoder can write);
// - the encoding decodes to an equal message (exactly: filters are trees, so
//   nothing is canonicalized) and re-encodes to the same bytes;
// - decoding into a std::pmr::monotonic_buffer_resource gives an equal
//   message without touching the default resource (a null resource is
//   installed as the default meanwhile); a copy made before the arena is
//   released stays valid after it (ASan reports any access to released
//   arena memory);
// - the framer measures the encoding as exactly one complete message;
// - peek_message_header never crashes, and agrees with decode (id) and with
//   the re-encoding (id, operation tag) whenever the input decodes;
// - a paged results, sort result or pre-/post-read control that decodes
//   re-encodes to an equal value (the entry of a read control allocated
//   from the message's resource);
// - search entries convert to ldap::entry, results to ldap::error, whose
//   message() is well-formed UTF-8 without C0 controls or DEL;
// - decode_options::from accepts exactly the responses (origin::server) or the
//   requests (origin::client), failing otherwise with unsupported_operation.
// Also, with the input as (possibly non-canonical) filter text: if it
// parses, the search request m carrying it encodes, decode(encode(m)) == m
// and encode(decode(encode(m))) == encode(m).
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/message.hpp"

#include "check.hpp"

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <variant>

constexpr jhetz::ldap::fuzz::checker check{ "message_fuzz" };

namespace {

namespace ldap = jhetz::ldap;

template<class T>
concept has_result = requires(const T &t) { t.result.to_error(); };

bool is_decode_failure(const ldap::error &e)
{
	return e.code == ldap::client_errc::decode_error || e.code == ldap::client_errc::unexpected_tag
		   || e.code == ldap::client_errc::nesting_too_deep || e.code == ldap::client_errc::integer_overflow
		   || e.code == ldap::client_errc::unsupported_tag;
}

void exercise_control(const ldap::control &c)
{
	if (c.type == ldap::paged_results_oid) {
		if (auto p = ldap::decode_paged_results(c)) {
			const auto again = ldap::encode_paged_results(*p, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_paged_results(*again) == *p, "ldap::decode_paged_results(*again) == *p");
		} else {
			check(is_decode_failure(p.error()), "is_decode_failure(p.error())");
		}
	} else if (c.type == ldap::sort_response_oid) {
		if (auto s = ldap::decode_sort_result(c, c.get_allocator().resource())) {
			check(s->get_allocator() == c.get_allocator(), "s->get_allocator() == c.get_allocator()");
			const auto again = ldap::encode_sort_result(*s, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_sort_result(*again) == *s, "ldap::decode_sort_result(*again) == *s");
		} else {
			check(is_decode_failure(s.error()), "is_decode_failure(s.error())");
		}
	} else if (c.type == ldap::pre_read_oid || c.type == ldap::post_read_oid) {
		ldap::decode_options options;
		options.memory = c.get_allocator().resource();
		if (auto e = ldap::decode_read_entry(c, options)) {
			check(e->get_allocator() == c.get_allocator(), "e->get_allocator() == c.get_allocator()");
			const auto again = ldap::encode_read_entry(c.type, *e, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_read_entry(*again) == *e, "ldap::decode_read_entry(*again) == *e");
		} else {
			check(is_decode_failure(e.error()) || e.error().code == ldap::client_errc::message_too_large,
			  "is_decode_failure(e.error()) || e.error().code == ldap::client_errc::message_too_large");
		}
	}
}

void exercise(const ldap::message &m)
{
	for (const auto &c : m.controls) exercise_control(c);
	std::visit(
	  [](const auto &op) {
		  using T = std::decay_t<decltype(op)>;
		  if constexpr (std::is_same_v<T, ldap::search_result_entry>) {
			  // A copy on op's resource, so the entry is made on it too.
			  const auto e = ldap::entry::from(ldap::search_result_entry(op, op.get_allocator()));
			  check(e.get_allocator() == op.get_allocator(), "e.get_allocator() == op.get_allocator()");
			  check(e.dn == op.object_name, "e.dn == op.object_name");
			  for (const auto &a : op.attributes) check(e.find(a.type) != nullptr, "e.find(a.type) != nullptr");
		  } else if constexpr (has_result<T>) {
			  const auto err = op.result.to_error("fuzz");
			  check(err.code.value() == op.result.result_code, "err.code.value() == op.result.result_code");
			  // The server's text is sanitized: well-formed UTF-8, no C0 or DEL.
			  const auto text = err.message();
			  check(!text.empty(), "!text.empty()");
			  for (std::size_t i = 0; i < text.size();) {
				  const std::size_t n = ldap::detail::utf8_sequence_length(text, i);
				  check(n != 0, "n != 0");
				  check(n > 1 || (text[i] >= 0x20 && text[i] != 0x7F), "n > 1 || (text[i] >= 0x20 && text[i] != 0x7F)");
				  i += n == 0 ? 1 : n;
			  }
		  }
	  },
	  m.op);
}

template<class T>
constexpr bool is_request_v = std::is_same_v<T, ldap::bind_request> || std::is_same_v<T, ldap::unbind_request>
							  || std::is_same_v<T, ldap::search_request> || std::is_same_v<T, ldap::modify_request>
							  || std::is_same_v<T, ldap::add_request> || std::is_same_v<T, ldap::del_request>
							  || std::is_same_v<T, ldap::modify_dn_request> || std::is_same_v<T, ldap::compare_request>
							  || std::is_same_v<T, ldap::abandon_request> || std::is_same_v<T, ldap::extended_request>;

void check_origins(std::span<const std::byte> input, const ldap::message &m)
{
	const bool request = std::visit([](const auto &op) { return is_request_v<std::decay_t<decltype(op)>>; }, m.op);
	auto from_server = ldap::decode(input, { .from = ldap::origin::server });
	auto from_client = ldap::decode(input, { .from = ldap::origin::client });
	check(from_server.has_value() == !request, "from_server.has_value() == !request");
	check(from_client.has_value() == request, "from_client.has_value() == request");
	const auto &rejected = request ? from_server : from_client;
	check(rejected.error().code == ldap::client_errc::unsupported_operation,
	  "rejected.error().code == ldap::client_errc::unsupported_operation");
	check(*(request ? from_client : from_server) == m, "*(request ? from_client : from_server) == m");
}

// Search requests with arbitrary filter text round-trip exactly.
void check_filter_text(std::span<const std::uint8_t> data)
{
	const std::string_view text(reinterpret_cast<const char *>(data.data()), data.size());
	auto f = ldap::filter::raw(text);
	if (!f) {
		check(
		  f.error().code == ldap::client_errc::invalid_filter, "f.error().code == ldap::client_errc::invalid_filter");
		return;
	}
	ldap::search_request s;
	s.filter = std::move(*f);
	const ldap::message m{ 1, std::move(s) };
	auto encoded = ldap::encode(m);
	check(encoded.has_value(), "encoded.has_value()");
	auto decoded = ldap::decode(*encoded);
	check(decoded.has_value(), "decoded.has_value()");
	check(*decoded == m, "*decoded == m");
	auto again = ldap::encode(*decoded);
	check(again.has_value() && *again == *encoded, "again.has_value() && *again == *encoded");
}

// Default resource that fails loudly (std::bad_alloc, an uncaught exception
// in the fuzzer) on any allocation, while the arena decode runs.
class scoped_null_default
{
  public:
	scoped_null_default() noexcept : old_(std::pmr::set_default_resource(std::pmr::null_memory_resource())) {}
	scoped_null_default(const scoped_null_default &) = delete;
	scoped_null_default &operator=(const scoped_null_default &) = delete;
	~scoped_null_default() { std::pmr::set_default_resource(old_); }

  private:
	std::pmr::memory_resource *old_;
};

// Decodes into an arena whose memory all comes from the heap in chunks (no
// initial buffer), so releasing it frees everything and ASan catches any
// later access to it.
void check_arena(std::span<const std::byte> input, const ldap::message &expected)
{
	std::pmr::monotonic_buffer_resource arena(std::pmr::new_delete_resource());
	ldap::decode_options options;
	options.memory = &arena;
	std::optional<ldap::message> copy;
	{
		std::optional<ldap::result<ldap::message>> in_arena;
		{
			scoped_null_default guard;
			in_arena.emplace(ldap::decode(input, options));
		}
		check(in_arena->has_value(), "in_arena->has_value()");
		const ldap::message &m = **in_arena;
		check(m == expected, "m == expected");
		check(m.get_allocator().resource() == &arena, "m.get_allocator().resource() == &arena");
		exercise(m);
		copy.emplace(m);// plain copy: default resource
	}
	arena.release();
	check(copy->get_allocator().resource() == std::pmr::get_default_resource(),
	  "copy->get_allocator().resource() == std::pmr::get_default_resource()");
	check(*copy == expected, "*copy == expected");
	auto bytes = ldap::encode(*copy);
	check(bytes.has_value(), "bytes.has_value()");
	check(ldap::decode(*bytes).value() == expected, "ldap::decode(*bytes).value() == expected");
}

}// namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
	const auto input = std::as_bytes(std::span(data, size));
	check_filter_text(std::span(data, size));
	const auto header = ldap::peek_message_header(input);// must not crash on anything
	auto m = ldap::decode(input);
	if (!m) {
		check(static_cast<bool>(m.error().code), "static_cast<bool>(m.error().code)");
		return 0;
	}
	// Whatever decodes, peeks, with the same id and the operation's tag.
	check(header.has_value() && header->id == m->id, "header.has_value() && header->id == m->id");

	auto encoded = ldap::encode(*m);
	check(encoded.has_value(), "encoded.has_value()");
	auto again = ldap::decode(*encoded);
	check(again.has_value(), "again.has_value()");
	check(*again == *m, "*again == *m");
	auto reencoded = ldap::encode(*again);
	check(reencoded.has_value() && *reencoded == *encoded, "reencoded.has_value() && *reencoded == *encoded");

	const auto reheader = ldap::peek_message_header(*encoded);
	check(reheader.has_value() && reheader->id == m->id && reheader->op.cls == header->op.cls
			&& reheader->op.number == header->op.number,
	  "reheader.has_value() && reheader->id == m->id && reheader->op.cls == header->op.cls && reheader->op.number == "
	  "header->op.number");

	auto framed = jhetz::ldap::ber::complete_message_size(*encoded);
	check(framed && *framed && **framed == encoded->size(), "framed && *framed && **framed == encoded->size()");

	check_origins(input, *m);
	exercise(*m);
	check_arena(input, *m);
	return 0;
}
