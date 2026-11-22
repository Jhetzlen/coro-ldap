// libFuzzer target for the LDAPMessage codec and the controls: what
// decodes encodes and round-trips exactly, also into an arena, and the
// framer, header peek and origin checks agree.
#include "jhetz/ldap/ad/controls.hpp"
#include "jhetz/ldap/ad/range.hpp"
#include "jhetz/ldap/content_sync.hpp"
#include "jhetz/ldap/controls.hpp"
#include "jhetz/ldap/entry.hpp"
#include "jhetz/ldap/message.hpp"
#include "jhetz/ldap/testing/server_codec.hpp"

#include "check.hpp"

#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

constexpr jhetz::ldap::fuzz::checker check{ "message_fuzz" };

namespace {

namespace ldap = jhetz::ldap;

template<class T>
concept has_result = requires(const T &t) { t.result.to_error(); };

auto is_decode_failure(const ldap::error &e) -> bool
{
	return e.code == ldap::client_errc::decode_error || e.code == ldap::client_errc::unexpected_tag
		   || e.code == ldap::client_errc::nesting_too_deep || e.code == ldap::client_errc::integer_overflow
		   || e.code == ldap::client_errc::unsupported_tag;
}

// The DirSync OID names the request and the response control alike.
void exercise_dirsync(const ldap::control &c)
{
	if (auto r = ldap::testing::ad::decode_dirsync_request(c)) {
		check(r->critical == c.criticality, "r->critical == c.criticality");
		check(ldap::testing::ad::decode_dirsync_request(ldap::ad::encode_dirsync_request(*r)) == *r,
		  "ldap::testing::ad::decode_dirsync_request(encode(*r)) == *r");
	} else {
		check(is_decode_failure(r.error()), "is_decode_failure(r.error())");
	}
	if (auto r = ldap::ad::decode_dirsync_response(c)) {
		const auto again = ldap::testing::ad::encode_dirsync_response(*r, c.criticality);
		check(ldap::ad::decode_dirsync_response(again) == *r, "ldap::ad::decode_dirsync_response(again) == *r");
	} else {
		check(is_decode_failure(r.error()), "is_decode_failure(r.error())");
	}
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
			const auto again = ldap::testing::encode_sort_result(*s, c.criticality);
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
			const auto again = ldap::testing::encode_read_entry(c.type, *e, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_read_entry(*again) == *e, "ldap::decode_read_entry(*again) == *e");
		} else {
			check(is_decode_failure(e.error()) || e.error().code == ldap::client_errc::message_too_large,
			  "is_decode_failure(e.error()) || e.error().code == ldap::client_errc::message_too_large");
		}
	} else if (c.type == ldap::matched_values_oid) {
		if (auto v = ldap::testing::decode_matched_values(c, c.get_allocator().resource())) {
			check(v->critical == c.criticality, "v->critical == c.criticality");
			const auto again = ldap::to_control(*v);
			check(again.has_value(), "again.has_value()");
			check(
			  ldap::testing::decode_matched_values(*again) == *v, "ldap::testing::decode_matched_values(*again) == *v");
		} else {
			check(is_decode_failure(v.error()), "is_decode_failure(v.error())");
		}
	} else if (c.type == ldap::vlv_request_oid) {
		if (auto v = ldap::testing::decode_virtual_list_view(c)) {
			check(v->critical == c.criticality, "v->critical == c.criticality");
			const auto again = ldap::to_control(*v);
			check(again.has_value(), "again.has_value()");
			check(ldap::testing::decode_virtual_list_view(*again) == *v,
			  "ldap::testing::decode_virtual_list_view(*again) == *v");
		} else {
			check(is_decode_failure(v.error()), "is_decode_failure(v.error())");
		}
	} else if (c.type == ldap::vlv_response_oid) {
		if (auto v = ldap::decode_vlv_response(c, c.get_allocator().resource())) {
			check(v->get_allocator() == c.get_allocator(), "v->get_allocator() == c.get_allocator()");
			const auto again = ldap::testing::encode_vlv_response(*v, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_vlv_response(*again) == *v, "ldap::decode_vlv_response(*again) == *v");
		} else {
			check(is_decode_failure(v.error()), "is_decode_failure(v.error())");
		}
	} else if (c.type == ldap::sync_request_oid) {
		if (auto r = ldap::testing::decode_sync_request(c)) {
			const auto again = ldap::encode_sync_request(*r);
			check(again.has_value(), "again.has_value()");
			check(ldap::testing::decode_sync_request(*again) == *r, "ldap::testing::decode_sync_request(*again) == *r");
		} else {
			check(is_decode_failure(r.error()), "is_decode_failure(r.error())");
		}
	} else if (c.type == ldap::sync_state_oid) {
		if (auto s = ldap::decode_sync_state(c, c.get_allocator().resource())) {
			check(s->get_allocator() == c.get_allocator(), "s->get_allocator() == c.get_allocator()");
			const auto again = ldap::testing::encode_sync_state(*s, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_sync_state(*again) == *s, "ldap::decode_sync_state(*again) == *s");
		} else {
			check(is_decode_failure(s.error()), "is_decode_failure(s.error())");
		}
	} else if (c.type == ldap::ad::dirsync_oid) {
		exercise_dirsync(c);
	} else if (c.type == ldap::sync_done_oid) {
		if (auto d = ldap::decode_sync_done(c)) {
			const auto again = ldap::testing::encode_sync_done(*d, c.criticality);
			check(again.has_value(), "again.has_value()");
			check(ldap::decode_sync_done(*again) == *d, "ldap::decode_sync_done(*again) == *d");
		} else {
			check(is_decode_failure(d.error()), "is_decode_failure(d.error())");
		}
	}
}

void exercise_transaction_specification(const ldap::control &c)
{
	if (c.type != ldap::transaction_specification_oid) {
		return;
	}
	if (auto t = ldap::testing::decode_transaction_specification(c)) {
		const auto again = ldap::to_control(*t);
		check(again.has_value(), "again.has_value()");
		check(*again == c, "*again == c");
	} else {
		check(is_decode_failure(t.error()), "is_decode_failure(t.error())");
	}
}

void exercise_sync_info(const ldap::intermediate_response &i)
{
	if (i.response_name != ldap::sync_info_oid) {
		return;
	}
	if (auto info = ldap::decode_sync_info(i, i.get_allocator().resource())) {
		check(info->get_allocator() == i.get_allocator(), "info->get_allocator() == i.get_allocator()");
		const auto again = ldap::testing::encode_sync_info(*info);
		check(again.has_value(), "again.has_value()");
		check(ldap::decode_sync_info(*again) == *info, "ldap::decode_sync_info(*again) == *info");
	} else {
		check(is_decode_failure(info.error()), "is_decode_failure(info.error())");
	}
}

// RFC 5805: a txnEndRes in any extended response's value, a txnEndReq in an
// End Transaction request's.
void exercise_transaction(const std::optional<std::pmr::string> &value, bool request)
{
	if (!value) {
		return;
	}
	if (request) {
		if (auto r = ldap::testing::decode_end_transaction_request(*value, value->get_allocator().resource())) {
			check(r->get_allocator() == value->get_allocator(), "r->get_allocator() == value->get_allocator()");
			const auto again = ldap::encode_end_transaction_request(*r);
			check(ldap::testing::decode_end_transaction_request(again) == *r,
			  "ldap::testing::decode_end_transaction_request(again) == *r");
		} else {
			check(is_decode_failure(r.error()), "is_decode_failure(r.error())");
		}
		return;
	}
	ldap::decode_options options;
	options.memory = value->get_allocator().resource();
	if (auto r = ldap::decode_end_transaction_response(*value, options)) {
		check(r->get_allocator() == value->get_allocator(), "r->get_allocator() == value->get_allocator()");
		const auto again = ldap::testing::encode_end_transaction_response(*r);
		check(again.has_value(), "again.has_value()");
		if (*again) {
			check(ldap::decode_end_transaction_response(**again) == *r,
			  "ldap::decode_end_transaction_response(**again) == *r");
		} else {
			check(*r == ldap::end_transaction_response{}, "*r == ldap::end_transaction_response{}");
		}
	} else {
		check(is_decode_failure(r.error()) || r.error().code == ldap::client_errc::message_too_large,
		  "is_decode_failure(r.error()) || r.error().code == ldap::client_errc::message_too_large");
	}
}

// An attribute description with an Active Directory range option splits
// into a type and a range that with_range() puts back together.
void exercise_range(std::string_view description)
{
	auto r = ldap::ad::parse_range(description);
	if (!r) {
		check(r.error().code == ldap::client_errc::decode_error, "parse_range fails with decode_error");
		return;
	}
	if (!*r) {
		return;
	}
	check(!(*r)->type.empty(), "!(*r)->type.empty()");
	check(!(*r)->range.high || *(*r)->range.high >= (*r)->range.low, "high >= low");
	auto again = ldap::ad::parse_range(ldap::ad::with_range((*r)->type, (*r)->range));
	check(again.has_value() && again->has_value() && **again == **r, "parse_range(with_range(r)) == r");
}

void exercise(const ldap::message &m)
{
	for (const auto &c : m.controls) {
		exercise_control(c);
		exercise_transaction_specification(c);
	}
	std::visit(
	  [](const auto &op) {
		  using T = std::decay_t<decltype(op)>;
		  if constexpr (std::is_same_v<T, ldap::intermediate_response>) {
			  exercise_sync_info(op);
		  } else if constexpr (std::is_same_v<T, ldap::extended_request>) {
			  if (op.request_name == ldap::end_transaction_oid) {
				  exercise_transaction(op.request_value, true);
			  }
		  } else if constexpr (std::is_same_v<T, ldap::search_result_entry>) {
			  // A copy on op's resource, so the entry is made on it too.
			  const auto e = ldap::entry::from(ldap::search_result_entry(op, op.get_allocator()));
			  check(e.get_allocator() == op.get_allocator(), "e.get_allocator() == op.get_allocator()");
			  check(e.dn == op.object_name, "e.dn == op.object_name");
			  for (const auto &a : op.attributes) {
				  check(e.find(a.type) != nullptr, "e.find(a.type) != nullptr");
				  exercise_range(a.type);
			  }
		  } else if constexpr (has_result<T>) {
			  if constexpr (std::is_same_v<T, ldap::extended_response>) {
				  exercise_transaction(op.response_value, false);
			  }
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
	auto from_server = ldap::decode(input);
	auto from_client = ldap::testing::decode(input, { .from = ldap::testing::origin::client });
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
	auto decoded = ldap::testing::decode(*encoded);
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
	auto operator=(const scoped_null_default &) -> scoped_null_default & = delete;
	~scoped_null_default() { std::pmr::set_default_resource(old_); }

  private:
	std::pmr::memory_resource *old_;
};

// Decodes into a heap-chunked arena, so ASan catches access after release.
void check_arena(std::span<const std::byte> input, const ldap::message &expected)
{
	std::pmr::monotonic_buffer_resource arena(std::pmr::new_delete_resource());
	ldap::testing::decode_options options;
	options.memory = &arena;
	std::optional<ldap::message> copy;
	{
		std::optional<ldap::result<ldap::message>> in_arena;
		{
			const scoped_null_default guard;
			in_arena.emplace(ldap::testing::decode(input, options));
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
	check(ldap::testing::decode(*bytes).value() == expected, "ldap::testing::decode(*bytes).value() == expected");
}

}// namespace

extern "C" auto LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) -> int
{
	const auto input = std::as_bytes(std::span(data, size));
	check_filter_text(std::span(data, size));
	const auto header = ldap::peek_message_header(input);// must not crash on anything
	auto m = ldap::testing::decode(input);
	if (!m) {
		check(static_cast<bool>(m.error().code), "static_cast<bool>(m.error().code)");
		return 0;
	}
	// Whatever decodes, peeks, with the same id and the operation's tag.
	check(header.has_value() && header->id == m->id, "header.has_value() && header->id == m->id");

	auto encoded = ldap::encode(*m);
	check(encoded.has_value(), "encoded.has_value()");
	auto again = ldap::testing::decode(*encoded);
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
