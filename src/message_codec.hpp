// The LDAPMessage decoder, shared with the request decoder of the testing
// target.
#pragma once

#include "control_util.hpp"
#include "format_util.hpp"

#include "jhetz/ldap/ber.hpp"
#include "jhetz/ldap/error.hpp"
#include "jhetz/ldap/message.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap::detail {

// Context tag numbers of operation fields (RFC 4511 sections 4.2.2 and
// 4.12).
namespace field_tag {
	inline constexpr std::uint8_t server_sasl_creds = 7;// BindResponse
	inline constexpr std::uint8_t response_name = 10;// ExtendedResponse
	inline constexpr std::uint8_t response_value = 11;
}// namespace field_tag

// BindRequest's version INTEGER (1 .. 127) (RFC 4511 section 4.2).
inline constexpr std::int64_t max_bind_version = 127;

inline auto bad_message(std::string_view what, std::size_t offset) -> std::unexpected<error>
{
	return fail(client_errc::decode_error, detail::format("message: {} at offset {}", what, offset));
}

// `before`, the peer's `text` sanitized and cut to 64 bytes, then `after`.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline auto sanitized_context(std::string_view before, std::string_view text, std::string_view after) -> std::string
{
	std::string out(before);
	detail::append_sanitized(out, text, 64);
	out += after;
	return out;
}

// Writes the Controls of an LDAPMessage (each control's SEQUENCE).
void write_control_list(ber::writer &list, const std::pmr::vector<control> &controls);

// Writes `e` as the SearchResultEntry protocolOp.
void write_search_result_entry(ber::writer &w, const search_result_entry &e);

inline auto
  read_ranged(ber::reader &r, ber::tag t, std::int64_t lo, std::int64_t hi, const char *what, bool enumerated = false)
	-> result<std::int32_t>
{
	const std::size_t offset = r.offset();
	auto copy = r;
	auto v = enumerated ? copy.read_enumerated(t) : copy.read_integer(t);
	if (!v) {
		return std::unexpected(std::move(v.error()));
	}
	if (*v < lo || *v > hi) {
		return bad_message(detail::format("{} {} outside {}..{}", what, *v, lo, hi), offset);
	}
	r = copy;
	return static_cast<std::int32_t>(*v);
}

// Leading elements of tag `t` and at least `min_size` bytes, up to `limit`,
// to reserve vectors exactly.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
inline auto count_elements(ber::reader r, ber::tag t, std::size_t min_size, std::size_t limit) -> std::size_t
{
	std::size_t n = 0;
	while (!r.empty() && n < limit) {
		auto e = r.read();
		if (!e || e->t != t || e->size() < min_size) {
			break;
		}
		++n;
	}
	return n;
}

// Smallest valid encodings: an OCTET STRING `04 00`, a PartialAttribute
// `30 04 04 00 31 00`.
inline constexpr std::size_t min_value_size = 2;
inline constexpr std::size_t min_attribute_size = 6;

class message_decoder;

// Decodes the request protocolOps (RFC 4511 section 4.2) for a
// message_decoder.
class request_reader
{
  public:
	request_reader() = default;
	request_reader(const request_reader &) = default;
	request_reader(request_reader &&) = default;
	auto operator=(const request_reader &) -> request_reader & = default;
	auto operator=(request_reader &&) -> request_reader & = default;

	// `t` is the request's tag, peeked from `r`.
	virtual auto read(message_decoder &d, ber::reader &r, ber::tag t) const -> result<protocol_op> = 0;

  protected:
	~request_reader() = default;
};

// Decodes into `a` (decode_options::memory), moving the parts in. Request
// operations go to `requests` (unsupported_operation when null), responses
// fail with unsupported_operation unless `responses`.
class message_decoder
{
  public:
	explicit message_decoder(const decode_options &options,
	  const request_reader *requests = nullptr,
	  bool responses = true)
	  : options_(&options), requests_(requests), responses_(responses), a_(options.memory)
	{}

	// The value of a pre-read / post-read response control: exactly one
	// SearchResultEntry.
	auto run_entry(std::span<const std::byte> bytes) -> result<search_result_entry>
	{
		ber::reader top(bytes, options_->max_depth);
		auto op = read_search_result_entry(top, ber::application(op_tag::search_result_entry));
		if (!op) {
			return std::unexpected(std::move(op.error()));
		}
		if (auto done = top.expect_end(); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return std::move(std::get<search_result_entry>(*op));
	}

	// txnEndRes (RFC 5805 section 2.3).
	auto run_end_transaction(std::span<const std::byte> bytes) -> result<end_transaction_response>
	{
		ber::reader top(bytes, options_->max_depth);
		auto r = top.enter();
		if (!r) {
			return std::unexpected(std::move(r.error()));
		}
		if (auto done = top.expect_end(); !done) {
			return std::unexpected(std::move(done.error()));
		}
		end_transaction_response out(a_);
		if (next_is(*r, ber::tags::integer)) {
			auto id = read_ranged(*r, ber::tags::integer, 0, max_int, "messageID");
			if (!id) {
				return std::unexpected(std::move(id.error()));
			}
			out.message_id = *id;
		}
		if (next_is(*r, ber::tags::sequence)) {
			auto list = r->enter();
			if (!list) {
				return std::unexpected(std::move(list.error()));
			}
			while (!list->empty()) {
				auto u = list->enter();
				if (!u) {
					return std::unexpected(std::move(u.error()));
				}
				update_controls item(a_);
				auto id = read_ranged(*u, ber::tags::integer, 0, max_int, "updateControls messageID");
				if (!id) {
					return std::unexpected(std::move(id.error()));
				}
				item.message_id = *id;
				// Controls ::= SEQUENCE OF control Control (RFC 4511
				// section 4.1.11), here with its universal tag.
				auto controls = u->enter();
				if (!controls) {
					return std::unexpected(std::move(controls.error()));
				}
				while (!controls->empty()) {
					auto c = read_control(*controls);
					if (!c) {
						return std::unexpected(std::move(c.error()));
					}
					item.controls.push_back(std::move(*c));
				}
				if (auto done = skip_rest(*u); !done) {
					return std::unexpected(std::move(done.error()));
				}
				out.updates_controls.push_back(std::move(item));
			}
		}
		if (auto done = skip_rest(*r); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

	auto run(std::span<const std::byte> bytes) -> result<message>
	{
		ber::reader top(bytes, options_->max_depth);
		auto r = top.enter();
		if (!r) {
			return std::unexpected(std::move(r.error()));
		}
		if (auto done = top.expect_end(); !done) {
			return std::unexpected(std::move(done.error()));
		}
		message m(a_);
		auto id = read_ranged(*r, ber::tags::integer, 0, max_int, "message id");
		if (!id) {
			return std::unexpected(std::move(id.error()));
		}
		m.id = *id;
		// RFC 4511 section 4.1.1: id 0 is reserved for unsolicited notifications.
		if (*id == 0 && !r->empty()) {
			auto t = r->peek_tag();
			if (t && t->cls == ber::tag_class::application && is_request(t->number)) {
				return bad_message("request with message id 0", r->offset());
			}
		}
		auto op = read_op(*r);
		if (!op) {
			return std::unexpected(std::move(op.error()));
		}
		m.op = std::move(*op);// same resource: moved, not copied
		if (next_is(*r, ber::context(0))) {
			auto list = r->enter(ber::context(0));
			if (!list) {
				return std::unexpected(std::move(list.error()));
			}
			while (!list->empty()) {
				auto c = read_control(*list);
				if (!c) {
					return std::unexpected(std::move(c.error()));
				}
				m.controls.push_back(std::move(*c));
			}
		}
		if (auto done = skip_rest(*r); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return m;
	}

	// Building blocks of a request_reader.

	[[nodiscard]] auto allocator() const noexcept -> const std::pmr::polymorphic_allocator<> & { return a_; }

	auto str(ber::reader &r, ber::tag t = ber::tags::octet_string) -> result<std::pmr::string>
	{
		if (strings_ == options_->max_elements) [[unlikely]] {
			return too_many_elements(r.offset());
		}
		// Counted before reading (a failed read ends the decode anyway),
		// so the result is returned directly, not copied.
		++strings_;
		return r.read_string(t, a_.resource());
	}

	// Kept out of str(), the hottest decoding path.
	[[nodiscard]] auto too_many_elements(std::size_t offset) const -> std::unexpected<error>
	{
		return fail(client_errc::message_too_large,
		  detail::format("message: more than {} elements at offset {}", options_->max_elements, offset));
	}

	// Elements str() may still decode.
	[[nodiscard]] auto budget() const noexcept -> std::size_t { return options_->max_elements - strings_; }

	auto optional_str(ber::reader &r, ber::tag t) -> result<std::optional<std::pmr::string>>
	{
		if (!next_is(r, t)) {
			return std::optional<std::pmr::string>{};
		}
		auto s = str(r, t);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		return std::optional<std::pmr::string>{ std::move(*s) };
	}

	// COMPONENTS OF LDAPResult: the fields are inline in the op's SEQUENCE.
	auto read_result(ber::reader &r, ldap_result &out) -> result<void>
	{
		auto code = read_ranged(r,
		  ber::tags::enumerated,
		  std::numeric_limits<std::int32_t>::min(),
		  std::numeric_limits<std::int32_t>::max(),
		  "resultCode",
		  true);
		if (!code) {
			return std::unexpected(std::move(code.error()));
		}
		auto matched = str(r);
		if (!matched) {
			return std::unexpected(std::move(matched.error()));
		}
		auto diag = str(r);
		if (!diag) {
			return std::unexpected(std::move(diag.error()));
		}
		out.result_code = *code;
		out.matched_dn = std::move(*matched);
		out.diagnostic_message = std::move(*diag);
		if (next_is(r, ber::context(3))) {
			auto ref = r.enter(ber::context(3));
			if (!ref) {
				return std::unexpected(std::move(ref.error()));
			}
			while (!ref->empty()) {
				auto uri = str(*ref);
				if (!uri) {
					return std::unexpected(std::move(uri.error()));
				}
				out.referral.push_back(std::move(*uri));
			}
		}
		return {};
	}

	template<class T> auto result_only(ber::reader &r, ber::tag t) -> result<protocol_op>
	{
		auto o = r.enter(t);
		if (!o) {
			return std::unexpected(std::move(o.error()));
		}
		protocol_op op(std::in_place_type<T>, a_);
		if (auto done = read_result(*o, std::get<T>(op).result); !done) {
			return std::unexpected(std::move(done.error()));
		}
		if (auto done = skip_rest(*o); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return op;
	}

	auto read_attribute(ber::reader &r, partial_attribute &out) -> result<void>
	{
		auto pa = r.enter();
		if (!pa) {
			return std::unexpected(std::move(pa.error()));
		}
		auto type = str(*pa);
		if (!type) {
			return std::unexpected(std::move(type.error()));
		}
		auto vals = pa->enter(ber::tags::set);
		if (!vals) {
			return std::unexpected(std::move(vals.error()));
		}
		out.type = std::move(*type);
		out.values.reserve(count_elements(*vals, ber::tags::octet_string, min_value_size, budget()));
		while (!vals->empty()) {
			auto v = str(*vals);
			if (!v) {
				return std::unexpected(std::move(v.error()));
			}
			out.values.push_back(std::move(*v));
		}
		if (auto done = skip_rest(*pa); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return {};
	}

	auto read_attributes(ber::reader &r, std::pmr::vector<partial_attribute> &out) -> result<void>
	{
		auto list = r.enter();
		if (!list) {
			return std::unexpected(std::move(list.error()));
		}
		out.reserve(count_elements(*list, ber::tags::sequence, min_attribute_size, budget()));
		while (!list->empty()) {
			if (auto done = read_attribute(*list, out.emplace_back()); !done) {
				return std::unexpected(std::move(done.error()));
			}
		}
		return {};
	}

  private:
	auto read_bind_response(ber::reader &r, ber::tag t) -> result<protocol_op>
	{
		auto o = r.enter(t);
		if (!o) {
			return std::unexpected(std::move(o.error()));
		}
		protocol_op op(std::in_place_type<bind_response>, a_);
		auto &b = std::get<bind_response>(op);
		if (auto done = read_result(*o, b.result); !done) {
			return std::unexpected(std::move(done.error()));
		}
		auto creds = optional_str(*o, ber::context(field_tag::server_sasl_creds));
		if (!creds) {
			return std::unexpected(std::move(creds.error()));
		}
		if (auto done = skip_rest(*o); !done) {
			return std::unexpected(std::move(done.error()));
		}
		b.server_sasl_creds = std::move(*creds);
		return op;
	}

	auto read_search_result_entry(ber::reader &r, ber::tag t) -> result<protocol_op>
	{
		auto o = r.enter(t);
		if (!o) {
			return std::unexpected(std::move(o.error()));
		}
		protocol_op op(std::in_place_type<search_result_entry>, a_);
		auto &e = std::get<search_result_entry>(op);
		auto name = str(*o);
		if (!name) {
			return std::unexpected(std::move(name.error()));
		}
		e.object_name = std::move(*name);
		if (auto done = read_attributes(*o, e.attributes); !done) {
			return std::unexpected(std::move(done.error()));
		}
		if (auto done = skip_rest(*o); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return op;
	}

	auto read_search_result_reference(ber::reader &r, ber::tag t) -> result<protocol_op>
	{
		auto o = r.enter(t);
		if (!o) {
			return std::unexpected(std::move(o.error()));
		}
		protocol_op op(std::in_place_type<search_result_reference>, a_);
		auto &ref = std::get<search_result_reference>(op);
		// RFC 4511 section 4.5.3: SEQUENCE SIZE (1..MAX) OF uri.
		if (o->empty()) {
			return bad_message("search result reference without a URI", o->offset());
		}
		while (!o->empty()) {
			auto uri = str(*o);
			if (!uri) {
				return std::unexpected(std::move(uri.error()));
			}
			ref.uris.push_back(std::move(*uri));
		}
		return op;
	}

	auto read_extended_response(ber::reader &r, ber::tag t) -> result<protocol_op>
	{
		auto o = r.enter(t);
		if (!o) {
			return std::unexpected(std::move(o.error()));
		}
		protocol_op op(std::in_place_type<extended_response>, a_);
		auto &e = std::get<extended_response>(op);
		if (auto done = read_result(*o, e.result); !done) {
			return std::unexpected(std::move(done.error()));
		}
		auto name = optional_str(*o, ber::context(field_tag::response_name));
		if (!name) {
			return std::unexpected(std::move(name.error()));
		}
		auto value = optional_str(*o, ber::context(field_tag::response_value));
		if (!value) {
			return std::unexpected(std::move(value.error()));
		}
		if (auto done = skip_rest(*o); !done) {
			return std::unexpected(std::move(done.error()));
		}
		e.response_name = std::move(*name);
		e.response_value = std::move(*value);
		return op;
	}

	auto read_intermediate_response(ber::reader &r, ber::tag t) -> result<protocol_op>
	{
		auto o = r.enter(t);
		if (!o) {
			return std::unexpected(std::move(o.error()));
		}
		protocol_op op(std::in_place_type<intermediate_response>, a_);
		auto &i = std::get<intermediate_response>(op);
		auto name = optional_str(*o, ber::context(0));
		if (!name) {
			return std::unexpected(std::move(name.error()));
		}
		auto value = optional_str(*o, ber::context(1));
		if (!value) {
			return std::unexpected(std::move(value.error()));
		}
		if (auto done = skip_rest(*o); !done) {
			return std::unexpected(std::move(done.error()));
		}
		i.response_name = std::move(*name);
		i.response_value = std::move(*value);
		return op;
	}

	auto read_op(ber::reader &r) -> result<protocol_op>
	{
		const std::size_t offset = r.offset();
		auto peeked = r.peek_tag();
		if (!peeked) {
			return std::unexpected(std::move(peeked.error()));
		}
		const ber::tag t = *peeked;
		if (t.cls != ber::tag_class::application) {
			return unknown_op(t, offset);
		}
		// Checked before decoding, so a peer cannot make us parse (for
		// example) a huge search request filter it may not send at all.
		if (is_request(t.number)) {
			if (requests_ == nullptr) {
				return fail(client_errc::unsupported_operation,
				  detail::format(
					"message: request operation {} from a server at offset {}", ber::to_string(t), offset));
			}
			return requests_->read(*this, r, t);
		}
		if (!responses_) {
			return fail(client_errc::unsupported_operation,
			  detail::format("message: response operation {} from a client at offset {}", ber::to_string(t), offset));
		}
		switch (t.number) {
		case op_tag::bind_response:
			return read_bind_response(r, t);
		case op_tag::search_result_entry:
			return read_search_result_entry(r, t);
		case op_tag::search_result_done:
			return result_only<search_result_done>(r, t);
		case op_tag::search_result_reference:
			return read_search_result_reference(r, t);
		case op_tag::modify_response:
			return result_only<modify_response>(r, t);
		case op_tag::add_response:
			return result_only<add_response>(r, t);
		case op_tag::del_response:
			return result_only<del_response>(r, t);
		case op_tag::modify_dn_response:
			return result_only<modify_dn_response>(r, t);
		case op_tag::compare_response:
			return result_only<compare_response>(r, t);
		case op_tag::extended_response:
			return read_extended_response(r, t);
		case op_tag::intermediate_response:
			return read_intermediate_response(r, t);
		default:
			return unknown_op(t, offset);
		}
	}

	static auto unknown_op(ber::tag t, std::size_t offset) -> std::unexpected<error>
	{
		return fail(client_errc::unsupported_operation,
		  detail::format("message: unknown protocolOp {} at offset {}", ber::to_string(t), offset));
	}

	auto read_control(ber::reader &r) -> result<control>
	{
		auto c = r.enter();
		if (!c) {
			return std::unexpected(std::move(c.error()));
		}
		control out(a_);
		auto type = str(*c);
		if (!type) {
			return std::unexpected(std::move(type.error()));
		}
		out.type = std::move(*type);
		if (next_is(*c, ber::tags::boolean)) {
			auto critical = c->read_boolean();
			if (!critical) {
				return std::unexpected(std::move(critical.error()));
			}
			out.criticality = *critical;
		}
		auto value = optional_str(*c, ber::tags::octet_string);
		if (!value) {
			return std::unexpected(std::move(value.error()));
		}
		out.value = std::move(*value);
		if (auto done = skip_rest(*c); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

	// Operations a client sends (RFC 4511 section 4.2 protocolOp requests).
	static auto is_request(std::uint8_t number) -> bool
	{
		switch (number) {
		case op_tag::bind_request:
		case op_tag::unbind_request:
		case op_tag::search_request:
		case op_tag::modify_request:
		case op_tag::add_request:
		case op_tag::del_request:
		case op_tag::modify_dn_request:
		case op_tag::compare_request:
		case op_tag::abandon_request:
		case op_tag::extended_request:
			return true;
		default:
			return false;
		}
	}

	const decode_options *options_;// non-null
	const request_reader *requests_;
	bool responses_;
	std::pmr::polymorphic_allocator<> a_;
	std::size_t strings_ = 0;// decoded by str(), against options_->max_elements
};

}// namespace jhetz::ldap::detail
