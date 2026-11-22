// The server side of the LDAPMessage codec: the request protocolOps and the
// response controls a server writes.
#include "jhetz/ldap/testing/server_codec.hpp"

#include "control_util.hpp"
#include "format_util.hpp"
#include "message_codec.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap::testing {

using detail::bad_message;
using detail::next_is;
using detail::read_ranged;
using detail::sanitized_context;
using detail::skip_rest;
using detail::value_control;

namespace {

	namespace op_tag = detail::op_tag;
	using detail::max_bind_version;

	// The request protocolOps (RFC 4511 section 4.2), as a server reads them.
	class client_requests final : public detail::request_reader
	{
	  public:
		explicit client_requests(const filter_limits &filter) : filter_(filter) {}

		auto read(detail::message_decoder &d, ber::reader &r, ber::tag t) const -> result<protocol_op> override
		{
			switch (t.number) {
			case op_tag::bind_request:
				return read_bind_request(d, r, t);
			case op_tag::unbind_request: {
				if (auto done = r.read_null(t); !done) {
					return std::unexpected(std::move(done.error()));
				}
				return protocol_op{ unbind_request{} };
			}
			case op_tag::search_request:
				return read_search_request(d, r, t);
			case op_tag::modify_request:
				return read_modify_request(d, r, t);
			case op_tag::add_request:
				return read_add_request(d, r, t);
			case op_tag::del_request: {
				auto entry = d.str(r, t);
				if (!entry) {
					return std::unexpected(std::move(entry.error()));
				}
				protocol_op op(std::in_place_type<del_request>, d.allocator());
				std::get<del_request>(op).entry = std::move(*entry);
				return op;
			}
			case op_tag::modify_dn_request:
				return read_modify_dn_request(d, r, t);
			case op_tag::compare_request:
				return read_compare_request(d, r, t);
			case op_tag::abandon_request: {
				auto id = read_ranged(r, t, 0, max_int, "abandoned message id");
				if (!id) {
					return std::unexpected(std::move(id.error()));
				}
				return protocol_op{ abandon_request{ *id } };
			}
			case op_tag::extended_request:
				return read_extended_request(d, r, t);
			default:
				return fail(client_errc::unsupported_operation,
				  detail::format("message: unknown protocolOp {} at offset {}", ber::to_string(t), r.offset()));
			}
		}

	  private:
		static auto read_bind_request(detail::message_decoder &d, ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<bind_request>, d.allocator());
			auto &b = std::get<bind_request>(op);
			auto version = read_ranged(*o, ber::tags::integer, 1, max_bind_version, "bind version");
			if (!version) {
				return std::unexpected(std::move(version.error()));
			}
			auto name = d.str(*o);
			if (!name) {
				return std::unexpected(std::move(name.error()));
			}
			b.version = *version;
			b.name = std::move(*name);
			const std::size_t auth_at = o->offset();
			if (next_is(*o, ber::context(0))) {
				auto password = d.str(*o, ber::context(0));
				if (!password) {
					return std::unexpected(std::move(password.error()));
				}
				std::get<simple_auth>(b.authentication).password = std::move(*password);
			} else if (next_is(*o, ber::context(3))) {
				auto s = o->enter(ber::context(3));
				if (!s) {
					return std::unexpected(std::move(s.error()));
				}
				auto mechanism = d.str(*s);
				if (!mechanism) {
					return std::unexpected(std::move(mechanism.error()));
				}
				auto credentials = d.optional_str(*s, ber::tags::octet_string);
				if (!credentials) {
					return std::unexpected(std::move(credentials.error()));
				}
				if (auto done = skip_rest(*s); !done) {
					return std::unexpected(std::move(done.error()));
				}
				auto &sasl = b.authentication.emplace<sasl_auth>(d.allocator());
				sasl.mechanism = std::move(*mechanism);
				sasl.credentials = std::move(*credentials);
			} else {
				if (o->empty()) {
					return bad_message("bind request without authentication", auth_at);
				}
				auto choice = o->peek_tag();
				if (!choice) {
					return std::unexpected(std::move(choice.error()));
				}
				return fail(client_errc::unsupported_operation,
				  detail::format(
					"message: bind authentication choice {} at offset {}", ber::to_string(*choice), auth_at));
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			return op;
		}

		auto read_search_request(detail::message_decoder &d, ber::reader &r, ber::tag t) const -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<search_request>, d.allocator());
			auto &s = std::get<search_request>(op);
			auto base = d.str(*o);
			if (!base) {
				return std::unexpected(std::move(base.error()));
			}
			auto scope = read_ranged(*o, ber::tags::enumerated, 0, 3, "search scope", true);
			if (!scope) {
				return std::unexpected(std::move(scope.error()));
			}
			auto deref = read_ranged(*o, ber::tags::enumerated, 0, 3, "derefAliases", true);
			if (!deref) {
				return std::unexpected(std::move(deref.error()));
			}
			auto size_limit = read_ranged(*o, ber::tags::integer, 0, max_int, "size limit");
			if (!size_limit) {
				return std::unexpected(std::move(size_limit.error()));
			}
			auto time_limit = read_ranged(*o, ber::tags::integer, 0, max_int, "time limit");
			if (!time_limit) {
				return std::unexpected(std::move(time_limit.error()));
			}
			auto types_only = o->read_boolean();
			if (!types_only) {
				return std::unexpected(std::move(types_only.error()));
			}
			auto f = decode_filter(*o, filter_, d.allocator().resource());
			if (!f) {
				return std::unexpected(std::move(f.error()));
			}
			auto attrs = o->enter();
			if (!attrs) {
				return std::unexpected(std::move(attrs.error()));
			}
			while (!attrs->empty()) {
				auto a = d.str(*attrs);
				if (!a) {
					return std::unexpected(std::move(a.error()));
				}
				s.attributes.push_back(std::move(*a));
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			s.base_object = std::move(*base);
			s.scope = static_cast<search_scope>(*scope);
			s.deref = static_cast<deref_aliases>(*deref);
			s.size_limit = *size_limit;
			s.time_limit = *time_limit;
			s.types_only = *types_only;
			s.filter = std::move(*f);
			return op;
		}

		static auto read_modify_request(detail::message_decoder &d, ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<modify_request>, d.allocator());
			auto &m = std::get<modify_request>(op);
			auto object = d.str(*o);
			if (!object) {
				return std::unexpected(std::move(object.error()));
			}
			m.object = std::move(*object);
			auto changes = o->enter();
			if (!changes) {
				return std::unexpected(std::move(changes.error()));
			}
			while (!changes->empty()) {
				auto change = changes->enter();
				if (!change) {
					return std::unexpected(std::move(change.error()));
				}
				auto op_code = read_ranged(*change, ber::tags::enumerated, 0, 3, "modify operation", true);
				if (!op_code) {
					return std::unexpected(std::move(op_code.error()));
				}
				const std::size_t attr_at = change->offset();
				auto &c = m.changes.emplace_back();
				c.operation = static_cast<modify_operation>(*op_code);
				if (auto done = d.read_attribute(*change, c.modification); !done) {
					return std::unexpected(std::move(done.error()));
				}
				if (c.operation == modify_operation::add && c.modification.values.empty()) {
					return bad_message("modify add change without values", attr_at);
				}
				if (auto done = skip_rest(*change); !done) {
					return std::unexpected(std::move(done.error()));
				}
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			return op;
		}

		static auto read_add_request(detail::message_decoder &d, ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<add_request>, d.allocator());
			auto &add = std::get<add_request>(op);
			auto entry = d.str(*o);
			if (!entry) {
				return std::unexpected(std::move(entry.error()));
			}
			add.entry = std::move(*entry);
			const std::size_t attrs_at = o->offset();
			if (auto done = d.read_attributes(*o, add.attributes); !done) {
				return std::unexpected(std::move(done.error()));
			}
			for (const auto &a : add.attributes) {
				if (a.values.empty()) {
					return bad_message(
					  sanitized_context("add request attribute '", a.type, "' without values"), attrs_at);
				}
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			return op;
		}

		static auto read_modify_dn_request(detail::message_decoder &d, ber::reader &r, ber::tag t)
		  -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<modify_dn_request>, d.allocator());
			auto &m = std::get<modify_dn_request>(op);
			auto entry = d.str(*o);
			if (!entry) {
				return std::unexpected(std::move(entry.error()));
			}
			auto new_rdn = d.str(*o);
			if (!new_rdn) {
				return std::unexpected(std::move(new_rdn.error()));
			}
			auto delete_old = o->read_boolean();
			if (!delete_old) {
				return std::unexpected(std::move(delete_old.error()));
			}
			auto superior = d.optional_str(*o, ber::context(0));
			if (!superior) {
				return std::unexpected(std::move(superior.error()));
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			m.entry = std::move(*entry);
			m.new_rdn = std::move(*new_rdn);
			m.delete_old_rdn = *delete_old;
			m.new_superior = std::move(*superior);
			return op;
		}

		static auto read_compare_request(detail::message_decoder &d, ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<compare_request>, d.allocator());
			auto &c = std::get<compare_request>(op);
			auto entry = d.str(*o);
			if (!entry) {
				return std::unexpected(std::move(entry.error()));
			}
			auto ava = o->enter();
			if (!ava) {
				return std::unexpected(std::move(ava.error()));
			}
			auto desc = d.str(*ava);
			if (!desc) {
				return std::unexpected(std::move(desc.error()));
			}
			auto value = d.str(*ava);
			if (!value) {
				return std::unexpected(std::move(value.error()));
			}
			if (auto done = skip_rest(*ava); !done) {
				return std::unexpected(std::move(done.error()));
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			c.entry = std::move(*entry);
			c.ava.attribute_desc = std::move(*desc);
			c.ava.assertion_value = std::move(*value);
			return op;
		}

		static auto read_extended_request(detail::message_decoder &d, ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<extended_request>, d.allocator());
			auto &e = std::get<extended_request>(op);
			auto name = d.str(*o, ber::context(0));
			if (!name) {
				return std::unexpected(std::move(name.error()));
			}
			auto value = d.optional_str(*o, ber::context(1));
			if (!value) {
				return std::unexpected(std::move(value.error()));
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			e.request_name = std::move(*name);
			e.request_value = std::move(*value);
			return op;
		}

		filter_limits filter_;
	};

}// namespace

auto decode(std::span<const std::byte> one_complete_message, const decode_options &options) -> result<message>
{
	const ldap::decode_options base{
		.max_depth = options.max_depth, .max_elements = options.max_elements, .memory = options.memory
	};
	const client_requests requests(options.filter);
	return detail::message_decoder(
	  base, options.from == origin::server ? nullptr : &requests, options.from != origin::client)
	  .run(one_complete_message);
}

auto encode_sort_result(const sort_result &value, bool criticality, std::pmr::memory_resource *mr) -> result<control>
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.enumerated(value.result_code);
		if (!value.attribute_type.empty()) {
			s.octet_string(value.attribute_type, ber::context(0));
		}
	});
	return value_control(sort_response_oid, criticality, w, mr);
}

auto encode_vlv_response(const vlv_response &value, bool criticality, std::pmr::memory_resource *mr) -> result<control>
{
	if (value.target_position < 0 || value.content_count < 0) {
		return fail(client_errc::encode_error,
		  detail::format("vlv response: targetPosition {} or contentCount {} is negative",
			value.target_position,
			value.content_count));
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(value.target_position);
		s.integer(value.content_count);
		s.enumerated(value.result_code);
		if (value.context_id) {
			s.octet_string(*value.context_id);
		}
	});
	return value_control(vlv_response_oid, criticality, w, mr);
}

auto encode_read_entry(std::string_view oid,
  const search_result_entry &entry,
  bool criticality,
  std::pmr::memory_resource *mr) -> result<control>
{
	if (oid != pre_read_oid && oid != post_read_oid) {
		return fail(client_errc::encode_error,
		  detail::sanitized_context("read entry control: ", oid, " is not pre-read or post-read"));
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	detail::write_search_result_entry(w, entry);
	return value_control(oid, criticality, w, mr);
}

auto decode_end_transaction_request(std::string_view value, std::pmr::memory_resource *mr)
  -> result<end_transaction_request>
{
	constexpr std::string_view name = "txnEndReq";
	const auto in_value = [name](error e) {
		e.context.insert(0, e.context.empty() ? std::string(name) : detail::format("{}: ", name));
		return e;
	};
	ber::reader top(std::as_bytes(std::span(value)));
	auto r = top.enter();
	if (!r) {
		return std::unexpected(in_value(std::move(r.error())));
	}
	if (auto done = top.expect_end(); !done) {
		return std::unexpected(in_value(std::move(done.error())));
	}
	end_transaction_request out{ std::pmr::polymorphic_allocator<>(mr) };
	if (next_is(*r, ber::tags::boolean)) {
		auto commit = r->read_boolean();
		if (!commit) {
			return std::unexpected(in_value(std::move(commit.error())));
		}
		out.commit = *commit;
	}
	auto id = r->read_string(ber::tags::octet_string, mr);
	if (!id) {
		return std::unexpected(in_value(std::move(id.error())));
	}
	out.identifier = std::move(*id);
	if (auto done = skip_rest(*r); !done) {
		return std::unexpected(in_value(std::move(done.error())));
	}
	return out;
}

auto encode_end_transaction_response(const end_transaction_response &value, std::pmr::memory_resource *mr)
  -> result<std::optional<std::pmr::string>>
{
	const auto out_of_range = [](std::int32_t id) { return id < 0; };
	if ((value.message_id && out_of_range(*value.message_id))
		|| std::ranges::any_of(value.updates_controls, out_of_range, &update_controls::message_id)) {
		return fail(client_errc::encode_error, "txnEndRes: negative message id");
	}
	if (!value.message_id && value.updates_controls.empty()) {
		return std::optional<std::pmr::string>{};
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		if (value.message_id) {
			s.integer(*value.message_id);
		}
		if (!value.updates_controls.empty()) {
			s.constructed(ber::tags::sequence, [&](ber::writer &list) {
				for (const auto &u : value.updates_controls) {
					list.constructed(ber::tags::sequence, [&](ber::writer &item) {
						item.integer(u.message_id);
						item.constructed(ber::tags::sequence,
						  [&](ber::writer &controls) { detail::write_control_list(controls, u.controls); });
					});
				}
			});
		}
	});
	return std::optional<std::pmr::string>{
		std::in_place, detail::as_text(w.bytes()), std::pmr::polymorphic_allocator<>(mr)
	};
}

}// namespace jhetz::ldap::testing
