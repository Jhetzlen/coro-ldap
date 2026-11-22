#include "jhetz/ldap/message.hpp"

#include "control_util.hpp"
#include "filter_ast.hpp"
#include "format_util.hpp"
#include "pmr_util.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

namespace jhetz::ldap {

// ---------------------------------------------------------------- constructors and assignment

using detail::assign_optional;
using detail::assign_variant;
using detail::control_value;
using detail::enter_value;
using detail::in_control;
using detail::next_is;
using detail::optional_string;
using detail::optional_with;
using detail::skip_rest;
using detail::value_control;
using detail::variant_with;

namespace {

	auto strings(std::initializer_list<std::string_view> list, const string_list::allocator_type &alloc) -> string_list
	{
		// Each element built straight on `alloc`.
		return { list.begin(), list.end(), alloc };
	}

	// `before`, the peer's `text` sanitized and cut to 64 bytes, then `after`.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto sanitized_context(std::string_view before, std::string_view text, std::string_view after) -> std::string
	{
		std::string out(before);
		detail::append_sanitized(out, text, 64);
		out += after;
		return out;
	}

}// namespace

// Public API, RFC 4511 field order.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
ldap_result::ldap_result(std::int32_t result_code_,
  std::string_view matched_dn_,
  std::string_view diagnostic_message_,
  std::initializer_list<std::string_view> referral_,
  const allocator_type &alloc)
  // NOLINTEND(bugprone-easily-swappable-parameters)
  : result_code(result_code_), matched_dn(matched_dn_, alloc), diagnostic_message(diagnostic_message_, alloc),
	referral(strings(referral_, alloc))
{}

ldap_result::ldap_result(const ldap_result &other, const allocator_type &alloc)
  : result_code(other.result_code), matched_dn(other.matched_dn, alloc),
	diagnostic_message(other.diagnostic_message, alloc), referral(other.referral, alloc)
{}

ldap_result::ldap_result(ldap_result &&other, const allocator_type &alloc)
  : result_code(other.result_code), matched_dn(std::move(other.matched_dn), alloc),
	diagnostic_message(std::move(other.diagnostic_message), alloc), referral(std::move(other.referral), alloc)
{}

auto ldap_result::to_error(std::string_view context) const -> error
{
	// On the default resource (see error.hpp).
	error e;
	e.code = std::error_code(result_code, result_category());
	e.diagnostic.assign(diagnostic_message);
	if (!matched_dn.empty()) {
		e.matched_dn.emplace(matched_dn);
	}
	e.referrals.assign(referral.begin(), referral.end());
	e.context.assign(context);
	return e;
}

control::control(std::string_view type_,
  bool criticality_,
  std::optional<std::string_view> value_,
  const allocator_type &alloc)
  : type(type_, alloc), criticality(criticality_), value(optional_string(value_, alloc))
{}

control::control(const control &other, const allocator_type &alloc)
  : type(other.type, alloc), criticality(other.criticality), value(optional_with(other.value, alloc))
{}

control::control(control &&other, const allocator_type &alloc)
  : type(std::move(other.type), alloc), criticality(other.criticality),
	value(optional_with(std::move(other.value), alloc))
{}

auto control::operator=(const control &other) -> control &
{
	if (this == &other) {
		return *this;
	}
	type = other.type;
	criticality = other.criticality;
	assign_optional(value, other.value, get_allocator());
	return *this;
}

auto control::operator=(control &&other) -> control &
{
	type = std::move(other.type);
	criticality = other.criticality;
	assign_optional(value, std::move(other.value), get_allocator());
	return *this;
}

partial_attribute::partial_attribute(std::string_view type_,
  std::initializer_list<std::string_view> values_,
  const allocator_type &alloc)
  : type(type_, alloc), values(strings(values_, alloc))
{}

sasl_auth::sasl_auth(std::string_view mechanism_,
  std::optional<std::string_view> credentials_,
  const allocator_type &alloc)
  : mechanism(mechanism_, alloc), credentials(optional_string(credentials_, alloc))
{}

sasl_auth::sasl_auth(const sasl_auth &other, const allocator_type &alloc)
  : mechanism(other.mechanism, alloc), credentials(optional_with(other.credentials, alloc))
{}

sasl_auth::sasl_auth(sasl_auth &&other, const allocator_type &alloc)
  : mechanism(std::move(other.mechanism), alloc), credentials(optional_with(std::move(other.credentials), alloc))
{}

auto sasl_auth::operator=(const sasl_auth &other) -> sasl_auth &
{
	if (this == &other) {
		return *this;
	}
	mechanism = other.mechanism;
	assign_optional(credentials, other.credentials, get_allocator());
	return *this;
}

auto sasl_auth::operator=(sasl_auth &&other) -> sasl_auth &
{
	mechanism = std::move(other.mechanism);
	assign_optional(credentials, std::move(other.credentials), get_allocator());
	return *this;
}

bind_request::bind_request(std::int32_t version_,
  std::string_view name_,
  auth_type authentication_,
  const allocator_type &alloc)
  : version(version_), name(name_, alloc), authentication(variant_with(std::move(authentication_), alloc))
{}

bind_request::bind_request(const bind_request &other, const allocator_type &alloc)
  : version(other.version), name(other.name, alloc), authentication(variant_with(other.authentication, alloc))
{}

bind_request::bind_request(bind_request &&other, const allocator_type &alloc)
  : version(other.version), name(std::move(other.name), alloc),
	authentication(variant_with(std::move(other.authentication), alloc))
{}

auto bind_request::operator=(const bind_request &other) -> bind_request &
{
	if (this == &other) {
		return *this;
	}
	version = other.version;
	name = other.name;
	assign_variant(authentication, other.authentication, get_allocator());
	return *this;
}

auto bind_request::operator=(bind_request &&other) -> bind_request &
{
	version = other.version;
	name = std::move(other.name);
	assign_variant(authentication, std::move(other.authentication), get_allocator());
	return *this;
}

bind_response::bind_response(const ldap_result &result_,
  std::optional<std::string_view> server_sasl_creds_,
  const allocator_type &alloc)
  : result(result_, alloc), server_sasl_creds(optional_string(server_sasl_creds_, alloc))
{}

bind_response::bind_response(const bind_response &other, const allocator_type &alloc)
  : result(other.result, alloc), server_sasl_creds(optional_with(other.server_sasl_creds, alloc))
{}

bind_response::bind_response(bind_response &&other, const allocator_type &alloc)
  : result(std::move(other.result), alloc), server_sasl_creds(optional_with(std::move(other.server_sasl_creds), alloc))
{}

auto bind_response::operator=(const bind_response &other) -> bind_response &
{
	if (this == &other) {
		return *this;
	}
	result = other.result;
	assign_optional(server_sasl_creds, other.server_sasl_creds, get_allocator());
	return *this;
}

auto bind_response::operator=(bind_response &&other) -> bind_response &
{
	result = std::move(other.result);
	assign_optional(server_sasl_creds, std::move(other.server_sasl_creds), get_allocator());
	return *this;
}

search_request::search_request(const allocator_type &alloc)
  : base_object(alloc), filter(filters::attr("objectClass", alloc).present()), attributes(alloc)
{}

search_request::search_request(std::string_view base_object_,
  search_scope scope_,
  ldap::filter filter_,
  std::initializer_list<std::string_view> attributes_,
  const allocator_type &alloc)
  : base_object(base_object_, alloc), scope(scope_), filter(std::move(filter_), alloc),
	attributes(strings(attributes_, alloc))
{}

search_request::search_request(const search_request &other, const allocator_type &alloc)
  : base_object(other.base_object, alloc), scope(other.scope), deref(other.deref), size_limit(other.size_limit),
	time_limit(other.time_limit), types_only(other.types_only), filter(other.filter, alloc),
	attributes(other.attributes, alloc)
{}

search_request::search_request(search_request &&other, const allocator_type &alloc)
  : base_object(std::move(other.base_object), alloc), scope(other.scope), deref(other.deref),
	size_limit(other.size_limit), time_limit(other.time_limit), types_only(other.types_only),
	filter(std::move(other.filter), alloc), attributes(std::move(other.attributes), alloc)
{}

// Public API, RFC 4511 field order.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
modify_dn_request::modify_dn_request(std::string_view entry_,
  std::string_view new_rdn_,
  bool delete_old_rdn_,
  std::optional<std::string_view> new_superior_,
  const allocator_type &alloc)
  : entry(entry_, alloc), new_rdn(new_rdn_, alloc), delete_old_rdn(delete_old_rdn_),
	new_superior(optional_string(new_superior_, alloc))
{}

modify_dn_request::modify_dn_request(const modify_dn_request &other, const allocator_type &alloc)
  : entry(other.entry, alloc), new_rdn(other.new_rdn, alloc), delete_old_rdn(other.delete_old_rdn),
	new_superior(optional_with(other.new_superior, alloc))
{}

modify_dn_request::modify_dn_request(modify_dn_request &&other, const allocator_type &alloc)
  : entry(std::move(other.entry), alloc), new_rdn(std::move(other.new_rdn), alloc),
	delete_old_rdn(other.delete_old_rdn), new_superior(optional_with(std::move(other.new_superior), alloc))
{}

auto modify_dn_request::operator=(const modify_dn_request &other) -> modify_dn_request &
{
	if (this == &other) {
		return *this;
	}
	entry = other.entry;
	new_rdn = other.new_rdn;
	delete_old_rdn = other.delete_old_rdn;
	assign_optional(new_superior, other.new_superior, get_allocator());
	return *this;
}

auto modify_dn_request::operator=(modify_dn_request &&other) -> modify_dn_request &
{
	entry = std::move(other.entry);
	new_rdn = std::move(other.new_rdn);
	delete_old_rdn = other.delete_old_rdn;
	assign_optional(new_superior, std::move(other.new_superior), get_allocator());
	return *this;
}

extended_request::extended_request(std::string_view request_name_,
  std::optional<std::string_view> request_value_,
  const allocator_type &alloc)
  : request_name(request_name_, alloc), request_value(optional_string(request_value_, alloc))
{}

extended_request::extended_request(const extended_request &other, const allocator_type &alloc)
  : request_name(other.request_name, alloc), request_value(optional_with(other.request_value, alloc))
{}

extended_request::extended_request(extended_request &&other, const allocator_type &alloc)
  : request_name(std::move(other.request_name), alloc),
	request_value(optional_with(std::move(other.request_value), alloc))
{}

auto extended_request::operator=(const extended_request &other) -> extended_request &
{
	if (this == &other) {
		return *this;
	}
	request_name = other.request_name;
	assign_optional(request_value, other.request_value, get_allocator());
	return *this;
}

auto extended_request::operator=(extended_request &&other) -> extended_request &
{
	request_name = std::move(other.request_name);
	assign_optional(request_value, std::move(other.request_value), get_allocator());
	return *this;
}

// Public API, RFC 4511 field order.
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
extended_response::extended_response(const ldap_result &result_,
  std::optional<std::string_view> response_name_,
  std::optional<std::string_view> response_value_,
  const allocator_type &alloc)
  // NOLINTEND(bugprone-easily-swappable-parameters)
  : result(result_, alloc), response_name(optional_string(response_name_, alloc)),
	response_value(optional_string(response_value_, alloc))
{}

extended_response::extended_response(const extended_response &other, const allocator_type &alloc)
  : result(other.result, alloc), response_name(optional_with(other.response_name, alloc)),
	response_value(optional_with(other.response_value, alloc))
{}

extended_response::extended_response(extended_response &&other, const allocator_type &alloc)
  : result(std::move(other.result), alloc), response_name(optional_with(std::move(other.response_name), alloc)),
	response_value(optional_with(std::move(other.response_value), alloc))
{}

auto extended_response::operator=(const extended_response &other) -> extended_response &
{
	if (this == &other) {
		return *this;
	}
	result = other.result;
	assign_optional(response_name, other.response_name, get_allocator());
	assign_optional(response_value, other.response_value, get_allocator());
	return *this;
}

auto extended_response::operator=(extended_response &&other) -> extended_response &
{
	result = std::move(other.result);
	assign_optional(response_name, std::move(other.response_name), get_allocator());
	assign_optional(response_value, std::move(other.response_value), get_allocator());
	return *this;
}

// Public API, RFC 4511 field order.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
intermediate_response::intermediate_response(std::optional<std::string_view> response_name_,
  std::optional<std::string_view> response_value_,
  const allocator_type &alloc)
  : response_name(optional_string(response_name_, alloc)), response_value(optional_string(response_value_, alloc)),
	alloc_(alloc)
{}

// A plain copy uses the default resource, like the pmr containers.
intermediate_response::intermediate_response(const intermediate_response &other)
  : intermediate_response(other, allocator_type{})
{}

intermediate_response::intermediate_response(const intermediate_response &other, const allocator_type &alloc)
  : response_name(optional_with(other.response_name, alloc)),
	response_value(optional_with(other.response_value, alloc)), alloc_(alloc)
{}

intermediate_response::intermediate_response(intermediate_response &&other, const allocator_type &alloc)
  : response_name(optional_with(std::move(other.response_name), alloc)),
	response_value(optional_with(std::move(other.response_value), alloc)), alloc_(alloc)
{}

auto intermediate_response::operator=(const intermediate_response &other) -> intermediate_response &
{
	if (this == &other) {
		return *this;
	}
	assign_optional(response_name, other.response_name, alloc_);
	assign_optional(response_value, other.response_value, alloc_);
	return *this;
}

auto intermediate_response::operator=(intermediate_response &&other) -> intermediate_response &
{
	assign_optional(response_name, std::move(other.response_name), alloc_);
	assign_optional(response_value, std::move(other.response_value), alloc_);
	return *this;
}

message::message(const allocator_type &alloc) : op(std::in_place_type<bind_request>, alloc), controls(alloc) {}

message::message(std::int32_t id_,
  protocol_op op_,
  std::initializer_list<control> controls_,
  const allocator_type &alloc)
  : id(id_), op(variant_with(std::move(op_), alloc)), controls(controls_, alloc)
{}

message::message(const message &other, const allocator_type &alloc)
  : id(other.id), op(variant_with(other.op, alloc)), controls(other.controls, alloc)
{}

message::message(message &&other, const allocator_type &alloc)
  : id(other.id), op(variant_with(std::move(other.op), alloc)), controls(std::move(other.controls), alloc)
{}

auto message::operator=(const message &other) -> message &
{
	if (this == &other) {
		return *this;
	}
	id = other.id;
	assign_variant(op, other.op, get_allocator());
	controls = other.controls;
	return *this;
}

auto message::operator=(message &&other) -> message &
{
	id = other.id;
	assign_variant(op, std::move(other.op), get_allocator());
	controls = std::move(other.controls);
	return *this;
}

namespace {

	namespace op_tag = detail::op_tag;

	// Context tag numbers of operation fields (RFC 4511 sections 4.2.2 and
	// 4.12).
	namespace field_tag {
		constexpr std::uint8_t server_sasl_creds = 7;// BindResponse
		constexpr std::uint8_t response_name = 10;// ExtendedResponse
		constexpr std::uint8_t response_value = 11;
	}// namespace field_tag

	// BindRequest's version INTEGER (1 .. 127) (RFC 4511 section 4.2).
	constexpr std::int64_t max_bind_version = 127;

	auto bad(std::string_view what, std::size_t offset) -> std::unexpected<error>
	{
		return fail(client_errc::decode_error, detail::format("message: {} at offset {}", what, offset));
	}

	// ---------------------------------------------------------------- encoder

	auto out_of_range(const char *what) -> std::unexpected<error>
	{
		return fail(client_errc::encode_error, detail::format("message: {} out of range", what));
	}

	// The operations a client sends (RFC 4511 section 4.2 protocolOp requests).
	template<class T>
	constexpr bool is_request_v =
	  std::is_same_v<T, bind_request> || std::is_same_v<T, unbind_request> || std::is_same_v<T, search_request>
	  || std::is_same_v<T, modify_request> || std::is_same_v<T, add_request> || std::is_same_v<T, del_request>
	  || std::is_same_v<T, modify_dn_request> || std::is_same_v<T, compare_request>
	  || std::is_same_v<T, abandon_request> || std::is_same_v<T, extended_request>;

	// By protocol_op::index(): safe on a valueless op.
	auto is_request_op(const protocol_op &op) noexcept -> bool
	{
		const std::size_t index = op.index();// variant_npos when valueless
		return [index]<std::size_t... I>(std::index_sequence<I...>) -> bool {
			return ((index == I && is_request_v<std::variant_alternative_t<I, protocol_op>>) || ...);
		}(std::make_index_sequence<std::variant_size_v<protocol_op>>{});
	}

	// Checks everything encoding could reject, before the writer is touched.
	auto precheck(const message &m) -> result<void>
	{
		if (m.id < 0) {
			return out_of_range("message id");
		}
		// RFC 4511 section 4.1.1: id 0 is reserved for unsolicited notifications.
		if (m.id == 0 && is_request_op(m.op)) {
			return fail(client_errc::encode_error, "message: a request with message id 0");
		}
		if (const auto *s = std::get_if<search_request>(&m.op)) {
			const auto scope = std::to_underlying(s->scope);
			const auto deref = std::to_underlying(s->deref);
			if (scope < 0 || scope > 3) {
				return out_of_range("search scope");
			}
			if (deref < 0 || deref > 3) {
				return out_of_range("derefAliases");
			}
			if (s->size_limit < 0) {
				return out_of_range("size limit");
			}
			if (s->time_limit < 0) {
				return out_of_range("time limit");
			}
			return detail::check_filter(s->filter, {});
		}
		if (const auto *b = std::get_if<bind_request>(&m.op)) {
			if (b->version < 1 || b->version > max_bind_version) {
				return out_of_range("bind version");
			}
		} else if (const auto *a = std::get_if<abandon_request>(&m.op)) {
			if (a->message_id < 0) {
				return out_of_range("abandoned message id");
			}
		} else if (const auto *mod = std::get_if<modify_request>(&m.op)) {
			for (const auto &c : mod->changes) {
				const auto op = std::to_underlying(c.operation);
				if (op < 0 || op > 3) {
					return out_of_range("modify operation");
				}
				if (c.operation == modify_operation::add && c.modification.values.empty()) {
					return fail(client_errc::encode_error, "message: modify add change without values");
				}
			}
		} else if (const auto *add = std::get_if<add_request>(&m.op)) {
			for (const auto &attr : add->attributes) {
				if (attr.values.empty()) {
					return fail(client_errc::encode_error, "message: add request attribute without values");
				}
			}
		} else if (const auto *ref = std::get_if<search_result_reference>(&m.op); ref != nullptr && ref->uris.empty()) {
			return fail(client_errc::encode_error, "message: search result reference without a URI");
		}
		return {};
	}

	void write_result(ber::writer &w, const ldap_result &r)
	{
		w.enumerated(r.result_code);
		w.octet_string(r.matched_dn);
		w.octet_string(r.diagnostic_message);
		if (!r.referral.empty()) {
			w.constructed(ber::context(3), [&](ber::writer &ref) {
				for (const auto &uri : r.referral) {
					ref.octet_string(uri);
				}
			});
		}
	}

	void write_attribute(ber::writer &w, const partial_attribute &a)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &pa) {
			pa.octet_string(a.type);
			pa.constructed(ber::tags::set, [&](ber::writer &vals) {
				for (const auto &v : a.values) {
					vals.octet_string(v);
				}
			});
		});
	}

	void write_attributes(ber::writer &w, const std::pmr::vector<partial_attribute> &attrs)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &a : attrs) {
				write_attribute(list, a);
			}
		});
	}

	struct op_writer
	{
		ber::writer *w;// non-null

		template<class F> void seq(std::uint8_t number, F &&body) const
		{
			w->constructed(ber::application(number), std::forward<F>(body));
		}

		template<std::uint8_t Tag> void operator()(const result_response<Tag> &r) const
		{
			seq(Tag, [&](ber::writer &o) { write_result(o, r.result); });
		}

		void operator()(const bind_request &b) const
		{
			seq(op_tag::bind_request, [&](ber::writer &o) {
				o.integer(b.version);
				o.octet_string(b.name);
				if (const auto *simple = std::get_if<simple_auth>(&b.authentication)) {
					o.octet_string(simple->password, ber::context(0));
				} else {
					const auto &sasl = std::get<sasl_auth>(b.authentication);
					o.constructed(ber::context(3), [&](ber::writer &s) {
						s.octet_string(sasl.mechanism);
						if (sasl.credentials) {
							s.octet_string(*sasl.credentials);
						}
					});
				}
			});
		}
		void operator()(const bind_response &b) const
		{
			seq(op_tag::bind_response, [&](ber::writer &o) {
				write_result(o, b.result);
				if (b.server_sasl_creds) {
					o.octet_string(*b.server_sasl_creds, ber::context(field_tag::server_sasl_creds));
				}
			});
		}
		void operator()(const unbind_request &) const { w->null(ber::application(op_tag::unbind_request)); }
		void operator()(const search_request &s) const
		{
			seq(op_tag::search_request, [&](ber::writer &o) {
				o.octet_string(s.base_object);
				o.enumerated(std::to_underlying(s.scope));
				o.enumerated(std::to_underlying(s.deref));
				o.integer(s.size_limit);
				o.integer(s.time_limit);
				o.boolean(s.types_only);
				detail::write_filter(o, s.filter);// checked by precheck
				o.constructed(ber::tags::sequence, [&](ber::writer &attrs) {
					for (const auto &a : s.attributes) {
						attrs.octet_string(a);
					}
				});
			});
		}
		void operator()(const search_result_entry &e) const
		{
			seq(op_tag::search_result_entry, [&](ber::writer &o) {
				o.octet_string(e.object_name);
				write_attributes(o, e.attributes);
			});
		}
		void operator()(const search_result_reference &r) const
		{
			seq(op_tag::search_result_reference, [&](ber::writer &o) {
				for (const auto &uri : r.uris) {
					o.octet_string(uri);
				}
			});
		}
		void operator()(const modify_request &m) const
		{
			seq(op_tag::modify_request, [&](ber::writer &o) {
				o.octet_string(m.object);
				o.constructed(ber::tags::sequence, [&](ber::writer &changes) {
					for (const auto &c : m.changes) {
						changes.constructed(ber::tags::sequence, [&](ber::writer &change) {
							change.enumerated(std::to_underlying(c.operation));
							write_attribute(change, c.modification);
						});
					}
				});
			});
		}
		void operator()(const add_request &a) const
		{
			seq(op_tag::add_request, [&](ber::writer &o) {
				o.octet_string(a.entry);
				write_attributes(o, a.attributes);
			});
		}
		void operator()(const del_request &d) const { w->octet_string(d.entry, ber::application(op_tag::del_request)); }
		void operator()(const modify_dn_request &m) const
		{
			seq(op_tag::modify_dn_request, [&](ber::writer &o) {
				o.octet_string(m.entry);
				o.octet_string(m.new_rdn);
				o.boolean(m.delete_old_rdn);
				if (m.new_superior) {
					o.octet_string(*m.new_superior, ber::context(0));
				}
			});
		}
		void operator()(const compare_request &c) const
		{
			seq(op_tag::compare_request, [&](ber::writer &o) {
				o.octet_string(c.entry);
				o.constructed(ber::tags::sequence, [&](ber::writer &ava) {
					ava.octet_string(c.ava.attribute_desc);
					ava.octet_string(c.ava.assertion_value);
				});
			});
		}
		void operator()(const abandon_request &a) const
		{
			w->integer(a.message_id, ber::application(op_tag::abandon_request));
		}
		void operator()(const extended_request &e) const
		{
			seq(op_tag::extended_request, [&](ber::writer &o) {
				o.octet_string(e.request_name, ber::context(0));
				if (e.request_value) {
					o.octet_string(*e.request_value, ber::context(1));
				}
			});
		}
		void operator()(const extended_response &e) const
		{
			seq(op_tag::extended_response, [&](ber::writer &o) {
				write_result(o, e.result);
				if (e.response_name) {
					o.octet_string(*e.response_name, ber::context(field_tag::response_name));
				}
				if (e.response_value) {
					o.octet_string(*e.response_value, ber::context(field_tag::response_value));
				}
			});
		}
		void operator()(const intermediate_response &i) const
		{
			seq(op_tag::intermediate_response, [&](ber::writer &o) {
				if (i.response_name) {
					o.octet_string(*i.response_name, ber::context(0));
				}
				if (i.response_value) {
					o.octet_string(*i.response_value, ber::context(1));
				}
			});
		}
	};

	// ---------------------------------------------------------------- decoder

	auto read_ranged(ber::reader &r,
	  ber::tag t,
	  std::int64_t lo,
	  std::int64_t hi,
	  const char *what,
	  bool enumerated = false) -> result<std::int32_t>
	{
		const std::size_t offset = r.offset();
		auto copy = r;
		auto v = enumerated ? copy.read_enumerated(t) : copy.read_integer(t);
		if (!v) {
			return std::unexpected(std::move(v.error()));
		}
		if (*v < lo || *v > hi) {
			return bad(detail::format("{} {} outside {}..{}", what, *v, lo, hi), offset);
		}
		r = copy;
		return static_cast<std::int32_t>(*v);
	}

	using alloc_t = std::pmr::polymorphic_allocator<>;

	// Leading elements of tag `t` and at least `min_size` bytes, up to `limit`,
	// to reserve vectors exactly.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto count_elements(ber::reader r, ber::tag t, std::size_t min_size, std::size_t limit) -> std::size_t
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
	constexpr std::size_t min_value_size = 2;
	constexpr std::size_t min_attribute_size = 6;

	// Decodes into `a` (decode_options::memory), moving the parts in.
	class decoder
	{
	  public:
		explicit decoder(const decode_options &options) : options_(&options), a_(options.memory) {}

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
					return bad("request with message id 0", r->offset());
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

	  private:
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

		auto read_bind_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<bind_request>, a_);
			auto &b = std::get<bind_request>(op);
			auto version = read_ranged(*o, ber::tags::integer, 1, max_bind_version, "bind version");
			if (!version) {
				return std::unexpected(std::move(version.error()));
			}
			auto name = str(*o);
			if (!name) {
				return std::unexpected(std::move(name.error()));
			}
			b.version = *version;
			b.name = std::move(*name);
			const std::size_t auth_at = o->offset();
			if (next_is(*o, ber::context(0))) {
				auto password = str(*o, ber::context(0));
				if (!password) {
					return std::unexpected(std::move(password.error()));
				}
				std::get<simple_auth>(b.authentication).password = std::move(*password);
			} else if (next_is(*o, ber::context(3))) {
				auto s = o->enter(ber::context(3));
				if (!s) {
					return std::unexpected(std::move(s.error()));
				}
				auto mechanism = str(*s);
				if (!mechanism) {
					return std::unexpected(std::move(mechanism.error()));
				}
				auto credentials = optional_str(*s, ber::tags::octet_string);
				if (!credentials) {
					return std::unexpected(std::move(credentials.error()));
				}
				if (auto done = skip_rest(*s); !done) {
					return std::unexpected(std::move(done.error()));
				}
				auto &sasl = b.authentication.emplace<sasl_auth>(a_);
				sasl.mechanism = std::move(*mechanism);
				sasl.credentials = std::move(*credentials);
			} else {
				if (o->empty()) {
					return bad("bind request without authentication", auth_at);
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

		auto read_search_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<search_request>, a_);
			auto &s = std::get<search_request>(op);
			auto base = str(*o);
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
			auto f = decode_filter(*o, options_->filter, a_.resource());
			if (!f) {
				return std::unexpected(std::move(f.error()));
			}
			auto attrs = o->enter();
			if (!attrs) {
				return std::unexpected(std::move(attrs.error()));
			}
			while (!attrs->empty()) {
				auto a = str(*attrs);
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
				return bad("search result reference without a URI", o->offset());
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

		auto read_modify_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<modify_request>, a_);
			auto &m = std::get<modify_request>(op);
			auto object = str(*o);
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
				if (auto done = read_attribute(*change, c.modification); !done) {
					return std::unexpected(std::move(done.error()));
				}
				if (c.operation == modify_operation::add && c.modification.values.empty()) {
					return bad("modify add change without values", attr_at);
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

		auto read_add_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<add_request>, a_);
			auto &add = std::get<add_request>(op);
			auto entry = str(*o);
			if (!entry) {
				return std::unexpected(std::move(entry.error()));
			}
			add.entry = std::move(*entry);
			const std::size_t attrs_at = o->offset();
			if (auto done = read_attributes(*o, add.attributes); !done) {
				return std::unexpected(std::move(done.error()));
			}
			for (const auto &a : add.attributes) {
				if (a.values.empty()) {
					return bad(sanitized_context("add request attribute '", a.type, "' without values"), attrs_at);
				}
			}
			if (auto done = skip_rest(*o); !done) {
				return std::unexpected(std::move(done.error()));
			}
			return op;
		}

		auto read_modify_dn_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<modify_dn_request>, a_);
			auto &m = std::get<modify_dn_request>(op);
			auto entry = str(*o);
			if (!entry) {
				return std::unexpected(std::move(entry.error()));
			}
			auto new_rdn = str(*o);
			if (!new_rdn) {
				return std::unexpected(std::move(new_rdn.error()));
			}
			auto delete_old = o->read_boolean();
			if (!delete_old) {
				return std::unexpected(std::move(delete_old.error()));
			}
			auto superior = optional_str(*o, ber::context(0));
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

		auto read_compare_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<compare_request>, a_);
			auto &c = std::get<compare_request>(op);
			auto entry = str(*o);
			if (!entry) {
				return std::unexpected(std::move(entry.error()));
			}
			auto ava = o->enter();
			if (!ava) {
				return std::unexpected(std::move(ava.error()));
			}
			auto desc = str(*ava);
			if (!desc) {
				return std::unexpected(std::move(desc.error()));
			}
			auto value = str(*ava);
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

		auto read_extended_request(ber::reader &r, ber::tag t) -> result<protocol_op>
		{
			auto o = r.enter(t);
			if (!o) {
				return std::unexpected(std::move(o.error()));
			}
			protocol_op op(std::in_place_type<extended_request>, a_);
			auto &e = std::get<extended_request>(op);
			auto name = str(*o, ber::context(0));
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
			e.request_name = std::move(*name);
			e.request_value = std::move(*value);
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
			const auto unsupported = [&] {
				return fail(client_errc::unsupported_operation,
				  detail::format("message: unknown protocolOp {} at offset {}", ber::to_string(t), offset));
			};
			if (t.cls != ber::tag_class::application) {
				return unsupported();
			}
			// Checked before decoding, so a peer cannot make us parse (for
			// example) a huge search request filter it may not send at all.
			if (options_->from == origin::server && is_request(t.number)) {
				return fail(client_errc::unsupported_operation,
				  detail::format(
					"message: request operation {} from a server at offset {}", ber::to_string(t), offset));
			}
			if (options_->from == origin::client && !is_request(t.number)) {
				return fail(client_errc::unsupported_operation,
				  detail::format(
					"message: response operation {} from a client at offset {}", ber::to_string(t), offset));
			}
			switch (t.number) {
			case op_tag::bind_request:
				return read_bind_request(r, t);
			case op_tag::bind_response:
				return read_bind_response(r, t);
			case op_tag::unbind_request: {
				if (auto done = r.read_null(t); !done) {
					return std::unexpected(std::move(done.error()));
				}
				return protocol_op{ unbind_request{} };
			}
			case op_tag::search_request:
				return read_search_request(r, t);
			case op_tag::search_result_entry:
				return read_search_result_entry(r, t);
			case op_tag::search_result_done:
				return result_only<search_result_done>(r, t);
			case op_tag::search_result_reference:
				return read_search_result_reference(r, t);
			case op_tag::modify_request:
				return read_modify_request(r, t);
			case op_tag::modify_response:
				return result_only<modify_response>(r, t);
			case op_tag::add_request:
				return read_add_request(r, t);
			case op_tag::add_response:
				return result_only<add_response>(r, t);
			case op_tag::del_request: {
				auto entry = str(r, t);
				if (!entry) {
					return std::unexpected(std::move(entry.error()));
				}
				protocol_op op(std::in_place_type<del_request>, a_);
				std::get<del_request>(op).entry = std::move(*entry);
				return op;
			}
			case op_tag::del_response:
				return result_only<del_response>(r, t);
			case op_tag::modify_dn_request:
				return read_modify_dn_request(r, t);
			case op_tag::modify_dn_response:
				return result_only<modify_dn_response>(r, t);
			case op_tag::compare_request:
				return read_compare_request(r, t);
			case op_tag::compare_response:
				return result_only<compare_response>(r, t);
			case op_tag::abandon_request: {
				auto id = read_ranged(r, t, 0, max_int, "abandoned message id");
				if (!id) {
					return std::unexpected(std::move(id.error()));
				}
				return protocol_op{ abandon_request{ *id } };
			}
			case op_tag::extended_request:
				return read_extended_request(r, t);
			case op_tag::extended_response:
				return read_extended_response(r, t);
			case op_tag::intermediate_response:
				return read_intermediate_response(r, t);
			default:
				return unsupported();
			}
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
		alloc_t a_;
		std::size_t strings_ = 0;// decoded by str(), against options_->max_elements
	};

}// namespace

namespace {

	void write_control_list(ber::writer &list, const std::pmr::vector<control> &controls)
	{
		for (const auto &c : controls) {
			list.constructed(ber::tags::sequence, [&](ber::writer &cw) {
				cw.octet_string(c.type);
				if (c.criticality) {
					cw.boolean(true);
				}
				if (c.value) {
					cw.octet_string(*c.value);
				}
			});
		}
	}

}// namespace

auto encode(ber::writer &w, const message &m) -> result<void>
{
	if (auto done = precheck(m); !done) {
		return std::unexpected(std::move(done.error()));
	}
	w.constructed(ber::tags::sequence, [&](ber::writer &msg) {
		msg.integer(m.id);
		std::visit(op_writer{ &msg }, m.op);
		if (!m.controls.empty()) {
			msg.constructed(ber::context(0), [&](ber::writer &list) { write_control_list(list, m.controls); });
		}
	});
	return {};
}

auto encode(const message &m, std::pmr::memory_resource *mr) -> result<std::pmr::vector<std::byte>>
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	// Most requests fit; saves the first few doublings of the buffer.
	w.reserve(256);
	if (auto done = encode(w, m); !done) {
		return std::unexpected(std::move(done.error()));
	}
	return w.take();
}

auto decode(std::span<const std::byte> one_complete_message, const decode_options &options) -> result<message>
{
	return decoder(options).run(one_complete_message);
}

auto peek_message_header(std::span<const std::byte> one_complete_message) -> result<message_header>
{
	ber::reader top(one_complete_message);
	auto r = top.enter();
	if (!r) {
		return std::unexpected(std::move(r.error()));
	}
	auto id = read_ranged(*r, ber::tags::integer, 0, max_int, "message id");
	if (!id) {
		return std::unexpected(std::move(id.error()));
	}
	if (r->empty()) {
		return fail(client_errc::decode_error, "LDAPMessage without a protocolOp");
	}
	auto op = r->peek_tag();
	if (!op) {
		return std::unexpected(std::move(op.error()));
	}
	return message_header{ .id = *id, .op = *op };
}

// ---------------------------------------------------------------- paged results

auto encode_paged_results(const paged_results &value, bool criticality, std::pmr::memory_resource *mr)
  -> result<control>
{
	if (value.size < 0) {
		return fail(client_errc::encode_error, "paged results: negative size");
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(value.size);
		s.octet_string(value.cookie);
	});
	return control(paged_results_oid, criticality, detail::as_text(w.bytes()), control::allocator_type(mr));
}

namespace {

	// realSearchControlValue ::= SEQUENCE { size INTEGER (0..maxInt), cookie OCTET STRING }
	auto read_paged_results(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<paged_results>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto size = read_ranged(*s, ber::tags::integer, 0, max_int, "size");
		if (!size) {
			return std::unexpected(std::move(size.error()));
		}
		auto cookie = s->read_string(ber::tags::octet_string, mr);
		if (!cookie) {
			return std::unexpected(std::move(cookie.error()));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		paged_results out{ paged_results::allocator_type(mr) };
		out.size = *size;
		out.cookie = std::move(*cookie);
		return out;
	}

}// namespace

auto decode_paged_results(const control &c, std::pmr::memory_resource *mr) -> result<paged_results>
{
	auto value = control_value(c, paged_results_oid, "paged results");
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(read_paged_results(*value, mr), "paged results");
}

// ---------------------------------------------------------------- server side sorting

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

namespace {

	// SortResult ::= SEQUENCE { sortResult ENUMERATED, attributeType [0] AttributeDescription OPTIONAL }
	auto read_sort_result(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<sort_result>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto code = read_ranged(*s,
		  ber::tags::enumerated,
		  std::numeric_limits<std::int32_t>::min(),
		  std::numeric_limits<std::int32_t>::max(),
		  "sortResult",
		  true);
		if (!code) {
			return std::unexpected(std::move(code.error()));
		}
		sort_result out{ sort_result::allocator_type(mr) };
		out.result_code = *code;
		if (next_is(*s, ber::context(0))) {
			auto type = s->read_string(ber::context(0), mr);
			if (!type) {
				return std::unexpected(std::move(type.error()));
			}
			out.attribute_type = std::move(*type);
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

}// namespace

auto decode_sort_result(const control &c, std::pmr::memory_resource *mr) -> result<sort_result>
{
	auto value = control_value(c, sort_response_oid, "sort result");
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(read_sort_result(*value, mr), "sort result");
}

// ---------------------------------------------------------------- virtual list view

// Public API, VirtualListViewResponse field order (draft-ietf-ldapext-ldapv3-vlv-09 section 6.2).
// NOLINTBEGIN(bugprone-easily-swappable-parameters)
vlv_response::vlv_response(std::int32_t target_position_,
  std::int32_t content_count_,
  std::int32_t result_code_,
  std::optional<std::string_view> context_id_,
  const allocator_type &alloc)
  // NOLINTEND(bugprone-easily-swappable-parameters)
  : target_position(target_position_), content_count(content_count_), result_code(result_code_),
	context_id(detail::optional_string(context_id_, alloc)), alloc_(alloc)
{}

// A plain copy uses the default resource, like the pmr containers.
vlv_response::vlv_response(const vlv_response &other) : vlv_response(other, allocator_type{}) {}

vlv_response::vlv_response(const vlv_response &other, const allocator_type &alloc)
  : target_position(other.target_position), content_count(other.content_count), result_code(other.result_code),
	context_id(detail::optional_with(other.context_id, alloc)), alloc_(alloc)
{}

vlv_response::vlv_response(vlv_response &&other, const allocator_type &alloc)
  : target_position(other.target_position), content_count(other.content_count), result_code(other.result_code),
	context_id(detail::optional_with(std::move(other.context_id), alloc)), alloc_(alloc)
{}

auto vlv_response::operator=(const vlv_response &other) -> vlv_response &
{
	if (this == &other) {
		return *this;
	}
	target_position = other.target_position;
	content_count = other.content_count;
	result_code = other.result_code;
	detail::assign_optional(context_id, other.context_id, alloc_);
	return *this;
}

auto vlv_response::operator=(vlv_response &&other) -> vlv_response &
{
	if (this == &other) {
		return *this;
	}
	target_position = other.target_position;
	content_count = other.content_count;
	result_code = other.result_code;
	detail::assign_optional(context_id, std::move(other.context_id), alloc_);
	return *this;
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

namespace {

	// VirtualListViewResponse ::= SEQUENCE { targetPosition INTEGER (0 .. maxInt),
	//   contentCount INTEGER (0 .. maxInt), virtualListViewResult ENUMERATED,
	//   contextID OCTET STRING OPTIONAL }
	auto read_vlv_response(std::span<const std::byte> value, std::pmr::memory_resource *mr) -> result<vlv_response>
	{
		ber::reader r(value);
		auto s = enter_value(r);
		if (!s) {
			return std::unexpected(std::move(s.error()));
		}
		auto position = read_ranged(*s, ber::tags::integer, 0, max_int, "targetPosition");
		if (!position) {
			return std::unexpected(std::move(position.error()));
		}
		auto count = read_ranged(*s, ber::tags::integer, 0, max_int, "contentCount");
		if (!count) {
			return std::unexpected(std::move(count.error()));
		}
		auto code = read_ranged(*s,
		  ber::tags::enumerated,
		  std::numeric_limits<std::int32_t>::min(),
		  std::numeric_limits<std::int32_t>::max(),
		  "virtualListViewResult",
		  true);
		if (!code) {
			return std::unexpected(std::move(code.error()));
		}
		vlv_response out{ vlv_response::allocator_type(mr) };
		out.target_position = *position;
		out.content_count = *count;
		out.result_code = *code;
		if (next_is(*s, ber::tags::octet_string)) {
			auto id = s->read_string(ber::tags::octet_string, mr);
			if (!id) {
				return std::unexpected(std::move(id.error()));
			}
			out.context_id.emplace(std::move(*id));
		}
		if (auto done = skip_rest(*s); !done) {
			return std::unexpected(std::move(done.error()));
		}
		return out;
	}

}// namespace

auto decode_vlv_response(const control &c, std::pmr::memory_resource *mr) -> result<vlv_response>
{
	auto value = control_value(c, vlv_response_oid, "vlv response");
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(read_vlv_response(*value, mr), "vlv response");
}

// ---------------------------------------------------------------- pre-read / post-read

auto encode_read_entry(std::string_view oid,
  const search_result_entry &entry,
  bool criticality,
  std::pmr::memory_resource *mr) -> result<control>
{
	if (oid != pre_read_oid && oid != post_read_oid) {
		return fail(
		  client_errc::encode_error, sanitized_context("read entry control: ", oid, " is not pre-read or post-read"));
	}
	ber::writer w{ ber::writer::allocator_type(mr) };
	op_writer{ &w }(entry);
	return value_control(oid, criticality, w, mr);
}

auto decode_read_entry(const control &c, const decode_options &options) -> result<search_result_entry>
{
	if (c.type != pre_read_oid && c.type != post_read_oid) {
		return fail(client_errc::decode_error,
		  sanitized_context("read entry: control type is ", c.type, ", not pre-read or post-read"));
	}
	const std::string_view name = c.type == pre_read_oid ? "pre-read" : "post-read";
	auto value = control_value(c, c.type, name);
	if (!value) {
		return std::unexpected(std::move(value.error()));
	}
	return in_control(decoder(options).run_entry(*value), name);
}

// ---------------------------------------------------------------- transactions (RFC 5805)

auto encode_end_transaction_request(const end_transaction_request &value, std::pmr::memory_resource *mr)
  -> std::pmr::string
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		if (!value.commit) {
			s.boolean(false);
		}
		s.octet_string(value.identifier);
	});
	return std::pmr::string(detail::as_text(w.bytes()), std::pmr::polymorphic_allocator<>(mr));
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
						  [&](ber::writer &controls) { write_control_list(controls, u.controls); });
					});
				}
			});
		}
	});
	return std::optional<std::pmr::string>{
		std::in_place, detail::as_text(w.bytes()), std::pmr::polymorphic_allocator<>(mr)
	};
}

auto decode_end_transaction_response(std::string_view value, const decode_options &options)
  -> result<end_transaction_response>
{
	return in_control(decoder(options).run_end_transaction(std::as_bytes(std::span(value))), "txnEndRes");
}

}// namespace jhetz::ldap
