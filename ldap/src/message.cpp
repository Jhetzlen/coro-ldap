#include "jhetz/ldap/message.hpp"

#include "filter_ast.hpp"
#include "pmr_util.hpp"

#include <limits>
#include <utility>

// Early return on failure: `LDAP_TRY(x, expr);` declares `x` from a result.
#define LDAP_TRY(var, expr)                                                       \
	auto var##_result_ = (expr);                                                  \
	if (!var##_result_) return std::unexpected(std::move(var##_result_.error())); \
	auto var = std::move(*var##_result_)

#define LDAP_TRY_VOID(expr)                                                       \
	do {                                                                          \
		auto try_result_ = (expr);                                                \
		if (!try_result_) return std::unexpected(std::move(try_result_.error())); \
	} while (false)

namespace jhetz::ldap {

// ---------------------------------------------------------------- constructors and assignment

using detail::assign_optional;
using detail::assign_variant;
using detail::optional_string;
using detail::optional_with;
using detail::variant_with;

namespace {

	string_list strings(std::initializer_list<std::string_view> list, const string_list::allocator_type &alloc)
	{
		string_list out(alloc);
		out.reserve(list.size());
		for (auto s : list) out.emplace_back(s);
		return out;
	}

}// namespace

ldap_result::ldap_result(std::int32_t result_code_,
  std::string_view matched_dn_,
  std::string_view diagnostic_message_,
  std::initializer_list<std::string_view> referral_,
  const allocator_type &alloc)
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

error ldap_result::to_error(std::string_view context) const
{
	// On the default resource, whatever this result's resource is: errors
	// must not depend on an arena (see error.hpp).
	error e;
	e.code = std::error_code(result_code, result_category());
	e.diagnostic.assign(diagnostic_message);
	if (!matched_dn.empty()) e.matched_dn.emplace(matched_dn);
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

control &control::operator=(const control &other)
{
	type = other.type;
	criticality = other.criticality;
	assign_optional(value, other.value, get_allocator());
	return *this;
}

control &control::operator=(control &&other)
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

sasl_auth &sasl_auth::operator=(const sasl_auth &other)
{
	mechanism = other.mechanism;
	assign_optional(credentials, other.credentials, get_allocator());
	return *this;
}

sasl_auth &sasl_auth::operator=(sasl_auth &&other)
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

bind_request &bind_request::operator=(const bind_request &other)
{
	version = other.version;
	name = other.name;
	assign_variant(authentication, other.authentication, get_allocator());
	return *this;
}

bind_request &bind_request::operator=(bind_request &&other)
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

bind_response &bind_response::operator=(const bind_response &other)
{
	result = other.result;
	assign_optional(server_sasl_creds, other.server_sasl_creds, get_allocator());
	return *this;
}

bind_response &bind_response::operator=(bind_response &&other)
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

modify_dn_request &modify_dn_request::operator=(const modify_dn_request &other)
{
	entry = other.entry;
	new_rdn = other.new_rdn;
	delete_old_rdn = other.delete_old_rdn;
	assign_optional(new_superior, other.new_superior, get_allocator());
	return *this;
}

modify_dn_request &modify_dn_request::operator=(modify_dn_request &&other)
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

extended_request &extended_request::operator=(const extended_request &other)
{
	request_name = other.request_name;
	assign_optional(request_value, other.request_value, get_allocator());
	return *this;
}

extended_request &extended_request::operator=(extended_request &&other)
{
	request_name = std::move(other.request_name);
	assign_optional(request_value, std::move(other.request_value), get_allocator());
	return *this;
}

extended_response::extended_response(const ldap_result &result_,
  std::optional<std::string_view> response_name_,
  std::optional<std::string_view> response_value_,
  const allocator_type &alloc)
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

extended_response &extended_response::operator=(const extended_response &other)
{
	result = other.result;
	assign_optional(response_name, other.response_name, get_allocator());
	assign_optional(response_value, other.response_value, get_allocator());
	return *this;
}

extended_response &extended_response::operator=(extended_response &&other)
{
	result = std::move(other.result);
	assign_optional(response_name, std::move(other.response_name), get_allocator());
	assign_optional(response_value, std::move(other.response_value), get_allocator());
	return *this;
}

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

intermediate_response &intermediate_response::operator=(const intermediate_response &other)
{
	assign_optional(response_name, other.response_name, alloc_);
	assign_optional(response_value, other.response_value, alloc_);
	return *this;
}

intermediate_response &intermediate_response::operator=(intermediate_response &&other)
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

message &message::operator=(const message &other)
{
	id = other.id;
	assign_variant(op, other.op, get_allocator());
	controls = other.controls;
	return *this;
}

message &message::operator=(message &&other)
{
	id = other.id;
	assign_variant(op, std::move(other.op), get_allocator());
	controls = std::move(other.controls);
	return *this;
}

namespace {

	// Application tag numbers of the protocolOp CHOICE (RFC 4511 section 4.2).
	namespace op_tag {
		constexpr std::uint8_t bind_request = 0;
		constexpr std::uint8_t bind_response = 1;
		constexpr std::uint8_t unbind_request = 2;
		constexpr std::uint8_t search_request = 3;
		constexpr std::uint8_t search_result_entry = 4;
		constexpr std::uint8_t search_result_done = 5;
		constexpr std::uint8_t modify_request = 6;
		constexpr std::uint8_t modify_response = 7;
		constexpr std::uint8_t add_request = 8;
		constexpr std::uint8_t add_response = 9;
		constexpr std::uint8_t del_request = 10;
		constexpr std::uint8_t del_response = 11;
		constexpr std::uint8_t modify_dn_request = 12;
		constexpr std::uint8_t modify_dn_response = 13;
		constexpr std::uint8_t compare_request = 14;
		constexpr std::uint8_t compare_response = 15;
		constexpr std::uint8_t abandon_request = 16;
		constexpr std::uint8_t search_result_reference = 19;
		constexpr std::uint8_t extended_request = 23;
		constexpr std::uint8_t extended_response = 24;
		constexpr std::uint8_t intermediate_response = 25;
	}// namespace op_tag

	std::string at(std::size_t offset) { return " at offset " + std::to_string(offset); }

	std::unexpected<error> bad(const std::string &what, std::size_t offset)
	{
		return fail(client_errc::decode_error, "message: " + what + at(offset));
	}

	// ---------------------------------------------------------------- encoder

	std::unexpected<error> out_of_range(const char *what)
	{
		return fail(client_errc::encode_error, std::string("message: ") + what + " out of range");
	}

	// The operations a client sends (RFC 4511 section 4.2 protocolOp requests).
	bool is_request_op(const protocol_op &op) noexcept
	{
		return std::visit(
		  []<class T>(const T &) {
			  return std::is_same_v<T, bind_request> || std::is_same_v<T, unbind_request>
					 || std::is_same_v<T, search_request> || std::is_same_v<T, modify_request>
					 || std::is_same_v<T, add_request> || std::is_same_v<T, del_request>
					 || std::is_same_v<T, modify_dn_request> || std::is_same_v<T, compare_request>
					 || std::is_same_v<T, abandon_request> || std::is_same_v<T, extended_request>;
		  },
		  op);
	}

	// Checks everything encoding could reject (the filter of a search request
	// included), so the writer is only touched once nothing can fail.
	result<void> precheck(const message &m)
	{
		if (m.id < 0) return out_of_range("message id");
		// RFC 4511 section 4.1.1: id 0 is reserved for unsolicited notifications.
		if (m.id == 0 && is_request_op(m.op))
			return fail(client_errc::encode_error, "message: a request with message id 0");
		if (const auto *s = std::get_if<search_request>(&m.op)) {
			const auto scope = static_cast<std::int32_t>(s->scope);
			const auto deref = static_cast<std::int32_t>(s->deref);
			if (scope < 0 || scope > 3) return out_of_range("search scope");
			if (deref < 0 || deref > 3) return out_of_range("derefAliases");
			if (s->size_limit < 0) return out_of_range("size limit");
			if (s->time_limit < 0) return out_of_range("time limit");
			return detail::check_filter(s->filter, {});
		}
		if (const auto *b = std::get_if<bind_request>(&m.op)) {
			if (b->version < 1 || b->version > 127) return out_of_range("bind version");
		} else if (const auto *a = std::get_if<abandon_request>(&m.op)) {
			if (a->message_id < 0) return out_of_range("abandoned message id");
		} else if (const auto *mod = std::get_if<modify_request>(&m.op)) {
			for (const auto &c : mod->changes) {
				const auto op = static_cast<std::int32_t>(c.operation);
				if (op < 0 || op > 3) return out_of_range("modify operation");
				if (c.operation == modify_operation::add && c.modification.values.empty())
					return fail(client_errc::encode_error, "message: modify add change without values");
			}
		} else if (const auto *add = std::get_if<add_request>(&m.op)) {
			for (const auto &attr : add->attributes)
				if (attr.values.empty())
					return fail(client_errc::encode_error, "message: add request attribute without values");
		}
		return {};
	}

	void write_result(ber::writer &w, const ldap_result &r)
	{
		w.enumerated(r.result_code);
		w.octet_string(r.matched_dn);
		w.octet_string(r.diagnostic_message);
		if (!r.referral.empty())
			w.constructed(ber::context(3), [&](ber::writer &ref) {
				for (const auto &uri : r.referral) ref.octet_string(uri);
			});
	}

	void write_attribute(ber::writer &w, const partial_attribute &a)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &pa) {
			pa.octet_string(a.type);
			pa.constructed(ber::tags::set, [&](ber::writer &vals) {
				for (const auto &v : a.values) vals.octet_string(v);
			});
		});
	}

	void write_attributes(ber::writer &w, const std::pmr::vector<partial_attribute> &attrs)
	{
		w.constructed(ber::tags::sequence, [&](ber::writer &list) {
			for (const auto &a : attrs) write_attribute(list, a);
		});
	}

	struct op_writer
	{
		ber::writer &w;

		template<class F> void seq(std::uint8_t number, F &&body) { w.constructed(ber::application(number), body); }

		template<std::uint8_t Tag> void operator()(const result_response<Tag> &r)
		{
			seq(Tag, [&](ber::writer &o) { write_result(o, r.result); });
		}

		void operator()(const bind_request &b)
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
						if (sasl.credentials) s.octet_string(*sasl.credentials);
					});
				}
			});
		}
		void operator()(const bind_response &b)
		{
			seq(op_tag::bind_response, [&](ber::writer &o) {
				write_result(o, b.result);
				if (b.server_sasl_creds) o.octet_string(*b.server_sasl_creds, ber::context(7));
			});
		}
		void operator()(const unbind_request &) { w.null(ber::application(op_tag::unbind_request)); }
		void operator()(const search_request &s)
		{
			seq(op_tag::search_request, [&](ber::writer &o) {
				o.octet_string(s.base_object);
				o.enumerated(static_cast<std::int32_t>(s.scope));
				o.enumerated(static_cast<std::int32_t>(s.deref));
				o.integer(s.size_limit);
				o.integer(s.time_limit);
				o.boolean(s.types_only);
				detail::write_filter(o, s.filter);// checked by precheck
				o.constructed(ber::tags::sequence, [&](ber::writer &attrs) {
					for (const auto &a : s.attributes) attrs.octet_string(a);
				});
			});
		}
		void operator()(const search_result_entry &e)
		{
			seq(op_tag::search_result_entry, [&](ber::writer &o) {
				o.octet_string(e.object_name);
				write_attributes(o, e.attributes);
			});
		}
		void operator()(const search_result_reference &r)
		{
			seq(op_tag::search_result_reference, [&](ber::writer &o) {
				for (const auto &uri : r.uris) o.octet_string(uri);
			});
		}
		void operator()(const modify_request &m)
		{
			seq(op_tag::modify_request, [&](ber::writer &o) {
				o.octet_string(m.object);
				o.constructed(ber::tags::sequence, [&](ber::writer &changes) {
					for (const auto &c : m.changes)
						changes.constructed(ber::tags::sequence, [&](ber::writer &change) {
							change.enumerated(static_cast<std::int32_t>(c.operation));
							write_attribute(change, c.modification);
						});
				});
			});
		}
		void operator()(const add_request &a)
		{
			seq(op_tag::add_request, [&](ber::writer &o) {
				o.octet_string(a.entry);
				write_attributes(o, a.attributes);
			});
		}
		void operator()(const del_request &d) { w.octet_string(d.entry, ber::application(op_tag::del_request)); }
		void operator()(const modify_dn_request &m)
		{
			seq(op_tag::modify_dn_request, [&](ber::writer &o) {
				o.octet_string(m.entry);
				o.octet_string(m.new_rdn);
				o.boolean(m.delete_old_rdn);
				if (m.new_superior) o.octet_string(*m.new_superior, ber::context(0));
			});
		}
		void operator()(const compare_request &c)
		{
			seq(op_tag::compare_request, [&](ber::writer &o) {
				o.octet_string(c.entry);
				o.constructed(ber::tags::sequence, [&](ber::writer &ava) {
					ava.octet_string(c.ava.attribute_desc);
					ava.octet_string(c.ava.assertion_value);
				});
			});
		}
		void operator()(const abandon_request &a)
		{
			w.integer(a.message_id, ber::application(op_tag::abandon_request));
		}
		void operator()(const extended_request &e)
		{
			seq(op_tag::extended_request, [&](ber::writer &o) {
				o.octet_string(e.request_name, ber::context(0));
				if (e.request_value) o.octet_string(*e.request_value, ber::context(1));
			});
		}
		void operator()(const extended_response &e)
		{
			seq(op_tag::extended_response, [&](ber::writer &o) {
				write_result(o, e.result);
				if (e.response_name) o.octet_string(*e.response_name, ber::context(10));
				if (e.response_value) o.octet_string(*e.response_value, ber::context(11));
			});
		}
		void operator()(const intermediate_response &i)
		{
			seq(op_tag::intermediate_response, [&](ber::writer &o) {
				if (i.response_name) o.octet_string(*i.response_name, ber::context(0));
				if (i.response_value) o.octet_string(*i.response_value, ber::context(1));
			});
		}
	};

	// ---------------------------------------------------------------- decoder

	// RFC 4511 section 4: unrecognized elements at the end of a SEQUENCE are
	// ignored. They must still be well-formed (read() checks the header and
	// that the length fits).
	result<void> skip_rest(ber::reader &r)
	{
		while (!r.empty()) {
			auto e = r.read();
			if (!e) return std::unexpected(std::move(e.error()));
		}
		return {};
	}

	// Class and number of the next element, without committing.
	bool next_is(const ber::reader &r, ber::tag t)
	{
		if (r.empty()) return false;
		auto p = r.peek_tag();
		return p && p->cls == t.cls && p->number == t.number;
	}

	result<std::int32_t> read_ranged(ber::reader &r,
	  ber::tag t,
	  std::int64_t lo,
	  std::int64_t hi,
	  const char *what,
	  bool enumerated = false)
	{
		const std::size_t offset = r.offset();
		auto copy = r;
		LDAP_TRY(v, enumerated ? copy.read_enumerated(t) : copy.read_integer(t));
		if (v < lo || v > hi)
			return bad(std::string(what) + " " + std::to_string(v) + " outside " + std::to_string(lo) + ".."
						 + std::to_string(hi),
			  offset);
		r = copy;
		return static_cast<std::int32_t>(v);
	}

	using alloc_t = std::pmr::polymorphic_allocator<>;

	// Number of leading elements in `r` (a copy: only headers are read) that
	// carry tag `t` and are at least `min_size` bytes, to reserve vectors
	// exactly. That saves the growth reallocations, which matter most in a
	// monotonic arena (it never reuses the old buffers). Counting stops at
	// the first element that could not decode as one, so a hostile list of
	// invalid elements (e.g. 8M empty SEQUENCEs) cannot make decode reserve
	// more than a valid message of the same size would really use. It also
	// stops at `limit` (what is left of decode_options::max_elements).
	std::size_t count_elements(ber::reader r, ber::tag t, std::size_t min_size, std::size_t limit)
	{
		std::size_t n = 0;
		while (!r.empty() && n < limit) {
			auto e = r.read();
			if (!e || e->t != t || e->size() < min_size) break;
			++n;
		}
		return n;
	}

	// Smallest valid encodings: a value is an OCTET STRING (`04 00`); a
	// PartialAttribute is SEQUENCE { type OCTET STRING, vals SET }
	// (`30 04 04 00 31 00`).
	constexpr std::size_t min_value_size = 2;
	constexpr std::size_t min_attribute_size = 6;

	// Everything decoded is allocated from `a` (decode_options::memory). The
	// objects are built with `a` and their parts moved in, so nothing is
	// copied twice and nothing touches the default resource (except errors).
	class decoder
	{
	  public:
		explicit decoder(const decode_options &options) : options_(options), a_(options.memory) {}

		// The value of a pre-read / post-read response control: exactly one
		// SearchResultEntry.
		result<search_result_entry> run_entry(std::span<const std::byte> bytes)
		{
			ber::reader top(bytes, options_.max_depth);
			LDAP_TRY(op, read_search_result_entry(top, ber::application(op_tag::search_result_entry)));
			LDAP_TRY_VOID(top.expect_end());
			return std::move(std::get<search_result_entry>(op));
		}

		result<message> run(std::span<const std::byte> bytes)
		{
			ber::reader top(bytes, options_.max_depth);
			LDAP_TRY(r, top.enter());
			LDAP_TRY_VOID(top.expect_end());
			message m(a_);
			LDAP_TRY(id, read_ranged(r, ber::tags::integer, 0, max_int, "message id"));
			m.id = id;
			// RFC 4511 section 4.1.1: id 0 is reserved for unsolicited notifications.
			if (id == 0 && !r.empty()) {
				auto t = r.peek_tag();
				if (t && t->cls == ber::tag_class::application && is_request(t->number))
					return bad("request with message id 0", r.offset());
			}
			LDAP_TRY(op, read_op(r));
			m.op = std::move(op);// same resource: moved, not copied
			if (next_is(r, ber::context(0))) {
				LDAP_TRY(list, r.enter(ber::context(0)));
				while (!list.empty()) {
					LDAP_TRY(c, read_control(list));
					m.controls.push_back(std::move(c));
				}
			}
			LDAP_TRY_VOID(skip_rest(r));
			return m;
		}

	  private:
		result<std::pmr::string> str(ber::reader &r, ber::tag t = ber::tags::octet_string)
		{
			if (strings_ == options_.max_elements) [[unlikely]]
				return too_many_elements(r.offset());
			// Counted before reading (a failed read ends the decode anyway),
			// so the result is returned directly, not copied.
			++strings_;
			return r.read_string(t, a_.resource());
		}

		// Kept out of str(), the hottest decoding path.
		std::unexpected<error> too_many_elements(std::size_t offset) const
		{
			return fail(client_errc::message_too_large,
			  "message: more than " + std::to_string(options_.max_elements) + " elements" + at(offset));
		}

		// Elements str() may still decode.
		std::size_t budget() const noexcept { return options_.max_elements - strings_; }

		result<std::optional<std::pmr::string>> optional_str(ber::reader &r, ber::tag t)
		{
			if (!next_is(r, t)) return std::optional<std::pmr::string>{};
			LDAP_TRY(s, str(r, t));
			return std::optional<std::pmr::string>{ std::move(s) };
		}

		// COMPONENTS OF LDAPResult: the fields are inline in the op's SEQUENCE.
		result<void> read_result(ber::reader &r, ldap_result &out)
		{
			LDAP_TRY(code,
			  read_ranged(r,
				ber::tags::enumerated,
				std::numeric_limits<std::int32_t>::min(),
				std::numeric_limits<std::int32_t>::max(),
				"resultCode",
				true));
			LDAP_TRY(matched, str(r));
			LDAP_TRY(diag, str(r));
			out.result_code = code;
			out.matched_dn = std::move(matched);
			out.diagnostic_message = std::move(diag);
			if (next_is(r, ber::context(3))) {
				LDAP_TRY(ref, r.enter(ber::context(3)));
				while (!ref.empty()) {
					LDAP_TRY(uri, str(ref));
					out.referral.push_back(std::move(uri));
				}
			}
			return {};
		}

		template<class T> result<protocol_op> result_only(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<T>, a_);
			LDAP_TRY_VOID(read_result(o, std::get<T>(op).result));
			LDAP_TRY_VOID(skip_rest(o));
			return op;
		}

		result<void> read_attribute(ber::reader &r, partial_attribute &out)
		{
			LDAP_TRY(pa, r.enter());
			LDAP_TRY(type, str(pa));
			LDAP_TRY(vals, pa.enter(ber::tags::set));
			out.type = std::move(type);
			out.values.reserve(count_elements(vals, ber::tags::octet_string, min_value_size, budget()));
			while (!vals.empty()) {
				LDAP_TRY(v, str(vals));
				out.values.push_back(std::move(v));
			}
			LDAP_TRY_VOID(skip_rest(pa));
			return {};
		}

		result<void> read_attributes(ber::reader &r, std::pmr::vector<partial_attribute> &out)
		{
			LDAP_TRY(list, r.enter());
			out.reserve(count_elements(list, ber::tags::sequence, min_attribute_size, budget()));
			while (!list.empty()) LDAP_TRY_VOID(read_attribute(list, out.emplace_back()));
			return {};
		}

		result<protocol_op> read_bind_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<bind_request>, a_);
			auto &b = std::get<bind_request>(op);
			LDAP_TRY(version, read_ranged(o, ber::tags::integer, 1, 127, "bind version"));
			LDAP_TRY(name, str(o));
			b.version = version;
			b.name = std::move(name);
			const std::size_t auth_at = o.offset();
			if (next_is(o, ber::context(0))) {
				LDAP_TRY(password, str(o, ber::context(0)));
				std::get<simple_auth>(b.authentication).password = std::move(password);
			} else if (next_is(o, ber::context(3))) {
				LDAP_TRY(s, o.enter(ber::context(3)));
				LDAP_TRY(mechanism, str(s));
				LDAP_TRY(credentials, optional_str(s, ber::tags::octet_string));
				LDAP_TRY_VOID(skip_rest(s));
				auto &sasl = b.authentication.emplace<sasl_auth>(a_);
				sasl.mechanism = std::move(mechanism);
				sasl.credentials = std::move(credentials);
			} else {
				if (o.empty()) return bad("bind request without authentication", auth_at);
				return fail(client_errc::unsupported_operation, "message: bind authentication choice" + at(auth_at));
			}
			LDAP_TRY_VOID(skip_rest(o));
			return op;
		}

		result<protocol_op> read_bind_response(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<bind_response>, a_);
			auto &b = std::get<bind_response>(op);
			LDAP_TRY_VOID(read_result(o, b.result));
			LDAP_TRY(creds, optional_str(o, ber::context(7)));
			LDAP_TRY_VOID(skip_rest(o));
			b.server_sasl_creds = std::move(creds);
			return op;
		}

		result<protocol_op> read_search_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<search_request>, a_);
			auto &s = std::get<search_request>(op);
			LDAP_TRY(base, str(o));
			LDAP_TRY(scope, read_ranged(o, ber::tags::enumerated, 0, 3, "search scope", true));
			LDAP_TRY(deref, read_ranged(o, ber::tags::enumerated, 0, 3, "derefAliases", true));
			LDAP_TRY(size_limit, read_ranged(o, ber::tags::integer, 0, max_int, "size limit"));
			LDAP_TRY(time_limit, read_ranged(o, ber::tags::integer, 0, max_int, "time limit"));
			LDAP_TRY(types_only, o.read_boolean());
			LDAP_TRY(f, decode_filter(o, options_.filter, a_.resource()));
			LDAP_TRY(attrs, o.enter());
			while (!attrs.empty()) {
				LDAP_TRY(a, str(attrs));
				s.attributes.push_back(std::move(a));
			}
			LDAP_TRY_VOID(skip_rest(o));
			s.base_object = std::move(base);
			s.scope = static_cast<search_scope>(scope);
			s.deref = static_cast<deref_aliases>(deref);
			s.size_limit = size_limit;
			s.time_limit = time_limit;
			s.types_only = types_only;
			s.filter = std::move(f);
			return op;
		}

		result<protocol_op> read_search_result_entry(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<search_result_entry>, a_);
			auto &e = std::get<search_result_entry>(op);
			LDAP_TRY(name, str(o));
			e.object_name = std::move(name);
			LDAP_TRY_VOID(read_attributes(o, e.attributes));
			LDAP_TRY_VOID(skip_rest(o));
			return op;
		}

		result<protocol_op> read_search_result_reference(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<search_result_reference>, a_);
			auto &ref = std::get<search_result_reference>(op);
			while (!o.empty()) {
				LDAP_TRY(uri, str(o));
				ref.uris.push_back(std::move(uri));
			}
			return op;
		}

		result<protocol_op> read_modify_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<modify_request>, a_);
			auto &m = std::get<modify_request>(op);
			LDAP_TRY(object, str(o));
			m.object = std::move(object);
			LDAP_TRY(changes, o.enter());
			while (!changes.empty()) {
				LDAP_TRY(change, changes.enter());
				LDAP_TRY(op_code, read_ranged(change, ber::tags::enumerated, 0, 3, "modify operation", true));
				const std::size_t attr_at = change.offset();
				auto &c = m.changes.emplace_back();
				c.operation = static_cast<modify_operation>(op_code);
				LDAP_TRY_VOID(read_attribute(change, c.modification));
				if (c.operation == modify_operation::add && c.modification.values.empty())
					return bad("modify add change without values", attr_at);
				LDAP_TRY_VOID(skip_rest(change));
			}
			LDAP_TRY_VOID(skip_rest(o));
			return op;
		}

		result<protocol_op> read_add_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<add_request>, a_);
			auto &add = std::get<add_request>(op);
			LDAP_TRY(entry, str(o));
			add.entry = std::move(entry);
			const std::size_t attrs_at = o.offset();
			LDAP_TRY_VOID(read_attributes(o, add.attributes));
			for (const auto &a : add.attributes)
				if (a.values.empty())
					return bad("add request attribute '" + std::string(a.type) + "' without values", attrs_at);
			LDAP_TRY_VOID(skip_rest(o));
			return op;
		}

		result<protocol_op> read_modify_dn_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<modify_dn_request>, a_);
			auto &m = std::get<modify_dn_request>(op);
			LDAP_TRY(entry, str(o));
			LDAP_TRY(new_rdn, str(o));
			LDAP_TRY(delete_old, o.read_boolean());
			LDAP_TRY(superior, optional_str(o, ber::context(0)));
			LDAP_TRY_VOID(skip_rest(o));
			m.entry = std::move(entry);
			m.new_rdn = std::move(new_rdn);
			m.delete_old_rdn = delete_old;
			m.new_superior = std::move(superior);
			return op;
		}

		result<protocol_op> read_compare_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<compare_request>, a_);
			auto &c = std::get<compare_request>(op);
			LDAP_TRY(entry, str(o));
			LDAP_TRY(ava, o.enter());
			LDAP_TRY(desc, str(ava));
			LDAP_TRY(value, str(ava));
			LDAP_TRY_VOID(skip_rest(ava));
			LDAP_TRY_VOID(skip_rest(o));
			c.entry = std::move(entry);
			c.ava.attribute_desc = std::move(desc);
			c.ava.assertion_value = std::move(value);
			return op;
		}

		result<protocol_op> read_extended_request(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<extended_request>, a_);
			auto &e = std::get<extended_request>(op);
			LDAP_TRY(name, str(o, ber::context(0)));
			LDAP_TRY(value, optional_str(o, ber::context(1)));
			LDAP_TRY_VOID(skip_rest(o));
			e.request_name = std::move(name);
			e.request_value = std::move(value);
			return op;
		}

		result<protocol_op> read_extended_response(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<extended_response>, a_);
			auto &e = std::get<extended_response>(op);
			LDAP_TRY_VOID(read_result(o, e.result));
			LDAP_TRY(name, optional_str(o, ber::context(10)));
			LDAP_TRY(value, optional_str(o, ber::context(11)));
			LDAP_TRY_VOID(skip_rest(o));
			e.response_name = std::move(name);
			e.response_value = std::move(value);
			return op;
		}

		result<protocol_op> read_intermediate_response(ber::reader &r, ber::tag t)
		{
			LDAP_TRY(o, r.enter(t));
			protocol_op op(std::in_place_type<intermediate_response>, a_);
			auto &i = std::get<intermediate_response>(op);
			LDAP_TRY(name, optional_str(o, ber::context(0)));
			LDAP_TRY(value, optional_str(o, ber::context(1)));
			LDAP_TRY_VOID(skip_rest(o));
			i.response_name = std::move(name);
			i.response_value = std::move(value);
			return op;
		}

		result<protocol_op> read_op(ber::reader &r)
		{
			const std::size_t offset = r.offset();
			LDAP_TRY(t, r.peek_tag());
			auto unsupported = [&] {
				return fail(
				  client_errc::unsupported_operation, "message: unknown protocolOp " + ber::to_string(t) + at(offset));
			};
			if (t.cls != ber::tag_class::application) return unsupported();
			// Checked before decoding, so a peer cannot make us parse (for
			// example) a huge search request filter it may not send at all.
			if (options_.from == origin::server && is_request(t.number))
				return fail(client_errc::unsupported_operation,
				  "message: request operation " + ber::to_string(t) + " from a server" + at(offset));
			if (options_.from == origin::client && !is_request(t.number))
				return fail(client_errc::unsupported_operation,
				  "message: response operation " + ber::to_string(t) + " from a client" + at(offset));
			switch (t.number) {
			case op_tag::bind_request:
				return read_bind_request(r, t);
			case op_tag::bind_response:
				return read_bind_response(r, t);
			case op_tag::unbind_request: {
				LDAP_TRY_VOID(r.read_null(t));
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
				LDAP_TRY(entry, str(r, t));
				protocol_op op(std::in_place_type<del_request>, a_);
				std::get<del_request>(op).entry = std::move(entry);
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
				LDAP_TRY(id, read_ranged(r, t, 0, max_int, "abandoned message id"));
				return protocol_op{ abandon_request{ id } };
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

		result<control> read_control(ber::reader &r)
		{
			LDAP_TRY(c, r.enter());
			control out(a_);
			LDAP_TRY(type, str(c));
			out.type = std::move(type);
			if (next_is(c, ber::tags::boolean)) {
				LDAP_TRY(critical, c.read_boolean());
				out.criticality = critical;
			}
			LDAP_TRY(value, optional_str(c, ber::tags::octet_string));
			out.value = std::move(value);
			LDAP_TRY_VOID(skip_rest(c));
			return out;
		}

		// Operations a client sends (RFC 4511 section 4.2 protocolOp requests).
		static bool is_request(std::uint8_t number)
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

		const decode_options &options_;
		alloc_t a_;
		std::size_t strings_ = 0;// decoded by str(), against options_.max_elements
	};

}// namespace

result<void> encode(ber::writer &w, const message &m)
{
	LDAP_TRY_VOID(precheck(m));
	w.constructed(ber::tags::sequence, [&](ber::writer &msg) {
		msg.integer(m.id);
		std::visit(op_writer{ msg }, m.op);
		if (!m.controls.empty())
			msg.constructed(ber::context(0), [&](ber::writer &list) {
				for (const auto &c : m.controls)
					list.constructed(ber::tags::sequence, [&](ber::writer &cw) {
						cw.octet_string(c.type);
						if (c.criticality) cw.boolean(true);
						if (c.value) cw.octet_string(*c.value);
					});
			});
	});
	return {};
}

result<std::pmr::vector<std::byte>> encode(const message &m, std::pmr::memory_resource *mr)
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	// Most requests fit; saves the first few doublings of the buffer.
	w.reserve(256);
	LDAP_TRY_VOID(encode(w, m));
	return w.take();
}

result<message> decode(std::span<const std::byte> one_complete_message, const decode_options &options)
{
	return decoder(options).run(one_complete_message);
}

result<message_header> peek_message_header(std::span<const std::byte> one_complete_message)
{
	ber::reader top(one_complete_message);
	LDAP_TRY(r, top.enter());
	LDAP_TRY(id, read_ranged(r, ber::tags::integer, 0, max_int, "message id"));
	if (r.empty()) return fail(client_errc::decode_error, "LDAPMessage without a protocolOp");
	LDAP_TRY(op, r.peek_tag());
	return message_header{ id, op };
}

// ---------------------------------------------------------------- paged results

result<control> encode_paged_results(const paged_results &value, bool criticality, std::pmr::memory_resource *mr)
{
	if (value.size < 0) return fail(client_errc::encode_error, "paged results: negative size");
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.integer(value.size);
		s.octet_string(value.cookie);
	});
	const auto &bytes = w.bytes();
	return control(paged_results_oid,
	  criticality,
	  std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()),
	  control::allocator_type(mr));
}

result<paged_results> decode_paged_results(const control &c, std::pmr::memory_resource *mr)
{
	if (c.type != paged_results_oid)
		return fail(client_errc::decode_error,
		  "paged results: control type is " + std::string(c.type) + ", not " + std::string(paged_results_oid));
	if (!c.value) return fail(client_errc::decode_error, "paged results: control has no value");
	// The control value was already taken out of its OCTET STRING by
	// decode(), so it is decoded with its own reader (offsets relative to the
	// value).
	ber::reader r(std::as_bytes(std::span(*c.value)));
	LDAP_TRY(s, r.enter());
	LDAP_TRY_VOID(r.expect_end());
	LDAP_TRY(size, read_ranged(s, ber::tags::integer, 0, max_int, "paged results size"));
	LDAP_TRY(cookie, s.read_string(ber::tags::octet_string, mr));
	LDAP_TRY_VOID(skip_rest(s));
	paged_results out{ paged_results::allocator_type(mr) };
	out.size = size;
	out.cookie = std::move(cookie);
	return out;
}

// ---------------------------------------------------------------- server side sorting

namespace {

	result<void> expect_control(const control &c, std::string_view oid, std::string_view what)
	{
		if (c.type != oid)
			return fail(client_errc::decode_error,
			  std::string(what) + ": control type is " + std::string(c.type) + ", not " + std::string(oid));
		if (!c.value) return fail(client_errc::decode_error, std::string(what) + ": control has no value");
		return {};
	}

	control bytes_control(std::string_view oid, bool criticality, const ber::writer &w, std::pmr::memory_resource *mr)
	{
		const auto &bytes = w.bytes();
		return control(oid,
		  criticality,
		  std::string_view(reinterpret_cast<const char *>(bytes.data()), bytes.size()),
		  control::allocator_type(mr));
	}

}// namespace

result<control> encode_sort_result(const sort_result &value, bool criticality, std::pmr::memory_resource *mr)
{
	ber::writer w{ ber::writer::allocator_type(mr) };
	w.constructed(ber::tags::sequence, [&](ber::writer &s) {
		s.enumerated(value.result_code);
		if (!value.attribute_type.empty()) s.octet_string(value.attribute_type, ber::context(0));
	});
	return bytes_control(sort_response_oid, criticality, w, mr);
}

namespace {

	// SortResult ::= SEQUENCE { sortResult ENUMERATED, attributeType [0] AttributeDescription OPTIONAL }
	result<sort_result> read_sort_result(std::span<const std::byte> value, std::pmr::memory_resource *mr)
	{
		ber::reader r(value);
		LDAP_TRY(s, r.enter());
		LDAP_TRY_VOID(r.expect_end());
		LDAP_TRY(code,
		  read_ranged(s,
			ber::tags::enumerated,
			std::numeric_limits<std::int32_t>::min(),
			std::numeric_limits<std::int32_t>::max(),
			"sortResult",
			true));
		sort_result out{ sort_result::allocator_type(mr) };
		out.result_code = code;
		if (next_is(s, ber::context(0))) {
			LDAP_TRY(type, s.read_string(ber::context(0), mr));
			out.attribute_type = std::move(type);
		}
		LDAP_TRY_VOID(skip_rest(s));
		return out;
	}

	// Errors from inside a control value name the control: their offsets
	// are relative to the value, not to the message.
	template<class T> result<T> in_control(result<T> r, std::string_view name)
	{
		if (r) return r;
		auto e = std::move(r.error());
		if (!e.context.empty()) e.context.insert(0, ": ");
		e.context.insert(0, name);
		return std::unexpected(std::move(e));
	}

}// namespace

result<sort_result> decode_sort_result(const control &c, std::pmr::memory_resource *mr)
{
	LDAP_TRY_VOID(expect_control(c, sort_response_oid, "sort result"));
	return in_control(read_sort_result(std::as_bytes(std::span(*c.value)), mr), "sort result");
}

// ---------------------------------------------------------------- pre-read / post-read

result<control> encode_read_entry(std::string_view oid,
  const search_result_entry &entry,
  bool criticality,
  std::pmr::memory_resource *mr)
{
	if (oid != pre_read_oid && oid != post_read_oid)
		return fail(
		  client_errc::encode_error, "read entry control: " + std::string(oid) + " is not pre-read or post-read");
	ber::writer w{ ber::writer::allocator_type(mr) };
	op_writer{ w }(entry);
	return bytes_control(oid, criticality, w, mr);
}

result<search_result_entry> decode_read_entry(const control &c, const decode_options &options)
{
	if (c.type != pre_read_oid && c.type != post_read_oid)
		return fail(client_errc::decode_error,
		  "read entry: control type is " + std::string(c.type) + ", not pre-read or post-read");
	const std::string_view name = c.type == pre_read_oid ? "pre-read" : "post-read";
	LDAP_TRY_VOID(expect_control(c, c.type, name));
	return in_control(decoder(options).run_entry(std::as_bytes(std::span(*c.value))), name);
}

}// namespace jhetz::ldap

#undef LDAP_TRY
#undef LDAP_TRY_VOID
