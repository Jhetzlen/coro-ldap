#include "jhetz/ldap/schema.hpp"

#include "format_util.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace jhetz::ldap {
namespace {

	auto is_space(char c) -> bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

	// RFC 4512 section 4.1 definitions: "(", ")", 'quoted strings' (with
	// \27 and \5C escapes) and bare words (keywords, OIDs, descriptors,
	// "noidlen" like 1.2.3{64}).
	struct token
	{
		enum class kind { open, close, quoted, word, end } k;
		std::string text;
	};

	class lexer
	{
	  public:
		explicit lexer(std::string_view s) : s_(s) {}

		auto next() -> result<token>
		{
			while (pos_ < s_.size() && is_space(s_[pos_])) {
				++pos_;
			}
			if (pos_ == s_.size()) {
				return token{ .k = token::kind::end, .text = {} };
			}
			const char c = s_[pos_];
			if (c == '(') {
				return ++pos_, token{ .k = token::kind::open, .text = {} };
			}
			if (c == ')') {
				return ++pos_, token{ .k = token::kind::close, .text = {} };
			}
			if (c == '\'') {
				++pos_;
				std::string out;
				while (pos_ < s_.size() && s_[pos_] != '\'') {
					if (s_[pos_] == '\\' && s_.size() - pos_ >= 3) {
						const std::string_view hex = s_.substr(pos_ + 1, 2);
						if (hex == "27") {
							out += '\'';
						} else if (hex == "5c" || hex == "5C") {
							out += '\\';
						} else {
							return fail(client_errc::decode_error, "schema: bad escape in a quoted string");
						}
						pos_ += 3;
					} else {
						out += s_[pos_++];
					}
				}
				if (pos_ == s_.size()) {
					return fail(client_errc::decode_error, "schema: unterminated quoted string");
				}
				++pos_;
				return token{ .k = token::kind::quoted, .text = std::move(out) };
			}
			const std::size_t start = pos_;
			while (pos_ < s_.size() && !is_space(s_[pos_]) && s_[pos_] != '(' && s_[pos_] != ')' && s_[pos_] != '\'') {
				++pos_;
			}
			return token{ .k = token::kind::word, .text = std::string(s_.substr(start, pos_ - start)) };
		}

	  private:
		std::string_view s_;
		std::size_t pos_ = 0;
	};

	// A keyword: RFC 4512 keystring (ALPHA *( ALPHA / DIGIT / "-" )) or an
	// extension's xstring ("X-" 1*( ALPHA / "-" / "_" ), as eDirectory's
	// X-NDS_SYNTAX). Anything else (a "{256}" spaced from SYNTAX's OID, a
	// stray "$" or OID) fails the definition: taken as a keyword, it would
	// swallow the next one (SINGLE-VALUE, say) as its value.
	auto is_keyword(std::string_view k) -> bool
	{
		if (k.empty() || !detail::is_alpha(k[0])) {
			return false;
		}
		return std::ranges::all_of(k, [](char c) { return detail::is_keychar(c) || c == '_'; });
	}

	// Keywords without an argument.
	auto is_flag(std::string_view k) -> bool
	{
		static constexpr std::array flags{
			"OBSOLETE", "SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION", "ABSTRACT", "STRUCTURAL", "AUXILIARY"
		};
		return std::ranges::any_of(flags, [k](const char *f) { return detail::iequals(k, f); });
	}

	// A definition as an OID and keyword -> values (a list argument gives
	// several values; '$' separators are dropped).
	struct definition
	{
		std::string oid;
		std::vector<std::pair<std::string, std::vector<std::string>>> fields;

		[[nodiscard]] auto get(std::string_view keyword) const -> const std::vector<std::string> *
		{
			for (const auto &[k, v] : fields) {
				if (detail::iequals(k, keyword)) {
					return &v;
				}
			}
			return nullptr;
		}
		[[nodiscard]] auto has(std::string_view keyword) const -> bool { return get(keyword) != nullptr; }
	};

	auto parse_definition(std::string_view text) -> result<definition>
	{
		const auto bad = [](const char *why) {
			return fail(client_errc::decode_error, detail::format("schema: {}", why));
		};
		lexer lx(text);
		auto t = lx.next();
		if (!t) {
			return std::unexpected(std::move(t.error()));
		}
		if (t->k != token::kind::open) {
			return bad("a definition starts with '('");
		}
		t = lx.next();
		if (!t) {
			return std::unexpected(std::move(t.error()));
		}
		if (t->k != token::kind::word && t->k != token::kind::quoted) {
			return bad("missing OID");
		}
		definition d;
		d.oid = std::move(t->text);
		if (!detail::is_oid(d.oid)) {
			return bad("invalid OID");
		}
		std::optional<token> pending;
		constexpr std::size_t max_fields = 256;
		constexpr std::size_t max_values = 4096;
		while (true) {
			result<token> k = pending ? result<token>(std::move(*pending)) : lx.next();
			pending.reset();
			if (!k) {
				return std::unexpected(std::move(k.error()));
			}
			if (k->k == token::kind::close) {
				break;
			}
			if (k->k == token::kind::end) {
				return bad("missing ')'");
			}
			if (k->k != token::kind::word || !is_keyword(k->text)) {
				return bad("expected a keyword");
			}
			if (d.fields.size() == max_fields) {
				return bad("too many fields");
			}
			std::vector<std::string> values;
			if (!is_flag(k->text)) {
				auto v = lx.next();
				if (!v) {
					return std::unexpected(std::move(v.error()));
				}
				if (v->k == token::kind::open) {
					while (true) {
						auto e = lx.next();
						if (!e) {
							return std::unexpected(std::move(e.error()));
						}
						if (e->k == token::kind::close) {
							break;
						}
						if (e->k == token::kind::end || e->k == token::kind::open) {
							return bad("unterminated list");
						}
						if (e->text == "$") {
							continue;
						}
						if (values.size() == max_values) {
							return bad("list too long");
						}
						values.push_back(std::move(e->text));
					}
				} else if (v->k == token::kind::word || v->k == token::kind::quoted) {
					values.push_back(std::move(v->text));
				} else {
					return bad("missing value");
				}
			}
			d.fields.emplace_back(std::move(k->text), std::move(values));
		}
		auto rest = lx.next();
		if (!rest) {
			return std::unexpected(std::move(rest.error()));
		}
		if (rest->k != token::kind::end) {
			return bad("text after the closing ')'");
		}
		return d;
	}

	// noidlen without its length: "1.2.3{64}" -> "1.2.3". The length must
	// be "{" 1*DIGIT "}" right after the OID and end the text; otherwise
	// nullopt (the definition is then skipped).
	auto strip_length(std::string_view s) -> std::optional<std::string>
	{
		const std::size_t open = s.find('{');
		if (open == std::string_view::npos) {
			return std::string(s);
		}
		const std::string_view len = s.substr(open + 1);
		if (len.size() < 2 || len.back() != '}') {
			return std::nullopt;
		}
		if (!std::ranges::all_of(len.substr(0, len.size() - 1), detail::is_digit)) {
			return std::nullopt;
		}
		return std::string(s.substr(0, open));
	}

	// Keeps the NAMEs that are valid descriptors (RFC 4512 section 1.4);
	// others could never be looked up, so they are dropped.
	auto valid_names(const std::vector<std::string> *names) -> std::vector<std::string>
	{
		std::vector<std::string> out;
		if (names != nullptr) {
			for (const auto &n : *names) {
				if (detail::is_descr(n)) {
					out.push_back(n);
				}
			}
		}
		return out;
	}

	// "cn;lang-en" -> "cn".
	auto without_options(std::string_view s) -> std::string_view { return s.substr(0, s.find(';')); }

}// namespace

namespace {

	// The attribute type of a definition that parsed; fails only for its
	// SYNTAX (server_schema::parse remembers those definitions' names).
	auto to_attribute_type(definition &&d) -> result<attribute_type>
	{
		attribute_type a;
		a.oid = std::move(d.oid);
		a.names = valid_names(d.get("NAME"));
		if (const auto *s = d.get("SUP"); s && !s->empty()) {
			a.sup = s->front();
		}
		// RFC 4512 section 4.1.2: SYNTAX noidlen, a numericoid with an
		// optional {len} right after it ("{" 1*DIGIT "}", no space; a spaced
		// "{len}" already failed as a keyword). Anything else could never
		// match a syntax the mapping knows, and would be the server's raw
		// text in a report.
		if (const auto *s = d.get("SYNTAX"); s && !s->empty()) {
			a.syntax = strip_length(s->front());
			if (!a.syntax || !detail::is_numericoid(*a.syntax)) {
				return fail(client_errc::decode_error, "schema: SYNTAX is not a numeric OID");
			}
		}
		a.single_value = d.has("SINGLE-VALUE");
		a.no_user_modification = d.has("NO-USER-MODIFICATION");
		return a;
	}

}// namespace

auto parse_attribute_type(std::string_view text) -> result<attribute_type>
{
	return parse_definition(text).and_then(to_attribute_type);
}

auto parse_object_class(std::string_view text) -> result<object_class_type>
{
	return parse_definition(text).transform([](definition &&d) {
		object_class_type c;
		c.oid = std::move(d.oid);
		c.names = valid_names(d.get("NAME"));
		return c;
	});
}

// Public API, subschema attribute order (RFC 4512 4.2); kept by decision (coro-ldap-bsm.30).
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
auto server_schema::parse(std::span<const std::pmr::string> attribute_types,
  std::span<const std::pmr::string> object_classes) -> server_schema
{
	server_schema s;
	for (const auto &text : attribute_types) {
		auto d = parse_definition(text);
		if (!d) {
			++s.skipped_;
			continue;
		}
		// Kept before the definition is moved: its names, if the SYNTAX
		// fails (they are valid descriptors or an OID, never raw text).
		std::vector<std::string> names = valid_names(d->get("NAME"));
		names.push_back(d->oid);
		auto a = to_attribute_type(std::move(*d));
		if (!a) {
			++s.skipped_;
			for (auto &n : names) {
				s.bad_syntax_.insert(std::move(n));
			}
			continue;
		}
		const std::size_t i = s.attributes_.size();
		s.attribute_index_.emplace(a->oid, i);
		for (const auto &n : a->names) {
			s.attribute_index_.emplace(n, i);
		}
		s.attributes_.push_back(std::move(*a));
	}
	for (const auto &text : object_classes) {
		auto c = parse_object_class(text);
		if (!c) {
			++s.skipped_;
			continue;
		}
		const std::size_t i = s.classes_.size();
		s.class_index_.emplace(c->oid, i);
		for (const auto &n : c->names) {
			s.class_index_.emplace(n, i);
		}
		s.classes_.push_back(std::move(*c));
	}
	return s;
}

auto server_schema::find_attribute(std::string_view name) const noexcept -> const attribute_type *
{
	const auto it = attribute_index_.find(without_options(name));
	return it == attribute_index_.end() ? nullptr : &attributes_[it->second];
}

auto server_schema::find_object_class(std::string_view name) const noexcept -> const object_class_type *
{
	const auto it = class_index_.find(name);
	return it == class_index_.end() ? nullptr : &classes_[it->second];
}

auto server_schema::skipped_for_syntax(std::string_view name) const noexcept -> bool
{
	return bad_syntax_.contains(without_options(name));
}

auto server_schema::syntax_of(const attribute_type &a) const noexcept -> const std::string *
{
	const attribute_type *cur = &a;
	for (int depth = 0; depth < 32 && cur != nullptr; ++depth) {
		if (cur->syntax) {
			return &*cur->syntax;
		}
		if (!cur->sup) {
			return nullptr;
		}
		cur = find_attribute(*cur->sup);
	}
	return nullptr;
}

// ---------------------------------------------------------------- report

auto schema_report::ok() const noexcept -> bool { return std::ranges::none_of(issues, &schema_issue::is_error); }

auto schema_report::to_string() const -> std::string
{
	std::string out;
	for (const auto &i : issues) {
		if (!out.empty()) {
			out += '\n';
		}
		detail::format_to(out,
		  "{}{}{}: {}",
		  i.is_error() ? "error: " : "warning: ",
		  i.what == schema_issue::kind::unknown_object_class ? "object class " : "attribute ",
		  i.name,
		  i.detail);
	}
	return out;
}

namespace {

	// Why syntax_of(a) is nullptr: a SUP that names no definition (or one
	// skipped for its SYNTAX), a chain too long (a cycle), or a chain that
	// ends without any SYNTAX (RFC 4512 4.1.2 requires a SYNTAX or a SUP;
	// slapd refuses such a definition, AD always gives SYNTAX). The syntax
	// cannot be checked then, which is an error, not a silent pass.
	auto broken_sup_chain(const server_schema &s, const attribute_type &a) -> std::optional<std::string>
	{
		const attribute_type *cur = &a;
		for (int depth = 0; depth < 32; ++depth) {
			if (cur->syntax) {
				return std::nullopt;
			}
			if (!cur->sup) {
				return cur == &a ? "syntax unknown: the server declares no SYNTAX and no SUP for it"
								 : "syntax unknown: the server declares no SYNTAX for it or its supertypes";
			}
			const attribute_type *next = s.find_attribute(*cur->sup);
			if (next == nullptr) {
				std::string text = "syntax unknown: SUP ";
				detail::append_sanitized(text, *cur->sup, 64);
				text += s.skipped_for_syntax(*cur->sup)
						  ? " is defined on the server, but skipped: its SYNTAX is not a numeric OID"
						  : " is not defined on the server";
				return text;
			}
			cur = next;
		}
		return "syntax unknown: the SUP chain is longer than 32 (a cycle?)";
	}

}// namespace

namespace detail {

	void check_object_class(const server_schema &s, std::string_view name, schema_report &out)
	{
		if (s.find_object_class(name) == nullptr) {
			out.issues.push_back({ .what = schema_issue::kind::unknown_object_class,
			  .name = std::string(name),
			  .detail = "not defined on the server" });
		}
	}

	void check_field(const server_schema &s,
	  std::string_view name,
	  cardinality kind,
	  bool read_only,
	  std::span<const char *const> syntaxes,
	  schema_report &out)
	{
		const attribute_type *a = s.find_attribute(name);
		if (a == nullptr) {
			out.issues.push_back({ .what = schema_issue::kind::unknown_attribute,
			  .name = std::string(name),
			  .detail = s.skipped_for_syntax(name)
						  ? "defined on the server, but skipped: its SYNTAX is not a numeric OID"
						  : "not defined on the server" });
			return;
		}
		if (kind != cardinality::multiple && !a->single_value) {
			out.issues.push_back({ .what = schema_issue::kind::single_member_multi_valued,
			  .name = std::string(name),
			  .detail =
				"single-valued member, but the attribute is multi-valued (decoding fails if an entry has several "
				"values)" });
		}
		if (!read_only && a->no_user_modification) {
			out.issues.push_back({ .what = schema_issue::kind::writable_but_no_user_modification,
			  .name = std::string(name),
			  .detail = "the attribute is NO-USER-MODIFICATION: mark the member ldap::read_only" });
		}
		if (!syntaxes.empty()) {
			const std::string *syn = s.syntax_of(*a);
			if (syn == nullptr) {
				if (auto why = broken_sup_chain(s, *a)) {
					out.issues.push_back({ .what = schema_issue::kind::syntax_mismatch,
					  .name = std::string(name),
					  .detail = std::move(*why) });
				}
			} else if (std::ranges::none_of(syntaxes, [&](const char *x) { return *syn == x; })) {
				// A numeric OID (parse_attribute_type), but of any length.
				std::string text = "syntax ";
				detail::append_sanitized(text, *syn, 64);
				text += " is not one the member's type reads (";
				for (std::size_t i = 0; i < syntaxes.size(); ++i) {
					detail::format_to(text, "{}{}", i != 0 ? ", " : "", syntaxes[i]);
				}
				text += ')';
				out.issues.push_back({ .what = schema_issue::kind::syntax_mismatch,
				  .name = std::string(name),
				  .detail = std::move(text) });
			}
		}
	}

}// namespace detail

}// namespace jhetz::ldap
