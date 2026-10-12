#include "jhetz/ldap/schema.hpp"

#include "format_util.hpp"

#include <algorithm>
#include <string>

namespace jhetz::ldap {
namespace {

	bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

	// RFC 4512 section 4.1 definitions: "(", ")", 'quoted strings' (with
	// \27 and \5C escapes) and bare words (keywords, OIDs, descriptors,
	// "noidlen" like 1.2.3{64}).
	struct token
	{
		enum kind { open, close, quoted, word, end } k;
		std::string text;
	};

	class lexer
	{
	  public:
		explicit lexer(std::string_view s) : s_(s) {}

		result<token> next()
		{
			while (pos_ < s_.size() && is_space(s_[pos_])) ++pos_;
			if (pos_ == s_.size()) return token{ token::end, {} };
			const char c = s_[pos_];
			if (c == '(') return ++pos_, token{ token::open, {} };
			if (c == ')') return ++pos_, token{ token::close, {} };
			if (c == '\'') {
				++pos_;
				std::string out;
				while (pos_ < s_.size() && s_[pos_] != '\'') {
					if (s_[pos_] == '\\' && s_.size() - pos_ >= 3) {
						const std::string_view hex = s_.substr(pos_ + 1, 2);
						if (hex == "27")
							out += '\'';
						else if (hex == "5c" || hex == "5C")
							out += '\\';
						else
							return fail(client_errc::decode_error, "schema: bad escape in a quoted string");
						pos_ += 3;
					} else {
						out += s_[pos_++];
					}
				}
				if (pos_ == s_.size()) return fail(client_errc::decode_error, "schema: unterminated quoted string");
				++pos_;
				return token{ token::quoted, std::move(out) };
			}
			const std::size_t start = pos_;
			while (pos_ < s_.size() && !is_space(s_[pos_]) && s_[pos_] != '(' && s_[pos_] != ')' && s_[pos_] != '\'')
				++pos_;
			return token{ token::word, std::string(s_.substr(start, pos_ - start)) };
		}

	  private:
		std::string_view s_;
		std::size_t pos_ = 0;
	};

	// Keywords without an argument.
	bool is_flag(std::string_view k)
	{
		for (auto f :
		  { "OBSOLETE", "SINGLE-VALUE", "COLLECTIVE", "NO-USER-MODIFICATION", "ABSTRACT", "STRUCTURAL", "AUXILIARY" })
			if (detail::iequals(k, f)) return true;
		return false;
	}

	// A definition as an OID and keyword -> values (a list argument gives
	// several values; '$' separators are dropped).
	struct definition
	{
		std::string oid;
		std::vector<std::pair<std::string, std::vector<std::string>>> fields;

		const std::vector<std::string> *get(std::string_view keyword) const
		{
			for (const auto &[k, v] : fields)
				if (detail::iequals(k, keyword)) return &v;
			return nullptr;
		}
		bool has(std::string_view keyword) const { return get(keyword) != nullptr; }
	};

	result<definition> parse_definition(std::string_view text)
	{
		auto bad = [](const char *why) { return fail(client_errc::decode_error, detail::format("schema: {}", why)); };
		lexer lx(text);
		auto t = lx.next();
		if (!t) return std::unexpected(std::move(t.error()));
		if (t->k != token::open) return bad("a definition starts with '('");
		t = lx.next();
		if (!t) return std::unexpected(std::move(t.error()));
		if (t->k != token::word && t->k != token::quoted) return bad("missing OID");
		definition d;
		d.oid = std::move(t->text);
		if (!detail::is_oid(d.oid)) return bad("invalid OID");
		std::optional<token> pending;
		constexpr std::size_t max_fields = 256, max_values = 4096;
		while (true) {
			result<token> k = pending ? result<token>(std::move(*pending)) : lx.next();
			pending.reset();
			if (!k) return std::unexpected(std::move(k.error()));
			if (k->k == token::close) break;
			if (k->k == token::end) return bad("missing ')'");
			if (k->k != token::word) return bad("expected a keyword");
			if (d.fields.size() == max_fields) return bad("too many fields");
			std::vector<std::string> values;
			if (!is_flag(k->text)) {
				auto v = lx.next();
				if (!v) return std::unexpected(std::move(v.error()));
				if (v->k == token::open) {
					while (true) {
						auto e = lx.next();
						if (!e) return std::unexpected(std::move(e.error()));
						if (e->k == token::close) break;
						if (e->k == token::end || e->k == token::open) return bad("unterminated list");
						if (e->text == "$") continue;
						if (values.size() == max_values) return bad("list too long");
						values.push_back(std::move(e->text));
					}
				} else if (v->k == token::word || v->k == token::quoted) {
					values.push_back(std::move(v->text));
				} else {
					return bad("missing value");
				}
			}
			d.fields.emplace_back(std::move(k->text), std::move(values));
		}
		auto rest = lx.next();
		if (!rest) return std::unexpected(std::move(rest.error()));
		if (rest->k != token::end) return bad("text after the closing ')'");
		return d;
	}

	// "1.2.3{64}" -> "1.2.3".
	std::string strip_length(std::string_view s) { return std::string(s.substr(0, s.find('{'))); }

	// Keeps the NAMEs that are valid descriptors (RFC 4512 section 1.4);
	// others could never be looked up, so they are dropped.
	std::vector<std::string> valid_names(const std::vector<std::string> *names)
	{
		std::vector<std::string> out;
		if (names != nullptr)
			for (const auto &n : *names)
				if (detail::is_descr(n)) out.push_back(n);
		return out;
	}

	// "cn;lang-en" -> "cn".
	std::string_view without_options(std::string_view s) { return s.substr(0, s.find(';')); }

}// namespace

result<attribute_type> parse_attribute_type(std::string_view text)
{
	return parse_definition(text).transform([](definition &&d) {
		attribute_type a;
		a.oid = std::move(d.oid);
		a.names = valid_names(d.get("NAME"));
		if (const auto *s = d.get("SUP"); s && !s->empty()) a.sup = s->front();
		if (const auto *s = d.get("SYNTAX"); s && !s->empty()) a.syntax = strip_length(s->front());
		a.single_value = d.has("SINGLE-VALUE");
		a.no_user_modification = d.has("NO-USER-MODIFICATION");
		return a;
	});
}

result<object_class_type> parse_object_class(std::string_view text)
{
	return parse_definition(text).transform([](definition &&d) {
		object_class_type c;
		c.oid = std::move(d.oid);
		c.names = valid_names(d.get("NAME"));
		return c;
	});
}

server_schema server_schema::parse(std::span<const std::pmr::string> attribute_types,
  std::span<const std::pmr::string> object_classes)
{
	server_schema s;
	for (const auto &text : attribute_types) {
		auto a = parse_attribute_type(text);
		if (!a) {
			++s.skipped_;
			continue;
		}
		const std::size_t i = s.attributes_.size();
		s.attribute_index_.emplace(a->oid, i);
		for (const auto &n : a->names) s.attribute_index_.emplace(n, i);
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
		for (const auto &n : c->names) s.class_index_.emplace(n, i);
		s.classes_.push_back(std::move(*c));
	}
	return s;
}

const attribute_type *server_schema::find_attribute(std::string_view name) const noexcept
{
	const auto it = attribute_index_.find(without_options(name));
	return it == attribute_index_.end() ? nullptr : &attributes_[it->second];
}

const object_class_type *server_schema::find_object_class(std::string_view name) const noexcept
{
	const auto it = class_index_.find(name);
	return it == class_index_.end() ? nullptr : &classes_[it->second];
}

const std::string *server_schema::syntax_of(const attribute_type &a) const noexcept
{
	const attribute_type *cur = &a;
	for (int depth = 0; depth < 32 && cur != nullptr; ++depth) {
		if (cur->syntax) return &*cur->syntax;
		if (!cur->sup) return nullptr;
		cur = find_attribute(*cur->sup);
	}
	return nullptr;
}

// ---------------------------------------------------------------- report

bool schema_report::ok() const noexcept
{
	return std::none_of(issues.begin(), issues.end(), [](const schema_issue &i) { return i.is_error(); });
}

std::string schema_report::to_string() const
{
	std::string out;
	for (const auto &i : issues) {
		if (!out.empty()) out += '\n';
		detail::format_to(out,
		  "{}{}{}: {}",
		  i.is_error() ? "error: " : "warning: ",
		  i.what == schema_issue::kind::unknown_object_class ? "object class " : "attribute ",
		  i.name,
		  i.detail);
	}
	return out;
}

namespace detail {

	void check_object_class(const server_schema &s, std::string_view name, schema_report &out)
	{
		if (s.find_object_class(name) == nullptr)
			out.issues.push_back(
			  { schema_issue::kind::unknown_object_class, std::string(name), "not defined on the server" });
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
			out.issues.push_back(
			  { schema_issue::kind::unknown_attribute, std::string(name), "not defined on the server" });
			return;
		}
		if (kind != cardinality::multiple && !a->single_value)
			out.issues.push_back({ schema_issue::kind::single_member_multi_valued,
			  std::string(name),
			  "single-valued member, but the attribute is multi-valued (decoding fails if an entry has several "
			  "values)" });
		if (!read_only && a->no_user_modification)
			out.issues.push_back({ schema_issue::kind::writable_but_no_user_modification,
			  std::string(name),
			  "the attribute is NO-USER-MODIFICATION: mark the member ldap::read_only" });
		if (!syntaxes.empty()) {
			const std::string *syn = s.syntax_of(*a);
			if (syn != nullptr && std::none_of(syntaxes.begin(), syntaxes.end(), [&](const char *x) { return *syn == x; })) {
				std::string text = detail::format("syntax {} is not one the member's type reads (", *syn);
				for (std::size_t i = 0; i < syntaxes.size(); ++i)
					detail::format_to(text, "{}{}", i ? ", " : "", syntaxes[i]);
				text += ')';
				out.issues.push_back({ schema_issue::kind::syntax_mismatch, std::string(name), std::move(text) });
			}
		}
	}

}// namespace detail

}// namespace jhetz::ldap
