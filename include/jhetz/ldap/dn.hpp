// Distinguished names (RFC 4514 string form), syntax only: values compare
// byte for byte after unescaping (docs/API.md, DESIGN.md section 1).
#pragma once

#include "jhetz/ldap/attribute.hpp"
#include "jhetz/ldap/error.hpp"

#include <cstddef>
#include <initializer_list>
#include <memory_resource>
#include <string>
#include <string_view>
#include <vector>

namespace jhetz::ldap {

namespace detail {

	// Characters that may follow `\` as themselves (RFC 4514 `special` + ESC).
	constexpr auto is_dn_escapable(char c) noexcept -> bool
	{
		switch (c) {
		case '\\':
		case '"':
		case '+':
		case ',':
		case ';':
		case '<':
		case '>':
		case ' ':
		case '#':
		case '=':
			return true;
		default:
			return false;
		}
	}

	struct dn_token
	{
		std::string_view type;
		std::string_view raw_value;// escaped text, or hex digits after '#'
		bool hex = false;
		bool new_rdn = true;// false: joined to the previous AVA with '+'
	};

	// The length of the value unit at s[i] (an escape, a UTF-8 sequence or one
	// character); 0 if none may start there.
	constexpr auto dn_value_unit_length(std::string_view s, std::size_t i) noexcept -> std::size_t
	{
		const std::size_t n = s.size();
		const char c = s[i];
		if (c == '\\') {
			if (i + 1 < n && is_dn_escapable(s[i + 1])) {
				return 2;
			}
			if (i + 2 < n && is_hex(s[i + 1]) && is_hex(s[i + 2])) {
				return 3;
			}
			return 0;
		}
		if (c == '"' || c == ';' || c == '<' || c == '>' || c == '\0') {
			return 0;
		}
		if (static_cast<unsigned char>(c) >= 0x80u) {
			return utf8_sequence_length(s, i);
		}
		return 1;
	}

	// Scans the `#hexstring` value at s[i]; npos, or the offset of the error.
	constexpr auto scan_dn_hex_value(std::string_view s, std::size_t &i, dn_token &tok) noexcept -> std::size_t
	{
		const std::size_t start = i;
		while (i < s.size() && is_hex(s[i])) {
			++i;
		}
		if (i == start || (i - start) % 2 != 0) {
			return i;
		}
		tok.raw_value = s.substr(start, i - start);
		tok.hex = true;
		return std::string_view::npos;
	}

	// Scans the string value at s[i] up to ',' or '+', without unescaped
	// trailing spaces; npos, or the offset of the error.
	constexpr auto scan_dn_string_value(std::string_view s, std::size_t &i, dn_token &tok) noexcept -> std::size_t
	{
		const std::size_t start = i;
		std::size_t end = i;// without unescaped trailing spaces
		while (i < s.size() && s[i] != ',' && s[i] != '+') {
			if (s[i] == ' ') {
				++i;
				continue;
			}
			const std::size_t len = dn_value_unit_length(s, i);
			if (len == 0) {
				return i;
			}
			i += len;
			end = i;
		}
		tok.raw_value = s.substr(start, end - start);
		return std::string_view::npos;
	}

	// Calls `on_ava(dn_token)` for every AVA of RFC 4514 text; npos on success,
	// else the offset of the error. constexpr, for the literals.
	template<class F> constexpr auto scan_dn(std::string_view s, const F &on_ava) -> std::size_t
	{
		constexpr std::size_t ok = std::string_view::npos;
		if (s.empty()) {
			return ok;
		}
		const std::size_t n = s.size();
		std::size_t i = 0;
		bool new_rdn = true;
		const auto skip_spaces = [&] {
			while (i < n && s[i] == ' ') {
				++i;
			}
		};
		while (true) {
			skip_spaces();
			const std::size_t type_start = i;
			while (i < n && (is_keychar(s[i]) || s[i] == '.')) {
				++i;
			}
			const std::string_view type = s.substr(type_start, i - type_start);
			if (!is_oid(type)) {
				return type_start;
			}
			skip_spaces();
			if (i == n || s[i] != '=') {
				return i;
			}
			++i;
			skip_spaces();

			dn_token tok{ .type = type, .raw_value = {}, .hex = false, .new_rdn = new_rdn };
			if (i < n && s[i] == '#') {
				++i;
				if (const std::size_t error = scan_dn_hex_value(s, i, tok); error != ok) {
					return error;
				}
				skip_spaces();
			} else if (const std::size_t error = scan_dn_string_value(s, i, tok); error != ok) {
				return error;
			}
			on_ava(tok);
			if (i == n) {
				return ok;
			}
			if (s[i] == ',') {
				new_rdn = true;
			} else if (s[i] == '+') {
				new_rdn = false;
			} else {
				return i;
			}
			++i;
		}
	}

	constexpr auto is_dn(std::string_view s) noexcept -> bool
	{
		return scan_dn(s, [](const dn_token &) {}) == std::string_view::npos;
	}

	// Exactly one RDN.
	constexpr auto is_rdn(std::string_view s) noexcept -> bool
	{
		std::size_t rdns = 0;
		const auto count = [&rdns](const dn_token &t) {
			if (t.new_rdn) {
				++rdns;
			}
		};
		return scan_dn(s, count) == std::string_view::npos && rdns == 1;
	}

}// namespace detail

// One attribute type and value; `value` holds the unescaped bytes, or the
// decoded BER bytes of the `#hexstring` form.
struct ava
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	attribute type{};
	std::pmr::string value{};
	bool hex_form = false;

	ava() = default;
	explicit ava(const allocator_type &alloc) : type(alloc), value(alloc) {}
	ava(const attribute &type_, std::string_view value_, bool hex_form_ = false, const allocator_type &alloc = {})
	  : type(type_, alloc), value(value_, alloc), hex_form(hex_form_)
	{}
	ava(const ava &) = default;
	ava(ava &&) noexcept = default;
	ava(const ava &other, const allocator_type &alloc)
	  : type(other.type, alloc), value(other.value, alloc), hex_form(other.hex_form)
	{}
	ava(ava &&other, const allocator_type &alloc)
	  : type(std::move(other.type), alloc), value(std::move(other.value), alloc), hex_form(other.hex_form)
	{}
	auto operator=(const ava &) -> ava & = default;
	auto operator=(ava &&) -> ava & = default;
	~ava() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return value.get_allocator(); }

	// Type case-insensitively, value and form exactly.
	friend auto operator==(const ava &, const ava &) -> bool = default;
};

// One or more AVAs joined with '+'; equality ignores their order.
struct rdn
{
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// Compile-time checked literal: `ldap::rdn{"uid=jdoe"}`.
	struct literal
	{
		// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_rdn(s)) {
				// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
				throw "ldap::rdn: not exactly one relative distinguished name";
			}
		}
		const char *text;
	};

	std::pmr::vector<ava> avas{};

	rdn() = default;
	explicit rdn(const allocator_type &alloc) : avas(alloc) {}
	explicit rdn(literal l, const allocator_type &alloc = {});
	rdn(std::initializer_list<ava> avas_, const allocator_type &alloc = {}) : avas(avas_, alloc) {}
	rdn(const rdn &) = default;
	rdn(rdn &&) noexcept = default;
	rdn(const rdn &other, const allocator_type &alloc) : avas(other.avas, alloc) {}
	rdn(rdn &&other, const allocator_type &alloc) : avas(std::move(other.avas), alloc) {}
	auto operator=(const rdn &) -> rdn & = default;
	auto operator=(rdn &&) -> rdn & = default;
	~rdn() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return avas.get_allocator(); }

	// RFC 4514 text of exactly one RDN; invalid_dn otherwise.
	[[nodiscard]] static auto parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<rdn>;

	// parse(to_string()) == *this.
	[[nodiscard]] auto to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	friend auto operator==(const rdn &a, const rdn &b) -> bool;
};

class dn
{
  public:
	using allocator_type = std::pmr::polymorphic_allocator<>;

	// Compile-time checked literal: `ldap::dn{"ou=people,dc=example,dc=org"}`.
	struct literal
	{
		// NOLINTNEXTLINE(cppcoreguidelines-explicit-constructor,misc-explicit-constructor)
		consteval literal(const char *s) : text(s)
		{
			if (!detail::is_dn(s)) {
				// NOLINTNEXTLINE(bugprone-std-exception-baseclass): consteval, fails compilation with this text
				throw "ldap::dn: invalid distinguished name";
			}
		}
		const char *text;
	};

	dn() = default;// the empty DN (root DSE)
	explicit dn(const allocator_type &alloc) : rdns_(alloc) {}
	explicit dn(literal l, const allocator_type &alloc = {});
	dn(const dn &) = default;
	dn(dn &&) noexcept = default;
	dn(const dn &other, const allocator_type &alloc) : rdns_(other.rdns_, alloc) {}
	dn(dn &&other, const allocator_type &alloc) : rdns_(std::move(other.rdns_), alloc) {}
	auto operator=(const dn &) -> dn & = default;
	auto operator=(dn &&) -> dn & = default;
	~dn() = default;

	[[nodiscard]] auto get_allocator() const noexcept -> allocator_type { return rdns_.get_allocator(); }

	[[nodiscard]] static auto parse(std::string_view text,
	  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> result<dn>;

	// RFC 4514 string form; parse(to_string()) == *this.
	[[nodiscard]] auto to_string(std::pmr::memory_resource *mr = std::pmr::get_default_resource()) const
	  -> std::pmr::string;

	// Most specific RDN first.
	[[nodiscard]] auto rdns() const noexcept -> const std::pmr::vector<rdn> & { return rdns_; }
	[[nodiscard]] auto empty() const noexcept -> bool { return rdns_.empty(); }
	// The parent of the empty DN is the empty DN.
	[[nodiscard]] auto parent() const -> dn;
	// `r` prepended; invalid_dn for an invalid RDN.
	[[nodiscard]] auto child(const rdn &r) const -> result<dn>;
	[[nodiscard]] auto child(rdn &&r) const -> result<dn>;
	// `relative` prepended, its RDNs in order.
	[[nodiscard]] auto child(const dn &relative) const -> dn;

	friend auto operator==(const dn &, const dn &) -> bool = default;

  private:
	std::pmr::vector<rdn> rdns_{};
};

// One attribute value escaped exactly as dn::to_string() writes it.
[[nodiscard]] auto escape_dn_value(std::string_view value,
  std::pmr::memory_resource *mr = std::pmr::get_default_resource()) -> std::pmr::string;

}// namespace jhetz::ldap
