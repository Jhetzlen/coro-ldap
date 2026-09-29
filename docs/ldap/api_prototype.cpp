// Throwaway prototype validating the API shapes in DESIGN.md compile as C++23.
// Not the implementation: filters are strings here (the real one builds an AST),
// values are std::string only, and there is no I/O.
//   g++ -std=c++23 -Wall -Wextra docs/ldap/api_prototype.cpp && ./a.out

#include <charconv>
#include <chrono>
#include <cstdint>
#include <expected>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <tuple>
#include <variant>
#include <vector>

namespace ldap {

// ---------------- errors ----------------
enum class client_errc { missing_attribute = 1, conversion_failed, too_many_values };
struct client_category_t : std::error_category {
    const char* name() const noexcept override { return "ldap.client"; }
    std::string message(int) const override { return "client error"; }
};
inline const std::error_category& client_category() { static client_category_t c; return c; }
inline std::error_code make_error_code(client_errc e) { return {int(e), client_category()}; }
}
template<> struct std::is_error_code_enum<ldap::client_errc> : std::true_type {};
namespace ldap {

struct error {
    std::error_code code{};
    std::string     diagnostic{};
    std::string     matched_dn{};
    std::string     context{};   // e.g. "entry 'uid=x', attribute 'mail'"
};
template<class T> using result = std::expected<T, error>;

// ---------------- values & entries ----------------
using values = std::vector<std::string>;
struct entry { std::string dn; std::map<std::string, values> attrs; };

template<class T> struct value_traits;  // customization point
template<> struct value_traits<std::string> {
    static result<std::string> decode(const std::string& s) { return s; }
    static std::string encode(const std::string& v) { return v; }
};
template<> struct value_traits<int> {
    static result<int> decode(const std::string& s) {
        int v{}; auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        if (ec != std::errc{} || p != s.data() + s.size())
            return std::unexpected(error{client_errc::conversion_failed, {}, {}, "not an integer: " + s});
        return v;
    }
    static std::string encode(int v) { return std::to_string(v); }
};

// ---------------- descriptor ----------------
template<class> struct member_type;
template<class C, class M> struct member_type<M C::*> { using type = M; using owner = C; };

template<auto Ptr> struct field {
    using type = typename member_type<decltype(Ptr)>::type;
    static constexpr auto ptr = Ptr;
    const char* name;
    constexpr explicit field(const char* n) : name(n) {}
};
template<class... F> struct descriptor { std::tuple<F...> fields; };
template<class... F> constexpr auto describe(F... f) { return descriptor<F...>{{f...}}; }

struct not_described {};
template<class T> constexpr auto schema = not_described{};
template<class T> concept described = !std::is_same_v<std::remove_cv_t<decltype(schema<T>)>, not_described>;

// field kinds: T (required single), optional<T>, vector<T>
template<class T> struct field_codec {
    static result<T> decode(const values* v) {
        if (!v || v->empty()) return std::unexpected(error{client_errc::missing_attribute});
        if (v->size() > 1) return std::unexpected(error{client_errc::too_many_values});
        return value_traits<T>::decode((*v)[0]);
    }
};
template<class T> struct field_codec<std::optional<T>> {
    static result<std::optional<T>> decode(const values* v) {
        if (!v || v->empty()) return std::optional<T>{};
        return field_codec<T>::decode(v).transform([](T x) { return std::optional<T>(std::move(x)); });
    }
};
template<class T> struct field_codec<std::vector<T>> {
    static result<std::vector<T>> decode(const values* v) {
        std::vector<T> out;
        if (v) for (auto& s : *v) {
            auto r = value_traits<T>::decode(s);
            if (!r) return std::unexpected(r.error());
            out.push_back(std::move(*r));
        }
        return out;
    }
};

template<described T> result<T> decode(const entry& e) {
    T obj{};
    std::optional<error> err;
    std::apply([&](auto const&... f) {
        ([&] {
            if (err) return;
            using F = std::remove_cvref_t<decltype(f)>;
            auto it = e.attrs.find(f.name);
            auto r = field_codec<typename F::type>::decode(it == e.attrs.end() ? nullptr : &it->second);
            if (!r) { err = r.error(); err->context = "entry '" + e.dn + "', attribute '" + f.name + "'"; return; }
            obj.*F::ptr = std::move(*r);
        }(), ...);
    }, schema<T>.fields);
    if (err) return std::unexpected(*err);
    return obj;
}

template<described T> std::vector<std::string> attribute_list() {
    return std::apply([](auto const&... f) { return std::vector<std::string>{f.name...}; }, schema<T>.fields);
}

// modify: member pointer -> attribute name, checked at compile time
template<auto A, auto B>
constexpr bool same_member = [] {
    if constexpr (std::is_same_v<decltype(A), decltype(B)>) return A == B;
    else return false;
}();
template<auto Ptr, class... F>
consteval const char* name_of(const descriptor<F...>& d) {
    static_assert((same_member<F::ptr, Ptr> || ...), "member is not listed in ldap::schema<T>");
    const char* n = nullptr;
    std::apply([&](auto const&... f) {
        ((n = same_member<std::remove_cvref_t<decltype(f)>::ptr, Ptr> ? f.name : n), ...);
    }, d.fields);
    return n;
}
struct modification { enum op_t { add, del, replace } op; std::string attr; values vals; };
template<auto Ptr, class V> modification replace(V&& v) {
    using C = typename member_type<decltype(Ptr)>::owner;
    constexpr const char* name = name_of<Ptr>(schema<C>);
    return {modification::replace, name, {std::string(std::forward<V>(v))}};
}

// ---------------- filter DSL ----------------
struct filter { std::string text; };  // real impl: AST; text form here for the prototype
inline std::string escape(std::string_view v) {
    std::string o;
    for (unsigned char c : v) {
        if (c == '*' || c == '(' || c == ')' || c == '\\' || c == 0) { char b[4]; std::snprintf(b, 4, "\\%02x", c); o += b; }
        else o += char(c);
    }
    return o;
}
struct attr { std::string name;
    filter operator==(std::string_view v) const { return {"(" + name + "=" + escape(v) + ")"}; }
    filter present() const { return {"(" + name + "=*)"}; }
    filter starts_with(std::string_view v) const { return {"(" + name + "=" + escape(v) + "*)"}; }
};
inline filter operator&&(filter a, filter b) { return {"(&" + a.text + b.text + ")"}; }
inline filter operator||(filter a, filter b) { return {"(|" + a.text + b.text + ")"}; }
inline filter operator!(filter a) { return {"(!" + a.text + ")"}; }
} // namespace ldap

// ---------------- user code ----------------
struct person {
    std::string                uid;
    std::optional<std::string> mail;
    std::vector<std::string>   member_of;
    int                        uid_number{};
};
template<> constexpr auto ldap::schema<person> = ldap::describe(
    ldap::field<&person::uid>("uid"),
    ldap::field<&person::mail>("mail"),
    ldap::field<&person::member_of>("memberOf"),
    ldap::field<&person::uid_number>("uidNumber"));

int main() {
    using ldap::attr;
    std::string evil = "x)(uid=*";
    auto f = attr{"objectClass"} == "person" && (attr{"uid"} == evil || attr{"mail"}.starts_with("j")) && !attr{"disabled"}.present();
    std::cout << f.text << '\n';

    for (auto& a : ldap::attribute_list<person>()) std::cout << a << ' ';
    std::cout << '\n';

    ldap::entry ok{"uid=jdoe,dc=x", {{"uid", {"jdoe"}}, {"memberOf", {"cn=a", "cn=b"}}, {"uidNumber", {"1000"}}}};
    auto p = ldap::decode<person>(ok);
    std::cout << "ok: " << p->uid << " groups=" << p->member_of.size() << " mail?" << p->mail.has_value() << " n=" << p->uid_number << '\n';

    ldap::entry bad{"uid=x,dc=x", {{"uid", {"x"}}, {"uidNumber", {"12a"}}}};
    auto b = ldap::decode<person>(bad);
    std::cout << "bad: " << b.error().context << " -> " << b.error().diagnostic << "|" << (b.error().code == ldap::client_errc::conversion_failed) << '\n';

    auto m = ldap::replace<&person::mail>("new@x.org");
    std::cout << "modify: " << m.attr << '\n';
}
