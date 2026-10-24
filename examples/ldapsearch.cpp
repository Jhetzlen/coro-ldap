// jhetz-ldapsearch: connect, optionally bind, search, print LDIF, unbind.
//
//   ldapsearch [options] URL [FILTER [ATTRIBUTE...]]
//
//   -D DN        bind DN (simple bind); the password comes from -w or the
//                LDAP_PASSWORD environment variable
//   -w PASSWORD  bind password
//   -b DN        search base (default: the URL's DN, else the root DSE)
//   -s SCOPE     base | one | sub | children (default: the URL's, else sub)
//   -z N         size limit (entries), -l N time limit (seconds)
//   --page N     fetch the results in pages of N entries (RFC 2696)
//   --ca-file F  CA certificates (PEM) for ldaps://
//   -Y EXTERNAL  SASL EXTERNAL bind (identity from --cert or ldapi://);
//                -X AUTHZID asks to act as another identity
//   -Z           StartTLS before binding (ldap:// only)
//   --cert F --key F  TLS client certificate and key (PEM)
//   --insecure   do not verify the server certificate (testing only)
//
// The URL's filter and attributes apply when none are given on the command
// line, as in `ldapsearch -H`. For example, against a local OpenLDAP:
//
//   ldapsearch -D cn=admin,dc=example,dc=org -w secret
//       ldap://localhost/dc=example,dc=org '(objectClass=person)' cn mail
//
// (one command line).
//
// Exit status: 0 on success, 1 on an LDAP or connection error, 2 on bad usage.
#include "jhetz/ldap/connection.hpp"

#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <optional>
#include <print>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ldap = jhetz::ldap;
namespace capy = boost::capy;
namespace corosio = boost::corosio;

namespace {

struct options
{
	std::string url{};
	std::optional<std::string> bind_dn{};
	std::optional<std::string> password{};
	std::optional<std::string> base{};
	std::optional<ldap::search_scope> scope{};
	std::optional<std::string> filter{};
	std::vector<std::string> attributes{};
	std::int32_t size_limit = 0;
	std::int32_t page_size = 0;
	std::int32_t time_limit = 0;
	std::string ca_file{};
	bool insecure = false;
	std::string cert_file{};
	std::string key_file{};
	bool start_tls = false;
	std::optional<std::string> sasl_mech{};
	std::string authz_id{};
};

[[noreturn]] void usage(std::string_view problem)
{
	if (!problem.empty()) {
		std::println(stderr, "jhetz-ldapsearch: {}", problem);
	}
	std::println(stderr,
	  "usage: jhetz-ldapsearch [-D binddn] [-w password] [-b base] [-s base|one|sub|children]\n"
	  "                  [-z sizelimit] [-l timelimit] [--page size] [-Y EXTERNAL [-X authzid]] [-Z]\n"
	  "                  [--ca-file file] [--cert file --key file] [--insecure]\n"
	  "                  URL [filter [attribute...]]");
	std::exit(2);// NOLINT(concurrency-mt-unsafe): during argument parsing, before any thread starts
}

auto to_int(std::string_view text, const char *what) -> std::int32_t
{
	std::int32_t v = 0;
	const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
	if (ec != std::errc{} || end != text.data() + text.size() || v < 0) {
		usage(std::string(what) + " must be a non-negative integer");
	}
	return v;
}

auto parse_args(int argc, char **argv) -> options
{
	options o;
	std::vector<std::string_view> positional;
	for (int i = 1; i < argc; ++i) {
		const std::string_view a = argv[i];
		const auto value = [&] -> std::string {
			if (i + 1 >= argc) {
				usage(std::string(a) + " needs a value");
			}
			return argv[++i];
		};
		if (a == "-D") {
			o.bind_dn = value();
		} else if (a == "-w") {
			o.password = value();
		} else if (a == "-b") {
			o.base = value();
		} else if (a == "-s") {
			const std::string s = value();
			if (s == "base") {
				o.scope = ldap::search_scope::base_object;
			} else if (s == "one") {
				o.scope = ldap::search_scope::single_level;
			} else if (s == "sub") {
				o.scope = ldap::search_scope::whole_subtree;
			} else if (s == "children") {
				o.scope = ldap::search_scope::subordinate_subtree;
			} else {
				usage("unknown scope " + s);
			}
		} else if (a == "-z") {
			o.size_limit = to_int(value(), "-z");
		} else if (a == "-l") {
			o.time_limit = to_int(value(), "-l");
		} else if (a == "--page") {
			o.page_size = to_int(value(), "--page");
			if (o.page_size == 0) {
				usage("--page must be positive");
			}
		} else if (a == "--ca-file") {
			o.ca_file = value();
		} else if (a == "--insecure") {
			o.insecure = true;
		} else if (a == "--cert") {
			o.cert_file = value();
		} else if (a == "--key") {
			o.key_file = value();
		} else if (a == "-Z") {
			o.start_tls = true;
		} else if (a == "-Y") {
			o.sasl_mech = value();
			if (*o.sasl_mech != "EXTERNAL") {
				usage("only -Y EXTERNAL is supported");
			}
		} else if (a == "-X") {
			o.authz_id = value();
		} else if (a == "-h" || a == "--help") {
			usage({});
		} else if (a.starts_with('-') && a.size() > 1) {
			usage("unknown option " + std::string(a));
		} else {
			positional.push_back(a);
		}
	}
	if (positional.empty()) {
		usage("missing URL");
	}
	o.url = positional[0];
	if (positional.size() > 1) {
		o.filter = positional[1];
	}
	o.attributes = std::ranges::to<std::vector<std::string>>(positional | std::views::drop(2));
	if (o.bind_dn && !o.password) {
		// NOLINTNEXTLINE(concurrency-mt-unsafe): argument parsing, single-threaded, nothing calls setenv
		if (const char *env = std::getenv("LDAP_PASSWORD")) {
			o.password = env;
		}
	}
	return o;
}

// ---------------------------------------------------------------- LDIF

// RFC 2849 SAFE-STRING: no NUL, CR, LF or non-ASCII octet, and no leading
// space, ':' or '<'; no trailing space either (readers may strip it).
auto ldif_safe(std::string_view v) noexcept -> bool
{
	if (v.empty()) {
		return true;
	}
	if (v.front() == ' ' || v.front() == ':' || v.front() == '<' || v.back() == ' ') {
		return false;
	}
	return std::ranges::none_of(v, [](char c) {
		const auto b = static_cast<unsigned char>(c);
		return b == 0 || b == '\n' || b == '\r' || b >= 0x80;
	});
}

auto base64(std::string_view in) -> std::string
{
	static constexpr std::string_view table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	// Six bits per character.
	constexpr unsigned bits = 6;
	constexpr std::uint32_t mask = 0x3F;
	std::string out;
	out.reserve((in.size() + 2) / 3 * 4);
	std::size_t i = 0;
	for (; i + 2 < in.size(); i += 3) {
		const auto n = static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16
					   | static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8
					   | static_cast<unsigned char>(in[i + 2]);
		out += table[n >> (3 * bits)];
		out += table[(n >> (2 * bits)) & mask];
		out += table[(n >> bits) & mask];
		out += table[n & mask];
	}
	if (const std::size_t rest = in.size() - i; rest > 0) {
		auto n = static_cast<std::uint32_t>(static_cast<unsigned char>(in[i])) << 16;
		if (rest == 2) {
			n |= static_cast<std::uint32_t>(static_cast<unsigned char>(in[i + 1])) << 8;
		}
		out += table[n >> (3 * bits)];
		out += table[(n >> (2 * bits)) & mask];
		out += rest == 2 ? table[(n >> bits) & mask] : '=';
		out += '=';
	}
	return out;
}

void print_line(std::string_view type, std::string_view value)
{
	if (ldif_safe(value)) {
		std::println("{}: {}", type, value);
	} else {
		std::println("{}:: {}", type, base64(value));
	}
}

void print_entry(const ldap::entry &e)
{
	print_line("dn", e.dn);
	for (const auto &a : e.attributes) {
		for (const auto &v : a.values) {
			print_line(a.type.name(), v);
		}
	}
	std::println("");
}

// ---------------------------------------------------------------- session

// Prints every entry of a search_stream or paged_search, then its
// references and a count; 0, or 1 on an error.
template<class Stream> auto print_all(ldap::result<Stream> &s) -> capy::task<int>
{
	if (!s) {
		std::println(stderr, "jhetz-ldapsearch: {}", s.error().message());
		co_return 1;
	}
	int status = 0;
	std::size_t count = 0;
	while (true) {
		auto e = co_await s->next();
		if (!e) {
			std::println(stderr, "jhetz-ldapsearch: {}", e.error().message());
			status = 1;
			break;
		}
		if (!*e) {
			break;
		}
		print_entry(**e);
		++count;
	}
	for (const auto &ref : s->references()) {
		std::println("# search reference: {}", ref);
	}
	if constexpr (requires { s->pages(); }) {
		std::println("# {} entries in {} pages", count, s->pages());
	} else {
		std::println("# {} entries", count);
	}
	co_return status;
}

auto run(corosio::io_context &ioc, options o) -> capy::task<int>
{
	auto u = ldap::url::parse(o.url);
	if (!u) {
		std::println(stderr, "jhetz-ldapsearch: {}", u.error().message());
		co_return 2;
	}

	ldap::search_params params;
	if (o.base) {
		auto d = ldap::dn::parse(*o.base);
		if (!d) {
			std::println(stderr, "jhetz-ldapsearch: -b: {}", d.error().message());
			co_return 2;
		}
		params.base = std::move(*d);
	} else if (u->base_dn()) {
		params.base = *u->base_dn();
	}
	params.scope = o.scope.value_or(u->scope().value_or(ldap::search_scope::whole_subtree));
	if (o.filter) {
		auto f = ldap::filter::raw(*o.filter);
		if (!f) {
			std::println(stderr, "jhetz-ldapsearch: {}", f.error().message());
			co_return 2;
		}
		params.filter = std::move(*f);
	} else if (u->search_filter()) {
		params.filter = *u->search_filter();
	}
	if (!o.attributes.empty()) {
		params.attributes.assign(o.attributes.begin(), o.attributes.end());
	} else {
		params.attributes.assign(u->attributes().begin(), u->attributes().end());
	}
	params.size_limit = o.size_limit;
	params.time_limit = std::chrono::seconds(o.time_limit);

	ldap::connection_options copts;
	copts.tls.ca_file = o.ca_file;
	if (o.insecure) {
		copts.tls.verification = ldap::net::certificate_verification::insecure_accept_any;
	}
	copts.tls.cert_file = o.cert_file;
	copts.tls.key_file = o.key_file;
	copts.start_tls = o.start_tls;

	auto c = co_await ldap::connect(ioc, std::move(*u), std::move(copts));
	if (!c) {
		std::println(stderr, "jhetz-ldapsearch: {}", c.error().message());
		co_return 1;
	}

	if (o.sasl_mech) {
		ldap::sasl_external mech(o.authz_id);
		if (auto b = co_await c->sasl_bind(mech); !b) {
			std::println(stderr, "jhetz-ldapsearch: {}", b.error().message());
			co_return 1;
		}
	} else if (o.bind_dn) {
		auto name = ldap::dn::parse(*o.bind_dn);
		if (!name) {
			std::println(stderr, "jhetz-ldapsearch: -D: {}", name.error().message());
			co_return 2;
		}
		if (auto b = co_await c->simple_bind(std::move(*name), o.password.value_or("")); !b) {
			std::println(stderr, "jhetz-ldapsearch: {}", b.error().message());
			co_return 1;
		}
	}

	int status = 0;
	if (o.page_size > 0) {
		auto s = co_await c->search_paged(std::move(params), o.page_size);
		status = co_await print_all(s);
	} else {
		auto s = co_await c->search_stream(std::move(params));
		status = co_await print_all(s);
	}
	if (c->is_open()) {
		if (auto r = co_await c->unbind(); !r) {
			std::println(stderr, "jhetz-ldapsearch: {}", r.error().message());
		}
	}
	co_return status;
}

}// namespace

auto main(int argc, char **argv) -> int
try {
	options o = parse_args(argc, argv);
	corosio::io_context ioc;
	int status = 1;
	capy::run_async(
	  ioc.get_executor(),
	  [&status](int s) { status = s; },
	  [](std::exception_ptr e) {
		  try {
			  std::rethrow_exception(std::move(e));
		  } catch (const std::exception &x) {
			  std::println(stderr, "jhetz-ldapsearch: {}", x.what());
		  }
	  })(run(ioc, std::move(o)));
	ioc.run();
	return status;
} catch (const std::exception &x) {
	// fputs rather than println, which could throw again.
	(void)std::fputs("jhetz-ldapsearch: ", stderr);
	(void)std::fputs(x.what(), stderr);
	(void)std::fputc('\n', stderr);
	return 1;
}
