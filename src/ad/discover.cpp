#include "jhetz/ldap/ad/discover.hpp"

#include <unicode/uidna.h>
#include <unicode/utypes.h>

#ifdef _WIN32
#include <windows.h>

#include <windns.h>
#else
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace jhetz::ldap::ad {

namespace {

	constexpr std::uint16_t ldaps_port = 636;
	constexpr std::uint16_t gc_ldaps_port = 3269;
	constexpr std::size_t max_dns_name = 1025;

	constexpr auto uts46_options = static_cast<std::uint32_t>(UIDNA_NONTRANSITIONAL_TO_ASCII)
								   | static_cast<std::uint32_t>(UIDNA_CHECK_BIDI)
								   | static_cast<std::uint32_t>(UIDNA_CHECK_CONTEXTJ);

	auto failed(UErrorCode status) noexcept -> bool { return U_FAILURE(status) != 0; }

	struct idna_closer
	{
		void operator()(UIDNA *p) const noexcept { uidna_close(p); }
	};

	// `name` (UTF-8) as A-labels (UTS #46, nontransitional).
	auto to_ascii(std::string_view name, const std::string &context) -> result<std::string>
	{
		UErrorCode status = U_ZERO_ERROR;
		const std::unique_ptr<UIDNA, idna_closer> idna(uidna_openUTS46(uts46_options, &status));
		if (failed(status)) {
			return fail(client_errc::internal_error, context + ": ICU uidna_openUTS46: " + u_errorName(status));
		}
		std::string out(max_dns_name, '\0');
		UIDNAInfo info = UIDNA_INFO_INITIALIZER;
		const int32_t n = uidna_nameToASCII_UTF8(idna.get(),
		  name.data(),
		  static_cast<int32_t>(name.size()),
		  out.data(),
		  static_cast<int32_t>(out.size()),
		  &info,
		  &status);
		if (failed(status) || info.errors != 0 || n < 0 || static_cast<std::size_t>(n) >= out.size()) {
			return fail(client_errc::string_prep_failed, context + ": not a valid domain name (UTS #46)");
		}
		out.resize(static_cast<std::size_t>(n));
		return out;
	}

	auto random_engine() -> std::mt19937_64 &
	{
		thread_local std::mt19937_64 engine{ std::random_device{}() };
		return engine;
	}

	struct query
	{
		std::string_view kind;// "dc" or "gc"
		std::string_view what;// for the context
		std::uint16_t tls_port;
	};

	auto discover(std::string_view domain, const discover_options &options, const query &q) -> result<std::vector<url>>
	{
		std::string context = "discover ";
		context += q.what;
		context += " of ";
		context += domain;
		if (domain.empty()) {
			return fail(std::make_error_code(std::errc::invalid_argument), context + ": no domain");
		}
		auto ascii_domain = to_ascii(domain, context);
		if (!ascii_domain) {
			return std::unexpected(std::move(ascii_domain.error()));
		}
		std::vector<std::string> names;
		if (!options.site.empty()) {
			auto site = to_ascii(options.site, context);
			if (!site) {
				return std::unexpected(std::move(site.error()));
			}
			names.push_back("_ldap._tcp." + *site + "._sites." + std::string(q.kind) + "._msdcs." + *ascii_domain);
		}
		names.push_back("_ldap._tcp." + std::string(q.kind) + "._msdcs." + *ascii_domain);

		const srv_resolver &resolve = options.resolver ? options.resolver : srv_resolver(resolve_srv);
		std::vector<srv_record> ordered;
		for (const auto &name : names) {
			auto records = resolve(name);
			if (!records) {
				std::string where = context;
				where.append(": SRV ").append(name);
				return std::unexpected(detail::with_context(std::move(records.error()), where));
			}
			for (auto &r : order_srv(std::move(*records), random_engine())) {
				const bool listed = std::ranges::any_of(
				  ordered, [&](const srv_record &o) { return o.target == r.target && o.port == r.port; });
				if (r.target != "." && !r.target.empty() && !listed) {
					ordered.push_back(std::move(r));
				}
			}
		}
		if (ordered.empty()) {
			return fail(std::make_error_code(std::errc::host_unreachable), context + ": no SRV record " + names.back());
		}
		std::vector<url> out;
		out.reserve(ordered.size());
		for (const auto &r : ordered) {
			const std::uint16_t port = options.tls ? q.tls_port : r.port;
			const std::string text = (options.tls ? "ldaps://" : "ldap://") + r.target + ":" + std::to_string(port);
			auto u = url::parse_server(text);
			if (!u) {
				return std::unexpected(detail::with_context(std::move(u.error()), context));
			}
			out.push_back(std::move(*u));
		}
		return out;
	}

}// namespace

#ifdef _WIN32

auto resolve_srv(std::string_view name) -> result<std::vector<srv_record>>
{
	const std::string query(name);
	PDNS_RECORD records = nullptr;
	const DNS_STATUS status =
	  DnsQuery_UTF8(query.c_str(), DNS_TYPE_SRV, DNS_QUERY_STANDARD, nullptr, &records, nullptr);
	if (status == DNS_ERROR_RCODE_NAME_ERROR || status == DNS_INFO_NO_RECORDS) {
		return std::vector<srv_record>{};
	}
	if (status != 0) {
		return fail(std::error_code(static_cast<int>(status), std::system_category()), "DnsQuery " + query);
	}
	std::vector<srv_record> out;
	for (auto *r = reinterpret_cast<DNS_RECORDA *>(records); r != nullptr; r = r->pNext) {
		if (r->wType == DNS_TYPE_SRV && r->Data.SRV.pNameTarget != nullptr) {
			out.push_back({ .priority = r->Data.SRV.wPriority,
			  .weight = r->Data.SRV.wWeight,
			  .port = r->Data.SRV.wPort,
			  .target = std::string(r->Data.SRV.pNameTarget) });
		}
	}
	DnsRecordListFree(records, DnsFreeRecordList);
	return out;
}

#else

auto resolve_srv(std::string_view name) -> result<std::vector<srv_record>>
{
	const std::string query(name);
	const std::string context = "res_nquery SRV " + query;
	struct state_closer
	{
		void operator()(res_state s) const noexcept
		{
			res_nclose(s);
			delete s;// NOLINT(cppcoreguidelines-owning-memory): allocated below for res_ninit
		}
	};
	const std::unique_ptr<struct __res_state, state_closer> st(new (struct __res_state){});
	if (res_ninit(st.get()) != 0) {
		return fail(std::make_error_code(std::errc::io_error), context + ": res_ninit failed");
	}
	std::vector<unsigned char> answer(NS_MAXMSG);
	const int n =
	  res_nquery(st.get(), query.c_str(), ns_c_in, ns_t_srv, answer.data(), static_cast<int>(answer.size()));
	if (n < 0) {
		switch (st->res_h_errno) {
		case HOST_NOT_FOUND:
		case NO_DATA:
			return std::vector<srv_record>{};
		case TRY_AGAIN:
			return fail(std::make_error_code(std::errc::resource_unavailable_try_again), context + ": try again");
		default:
			return fail(std::make_error_code(std::errc::io_error), context + ": DNS failure");
		}
	}
	ns_msg msg{};
	if (ns_initparse(answer.data(), std::min(n, static_cast<int>(answer.size())), &msg) < 0) {
		return fail(client_errc::decode_error, context + ": malformed answer");
	}
	constexpr std::size_t fixed = 6;// priority, weight, port
	std::vector<srv_record> out;
	const int count = ns_msg_count(msg, ns_s_an);
	for (int i = 0; i < count; ++i) {
		ns_rr rr{};
		if (ns_parserr(&msg, ns_s_an, i, &rr) < 0) {
			return fail(client_errc::decode_error, context + ": malformed record");
		}
		if (ns_rr_type(rr) != ns_t_srv) {
			continue;
		}
		const unsigned char *data = ns_rr_rdata(rr);
		if (ns_rr_rdlen(rr) <= fixed) {
			return fail(client_errc::decode_error, context + ": short SRV record");
		}
		std::array<char, NS_MAXDNAME> target{};
		if (dn_expand(ns_msg_base(msg), ns_msg_end(msg), data + fixed, target.data(), static_cast<int>(target.size()))
			< 0) {
			return fail(client_errc::decode_error, context + ": malformed SRV target");
		}
		out.push_back({ .priority = static_cast<std::uint16_t>(ns_get16(data)),
		  .weight = static_cast<std::uint16_t>(ns_get16(data + 2)),
		  .port = static_cast<std::uint16_t>(ns_get16(data + 4)),
		  .target = std::string(target.data()) });
	}
	return out;
}

#endif

auto discover_domain_controllers(std::string_view domain, const discover_options &options) -> result<std::vector<url>>
{
	return discover(domain, options, { .kind = "dc", .what = "domain controllers", .tls_port = ldaps_port });
}

auto discover_global_catalogs(std::string_view forest, const discover_options &options) -> result<std::vector<url>>
{
	return discover(forest, options, { .kind = "gc", .what = "global catalogs", .tls_port = gc_ldaps_port });
}

}// namespace jhetz::ldap::ad
