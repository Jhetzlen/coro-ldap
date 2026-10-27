// chase_search and chase_compare (referral_chase.hpp): opt-in referral
// chasing on top of the connection's operations.
#include "jhetz/ldap/referral_chase.hpp"

#include "jhetz/ldap/matching.hpp"

#include "../format_util.hpp"
#include "../net/deadline.hpp"
#include "../net/host_name.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/io_result.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace capy = boost::capy;

namespace jhetz::ldap {
namespace {

	using net::detail::clock;

	// What RFC 4511 calls the same server and the same request with the same
	// parameters, for loop detection.
	struct visit_key
	{
		url_scheme scheme = url_scheme::ldap;
		std::string host{};
		std::uint16_t port = 0;
		dn base{};
		std::optional<search_scope> scope{};
		std::optional<ldap::filter> filter{};
	};

	auto same_dn(const dn &a, const dn &b) -> bool
	{
		return a == b || distinguished_name_match(a, b) == match_result::true_value;
	}

	auto same_visit(const visit_key &a, const visit_key &b) -> bool
	{
		return a.scheme == b.scheme && a.host == b.host && a.port == b.port && a.scope == b.scope
			   && a.filter == b.filter && same_dn(a.base, b.base);
	}

	auto server_key(const url &server) -> visit_key
	{
		visit_key k;
		k.scheme = server.scheme();
		// A name ICU cannot convert stays as written: it then only matches
		// itself, which at worst costs one more hop.
		auto host = net::detail::ascii_host_name(server.host());
		k.host = host ? std::move(*host) : std::string(server.host());
		k.port = server.port_or_default();
		return k;
	}

	auto request_key(const url &server, const search_params &p) -> visit_key
	{
		visit_key k = server_key(server);
		k.base = p.base;
		k.scope = p.scope;
		k.filter = p.filter;
		return k;
	}

	auto request_key(const url &server, const compare_params &p) -> visit_key
	{
		visit_key k = server_key(server);
		k.base = p.entry;
		return k;
	}

	// One server's search: its entries and each continuation reference's URIs.
	struct search_run
	{
		std::pmr::vector<entry> entries{};
		std::vector<string_list> references{};
	};

	auto run_search(connection &c, search_params p, std::pmr::memory_resource *mr) -> capy::task<result<search_run>>
	{
		auto s = co_await c.search_stream(std::move(p), mr);
		if (!s) {
			co_return std::unexpected(std::move(s.error()));
		}
		search_run out{ .entries = std::pmr::vector<entry>(mr) };
		while (true) {
			auto item = co_await s->next_item();
			if (!item) {
				co_return std::unexpected(std::move(item.error()));
			}
			if (!*item) {
				co_return out;
			}
			if (auto *e = std::get_if<search_entry>(&**item)) {
				out.entries.push_back(std::move(static_cast<entry &>(*e)));
			} else if (auto *r = std::get_if<search_reference>(&**item)) {
				out.references.push_back(std::move(r->uris));
			}
		}
	}

	struct search_op
	{
		std::pmr::memory_resource *mr;
		auto operator()(connection &c, search_params p) const -> capy::task<result<search_run>>
		{
			return run_search(c, std::move(p), mr);
		}
	};

	struct compare_op
	{
		auto operator()(connection &c, compare_params p) const -> capy::task<result<bool>>
		{
			return c.compare(std::move(p));
		}
	};

	// The first URI of a reference that was followed: the request sent
	// there, its answer, and its depth.
	template<class Params, class Value> struct reached
	{
		Params request{};
		Value value{};
		std::size_t depth = 0;
	};

	// How one reference ended: reached, or not (then the last failure, and
	// whether one of its URIs was a loop).
	template<class Params, class Value> struct followed
	{
		std::optional<reached<Params, Value>> target{};
		std::optional<error> last_failure{};
		bool loop = false;
	};

	struct chase_state
	{
		referral_connector connector;
		referral_policy policy;
		std::optional<clock::time_point> deadline;
		std::vector<referral_attempt> attempts{};
		// URIs considered beyond policy.max_attempts, or not examined.
		std::size_t unlisted = 0;
		std::vector<visit_key> visited{};
		std::size_t targets = 0;

		void record(std::string_view uri,
		  reference_kind kind,
		  std::size_t depth,
		  referral_outcome outcome,
		  std::optional<error> failure = std::nullopt)
		{
			if (attempts.size() >= policy.max_attempts) {
				++unlisted;
				return;
			}
			attempts.push_back({ .uri = std::string(uri),
			  .kind = kind,
			  .depth = depth,
			  .outcome = outcome,
			  .failure = std::move(failure) });
		}

		[[nodiscard]] auto visited_before(const visit_key &k) const -> bool
		{
			return std::ranges::any_of(visited, [&k](const visit_key &v) { return same_visit(v, k); });
		}

		// What is left of the chase's budget, nullopt without one; zero or
		// less once it is spent.
		[[nodiscard]] auto remaining() const -> std::optional<std::chrono::milliseconds>
		{
			if (!deadline) {
				return std::nullopt;
			}
			return std::chrono::ceil<std::chrono::milliseconds>(*deadline - clock::now());
		}

		[[nodiscard]] auto spent() const -> bool
		{
			const auto left = remaining();
			return left && left->count() <= 0;
		}

		// max_targets reached or the budget spent: the chase stops.
		[[nodiscard]] auto exhausted() const -> bool { return targets >= policy.max_targets || spent(); }
	};

	auto canceled() -> error { return make_error(capy::error::canceled, "referral chase"); }

	// The connector's answer as an io_result, for corosio::timeout: its
	// cancellation shows in the code (the deadline is then reported as
	// such), the answer itself in the payload.
	auto as_io_result(capy::task<result<connection *>> asked)
	  -> capy::task<capy::io_result<std::optional<result<connection *>>>>
	{
		auto c = co_await std::move(asked);
		std::error_code ec;
		if (!c && c.error().code == cond::canceled) {
			ec = make_error_code(capy::error::canceled);
		}
		co_return { ec, std::move(c) };
	}

	// Asks the connector for `server`'s connection, cancelled when the
	// chase's budget is spent (then a timeout error).
	auto ask(const chase_state &st, const url &server, std::size_t depth) -> capy::task<result<connection *>>
	{
		auto [ec, c] = co_await net::detail::bounded(as_io_result(st.connector(server, depth)), st.deadline);
		if (c) {
			co_return std::move(*c);
		}
		co_return fail(
		  ec ? ec : make_error_code(capy::error::timeout), "referral connector: the chase's timeout was spent");
	}

	// A URI that passed the checks made before the connector is asked: its
	// server, the request for it, and that request's loop key.
	template<class Params> struct prepared
	{
		url server{};
		Params request{};
		visit_key key{};
	};

	// The URL and the request for `uri`; nullopt (the attempt recorded)
	// when either cannot be had.
	template<class Params>
	auto prepare(chase_state &st, std::string_view uri, reference_kind kind, std::size_t depth, const Params &base)
	  -> std::optional<prepared<Params>>
	{
		auto u = url::parse(uri);
		if (!u) {
			st.record(uri, kind, depth, referral_outcome::unparseable, std::move(u.error()));
			return std::nullopt;
		}
		auto request = [&] {
			if constexpr (std::is_same_v<Params, search_params>) {
				return referral_target(*u, base, kind);
			} else {
				return referral_target(*u, base);
			}
		}();
		if (!request) {
			st.record(uri, kind, depth, referral_outcome::unparseable, std::move(request.error()));
			return std::nullopt;
		}
		visit_key key = request_key(*u, *request);
		return prepared<Params>{ .server = std::move(*u), .request = std::move(*request), .key = std::move(key) };
	}

	// Tries the URIs of one reference in order until one is followed. Over
	// max_hops nothing is parsed: the reference's first URI is limit_reached
	// (a loop there too: telling would cost a parse and a copy of the
	// request per reference). A URI over max_targets or the budget (and not
	// a loop) is limit_reached. Either way the reference's other URIs are
	// not looked at (they would be over it too). Fails only when the chase
	// is cancelled.
	template<class Params, class Value, class Op>
	auto follow(chase_state &st,
	  std::span<const std::pmr::string> uris,
	  reference_kind kind,
	  std::size_t depth,
	  const Params &base,
	  Op op) -> capy::task<result<followed<Params, Value>>>
	{
		// The analyzer does not model the promise's construction: Capy's env_ is
		// nullptr-initialised and set by the awaiting caller before the first resume.
		// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch): false positive
		const std::stop_token stop = co_await capy::this_coro::stop_token;
		followed<Params, Value> out;
		for (const auto &uri : uris) {
			if (stop.stop_requested()) {
				co_return std::unexpected(canceled());
			}
			if (depth > st.policy.max_hops) {
				st.record(uri, kind, depth, referral_outcome::limit_reached);
				break;
			}
			auto p = prepare(st, uri, kind, depth, base);
			if (!p) {
				continue;
			}
			// A loop before max_targets and the budget: a reference that is
			// only a loop leaves the search complete, over them or not.
			if (st.visited_before(p->key)) {
				st.record(uri, kind, depth, referral_outcome::skipped_loop);
				out.loop = true;
				continue;
			}
			if (st.exhausted()) {
				st.record(uri, kind, depth, referral_outcome::limit_reached);
				break;
			}
			++st.targets;
			connection *target = nullptr;
			if (st.connector) {
				auto c = co_await ask(st, p->server, depth);
				if (!c) {
					if (stop.stop_requested()) {
						co_return std::unexpected(std::move(c.error()));
					}
					out.last_failure = c.error();
					st.record(uri, kind, depth, referral_outcome::failed, std::move(c.error()));
					continue;
				}
				target = *c;
			}
			if (target == nullptr) {
				st.record(uri, kind, depth, referral_outcome::skipped_policy);
				continue;
			}
			// What the connector left of the budget bounds the request.
			if (const auto left = st.remaining()) {
				if (left->count() <= 0) {// the reference stops here, as above
					st.record(uri, kind, depth, referral_outcome::limit_reached);
					break;
				}
				p->request.timeout = *left;
			}
			st.visited.push_back(std::move(p->key));
			auto v = co_await op(*target, p->request);
			if (v) {
				st.record(uri, kind, depth, referral_outcome::followed);
				out.target =
				  reached<Params, Value>{ .request = std::move(p->request), .value = std::move(*v), .depth = depth };
				co_return out;
			}
			if (stop.stop_requested()) {
				co_return std::unexpected(std::move(v.error()));
			}
			if (v.error().code != errc::referral) {
				out.last_failure = v.error();
				st.record(uri, kind, depth, referral_outcome::failed, std::move(v.error()));
				continue;
			}
			// A referral result from the target: chase it one hop deeper.
			st.record(uri, kind, depth, referral_outcome::followed);
			auto nested = co_await follow<Params, Value>(st,
			  std::span<const std::pmr::string>(v.error().referrals),
			  reference_kind::referral,
			  depth + 1,
			  p->request,
			  op);
			if (!nested) {
				co_return std::unexpected(std::move(nested.error()));
			}
			if (nested->target) {
				co_return std::move(*nested);
			}
			out.last_failure = nested->last_failure ? std::move(nested->last_failure) : std::move(v.error());
		}
		co_return out;
	}

	// The chase's state for `request` on `origin`: its budget, and the
	// origin's own request as visited when its name is a URL.
	template<class Params>
	auto start(connection &origin, const Params &request, referral_connector &&connector, referral_policy policy)
	  -> chase_state
	{
		chase_state st{ .connector = std::move(connector),
			.policy = policy,
			.deadline = net::detail::deadline_after(request.timeout) };
		if (auto u = url::parse(origin.name())) {
			st.visited.push_back(request_key(*u, request));
		}
		return st;
	}

	auto outcome_name(referral_outcome o) -> std::string_view
	{
		switch (o) {
		case referral_outcome::followed:
			return "followed";
		case referral_outcome::skipped_policy:
			return "skipped_policy";
		case referral_outcome::skipped_loop:
			return "skipped_loop";
		case referral_outcome::limit_reached:
			return "limit_reached";
		case referral_outcome::unparseable:
			return "unparseable";
		case referral_outcome::failed:
			return "failed";
		}
		return "unknown";
	}

	// The error of a referral result that could not be followed, its
	// context counting what became of the URIs (the attempt list itself is
	// not returned with an error).
	auto with_attempts(error e, const chase_state &st) -> error
	{
		if (st.attempts.empty() && st.unlisted == 0) {
			return e;
		}
		constexpr std::array all{ referral_outcome::followed,
			referral_outcome::skipped_policy,
			referral_outcome::skipped_loop,
			referral_outcome::limit_reached,
			referral_outcome::unparseable,
			referral_outcome::failed };
		std::string summary = "referral chase (URIs:";
		const char *sep = " ";
		for (const auto o : all) {
			const auto n = std::ranges::count(st.attempts, o, &referral_attempt::outcome);
			if (n > 0) {
				ldap::detail::format_to(summary, "{}{} {}", sep, n, outcome_name(o));
				sep = ", ";
			}
		}
		if (st.unlisted > 0) {
			ldap::detail::format_to(summary, "{}{} unlisted", sep, st.unlisted);
		}
		summary += ')';
		return detail::with_context(std::move(e), summary);
	}

	// A continuation reference waiting to be followed: its URIs, and the
	// request that got it, shared by the references of one run (not a copy
	// each: a reference costs the server a few dozen bytes).
	struct pending_reference
	{
		string_list uris{};
		std::size_t depth = 0;
		std::shared_ptr<const search_params> request{};
	};

}// namespace

auto chase_search(connection &origin,
  search_params request,
  referral_connector connector,
  referral_policy policy,
  std::pmr::memory_resource *mr) -> capy::task<result<chased_search>>
{
	chase_state st = start(origin, request, std::move(connector), policy);
	const search_op op{ mr };

	std::optional<reached<search_params, search_run>> first;
	{
		auto r = co_await op(origin, request);
		if (r) {
			first.emplace(reached<search_params, search_run>{ .request = std::move(request), .value = std::move(*r) });
		} else if (r.error().code != errc::referral) {
			co_return std::unexpected(std::move(r.error()));
		} else {
			auto f = co_await follow<search_params, search_run>(
			  st, std::span<const std::pmr::string>(r.error().referrals), reference_kind::referral, 1, request, op);
			if (!f) {
				co_return std::unexpected(std::move(f.error()));
			}
			if (!f->target) {
				co_return std::unexpected(
				  with_attempts(f->last_failure ? std::move(*f->last_failure) : std::move(r.error()), st));
			}
			first = std::move(f->target);
		}
	}

	chased_search out{ .entries = std::pmr::vector<entry>(mr) };
	std::deque<pending_reference> queue;
	const auto take = [&out, &queue](reached<search_params, search_run> &r) {
		for (auto &e : r.value.entries) {
			out.entries.push_back(std::move(e));
		}
		if (r.value.references.empty()) {
			return;
		}
		const auto shared = std::make_shared<const search_params>(std::move(r.request));
		for (auto &uris : r.value.references) {
			queue.push_back({ .uris = std::move(uris), .depth = r.depth + 1, .request = shared });
		}
	};
	take(*first);
	while (!queue.empty()) {
		if (st.exhausted()) {
			// The chase stops: what is left is counted, not examined.
			for (const auto &ref : queue) {
				st.unlisted += ref.uris.size();
			}
			queue.clear();
			out.complete = false;
			break;
		}
		pending_reference ref = std::move(queue.front());
		queue.pop_front();
		auto f = co_await follow<search_params, search_run>(st,
		  std::span<const std::pmr::string>(ref.uris),
		  reference_kind::continuation_reference,
		  ref.depth,
		  *ref.request,
		  op);
		if (!f) {
			co_return std::unexpected(std::move(f.error()));
		}
		if (f->target) {
			take(*f->target);
		} else if (!f->loop) {
			out.complete = false;
		}
	}
	out.referrals = std::move(st.attempts);
	out.unlisted = st.unlisted;
	co_return out;
}

auto chase_compare(connection &origin, compare_params request, referral_connector connector, referral_policy policy)
  -> capy::task<result<chased_compare>>
{
	chase_state st = start(origin, request, std::move(connector), policy);
	auto r = co_await origin.compare(request);
	if (r) {
		co_return chased_compare{ .value = *r };
	}
	if (r.error().code != errc::referral) {
		co_return std::unexpected(std::move(r.error()));
	}
	auto f = co_await follow<compare_params, bool>(
	  st, std::span<const std::pmr::string>(r.error().referrals), reference_kind::referral, 1, request, compare_op{});
	if (!f) {
		co_return std::unexpected(std::move(f.error()));
	}
	if (!f->target) {
		co_return std::unexpected(
		  with_attempts(f->last_failure ? std::move(*f->last_failure) : std::move(r.error()), st));
	}
	co_return chased_compare{ .value = f->target->value, .referrals = std::move(st.attempts), .unlisted = st.unlisted };
}

}// namespace jhetz::ldap
