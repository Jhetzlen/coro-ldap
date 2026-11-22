// chase_search and chase_compare (referral_chase.hpp): opt-in referral
// chasing on top of the connection's operations.
#include "jhetz/ldap/referral_chase.hpp"

#include "jhetz/ldap/matching.hpp"

#include "../format_util.hpp"
#include "../net/deadline.hpp"
#include "../net/host_name.hpp"
#include "../strand_util.hpp"
#include "referral_chase_impl.hpp"
#include "search.hpp"

#include <boost/capy/error.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/results.hpp>

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

	// One server's search: its entries, each continuation reference's URIs,
	// and its SearchResultDone (success or a limit code) with its controls.
	struct search_run
	{
		std::pmr::vector<entry> entries{};
		std::vector<string_list> references{};
		ldap_result done{};
		std::pmr::vector<control> controls{};
	};

	auto run_search_here(connection &c, search_params p, std::pmr::memory_resource *mr)
	  -> capy::task<result<search_run>>
	{
		auto s = co_await c.search_stream(std::move(p), mr);
		if (!s) {
			co_return std::unexpected(std::move(s.error()));
		}
		search_run out{ .entries = std::pmr::vector<entry>(mr) };
		auto done = co_await detail::drain_search(
		  *s,
		  [](ldap::search_stream &stream) { return stream.next_item(); },
		  [&out](ldap::search_stream::item &&item) {
			  if (auto *e = std::get_if<search_entry>(&item)) {
				  out.entries.push_back(std::move(static_cast<entry &>(*e)));
			  } else if (auto *r = std::get_if<search_reference>(&item)) {
				  out.references.push_back(std::move(r->uris));
			  }
		  });
		if (!done) {
			co_return std::unexpected(std::move(done.error()));
		}
		out.done = **done;
		out.controls = s->controls();
		co_return out;
	}

	// On the connection's strand: the search_stream ends there, before the
	// result is delivered.
	auto run_search(connection &c, search_params p, std::pmr::memory_resource *mr) -> capy::task<result<search_run>>
	{
		return detail::on_strand(c.executor(), run_search_here(c, std::move(p), mr));
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
		auto operator()(connection &c, compare_params p) const -> capy::task<result<compare_result>>
		{
			return c.compare(std::move(p));
		}
	};

	// The first URI of a reference that was followed: request, answer, depth.
	template<class Params, class Value> struct reached
	{
		Params request;
		Value value{};
		std::size_t depth = 0;
	};

	// How one reference ended: reached, or the last failure and whether a URI
	// was a loop.
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
		detail::chase_settings settings{};
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
			const bool listed = attempts.size() < policy.max_attempts;
			if (!listed) {
				++unlisted;
				if (!settings.on_attempt) {
					return;
				}
			}
			referral_attempt a{
				.uri = std::string(uri), .kind = kind, .depth = depth, .outcome = outcome, .failure = std::move(failure)
			};
			if (settings.on_attempt) {
				settings.on_attempt(a);
			}
			if (listed) {
				attempts.push_back(std::move(a));
			}
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

	// The connector's answer as a capy::results, for corosio::timeout.
	auto as_results(capy::task<result<connection *>> asked)
	  -> capy::task<capy::results<std::optional<result<connection *>>>>
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
		auto [ec, c] = co_await net::detail::bounded(as_results(st.connector(server, depth)), st.deadline);
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
		Params request;
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

	// Tries the URIs of one reference in order until one is followed; over a
	// limit, the first URI is limit_reached and the others are skipped. Fails
	// only when the chase is cancelled.
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
			if (v.error().code != errc::referral || !st.settings.referrals) {
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
	auto start(connection &origin,
	  const Params &request,
	  referral_connector &&connector,
	  referral_policy policy,
	  detail::chase_settings &&settings) -> chase_state
	{
		chase_state st{ .connector = std::move(connector),
			.policy = policy,
			.deadline = net::detail::deadline_after(request.timeout),
			.settings = std::move(settings) };
		if (request.follow_referrals) {
			st.settings.referrals = *request.follow_referrals;
		}
		if constexpr (requires { request.follow_references; }) {
			if (request.follow_references) {
				st.settings.references = *request.follow_references;
			}
		}
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

	// The error of an unfollowed referral result, its context counting the
	// URI outcomes.
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

	// A continuation reference waiting to be followed, with the request that
	// got it (shared).
	struct pending_reference
	{
		string_list uris{};
		std::size_t depth = 0;
		std::shared_ptr<const search_params> request{};
	};

}// namespace

namespace {

	using search_reached = reached<search_params, search_run>;

	// The operation on the origin, and the chase of its referral result.
	template<class Params, class Value, class Op>
	auto first_hop(connection &origin, chase_state &st, Params request, const Op &op)
	  -> capy::task<detail::chase_result<reached<Params, Value>>>
	{
		auto r = co_await op(origin, request);
		if (r) {
			co_return { .value = reached<Params, Value>{ .request = std::move(request), .value = std::move(*r) } };
		}
		if (r.error().code != errc::referral || !st.settings.referrals) {
			co_return { .value = std::unexpected(std::move(r.error())), .origin_failed = true };
		}
		auto f = co_await follow<Params, Value>(
		  st, std::span<const std::pmr::string>(r.error().referrals), reference_kind::referral, 1, request, op);
		if (!f) {
			co_return { .value = std::unexpected(std::move(f.error())) };
		}
		if (!f->target) {
			co_return { .value = std::unexpected(
						  with_attempts(f->last_failure ? std::move(*f->last_failure) : std::move(r.error()), st)) };
		}
		co_return { .value = std::move(*f->target) };
	}

	// The continuation references waiting, and the result being built.
	struct reference_queue
	{
		chase_state *st;
		search_result *out;
		std::deque<pending_reference> queue{};

		// The URIs of a reference not followed: kept in `references`.
		void unfollowed(const string_list &uris) const
		{
			out->references.insert(out->references.end(), uris.begin(), uris.end());
		}

		// Takes the entries of `r` and queues (or counts) its references; a
		// continuation's limit code replaces the origin's success.
		void take(search_reached &r, bool continuation)
		{
			for (auto &e : r.value.entries) {
				out->entries.push_back(std::move(e));
			}
			if (!r.value.done.is_success() && continuation && out->result_code == 0) {
				out->result_code = r.value.done.result_code;
				out->matched_dn.assign(r.value.done.matched_dn);
				out->diagnostic_message.assign(r.value.done.diagnostic_message);
			}
			if (r.value.references.empty()) {
				return;
			}
			if (!st->settings.references) {
				for (const auto &uris : r.value.references) {
					st->unlisted += uris.size();
					unfollowed(uris);
				}
				return;
			}
			const auto shared = std::make_shared<const search_params>(std::move(r.request));
			for (auto &uris : r.value.references) {
				queue.push_back({ .uris = std::move(uris), .depth = r.depth + 1, .request = shared });
			}
		}

		// The chase stops: what is left is counted, not examined.
		void drop_rest()
		{
			for (const auto &ref : queue) {
				st->unlisted += ref.uris.size();
				unfollowed(ref.uris);
			}
			queue.clear();
		}
	};

}// namespace

namespace detail {

	auto chase_search(connection &origin,
	  search_params request,
	  referral_connector connector,
	  referral_policy policy,
	  std::pmr::memory_resource *mr,
	  chase_settings settings) -> capy::task<chase_result<search_result>>
	{
		chase_state st = start(origin, request, std::move(connector), policy, std::move(settings));
		const search_op op{ mr };

		auto first = co_await first_hop<search_params, search_run>(origin, st, std::move(request), op);
		if (!first.value) {
			co_return { .value = std::unexpected(std::move(first.value.error())),
				.origin_failed = first.origin_failed };
		}
		const search_run &origin_run = first.value->value;
		search_result out{ .entries = std::pmr::vector<entry>(mr),
			.references = string_list(mr),
			.result_code = origin_run.done.result_code,
			.matched_dn = origin_run.done.matched_dn,
			.diagnostic_message = origin_run.done.diagnostic_message,
			.controls = origin_run.controls };
		reference_queue refs{ .st = &st, .out = &out };
		refs.take(*first.value, false);
		while (!refs.queue.empty()) {
			if (st.exhausted()) {
				refs.drop_rest();
				break;
			}
			pending_reference ref = std::move(refs.queue.front());
			refs.queue.pop_front();
			auto f = co_await follow<search_params, search_run>(st,
			  std::span<const std::pmr::string>(ref.uris),
			  reference_kind::continuation_reference,
			  ref.depth,
			  *ref.request,
			  op);
			if (!f) {
				co_return { .value = std::unexpected(std::move(f.error())) };
			}
			if (f->target) {
				refs.take(*f->target, true);
			} else if (!f->loop) {
				refs.unfollowed(ref.uris);
			}
		}
		out.referrals = std::move(st.attempts);
		out.unlisted = st.unlisted;
		co_return { .value = std::move(out) };
	}

	auto chase_compare(connection &origin,
	  compare_params request,
	  referral_connector connector,
	  referral_policy policy,
	  chase_settings settings) -> capy::task<chase_result<compare_result>>
	{
		chase_state st = start(origin, request, std::move(connector), policy, std::move(settings));
		const compare_op op{};
		auto first = co_await first_hop<compare_params, compare_result>(origin, st, std::move(request), op);
		if (!first.value) {
			co_return { .value = std::unexpected(std::move(first.value.error())),
				.origin_failed = first.origin_failed };
		}
		compare_result out = std::move(first.value->value);
		out.referrals = std::move(st.attempts);
		out.unlisted = st.unlisted;
		co_return { .value = std::move(out) };
	}

}// namespace detail

auto chase_search(connection &origin,
  search_params request,
  referral_connector connector,
  referral_policy policy,
  std::pmr::memory_resource *mr) -> capy::task<result<search_result>>
{
	auto r = co_await detail::chase_search(origin, std::move(request), std::move(connector), policy, mr, {});
	co_return std::move(r.value);
}

auto chase_compare(connection &origin, compare_params request, referral_connector connector, referral_policy policy)
  -> capy::task<result<compare_result>>
{
	auto r = co_await detail::chase_compare(origin, std::move(request), std::move(connector), policy, {});
	co_return std::move(r.value);
}

}// namespace jhetz::ldap
