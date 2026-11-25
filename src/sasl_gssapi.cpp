// SASL GSSAPI client (RFC 4752): the exchange and the security layer over a
// gssapi_context (sasl_gssapi_context.hpp). See sasl_gssapi.hpp.
#include "jhetz/ldap/sasl_gssapi.hpp"

#include "jhetz/ldap/ber.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"
#include "sasl_gssapi_context.hpp"
#include "sasl_util.hpp"
#include "scope_util.hpp"

#include "net/channel_binding.hpp"

#include <unicode/uchar.h>
#include <unicode/ustring.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace jhetz::ldap {

using detail::input_error;
using detail::refused;
namespace {

	// Well-formed UTF-8.
	auto check_utf8(std::string_view s, std::string_view what) -> result<void>
	{
		for (std::size_t i = 0; i < s.size();) {
			const auto [c, n] = detail::utf8_next(s, i);
			if (c < 0) {
				return input_error(std::string(what) + " is not valid UTF-8");
			}
			i += n;
		}
		return {};
	}

	// A string wiped when destroyed.
	struct wiped_string
	{
		std::string text;
		explicit wiped_string(std::string_view s) : text(s) {}
		wiped_string(const wiped_string &) = delete;
		auto operator=(const wiped_string &) -> wiped_string & = delete;
		~wiped_string() { detail::wipe_string(text); }
	};

	auto as_bytes(std::string_view s) noexcept -> std::span<const std::byte>
	{
		return std::as_bytes(std::span(s.data(), s.size()));
	}

	// The integrity or confidentiality layer of RFC 4752 section 3.1, owning
	// the security context.
	class gssapi_layer final : public sasl_security_layer
	{
	  public:
		// NOLINTBEGIN(bugprone-easily-swappable-parameters)
		gssapi_layer(detail::gssapi_context context,
		  bool confidentiality,
		  std::size_t max_wrap_input,
		  std::size_t max_received)
		  // NOLINTEND(bugprone-easily-swappable-parameters)
		  : context_(std::move(context)), confidentiality_(confidentiality), max_wrap_input_(max_wrap_input),
			max_received_(max_received)
		{}

		[[nodiscard]] auto protection() const noexcept -> sasl_protection override
		{
			return confidentiality_ ? sasl_protection::confidentiality : sasl_protection::integrity;
		}
		[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return max_wrap_input_; }
		[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return max_received_; }

		[[nodiscard]] auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
		  -> result<void> override
		{
			return context_.wrap(plaintext, confidentiality_, out);
		}

		[[nodiscard]] auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
		  -> result<void> override
		{
			const std::size_t before = out.size();
			bool confidential = false;
			if (auto r = context_.unwrap(buffer, out, confidential); !r) {
				return r;
			}
			// A confidentiality layer refuses a buffer without confidentiality.
			if (confidentiality_ && !confidential) {
				out.resize(before);
				return refused("a buffer without confidentiality on a confidentiality layer");
			}
			return {};
		}

	  private:
		detail::gssapi_context context_;
		bool confidentiality_;
		std::size_t max_wrap_input_;
		std::size_t max_received_;
	};

}// namespace

namespace detail {

	auto gssapi_check_text(std::string_view s, std::string_view what) -> result<void>
	{
		for (std::size_t i = 0; i < s.size();) {
			const auto [c, n] = detail::utf8_next(s, i);
			if (c < 0) {
				return input_error(std::string(what) + " is not valid UTF-8");
			}
			if (u_charType(c) == U_CONTROL_CHAR) {
				return input_error(std::string(what) + " contains a control character");
			}
			i += n;
		}
		return {};
	}

	auto utf8_to_utf16(std::string_view s, std::string_view what) -> result<std::u16string>
	{
		if (s.size() > static_cast<std::size_t>(INT32_MAX)) {
			return input_error(std::string(what) + " is too long");
		}
		std::vector<UChar> units;
		const scope_exit wipe{ [&units] noexcept { wipe_vector(units); } };
		const UErrorCode status = to_utf16(s, units);
		if (is_invalid_utf8(status)) {
			return input_error(std::string(what) + " is not valid UTF-8");
		}
		if (icu_failed(status)) {
			return library_error(std::string(what) + ": UTF-16 conversion failed (ICU " + u_errorName(status) + ")");
		}
		return std::u16string(units.begin(), units.end());
	}

	sspi_identity::~sspi_identity()
	{
		wipe_string(user);
		wipe_string(domain);
		wipe_string(password);
	}

	auto make_sspi_identity(std::string_view principal, std::string_view password) -> result<sspi_identity>
	{
		std::string_view user = principal;
		std::string_view domain;
		if (const auto slash = principal.find('\\'); slash != std::string_view::npos) {
			domain = principal.substr(0, slash);
			user = principal.substr(slash + 1);
		} else if (const auto at = principal.rfind('@'); at != std::string_view::npos) {
			user = principal.substr(0, at);
			domain = principal.substr(at + 1);
		}
		if (user.empty()) {
			return input_error("principal has no user name");
		}
		sspi_identity id;
		auto u = utf8_to_utf16(user, "principal");
		if (!u) {
			return std::unexpected(std::move(u.error()));
		}
		id.user = std::move(*u);
		auto d = utf8_to_utf16(domain, "principal");
		if (!d) {
			return std::unexpected(std::move(d.error()));
		}
		id.domain = std::move(*d);
		auto p = utf8_to_utf16(password, "password");
		if (!p) {
			return std::unexpected(std::move(p.error()));
		}
		id.password = std::move(*p);
		return id;
	}

	auto sspi_target_name(std::string_view target) -> result<std::u16string>
	{
		std::string name(target);
		if (name.find('/') == std::string::npos) {
			if (const auto at = name.find('@'); at != std::string::npos) {
				name[at] = '/';
			}
		}
		return utf8_to_utf16(name, "target");
	}

	auto parse_gssapi_layer_offer(std::string_view message) -> result<gssapi_layer_offer>
	{
		// RFC 4752 section 3.1: "If the resulting cleartext is not 4 octets
		// long, the client fails the negotiation."
		if (message.size() != 4) {
			return fail(
			  client_errc::decode_error, detail::format("security layer offer of {} bytes, not 4", message.size()));
		}
		const auto byte = [&](std::size_t i) { return static_cast<std::uint8_t>(message[i]); };
		return gssapi_layer_offer{ .layers = byte(0),
			.max_size = (std::uint32_t{ byte(1) } << 16) | (std::uint32_t{ byte(2) } << 8) | std::uint32_t{ byte(3) } };
	}

	auto
	  gssapi_select_layer(const gssapi_layer_offer &offer, gssapi_security_layer requested, bool tls, bool require_tls)
		-> result<std::uint8_t>
	{
		const bool none = (offer.layers & gssapi_no_layer) != 0;
		const bool integrity = (offer.layers & gssapi_integrity) != 0;
		const bool confidentiality = (offer.layers & gssapi_confidentiality) != 0;
		if (!none && !integrity && !confidentiality) {
			return refused("the server offers no security layer, not even none");
		}
		std::uint8_t layer = gssapi_no_layer;
		switch (requested) {
		case gssapi_security_layer::none:
			if (!none) {
				return fail(client_errc::security_layer_required,
				  "the server requires integrity or confidentiality protection, which the options do not ask for "
				  "(use TLS, and a server policy that accepts no security layer over it, or set security_layer)");
			}
			break;
		case gssapi_security_layer::integrity:
			if (!integrity && !confidentiality) {
				return fail(client_errc::security_layer_unavailable,
				  "the server offers neither integrity nor confidentiality protection");
			}
			layer = integrity ? gssapi_integrity : gssapi_confidentiality;
			break;
		case gssapi_security_layer::confidentiality:
			if (!confidentiality) {
				return fail(
				  client_errc::security_layer_unavailable, "the server does not offer confidentiality protection");
			}
			layer = gssapi_confidentiality;
			break;
		case gssapi_security_layer::best_offered:
			if (tls && none) {
				break;
			}
			if (confidentiality) {
				layer = gssapi_confidentiality;
			} else if (integrity) {
				layer = gssapi_integrity;
			}
			break;
		}
		if (layer == gssapi_no_layer && require_tls && !tls) {
			return fail(client_errc::tls_required,
			  "the server offers no security layer and the connection has no TLS (sasl_gssapi_options::require_tls)");
		}
		if (layer != gssapi_no_layer && offer.max_size == 0) {
			return refused("the server offers a security layer with a maximum buffer size of 0");
		}
		return layer;
	}

	auto gssapi_check_context_flags(const gssapi_context_flags &flags, bool confidentiality) -> result<void>
	{
		if (!(confidentiality ? flags.confidentiality : flags.integrity)) {
			return fail(client_errc::gssapi_failure,
			  confidentiality ? "the security context provides no confidentiality"
							  : "the security context provides no integrity");
		}
		if (!flags.sequence) {
			return fail(client_errc::gssapi_failure,
			  "the security context provides no sequence detection (replayed or reordered buffers would pass)");
		}
		return {};
	}

	auto gssapi_layer_reply(std::uint8_t layer, std::uint32_t max_size, std::string_view authz_id)
	  -> result<std::string>
	{
		if (layer == gssapi_no_layer) {
			// No security layer, and so no maximum buffer size: 0 (RFC 4752
			// section 3.1: "which MAY be 0 if a security layer is not selected").
			max_size = 0;
		} else if (max_size == 0 || max_size > gssapi_max_buffer_limit) {
			return input_error(
			  detail::format("maximum buffer size {} out of range (1 to {})", max_size, gssapi_max_buffer_limit));
		}
		if (auto c = gssapi_check_text(authz_id, "authorization identity"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		constexpr unsigned byte_bits = 8;
		constexpr std::uint32_t byte_mask = 0xff;
		std::string reply{ static_cast<char>(layer),
			static_cast<char>((max_size >> (2 * byte_bits)) & byte_mask),
			static_cast<char>((max_size >> byte_bits) & byte_mask),
			static_cast<char>(max_size & byte_mask) };
		reply += authz_id;
		return reply;
	}

	auto gssapi_channel_binding_data(const sasl_bind_context &context,
	  gssapi_channel_binding binding,
	  gssapi_channel_binding_form form) -> result<std::string>
	{
		if (binding == gssapi_channel_binding::none || !context.tls) {
			return {};
		}
		std::vector<std::byte> openldap_hash;
		std::span<const std::byte> hash = context.bindings.tls_server_end_point;
		if (form == gssapi_channel_binding_form::openldap) {
			openldap_hash = net::detail::openldap_tls_server_end_point(context.peer_certificate);
			hash = openldap_hash;
		}
		// No fallback to no bindings without a hash;
		// gssapi_channel_binding::none opts out.
		if (hash.empty()) {
			return fail(client_errc::tls_required,
			  form == gssapi_channel_binding_form::rfc5929
				? "the TLS connection has no tls-server-end-point channel binding data (no hash for the server's "
				  "certificate, e.g. Ed25519 or Ed448, or no certificate)"
				: "the TLS connection has no tls-server-end-point channel binding data (no OpenLDAP hash for the "
				  "server's certificate: not parsed, or an unknown signature algorithm, or no certificate)");
		}
		return prefixed_channel_binding(channel_binding_type::tls_server_end_point, hash);
	}

}// namespace detail

struct sasl_gssapi::state
{
	enum class phase : std::uint8_t {
		idle,// before start(), after an error or the end of a bind
		negotiating,// security context not established yet: tokens go back and forth
		established,// context complete, our last token sent: the server's offer comes next
		replied,// security layer reply sent: success comes next
	};

	phase at = phase::idle;
	// Set while a step runs on sasl_bind's thread (offload_start,
	// offload_step): the mechanism leaves the state alone until it clears.
	std::atomic<bool> busy{ false };
	detail::gssapi_context context;
	// The channel bindings' application data (empty: none), the same for
	// every context establishment call of the exchange.
	std::string bindings;
	// The security layer to select, the maximum buffer size to announce
	// with one and require_tls (sasl_gssapi_options), and whether TLS is
	// below.
	gssapi_security_layer requested_layer = gssapi_security_layer::none;
	std::uint32_t max_receive_size = 0;
	bool require_tls = true;
	bool tls = false;
	// The layer reply() selected (integrity or confidentiality), owning the
	// context, until take_security_layer() hands it over.
	std::unique_ptr<sasl_security_layer> layer;

	state() = default;
	state(const state &) = delete;
	auto operator=(const state &) -> state & = delete;
	~state() = default;

	// Clears `busy` when the returned guard goes out of scope: at the end of
	// an offloaded step, whatever its outcome.
	[[nodiscard]] auto busy_scope() noexcept
	{
		return detail::scope_exit{ [this] noexcept { busy.store(false, std::memory_order_release); } };
	}

	void reset() noexcept
	{
		at = phase::idle;
		layer.reset();
		context.reset();
	}

	// One context establishment call, with the server's token (none at first).
	auto init(std::optional<std::string_view> token) -> result<std::optional<std::string>>
	{
		auto out = context.init(token);
		if (!out) {
			reset();
			return std::unexpected(std::move(out.error()));
		}
		at = context.established() ? phase::established : phase::negotiating;
		// RFC 4752 section 3.1: the output token, possibly empty.
		return std::optional<std::string>(std::move(*out));
	}

	// The server's wrapped offer gives the wrapped reply; with a layer
	// selected, `layer` takes over the context.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto reply(std::string_view wrapped_offer, std::string_view authz_id) -> result<std::optional<std::string>>
	{
		std::pmr::vector<std::byte> offer_text;
		bool confidential = false;
		if (auto u = context.unwrap(as_bytes(wrapped_offer), offer_text, confidential); !u) {
			return std::unexpected(std::move(u.error()));
		}
		auto offer = detail::parse_gssapi_layer_offer(detail::as_text(offer_text));
		if (!offer) {
			return std::unexpected(std::move(offer.error()));
		}
		auto selected = detail::gssapi_select_layer(*offer, requested_layer, tls, require_tls);
		if (!selected) {
			return std::unexpected(std::move(selected.error()));
		}
		const bool confidentiality = *selected == detail::gssapi_confidentiality;
		std::size_t max_wrap_input = 0;
		if (*selected != detail::gssapi_no_layer) {
			if (auto c = detail::gssapi_check_context_flags(context.flags(), confidentiality); !c) {
				return std::unexpected(std::move(c.error()));
			}
			auto limit = context.wrap_size_limit(confidentiality, offer->max_size);
			if (!limit) {
				return std::unexpected(std::move(limit.error()));
			}
			if (*limit == 0) {
				return refused(
				  detail::format("the server's maximum buffer size, {}, leaves no room for data", offer->max_size));
			}
			max_wrap_input = *limit;
		}
		auto text = detail::gssapi_layer_reply(*selected, max_receive_size, authz_id);
		if (!text) {
			return std::unexpected(std::move(text.error()));
		}
		// RFC 4752 section 3.1: wrapped without confidentiality.
		std::pmr::vector<std::byte> wrapped;
		if (auto w = context.wrap(as_bytes(*text), false, wrapped); !w) {
			return std::unexpected(std::move(w.error()));
		}
		std::string out(detail::as_text(wrapped));
		if (*selected != detail::gssapi_no_layer) {
			layer =
			  std::make_unique<gssapi_layer>(std::move(context), confidentiality, max_wrap_input, max_receive_size);
		}
		at = phase::replied;
		return std::optional<std::string>(std::move(out));
	}

	// The first token: names and credentials, then the first context
	// establishment call.
	auto begin(const sasl_gssapi_options &options, std::string_view password, std::string_view host)
	  -> result<std::optional<std::string>>
	{
		std::string target_name = options.target;
		if (target_name.empty()) {
			if (host.empty()) {
				return input_error(
				  "no target: the connection has no host name (ldapi://, or a wrapped transport): set the target");
			}
			target_name = "ldap@";
			target_name += host;
		}
		if (auto c = detail::gssapi_check_text(target_name, "target"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (auto c = detail::gssapi_check_text(options.principal, "principal"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (auto c = detail::gssapi_check_text(options.authz_id, "authorization identity"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (auto c = check_utf8(password, "password"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (!password.empty() && options.principal.empty()) {
			return input_error("a password without a principal");
		}
		if (options.security_layer != gssapi_security_layer::none
			&& (options.max_receive_size == 0 || options.max_receive_size > gssapi_max_buffer_limit)) {
			return input_error(detail::format(
			  "max_receive_size {} out of range (1 to {})", options.max_receive_size, gssapi_max_buffer_limit));
		}
		requested_layer = options.security_layer;
		max_receive_size = options.max_receive_size;
		require_tls = options.require_tls;

		const detail::gssapi_request request{ .target = target_name,
			.principal = options.principal,
			.password = password,
			.bindings = bindings,
			.layer = requested_layer != gssapi_security_layer::none };
		if (auto a = context.acquire(request); !a) {
			reset();
			return std::unexpected(std::move(a.error()));
		}
		return init(std::nullopt);
	}
};

sasl_gssapi::sasl_gssapi(sasl_gssapi_options options) : options_(std::move(options)), state_(std::make_shared<state>())
{}

sasl_gssapi::sasl_gssapi(std::string principal, std::string password, sasl_gssapi_options options)
  : options_(std::move(options)), password_(password), state_(std::make_shared<state>())
{
	detail::wipe_string(password);
	options_.principal = std::move(principal);
}

sasl_gssapi::~sasl_gssapi() { detail::wipe_string(password_); }

sasl_gssapi::sasl_gssapi(sasl_gssapi &&other) noexcept
  : options_(std::move(other.options_)), password_(other.password_), host_(std::move(other.host_)), tls_(other.tls_),
	bindings_(std::move(other.bindings_)), binding_error_(std::move(other.binding_error_)),
	state_(std::move(other.state_))
{
	detail::wipe_string(other.password_);
}

auto sasl_gssapi::operator=(sasl_gssapi &&other) noexcept -> sasl_gssapi &
{
	if (this != &other) {
		options_ = std::move(other.options_);
		detail::wipe_string(password_);
		password_ = other.password_;
		detail::wipe_string(other.password_);
		host_ = std::move(other.host_);
		tls_ = other.tls_;
		bindings_ = std::move(other.bindings_);
		binding_error_ = std::move(other.binding_error_);
		state_ = std::move(other.state_);
	}
	return *this;
}

void sasl_gssapi::prepare(const sasl_bind_context &context)
{
	host_.assign(context.host);
	tls_ = context.tls;
	bindings_.clear();
	binding_error_.clear();
	if (auto data = detail::gssapi_channel_binding_data(context, options_.channel_binding, options_.binding_form)) {
		bindings_ = std::move(*data);
	} else {
		binding_error_.assign(std::string_view(data.error().context));
	}
}

auto sasl_gssapi::unprotected() const noexcept -> bool
{
	return options_.require_tls && !tls_ && options_.security_layer == gssapi_security_layer::none;
}

auto sasl_gssapi::offload_start() -> sasl_work
{
	// Nothing to offload: start() fails on the I/O thread.
	if (!binding_error_.empty() || unprotected()) {
		return {};
	}
	// A new state for each bind: one whose step sasl_bind gave up on may
	// still be in use by its thread.
	const auto s = std::make_shared<state>();
	s->busy.store(true, std::memory_order_relaxed);
	s->bindings = bindings_;
	s->tls = tls_;
	state_ = s;
	// The password goes along by shared_ptr: no copy left behind unwiped.
	auto password = std::make_shared<const wiped_string>(password_);
	return [s, options = options_, password = std::move(password), host = host_] {
		const auto scope = s->busy_scope();
		return s->begin(options, password->text, host);
	};
}

auto sasl_gssapi::offload_step(std::optional<std::string_view> challenge) -> sasl_work
{
	// Only the context establishment may block; step() handles the rest
	// (the security layer reply, errors) on the I/O thread.
	if (state_ == nullptr || state_->busy.load(std::memory_order_acquire) || state_->at != state::phase::negotiating
		|| !challenge) {
		return {};
	}
	const auto s = state_;
	s->busy.store(true, std::memory_order_relaxed);
	return [s, token = std::string(*challenge)] {
		const auto scope = s->busy_scope();
		return s->init(token);
	};
}

auto sasl_gssapi::start() -> result<std::optional<std::string>>
{
	if (unprotected()) {
		state_ = std::make_shared<state>();// as offload_start(): this bind's state, idle
		return fail(client_errc::tls_required,
		  "GSSAPI without a security layer needs a TLS-protected connection (sasl_gssapi_options::require_tls, "
		  "security_layer)");
	}
	if (!binding_error_.empty()) {
		state_ = std::make_shared<state>();// as offload_start(): this bind's state, idle
		return fail(client_errc::tls_required, binding_error_);
	}
	return offload_start()();
}

auto sasl_gssapi::step(std::optional<std::string_view> challenge) -> result<std::optional<std::string>>
{
	if (state_ == nullptr) {
		return refused("a challenge before the exchange started");
	}
	state &s = *state_;
	if (s.busy.load(std::memory_order_acquire)) {
		return refused("a challenge while the previous step still runs");
	}
	switch (s.at) {
	case state::phase::negotiating:
		if (!challenge) {
			s.reset();
			return fail(client_errc::decode_error, "no token in the server's challenge");
		}
		return s.init(challenge);
	case state::phase::established: {
		if (!challenge) {
			s.reset();
			return fail(client_errc::decode_error, "no security layer offer in the server's challenge");
		}
		auto r = s.reply(*challenge, options_.authz_id);
		if (!r) {
			s.reset();
		}
		return r;
	}
	case state::phase::idle:
		return refused("a challenge before the exchange started");
	case state::phase::replied:
		break;
	}
	s.reset();
	return refused("a challenge after the security layer reply");
}

auto sasl_gssapi::complete(std::optional<std::string_view> server_creds) -> result<void>
{
	if (state_ == nullptr) {
		return refused("success before the exchange started");
	}
	state &s = *state_;
	if (s.busy.load(std::memory_order_acquire)) {
		return refused("success while the previous step still runs");
	}
	const bool replied = s.at == state::phase::replied;
	// The context is not used after the bind (a layer took it over).
	s.reset();
	if (!replied) {
		return refused("the server reported success before the security layer negotiation");
	}
	if (server_creds && !server_creds->empty()) {
		return refused("unexpected server credentials with the success");
	}
	return {};
}

auto sasl_gssapi::take_security_layer() -> std::unique_ptr<sasl_security_layer>
{
	if (state_ == nullptr || state_->busy.load(std::memory_order_acquire)) {
		return nullptr;
	}
	return std::move(state_->layer);
}

}// namespace jhetz::ldap
