// SASL GSSAPI client (RFC 4752) over the GSS-API C library. See
// sasl_gssapi.hpp.
#include "jhetz/ldap/sasl_gssapi.hpp"

#include "jhetz/ldap/ber.hpp"

#include "format_util.hpp"
#include "icu_util.hpp"
#include "sasl_util.hpp"
#include "scope_util.hpp"

#include "net/channel_binding.hpp"

#include <gssapi/gssapi.h>

#include <unicode/uchar.h>

#include <array>
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

	// The Kerberos V5 mechanism OID 1.2.840.113554.1.2.2 (RFC 1964), DER.
	constexpr auto krb5_oid_der =
	  std::to_array<unsigned char>({ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 });
	// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables): GSS-API takes them non-const, never writes
	auto krb5_oid_bytes = krb5_oid_der;
	gss_OID_desc krb5_oid{ .length = krb5_oid_bytes.size(), .elements = krb5_oid_bytes.data() };
	gss_OID_set_desc krb5_oid_set{ .count = 1, .elements = &krb5_oid };
	// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

	// GSS_C_CHANNEL_BOUND_FLAG, for libraries that lack it.
	constexpr OM_uint32 channel_bound_flag = 2048;

	// The req_flags a security layer needs: integrity and confidentiality
	// (the server's offer decides which is used).
	constexpr OM_uint32 layer_flags = OM_uint32{ GSS_C_INTEG_FLAG } | OM_uint32{ GSS_C_CONF_FLAG };

	// Owns a GSS-API handle (a pointer type), released with `Release`.
	template<class H, auto Release> class gss_handle
	{
	  public:
		gss_handle() = default;
		gss_handle(const gss_handle &) = delete;
		auto operator=(const gss_handle &) -> gss_handle & = delete;
		~gss_handle() { reset(); }

		[[nodiscard]] auto get() const noexcept -> H { return h_; }
		// For a call that creates the handle: releases the current one.
		auto out() noexcept -> H *
		{
			reset();
			return &h_;
		}
		// For a call that updates the handle in place (gss_init_sec_context).
		auto in_out() noexcept -> H * { return &h_; }
		// Hands the handle over (to another owner); null from then on.
		[[nodiscard]] auto release() noexcept -> H { return std::exchange(h_, nullptr); }
		// Takes ownership of `h`.
		void adopt(H h) noexcept
		{
			reset();
			h_ = h;
		}
		void reset() noexcept
		{
			if (h_ == nullptr) {
				return;
			}
			OM_uint32 minor = 0;
			Release(&minor, &h_);
			h_ = nullptr;
		}

	  private:
		H h_ = nullptr;
	};

	constexpr auto delete_context = [](OM_uint32 *minor, gss_ctx_id_t *c) {
		return gss_delete_sec_context(minor, c, GSS_C_NO_BUFFER);
	};
	using name_handle = gss_handle<gss_name_t, &gss_release_name>;
	using cred_handle = gss_handle<gss_cred_id_t, &gss_release_cred>;
	using context_handle = gss_handle<gss_ctx_id_t, delete_context>;

	// A buffer the GSS-API library allocated (output tokens, messages).
	struct output_buffer
	{
		gss_buffer_desc desc{ .length = 0, .value = nullptr };
		output_buffer() = default;
		output_buffer(const output_buffer &) = delete;
		auto operator=(const output_buffer &) -> output_buffer & = delete;
		~output_buffer()
		{
			OM_uint32 minor = 0;
			if (desc.value != nullptr) {
				gss_release_buffer(&minor, &desc);
			}
		}
		[[nodiscard]] auto view() const noexcept -> std::string_view
		{
			return desc.value == nullptr ? std::string_view()
										 : std::string_view(static_cast<const char *>(desc.value), desc.length);
		}
	};

	// An input buffer over caller memory (GSS-API takes non-const pointers
	// but does not write through input buffers).
	auto input(std::string_view s) noexcept -> gss_buffer_desc
	{
		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): input buffers are never written (see above)
		return gss_buffer_desc{ .length = s.size(), .value = const_cast<char *>(s.data()) };
	}

	// gss_display_status's messages for one status value, joined with "; ".
	auto status_text(OM_uint32 status, int type) -> std::string
	{
		std::string out;
		OM_uint32 message_context = 0;
		do {
			OM_uint32 minor = 0;
			output_buffer message;
			const OM_uint32 major = gss_display_status(&minor,
			  status,
			  type,
			  type == GSS_C_MECH_CODE ? &krb5_oid : GSS_C_NO_OID,
			  &message_context,
			  &message.desc);
			if (GSS_ERROR(major) != 0) {
				break;
			}
			if (!out.empty()) {
				out += "; ";
			}
			// Messages may quote names from the KDC or the server.
			detail::append_sanitized(out, message.view(), 256);
		} while (message_context != 0);
		return out;
	}

	auto gss_failure(std::string_view call, OM_uint32 major, OM_uint32 minor) -> std::unexpected<error>
	{
		std::string text(call);
		text += ": ";
		text += status_text(major, GSS_C_GSS_CODE);
		if (minor != 0) {
			if (const auto m = status_text(minor, GSS_C_MECH_CODE); !m.empty()) {
				text += " (";
				text += m;
				text += ')';
			}
		}
		return fail(client_errc::gssapi_failure, text);
	}

	// Well-formed UTF-8 without control characters (Cc).
	auto check_text(std::string_view s, std::string_view what) -> result<void>
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

	auto import_name(std::string_view text, gss_OID type, name_handle &name) -> result<void>
	{
		OM_uint32 minor = 0;
		gss_buffer_desc in = input(text);
		const OM_uint32 major = gss_import_name(&minor, &in, type, name.out());
		if (GSS_ERROR(major) != 0) {
			return gss_failure("gss_import_name", major, minor);
		}
		return {};
	}

	// The supplementary statuses of a replayed, old or out-of-order buffer (RFC
	// 2744 section 3.9.1).
	constexpr OM_uint32 sequence_problems =
	  GSS_S_DUPLICATE_TOKEN | GSS_S_OLD_TOKEN | GSS_S_UNSEQ_TOKEN | GSS_S_GAP_TOKEN;

	// The integrity or confidentiality layer of RFC 4752 section 3.1, owning
	// the security context.
	class gssapi_layer final : public sasl_security_layer
	{
	  public:
		// Takes over `context` once allocated.
		// NOLINTBEGIN(bugprone-easily-swappable-parameters)
		gssapi_layer(context_handle &context,
		  bool confidentiality,
		  std::size_t max_wrap_input,
		  std::size_t max_received)
		  // NOLINTEND(bugprone-easily-swappable-parameters)
		  : confidentiality_(confidentiality), max_wrap_input_(max_wrap_input), max_received_(max_received)
		{
			context_.adopt(context.release());
		}

		[[nodiscard]] auto protection() const noexcept -> sasl_protection override
		{
			return confidentiality_ ? sasl_protection::confidentiality : sasl_protection::integrity;
		}
		[[nodiscard]] auto max_wrap_input() const noexcept -> std::size_t override { return max_wrap_input_; }
		[[nodiscard]] auto max_received() const noexcept -> std::size_t override { return max_received_; }

		[[nodiscard]] auto wrap(std::span<const std::byte> plaintext, std::pmr::vector<std::byte> &out)
		  -> result<void> override
		{
			OM_uint32 minor = 0;
			gss_buffer_desc in = input(detail::as_text(plaintext));
			output_buffer wrapped;
			int conf_state = 0;
			const OM_uint32 major = gss_wrap(
			  &minor, context_.get(), confidentiality_ ? 1 : 0, GSS_C_QOP_DEFAULT, &in, &conf_state, &wrapped.desc);
			if (GSS_ERROR(major) != 0) {
				return gss_failure("gss_wrap", major, minor);
			}
			if (confidentiality_ && conf_state == 0) {
				return fail(client_errc::gssapi_failure, "gss_wrap: no confidentiality applied");
			}
			append(out, wrapped.view());
			return {};
		}

		[[nodiscard]] auto unwrap(std::span<const std::byte> buffer, std::pmr::vector<std::byte> &out)
		  -> result<void> override
		{
			OM_uint32 minor = 0;
			gss_buffer_desc in = input(detail::as_text(buffer));
			output_buffer plain;
			int conf_state = 0;
			const OM_uint32 major = gss_unwrap(&minor, context_.get(), &in, &plain.desc, &conf_state, nullptr);
			if (GSS_ERROR(major) != 0) {
				return gss_failure("gss_unwrap", major, minor);
			}
			if ((major & sequence_problems) != 0) {
				return fail(client_errc::gssapi_failure,
				  "gss_unwrap: a buffer replayed or out of sequence: " + status_text(major, GSS_C_GSS_CODE));
			}
			// A confidentiality layer refuses a buffer without confidentiality.
			if (confidentiality_ && conf_state == 0) {
				return refused("a buffer without confidentiality on a confidentiality layer");
			}
			append(out, plain.view());
			return {};
		}

	  private:
		static void append(std::pmr::vector<std::byte> &out, std::string_view bytes)
		{
			const auto *p = reinterpret_cast<const std::byte *>(bytes.data());
			out.insert(out.end(), p, p + bytes.size());
		}

		context_handle context_;
		bool confidentiality_;
		std::size_t max_wrap_input_;
		std::size_t max_received_;
	};

}// namespace

namespace detail {

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
		if (auto c = check_text(authz_id, "authorization identity"); !c) {
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
	name_handle target;
	cred_handle credentials;
	context_handle context;
	// The channel bindings' application data (empty: none), the same for
	// every gss_init_sec_context call of the exchange.
	std::string bindings;
	// The security layer to select, the maximum buffer size to announce
	// with one and require_tls (sasl_gssapi_options), and whether TLS is
	// below.
	gssapi_security_layer requested_layer = gssapi_security_layer::none;
	std::uint32_t max_receive_size = 0;
	bool require_tls = true;
	bool tls = false;
	// The flags of the established context (gss_init_sec_context's
	// ret_flags).
	OM_uint32 context_flags = 0;
	// The layer reply() selected (integrity or confidentiality), owning the
	// context, until take_security_layer() hands it over.
	std::unique_ptr<sasl_security_layer> layer;

	// Clears `busy` when the returned guard goes out of scope: at the end of
	// an offloaded step, whatever its outcome.
	[[nodiscard]] auto busy_scope() noexcept
	{
		return detail::scope_exit{ [this] noexcept { busy.store(false, std::memory_order_release); } };
	}

	void reset() noexcept
	{
		at = phase::idle;
		context_flags = 0;
		layer.reset();
		context.reset();
		credentials.reset();
		target.reset();
	}

	// One gss_init_sec_context call, with the server's token (none at first).
	auto init(std::optional<std::string_view> token) -> result<std::optional<std::string>>
	{
		OM_uint32 minor = 0;
		gss_buffer_desc in = input(token.value_or(std::string_view()));
		output_buffer out;
		OM_uint32 flags = 0;
		// RFC 2744 section 3.11: no addresses, the TLS binding as application data.
		gss_channel_bindings_struct channel{ .initiator_addrtype = GSS_C_AF_UNSPEC,
			.initiator_address = { .length = 0, .value = nullptr },
			.acceptor_addrtype = GSS_C_AF_UNSPEC,
			.acceptor_address = { .length = 0, .value = nullptr },
			.application_data = input(bindings) };
		const OM_uint32 major = gss_init_sec_context(&minor,
		  credentials.get(),
		  context.in_out(),
		  target.get(),
		  &krb5_oid,
		  // With bindings, the client says it binds (channel_bound_flag);
		  // with a layer to select, integrity and confidentiality.
		  GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | (bindings.empty() ? 0 : channel_bound_flag)
			| (requested_layer == gssapi_security_layer::none ? OM_uint32{ 0 } : layer_flags),
		  0,
		  bindings.empty() ? GSS_C_NO_CHANNEL_BINDINGS : &channel,
		  token ? &in : GSS_C_NO_BUFFER,
		  nullptr,
		  &out.desc,
		  &flags,
		  nullptr);
		if (GSS_ERROR(major) != 0) {
			reset();
			return gss_failure("gss_init_sec_context", major, minor);
		}
		if ((major & GSS_S_CONTINUE_NEEDED) != 0) {
			at = phase::negotiating;
		} else {
			if ((flags & GSS_C_MUTUAL_FLAG) == 0) {
				reset();
				return fail(client_errc::gssapi_failure,
				  "gss_init_sec_context: no mutual authentication (the server was not authenticated)");
			}
			at = phase::established;
			context_flags = flags;
		}
		// RFC 4752 section 3.1: the output token, possibly empty.
		return std::optional<std::string>(std::string(out.view()));
	}

	// The server's wrapped offer gives the wrapped reply; with a layer
	// selected, `layer` takes over the context.
	// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
	auto reply(std::string_view wrapped_offer, std::string_view authz_id) -> result<std::optional<std::string>>
	{
		OM_uint32 minor = 0;
		gss_buffer_desc in = input(wrapped_offer);
		output_buffer offer_text;
		OM_uint32 major = gss_unwrap(&minor, context.get(), &in, &offer_text.desc, nullptr, nullptr);
		if (GSS_ERROR(major) != 0) {
			return gss_failure("gss_unwrap", major, minor);
		}
		auto offer = detail::parse_gssapi_layer_offer(offer_text.view());
		if (!offer) {
			return std::unexpected(std::move(offer.error()));
		}
		auto selected = detail::gssapi_select_layer(*offer, requested_layer, tls, require_tls);
		if (!selected) {
			return std::unexpected(std::move(selected.error()));
		}
		std::size_t max_wrap_input = 0;
		if (*selected != detail::gssapi_no_layer) {
			auto limit = wrap_limit(*selected == detail::gssapi_confidentiality, offer->max_size);
			if (!limit) {
				return std::unexpected(std::move(limit.error()));
			}
			max_wrap_input = *limit;
		}
		auto text = detail::gssapi_layer_reply(*selected, max_receive_size, authz_id);
		if (!text) {
			return std::unexpected(std::move(text.error()));
		}
		// RFC 4752 section 3.1: wrapped with conf_flag FALSE.
		gss_buffer_desc reply_in = input(*text);
		output_buffer wrapped;
		major = gss_wrap(&minor, context.get(), 0, GSS_C_QOP_DEFAULT, &reply_in, nullptr, &wrapped.desc);
		if (GSS_ERROR(major) != 0) {
			return gss_failure("gss_wrap", major, minor);
		}
		std::string out(wrapped.view());
		if (*selected != detail::gssapi_no_layer) {
			layer = std::make_unique<gssapi_layer>(
			  context, *selected == detail::gssapi_confidentiality, max_wrap_input, max_receive_size);
		}
		at = phase::replied;
		return std::optional<std::string>(std::move(out));
	}

	// The most plaintext gss_wrap turns into at most `max_size` octets, after
	// checking the context's flags for the layer.
	auto wrap_limit(bool confidentiality, std::uint32_t max_size) const -> result<std::size_t>
	{
		const detail::gssapi_context_flags provided{ .integrity = (context_flags & GSS_C_INTEG_FLAG) != 0,
			.confidentiality = (context_flags & GSS_C_CONF_FLAG) != 0,
			.sequence = (context_flags & GSS_C_SEQUENCE_FLAG) != 0 };
		if (auto c = detail::gssapi_check_context_flags(provided, confidentiality); !c) {
			return std::unexpected(std::move(c.error()));
		}
		OM_uint32 minor = 0;
		OM_uint32 max_input = 0;
		const OM_uint32 major =
		  gss_wrap_size_limit(&minor, context.get(), confidentiality ? 1 : 0, GSS_C_QOP_DEFAULT, max_size, &max_input);
		if (GSS_ERROR(major) != 0) {
			return gss_failure("gss_wrap_size_limit", major, minor);
		}
		if (max_input == 0) {
			return refused(detail::format("the server's maximum buffer size, {}, leaves no room for data", max_size));
		}
		return std::size_t{ max_input };
	}

	// The first token: names imported, credentials acquired (for a given
	// principal), first gss_init_sec_context call.
	auto begin(const sasl_gssapi_options &options, std::string_view host) -> result<std::optional<std::string>>
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
		if (auto c = check_text(target_name, "target"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (auto c = check_text(options.principal, "principal"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (auto c = check_text(options.authz_id, "authorization identity"); !c) {
			return std::unexpected(std::move(c.error()));
		}
		if (options.security_layer != gssapi_security_layer::none
			&& (options.max_receive_size == 0 || options.max_receive_size > gssapi_max_buffer_limit)) {
			return input_error(detail::format(
			  "max_receive_size {} out of range (1 to {})", options.max_receive_size, gssapi_max_buffer_limit));
		}
		requested_layer = options.security_layer;
		max_receive_size = options.max_receive_size;
		require_tls = options.require_tls;

		if (auto n = import_name(target_name, GSS_C_NT_HOSTBASED_SERVICE, target); !n) {
			return std::unexpected(std::move(n.error()));
		}
		if (!options.principal.empty()) {
			name_handle principal;
			if (auto n = import_name(options.principal, GSS_C_NT_USER_NAME, principal); !n) {
				return std::unexpected(std::move(n.error()));
			}
			OM_uint32 minor = 0;
			const OM_uint32 major = gss_acquire_cred(&minor,
			  principal.get(),
			  GSS_C_INDEFINITE,
			  &krb5_oid_set,
			  GSS_C_INITIATE,
			  credentials.out(),
			  nullptr,
			  nullptr);
			if (GSS_ERROR(major) != 0) {
				reset();
				return gss_failure("gss_acquire_cred", major, minor);
			}
		}
		return init(std::nullopt);
	}
};

sasl_gssapi::sasl_gssapi(sasl_gssapi_options options) : options_(std::move(options)), state_(std::make_shared<state>())
{}

sasl_gssapi::~sasl_gssapi() = default;
sasl_gssapi::sasl_gssapi(sasl_gssapi &&) noexcept = default;
auto sasl_gssapi::operator=(sasl_gssapi &&) noexcept -> sasl_gssapi & = default;

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
	return [s, options = options_, host = host_] {
		const auto scope = s->busy_scope();
		return s->begin(options, host);
	};
}

auto sasl_gssapi::offload_step(std::optional<std::string_view> challenge) -> sasl_work
{
	// Only gss_init_sec_context may block; step() handles the rest
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
