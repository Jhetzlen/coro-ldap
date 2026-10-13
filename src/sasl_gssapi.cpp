// SASL GSSAPI client (RFC 4752) over the GSS-API C library. See
// sasl_gssapi.hpp.
#include "jhetz/ldap/sasl_gssapi.hpp"

#include "format_util.hpp"

#include <gssapi/gssapi.h>

#include <unicode/utf8.h>
#include <unicode/utypes.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace jhetz::ldap {
namespace {

	// The Kerberos V5 mechanism, 1.2.840.113554.1.2.2 (RFC 1964), spelled
	// out rather than taken from gssapi_krb5.h (MIT's gss_mech_krb5,
	// Heimdal's GSS_KRB5_MECHANISM).
	unsigned char krb5_oid_bytes[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
	gss_OID_desc krb5_oid{ sizeof krb5_oid_bytes, krb5_oid_bytes };
	gss_OID_set_desc krb5_oid_set{ 1, &krb5_oid };

	// Owns a GSS-API handle (a pointer type), released with `Release`.
	template<class H, auto Release> class gss_handle
	{
	  public:
		gss_handle() = default;
		gss_handle(const gss_handle &) = delete;
		gss_handle &operator=(const gss_handle &) = delete;
		~gss_handle() { reset(); }

		H get() const noexcept { return h_; }
		// For a call that creates the handle: releases the current one.
		H *out() noexcept
		{
			reset();
			return &h_;
		}
		// For a call that updates the handle in place (gss_init_sec_context).
		H *in_out() noexcept { return &h_; }
		void reset() noexcept
		{
			if (h_ == nullptr) return;
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
		gss_buffer_desc desc{ 0, nullptr };
		output_buffer() = default;
		output_buffer(const output_buffer &) = delete;
		output_buffer &operator=(const output_buffer &) = delete;
		~output_buffer()
		{
			OM_uint32 minor = 0;
			if (desc.value != nullptr) gss_release_buffer(&minor, &desc);
		}
		std::string_view view() const noexcept
		{
			return desc.value == nullptr ? std::string_view()
										 : std::string_view(static_cast<const char *>(desc.value), desc.length);
		}
	};

	// An input buffer over caller memory (GSS-API takes non-const pointers
	// but does not write through input buffers).
	gss_buffer_desc input(std::string_view s) noexcept
	{
		return gss_buffer_desc{ s.size(), const_cast<char *>(s.data()) };
	}

	// gss_display_status's messages for one status value, joined with "; ".
	std::string status_text(OM_uint32 status, int type)
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
			if (GSS_ERROR(major) != 0) break;
			if (!out.empty()) out += "; ";
			// Messages may quote names from the KDC or the server.
			detail::append_sanitized(out, message.view(), 256);
		} while (message_context != 0);
		return out;
	}

	std::unexpected<error> gss_failure(std::string_view call, OM_uint32 major, OM_uint32 minor)
	{
		std::string text(call);
		text += ": ";
		text += status_text(major, GSS_C_GSS_CODE);
		if (minor != 0) {
			if (auto m = status_text(minor, GSS_C_MECH_CODE); !m.empty()) {
				text += " (";
				text += m;
				text += ')';
			}
		}
		return fail(client_errc::gssapi_failure, text);
	}

	std::unexpected<error> input_error(std::string_view what) { return fail(client_errc::encode_error, what); }

	std::unexpected<error> refused(std::string_view what) { return fail(client_errc::unexpected_response, what); }

	// Well-formed UTF-8 (RFC 3629: U8_NEXT refuses overlong forms,
	// surrogates and code points above U+10FFFF) without control characters
	// (C0, DEL, C1). Every other code point is accepted.
	result<void> check_text(std::string_view s, std::string_view what)
	{
		const auto *p = reinterpret_cast<const std::uint8_t *>(s.data());
		const auto n = static_cast<std::int64_t>(s.size());
		for (std::int64_t i = 0; i < n;) {
			UChar32 c = 0;
			U8_NEXT(p, i, n, c);
			if (c < 0) return input_error(std::string(what) + " is not valid UTF-8");
			if (c < 0x20 || (c >= 0x7f && c < 0xa0))
				return input_error(std::string(what) + " contains a control character");
		}
		return {};
	}

	result<void> import_name(std::string_view text, gss_OID type, name_handle &name)
	{
		OM_uint32 minor = 0;
		gss_buffer_desc in = input(text);
		const OM_uint32 major = gss_import_name(&minor, &in, type, name.out());
		if (GSS_ERROR(major) != 0) return gss_failure("gss_import_name", major, minor);
		return {};
	}

}// namespace

namespace detail {

	result<gssapi_layer_offer> parse_gssapi_layer_offer(std::string_view message)
	{
		// RFC 4752 section 3.1: "If the resulting cleartext is not 4 octets
		// long, the client fails the negotiation."
		if (message.size() != 4)
			return fail(
			  client_errc::decode_error, detail::format("security layer offer of {} bytes, not 4", message.size()));
		const auto byte = [&](std::size_t i) { return static_cast<std::uint8_t>(message[i]); };
		return gssapi_layer_offer{ byte(0),
			(std::uint32_t{ byte(1) } << 16) | (std::uint32_t{ byte(2) } << 8) | std::uint32_t{ byte(3) } };
	}

	result<std::string> gssapi_layer_reply(const gssapi_layer_offer &offer, std::string_view authz_id)
	{
		if ((offer.layers & gssapi_no_layer) == 0) {
			if ((offer.layers & (gssapi_integrity | gssapi_confidentiality)) != 0)
				return fail(client_errc::security_layer_required,
				  "the server requires integrity or confidentiality protection, which this client does not "
				  "provide (use TLS, and a server policy that accepts no security layer over it)");
			return refused("the server offers no security layer, not even none");
		}
		if (auto c = check_text(authz_id, "authorization identity"); !c) return std::unexpected(std::move(c.error()));
		// No security layer, and so no maximum buffer size: 0 (RFC 4752
		// section 3.1: "which MAY be 0 if a security layer is not selected").
		std::string reply{ static_cast<char>(gssapi_no_layer), '\0', '\0', '\0' };
		reply += authz_id;
		return reply;
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

	// Clears `busy` at the end of an offloaded step, whatever its outcome.
	struct busy_scope
	{
		state &s;
		explicit busy_scope(state &s_) noexcept : s(s_) {}
		busy_scope(const busy_scope &) = delete;
		busy_scope &operator=(const busy_scope &) = delete;
		~busy_scope() { s.busy.store(false, std::memory_order_release); }
	};

	void reset() noexcept
	{
		at = phase::idle;
		context.reset();
		credentials.reset();
		target.reset();
	}

	// One gss_init_sec_context call, with the server's token (none at first).
	result<std::optional<std::string>> init(std::optional<std::string_view> token)
	{
		OM_uint32 minor = 0;
		gss_buffer_desc in = input(token.value_or(std::string_view()));
		output_buffer out;
		OM_uint32 flags = 0;
		const OM_uint32 major = gss_init_sec_context(&minor,
		  credentials.get(),
		  context.in_out(),
		  target.get(),
		  &krb5_oid,
		  GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG,
		  0,
		  GSS_C_NO_CHANNEL_BINDINGS,
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
		}
		// RFC 4752 section 3.1: the output token, possibly empty.
		return std::optional<std::string>(std::string(out.view()));
	}

	// The server's wrapped offer gives the wrapped reply.
	result<std::optional<std::string>> reply(std::string_view wrapped_offer, std::string_view authz_id)
	{
		OM_uint32 minor = 0;
		gss_buffer_desc in = input(wrapped_offer);
		output_buffer offer_text;
		OM_uint32 major = gss_unwrap(&minor, context.get(), &in, &offer_text.desc, nullptr, nullptr);
		if (GSS_ERROR(major) != 0) return gss_failure("gss_unwrap", major, minor);
		auto offer = detail::parse_gssapi_layer_offer(offer_text.view());
		if (!offer) return std::unexpected(std::move(offer.error()));
		auto text = detail::gssapi_layer_reply(*offer, authz_id);
		if (!text) return std::unexpected(std::move(text.error()));
		// RFC 4752 section 3.1: wrapped with conf_flag FALSE.
		gss_buffer_desc reply_in = input(*text);
		output_buffer wrapped;
		major = gss_wrap(&minor, context.get(), 0, GSS_C_QOP_DEFAULT, &reply_in, nullptr, &wrapped.desc);
		if (GSS_ERROR(major) != 0) return gss_failure("gss_wrap", major, minor);
		at = phase::replied;
		return std::optional<std::string>(std::string(wrapped.view()));
	}

	// The first token: names imported, credentials acquired (for a given
	// principal), first gss_init_sec_context call.
	result<std::optional<std::string>> begin(const sasl_gssapi_options &options, std::string_view host)
	{
		std::string target_name = options.target;
		if (target_name.empty()) {
			if (host.empty())
				return input_error(
				  "no target: the connection has no host name (ldapi://, or a wrapped transport): set the target");
			target_name = "ldap@";
			target_name += host;
		}
		if (auto c = check_text(target_name, "target"); !c) return std::unexpected(std::move(c.error()));
		if (auto c = check_text(options.principal, "principal"); !c) return std::unexpected(std::move(c.error()));
		if (auto c = check_text(options.authz_id, "authorization identity"); !c)
			return std::unexpected(std::move(c.error()));

		if (auto n = import_name(target_name, GSS_C_NT_HOSTBASED_SERVICE, target); !n)
			return std::unexpected(std::move(n.error()));
		if (!options.principal.empty()) {
			name_handle principal;
			if (auto n = import_name(options.principal, GSS_C_NT_USER_NAME, principal); !n)
				return std::unexpected(std::move(n.error()));
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
sasl_gssapi &sasl_gssapi::operator=(sasl_gssapi &&) noexcept = default;

void sasl_gssapi::prepare(const sasl_bind_context &context) { host_.assign(context.host); }

sasl_work sasl_gssapi::offload_start()
{
	// A new state for each bind: one whose step sasl_bind gave up on may
	// still be in use by its thread.
	auto s = std::make_shared<state>();
	s->busy.store(true, std::memory_order_relaxed);
	state_ = s;
	return [s, options = options_, host = host_]() {
		const state::busy_scope scope{ *s };
		return s->begin(options, host);
	};
}

sasl_work sasl_gssapi::offload_step(std::optional<std::string_view> challenge)
{
	// Only gss_init_sec_context may block; step() handles the rest
	// (the security layer reply, errors) on the I/O thread.
	if (state_ == nullptr || state_->busy.load(std::memory_order_acquire) || state_->at != state::phase::negotiating
		|| !challenge)
		return {};
	auto s = state_;
	s->busy.store(true, std::memory_order_relaxed);
	return [s, token = std::string(*challenge)]() {
		const state::busy_scope scope{ *s };
		return s->init(token);
	};
}

result<std::optional<std::string>> sasl_gssapi::start() { return offload_start()(); }

result<std::optional<std::string>> sasl_gssapi::step(std::optional<std::string_view> challenge)
{
	if (state_ == nullptr) return refused("a challenge before the exchange started");
	state &s = *state_;
	if (s.busy.load(std::memory_order_acquire)) return refused("a challenge while the previous step still runs");
	switch (s.at) {
	case state::phase::negotiating:
		if (!challenge) {
			s.reset();
			return fail(client_errc::decode_error, "no token in the server's challenge");
		}
		return s.init(*challenge);
	case state::phase::established: {
		if (!challenge) {
			s.reset();
			return fail(client_errc::decode_error, "no security layer offer in the server's challenge");
		}
		auto r = s.reply(*challenge, options_.authz_id);
		if (!r) s.reset();
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

result<void> sasl_gssapi::complete(std::optional<std::string_view> server_creds)
{
	if (state_ == nullptr) return refused("success before the exchange started");
	state &s = *state_;
	if (s.busy.load(std::memory_order_acquire)) return refused("success while the previous step still runs");
	const bool replied = s.at == state::phase::replied;
	// No security layer: the context is not used after the bind.
	s.reset();
	if (!replied) return refused("the server reported success before the security layer negotiation");
	if (server_creds && !server_creds->empty()) return refused("unexpected server credentials with the success");
	return {};
}

}// namespace jhetz::ldap
