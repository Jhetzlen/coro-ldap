// sasl_gssapi's security context over the GSS-API C library (MIT krb5 or
// Heimdal). See sasl_gssapi_context.hpp.
#include "sasl_gssapi_context.hpp"

#include "jhetz/ldap/ber.hpp"

#include "format_util.hpp"
#include "sasl_util.hpp"

#include <gssapi/gssapi.h>
#if __has_include(<gssapi/gssapi_ext.h>)
#include <gssapi/gssapi_ext.h>
#endif

#include <array>
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

namespace jhetz::ldap::detail {

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

	void append(std::pmr::vector<std::byte> &out, std::string_view bytes)
	{
		const auto *p = reinterpret_cast<const std::byte *>(bytes.data());
		out.insert(out.end(), p, p + bytes.size());
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
			append_sanitized(out, message.view(), 256);
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

}// namespace

struct gssapi_context::handles
{
	name_handle target;
	cred_handle credentials;
	context_handle context;
	std::string bindings;
	OM_uint32 req_flags = 0;
	// gss_init_sec_context's ret_flags once established.
	OM_uint32 ret_flags = 0;
	bool established = false;
};

gssapi_context::gssapi_context() = default;
gssapi_context::~gssapi_context() = default;
gssapi_context::gssapi_context(gssapi_context &&) noexcept = default;
auto gssapi_context::operator=(gssapi_context &&) noexcept -> gssapi_context & = default;

void gssapi_context::reset() noexcept { h_.reset(); }

auto gssapi_context::established() const noexcept -> bool { return h_ != nullptr && h_->established; }

auto gssapi_context::flags() const noexcept -> gssapi_context_flags
{
	if (h_ == nullptr) {
		return {};
	}
	return { .integrity = (h_->ret_flags & GSS_C_INTEG_FLAG) != 0,
		.confidentiality = (h_->ret_flags & GSS_C_CONF_FLAG) != 0,
		.sequence = (h_->ret_flags & GSS_C_SEQUENCE_FLAG) != 0 };
}

auto gssapi_context::acquire(const gssapi_request &request) -> result<void>
{
	h_ = std::make_unique<handles>();
	h_->bindings.assign(request.bindings);
	// With bindings, the client says it binds (channel_bound_flag); with a
	// layer to select, integrity and confidentiality.
	h_->req_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | (request.bindings.empty() ? 0 : channel_bound_flag)
					| (request.layer ? layer_flags : OM_uint32{ 0 });
	if (auto n = import_name(request.target, GSS_C_NT_HOSTBASED_SERVICE, h_->target); !n) {
		reset();
		return n;
	}
	if (request.principal.empty()) {
		return {};
	}
	name_handle principal;
	if (auto n = import_name(request.principal, GSS_C_NT_USER_NAME, principal); !n) {
		reset();
		return n;
	}
	OM_uint32 minor = 0;
	OM_uint32 major = 0;
	if (request.password.empty()) {
		major = gss_acquire_cred(&minor,
		  principal.get(),
		  GSS_C_INDEFINITE,
		  &krb5_oid_set,
		  GSS_C_INITIATE,
		  h_->credentials.out(),
		  nullptr,
		  nullptr);
		if (GSS_ERROR(major) != 0) {
			reset();
			return gss_failure("gss_acquire_cred", major, minor);
		}
		return {};
	}
	gss_buffer_desc password = input(request.password);
	major = gss_acquire_cred_with_password(&minor,
	  principal.get(),
	  &password,
	  GSS_C_INDEFINITE,
	  &krb5_oid_set,
	  GSS_C_INITIATE,
	  h_->credentials.out(),
	  nullptr,
	  nullptr);
	if (GSS_ERROR(major) != 0) {
		reset();
		return gss_failure("gss_acquire_cred_with_password", major, minor);
	}
	return {};
}

auto gssapi_context::init(std::optional<std::string_view> token) -> result<std::string>
{
	if (h_ == nullptr) {
		return fail(client_errc::internal_error, "gss_init_sec_context: no credentials acquired");
	}
	handles &h = *h_;
	OM_uint32 minor = 0;
	gss_buffer_desc in = input(token.value_or(std::string_view()));
	output_buffer out;
	OM_uint32 flags = 0;
	// RFC 2744 section 3.11: no addresses, the TLS binding as application data.
	gss_channel_bindings_struct channel{ .initiator_addrtype = GSS_C_AF_UNSPEC,
		.initiator_address = { .length = 0, .value = nullptr },
		.acceptor_addrtype = GSS_C_AF_UNSPEC,
		.acceptor_address = { .length = 0, .value = nullptr },
		.application_data = input(h.bindings) };
	const OM_uint32 major = gss_init_sec_context(&minor,
	  h.credentials.get(),
	  h.context.in_out(),
	  h.target.get(),
	  &krb5_oid,
	  h.req_flags,
	  0,
	  h.bindings.empty() ? GSS_C_NO_CHANNEL_BINDINGS : &channel,
	  token ? &in : GSS_C_NO_BUFFER,
	  nullptr,
	  &out.desc,
	  &flags,
	  nullptr);
	if (GSS_ERROR(major) != 0) {
		auto e = gss_failure("gss_init_sec_context", major, minor);
		reset();
		return e;
	}
	if ((major & GSS_S_CONTINUE_NEEDED) == 0) {
		if ((flags & GSS_C_MUTUAL_FLAG) == 0) {
			reset();
			return fail(client_errc::gssapi_failure,
			  "gss_init_sec_context: no mutual authentication (the server was not authenticated)");
		}
		h.established = true;
		h.ret_flags = flags;
	}
	return std::string(out.view());
}

auto gssapi_context::wrap(std::span<const std::byte> plaintext, bool confidentiality, std::pmr::vector<std::byte> &out)
  -> result<void>
{
	if (h_ == nullptr) {
		return fail(client_errc::internal_error, "gss_wrap: no security context");
	}
	OM_uint32 minor = 0;
	gss_buffer_desc in = input(as_text(plaintext));
	output_buffer wrapped;
	int conf_state = 0;
	const OM_uint32 major =
	  gss_wrap(&minor, h_->context.get(), confidentiality ? 1 : 0, GSS_C_QOP_DEFAULT, &in, &conf_state, &wrapped.desc);
	if (GSS_ERROR(major) != 0) {
		return gss_failure("gss_wrap", major, minor);
	}
	if (confidentiality && conf_state == 0) {
		return fail(client_errc::gssapi_failure, "gss_wrap: no confidentiality applied");
	}
	append(out, wrapped.view());
	return {};
}

auto gssapi_context::unwrap(std::span<const std::byte> token, std::pmr::vector<std::byte> &out, bool &confidential)
  -> result<void>
{
	if (h_ == nullptr) {
		return fail(client_errc::internal_error, "gss_unwrap: no security context");
	}
	OM_uint32 minor = 0;
	gss_buffer_desc in = input(as_text(token));
	output_buffer plain;
	int conf_state = 0;
	const OM_uint32 major = gss_unwrap(&minor, h_->context.get(), &in, &plain.desc, &conf_state, nullptr);
	if (GSS_ERROR(major) != 0) {
		return gss_failure("gss_unwrap", major, minor);
	}
	if ((major & sequence_problems) != 0) {
		return fail(client_errc::gssapi_failure,
		  "gss_unwrap: a buffer replayed or out of sequence: " + status_text(major, GSS_C_GSS_CODE));
	}
	confidential = conf_state != 0;
	append(out, plain.view());
	return {};
}

auto gssapi_context::wrap_size_limit(bool confidentiality, std::uint32_t max_size) const -> result<std::size_t>
{
	if (h_ == nullptr) {
		return fail(client_errc::internal_error, "gss_wrap_size_limit: no security context");
	}
	OM_uint32 minor = 0;
	OM_uint32 max_input = 0;
	const OM_uint32 major =
	  gss_wrap_size_limit(&minor, h_->context.get(), confidentiality ? 1 : 0, GSS_C_QOP_DEFAULT, max_size, &max_input);
	if (GSS_ERROR(major) != 0) {
		return gss_failure("gss_wrap_size_limit", major, minor);
	}
	return std::size_t{ max_input };
}

}// namespace jhetz::ldap::detail
