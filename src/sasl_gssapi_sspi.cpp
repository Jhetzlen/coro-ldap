// sasl_gssapi's security context over SSPI's Kerberos package (Windows).
// Needs SECURITY_WIN32 (CMake). See sasl_gssapi_context.hpp.
#include "sasl_gssapi_context.hpp"

#include "format_util.hpp"
#include "sasl_util.hpp"

#include <windows.h>
// After <windows.h>, with SECURITY_WIN32.
#include <sspi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
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

	struct status_text
	{
		std::int32_t status;
		std::string_view name;
		std::string_view text;
	};
	// NOLINTBEGIN(readability-magic-numbers): the SEC_E_* values from <winerror.h>
	constexpr std::array status_texts{
		status_text{ static_cast<std::int32_t>(SEC_E_INSUFFICIENT_MEMORY),
		  "SEC_E_INSUFFICIENT_MEMORY",
		  "not enough memory" },
		status_text{ static_cast<std::int32_t>(SEC_E_INVALID_HANDLE), "SEC_E_INVALID_HANDLE", "invalid handle" },
		status_text{ static_cast<std::int32_t>(SEC_E_UNSUPPORTED_FUNCTION),
		  "SEC_E_UNSUPPORTED_FUNCTION",
		  "function not supported" },
		status_text{ static_cast<std::int32_t>(SEC_E_TARGET_UNKNOWN),
		  "SEC_E_TARGET_UNKNOWN",
		  "unknown target (no such service principal)" },
		status_text{ static_cast<std::int32_t>(SEC_E_INTERNAL_ERROR),
		  "SEC_E_INTERNAL_ERROR",
		  "internal error of the security package" },
		status_text{ static_cast<std::int32_t>(SEC_E_SECPKG_NOT_FOUND),
		  "SEC_E_SECPKG_NOT_FOUND",
		  "security package not found" },
		status_text{ static_cast<std::int32_t>(SEC_E_INVALID_TOKEN), "SEC_E_INVALID_TOKEN", "invalid token" },
		status_text{ static_cast<std::int32_t>(SEC_E_QOP_NOT_SUPPORTED),
		  "SEC_E_QOP_NOT_SUPPORTED",
		  "protection not supported" },
		status_text{ static_cast<std::int32_t>(SEC_E_LOGON_DENIED), "SEC_E_LOGON_DENIED", "logon denied" },
		status_text{ static_cast<std::int32_t>(SEC_E_UNKNOWN_CREDENTIALS),
		  "SEC_E_UNKNOWN_CREDENTIALS",
		  "unknown credentials" },
		status_text{ static_cast<std::int32_t>(SEC_E_NO_CREDENTIALS), "SEC_E_NO_CREDENTIALS", "no credentials" },
		status_text{ static_cast<std::int32_t>(SEC_E_MESSAGE_ALTERED),
		  "SEC_E_MESSAGE_ALTERED",
		  "message altered (integrity check failed)" },
		status_text{ static_cast<std::int32_t>(SEC_E_OUT_OF_SEQUENCE),
		  "SEC_E_OUT_OF_SEQUENCE",
		  "message replayed or out of sequence" },
		status_text{ static_cast<std::int32_t>(SEC_E_NO_AUTHENTICATING_AUTHORITY),
		  "SEC_E_NO_AUTHENTICATING_AUTHORITY",
		  "no domain controller (KDC) could be contacted" },
		status_text{ static_cast<std::int32_t>(SEC_E_INCOMPLETE_MESSAGE),
		  "SEC_E_INCOMPLETE_MESSAGE",
		  "incomplete message" },
		status_text{ static_cast<std::int32_t>(SEC_E_CONTEXT_EXPIRED),
		  "SEC_E_CONTEXT_EXPIRED",
		  "security context expired" },
		status_text{ static_cast<std::int32_t>(SEC_E_WRONG_PRINCIPAL),
		  "SEC_E_WRONG_PRINCIPAL",
		  "the server is not the expected principal" },
		status_text{ static_cast<std::int32_t>(SEC_E_TIME_SKEW),
		  "SEC_E_TIME_SKEW",
		  "clock skew between client and server too great" },
		status_text{ static_cast<std::int32_t>(SEC_E_DECRYPT_FAILURE), "SEC_E_DECRYPT_FAILURE", "decryption failed" },
		status_text{ static_cast<std::int32_t>(SEC_E_ALGORITHM_MISMATCH),
		  "SEC_E_ALGORITHM_MISMATCH",
		  "no common encryption type" },
		status_text{ static_cast<std::int32_t>(SEC_E_BAD_BINDINGS),
		  "SEC_E_BAD_BINDINGS",
		  "channel bindings do not match" },
		status_text{ static_cast<std::int32_t>(SEC_E_DOWNGRADE_DETECTED),
		  "SEC_E_DOWNGRADE_DETECTED",
		  "downgrade detected" },
	};
	// NOLINTEND(readability-magic-numbers)

	// The SSPI name of the Kerberos package (MICROSOFT_KERBEROS_NAME_W).
	constexpr std::wstring_view kerberos_package = L"Kerberos";

	auto failed(SECURITY_STATUS status) noexcept -> bool { return status < 0; }

	auto failure(std::string_view call, SECURITY_STATUS status) -> std::unexpected<error>
	{
		return sspi_failure(call, static_cast<std::int32_t>(status));
	}

	auto to_ulong(std::size_t n, std::string_view call) -> result<unsigned long>
	{
		if (n > std::numeric_limits<unsigned long>::max()) {
			return fail(client_errc::encode_error, std::string(call) + ": buffer too large");
		}
		return static_cast<unsigned long>(n);
	}

	auto to_wide(const std::u16string &s) -> std::wstring
	{
		static_assert(sizeof(wchar_t) == sizeof(char16_t));
		return { s.begin(), s.end() };
	}

	// A wide string wiped when destroyed.
	struct wiped_wstring
	{
		std::wstring text;
		wiped_wstring() = default;
		wiped_wstring(const wiped_wstring &) = delete;
		auto operator=(const wiped_wstring &) -> wiped_wstring & = delete;
		~wiped_wstring() { wipe_string(text); }
		// SEC_WINNT_AUTH_IDENTITY_W's pointer; null when empty.
		auto pointer() noexcept -> unsigned short *
		{
			return text.empty() ? nullptr : reinterpret_cast<unsigned short *>(text.data());
		}
		[[nodiscard]] auto length() const noexcept -> unsigned long { return static_cast<unsigned long>(text.size()); }
	};

	// A buffer the security package allocated (ISC_REQ_ALLOCATE_MEMORY).
	struct context_buffer
	{
		void *p = nullptr;
		context_buffer() = default;
		context_buffer(const context_buffer &) = delete;
		auto operator=(const context_buffer &) -> context_buffer & = delete;
		~context_buffer()
		{
			if (p != nullptr) {
				FreeContextBuffer(p);
			}
		}
	};

}// namespace

auto sspi_failure(std::string_view call, std::int32_t status) -> std::unexpected<error>
{
	const auto it = std::ranges::find_if(status_texts, [status](const status_text &s) { return s.status == status; });
	const auto code = static_cast<std::uint32_t>(status);
	if (it == status_texts.end()) {
		return fail(client_errc::gssapi_failure, detail::format("{}: 0x{:08X}", call, code));
	}
	return fail(client_errc::gssapi_failure, detail::format("{}: {} (0x{:08X}): {}", call, it->name, code, it->text));
}

struct gssapi_context::handles
{
	CredHandle credentials{};
	bool have_credentials = false;
	CtxtHandle context{};
	bool have_context = false;
	std::wstring target;
	// SEC_CHANNEL_BINDINGS and the application data after it; empty: none.
	std::vector<unsigned char> bindings;
	unsigned long req_flags = 0;
	unsigned long ret_flags = 0;
	SecPkgContext_Sizes sizes{};
	bool established = false;

	handles() = default;
	handles(const handles &) = delete;
	auto operator=(const handles &) -> handles & = delete;
	~handles()
	{
		if (have_context) {
			DeleteSecurityContext(&context);
		}
		if (have_credentials) {
			FreeCredentialsHandle(&credentials);
		}
	}
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
	return { .integrity = (h_->ret_flags & ISC_RET_INTEGRITY) != 0,
		.confidentiality = (h_->ret_flags & ISC_RET_CONFIDENTIALITY) != 0,
		.sequence = (h_->ret_flags & ISC_RET_SEQUENCE_DETECT) != 0 };
}

auto gssapi_context::acquire(const gssapi_request &request) -> result<void>
{
	h_ = std::make_unique<handles>();
	handles &h = *h_;
	auto target = sspi_target_name(request.target);
	if (!target) {
		reset();
		return std::unexpected(std::move(target.error()));
	}
	h.target = to_wide(*target);
	if (!request.bindings.empty()) {
		auto length = to_ulong(request.bindings.size(), "channel bindings");
		if (!length) {
			reset();
			return std::unexpected(std::move(length.error()));
		}
		SEC_CHANNEL_BINDINGS header{};
		header.cbApplicationDataLength = *length;
		header.dwApplicationDataOffset = sizeof(SEC_CHANNEL_BINDINGS);
		h.bindings.resize(sizeof(SEC_CHANNEL_BINDINGS) + request.bindings.size());
		std::memcpy(h.bindings.data(), &header, sizeof(header));
		std::memcpy(h.bindings.data() + sizeof(header), request.bindings.data(), request.bindings.size());
	}
	// With a layer to select, integrity and confidentiality.
	h.req_flags = ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_ALLOCATE_MEMORY
				  | (request.layer ? (ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY) : 0UL);

	// Without a principal: the logged-on user's credentials.
	SEC_WINNT_AUTH_IDENTITY_W identity{};
	wiped_wstring user;
	wiped_wstring domain;
	wiped_wstring password;
	if (!request.principal.empty()) {
		auto id = make_sspi_identity(request.principal, request.password);
		if (!id) {
			reset();
			return std::unexpected(std::move(id.error()));
		}
		user.text = to_wide(id->user);
		domain.text = to_wide(id->domain);
		password.text = to_wide(id->password);
		identity = SEC_WINNT_AUTH_IDENTITY_W{ .User = user.pointer(),
			.UserLength = user.length(),
			.Domain = domain.pointer(),
			.DomainLength = domain.length(),
			.Password = password.pointer(),
			.PasswordLength = password.length(),
			.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE };
	}
	std::wstring package(kerberos_package);
	TimeStamp expiry{};
	const SECURITY_STATUS status = AcquireCredentialsHandleW(nullptr,
	  package.data(),
	  SECPKG_CRED_OUTBOUND,
	  nullptr,
	  request.principal.empty() ? nullptr : &identity,
	  nullptr,
	  nullptr,
	  &h.credentials,
	  &expiry);
	wipe_bytes(&identity, sizeof(identity));
	if (failed(status)) {
		reset();
		return failure("AcquireCredentialsHandleW", status);
	}
	h.have_credentials = true;
	return {};
}

auto gssapi_context::init(std::optional<std::string_view> token) -> result<std::string>
{
	if (h_ == nullptr) {
		return fail(client_errc::internal_error, "InitializeSecurityContextW: no credentials acquired");
	}
	handles &h = *h_;
	std::array<SecBuffer, 2> in_buffers{};
	unsigned long in_count = 0;
	if (token) {
		auto length = to_ulong(token->size(), "InitializeSecurityContextW");
		if (!length) {
			reset();
			return std::unexpected(std::move(length.error()));
		}
		// NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast): SSPI does not write through input tokens
		in_buffers.at(in_count++) = SecBuffer{
			.cbBuffer = *length, .BufferType = SECBUFFER_TOKEN, .pvBuffer = const_cast<char *>(token->data())
		};
		// NOLINTEND(cppcoreguidelines-pro-type-const-cast)
	}
	if (!h.bindings.empty()) {
		in_buffers.at(in_count++) = SecBuffer{ .cbBuffer = static_cast<unsigned long>(h.bindings.size()),
			.BufferType = SECBUFFER_CHANNEL_BINDINGS,
			.pvBuffer = h.bindings.data() };
	}
	SecBufferDesc in_desc{ .ulVersion = SECBUFFER_VERSION, .cBuffers = in_count, .pBuffers = in_buffers.data() };
	SecBuffer out_buffer{ .cbBuffer = 0, .BufferType = SECBUFFER_TOKEN, .pvBuffer = nullptr };
	SecBufferDesc out_desc{ .ulVersion = SECBUFFER_VERSION, .cBuffers = 1, .pBuffers = &out_buffer };
	unsigned long attributes = 0;
	TimeStamp expiry{};
	SECURITY_STATUS status = InitializeSecurityContextW(&h.credentials,
	  h.have_context ? &h.context : nullptr,
	  h.target.data(),
	  h.req_flags,
	  0,
	  SECURITY_NATIVE_DREP,
	  in_count == 0 ? nullptr : &in_desc,
	  0,
	  &h.context,
	  &out_desc,
	  &attributes,
	  &expiry);
	context_buffer out_owner;
	out_owner.p = out_buffer.pvBuffer;
	if (failed(status)) {
		auto e = failure("InitializeSecurityContextW", status);
		reset();
		return e;
	}
	h.have_context = true;
	if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
		const SECURITY_STATUS completed = CompleteAuthToken(&h.context, &out_desc);
		if (failed(completed)) {
			auto e = failure("CompleteAuthToken", completed);
			reset();
			return e;
		}
	}
	std::string out;
	if (out_buffer.pvBuffer != nullptr) {
		out.assign(static_cast<const char *>(out_buffer.pvBuffer), out_buffer.cbBuffer);
	}
	if (status == SEC_I_CONTINUE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE) {
		return out;
	}
	if ((attributes & ISC_RET_MUTUAL_AUTH) == 0) {
		reset();
		return fail(client_errc::gssapi_failure,
		  "InitializeSecurityContextW: no mutual authentication (the server was not authenticated)");
	}
	status = QueryContextAttributesW(&h.context, SECPKG_ATTR_SIZES, &h.sizes);
	if (failed(status)) {
		auto e = failure("QueryContextAttributesW", status);
		reset();
		return e;
	}
	h.ret_flags = attributes;
	h.established = true;
	return out;
}

auto gssapi_context::wrap(std::span<const std::byte> plaintext, bool confidentiality, std::pmr::vector<std::byte> &out)
  -> result<void>
{
	if (h_ == nullptr || !h_->established) {
		return fail(client_errc::internal_error, "EncryptMessage: no security context");
	}
	handles &h = *h_;
	auto length = to_ulong(plaintext.size(), "EncryptMessage");
	if (!length) {
		return std::unexpected(std::move(length.error()));
	}
	// The wrap token: header (security trailer), data and padding, in place.
	const std::size_t base = out.size();
	const std::size_t header = h.sizes.cbSecurityTrailer;
	const std::size_t padding = h.sizes.cbBlockSize;
	out.resize(base + header + plaintext.size() + padding);
	std::byte *p = out.data() + base;
	std::ranges::copy(plaintext, p + header);
	std::array<SecBuffer, 3> buffers{
		SecBuffer{ .cbBuffer = h.sizes.cbSecurityTrailer, .BufferType = SECBUFFER_TOKEN, .pvBuffer = p },
		SecBuffer{ .cbBuffer = *length, .BufferType = SECBUFFER_DATA, .pvBuffer = p + header },
		SecBuffer{
		  .cbBuffer = h.sizes.cbBlockSize, .BufferType = SECBUFFER_PADDING, .pvBuffer = p + header + plaintext.size() }
	};
	SecBufferDesc desc{ .ulVersion = SECBUFFER_VERSION,
		.cBuffers = static_cast<unsigned long>(buffers.size()),
		.pBuffers = buffers.data() };
	// Integrity only: a wrap token without encryption (gss_wrap with
	// conf_req_flag false), not a MIC token.
	const SECURITY_STATUS status = EncryptMessage(&h.context, confidentiality ? 0 : SECQOP_WRAP_NO_ENCRYPT, &desc, 0);
	if (failed(status)) {
		out.resize(base);
		return failure("EncryptMessage", status);
	}
	// The three buffers as they came back, back to back.
	std::size_t at = 0;
	for (const SecBuffer &b : buffers) {
		std::memmove(p + at, b.pvBuffer, b.cbBuffer);
		at += b.cbBuffer;
	}
	out.resize(base + at);
	return {};
}

auto gssapi_context::unwrap(std::span<const std::byte> token, std::pmr::vector<std::byte> &out, bool &confidential)
  -> result<void>
{
	if (h_ == nullptr || !h_->established) {
		return fail(client_errc::internal_error, "DecryptMessage: no security context");
	}
	auto length = to_ulong(token.size(), "DecryptMessage");
	if (!length) {
		return std::unexpected(std::move(length.error()));
	}
	// Decrypted in place: the whole token as a stream, the data found in it.
	const std::size_t base = out.size();
	out.insert(out.end(), token.begin(), token.end());
	std::byte *p = out.data() + base;
	std::array<SecBuffer, 2> buffers{ SecBuffer{ .cbBuffer = *length, .BufferType = SECBUFFER_STREAM, .pvBuffer = p },
		SecBuffer{ .cbBuffer = 0, .BufferType = SECBUFFER_DATA, .pvBuffer = nullptr } };
	SecBufferDesc desc{ .ulVersion = SECBUFFER_VERSION,
		.cBuffers = static_cast<unsigned long>(buffers.size()),
		.pBuffers = buffers.data() };
	unsigned long qop = 0;
	const SECURITY_STATUS status = DecryptMessage(&h_->context, &desc, 0, &qop);
	if (failed(status)) {
		out.resize(base);
		return failure("DecryptMessage", status);
	}
	const auto data = std::ranges::find_if(buffers, [](const SecBuffer &b) { return b.BufferType == SECBUFFER_DATA; });
	if (data == buffers.end() || (data->cbBuffer != 0 && data->pvBuffer == nullptr)) {
		out.resize(base);
		return fail(client_errc::gssapi_failure, "DecryptMessage: no data buffer");
	}
	if (data->cbBuffer != 0) {
		std::memmove(p, data->pvBuffer, data->cbBuffer);
	}
	out.resize(base + data->cbBuffer);
	confidential = (qop & SECQOP_WRAP_NO_ENCRYPT) == 0;
	return {};
}

// The same overhead bound with or without confidentiality.
auto gssapi_context::wrap_size_limit([[maybe_unused]] bool confidentiality, std::uint32_t max_size) const
  -> result<std::size_t>
{
	if (h_ == nullptr || !h_->established) {
		return fail(client_errc::internal_error, "wrap size limit: no security context");
	}
	const std::size_t overhead = std::size_t{ h_->sizes.cbSecurityTrailer } + h_->sizes.cbBlockSize;
	return max_size > overhead ? max_size - overhead : 0;
}

}// namespace jhetz::ldap::detail
