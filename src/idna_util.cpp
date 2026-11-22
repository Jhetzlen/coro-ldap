#include "idna_util.hpp"

#include "icu_util.hpp"

#include <unicode/uidna.h>

#include <limits>
#include <memory>
#include <utility>

namespace jhetz::ldap::detail {
namespace {

	struct idna_closer
	{
		void operator()(UIDNA *p) const noexcept { uidna_close(p); }
	};

	auto refused() -> std::unexpected<error>
	{
		return fail(client_errc::string_prep_failed, "not a valid domain name (UTS #46)");
	}

}// namespace

auto idna_to_ascii(std::string_view name, std::uint32_t options, std::size_t max_length) -> result<std::string>
{
	constexpr auto max_icu_length = static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max());
	if (name.size() > max_icu_length || max_length >= max_icu_length) {
		return refused();
	}
	UErrorCode status = U_ZERO_ERROR;
	const std::unique_ptr<UIDNA, idna_closer> idna(uidna_openUTS46(options, &status));
	if (icu_failed(status)) {
		return fail(client_errc::internal_error, std::string("ICU uidna_openUTS46: ") + u_errorName(status));
	}
	std::string out(max_length + 1, '\0');
	UIDNAInfo info = UIDNA_INFO_INITIALIZER;
	const std::int32_t length = uidna_nameToASCII_UTF8(idna.get(),
	  name.data(),
	  static_cast<std::int32_t>(name.size()),
	  out.data(),
	  static_cast<std::int32_t>(out.size()),
	  &info,
	  &status);
	if (icu_failed(status) || info.errors != 0 || length <= 0 || std::cmp_greater(length, max_length)) {
		return refused();
	}
	out.resize(static_cast<std::size_t>(length));
	return out;
}

}// namespace jhetz::ldap::detail
