#include "jhetz/ldap/testing/message_io.hpp"

#include "format_util.hpp"

#include <utility>

namespace jhetz::ldap::testing {

auto read_message(net::transport &t, net::read_buffer &buf, read_options options) -> boost::capy::task<result<message>>
{
	auto size = co_await net::read_frame(t, buf, options.max_message_size);
	if (!size) {
		co_return std::unexpected(std::move(size.error()));
	}
	auto m = decode(buf.data().first(*size), options.decode);
	buf.consume(*size);
	if (!m) {
		co_return std::unexpected(detail::with_context(std::move(m.error()), detail::format("read {}", t.name())));
	}
	co_return m;
}

}// namespace jhetz::ldap::testing
