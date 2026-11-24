#include <boost/capy.hpp>

#include <cstdio>

namespace capy = boost::capy;

auto hello() -> capy::task<>
{
	std::puts("capy ok");
	co_return;
}

auto main() -> int
{
	capy::thread_pool pool;
	capy::run_async(pool.get_executor())(hello());
	pool.join();
	return 0;
}
