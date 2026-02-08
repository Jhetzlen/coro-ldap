#include <boost/asio.hpp>
#include <chrono>
#include <print>
#include <resource_pool.hpp>


struct Connection
{
	int id;
	explicit Connection(int index) : id(index) { std::println("Connection {} created", id); }
	~Connection() { std::println("Connection {} destroyed", id); }
};

boost::asio::awaitable<void> example_task(std::shared_ptr<resource_pool<Connection>> pool)
{
	auto conn = co_await pool->acquire();

	// Simulate work
	co_await boost::asio::steady_timer(co_await boost::asio::this_coro::executor, std::chrono::seconds(3))
	  .async_wait(boost::asio::use_awaitable);
	std::println("Owning connection {} ", conn->id);
	// Resource automatically returns to pool when conn goes out of scope
}

int main()
{
	constexpr size_t pool_size = 2;
	constexpr size_t task_number = 10;
	
	boost::asio::io_context io_context;
	
	auto pool = std::make_shared<resource_pool<Connection>>(
		io_context.get_executor(),
		[]()
		{
			static int id = 0;
			return std::make_unique<Connection>(id++);
		},
		pool_size);

	for (size_t i = 0; i < task_number; ++i) 
	{
		boost::asio::co_spawn(
			io_context, 
			example_task(pool),
			boost::asio::detached); 
	}

	io_context.run();
	return 0;
}
