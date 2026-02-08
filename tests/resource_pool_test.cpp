#include <catch2/catch_test_macros.hpp>
#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

struct MockResource {
    int id;
};

TEST_CASE("resource_pool basics", "[resource_pool]") {
    boost::asio::io_context ctx;
    int counter = 0;
    auto factory = [&]() { return std::make_unique<MockResource>(++counter); };

    auto pool = resource_pool<MockResource>::create(ctx.get_executor(), factory, 2);

    SECTION("Acquire and release increases available count") {
        auto res = pool->try_acquire();
        REQUIRE(res.has_value());
        CHECK((*res)->id == 1);
        CHECK(pool->try_acquire().has_value());
        CHECK_FALSE(pool->try_acquire().has_value()); // Empty

        res.reset(); // Release back to pool
        ctx.poll();  // Run the dispatch that returns the resource
        CHECK(pool->try_acquire().has_value());
    }

    SECTION("Async acquire with coroutine") {
        boost::asio::co_spawn(ctx, [&]() -> boost::asio::awaitable<void> {
            auto res1 = co_await pool->acquire();
            auto res2 = co_await pool->acquire();
            
            CHECK(res1->id != res2->id);
            co_return;
        }, boost::asio::detached);

        ctx.run();
    }

    SECTION("Closing the pool") {
        pool->close();
        CHECK_FALSE(pool->try_acquire().has_value());
        
        boost::asio::co_spawn(ctx, [&]() -> boost::asio::awaitable<void> {
            try {
                co_await pool->acquire();
                FAIL("Should have thrown error");
            } catch (const boost::system::system_error&) {
                SUCCEED("Correctly caught error on closed pool");
            }
            co_return;
        }, boost::asio::detached);

        ctx.run();
    }
}
