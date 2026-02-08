#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>  
#include <boost/asio/use_awaitable.hpp>
#include <memory>
#include <optional>

template<typename T>
class resource_pool 
    : public std::enable_shared_from_this<resource_pool<T>> 
{
    friend struct deleter ;
    
    struct deleter
    {
        std::weak_ptr<resource_pool> pool;
        
        auto operator()(
            T* res) const 
            -> void 
        {
            if (auto self = pool.lock()) 
            {
                self->register_(std::unique_ptr<T>{res});
            } 
            else 
            {
                delete res;
            }
        }
    };

public:
    using resource_ptr = std::unique_ptr<T, deleter>;
    using channel_type = boost::asio::experimental::channel<
        void(
            boost::system::error_code, 
            std::unique_ptr<T>
            )
        >;

private:
    boost::asio::any_io_executor executor_;
    channel_type channel_;
public:
    template<typename Factory>
    resource_pool(
        boost::asio::any_io_executor executor, 
        Factory&& factory,
        size_t capacity
    )
        : executor_(executor)
        , channel_(executor, capacity)
    {
        populate_(std::forward<Factory>(factory));
    }

    auto acquire() 
        -> boost::asio::awaitable<resource_ptr> 
    {
        auto ptr = co_await channel_.async_receive(
                boost::asio::use_awaitable);
        co_return resource_ptr(
                ptr.release(),
                deleter{this->weak_from_this()});
    }
    
    auto try_acquire() 
        -> std::optional<resource_ptr>
    {
        std::unique_ptr<T> ptr = nullptr;
        if (channel_.try_receive(
            [&](
                boost::system::error_code,
                std::unique_ptr<T> res)
            {
                ptr = std::move(res);
            })
        ) 
        { 
            return resource_ptr(
                ptr.release(),
                deleter{this->weak_from_this()});
        }
        return std::nullopt;
    }

    auto available() const 
        -> size_t 
    { 
        return channel_.ready(); 
    }

    auto close() 
        -> void 
    { 
        channel_.close(); 
    }
private:
    auto register_(
        std::unique_ptr<T> res) 
        -> void 
    {
        if (!channel_.try_send(
            boost::system::error_code{},
            std::move(res)))
        {
            throw std::runtime_error("ResourcePool: register_ failed");
        } 
    }
    
    template<typename Factory>
    auto populate_(
        Factory&& factory)
        -> void 
    {
        for (size_t i = 0; i < channel_.capacity(); ++i) 
        {
            channel_.try_send(
                boost::system::error_code{},
                factory());
        }
    }

};




