add_executable(basic_example basic_example.cpp)
target_link_libraries(basic_example 
    PRIVATE 
        resource_pool
        Boost::boost
)
#[==[

add_executable(channel_example channel_example.cpp)
target_link_libraries(channel_example
    PRIVATE
        Boost::boost
        Boost::system
)
]==]
#



