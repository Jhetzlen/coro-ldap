cmake_minimum_required(VERSION 3.25)
project(test_package LANGUAGES CXX)

find_package(boost_capy CONFIG REQUIRED)

add_executable(test_package test_package.cpp)
target_link_libraries(test_package PRIVATE Boost::capy)
