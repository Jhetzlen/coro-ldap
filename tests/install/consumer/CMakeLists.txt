# A project using an installed jhetz_ldap package (check_install.sh).
cmake_minimum_required(VERSION 3.25)
project(jhetz_ldap_consumer LANGUAGES CXX)

option(WITH_NET "Use jhetz::ldap_net and jhetz::ldap_ad too" ON)
if(WITH_NET)
    find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS net ad)
else()
    find_package(jhetz_ldap 0.1 REQUIRED)
endif()

add_executable(consumer main.cpp)
target_compile_definitions(consumer PRIVATE $<$<BOOL:${WITH_NET}>:WITH_NET>)
target_link_libraries(consumer PRIVATE jhetz::ldap $<$<BOOL:${WITH_NET}>:jhetz::ldap_net jhetz::ldap_ad>)
