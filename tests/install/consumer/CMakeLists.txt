# A project using an installed jhetz_ldap package (check_install.sh).
cmake_minimum_required(VERSION 3.25)
project(jhetz_ldap_consumer LANGUAGES CXX)

option(WITH_NET "Use jhetz::ldap and jhetz::ldap_ad, not jhetz::ldap_core alone" ON)
if(WITH_NET)
    find_package(jhetz_ldap 0.1 REQUIRED)
else()
    find_package(jhetz_ldap 0.1 REQUIRED COMPONENTS core)
endif()

add_executable(consumer main.cpp)
target_compile_definitions(consumer PRIVATE $<$<BOOL:${WITH_NET}>:WITH_NET>)
if(WITH_NET)
    target_link_libraries(consumer PRIVATE jhetz::ldap jhetz::ldap_ad)
else()
    target_link_libraries(consumer PRIVATE jhetz::ldap_core)
endif()
