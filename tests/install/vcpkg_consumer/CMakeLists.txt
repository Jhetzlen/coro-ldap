# A manifest-mode vcpkg project using the jhetz-ldap port (check_vcpkg.sh).
cmake_minimum_required(VERSION 3.25)
project(jhetz_ldap_vcpkg_consumer LANGUAGES CXX)

option(WITH_GSSAPI "Use the gssapi feature (component gssapi)" OFF)
if(WITH_GSSAPI)
    find_package(jhetz_ldap 0.1 CONFIG REQUIRED COMPONENTS net ad gssapi)
else()
    find_package(jhetz_ldap 0.1 CONFIG REQUIRED COMPONENTS net ad)
endif()

add_executable(consumer ../consumer/main.cpp)
target_compile_definitions(consumer PRIVATE WITH_NET $<$<BOOL:${WITH_GSSAPI}>:WITH_GSSAPI>)
target_link_libraries(consumer PRIVATE jhetz::ldap jhetz::ldap_net jhetz::ldap_ad)
