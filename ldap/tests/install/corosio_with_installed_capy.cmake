# Injected into a standalone Corosio configure (CMAKE_PROJECT_INCLUDE) by
# check_install.sh. Corosio (pinned 54e28fd, also develop 0a387cb) expects
# its consumer to provide Boost::capy, and its install rules look for a
# target named boost_capy to decide whether Capy is an installed package:
# neither works for a plain standalone build against an installed Capy.
find_package(boost_capy CONFIG REQUIRED)
if(NOT TARGET boost_capy)
    add_library(boost_capy ALIAS Boost::capy)
endif()
