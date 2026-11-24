# CMAKE_PROJECT_INCLUDE for Corosio: Boost::capy from the installed package,
# and the boost_capy target its install rules look for.
find_package(boost_capy CONFIG REQUIRED)
if(NOT TARGET boost_capy)
    add_library(boost_capy ALIAS Boost::capy)
endif()
