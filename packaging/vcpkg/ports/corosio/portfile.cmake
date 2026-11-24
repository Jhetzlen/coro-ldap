vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO cppalliance/corosio
    REF 2d246de82c62a62d0da9c1e4c81a1865be7f9321
    SHA512 553d23d367e0604b6fa1f7bd4f71fcb50d3452c7edd27acd0be58130b9a8b32e8e1e93eccd2a9fc621047efa71cde9c54d2e5889f330ba16298ef920d2129dbf
    HEAD_REF develop
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        "-DCMAKE_PROJECT_INCLUDE=${CMAKE_CURRENT_LIST_DIR}/capy-imported.cmake"
        -DBUILD_TESTING=OFF
        -DBOOST_COROSIO_BUILD_TESTS=OFF
        -DBOOST_COROSIO_BUILD_EXAMPLES=OFF
        -DBOOST_COROSIO_BUILD_BENCH=OFF
        -DCMAKE_DISABLE_FIND_PACKAGE_WolfSSL=ON
        -DCMAKE_DISABLE_FIND_PACKAGE_liburing=ON
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME boost_corosio CONFIG_PATH lib/cmake/boost_corosio)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE_1_0.txt")
