vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO cppalliance/capy
    REF 6a9569060f999453e1f7b59cc9ae31c808c0778b
    SHA512 014bfed7ff2bdfa4c0a6def1b85475e341f6ece2d438fc7e6ea3e26519e6aa2d1805508e6d9d16730e075ae3afd00b9b0df36bf3276f0801ccf5848661c8734c
    HEAD_REF develop
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
        -DBOOST_CAPY_BUILD_TESTS=OFF
        -DBOOST_CAPY_BUILD_EXAMPLES=OFF
        -DBOOST_CAPY_BUILD_BENCH=OFF
)
vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME boost_capy CONFIG_PATH lib/cmake/boost_capy)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include" "${CURRENT_PACKAGES_DIR}/debug/share")
vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE_1_0.txt")
