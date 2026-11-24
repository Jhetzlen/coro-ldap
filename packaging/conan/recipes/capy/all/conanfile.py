import os

from conan import ConanFile
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir

required_conan_version = ">=2.1"


class CapyConan(ConanFile):
    name = "capy"
    description = "Boost.Capy: coroutine primitives for asynchronous I/O (C++20)."
    license = "BSL-1.0"
    homepage = "https://github.com/cppalliance/capy"
    url = "https://github.com/Jhetzlen/coro-ldap"
    topics = ("coroutines", "async", "io")
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self, src_folder="src")

    def validate(self):
        check_min_cppstd(self, 20)

    def source(self):
        get(self, **self.conan_data["sources"][self.version], strip_root=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.cache_variables["BUILD_TESTING"] = False
        tc.cache_variables["BOOST_CAPY_BUILD_TESTS"] = False
        tc.cache_variables["BOOST_CAPY_BUILD_EXAMPLES"] = False
        tc.cache_variables["BOOST_CAPY_BUILD_BENCH"] = False
        tc.cache_variables["CMAKE_CXX_SCAN_FOR_MODULES"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE_1_0.txt", self.source_folder, os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "boost_capy")
        self.cpp_info.set_property("cmake_target_name", "Boost::capy")
        self.cpp_info.libs = ["boost_capy"]
        self.cpp_info.defines = [
            "BOOST_CAPY_NO_LIB",
            "BOOST_CAPY_DYN_LINK" if self.options.shared else "BOOST_CAPY_STATIC_LINK",
        ]
        if self.settings.os in ["Linux", "FreeBSD"]:
            self.cpp_info.system_libs = ["pthread"]
