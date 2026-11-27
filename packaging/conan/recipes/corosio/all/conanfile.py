import os

from conan import ConanFile
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get, rmdir, save

required_conan_version = ">=2.28"

# CMAKE_PROJECT_INCLUDE: Corosio links Boost::capy without finding it, and
# its install rules look for a target named boost_capy.
_CAPY_IMPORTED = """\
find_package(boost_capy CONFIG REQUIRED)
if(NOT TARGET boost_capy)
    add_library(boost_capy ALIAS Boost::capy)
endif()
"""


class CorosioConan(ConanFile):
    name = "corosio"
    description = "Boost.Corosio: coroutine-first networking on Capy, with OpenSSL TLS streams."
    license = "BSL-1.0"
    homepage = "https://github.com/cppalliance/corosio"
    url = "https://github.com/conan-io/conan-center-index"
    topics = ("coroutines", "networking", "tls")
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

    def requirements(self):
        self.requires("capy/cci.20261119", transitive_headers=True, transitive_libs=True)
        self.requires("openssl/[>=3 <4]", transitive_headers=True, transitive_libs=True)

    def validate(self):
        check_min_cppstd(self, 20)

    def source(self):
        get(self, **self.conan_data["sources"][self.version], strip_root=True)

    def generate(self):
        capy_imported = os.path.join(self.generators_folder, "capy_imported.cmake")
        save(self, capy_imported, _CAPY_IMPORTED)
        tc = CMakeToolchain(self)
        tc.cache_variables["CMAKE_PROJECT_INCLUDE"] = capy_imported.replace("\\", "/")
        tc.cache_variables["BUILD_TESTING"] = False
        tc.cache_variables["BOOST_COROSIO_BUILD_TESTS"] = False
        tc.cache_variables["BOOST_COROSIO_BUILD_EXAMPLES"] = False
        tc.cache_variables["BOOST_COROSIO_BUILD_BENCH"] = False
        tc.cache_variables["CMAKE_DISABLE_FIND_PACKAGE_WolfSSL"] = True
        tc.cache_variables["CMAKE_DISABLE_FIND_PACKAGE_liburing"] = True
        tc.cache_variables["CMAKE_CXX_SCAN_FOR_MODULES"] = False
        tc.generate()
        CMakeDeps(self).generate()

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
        self.cpp_info.set_property("cmake_file_name", "boost_corosio")

        core = self.cpp_info.components["corosio"]
        core.set_property("cmake_target_name", "Boost::corosio")
        core.libs = ["boost_corosio"]
        core.requires = ["capy::capy"]
        core.defines = [
            "BOOST_COROSIO_NO_LIB",
            "BOOST_COROSIO_HAVE_LIBURING=0",
            "BOOST_COROSIO_DYN_LINK" if self.options.shared else "BOOST_COROSIO_STATIC_LINK",
        ]
        if self.settings.os in ["Linux", "FreeBSD"]:
            core.system_libs = ["pthread"]
        elif self.settings.os == "Windows":
            core.system_libs = ["ws2_32"]
            core.defines.append("_WIN32_WINNT=0x0A00")

        tls = self.cpp_info.components["corosio_openssl"]
        tls.set_property("cmake_target_name", "Boost::corosio_openssl")
        tls.libs = ["boost_corosio_openssl"]
        tls.requires = ["corosio", "openssl::ssl", "openssl::crypto"]
        tls.defines = ["BOOST_COROSIO_HAS_OPENSSL"]
        if self.settings.os == "Windows":
            tls.system_libs = ["ws2_32", "crypt32"]
