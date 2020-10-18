cmake_minimum_required(VERSION 3.12)

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif (CCACHE_FOUND)

option(TESTING "Enable tests" OFF)

if (TESTING)
  include("cmake/3rdparty/Hunter/init.cmake")
  HunterGate(
      URL "https://github.com/soramitsu/soramitsu-hunter/archive/v0.23.257-soramitsu1.tar.gz"
      SHA1 "130ab680eefe8d85e30ade39fd273c9dd36717f5"
  )
endif ()

project(schnorrkel-crust CXX)

include(FindPackageHandleStandardArgs)
include(cmake/functions.cmake)

include(cmake/rust.cmake)

if (NOT EXISTS "${CMAKE_TOOLCHAIN_FILE}")
  # https://cgold.readthedocs.io/en/latest/tutorials/toolchain/globals/cxx-standard.html#summary
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif ()


if (TESTING)
  enable_testing()
  add_subdirectory(test)
endif ()
