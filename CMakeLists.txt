cmake_minimum_required(VERSION 3.12)

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif (CCACHE_FOUND)


option(TESTING  "Enable tests" ON)

if (TESTING)
  include("cmake/3rdparty/Hunter/init.cmake")
  HunterGate(
      URL "https://github.com/ruslo/hunter/archive/v0.23.165.tar.gz"
      SHA1 "5a73f91df5f6109c0bb1104d0c0ee423f7bece79"
  )
endif ()

project(sr25519crust CXX)
enable_testing()

include(FindPackageHandleStandardArgs)
include(cmake/functions.cmake)

include(rust.cmake)

if (NOT EXISTS "${CMAKE_TOOLCHAIN_FILE}")
  # https://cgold.readthedocs.io/en/latest/tutorials/toolchain/globals/cxx-standard.html#summary
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif ()


if (TESTING)
  add_subdirectory(test)
endif ()
