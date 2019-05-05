cmake_minimum_required(VERSION 3.12)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

include("cmake/3rdparty/Hunter/init.cmake")
HunterGate(
    URL "https://github.com/ruslo/hunter/archive/v0.23.165.tar.gz"
    SHA1 "5a73f91df5f6109c0bb1104d0c0ee423f7bece79"
)

project(sr25519crust CXX)

include(cmake/dependencies.cmake)
include(cmake/functions.cmake)


if(NOT EXISTS "${CMAKE_TOOLCHAIN_FILE}")
  # https://cgold.readthedocs.io/en/latest/tutorials/toolchain/globals/cxx-standard.html#summary
  set(CMAKE_CXX_STANDARD 17)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif()


if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(path_prefix    "${CMAKE_BINARY_DIR}/release")
  set(release_option "--release")
  message(STATUS "CMAKE_BUILD_TYPE=Release, adding ${release_option}")
else()
  set(path_prefix    "${CMAKE_BINARY_DIR}/debug")
endif()


set(a_path ${path_prefix}/libsr25519crust.a)
set(include_path ${CMAKE_BINARY_DIR}/include)
set(sr25519_h_dir ${include_path}/sr25519)


### setup install task
include(GNUInstallDirs)
function(ifd_install what where)
  message(STATUS "[make install]: '${what}' will be installed to '${where}'")
  if (IS_DIRECTORY ${what})
    install(
        DIRECTORY ${what}
        DESTINATION ${where}
    )
  else()
    install(
        FILES ${what}
        DESTINATION ${where}
    )
  endif()
endfunction()


ifd_install(${include_path} ${CMAKE_INSTALL_INCLUDEDIR})
ifd_install(${a_path}       ${CMAKE_INSTALL_LIBDIR})


### setup tasks
add_custom_target(
  cargo_build
  ALL
  COMMAND cargo build --target-dir ${CMAKE_BINARY_DIR} ${release_option}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(
  bindings
  ALL
  COMMAND cbindgen -o ${sr25519_h_dir}/sr25519.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)


### create imported target for tests
add_library(sr25519 UNKNOWN IMPORTED)
set_target_properties(sr25519 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${include_path}
    IMPORTED_LOCATION             ${a_path}
    )
add_dependencies(sr25519 bindings cargo_build)
file(MAKE_DIRECTORY ${sr25519_h_dir})

enable_testing()
add_subdirectory(test)
add_test(
  NAME cargo_test
  COMMAND cargo test
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
