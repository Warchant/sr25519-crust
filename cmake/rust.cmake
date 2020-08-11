find_program(RUSTC rustc REQUIRED)
find_program(CARGO cargo REQUIRED)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
  set(path_prefix "${CMAKE_BINARY_DIR}/release")
  set(release_option "--release")
  message(STATUS "CMAKE_BUILD_TYPE=Release, adding ${release_option}")
else ()
  set(path_prefix "${CMAKE_BINARY_DIR}/debug")
endif ()


if (BUILD_SHARED_LIBS)
  set(lib ${path_prefix}/${CMAKE_SHARED_LIBRARY_PREFIX}sr25519crust${CMAKE_SHARED_LIBRARY_SUFFIX})
else ()
  set(lib ${path_prefix}/${CMAKE_STATIC_LIBRARY_PREFIX}sr25519crust${CMAKE_STATIC_LIBRARY_SUFFIX})
endif ()
message(STATUS "[sr25519] library: ${lib}")


set(include_path ${PROJECT_SOURCE_DIR}/include)
set(sr25519_h_dir ${include_path}/sr25519)


### setup tasks
add_custom_target(
    cargo_build
    ALL
    COMMAND cargo build --target-dir ${CMAKE_BINARY_DIR} ${release_option}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)

add_library(sr25519 STATIC IMPORTED GLOBAL)

# if we build static lib
if (NOT BUILD_SHARED_LIBS)
  if (APPLE)
    # on apple we need to link Security
    find_library(Security Security)
    find_package_handle_standard_args(sr25519
        REQUIRED_VARS Security
        )
    set_target_properties(sr25519 PROPERTIES
        INTERFACE_LINK_LIBRARIES ${Security}
        )
  elseif (UNIX)
    # on Linux we need to link pthread
    target_link_libraries(sr25519 INTERFACE
        pthread
        -Wl,--no-as-needed
        dl
        )
  else ()
    message(WARNING "You're building static lib, it may not link. Come here and fix.")
  endif ()
endif ()

set_target_properties(sr25519 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${include_path}
    IMPORTED_LOCATION ${lib}
    )
add_dependencies(sr25519 cargo_build)

file(MAKE_DIRECTORY ${sr25519_h_dir})


### add tests
add_test(
    NAME cargo_test
    COMMAND cargo test
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)

### setup install task
include(GNUInstallDirs)

install(
    DIRECTORY ${sr25519_h_dir}
    TYPE INCLUDE
)
install(
    FILES ${lib}
    TYPE LIB
)

install(
    FILES ${PROJECT_SOURCE_DIR}/cmake/sr25519Config.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sr25519
)
