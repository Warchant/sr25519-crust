must_have_exe(rustc)
must_have_exe(cargo)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
  set(path_prefix "${CMAKE_BINARY_DIR}/release")
  set(release_option "--release")
  message(STATUS "CMAKE_BUILD_TYPE=Release, adding ${release_option}")
else ()
  set(path_prefix "${CMAKE_BINARY_DIR}/debug")
endif ()


if (BUILD_SHARED_LIBS)
  set(lib ${path_prefix}/${CMAKE_SHARED_LIBRARY_PREFIX}_25519crust${CMAKE_SHARED_LIBRARY_SUFFIX})
else ()
  set(lib ${path_prefix}/${CMAKE_STATIC_LIBRARY_PREFIX}_25519crust${CMAKE_STATIC_LIBRARY_SUFFIX})
endif ()
message(STATUS "[_25519] library: ${lib}")


set(include_path ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(_25519_h_dir ${include_path}/_25519)

### setup install task
include(GNUInstallDirs)
function(ifd_install what where)
  message(STATUS "[_25519] '${what}' will be installed to '${where}'")
  if (IS_DIRECTORY ${what})
    install(
        DIRECTORY ${what}
        DESTINATION ${where}
    )
  else ()
    install(
        FILES ${what}
        DESTINATION ${where}
    )
  endif ()
endfunction()


ifd_install(${_25519_h_dir} ${CMAKE_INSTALL_INCLUDEDIR})
ifd_install(${lib} ${CMAKE_INSTALL_LIBDIR})
ifd_install(${CMAKE_SOURCE_DIR}/_25519Config.cmake ${CMAKE_INSTALL_LIBDIR}/cmake/_25519)
ifd_install(${CMAKE_SOURCE_DIR}/_25519Config-noconfig.cmake ${CMAKE_INSTALL_LIBDIR}/cmake/_25519)


### setup tasks
add_custom_target(
    cargo_build
    ALL
    COMMAND cargo build --target-dir ${CMAKE_BINARY_DIR} ${release_option}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_library(_25519 STATIC IMPORTED GLOBAL)

# if we build static lib
if (NOT BUILD_SHARED_LIBS)
  if (APPLE)
    # on apple we need to link Security
    find_library(Security Security)
    find_package_handle_standard_args(_25519
        REQUIRED_VARS Security
        )
    set_target_properties(_25519 PROPERTIES
        INTERFACE_LINK_LIBRARIES ${Security}
        )
  elseif (UNIX)
    # on Linux we need to link pthread
    target_link_libraries(_25519 INTERFACE
        pthread
        -Wl,--no-as-needed
        dl
        )
  else ()
    message(WARNING "You're building static lib, it may not link. Come here and fix.")
  endif ()
endif ()

set_target_properties(_25519 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${include_path}
    IMPORTED_LOCATION ${lib}
    )
add_dependencies(_25519 cargo_build)

file(MAKE_DIRECTORY ${_25519_h_dir})


### add tests
add_test(
    NAME cargo_test
    COMMAND cargo test
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
