cmake_minimum_required(VERSION 3.12)

project(sr25519crust NONE)


if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(has_release "--release")
  message(STATUS "CMAKE_BUILD_TYPE=Release, adding ${has_release}")
endif()


set(a_path ${CMAKE_BINARY_DIR}/libsr25519crust.a)
set(dylib_path ${CMAKE_BINARY_DIR}/libsr25519crust.dylib)
set(include_path ${CMAKE_BINARY_DIR}/sr25519)


include(GNUInstallDirs)


### setup tasks
add_custom_target(
  cargo_build
  ALL
  # out dir copies build artifacts to binary dir
  # -Z unstable-options enables --out-dir
  COMMAND cargo build --out-dir ${CMAKE_BINARY_DIR} -Z unstable-options ${has_release}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(
  sr25519
  ALL
  COMMAND cbindgen -o ${include_path}/sr25519.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

enable_testing()
add_test(
  NAME cargo_test
  COMMAND cargo test
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)



### setup install task
function(ifd_install what where)
  if(EXISTS ${what})
    message(STATUS "make install: '${what}' will be installed to '${where}'")
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
  else()
    message(STATUS "make install: '${what}' will not be installed")
  endif()
endfunction()


ifd_install(${include_path} ${CMAKE_INSTALL_INCLUDEDIR})
ifd_install(${a_path} ${CMAKE_INSTALL_LIBDIR})
ifd_install(${dylib_path} ${CMAKE_INSTALL_LIBDIR})
