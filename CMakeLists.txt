cmake_minimum_required(VERSION 3.12)

project(sr25519crust NONE)

add_custom_target(
  build_rust
  ALL
  # out dir copies build artifacts to binary dir
  # -Z unstable-options enables --out-dir
  COMMAND cargo build --out-dir ${CMAKE_BINARY_DIR} -Z unstable-options
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(
  sr25519
  ALL
  COMMAND cbindgen -o ${CMAKE_BINARY_DIR}/sr25519.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
