cmake_minimum_required(VERSION 3.12)

project(sr25519crust NONE)


add_custom_target(
  sr25519
  ALL
  COMMAND cbindgen -o ${CMAKE_BINARY_DIR}/sr25519.h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
