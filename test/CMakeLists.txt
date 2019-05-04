cmake_minimum_required(VERSION 3.12)

project(Test)

add_executable(Test main.c)
target_link_libraries(Test ${CMAKE_SOURCE_DIR}/../target/debug/libsr25519crust.so)
