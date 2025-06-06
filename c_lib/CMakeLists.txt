cmake_minimum_required(VERSION 3.31)
project(aes_blake C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(aes_block)
add_subdirectory(shared)
add_subdirectory(tests)