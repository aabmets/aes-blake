cmake_minimum_required(VERSION 3.31)
project(aes_blake C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

#add_subdirectory(aes_blake)
add_subdirectory(aes_block)
add_subdirectory(blake_keygen)
add_subdirectory(masking)
add_subdirectory(tests)
add_subdirectory(tools)
