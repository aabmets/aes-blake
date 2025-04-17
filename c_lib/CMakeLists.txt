cmake_minimum_required(VERSION 3.31)
project(aes_blake C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(avx2)
add_subdirectory(clean)
add_subdirectory(hardened)
add_subdirectory(shared)
add_subdirectory(tests)