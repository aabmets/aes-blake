cmake_minimum_required(VERSION 3.31)
project(aes_blake_tests CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CATCH_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.8.1
)
FetchContent_MakeAvailable(Catch2)

file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS *.cpp)

add_executable(tests
    test_main.cpp
    ${TEST_SOURCES}
)
target_link_libraries(tests PRIVATE
    Catch2::Catch2WithMain
    aes_block_lib
    blake_keygen_lib
    utils_lib
)

if (WIN32)
    target_link_libraries(tests PRIVATE bcrypt)
endif()

include(CTest)
include(Catch)
catch_discover_tests(tests)
