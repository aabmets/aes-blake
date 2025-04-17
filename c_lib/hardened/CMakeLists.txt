file(GLOB_RECURSE HARDENED_SOURCES CONFIGURE_DEPENDS *.c)

add_library(hardened_lib
    ${HARDENED_SOURCES}
)

target_include_directories(hardened_lib
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)