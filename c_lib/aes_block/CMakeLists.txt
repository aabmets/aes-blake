file(GLOB_RECURSE CLEAN_SOURCES CONFIGURE_DEPENDS *.c)

add_library(aes_block_lib
    ${CLEAN_SOURCES}
)

target_include_directories(aes_block_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)