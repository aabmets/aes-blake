file(GLOB_RECURSE AES_BLOCK_SOURCES CONFIGURE_DEPENDS *.c)

add_library(aes_block_lib
    ${AES_BLOCK_SOURCES}
)

target_include_directories(aes_block_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)