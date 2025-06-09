file(GLOB_RECURSE BLAKE_KEYGEN_SOURCES CONFIGURE_DEPENDS *.c)

add_library(blake_keygen_lib
    ${BLAKE_KEYGEN_SOURCES}
)

target_include_directories(blake_keygen_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../aes_block
)