file(GLOB_RECURSE SHARED_SOURCES CONFIGURE_DEPENDS *.c)

add_library(blake_keygen_lib
    ${SHARED_SOURCES}
)

target_include_directories(blake_keygen_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../aes_block
)