file(GLOB_RECURSE AES_BLAKE_SOURCES CONFIGURE_DEPENDS *.c)

add_library(aes_blake_lib
    ${AES_BLAKE_SOURCES}
)

target_include_directories(aes_blake_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../tools
)