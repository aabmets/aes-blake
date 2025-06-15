file(GLOB_RECURSE MASKING_SOURCES CONFIGURE_DEPENDS *.c)

add_library(masking_lib
    ${MASKING_SOURCES}
)

target_include_directories(masking_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../tools
)