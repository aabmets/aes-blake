file(GLOB_RECURSE CLEAN_SOURCES CONFIGURE_DEPENDS *.c)

add_library(clean_lib
    ${CLEAN_SOURCES}
)

target_include_directories(clean_lib
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)