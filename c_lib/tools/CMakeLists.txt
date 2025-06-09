file(GLOB_RECURSE TOOLS_SOURCES CONFIGURE_DEPENDS *.c)

add_library(tools_lib
    ${TOOLS_SOURCES}
)

target_include_directories(tools_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)