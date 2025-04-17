file(GLOB_RECURSE SHARED_SOURCES CONFIGURE_DEPENDS *.c)

add_library(shared_lib
    ${SHARED_SOURCES}
)

target_include_directories(shared_lib
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)