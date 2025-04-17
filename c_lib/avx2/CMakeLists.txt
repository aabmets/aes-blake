#file(GLOB_RECURSE AVX2_SOURCES CONFIGURE_DEPENDS *.c)
#
#add_library(avx2_lib
#    ${AVX2_SOURCES}
#)
#
#target_include_directories(avx2_lib
#    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
#)