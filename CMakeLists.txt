cmake_minimum_required(VERSION 2.6.4)

project( storelandia )

find_program(MEMORYCHECK_COMMAND NAMES valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--error-exitcode=1 --num-callers=20 --trace-children=yes --leak-check=full --track-origins=yes --gen-suppressions=all --suppressions=${CMAKE_SOURCE_DIR}/valgrind_supp.xml")

include(CTest)
enable_testing()

add_subdirectory( libs )
add_subdirectory( nuvo )
add_subdirectory( util )

CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/CTestCustom.cmake"
                "${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake")
