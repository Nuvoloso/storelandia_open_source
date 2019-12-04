project( nuvo_func_tests C)

add_subdirectory( check_proto )
add_subdirectory( passthrough )
add_subdirectory( pm_api_cmds )
add_subdirectory( parcel_vol )
add_subdirectory( log_vol )

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/run_func_tests.sh ${CMAKE_CURRENT_BINARY_DIR}/run_func_tests.sh COPYONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/run_extended_func_tests.sh ${CMAKE_CURRENT_BINARY_DIR}/run_extended_func_tests.sh COPYONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/func_tests_common.sh ${CMAKE_CURRENT_BINARY_DIR}/func_tests_common.sh COPYONLY)
