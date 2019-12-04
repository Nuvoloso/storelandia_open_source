configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pm_api_cmds.sh ${CMAKE_CURRENT_BINARY_DIR}/pm_api_cmds.sh COPYONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/valgrind_supp.xml ${CMAKE_CURRENT_BINARY_DIR}/valgrind_supp.xml COPYONLY)
