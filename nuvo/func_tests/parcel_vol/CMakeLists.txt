configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/parcel_vol_test ${CMAKE_CURRENT_BINARY_DIR}/parcel_vol_test COPYONLY)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/valgrind_supp.xml ${CMAKE_CURRENT_BINARY_DIR}/valgrind_supp.xml COPYONLY)
