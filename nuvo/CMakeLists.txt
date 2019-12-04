cmake_minimum_required(VERSION 2.6.4)

project( nuvo C)

add_subdirectory( tests )
add_subdirectory( func_tests)

# set directory to teach cmake about protobuf-c
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake/)

find_package(ProtobufC REQUIRED)
find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(Check REQUIRED)

# set the path to the library folder
link_directories(/usr/local/lib)
find_package(Gperftools REQUIRED)

enable_testing()

SET (COVERAGE_BUILD $ENV{COVERAGE})
IF(COVERAGE_BUILD)
MESSAGE(COVERAGE_BUILD)
include(CodeCoverage)
APPEND_COVERAGE_COMPILER_FLAGS()
ENDIF(COVERAGE_BUILD)

set (NUVO_COMMON_FLAGS "-g -pthread -Wall -Wextra -Werror -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
set (NUVO_C_FLAGS "${NUVO_COMMON_FLAGS} -std=c11")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NUVO_C_FLAGS}")
set (CMAKE_SHARED_LINKER_FLAGS "-pthread")

include_directories(
    "../libs"
    "/usr/local/include/fuse3"
    ${PROTOBUFC_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR} )

# Copy the .proto file to the build dir.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/nuvo.proto ${CMAKE_CURRENT_BINARY_DIR}/nuvo.proto COPYONLY)

# START - VERSION_STRING section
# This is for adding git hash and build info into the nuvo binary

# Get the current working branch
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_NUVO_BRANCH_NAME
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the git build date
execute_process(
  COMMAND git log -1 --pretty=%ad
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_NUVO_COMMIT_DATE
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the git commit hash
execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_NUVO_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the local timestamp at time of build
execute_process(
  COMMAND date
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE NUVO_MAKE_TIMESTAMP
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_definitions("-DGIT_NUVO_BRANCH_NAME=${GIT_NUVO_BRANCH_NAME}")
add_definitions("-DGIT_NUVO_COMMIT_DATE=${GIT_NUVO_COMMIT_DATE}")
add_definitions("-DGIT_NUVO_COMMIT_HASH=${GIT_NUVO_COMMIT_HASH}")
add_definitions("-DNUVO_MAKE_TIMESTAMP=${NUVO_MAKE_TIMESTAMP}")

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/version_nuvo.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/version_nuvo.h
)
# END - VERSION_STRING section

# Generate the c proto
protoc(NUVO_PROTO_SRC nuvo.proto)

# Generate the python proto
protobuf_generate_python(PROTO_PY nuvo.proto)
add_custom_target(python_proto ALL DEPENDS ${PROTO_PY})

# c library for all the code called from main and tests.
add_library(nuvo_lib
    fault_inject.c
    gc.c
    io_concatenator.c
    log_volume.c
    log_volume_iops.c
    log_volume_diff.c
    log_vol_lun.c
    nuvo_fuse.c
    nuvo_list.c
    nuvo_range_lock.c
    nuvo_stats.c
    nuvo_api.c
    nuvo_vol_series.c
    nuvo_lock.c
    nuvo.c
    parcel_manager.c
    logger.c
    logger_debug.c
    lun.c
    lun_state.c
    nuvo_pr.c
    nuvo_pr_parallel.c
    nuvo_pr_sync.c
    nuvo_sig_handler.c
    manifest.c
    manifest_api.c
    map.c
    map_mfl.c
    map_diff.c
    map_replay.c
    parcel_vol.c
    parallel.c
    passthrough_vol.c
    segment.c
    signal_handler.c
    space.c
    space_debug.c
    status.c
    superblock.c
    replay.c
    resilience.c
    cache.c
    version_nuvo.c
    ${NUVO_PROTO_SRC} )
target_link_libraries(nuvo_lib
    fuse3
    nuvo_xxhash
    protobuf-c
    uuid
    unwind
    aio
    m )

# Build the executable
add_Executable(nuvo main.c)
target_link_libraries(nuvo nuvo_lib)

# Build the executable
add_Executable(nuvo_gperftools main.c version_nuvo.c)
target_link_libraries(nuvo_gperftools nuvo_lib tcmalloc_and_profiler)

# Doxygenation
find_package(Doxygen)

# set input and output files
set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

# request to configure the file
configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
message("Doxygen build started")

# add ALL after target name to always build.
add_custom_target( doxygen
    COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM )
