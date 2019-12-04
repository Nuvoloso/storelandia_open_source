
cmake_minimum_required(VERSION 2.6.4)

project( nuvo C CXX)

# set directory to teach cmake about protobuf-c
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/../cmake/)

find_package(ProtobufC REQUIRED)
find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
find_package(Check REQUIRED)

SET (COVERAGE_BUILD $ENV{COVERAGE})
IF(COVERAGE_BUILD)
MESSAGE(COVERAGE_BUILD)
include(CodeCoverage)
APPEND_COVERAGE_COMPILER_FLAGS()
ENDIF(COVERAGE_BUILD)

enable_testing()

set (NUVO_COMMON_FLAGS "-g -pthread -Wall -Wextra -Werror -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64")
set (NUVO_C_FLAGS "${NUVO_COMMON_FLAGS} -std=c11")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NUVO_C_FLAGS}")
set (CMAKE_SHARED_LINKER_FLAGS "-pthread")
set (GENERATED_PROTOBUF_C_DIR "${CMAKE_CURRENT_BINARY_DIR}/..")
include_directories(
    "../"
    "/usr/local/include/fuse3"
    "../../libs"
    ${PROTOBUFC_INCLUDE_DIRS}
    ${GENERATED_PROTOBUF_C_DIR}
    ${CHECK_INCLUDE_DIRS})

# Build the tests that can pass valgrind
add_executable(unit_test_nuvo
    unit_test_nuvo_api.c
    unit_test_nuvo_fuse.c
    unit_test_nuvo_list.c
    unit_test_log_level.c
    unit_test_nuvo_stats.c
    unit_test_nuvo_status.c
    unit_test_segment.c
    unit_test_valgrind_error.c
    check_unit_tests.c)
add_dependencies(unit_test_nuvo nuvo_lib)
target_link_libraries(unit_test_nuvo
    nuvo_lib
    protobuf-c
    uuid
    ${CHECK_LIBRARIES})

# Build the tests that cannot pass valgrind, because they e.g. purposely
# exit uncleanly.
add_executable(unit_test_nuvo_no_valgrind
    unit_test_nuvo_error.c
    check_unit_tests_no_valgrind.c)
add_dependencies(unit_test_nuvo_no_valgrind nuvo_lib)
target_link_libraries(unit_test_nuvo_no_valgrind
    nuvo_lib
    protobuf-c
    uuid
    ${CHECK_LIBRARIES})

add_executable(unit_test_space
    check_space_tests.c
    unit_test_space.c
    nuvo_ck_assert.c
    fake_pr.c
    fake_mfl.c
    ../fault_inject.c
    ../lun.c
    ../lun_state.c
    ../nuvo_list.c
    ../nuvo_lock.c
    ../nuvo_pr_sync.c
    ../nuvo_pr_parallel.c
    ../nuvo_range_lock.c
    ../nuvo_stats.c
    ../nuvo.c
    ../manifest.c
    ../parallel.c
    ../segment.c
    ../space.c
    ../superblock.c
    ../version_nuvo.c
    ${NUVO_PROTO_SRC})
add_dependencies(unit_test_space nuvo_lib)
target_link_libraries(unit_test_space
    uuid
    unwind
    nuvo_xxhash
    atomic
    aio
    ${CHECK_LIBRARIES})

add_executable(unit_test_gc
    check_gc_tests.c
    unit_test_gc.c
    nuvo_ck_assert.c
    fake_pr.c
    fake_mfl.c
    ../fault_inject.c
    ../gc.c
    ../io_concatenator.c
    ../logger.c
    ../log_vol_lun.c
    ../log_volume_iops.c
    ../lun.c
    ../lun_state.c
    ../nuvo_list.c
    ../nuvo_lock.c
    ../nuvo_pr_sync.c
    ../nuvo_pr_parallel.c
    ../nuvo_range_lock.c
    ../nuvo_stats.c
    ../nuvo.c
    ../manifest.c
    ../parallel.c
    ../replay.c
    ../segment.c
    ../space.c
    ../superblock.c
    ../version_nuvo.c
    ${NUVO_PROTO_SRC})
add_dependencies(unit_test_gc nuvo_lib)
target_link_libraries(unit_test_gc
    uuid
    unwind
    nuvo_xxhash
    atomic
    aio
    ${CHECK_LIBRARIES})

add_executable(unit_test_nuvo_map
    check_map_tests.c
    unit_test_nuvo_map.c
    nuvo_ck_assert.c
    map_ut.c
    fake_space.c
    ../lun_state.c
    ../map.c
    ../parallel.c
    ../map_diff.c
    ../map_replay.c
    ../map_mfl.c
    ../nuvo_list.c
    ../nuvo_lock.c
    ../nuvo_range_lock.c
    ../nuvo.c
    ../fault_inject.c
    ${NUVO_PROTO_SRC})
add_dependencies(unit_test_nuvo_map nuvo_lib)
target_link_libraries(unit_test_nuvo_map
    uuid
    unwind
    nuvo_xxhash
    atomic
    ${CHECK_LIBRARIES})

add_executable(unit_test_nuvo_map_replay
    check_map_replay_tests.c
    unit_test_map_replay.c
    nuvo_ck_assert.c
    fake_pr.c
    ../fault_inject.c
    ../io_concatenator.c
    ../logger.c
    ../log_volume_iops.c
    ../log_vol_lun.c
    ../lun.c
    ../lun_state.c
    ../manifest.c
    ../map.c
    ../map_replay.c
    ../parallel.c
    ../map_mfl.c
    ../map_diff.c
    ../nuvo_list.c
    ../nuvo_lock.c
    ../nuvo_range_lock.c
    ../nuvo_pr_sync.c
    ../nuvo_pr_parallel.c
    ../nuvo.c
    ../replay.c
    ../nuvo_stats.c
    ../segment.c
    ../space.c
    ../superblock.c
    ../version_nuvo.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_nuvo_map_replay nuvo_lib)
target_link_libraries(unit_test_nuvo_map_replay
    uuid
    unwind
    nuvo_xxhash
    atomic
    ${CHECK_LIBRARIES})

add_executable(unit_test_mfst
    check_mfst_tests.c
    unit_test_mfst.c
    nuvo_ck_assert.c
    fake_pr.c
    ../lun_state.c
    ../nuvo.c
    ../nuvo_list.c
    ../nuvo_lock.c
    ../nuvo_pr_sync.c
    ../nuvo_pr_parallel.c
    ../manifest.c
    ../segment.c
    ../superblock.c
    ../signal_handler.c
    ../version_nuvo.c
    ../fault_inject.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_mfst nuvo_lib)
target_link_libraries(unit_test_mfst
    uuid
    unwind
    nuvo_xxhash
    ${CHECK_LIBRARIES})

add_executable(unit_test_nuvo_pr
    check_pr_tests.c
    unit_test_nuvo_pr.c
    ../fault_inject.c
    ../nuvo_pr.c
    ../nuvo_pr_sync.c
    ../nuvo_list.c
    ../nuvo_stats.c
    ../nuvo_lock.c
    ../nuvo.c
    ../signal_handler.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_nuvo_pr nuvo_lib)
target_link_libraries(unit_test_nuvo_pr
    uuid
    unwind
    nuvo_xxhash
    atomic
    ${CHECK_LIBRARIES})

add_executable(unit_test_parcel_manager
    check_parcel_manager_tests.c
    unit_test_parcel_manager.c
    ../parcel_manager.c
    ../nuvo_list.c
    ../nuvo_stats.c
    ../nuvo_lock.c
    ../nuvo.c
    ../signal_handler.c
    ../status.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_parcel_manager nuvo_lib)
target_link_libraries(unit_test_parcel_manager
    uuid
    unwind
    nuvo_xxhash
    atomic
    aio
    ${CHECK_LIBRARIES})

add_executable(unit_test_logger
    check_logger_tests.c
    unit_test_logger.c
    ../fault_inject.c
    ../io_concatenator.c
    ../logger.c
    ../replay.c
    ../parcel_manager.c
    ../nuvo_pr.c
    ../nuvo_pr_sync.c
    ../nuvo_list.c
    ../nuvo_stats.c
    ../nuvo_lock.c
    ../nuvo.c
    ../cache.c
    ../parallel.c
    ../resilience.c
    ../signal_handler.c
    ../status.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_logger nuvo_lib)
target_link_libraries(unit_test_logger
    uuid
    unwind
    nuvo_xxhash
    atomic
    aio
    ${CHECK_LIBRARIES})

add_executable(unit_test_cache
    check_cache_tests.c
    unit_test_cache.c
    ../cache.c
    ../fault_inject.c
    ../parallel.c
    ../parcel_manager.c
    ../nuvo_pr.c
    ../nuvo_pr_sync.c
    ../nuvo_list.c
    ../nuvo_stats.c
    ../nuvo_lock.c
    ../nuvo.c
    ../signal_handler.c
    ../status.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_cache nuvo_lib)
target_link_libraries(unit_test_cache
    uuid
    unwind
    nuvo_xxhash
    atomic
    aio
    ${CHECK_LIBRARIES})

add_executable(unit_test_io_concatenator
    check_io_concatenator_tests.c
    unit_test_io_concatenator.c
    nuvo_ck_assert.c
    fake_pr.c
    ../io_concatenator.c
    ../nuvo.c
    ../nuvo_list.c
    ../nuvo_lock.c
    ../nuvo_pr_sync.c
    ${NUVO_PROTO_SRC}
    )
add_dependencies(unit_test_io_concatenator nuvo_lib)
target_link_libraries(unit_test_io_concatenator
    uuid
    unwind
    nuvo_xxhash
    ${CHECK_LIBRARIES})


# Move all of the unit test adds to the bottom to make easier to comment out
# tests when focussing on one or a few.
add_test(nuvo_unit_test_io_concatenator unit_test_io_concatenator)
add_test(nuvo_unit_tests_gc unit_test_gc)
add_test(nuvo_unit_tests_space unit_test_space)
add_test(nuvo_unit_tests unit_test_nuvo)
add_test(nuvo_unit_tests_no_valgrind unit_test_nuvo_no_valgrind)
add_test(nuvo_unit_tests_map unit_test_nuvo_map)
add_test(nuvo_unit_tests_map_replay unit_test_nuvo_map_replay)
add_test(nuvo_unit_tests_mfst unit_test_mfst)
add_test(nuvo_unit_tests_pr unit_test_nuvo_pr)
add_test(nuvo_unit_tests_parcel_manager unit_test_parcel_manager)
add_test(nuvo_unit_tests_logger unit_test_logger)
add_test(nuvo_unit_tests_map_replay unit_test_nuvo_map_replay)
add_test(nuvo_unit_tests_cache unit_test_cache)
