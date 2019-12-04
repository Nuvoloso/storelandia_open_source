/* Copyright 2019 Tad Lebeck
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file fault_inject.h
 * @brief Routines for fault injection.
 */


#pragma once

#include <uuid/uuid.h>
#include <stdbool.h>
#include "status.h"


/*
 * Steps to add fault injection to your module
 *
 * Add the new error(s) for your trigger:
 * fault_inject.h:
 * Add a new error type(s) to the test_fi_err_type enum below
 *
 * Add your module to the debug trigger via a new string:
 * nuvo_api.c:
 * Insert check for your module name in nuvo_api_debug_trigger()
 * - Ex: see “pr_error” in this function
 * You also need to add your function for allocating the trigger, see next step
 *
 * Allocate/store struct for trigger:
 * <your_file.c>:
 * Include the fault injection header file
 * - #include "fault_inject.h"
 * Figure out where you want to allocate/store the test_fi_info struct
 * - Ex: Create a function similar to nuvo_pr_get_test_fi()
 * - call this function from nuvo_api_debug_trigger()
 *
 * Add fault injection to your module:
 * <your_file.c>:
 * test_fi_inject_rc()
 * Ex: look at nuvo_pr_submit(), find the first test_fi_inject_rc()
 * - If you also want to compare the volume uuid, use test_fi_inject_vol_rc()
 *
 * Create a functional test which uses the trigger
 * <your functional test>:
 * - Ex: see pr_errors functional test
 * Here is an example below of setting the trigger:
 *   This lets the first 50 I/0's go through and return errors for the next 10
 *   FI_ERR_TYPE=2
 *   fake_cluster_debug_trigger 1 debug-trigger --trigger "pr_error"
 *       --node ${NODE_UUID_LOCAL} --error-type ${FI_ERR_TYPE}
 *       --return-code -10 --repeat-cnt 10 --skip-cnt 50
 *
 */

/** An enum for Fault Injection which determines where to inject an error.
 *
 * Each new module should leave extra space for the previous module so
 * module errors can be grouped together.  So jump to the next 100 boundary
 * when numbering.
 *
 */
enum test_fi_err_type
{
    TEST_FI_PR_ERR_MIN                           = 1,
    TEST_FI_PR_PDEF_GET                          = 2,
    TEST_FI_PR_CLIENT_SEND_HEADER                = 3,
    TEST_FI_PR_CLIENT_SEND_DATA                  = 4,
    TEST_FI_PR_CLIENT_RECV_HEADER                = 5,
    TEST_FI_PR_CLIENT_RECV_DATA                  = 6,
    TEST_FI_PR_SERVER_SEND_HEADER                = 7,
    TEST_FI_PR_SERVER_SEND_DATA                  = 8,
    TEST_FI_PR_SERVER_RECV_HEADER                = 9,
    TEST_FI_PR_SERVER_RECV_DATA                  = 10,
    TEST_FI_PR_SERVER_SEND_ALLOC                 = 11,
    TEST_FI_PR_SERVER_SEND_OPEN                  = 12,
    TEST_FI_PR_SERVER_SEND_CLOSE                 = 13,
    TEST_FI_PR_SERVER_SEND_FREE                  = 14,
    TEST_FI_PR_SERVER_SEND_CLOSE_FREE            = 15,
    TEST_FI_PR_SERVER_SEND_ALL_CONFIG            = 16,
    TEST_FI_PR_ERR_MAX                           = 17,
    TEST_FI_GENERAL_USE_ERR_MIN                  = 100,
    TEST_FI_GENERAL_USE_FAIL_VOL_REPLAY          = 101,
    TEST_FI_GENERAL_VER_GIT_COMMIT_HASH_OVERRIDE = 102,
    TEST_FI_GENERAL_USE_ERR_MAX                  = 103,
    TEST_FI_MAP_ERR_MIN                          = 200,
    TEST_FI_MAP_MFL_ERR                          = 201,
    TEST_FI_MAP_ERR_MAX                          = 202,
    TEST_FI_VOL_MIN                              = 300,
    TEST_FI_VOL_DESTROY                          = 301,
    TEST_FI_VOL_MAX                              = 302,
    TEST_FI_NEXT_MODULE_ERR_MIN                  = 400,
    TEST_FI_NEXT_MODULE_ERR_MAX                  = 401,
};

/**
 * A struct for Fault Injection which tracks when/where to inject an error.
 *
 * The fields in this struct are not protected by a lock, because this is
 * test only code.  It is possible that skip/repeat counts may not be 100%
 * accurate because of this.
 */
struct test_fi_info {
    uuid_t                node_uuid;
    uuid_t                vol_uuid;
    uuid_t                dev_uuid;
    enum test_fi_err_type test_err_type;
    nuvo_return_t         test_err_rc;      // Desired error return code
    int32_t               test_repeat_cnt;  // Number of times to inject error
    bool                  infinite_repeat;  // Ignore repeat cnt, always return error
    int32_t               test_skip_cnt;    // Allow success n times before trigger
    uint64_t              multiuse1;        // Extra, use if needed for fault injection
    uint64_t              multiuse2;        // Extra, use if needed for fault injection
    uint64_t              multiuse3;        // Extra, use if needed for fault injection
    uint32_t              total_inject_cnt; // Counts if any errors were ever injected
};


/**
 * \brief TEST ONLY - Set error to be injected into module for testing purposes
 *
 * Currently only one error can be set at a time in each module.  This sets
 * which error to trigger, and when it will be triggered.
 *
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param err_type Which error we want to trigger (test_fi_err_type)
 * \param err_rc Error code to inject
 * \param err_repeat_cnt Number of times we inject the error
 * \param err_skip_cnt Number of attempts that succeed before error injection
 */
void test_fi_set_basic_error(struct test_fi_info *fi_info, uint32_t err_type,
                             int32_t err_rc, int32_t err_repeat_cnt,
                             int32_t err_skip_cnt);

/**
 * \brief TEST ONLY - Set optional uuid fields for fault injection
 *
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param node_uuid node_uuid to inject error on
 * \param vol_uuid vol_uuid to inject error on
 * \param dev_uuid dev_uuid to inject error on
 */
void test_fi_set_uuids(struct test_fi_info *fi_info, uuid_t node_uuid,
                       uuid_t vol_uuid, uuid_t dev_uuid);

/**
 * \brief TEST ONLY - Set optional multiuse fields for fault injection
 *
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param multiuse1 user defineable field for fault injection
 * \param multiuse2 user defineable field for fault injection
 * \param multiuse3 user defineable field for fault injection
 */
void test_fi_set_multiuse(struct test_fi_info *fi_info, uint64_t multiuse1,
                          uint64_t multiuse2, uint64_t multiuse3);

/**
 * \brief TEST ONLY - Can inject an error by modifying the return code
 *
 * \param err_type Which error we want to trigger (test_fi_err_type)
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param err_rc The potentially modified return code
 * \returns true if a new return code has been set, otherwise false
 */
bool test_fi_inject_rc(uint32_t err_type, struct test_fi_info *fi_info,
                       nuvo_return_t *err_rc);


/**
 * \brief TEST ONLY - Can inject an error by modifying the return code
 *
 * This is a wrapper around test_fi_inject_rc that accepts an additional
 * volume uuid for comparison.  If volume uuid is null, it will match
 * all volume uuids.
 *
 * \param err_type Which error we want to trigger (test_fi_err_type)
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param vol_uuid the volume uuid you want to injection an error on
 * \param err_rc The potentially modified return code
 * \returns true if a new return code has been set, otherwise false
 */
bool test_fi_inject_vol_rc(uint32_t err_type, struct test_fi_info *fi_info,
                           uuid_t vol_uuid, nuvo_return_t *err_rc);

/**
 * \brief TEST ONLY - Can inject an error by modifying the return code
 *
 * This is a wrapper around test_fi_inject_rc that accepts an additional
 * node uuid for comparison.  If node_uuid is null, it will match all
 * node uuids.
 *
 * \param err_type Which error we want to trigger (test_fi_err_type)
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param node_uuid the node uuid you want to injection an error on
 * \param err_rc The potentially modified return code
 * \returns true if a new return code has been set, otherwise false
 */
bool test_fi_inject_node_rc(uint32_t err_type, struct test_fi_info *fi_info,
                            uuid_t node_uuid, nuvo_return_t *err_rc);

/**
 * \brief TEST ONLY - Can inject an error by modifying the return code
 *
 * This is a wrapper around test_fi_inject_rc that accepts additional
 * multiuse fields for comparison.  All fields must match.
 *
 * \param err_type Which error we want to trigger (test_fi_err_type)
 * \param fi_info Struct that tracks the fault injection error info and state
 * \param muse1 A multiuse variable used for comparison
 * \param muse2 A multiuse variable used for comparison
 * \param muse3 A multiuse variable used for comparison
 * \param err_rc The potentially modified return code
 * \returns true if a new return code has been set, otherwise false
 */

bool test_fi_inject_multi_use(uint32_t err_type, struct test_fi_info *fi_info,
                              uint64_t muse1, uint64_t muse2, uint64_t muse3,
                              nuvo_return_t *err_rc);

/**
 * \brief TEST ONLY - If not already allocated, allocates mem for fi_info
 *
 * There is only one of these per node, so it can only be used by one
 * module per test.
 *
 * This is used to alloc and/or get the general use test info struct.
 * This can be used by modules which need to squirrel away a fault injection
 * error because the vol (or other structure) doesn't exist in mem.
 *
 * \returns pointer to test_fi_info in nuvo_pr
 */
struct test_fi_info *test_fi_general_use_fi_get(void);

/**
 * \brief TEST ONLY - Free memory allocated by fault injection
 */
void nuvo_test_fi_free(void);
