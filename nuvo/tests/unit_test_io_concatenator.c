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

#include <check.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>

#include "../io_concatenator.h"
#include "../nuvo_pr_parallel.h"
#include "../nuvo_pr_sync.h"

#include "fake_pr.h"
#include "nuvo_ck_assert.h"


#define IO_TEST_PARCELS 3
#define IO_TEST_PARCEL_BLOCKS 10240
#define TEST_DATA_BLOCKS 1024
#define TEST_DATA_SIZE (TEST_DATA_BLOCKS * NUVO_BLOCK_SIZE)

struct {
    uuid_t vol_uuid;
    uuid_t device_uuid;
    struct {
        uuid_t parcel_uuid;
        uint_fast32_t pd;
    } parcel[IO_TEST_PARCELS];

    union __attribute__((aligned(NUVO_BLOCK_SIZE))) {
        uint8_t data[NUVO_BLOCK_SIZE];
        uint32_t data_bno;
    } test_data[TEST_DATA_BLOCKS];

    uint_fast16_t ios_outstanding;
    nuvo_mutex_t ios_outstanding_mutex;
    nuvo_mutex_t ios_wait_mutex;
} io_test_var;

// Testing structure to validate io's being sent from an io_concatenator test.

struct test_expected_io {
    uint_fast32_t               parcel_desc;
    uint_fast32_t               block_offset;
    uint_fast32_t               block_count;
    enum nuvo_cache_hint        cache_hint;
    enum nuvo_io_origin         io_origin;
 };

#define TEST_IO_SUBMIT_MAX 20
struct {
    struct test_expected_io expected_ios[TEST_IO_SUBMIT_MAX];

    uint_fast16_t next_expected_io;
    uint_fast16_t total_expected_ios;
} test_io_submit_tracking;

void test_io_submit_tracking_reset()
{
    memset(&test_io_submit_tracking, 0, sizeof(test_io_submit_tracking));
}

void test_io_submit_tracking_expect(uint_fast32_t            parcel_desc,
                                    uint_fast32_t            block_offset,
                                    uint_fast32_t            block_count,
                                    enum nuvo_cache_hint     cache_hint,
                                    enum nuvo_io_origin      io_origin)
{
    NUVO_ASSERT(test_io_submit_tracking.total_expected_ios < TEST_IO_SUBMIT_MAX);
    struct test_expected_io *next_io = &test_io_submit_tracking.expected_ios[test_io_submit_tracking.total_expected_ios];
    next_io->parcel_desc = parcel_desc;
    next_io->block_offset = block_offset;
    next_io->block_count = block_count;
    next_io->cache_hint = cache_hint;
    next_io->io_origin = io_origin;

    test_io_submit_tracking.total_expected_ios++;
}

void test_io_concat_submit(struct nuvo_dlist *submit_list)
{
    struct nuvo_io_request *req = nuvo_dlist_get_head_object(submit_list, struct nuvo_io_request, list_node);
    while (req != NULL) {
        NUVO_ASSERT(test_io_submit_tracking.next_expected_io < test_io_submit_tracking.total_expected_ios);
        struct test_expected_io *next_io = &test_io_submit_tracking.expected_ios[test_io_submit_tracking.next_expected_io];
        NUVO_ASSERT(next_io->parcel_desc == req->rw.parcel_desc);
        NUVO_ASSERT(next_io->block_offset == req->rw.block_offset);
        NUVO_ASSERT(next_io->block_count == req->rw.block_count);
        NUVO_ASSERT(next_io->cache_hint == req->rw.cache_hint);
        NUVO_ASSERT(next_io->io_origin == req->rw.io_origin);

        test_io_submit_tracking.next_expected_io++;
        req = nuvo_dlist_get_next_object(submit_list, req, struct nuvo_io_request, list_node);
    }
    nuvo_pr_submit(submit_list);
}

void test_io_concat_done()
{
    NUVO_ASSERT(test_io_submit_tracking.next_expected_io == test_io_submit_tracking.total_expected_ios);
}

void io_concat_tests_setup() {
    fake_pr_init();
    test_io_submit_tracking_reset();
    uuid_generate_random(io_test_var.vol_uuid);
    uuid_generate_random(io_test_var.device_uuid);
    nuvo_return_t rc;
    rc = nuvo_pm_device_format("blah", io_test_var.device_uuid, IO_TEST_PARCEL_BLOCKS * NUVO_BLOCK_SIZE);
    NUVO_ASSERT(rc == 0);
     rc = nuvo_pm_device_open("blah", io_test_var.device_uuid, NUVO_DEV_TYPE_SSD);
    NUVO_ASSERT(rc == 0);

    for (uint_fast16_t i = 0; i < IO_TEST_PARCELS; i++)
    {
        uuid_clear(io_test_var.parcel[i].parcel_uuid);
        rc = nuvo_pr_sync_parcel_alloc(io_test_var.parcel[i].parcel_uuid,
                                       io_test_var.device_uuid,
                                       io_test_var.vol_uuid);
        NUVO_ASSERT(rc == 0);
        rc = nuvo_pr_sync_parcel_open(&io_test_var.parcel[i].pd,
                                      io_test_var.parcel[i].parcel_uuid,
                                      io_test_var.device_uuid,
                                      io_test_var.vol_uuid);
        NUVO_ASSERT(rc == 0);
    }
    memset(io_test_var.test_data, 0, TEST_DATA_SIZE);
    for (unsigned j = 0; j < TEST_DATA_BLOCKS; j++)
    {
        io_test_var.test_data[j].data_bno = j;
    }
    io_test_var.ios_outstanding = 0;
    nuvo_mutex_init(&io_test_var.ios_outstanding_mutex);
    nuvo_mutex_init(&io_test_var.ios_wait_mutex);

    nuvo_io_concat_control.min_outstanding = 0;

    nuvo_io_concat_pool_init(20);
}

void io_concat_tests_teardown() {
    nuvo_io_concat_pool_destroy();
    nuvo_mutex_destroy(&io_test_var.ios_outstanding_mutex);
    nuvo_mutex_destroy(&io_test_var.ios_wait_mutex);
    fake_pr_teardown();
}

void io_concat_tests_pr_req_cb(struct nuvo_io_request *io_req)
{
    nuvo_mutex_lock(&io_test_var.ios_outstanding_mutex);
    io_test_var.ios_outstanding--;
    bool done = (io_test_var.ios_outstanding == 0);
    nuvo_mutex_unlock(&io_test_var.ios_outstanding_mutex);

    if (done)
    {
        nuvo_mutex_unlock(&io_test_var.ios_wait_mutex);
    }
    nuvo_pr_client_req_free(io_req);
}

void io_concat_tests_submit_list(struct nuvo_io_concatenator *io_concatenator, struct nuvo_dlist *req_list)
{
    struct nuvo_io_request *io_req;
    while (NULL != (io_req = nuvo_dlist_remove_head_object(req_list, struct nuvo_io_request, list_node)))
    {
        nuvo_mutex_lock(&io_test_var.ios_outstanding_mutex);
        io_test_var.ios_outstanding++;
        nuvo_mutex_unlock(&io_test_var.ios_outstanding_mutex);
        io_req->callback = io_concat_tests_pr_req_cb;
        io_req->tag.ptr = io_concatenator;

        nuvo_io_concat_submit_req(io_concatenator, io_req);
    }
}

START_TEST(io_concat_init)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, nuvo_pr_submit);
    ck_assert(rc == 0);
    nuvo_io_concat_destroy(&io_concatenator);
}
END_TEST

START_TEST(io_concat_op_alloc_free)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, nuvo_pr_submit);
    ck_assert(rc == 0);

    struct nuvo_io_concat_op* op = nuvo_io_concat_op_alloc(&io_concatenator, NULL);
    ck_assert(op->req != NULL);
    ck_assert(op->outstanding_reqs == 1);
    ck_assert(op->io_concatenator == &io_concatenator);

    // Pretend done
    op->outstanding_reqs = 0;
    nuvo_pr_client_req_free(op->req);
    op->req = NULL;

    nuvo_io_concat_op_free(op);

    nuvo_io_concat_destroy(&io_concatenator);
}
END_TEST

// TODO - check that passthrough when alloc will fail works.

// Build consecutive writes approximately equal sized, append to list
void io_concat_test_build_write_list(struct nuvo_dlist    *list,
                                     uint_fast32_t          pd,
                                     uint_fast32_t          block_offset,
                                     uint_fast16_t          num_blocks,
                                     uint_fast16_t          num_ios,
                                     enum nuvo_cache_hint   cache_hint,
                                     enum nuvo_io_origin    io_origin,
                                     uint8_t               *data)
{
    while (num_ios > 0)
    {
        struct nuvo_io_request *req = nuvo_pr_client_req_alloc();
        req->operation = NUVO_OP_WRITE;
        req->rw.parcel_desc = pd;
        req->rw.block_offset = block_offset;
        req->rw.block_count = num_blocks / num_ios;
        req->rw.vol = NULL;
        req->rw.cache_hint = cache_hint;
        req->rw.io_origin = io_origin;

        // Set up the io_vecs.
        for (unsigned i = 0; i < req->rw.block_count; i++)
        {
            req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            req->rw.iovecs[i].iov_base = data;
            req->rw.block_hashes[i] = nuvo_hash(data, NUVO_BLOCK_SIZE);
            data += NUVO_BLOCK_SIZE;
        }

        block_offset += req->rw.block_count;
        num_blocks -= req->rw.block_count;
        num_ios--;

        nuvo_dlnode_init(&req->list_node);
        nuvo_dlist_insert_tail(list, &req->list_node);
    }
}

void io_concat_test_do_writes_wait()
{
    nuvo_mutex_lock(&io_test_var.ios_outstanding_mutex);
    io_test_var.ios_outstanding--;
    bool done = (io_test_var.ios_outstanding == 0);
    nuvo_mutex_unlock(&io_test_var.ios_outstanding_mutex);

    if (done)
    {
        // IOs finished before we decremented.  They won't unlock the mutex.
    } else {
         // IOs fnished before we got here.  They won't unlock the mutex.
        nuvo_mutex_lock(&io_test_var.ios_wait_mutex);
    }
    nuvo_mutex_unlock(&io_test_var.ios_wait_mutex);
}

void io_concat_test_do_writes(struct nuvo_io_concatenator *io_concatenator,
                              struct nuvo_dlist     *list,
                              bool                  flush,
                              bool                  wait)
{
    nuvo_mutex_lock(&io_test_var.ios_wait_mutex);
    nuvo_mutex_lock(&io_test_var.ios_outstanding_mutex);
    io_test_var.ios_outstanding++;
    nuvo_mutex_unlock(&io_test_var.ios_outstanding_mutex);

    fake_pr_suspend_replies();
    io_concat_tests_submit_list(io_concatenator, list);
    fake_pr_unsuspend_replies();
    if (flush)
    {
        nuvo_io_concat_flush(io_concatenator);
    }

    if (wait)
    {
        io_concat_test_do_writes_wait();
    }
}

static void io_concat_test_check_data(uint_fast32_t pd,
                                      uint_fast32_t block_offset,
                                      uint_fast16_t num_blocks,
                                      uint8_t      *data)
{
    for (uint_fast16_t i = 0; i < num_blocks; i++)
    {
        // read block (pd, block_offset+i)
        nuvo_return_t rc;
        uint8_t buffer[NUVO_BLOCK_SIZE];
        rc = nuvo_pr_sync_read(pd, block_offset + i, 1, buffer);
        ck_assert(rc >= 0);

        // compare data and the block.
        ck_assert(0 == memcmp(data, buffer, NUVO_BLOCK_SIZE));
        data += NUVO_BLOCK_SIZE;
    }
}

// Check that things work when sending IOs and block all.
// check that sending a bunch of IOs that exactly fit in an IO work
START_TEST(perfect_fit_1)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    7,
                                    NUVO_MAX_IO_BLOCKS,
                                    1,
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 7, NUVO_MAX_IO_BLOCKS, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_USER);

    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 1 == post_op_count);
    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[1].pd, 7, NUVO_MAX_IO_BLOCKS, io_test_var.test_data[1].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

START_TEST(perfect_fit_3)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    8,
                                    NUVO_MAX_IO_BLOCKS,
                                    3,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8, NUVO_MAX_IO_BLOCKS, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);

    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 1 == post_op_count);
    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[1].pd, 8, NUVO_MAX_IO_BLOCKS, io_test_var.test_data[1].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// check that sending a non-aligned immediately completes the existing.
START_TEST(non_aligned_same_parcel)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    50,
                                    34,
                                    2,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    107,
                                    20,
                                    2,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);

    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 50, 34, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 107, 20, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);
    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[1].pd, 50, 34, io_test_var.test_data[1].data);
    io_concat_test_check_data(io_test_var.parcel[1].pd, 107, 20, io_test_var.test_data[1].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// check that sending aligned but changing cache hint completes the existing.
START_TEST(non_aligned_cache_hint_change)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[2].pd,
                                    100,
                                    64,
                                    2,
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_GC_DATA,
                                    io_test_var.test_data[12].data);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[2].pd,
                                    164,
                                    64,
                                    2,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_GC_DATA,
                                    io_test_var.test_data[5].data);

    test_io_submit_tracking_expect(io_test_var.parcel[2].pd, 100, 64, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_GC_DATA);
    test_io_submit_tracking_expect(io_test_var.parcel[2].pd, 164, 64, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_GC_DATA);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);
    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[2].pd, 100, 64, io_test_var.test_data[12].data);
    io_concat_test_check_data(io_test_var.parcel[2].pd, 164, 64, io_test_var.test_data[5].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// check that sending an aligned, but different parcel will complete existing.
START_TEST(aligned_different_parcel)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    0,
                                    100,
                                    4,
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[2].data);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    100,
                                    100,
                                    4,
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[17].data);

    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 0, 100, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 100, 100, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_USER);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);
    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[0].pd, 0, 100, io_test_var.test_data[2].data);
    io_concat_test_check_data(io_test_var.parcel[1].pd, 100, 100, io_test_var.test_data[17].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Check that overflowing into next section works.  This has 600 blocks, so overflows
// 88 into third op.
START_TEST(overflow)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    8,
                                    600,
                                    6,
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_GC_DATA,
                                    io_test_var.test_data[12].data);
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 8, NUVO_MAX_IO_BLOCKS, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_GC_DATA);
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 8 + NUVO_MAX_IO_BLOCKS, NUVO_MAX_IO_BLOCKS, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_GC_DATA);
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 8 + 2 * NUVO_MAX_IO_BLOCKS, 600 - 2 * NUVO_MAX_IO_BLOCKS, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_GC_DATA);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 3 == post_op_count);
    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[0].pd, 8, 600, io_test_var.test_data[12].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Check that bumping an 8 block io that won't fit into next block works.
START_TEST(overflow_bump8)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    8,   // Start at 8
                                    250, // 250 long
                                    1,   // 1 io
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[12].data);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    258,  // advance 250
                                    8,    // 8 blocks
                                    1,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[262].data); // advance 250

    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 8, 250, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 258, 8, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, false, false);// Don't flush, don't wait - want to see that we got 8 blocks spillover.
    ck_assert(io_concatenator.current_op->req->rw.block_count == 8);
    nuvo_io_concat_flush(&io_concatenator);
    io_concat_test_do_writes_wait();
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);

    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[0].pd, 8, 258, io_test_var.test_data[12].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Check that bumping an 7 block io that won't fit into next block works.
START_TEST(overflow_bump7)
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    100,   // Start at 100
                                    250, // 250 long
                                    1,   // 1 io
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[100].data);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    350,  // advance 250
                                    7,    // 7 blocks
                                    1,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[350].data); // advance 250
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 100, 256, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 356, 1, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);

    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, false, false);// Don't flush, don't wait - want to see that we got 8 blocks spillover.
    ck_assert(io_concatenator.current_op->req->rw.block_count == 1); // 7 won't fit.  We get a runt anyway.
    nuvo_io_concat_flush(&io_concatenator);
    io_concat_test_do_writes_wait();
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);

    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[0].pd, 100, 257, io_test_var.test_data[100].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Check that bumping an 12 block io that only has one has one overhang fits.
START_TEST(overflow_bump12)
{
{
    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    0,   // Start at 0
                                    245, // 245 long
                                    1,   // 1 io
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_GC_DATA,
                                    io_test_var.test_data[100].data);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[0].pd,
                                    245,  // advance 245
                                    12,    // 7 blocks
                                    1,
                                    NUVO_CACHE_NONE,
                                    NUVO_IO_ORIGIN_GC_DATA,
                                    io_test_var.test_data[345].data); // advance 245

    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 0, 249, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_GC_DATA);
    test_io_submit_tracking_expect(io_test_var.parcel[0].pd, 249, 8, NUVO_CACHE_NONE, NUVO_IO_ORIGIN_GC_DATA);

    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, false, false);// Don't flush, don't wait - want to see that we got 8 blocks spillover.
    ck_assert(io_concatenator.current_op->req->rw.block_count == 8); // We made at least 8 overhang.
    nuvo_io_concat_flush(&io_concatenator);
    io_concat_test_do_writes_wait();
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);

    test_io_concat_done();

    io_concat_test_check_data(io_test_var.parcel[0].pd, 0, 257, io_test_var.test_data[100].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
}
END_TEST

// Check that bypass when no free ops works.
START_TEST(no_free_ops)
{
    nuvo_return_t rc;
    nuvo_io_concat_pool_destroy();
    rc = nuvo_io_concat_pool_init(0);
    ck_assert(rc == 0);

    struct nuvo_io_concatenator io_concatenator;
    rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);

    struct nuvo_io_concat_op* op = nuvo_io_concat_op_alloc(&io_concatenator, NULL);
    ck_assert(op == NULL);

    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    100,
                                    8,
                                    1,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_INTERNAL,
                                    io_test_var.test_data[10].data);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 100, 8, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_INTERNAL);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 1 == post_op_count);
    test_io_concat_done();
    io_concat_test_check_data(io_test_var.parcel[1].pd, 100, 8, io_test_var.test_data[10].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Check that bypass when no free ops for next works.
START_TEST(one_free_ops)
{
    nuvo_return_t rc;
    nuvo_io_concat_pool_destroy();
    rc = nuvo_io_concat_pool_init(1);
    ck_assert(rc == 0);

    struct nuvo_io_concatenator io_concatenator;
    rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);

    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    100,
                                    260,
                                    2,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[50].data);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 100, 130, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 230, 130, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);

    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, true, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);
    test_io_concat_done();
    io_concat_test_check_data(io_test_var.parcel[1].pd, 100, 260, io_test_var.test_data[50].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

START_TEST(perfect_fit_4_min_1)
{
    nuvo_io_concat_control.min_outstanding = 1;

    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    8,
                                    NUVO_MAX_IO_BLOCKS,
                                    4,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8, 64, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8 + 64, 3 * 64, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, false, true);  // Don't flush, checking dispatch of perfect fit.
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 2 == post_op_count);
    test_io_concat_done();
    io_concat_test_check_data(io_test_var.parcel[1].pd, 8, NUVO_MAX_IO_BLOCKS, io_test_var.test_data[1].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Write two max ios worth of data, but split up and with
// policy of sending until 2 ops are outstanding, so 4 total will go.
START_TEST(perfect_fit_16_min_2)
{
    nuvo_io_concat_control.min_outstanding = 2;

    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, test_io_concat_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    // 2 *256 / 16 means each req is 32 blocks.
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    8,
                                    2 * NUVO_MAX_IO_BLOCKS,
                                    16,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8, 32, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8 + 32, 32, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8 + 2 * 32, NUVO_MAX_IO_BLOCKS, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    test_io_submit_tracking_expect(io_test_var.parcel[1].pd, 8 + 2 * 32 + NUVO_MAX_IO_BLOCKS, NUVO_MAX_IO_BLOCKS - 2 * 32, NUVO_CACHE_DEFAULT, NUVO_IO_ORIGIN_USER);
    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, false, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 4 == post_op_count); // Two max IOs of data, but first two go alone, leaving 2 bigs.
    test_io_concat_done();
    io_concat_test_check_data(io_test_var.parcel[1].pd, 8, 2 * NUVO_MAX_IO_BLOCKS, io_test_var.test_data[1].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

// Write two max ios worth of data, but split up and with
// policy of sending until 1 ops are outstanding, so 3 total will go.
START_TEST(perfect_fit_10_min_1_no_flush)
{
    nuvo_io_concat_control.min_outstanding = 1;

    struct nuvo_io_concatenator io_concatenator;
    nuvo_return_t rc = nuvo_io_concat_init(&io_concatenator, nuvo_pr_submit);
    ck_assert(rc == 0);
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);
    io_concat_test_build_write_list(&list,
                                    io_test_var.parcel[1].pd,
                                    8,
                                    2 * NUVO_MAX_IO_BLOCKS,
                                    10,
                                    NUVO_CACHE_DEFAULT,
                                    NUVO_IO_ORIGIN_USER,
                                    io_test_var.test_data[1].data);

    uint64_t pre_op_count = fake_pr_ops_completed();
    io_concat_test_do_writes(&io_concatenator, &list, false, true);
    uint64_t post_op_count = fake_pr_ops_completed();
    ck_assert(pre_op_count + 3 == post_op_count); // Two max IOs of data, but first one goes alone, leaving 2 bigs.

    io_concat_test_check_data(io_test_var.parcel[1].pd, 8, 2 * NUVO_MAX_IO_BLOCKS, io_test_var.test_data[1].data);

    nuvo_io_concat_destroy(&io_concatenator);
    ck_assert(rc == 0);
}
END_TEST

Suite * nuvo_pr_helpers_suite(void)
{
    Suite *s = suite_create("io_concatenator");
    TCase *tc_io_concat = tcase_create("IO_Concat");
    tcase_add_checked_fixture(tc_io_concat, io_concat_tests_setup, io_concat_tests_teardown);
    tcase_add_test(tc_io_concat, io_concat_init);
    tcase_add_test(tc_io_concat, io_concat_op_alloc_free);
    tcase_add_test(tc_io_concat, perfect_fit_1);
    tcase_add_test(tc_io_concat, perfect_fit_3);
    tcase_add_test(tc_io_concat, non_aligned_same_parcel);
    tcase_add_test(tc_io_concat, non_aligned_cache_hint_change);
    tcase_add_test(tc_io_concat, aligned_different_parcel);

    tcase_add_test(tc_io_concat, overflow);
    tcase_add_test(tc_io_concat, overflow_bump8);
    tcase_add_test(tc_io_concat, overflow_bump7);
    tcase_add_test(tc_io_concat, overflow_bump12);

    tcase_add_test(tc_io_concat, no_free_ops);
    tcase_add_test(tc_io_concat, one_free_ops);

    tcase_add_test(tc_io_concat, perfect_fit_4_min_1);
    tcase_add_test(tc_io_concat, perfect_fit_16_min_2);
    tcase_add_test(tc_io_concat, perfect_fit_10_min_1_no_flush);
    suite_add_tcase(s, tc_io_concat);

    return s;
}