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
#include "parcel_manager_priv.h"
#include "nuvo.h"
#include <errno.h>
#include <fcntl.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <semaphore.h>

UUID_DEFINE(bad_uuid, 186, 219, 173, 186, 219, 173, 186, 219, 173, 186, 219, 173, 186, 219, 173, 186);
UUID_DEFINE(test_uuid, 97, 80, 43, 211, 70, 41, 116, 63, 88, 180, 119, 79, 151, 29, 53, 66);

/*
 * used for creating a pool of test devices
 * each device has enough nuvo_io_requests pre-allocated to fully utilize the device.
 * devices in the test pool may not be suitable for limit tests.
 */
#define TEST_DEVICE_NAME_TEMPLATE ("/tmp/nuvo_test_device.XXXXXX")
/* number of devices in the test pool */
#define MAX_TEST_DEVICES (12)
/* maximum number of test volumes per device */
#define MAX_TEST_VOLUMES (16)
/* the default size used for test devices */
#define TEST_DEVICE_USABLE_SIZE (268435456)
#define TEST_DEVICE_DEFAULT_SIZE (TEST_DEVICE_USABLE_SIZE + (NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2))
#define TEST_DEVICE_DEFAULT_TYPE (NUVO_DEV_TYPE_SSD)
/* the default parcel size used for test devices */
#define TEST_PARCEL_DEFAULT_SIZE (1048576)
/* the minimum parcel size supported for test devices */
#define TEST_PARCEL_MIN_SIZE (NUVO_PM_PARCEL_MIN_SIZE)
#define TEST_DEVICE_MAX_PARCELS (TEST_DEVICE_USABLE_SIZE / TEST_PARCEL_MIN_SIZE)
#define TEST_DEVICE_MAX_IOREQS (TEST_DEVICE_USABLE_SIZE / NUVO_MAX_IO_SIZE)
#define PARALLEL_DEVICE_COUNT (3)

extern struct device_records g_devices;

sem_t sem;

struct io_completion
{
    struct nuvo_io_request io_req;
    int io_complete;
};

struct test_device
{
    char name[128];
    int fd;
    uuid_t uuid;
    uint64_t device_size;
    uint32_t parcel_size;
    enum nuvo_dev_type device_type;
    struct device_info device_info;
    uuid_t volume_uuid[MAX_TEST_VOLUMES];
    struct io_completion op_info;

    struct io_completion op_alloc[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_free[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_open[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_close[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_read[TEST_DEVICE_MAX_IOREQS];
    struct io_completion op_write[TEST_DEVICE_MAX_IOREQS];

    struct nuvo_io_stats_snap write_io_stats;
    uint_fast64_t write_size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t write_latency_hist[NUVO_STATS_LAT_BINS];

    struct nuvo_io_stats_snap read_io_stats;
    uint_fast64_t read_size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t read_latency_hist[NUVO_STATS_LAT_BINS];
};


struct test_device test_devs[MAX_TEST_DEVICES];

enum cleanup
{
    KEEP_BUFFERS = 0,
    DISCARD_BUFFERS = 1
};

void nuvo_pr_complete(struct nuvo_io_request *io_req)
{
    (*(io_req->callback))(io_req);
}

void init_test_device_array()
{
    for (int i = 0; i <= MAX_TEST_DEVICES; i++)
    {
        memset(test_devs[i].name, 0, sizeof(test_devs[i].name));
        uuid_generate(test_devs[i].uuid);
        test_devs[i].device_size = TEST_DEVICE_DEFAULT_SIZE;
        test_devs[i].parcel_size = TEST_PARCEL_DEFAULT_SIZE;
        test_devs[i].device_type = TEST_DEVICE_DEFAULT_TYPE;
        memset(&test_devs[i].device_info, 0, sizeof(test_devs[i].device_info));
        memset(&test_devs[i].op_info, 0, sizeof(struct io_completion));
        for (int j = 0;  j < TEST_DEVICE_MAX_IOREQS; j++)
        {
            memset(&test_devs[i].op_read[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_write[j], 0, sizeof(struct io_completion));
        }
        for (int j = 0;  j < TEST_DEVICE_MAX_PARCELS; j++)
        {
            memset(&test_devs[i].op_alloc[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_free[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_open[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_close[j], 0, sizeof(struct io_completion));
        }

        test_devs[i].write_io_stats.size_hist = test_devs[i].write_size_hist;
        test_devs[i].write_io_stats.latency_hist = test_devs[i].write_latency_hist;
        test_devs[i].read_io_stats.size_hist = test_devs[i].read_size_hist;
        test_devs[i].read_io_stats.latency_hist = test_devs[i].read_latency_hist;
    }
}


void test_callback(struct nuvo_io_request *iorp)
{
    struct io_completion *op;

    switch(iorp->operation)
    {
    case NUVO_OP_READ:
    case NUVO_OP_WRITE:
    case NUVO_OP_OPEN:
    case NUVO_OP_CLOSE:
    case NUVO_OP_ALLOC:
    case NUVO_OP_FREE:
    case NUVO_OP_DEV_INFO:
        op = (struct io_completion *)iorp->tag.ptr;
        op->io_complete = 1;
        break;
    default:
        break;
    }

    sem_post(&sem);
}


int allocate_parcels(struct test_device *device, uint32_t parcel_cnt)
{
    uuid_t device_uuid;
    uuid_t volume_uuid;
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);

    uuid_copy(device_uuid, device->uuid);
    uuid_copy(volume_uuid, device->volume_uuid[0]);

    /* allocate all parcels */
    uint32_t submit_cnt = 0;
    while (submit_cnt < parcel_cnt)
    {
        struct nuvo_io_request *io_req = &device->op_alloc[submit_cnt].io_req;
        device->op_alloc[submit_cnt].io_complete = 0;
        nuvo_dlnode_init(&io_req->list_node);

        uuid_copy(io_req->alloc.device_uuid, device_uuid);
        uuid_copy(io_req->alloc.volume_uuid, volume_uuid);
        io_req->operation = NUVO_OP_ALLOC;
        io_req->tag.ptr = &device->op_alloc[submit_cnt];
        io_req->callback=(void *)&test_callback;

        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        submit_cnt++;
    }

    (void)nuvo_pm_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (device->op_alloc[i].io_complete != 0)
        {
            if (device->op_alloc[i].io_req.status != 0)
            {
                failed++;
            }
            done++;
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    return (done - failed);
}

int free_parcels(struct test_device *device)
{
    uint32_t parcel_cnt = device->device_info.parcels_allocated;
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);

    /* submit all free requests at once */
    uint32_t submit_cnt = 0;
    while (submit_cnt < parcel_cnt)
    {
        /* uses results of the previous parcel alloc stored in g_alloc[] */
        struct nuvo_io_request *io_req = &device->op_free[submit_cnt].io_req;
        device->op_free[submit_cnt].io_complete = 0;
        nuvo_dlnode_init(&io_req->list_node);

        uuid_copy(io_req->free.parcel_uuid, device->op_alloc[submit_cnt].io_req.alloc.parcel_uuid);
        uuid_copy(io_req->free.volume_uuid, device->op_alloc[submit_cnt].io_req.alloc.volume_uuid);
        uuid_copy(io_req->free.device_uuid, device->op_alloc[submit_cnt].io_req.alloc.device_uuid);
        io_req->operation = NUVO_OP_FREE;
        io_req->tag.ptr = &device->op_free[submit_cnt];
        io_req->callback=(void *)&test_callback;

        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        submit_cnt++;
    }

    (void)nuvo_pm_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (device->op_free[i].io_complete != 0)
        {
            if (device->op_free[i].io_req.status != 0)
            {
                failed++;
            }
            done++;
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    return (done - failed);
}


int open_close_parcels(struct test_device *device, uint32_t parcel_cnt, int op)
{
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);

    uint32_t submit_cnt = 0;
    while (submit_cnt < parcel_cnt)
    {
        /* uses results of the previous parcel alloc stored in op_alloc[] */
        device->op_open[submit_cnt].io_complete = 0;
        struct nuvo_io_request *io_req = &device->op_open[submit_cnt].io_req;
        nuvo_dlnode_init(&io_req->list_node);

        if (op == NUVO_OP_OPEN)
        {
            uuid_copy(io_req->open.parcel_uuid, device->op_alloc[submit_cnt].io_req.alloc.parcel_uuid);
            uuid_copy(io_req->open.volume_uuid, device->op_alloc[submit_cnt].io_req.alloc.volume_uuid);
            uuid_copy(io_req->open.device_uuid, device->op_alloc[submit_cnt].io_req.alloc.device_uuid);
            io_req->open.reopen_flag = 0;
            io_req->operation = NUVO_OP_OPEN;
            io_req->tag.ptr = &device->op_open[submit_cnt];
        }
        else
        {
            io_req->close.native_parcel_desc = device->op_open[submit_cnt].io_req.open.parcel_desc;
            io_req->operation = NUVO_OP_CLOSE;
            io_req->tag.ptr = &device->op_close[submit_cnt];
        }
        io_req->callback=(void *)test_callback;

        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        submit_cnt++;
    }

    (void)nuvo_pm_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (op == NUVO_OP_OPEN)
        {
            if (device->op_open[i].io_complete != 0)
            {
                if (device->op_open[i].io_req.status != 0)
                {
                    failed++;
                }
                done++;
            }
        }
        else
        {
            if (device->op_close[i].io_complete != 0)
            {
                if (device->op_close[i].io_req.status != 0)
                {
                    failed++;
                }
                done++;
            }
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    return (done - failed);
}

int write_parcels(struct test_device *device, uint32_t io_size, int parcel_cnt, int cleanup)
{
    int parcel_size = device->parcel_size;
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);

    /*
     * a parcel may require multiple io_reqs to be fully written
     * 1mb is the maximum io size, to fill a parcel need parcel_size / 1mb iovecs.
     */
    uint32_t submit_cnt = 0;
    for (int i = 0; i < parcel_cnt; i++)
    {
        int io_cnt = 0;
        int bytes_to_write = parcel_size;
        while (bytes_to_write > 0) {
            int buffer_cnt = 0;

            struct nuvo_io_request *io_req = &device->op_write[submit_cnt].io_req;
            device->op_write[submit_cnt].io_complete = 0;
            nuvo_dlnode_init(&io_req->list_node);

            if (bytes_to_write < (int)io_size) {
                buffer_cnt = bytes_to_write / NUVO_BLOCK_SIZE;
                bytes_to_write = 0;
            } else {
                buffer_cnt = io_size / NUVO_BLOCK_SIZE;
                bytes_to_write -=  io_size;
            }

            /* allocates buffer_cnt aligned 4K buffers */
            for (int j = 0; j < buffer_cnt; j++) {
                posix_memalign(&io_req->rw.iovecs[j].iov_base, NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
                memset(io_req->rw.iovecs[j].iov_base, rand() % 256, NUVO_BLOCK_SIZE);
                io_req->rw.iovecs[j].iov_len = NUVO_BLOCK_SIZE;
                io_req->rw.block_hashes[j] = nuvo_hash(io_req->rw.iovecs[j].iov_base, NUVO_BLOCK_SIZE);
            }
            io_req->rw.block_count = buffer_cnt;
            io_req->rw.block_offset = io_cnt * buffer_cnt;

            /* uses the descriptor from the open test */
            io_req->rw.native_parcel_desc = device->op_open[i].io_req.open.parcel_desc;
            io_req->operation = NUVO_OP_WRITE;
            io_req->callback = (void *)&test_callback;

            io_req->tag.ptr = &device->op_write[submit_cnt];

            submit_cnt++;
            io_cnt++;

            nuvo_dlnode_init(&io_req->list_node);
            nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

        }
    }

    (void)nuvo_pm_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (device->op_write[i].io_complete != 0)
        {
            if (device->op_write[i].io_req.status != 0)
            {
                failed++;
            }
            done++;
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    if (cleanup)
    {
        for (uint32_t i = 0; i < submit_cnt; i++)
        {
            for (uint32_t j = 0; j < NUVO_MAX_IO_BLOCKS; j++)
            {
                if (device->op_write[i].io_req.rw.iovecs[j].iov_base)
                {
                    free(device->op_write[i].io_req.rw.iovecs[j].iov_base);
                    device->op_write[i].io_req.rw.iovecs[j].iov_base = NULL;
                }
            }
        }
    }

    return (done - failed);
}

int read_parcels(struct test_device *device, uint32_t io_size, int parcel_cnt, int cleanup)
{
    int parcel_size = device->parcel_size;
    struct nuvo_dlist submit_list;

    nuvo_dlist_init(&submit_list);

    uint32_t submit_cnt = 0;
    for (int i = 0; i < parcel_cnt; i++)
    {
        int io_cnt = 0;
        int bytes_to_read = parcel_size;
        while (bytes_to_read > 0)
        {
            int buffer_cnt = 0;

            struct nuvo_io_request *io_req = &device->op_read[submit_cnt].io_req;
            device->op_read[submit_cnt].io_complete = 0;
            nuvo_dlnode_init(&io_req->list_node);

            if (bytes_to_read < (int)io_size)
            {
                buffer_cnt = bytes_to_read / NUVO_BLOCK_SIZE;
                bytes_to_read = 0;
            }
            else
            {
                buffer_cnt = io_size / NUVO_BLOCK_SIZE;
                bytes_to_read -=  io_size;
            }

            /* allocates buffer_cnt aligned 4K buffers */
            for (int j = 0; j < buffer_cnt; j++)
            {
                posix_memalign(&io_req->rw.iovecs[j].iov_base, NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);;
                memset(io_req->rw.iovecs[j].iov_base, 0, NUVO_BLOCK_SIZE);
                io_req->rw.iovecs[j].iov_len = NUVO_BLOCK_SIZE;
                /* uses the block hash calculated and stored in the write test io_req */
                io_req->rw.block_hashes[j] = device->op_write[i].io_req.rw.block_hashes[j];
            }
            io_req->rw.block_count = buffer_cnt;
            io_req->rw.block_offset = io_cnt * buffer_cnt;
            /* uses the descriptor from the open test */
            io_req->rw.native_parcel_desc = device->op_open[i].io_req.open.parcel_desc;

            io_req->operation = NUVO_OP_READ;
            io_req->callback = (void *)&test_callback;

            io_req->tag.ptr = &device->op_read[submit_cnt];

            submit_cnt++;
            io_cnt++;

            nuvo_dlnode_init(&io_req->list_node);
            nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        }
    }

    (void)nuvo_pm_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (device->op_read[i].io_complete != 0)
        {
            if (device->op_read[i].io_req.status != 0)
            {
                failed++;
            }
            done++;
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        for (uint32_t j = 0; j < device->op_read[i].io_req.rw.block_count; j++)
        {
            ck_assert_uint_eq(device->op_read[i].io_req.rw.block_hashes[j], device->op_write[i].io_req.rw.block_hashes[j]);
        }
    }

    if (cleanup)
    {
        for (uint32_t i = 0; i < submit_cnt; i++)
        {
            for (uint32_t j = 0; j < NUVO_MAX_IO_BLOCKS; j++)
            {
                if (device->op_read[i].io_req.rw.iovecs[j].iov_base)
                {
                    free(device->op_read[i].io_req.rw.iovecs[j].iov_base);
                    device->op_read[i].io_req.rw.iovecs[j].iov_base = NULL;
                }
            }
        }
    }

    return (done - failed);
}

START_TEST(nuvo_pm_test_device_format)
{
    int ret;
    int idx = 0;

    printf("%s\n", __func__);

    /* parcel size too small */
    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, 4096);
    ck_assert_int_eq(ret, -EINVAL);

    /* parcel size not 4K aligned */
    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size + 1);
    ck_assert_int_eq(ret, -EINVAL);

    /* parcel size too large for device */
    uint32_t size = (TEST_DEVICE_MAX_PARCELS * TEST_PARCEL_DEFAULT_SIZE) + NUVO_BLOCK_SIZE;
    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, size);
    ck_assert_int_eq(ret, -ENOSPC);

    /* device doesn't exist */
    ret = nuvo_pm_device_format("/tmp/no-exist", test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, -ENOENT);

    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, 0);

}
END_TEST

START_TEST(nuvo_pm_test_device_open)
{
    int ret;
    int idx = 0;
    struct nuvo_dlist submit_list;

    printf("%s\n", __func__);

    nuvo_dlist_init(&submit_list);

    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, 0);

    /* device doesn't exist */
    ret = nuvo_pm_device_open("/tmp/no-exist", test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, -ENOENT);

    ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, 0);

    /* try to open twice */
    ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, -NUVO_E_DEVICE_ALREADY_OPEN);

    /* try to open with wrong uuid */
    ret = nuvo_pm_device_open(test_devs[idx].name, bad_uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, -ENOENT);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.device_size, test_devs[idx].device_size);
    ck_assert_int_eq(test_devs[idx].device_info.parcel_size, test_devs[idx].parcel_size);
    ck_assert_int_eq(test_devs[idx].device_info.device_type, test_devs[idx].device_type);

    /* try to get info with wrong uuid */
    struct device_info device_info;
    ret = nuvo_pm_device_info(bad_uuid, &device_info);
    ck_assert_int_eq(ret, -ENOENT);

    /* try to get info with wrong uuid using async method */
    struct nuvo_io_request *io_req = &test_devs[idx].op_info.io_req;
    test_devs[idx].op_info.io_complete = 0;
    nuvo_dlnode_init(&io_req->list_node);

    uuid_copy(io_req->dev_info.device_uuid, bad_uuid);
    io_req->operation = NUVO_OP_DEV_INFO;
    io_req->tag.ptr = &test_devs[idx].op_info;
    io_req->callback=(void *)&test_callback;

    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    uint32_t done = 0;
    while (!done)
    {
        if (test_devs[idx].op_info.io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_info.io_req.status, -ENOENT);
            done++;
        }
    }

    /* try using correct uuid */
    test_devs[idx].op_info.io_complete = 0;
    uuid_copy(io_req->dev_info.device_uuid, test_devs[idx].uuid);
    io_req->operation = NUVO_OP_DEV_INFO;
    io_req->tag.ptr = &test_devs[idx].op_info;
    io_req->callback=(void *)&test_callback;

    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_info.io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_info.io_req.status, 0);
            done++;
        }
    }
    ck_assert_int_eq(test_devs[idx].op_info.io_req.dev_info.device_size, test_devs[idx].device_size);
    ck_assert_int_eq(test_devs[idx].op_info.io_req.dev_info.parcel_size, test_devs[idx].parcel_size);
    ck_assert_int_eq(test_devs[idx].op_info.io_req.dev_info.device_type, test_devs[idx].device_type);

}
END_TEST

START_TEST(nuvo_pm_test_parcel_alloc_and_open_fail)
{
    int ret;
    int idx = 0;
    int done = 0;
    int allocated = 0;
    struct nuvo_io_request *io_req;
    struct nuvo_dlist submit_list;

    printf("%s\n", __func__);

    nuvo_dlist_init(&submit_list);

    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.device_size, test_devs[idx].device_size);
    ck_assert_int_eq(test_devs[idx].device_info.parcel_size, test_devs[idx].parcel_size);

    io_req = &test_devs[idx].op_alloc[idx].io_req;
    test_devs[idx].op_alloc[idx].io_complete = 0;
    nuvo_dlnode_init(&io_req->list_node);

    uuid_copy(io_req->alloc.device_uuid, bad_uuid);
    uuid_copy(io_req->alloc.volume_uuid, test_uuid);
    io_req->operation = NUVO_OP_ALLOC;
    io_req->tag.ptr = &test_devs[idx].op_alloc[idx];
    io_req->callback=(void *)&test_callback;

    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_alloc[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_alloc[idx].io_req.status, -ENOENT);
            done++;
        }
    }

    /* allocates all parcels on the device. submits 1.5x more requests than necessary */
    int over_alloc = test_devs[idx].device_info.max_parcels + (test_devs[idx].device_info.max_parcels / 2);
    allocated = allocate_parcels(&test_devs[idx], over_alloc);
    ck_assert_int_eq(test_devs[idx].device_info.max_parcels, allocated);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, allocated);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, test_devs[idx].device_info.max_parcels);
    ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 1);

    /* request more when parcel table is full */
    allocated = allocate_parcels(&test_devs[idx], test_devs[idx].device_info.max_parcels);
    ck_assert_int_eq(allocated, 0);

    /* open a parcel with the wrong volume uuid */
    test_devs[idx].op_open[idx].io_complete = 0;
    io_req = &test_devs[idx].op_open[idx].io_req;
    nuvo_dlnode_init(&io_req->list_node);

    uuid_copy(io_req->open.parcel_uuid, test_devs[idx].op_alloc[idx].io_req.alloc.parcel_uuid);
    uuid_copy(io_req->open.volume_uuid, bad_uuid);
    uuid_copy(io_req->open.device_uuid, test_devs[idx].op_alloc[idx].io_req.alloc.device_uuid);
    io_req->open.reopen_flag = 0;
    io_req->operation = NUVO_OP_OPEN;
    io_req->tag.ptr = &test_devs[idx].op_open[idx];
    io_req->callback=(void *)test_callback;
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_open[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_open[idx].io_req.status, -EPERM);
            done++;
        }
    }

    /* open a parcel with the wrong volume uuid */
    test_devs[idx].op_open[idx].io_complete = 0;
    io_req = &test_devs[idx].op_open[idx].io_req;
    nuvo_dlnode_init(&io_req->list_node);

    uuid_copy(io_req->open.parcel_uuid, test_devs[idx].op_alloc[idx].io_req.alloc.parcel_uuid);
    uuid_copy(io_req->open.volume_uuid, test_devs[idx].op_alloc[idx].io_req.alloc.volume_uuid);
    uuid_copy(io_req->open.device_uuid, test_devs[idx].op_alloc[idx].io_req.alloc.device_uuid);
    io_req->open.reopen_flag = 0;
    io_req->operation = NUVO_OP_OPEN;
    io_req->tag.ptr = &test_devs[idx].op_open[idx];
    io_req->callback=(void *)test_callback;
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_open[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_open[idx].io_req.status, 0);
            done++;
        }
    }

    /* try to open the parcel twice */
    union native_parcel_descriptor npd;
    npd.native_parcel_desc = test_devs[idx].op_open[idx].io_req.open.parcel_desc;
    test_devs[idx].op_open[idx].io_complete = 0;
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_open[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_open[idx].io_req.status,
                             -NUVO_E_PARCEL_ALREADY_OPEN);
            done++;
        }
    }
    test_devs[idx].op_open[idx].io_req.open.parcel_desc = npd.native_parcel_desc;

    /* close a parcel with the wrong generation */
    test_devs[idx].op_close[idx].io_complete = 0;
    io_req = &test_devs[idx].op_close[idx].io_req;
    nuvo_dlnode_init(&io_req->list_node);

    npd.native_parcel_desc = test_devs[idx].op_open[idx].io_req.open.parcel_desc;
    npd.gen_id++;
    io_req->close.native_parcel_desc = npd.native_parcel_desc;
    io_req->operation = NUVO_OP_CLOSE;
    io_req->tag.ptr = &test_devs[idx].op_close[idx];
    io_req->callback=(void *)test_callback;
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);

    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_close[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_close[idx].io_req.status,
                             -EBADF);
            done++;
        }
    }

    /* now close the parcel using the correct descriptor */
    nuvo_dlnode_init(&io_req->list_node);
    test_devs[idx].op_close[idx].io_complete = 0;
    io_req->close.native_parcel_desc = test_devs[idx].op_open[idx].io_req.open.parcel_desc;
    io_req->operation = NUVO_OP_CLOSE;
    io_req->tag.ptr = &test_devs[idx].op_close[idx];
    io_req->callback=(void *)test_callback;
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_close[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_close[idx].io_req.status, 0);
            done++;
        }
    }

    /* try closing it again */
    test_devs[idx].op_close[idx].io_complete = 0;
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
    (void)nuvo_pm_submit(&submit_list);

    sem_wait(&sem);

    done = 0;
    while (!done)
    {
        if (test_devs[idx].op_close[idx].io_complete != 0)
        {
            ck_assert_int_eq(test_devs[idx].op_close[idx].io_req.status,
                             -NUVO_E_PARCEL_ALREADY_CLOSED);
            done++;
        }
    }
}
END_TEST

START_TEST(nuvo_pm_test_multi_device_open)
{
    int ret;
    struct nuvo_dlist submit_list;
    uint32_t submit_cnt = 0;
    uint32_t done = 0;

    printf("%s\n", __func__);

    nuvo_dlist_init(&submit_list);

    /* format devices */
    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        ret = nuvo_pm_device_format(test_devs[i].name, test_devs[i].uuid, test_devs[i].parcel_size);
        ck_assert_int_eq(ret, 0);
    }

    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        ret = nuvo_pm_device_open(test_devs[i].name, test_devs[i].uuid, test_devs[i].device_type);
        ck_assert_int_eq(ret, 0);
    }

    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        ret = nuvo_pm_device_info(test_devs[i].uuid, &test_devs[i].device_info);
        ck_assert_int_eq(ret, 0);
        ck_assert_int_eq(test_devs[i].device_info.device_size, test_devs[i].device_size);
        ck_assert_int_eq(test_devs[i].device_info.parcel_size, test_devs[i].parcel_size);
        ck_assert_int_eq(test_devs[i].device_info.device_type, test_devs[i].device_type);
    }

    submit_cnt = 0;
    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        struct nuvo_io_request *io_req = &test_devs[i].op_info.io_req;
        nuvo_dlnode_init(&io_req->list_node);
        test_devs[i].op_info.io_complete = 0;

        uuid_copy(io_req->dev_info.device_uuid, test_devs[i].uuid);
        io_req->operation = NUVO_OP_DEV_INFO;
        io_req->tag.ptr = &test_devs[i].op_info;
        io_req->callback=(void *)&test_callback;

        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        submit_cnt++;
    }

    (void)nuvo_pm_submit(&submit_list);

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    done = 0;
    while (done != submit_cnt)
    {
        done = 0;
        for (uint32_t i = 0; i < submit_cnt; i++)
        {
            if (test_devs[i].op_info.io_complete != 0)
            {
                ck_assert_int_eq(test_devs[i].op_info.io_req.status, 0);
                done++;
            }
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        ck_assert_int_eq(test_devs[i].op_info.io_req.dev_info.device_size, test_devs[i].device_size);
        ck_assert_int_eq(test_devs[i].op_info.io_req.dev_info.parcel_size, test_devs[i].parcel_size);
    }

    /* close all devices */
    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        ret = nuvo_pm_device_close(test_devs[i].uuid);
        ck_assert_int_eq(ret, 0);
    }

    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        ret = nuvo_pm_device_info(test_devs[i].uuid, &test_devs[i].device_info);
        ck_assert_int_eq(ret, -ENOENT);
    }

}
END_TEST

START_TEST(nuvo_pm_test_parcel_write_read_parallel)
{
    int ret;
    int io_size = NUVO_MAX_IO_SIZE;
    int parcel_cnt = 0;
    int fd;
    struct nuvo_dlist submit_list;

    printf("%s\n", __func__);

    nuvo_dlist_init(&submit_list);

    /* format, open, allocate two devices */
    for (int idx = 0; idx < PARALLEL_DEVICE_COUNT; idx++)
    {
        int allocated = 0;

        /* re-size the test device */
        test_devs[idx].device_size = (NUVO_PM_PARCEL_MIN_SIZE * 32) + (NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2);
        test_devs[idx].parcel_size = NUVO_PM_PARCEL_MIN_SIZE;
        ret = ftruncate(test_devs[idx].fd, test_devs[idx].device_size);
        ck_assert_int_eq(ret, 0);

        test_devs[idx].parcel_size = TEST_PARCEL_MIN_SIZE;
        ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
        ck_assert_int_eq(ret, 0);

        ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
        ck_assert_int_eq(ret, 0);

        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);
        ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, 0);
        ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 0);

        allocated = allocate_parcels(&test_devs[idx], test_devs[idx].device_info.max_parcels);

        memset(&test_devs[idx].device_info, 0, sizeof(struct device_info));
        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);
        ck_assert_int_eq(allocated, test_devs[idx].device_info.parcels_allocated);
        ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, test_devs[idx].device_info.max_parcels);
        ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 1);

        ret = open_close_parcels(&test_devs[idx], allocated, NUVO_OP_OPEN);
        ck_assert_int_eq(ret, allocated);

        parcel_cnt += allocated;
    }

    uint32_t device_parcel_cnt = parcel_cnt / PARALLEL_DEVICE_COUNT;

    for (int idx = 0; idx < PARALLEL_DEVICE_COUNT; idx++)
    {
        /* read stats should be empty */
        ret = nuvo_pm_device_stats(test_devs[idx].uuid, NUVO_OP_READ, false, &test_devs[idx].read_io_stats);
        ck_assert_int_eq(ret, 0);

        printf("%s: device: %2d  read count: %4lu size_total: %10lu latency_mean: %20f latency_stdev: %20f\n",
               __func__, idx, test_devs[idx].write_io_stats.count, test_devs[idx].write_io_stats.size_total, test_devs[idx].write_io_stats.latency_mean, test_devs[idx].write_io_stats.latency_stdev);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.count, 0);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.size_total, 0);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.latency_mean, 0);
        ck_assert(!isnan(test_devs[idx].read_io_stats.latency_stdev));

        /* allocs are reflected in the write stats, clear for the write test */
        ret = nuvo_pm_device_stats(test_devs[idx].uuid, NUVO_OP_WRITE, false, &test_devs[idx].write_io_stats);
        ck_assert_int_eq(ret, 0);

        printf("%s: device: %2d write count: %4lu size_total: %10lu latency_mean: %20f latency_stdev: %20f\n",
               __func__, idx, test_devs[idx].write_io_stats.count, test_devs[idx].write_io_stats.size_total, test_devs[idx].write_io_stats.latency_mean, test_devs[idx].write_io_stats.latency_stdev);
        ck_assert_uint_eq(test_devs[idx].write_io_stats.count, device_parcel_cnt);
        ck_assert_uint_eq(test_devs[idx].write_io_stats.size_total, device_parcel_cnt * NUVO_BLOCK_SIZE);
        ck_assert_uint_gt(test_devs[idx].write_io_stats.latency_mean, 0);
        ck_assert(!isnan(test_devs[idx].write_io_stats.latency_stdev));

        /* reset the io stats for the devices */
        ret = nuvo_pm_device_reset_stats(test_devs[idx].uuid);
        ck_assert_int_eq(ret, 0);
    }

    /*
     * writes devices in parallel.
     * device 0 will be given a bad file descriptor to force the removal of the request,
     * to test re-submission of the remaining requests.
     * devices >= 1 will be ok.
     */
    uint32_t submit_cnt = 0;
    uint32_t valid_submit_cnt = 0;
    for (uint32_t i = 0; i < device_parcel_cnt; i++)
    {
        for (int idx = 0; idx < PARALLEL_DEVICE_COUNT; idx++)
        {

            int buffer_cnt = io_size / NUVO_BLOCK_SIZE;

            struct nuvo_io_request *io_req = &test_devs[idx].op_write[i].io_req;
            test_devs[idx].op_write[i].io_complete = 0;
            nuvo_dlnode_init(&io_req->list_node);

            for (int j = 0; j < buffer_cnt; j++) {
                posix_memalign(&io_req->rw.iovecs[j].iov_base, NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
                memset(io_req->rw.iovecs[j].iov_base, rand() % 256, NUVO_BLOCK_SIZE);
                io_req->rw.iovecs[j].iov_len = NUVO_BLOCK_SIZE;
                io_req->rw.block_hashes[j] = nuvo_hash(io_req->rw.iovecs[j].iov_base, NUVO_BLOCK_SIZE);
            }
            io_req->rw.block_count = buffer_cnt;
            io_req->rw.block_offset = 0;

            /* uses the descriptor from the open */
            io_req->rw.native_parcel_desc = test_devs[idx].op_open[i].io_req.open.parcel_desc;
            io_req->operation = NUVO_OP_WRITE;
            io_req->callback = (void *)&test_callback;

            io_req->tag.ptr = &test_devs[idx].op_write[i];

            submit_cnt++;
            if (idx > 0)
            {
                valid_submit_cnt++;
            }

            nuvo_dlnode_init(&io_req->list_node);
            nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        }
    }

    ck_assert_int_eq(submit_cnt, parcel_cnt);

    /*
     * corrupt the first device's file descriptor
     * this will cause device_parcel_cnt failures
     */
    fd = g_devices.devices[0].fd;
    g_devices.devices[0].fd = -1;

    (void)nuvo_pm_submit(&submit_list);

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    uint32_t done = 0;
    uint32_t failed = 0;
    while (done != submit_cnt)
    {
        done = 0;
        failed = 0;
        for (int idx = 0; idx < PARALLEL_DEVICE_COUNT; idx++)
        {
            for (int i = 0; i < (int)test_devs[idx].device_info.parcels_allocated; i++)
            {
                if (test_devs[idx].op_write[i].io_complete != 0)
                {
                    if (test_devs[idx].op_write[i].io_req.status != 0)
                    {
                        failed++;
                    }
                   done++;
                }
            }
        }
    }

    ck_assert_int_eq(done, parcel_cnt);
    ck_assert_int_eq(failed, submit_cnt - valid_submit_cnt);
    ck_assert_int_eq(failed, device_parcel_cnt);

    /* put back the original fd */
    g_devices.devices[0].fd = fd;

    /* start at index 1 because device 0 wasn't written in this test */
    for (int idx = 1; idx < PARALLEL_DEVICE_COUNT; idx++)
    {

        int read = read_parcels(&test_devs[idx], io_size, test_devs[idx].device_info.parcels_allocated, DISCARD_BUFFERS);
        ck_assert_int_eq(read, test_devs[idx].device_info.parcels_allocated);

        ret = nuvo_pm_device_stats(test_devs[idx].uuid, NUVO_OP_WRITE, false, &test_devs[idx].write_io_stats);
        ck_assert_int_eq(ret, 0);

        printf("%s: device: %2d  read count: %4lu size_total: %10lu latency_mean: %20f latency_stdev: %20f\n",
               __func__, idx, test_devs[idx].write_io_stats.count, test_devs[idx].write_io_stats.size_total, test_devs[idx].write_io_stats.latency_mean, test_devs[idx].write_io_stats.latency_stdev);
        ck_assert_uint_eq(test_devs[idx].write_io_stats.count, device_parcel_cnt);
        ck_assert_uint_eq(test_devs[idx].write_io_stats.size_total, device_parcel_cnt * NUVO_MAX_IO_SIZE);
        ck_assert_uint_gt(test_devs[idx].write_io_stats.latency_mean, 0);
        ck_assert(!isnan(test_devs[idx].write_io_stats.latency_stdev));

        ret = nuvo_pm_device_stats(test_devs[idx].uuid, NUVO_OP_READ, false, &test_devs[idx].read_io_stats);
        ck_assert_int_eq(ret, 0);

        printf("%s: device: %2d write count: %4lu size_total: %10lu latency_mean: %20f latency_stdev: %20f\n",
               __func__, idx, test_devs[idx].read_io_stats.count, test_devs[idx].read_io_stats.size_total, test_devs[idx].read_io_stats.latency_mean, test_devs[idx].read_io_stats.latency_stdev);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.count, device_parcel_cnt);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.size_total, device_parcel_cnt * NUVO_MAX_IO_SIZE);
        ck_assert_uint_gt(test_devs[idx].read_io_stats.latency_mean, 0);
        ck_assert(!isnan(test_devs[idx].read_io_stats.latency_stdev));
    }
}
END_TEST


START_TEST(nuvo_pm_test_parcel_alloc_invalid_fd)
{
    int ret;
    int idx = 0;
    int allocated = 0;
    int fd;

    printf("%s\n", __func__);

    struct nuvo_dlist submit_list;

    nuvo_dlist_init(&submit_list);

    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.device_size, test_devs[idx].device_size);
    ck_assert_int_eq(test_devs[idx].device_info.parcel_size, test_devs[idx].parcel_size);
    ck_assert_int_eq(test_devs[idx].device_info.device_type, test_devs[idx].device_type);

    /* corrupt the device file descriptor to cause io_submit to fail */
    fd = g_devices.devices[idx].fd;
    g_devices.devices[idx].fd = -1;

    /* attempt to allocates all parcels on the device. submits 1.5x more requests than necessary */
    int over_alloc = test_devs[idx].device_info.max_parcels + (test_devs[idx].device_info.max_parcels / 2);
    allocated = allocate_parcels(&test_devs[idx], over_alloc);
    ck_assert_int_eq(allocated, 0);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, allocated);

    g_devices.devices[idx].fd = fd;

}
END_TEST

START_TEST(nuvo_pm_test_parcel_write_read)
{
    int ret;
    int allocated;
    int read;
    int written;
    int freed;
    int idx = 0;
    int io_size;

    printf("%s\n", __func__);

    for (io_size = NUVO_BLOCK_SIZE; io_size <= NUVO_MAX_IO_SIZE; io_size = io_size * 2)
    {


        /* re-size the test device */
        test_devs[idx].device_size = (io_size * TEST_DEVICE_MAX_IOREQS) + (NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2);
        test_devs[idx].parcel_size = NUVO_PM_PARCEL_MIN_SIZE;
        ret = ftruncate(test_devs[idx].fd, test_devs[idx].device_size);
        ck_assert_int_eq(ret, 0);

        ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
        ck_assert_int_eq(ret, 0);

        ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
        ck_assert_int_eq(ret, 0);

        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);
        ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, 0);
        ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 0);

        allocated = allocate_parcels(&test_devs[idx], test_devs[idx].device_info.max_parcels);

        memset(&test_devs[idx].device_info, 0, sizeof(struct device_info));
        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);
        ck_assert_int_eq(allocated, test_devs[idx].device_info.parcels_allocated);
        ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, test_devs[idx].device_info.max_parcels);
        ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 1);

        ret = open_close_parcels(&test_devs[idx], allocated, NUVO_OP_OPEN);
        ck_assert_int_eq(ret, allocated);

        written = write_parcels(&test_devs[idx], io_size, allocated, DISCARD_BUFFERS);
        ck_assert_int_eq(written, ((test_devs[idx].device_info.parcel_size / io_size) * allocated));

        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);

        uint64_t total_write_io_size = written * io_size + NUVO_BLOCK_SIZE * allocated;

        ret = nuvo_pm_device_stats(test_devs[idx].uuid, NUVO_OP_WRITE, false, &test_devs[idx].write_io_stats);
        ck_assert_int_eq(ret, 0);

        printf("%s: device: %2d  write: count: %4lu  size_total: %10lu  latency_mean: %15f  latency_stdev: %15f\n",
               __func__, idx, test_devs[idx].write_io_stats.count, test_devs[idx].write_io_stats.size_total, test_devs[idx].write_io_stats.latency_mean, test_devs[idx].write_io_stats.latency_stdev);
        ck_assert_uint_eq(test_devs[idx].write_io_stats.count, allocated + written);
        ck_assert_uint_eq(test_devs[idx].write_io_stats.size_total, total_write_io_size);
        ck_assert_uint_gt(test_devs[idx].write_io_stats.latency_mean, 0);
        ck_assert(!isnan(test_devs[idx].write_io_stats.latency_stdev));


        ret = open_close_parcels(&test_devs[idx], allocated, NUVO_OP_CLOSE);
        ck_assert_int_eq(ret, allocated);

        ret = nuvo_pm_device_close(test_devs[idx].uuid);
        ck_assert_int_eq(ret, 0);

        ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
        ck_assert_int_eq(ret, 0);

        ret = open_close_parcels(&test_devs[idx], allocated, NUVO_OP_OPEN);
        ck_assert_int_eq(ret, allocated);

        read = read_parcels(&test_devs[idx], io_size, allocated, DISCARD_BUFFERS);
        ck_assert_int_eq(read, ((test_devs[idx].device_info.parcel_size / io_size) * allocated));

        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);

        ret = open_close_parcels(&test_devs[idx], allocated, NUVO_OP_CLOSE);
        ck_assert_int_eq(ret, allocated);

        freed = free_parcels(&test_devs[idx]);
        ck_assert_int_eq(allocated, freed);

        ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
        ck_assert_int_eq(ret, 0);
        ck_assert_int_eq(test_devs[idx].device_info.max_parcels, freed);
        ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, 0);
        ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 0);

        ret = nuvo_pm_device_stats(test_devs[idx].uuid, NUVO_OP_READ, false, &test_devs[idx].read_io_stats);
        ck_assert_int_eq(ret, 0);

        printf("%s: device: %2d   read: count: %4lu  size_total: %10lu  latency_mean: %15f  latency_stdev: %15f\n",
               __func__, idx, test_devs[idx].read_io_stats.count, test_devs[idx].read_io_stats.size_total, test_devs[idx].read_io_stats.latency_mean, test_devs[idx].read_io_stats.latency_stdev);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.count, read);
        ck_assert_uint_eq(test_devs[idx].read_io_stats.size_total, io_size * read);
        ck_assert_uint_gt(test_devs[idx].read_io_stats.latency_mean, 0);
        ck_assert(!isnan(test_devs[idx].read_io_stats.latency_stdev));

        idx++;
    }
}
END_TEST

START_TEST(nuvo_pm_test_parcel_alloc_and_free)
{
    int ret;
    int allocated;
    int freed;
    int idx = 0;

    printf("%s\n", __func__);

    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 0);

    allocated = allocate_parcels(&test_devs[idx], test_devs[idx].device_info.max_parcels);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, allocated);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, test_devs[idx].device_info.max_parcels);
    ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 1);

    freed = free_parcels(&test_devs[idx]);
    ck_assert_int_eq(allocated, freed);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.max_parcels, freed);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 0);

}
END_TEST

void nuvo_pm_test_setup(void)
{
    int fd;
    int ret = 0;

    ck_assert_int_eq(sem_init(&sem, 0, 0), 0);

    init_test_device_array();

    for (int i = 0; i < MAX_TEST_DEVICES; i++ )
    {
        char *name = &test_devs[i].name[0];
        strcpy(name, TEST_DEVICE_NAME_TEMPLATE);
        fd = mkstemp(name);
        ck_assert_int_ge(fd, 0);

        ret = ftruncate(fd, test_devs[i].device_size);
        test_devs[i].fd = fd;
        ck_assert_int_eq(ret, 0);

        uuid_generate(test_devs[i].uuid);
        for (int j = 0; j < MAX_TEST_VOLUMES; j++ )
        {
            uuid_generate(test_devs[i].volume_uuid[j]);
        }
    }

    /* initialize the parcel manager */
    ret = nuvo_pm_init();
    ck_assert_int_ge(ret, 0);
}

void nuvo_pm_test_teardown(void)
{
    int ret;

    /* initialize the parcel manager */
    ret = nuvo_pm_destroy();
    ck_assert_int_ge(ret, 0);

    for (int i = 0; i < MAX_TEST_DEVICES; i++ )
    {
        for (int j = 0;  j < TEST_DEVICE_MAX_IOREQS; j++)
        {
            for (int k = 0; k < NUVO_MAX_IO_BLOCKS; k++)
            {
                if (test_devs[i].op_read[j].io_req.rw.iovecs[k].iov_base)
                {
                    free(test_devs[i].op_read[j].io_req.rw.iovecs[k].iov_base);
                }
                if (test_devs[i].op_write[j].io_req.rw.iovecs[k].iov_base)
                {
                    free(test_devs[i].op_write[j].io_req.rw.iovecs[k].iov_base);
                }
            }
        }
        close(test_devs[i].fd);
        unlink(test_devs[i].name);
    }

    sem_destroy(&sem);
}

Suite * nuvo_pm_suite(void)
{
    Suite *s;
    TCase *tc_pm;

    s = suite_create("NuvoPM");

    tc_pm = tcase_create("NuvoPM");
    tcase_add_checked_fixture(tc_pm, nuvo_pm_test_setup, nuvo_pm_test_teardown);
    tcase_add_test(tc_pm, nuvo_pm_test_parcel_alloc_and_open_fail);
    tcase_add_test(tc_pm, nuvo_pm_test_parcel_alloc_and_free);
    tcase_add_test(tc_pm, nuvo_pm_test_parcel_alloc_invalid_fd);
    tcase_add_test(tc_pm, nuvo_pm_test_device_format);
    tcase_add_test(tc_pm, nuvo_pm_test_device_open);
    tcase_add_test(tc_pm, nuvo_pm_test_parcel_write_read);
    tcase_add_test(tc_pm, nuvo_pm_test_parcel_write_read_parallel);
    tcase_add_test(tc_pm, nuvo_pm_test_multi_device_open);

    suite_add_tcase(s, tc_pm);

    return s;
}
