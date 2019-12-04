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
#include <errno.h>
#include <fcntl.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <semaphore.h>

#include "cache.h"
#include "cache_priv.h"
#include "parcel_manager.h"
#include "parcel_manager_priv.h"
#include "nuvo_pr.h"
#include "nuvo.h"
#include "parallel.h"
#include "nuvo_vol_series.h"

UUID_DEFINE(node_uuid, 52, 48, 81, 19, 185, 24, 20, 141, 72, 211, 221, 54, 20, 191, 82, 84);
#define TEST_DEVICE_NAME_TEMPLATE        ("/tmp/nuvo_test_device.XXXXXX")
#define TEST_MAX_CACHE_DEVICES           (NUVO_CACHE_MAX_DEVICES)
#define TEST_MAX_VOLUMES                 (4)

//1536 is the number of usable blocks on the cache device (96 cache lines per device)
//Add 3 blocks per device so they don't have perfect alignment.
#define TEST_CACHE_DEVICE_OVERHEAD_BLOCKS ((NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2) / NUVO_BLOCK_SIZE)
#define TEST_CACHE_DEVICE_USABLE_SIZE_BLOCKS (1536 + 3)
static_assert(TEST_CACHE_DEVICE_USABLE_SIZE_BLOCKS % NUVO_CACHE_LINE_SIZE_BLOCKS > 0, "device size can't have perfect alignment");
#define TEST_CACHE_DEVICE_SIZE_BLOCKS    (TEST_CACHE_DEVICE_OVERHEAD_BLOCKS + TEST_CACHE_DEVICE_USABLE_SIZE_BLOCKS)
// Some tests expect the devices don't have perfect alignment and some do, makes sure everyone's happy.
// (16 < x < 64)
static_assert(NUVO_CACHE_LINE_SIZE_BLOCKS < (TEST_CACHE_DEVICE_SIZE_BLOCKS * (TEST_MAX_CACHE_DEVICES - 1)) % (NUVO_CACHE_LINE_SIZE_BLOCKS * NUVO_CACHE_TB_NUM_SETS_PER_ALLOCATION), "cache size is wrong");
#define TEST_CACHE_DEVICE_SIZE           (TEST_CACHE_DEVICE_SIZE_BLOCKS * NUVO_BLOCK_SIZE)

#define CL_TO_BYTES(x) ((uint64_t)(x) * NUVO_CACHE_LINE_SIZE_BLOCKS * NUVO_BLOCK_SIZE)

extern uint32_t cl_block_offset(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl);
extern uint32_t cl_parcel_desc(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl);
extern struct nuvo_cache_line *device_offset_to_cl(struct nuvo_cache_vol *cache_vol, uint32_t device_index, uint32_t block_offset);
extern int32_t cache_get_device_idx_by_parcel_desc(uint32_t parcel_desc);

struct test_vol
{
    struct nuvo_vol vol;
    uint64_t alloc_size_bytes;
};
struct test_vol test_vol[TEST_MAX_VOLUMES];

struct test_cache_device
{
    char   name[128];
    uint64_t size_bytes;
    uuid_t uuid;
    int    fd;
};
struct test_cache_device test_cache_dev[TEST_MAX_CACHE_DEVICES + 1];

/* fake volume index lookup */
unsigned int nuvo_vol_index_lookup(const struct nuvo_vol *vol)
{
    return ((struct test_vol *)vol - &test_vol[0]);
}

/* verifies the cache line to device and block address mapping. */
bool verify_cache_line_block_addresses(struct nuvo_cache_vol *cache_vol)
{
    nuvo_mutex_lock(&cache.mutex);
    for (uint32_t cl_pos = 0; cl_pos < cache_vol->num_cl; cl_pos++)
    {
        struct nuvo_cache_line *cl = cache_vol->tb + cl_pos;
        uint32_t parcel_desc = cl_parcel_desc(cache_vol, cl);
        uint32_t block_offset = cl_block_offset(cache_vol, cl);
        struct nuvo_cache_line *ret_cl = device_offset_to_cl(cache_vol, cache_get_device_idx_by_parcel_desc(parcel_desc), block_offset);
        assert(ret_cl == cl);
    }
    nuvo_mutex_unlock(&cache.mutex);
    return true;
}

bool test_verify_cl_block_addresses(struct test_vol *test_vol, unsigned num_vols)
{
    for (unsigned i = 0; i < num_vols; i++)
    {
        struct test_vol *t_vol = &test_vol[i];
        struct nuvo_cache_vol *cache_vol = &t_vol->vol.log_volume.cache_vol;
        ck_assert(verify_cache_line_block_addresses(cache_vol));
    }
    return true;
}

START_TEST(nuvo_cache_vol_alloc_fragmented_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);
    struct test_cache_device *cache_dev = &test_cache_dev[0];

    uint64_t alloc_unit_size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert(cache_dev->size_bytes != 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == cache_dev->size_bytes);

    uint64_t total_alloc_size_bytes = 0; // total number of cache lines allocated to volumes.
    uint32_t total_alloc_units = cache.cache_size_bytes / alloc_unit_size_bytes;
    printf("total cache lines = %u  cache lines available = %u total alloc units = %u\n", cache.cl_count, cache.cache_avail_cl_count, total_alloc_units);

    // create a volume and allocate 1/3 of the cache to it.
    // 00------
    struct test_vol *t_vol;
    t_vol = &test_vol[0];
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    t_vol->alloc_size_bytes = (total_alloc_units / 3) * alloc_unit_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    total_alloc_size_bytes += t_vol->alloc_size_bytes;
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 1);
    ck_assert(test_verify_cl_block_addresses(test_vol, 1));

    // create a volume and allocate 1/2 of the cache to it.
    // 00111---
    t_vol = &test_vol[1];
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    t_vol->alloc_size_bytes = (total_alloc_units / 2) * alloc_unit_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    total_alloc_size_bytes += t_vol->alloc_size_bytes;
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 1);
    ck_assert(test_verify_cl_block_addresses(test_vol, 2));

    // now release the first volume's cache to create a fragment
    // --111---
    t_vol = &test_vol[0];
    ret = nuvo_cache_vol_allocate(&t_vol->vol, 0);
    ck_assert_int_eq(ret, 0);
    total_alloc_size_bytes -= t_vol->alloc_size_bytes;
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 2);
    t_vol->alloc_size_bytes = 0;
    ck_assert(test_verify_cl_block_addresses(test_vol, 2));

    // create a volume and allocate the remaining cache to it.
    // 22111222
    t_vol = &test_vol[2];
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    t_vol->alloc_size_bytes = cache.cache_avail_cl_count * NUVO_CACHE_LINE_SIZE_BLOCKS * NUVO_BLOCK_SIZE;
    t_vol->alloc_size_bytes = CL_TO_BYTES(cache.cache_avail_cl_count);
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    total_alloc_size_bytes += t_vol->alloc_size_bytes;
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 0);
    ck_assert(test_verify_cl_block_addresses(test_vol, 3));

    // shrink volume 1 by 1 allocation unit (1/6) creating a free cache line.
    // 2211-222
    t_vol = &test_vol[1];
    t_vol->alloc_size_bytes = t_vol->alloc_size_bytes - alloc_unit_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    total_alloc_size_bytes -= alloc_unit_size_bytes;
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 1);
    ck_assert(test_verify_cl_block_addresses(test_vol, 3));

    // grow volume 2 by 1/6 to use the fragment.
    // the fragment will not be sequential to the others on media.
    // 22112222
    t_vol = &test_vol[2];
    t_vol->alloc_size_bytes = t_vol->alloc_size_bytes + alloc_unit_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    total_alloc_size_bytes += alloc_unit_size_bytes;
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 0);
    ck_assert(test_verify_cl_block_addresses(test_vol, 3));

    nuvo_cache_vol_destroy(&test_vol[0].vol);
    nuvo_cache_vol_destroy(&test_vol[1].vol);
    nuvo_cache_vol_destroy(&test_vol[2].vol);
    ck_assert_int_eq(cache.num_fragments, 1);
    ck_assert_int_eq(cache.cl_count, cache.cache_avail_cl_count);
}
END_TEST

START_TEST(nuvo_cache_vol_alloc_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);

    struct test_cache_device *cache_dev = NULL;
    uint64_t total_size_bytes = 0;
    uint64_t alloc_unit_size_bytes = 0;
    for (int i = 0; i < TEST_MAX_CACHE_DEVICES - 1; i++)
    {
        cache_dev = &test_cache_dev[i];
        ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
        ck_assert_int_eq(ret, 0);
        ck_assert(cache_dev->size_bytes != 0);
        ck_assert(alloc_unit_size_bytes != 0);
        total_size_bytes += cache_dev->size_bytes;
        ck_assert(cache.cache_size_bytes == total_size_bytes);
        ck_assert_int_eq(cache.num_fragments, 1);
    }

    uint64_t total_alloc_size_bytes = 0;
    uint32_t total_alloc_units = cache.cache_size_bytes / alloc_unit_size_bytes;
    printf("total cache lines = %u  cache lines available = %u total alloc units = %u\n", cache.cl_count, cache.cache_avail_cl_count, total_alloc_units);

    // the test assertions assume there will at least 1 cache line lost to alignment
    // note that cache.cl_count is rounded down.
    ck_assert_int_ne(cache.cache_size_bytes % alloc_unit_size_bytes, 0);

    // create a volume and allocate half of the cache to it.
    struct test_vol *t_vol;
    t_vol = &test_vol[0];
    t_vol->alloc_size_bytes = (total_alloc_units / 2) * alloc_unit_size_bytes;
    total_alloc_size_bytes += t_vol->alloc_size_bytes;
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(total_alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 1);

    // create another volume.
    t_vol = &test_vol[1];
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    // allocate 0 bytes to cache. (idempotent)
    t_vol->alloc_size_bytes = 0;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, 0);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(cache.num_fragments, 1);

    // allocate the entire cache to it. (fail).
    t_vol->alloc_size_bytes = total_alloc_units * alloc_unit_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, -NUVO_EINVAL);
    ck_assert_int_eq(cache.num_fragments, 1);

    // try a good value (rest of the cache).
    t_vol->alloc_size_bytes = (total_alloc_units - (total_alloc_units / 2)) * alloc_unit_size_bytes;
    total_alloc_size_bytes += t_vol->alloc_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(CL_TO_BYTES(cache.cache_avail_cl_count), CL_TO_BYTES(cache.cl_count) - total_alloc_size_bytes);
    // there should be one fragment left over due to unit size alignment
    ck_assert_int_lt(CL_TO_BYTES(cache.cache_avail_cl_count), alloc_unit_size_bytes);
    ck_assert_int_eq(cache.num_fragments, 1);

    // deallocate the cache of the first volume by setting its size to 0
    t_vol = &test_vol[0];
    total_alloc_size_bytes -= t_vol->alloc_size_bytes;
    t_vol->alloc_size_bytes = 0;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(CL_TO_BYTES(cache.cache_avail_cl_count), CL_TO_BYTES(cache.cl_count) - total_alloc_size_bytes);
    ck_assert_int_eq(cache.num_fragments, 2);

    // now resize the second volume to use the entire cache (aligned size).
    t_vol = &test_vol[1];
    t_vol->alloc_size_bytes = (cache.cache_size_bytes / alloc_unit_size_bytes) * alloc_unit_size_bytes;
    total_alloc_size_bytes += t_vol->alloc_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(CL_TO_BYTES(cache.cache_avail_cl_count), CL_TO_BYTES(cache.cl_count) - t_vol->alloc_size_bytes);
    // there should be one fragment left over due to unit size alignment
    ck_assert_int_lt(CL_TO_BYTES(cache.cache_avail_cl_count), alloc_unit_size_bytes);
    ck_assert_int_eq(cache.num_fragments, 1);

    // deallocate the cache by setting its size to 0
    t_vol->alloc_size_bytes = 0;
    total_alloc_size_bytes -= t_vol->alloc_size_bytes;
    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(cache.cache_avail_cl_count, cache.cl_count);
    ck_assert_int_eq(cache.num_fragments, 1);

    // attempt to add a new cache device (fail).
    cache_dev = &test_cache_dev[TEST_MAX_CACHE_DEVICES];
    alloc_unit_size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, -NUVO_E_DEVICE_NOT_USABLE);
    ck_assert(cache_dev->size_bytes == 0);
    ck_assert(alloc_unit_size_bytes != 0);

    nuvo_cache_vol_destroy(&test_vol[1].vol);
    nuvo_cache_vol_destroy(&test_vol[0].vol);
    ck_assert_int_eq(cache.num_fragments, 1);
    ck_assert_int_eq(cache.cl_count, cache.cache_avail_cl_count);
}
END_TEST

START_TEST(nuvo_use_cache_device_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);
    struct test_cache_device *cache_dev = &test_cache_dev[0];

    uint64_t alloc_unit_size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert(cache_dev->size_bytes != 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == cache_dev->size_bytes);
}
END_TEST

START_TEST(nuvo_use_multiple_cache_device_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);

    struct test_cache_device *cache_dev = NULL;
    uint64_t total_size_bytes = 0;
    uint64_t alloc_unit_size_bytes = 0;
    for (int i = 0; i < TEST_MAX_CACHE_DEVICES - 1; i++)
    {
        cache_dev = &test_cache_dev[i];
        ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
        ck_assert_int_eq(ret, 0);
        ck_assert(cache_dev->size_bytes != 0);
        ck_assert(alloc_unit_size_bytes != 0);
        total_size_bytes += cache_dev->size_bytes;
        ck_assert(cache.cache_size_bytes == total_size_bytes);
    }

    // try to add another device with an invalid size
    cache_dev = &test_cache_dev[TEST_MAX_CACHE_DEVICES];
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, -NUVO_E_DEVICE_NOT_USABLE);
    ck_assert(cache_dev->size_bytes == 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == total_size_bytes);

    // add the last device
    cache_dev = &test_cache_dev[TEST_MAX_CACHE_DEVICES - 1];
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert(cache_dev->size_bytes != 0);
    ck_assert(alloc_unit_size_bytes != 0);
    total_size_bytes += cache_dev->size_bytes;
    ck_assert(cache.cache_size_bytes == total_size_bytes);

   // try to add one too many
    cache_dev = &test_cache_dev[TEST_MAX_CACHE_DEVICES];
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, -NUVO_E_DEVICE_NOT_USABLE);
    ck_assert(cache_dev->size_bytes == 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == total_size_bytes);

}
END_TEST

START_TEST(nuvo_use_cache_device_idempotent_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);
    struct test_cache_device *cache_dev = &test_cache_dev[0];

    uint64_t alloc_unit_size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert(cache_dev->size_bytes != 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == cache_dev->size_bytes);

    uint64_t prev_size_bytes = cache_dev->size_bytes;
    uint64_t prev_alloc_unit_size_bytes = alloc_unit_size_bytes;
    cache_dev->size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, -NUVO_E_DEVICE_ALREADY_OPEN);
    ck_assert(cache_dev->size_bytes == prev_size_bytes);
    ck_assert(cache.cache_size_bytes == prev_size_bytes);
    ck_assert_uint_eq(prev_alloc_unit_size_bytes, alloc_unit_size_bytes);
}
END_TEST

/**
 * Insert and delete keys into the set associative mapping table and
 * verify the proper maintenance of the logical LRU list
 */
START_TEST(nuvo_cache_table_insert_invalidate_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);
    struct test_cache_device *cache_dev = &test_cache_dev[0];

    uint64_t alloc_unit_size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert(cache_dev->size_bytes != 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == cache_dev->size_bytes);

    uint32_t total_alloc_units = cache.cache_size_bytes / alloc_unit_size_bytes;
    printf("total cache lines = %u  cache lines available = %u total alloc units = %u\n", cache.cl_count, cache.cache_avail_cl_count, total_alloc_units);

    // create a volume and allocate entire cache to it
    struct test_vol *t_vol;
    t_vol = &test_vol[0];
    t_vol->alloc_size_bytes = total_alloc_units * alloc_unit_size_bytes;
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(t_vol->alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 0);

    // Only one cache device should default to 4 ways
    struct nuvo_cache_vol *cache_vol = &t_vol->vol.log_volume.cache_vol;
    ck_assert_int_eq(cache_vol->num_ways, 4);

    // Setup 8 keys that will be hashed into the same set
    union nuvo_cache_key test_key[8];
    for (int i=0; i < 8; i++)
    {
        test_key[i].block_key = (7 + (i * cache_vol->num_sets[0])) << NUVO_CACHE_LINE_SIZE_BITS;
    }

    struct nuvo_cache_line *cl;

    // Insert eight keys that will go into the same set
    for (int i=0; i < 8; i++)
    {
        // Verify key does not exist in table yet
        ck_assert(cache_tb_get(cache_vol, test_key[i]) == NULL);

        // Insert key into set
        cl = cache_tb_insert(cache_vol, test_key[i]);
        ck_assert(cl != NULL);
        ck_assert(cl->in_use == 1);
        ck_assert(cl->block_key == test_key[i].block_key);

        // Verify newest inserted key is at head of logical LRU list
        ck_assert(cl->lpos == 0);
    }

    // Verify expected state of the set: key (position on LRU)
    // Set content: {key4 (pos 3), key5 (pos 2), key6 (pos 1), key7 (pos 0)}
    // Key0 to key3 evicted
    struct nuvo_cache_line *set_cl = cache_tb_get_set(cache_vol, test_key[0].block_key, cache_vol->num_sets[cache_vol->num_hashes]);
    int expected_lpos = cache_vol->num_ways - 1;
    int j = 4;
    for (struct nuvo_cache_line *iter = set_cl;
         iter < set_cl + cache_vol->num_ways;
         iter++, expected_lpos--, j++)
    {
        ck_assert(iter->block_key == test_key[j].block_key);
        ck_assert(iter->lpos == expected_lpos);
    }

    // Test invalidating cache line
    // Delete key6
    cache_tb_invalidate(cache_vol, cache_tb_get(cache_vol, test_key[6]));

    // Verify set: {key4 (pos 2), key5 (pos 1), unused, key7 (pos 0)}
    cl = cache_tb_get(cache_vol, test_key[4]);
    ck_assert(cl->block_key == test_key[4].block_key);
    ck_assert(cl->lpos == 2);

    cl = cache_tb_get(cache_vol, test_key[5]);
    ck_assert(cl->block_key == test_key[5].block_key);
    ck_assert(cl->lpos == 1);

    // key6 should not exist now
    ck_assert(cache_tb_get(cache_vol, test_key[6]) == NULL);

    // key7 should have lpos 0
    cl = cache_tb_get(cache_vol, test_key[7]);
    ck_assert(cl->block_key == test_key[7].block_key);
    ck_assert(cl->lpos == 0);

    // Delete key7
    cache_tb_invalidate(cache_vol, cache_tb_get(cache_vol, test_key[7]));

    // Verify set: {key4 (pos 1), key5 (pos 0), unused, unused}
    cl = cache_tb_get(cache_vol, test_key[4]);
    ck_assert(cl->lpos == 1);
    cl = cache_tb_get(cache_vol, test_key[5]);
    ck_assert(cl->lpos == 0);

    // Delete key4
    cache_tb_invalidate(cache_vol, cache_tb_get(cache_vol, test_key[4]));

    // Verify set: {unused, key5 (pos 0), unused, unused}
    cl = cache_tb_get(cache_vol, test_key[5]);
    ck_assert(cl->lpos == 0);

    // Delete key5
    cache_tb_invalidate(cache_vol, cache_tb_get(cache_vol, test_key[5]));

    // Verify entire set is empty
    for (struct nuvo_cache_line *iter = set_cl;
         iter < set_cl + cache_vol->num_ways;
         iter++)
    {
        ck_assert(iter->in_use == 0);
    }

    nuvo_cache_vol_destroy(&test_vol[0].vol);

}
END_TEST

/**
 * Verify cache line selection behavior with pending I/O
 */
START_TEST(nuvo_cache_table_cl_io_pending_test)
{
    int64_t ret;

    printf("\n%s\n", __func__);
    struct test_cache_device *cache_dev = &test_cache_dev[0];

    uint64_t alloc_unit_size_bytes = 0;
    ret = nuvo_cache_device_open(cache_dev->name, cache_dev->uuid, &cache_dev->size_bytes, &alloc_unit_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert(cache_dev->size_bytes != 0);
    ck_assert(alloc_unit_size_bytes != 0);
    ck_assert(cache.cache_size_bytes == cache_dev->size_bytes);

    uint32_t total_alloc_units = cache.cache_size_bytes / alloc_unit_size_bytes;
    // Create a volume and allocate entire cache to it
    struct test_vol *t_vol;
    t_vol = &test_vol[0];
    t_vol->alloc_size_bytes = total_alloc_units * alloc_unit_size_bytes;
    ret = nuvo_cache_vol_init(&t_vol->vol);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_cache_vol_allocate(&t_vol->vol, t_vol->alloc_size_bytes);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(t_vol->alloc_size_bytes, CL_TO_BYTES(cache.cl_count - cache.cache_avail_cl_count));
    ck_assert_int_eq(cache.num_fragments, 0);

    // Only one cache device should default to 4 ways
    struct nuvo_cache_vol *cache_vol = &t_vol->vol.log_volume.cache_vol;
    ck_assert_int_eq(cache.num_fragments, 0);

    // Setup 6 keys that will be hashed into the same set
    union nuvo_cache_key test_key[6];
    for (int i=0; i < 6; i++)
    {
        test_key[i].block_key = (19 + (i * cache_vol->num_sets[0])) << NUVO_CACHE_LINE_SIZE_BITS;
    }

    struct nuvo_cache_line *cl;

    // Insert four keys that will go into the same set
    for (int i=0; i < cache_vol->num_ways; i++)
    {
        cl = cache_tb_insert(cache_vol, test_key[i]);
        ck_assert(cl->in_use == 1);
        ck_assert(cl->block_key == test_key[i].block_key);
    }

    // The set now has these keys:
    // {key0 (pos 3), key1 (pos 2), key2 (pos 1), key3 (pos 0)}

    // The next insert will use the cache line currently occupied by key0
    // as it is the LRU cache line in the set
    // Let's set key0 as having pending I/O so it cannot be evicted
    cl = cache_tb_get(cache_vol, test_key[0]);
    cl->rd_count = 1;

    // Do an insertion, verify it will evict key2 (the second lest recently
    // used cache line) instead of key0
    cl = cache_tb_insert(cache_vol, test_key[4]);

    // Verify expected set content: {key0 (pos 3), key4 (pos 0), key2 (pos 2), key3 (pos 1)}
    cl = cache_tb_get(cache_vol, test_key[0]);
    ck_assert(cl->lpos == 3);
    cl = cache_tb_get(cache_vol, test_key[4]);
    ck_assert(cl->lpos == 0);
    cl = cache_tb_get(cache_vol, test_key[2]);
    ck_assert(cl->lpos == 2);
    cl = cache_tb_get(cache_vol, test_key[3]);
    ck_assert(cl->lpos == 1);

    // Set all cache lines as having pending I/O
    for (struct nuvo_cache_line *cl = cache_tb_get_set(cache_vol, test_key[0].block_key, cache_vol->num_sets[cache_vol->num_hashes]);
         cl < cache_tb_get_set(cache_vol, test_key[0].block_key, cache_vol->num_sets[cache_vol->num_hashes]) + cache_vol->num_ways;
         cl++)
    {
        cl->wr_count++;
    }

    // Verify if all cache lines in set have pending I/O, cache_tb_insert() will return NULL
    cl = cache_tb_insert(cache_vol, test_key[5]);
    ck_assert(cl == NULL);

    nuvo_cache_vol_destroy(&test_vol[0].vol);
}
END_TEST

/* wrapper to initialized PR for test */
int64_t pr_test_setup(const uuid_t uuid, uint64_t port)
{
    int64_t ret = nuvo_pr_init(port);

    if (ret == 0)
    {
        nuvo_pr_set_node_uuid(uuid);
        nuvo_pr_enable(true);
    }
    return ret;
}

void nuvo_cache_test_setup(void)
{
    int64_t ret;

    /* initialize the parcel manager */
    ret = nuvo_pm_init();
    ck_assert_int_eq(ret, 0);

    /* initialize the parcel router */
    ret = pr_test_setup(node_uuid, 0);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_cache_init();
    ck_assert_int_eq(ret, 0);

    /* create TEST_MAX_CACHE_DEVICES fake cache devices, and an extra one with a different size */
    for (int i = 0; i <= TEST_MAX_CACHE_DEVICES; i++)
    {
        uint32_t size = (i != TEST_MAX_CACHE_DEVICES) ? TEST_CACHE_DEVICE_SIZE : TEST_CACHE_DEVICE_SIZE * 2;
        uuid_generate(test_cache_dev[i].uuid);
        strcpy(test_cache_dev[i].name, TEST_DEVICE_NAME_TEMPLATE);
        test_cache_dev[i].fd = mkstemp(test_cache_dev[i].name);
        test_cache_dev[i].size_bytes = 0;
        ret = ftruncate(test_cache_dev[i].fd, size);
        ck_assert_int_eq(ret, 0);
    }

    /* generate a uuids for the fake volumes */
    for (int i = 0; i <= TEST_MAX_VOLUMES; i++)
    {
        uuid_generate(test_vol[i].vol.vs_uuid);
        test_vol[i].alloc_size_bytes = 0;
    }
}

void nuvo_cache_test_teardown(void)
{
    int64_t ret;

    nuvo_cache_destroy();
    nuvo_pr_shutdown();

    ret = nuvo_pm_destroy();
    ck_assert_int_eq(ret, 0);

    for (int i = 0; i <= TEST_MAX_CACHE_DEVICES; i++)
    {
        close(test_cache_dev[i].fd);
        unlink(test_cache_dev[i].name);
    }
}

Suite *nuvo_cache_suite(void)
{
    Suite *s;
    TCase *tc_pm;

    s = suite_create("NuvoCache");
    tc_pm = tcase_create("NuvoCache");
    tcase_add_checked_fixture(tc_pm, nuvo_cache_test_setup, nuvo_cache_test_teardown);
    tcase_add_test(tc_pm, nuvo_use_cache_device_test);
    tcase_add_test(tc_pm, nuvo_use_cache_device_idempotent_test);
    tcase_add_test(tc_pm, nuvo_cache_vol_alloc_test);
    tcase_add_test(tc_pm, nuvo_cache_vol_alloc_fragmented_test);
    tcase_add_test(tc_pm, nuvo_use_multiple_cache_device_test);
    tcase_add_test(tc_pm, nuvo_cache_table_insert_invalidate_test);
    tcase_add_test(tc_pm, nuvo_cache_table_cl_io_pending_test);

    suite_add_tcase(s, tc_pm);

    return s;
}
