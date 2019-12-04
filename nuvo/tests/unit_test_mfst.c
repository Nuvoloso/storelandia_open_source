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

#include "../lun.h"
#include "../nuvo_pr_sync.h"
#include "../parcel_manager.h"
#include "../manifest.h"
#include "../manifest_priv.h"
#include "../segment.h"

#include "fake_pr.h"
#include "fake_rl.h"
#include "nuvo_ck_assert.h"

static struct {
    bool fail;
    uint16_t fail_after;
} aligned_alloc_control;

void mfst_tests_setup() {
    aligned_alloc_control.fail = false;
    aligned_alloc_control.fail_after = 0;
    fake_pr_init();
}

void mfst_tests_teardown() {
    fake_pr_teardown();
}

void *aligned_alloc(size_t alignment, size_t size)
{
    if (aligned_alloc_control.fail)
    {
        return NULL;
    }
    if (aligned_alloc_control.fail_after > 0)
    {
        aligned_alloc_control.fail_after--;
        if (aligned_alloc_control.fail_after == 0)
        {
            aligned_alloc_control.fail = true;
        }
    }
    void *ptr;
    (void) posix_memalign(&ptr, alignment, size);
    return ptr;
}

/* fake volume lookup */
struct nuvo_vol *nuvo_vol_lookup(const uuid_t vs_uuid)
{
    (void) vs_uuid;
    return NULL;
}

START_TEST(alloc_mfst)
{
    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_close(&mfst);
}
END_TEST

START_TEST(grow_devices_mem)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);
    nuvo_mfst_parcels_change_lock(&mfst);

    // Grow to hold one device.
    rc = nuvo_mfst_grow_devices_mem(&mfst, 1);
    ck_assert(rc == 0);
    ck_assert(mfst.header.num_used_devices == 0);
    ck_assert(mfst.header.num_device_blocks == 1);
    ck_assert(mfst.header.num_used_parcels == 0);
    ck_assert(mfst.header.num_parcel_blocks == 0);
    ck_assert(mfst.alloced_device_blocks == 1);
    for (uint32_t i = 0; i < NUVO_MFST_BLKS_TO_DEVICES(1); i++)
    {
        ck_assert(1 == uuid_is_null(mfst.device_state_media[i].device_uuid));
    }

    // Confirm that "growing" to a smaller number does nothing.
    rc = nuvo_mfst_grow_devices_mem(&mfst, NUVO_MFST_BLKS_TO_DEVICES(1));
    ck_assert(rc == 0);
    ck_assert(mfst.header.num_used_devices == 0);
    ck_assert(mfst.header.num_device_blocks == 1);
    ck_assert(mfst.header.num_used_parcels == 0);
    ck_assert(mfst.header.num_parcel_blocks == 0);
    ck_assert(mfst.alloced_device_blocks == 1);
    for (uint32_t i = 0; i < NUVO_MFST_BLKS_TO_DEVICES(1); i++)
    {
        ck_assert(1 == uuid_is_null(mfst.device_state_media[i].device_uuid));
    }

    // Grow into next block.
    rc = nuvo_mfst_grow_devices_mem(&mfst, NUVO_MFST_BLKS_TO_DEVICES(1) + 1);
    ck_assert(rc == 0);
    ck_assert(mfst.header.num_used_devices == 0);
    ck_assert(mfst.header.num_device_blocks == 2);
    ck_assert(mfst.header.num_used_parcels == 0);
    ck_assert(mfst.header.num_parcel_blocks == 0);
    ck_assert(mfst.alloced_device_blocks == 2);
    for (uint32_t i = 0; i < NUVO_MFST_BLKS_TO_DEVICES(2); i++)
    {
        ck_assert(1 == uuid_is_null(mfst.device_state_media[i].device_uuid));
    }

    // Test that we handle alloc failure.
    aligned_alloc_control.fail = true;
    rc = nuvo_mfst_grow_devices_mem(&mfst, NUVO_MFST_BLKS_TO_DEVICES(3));
    ck_assert(rc == -NUVO_ENOMEM);
    ck_assert(mfst.header.num_used_devices == 0);
    ck_assert(mfst.header.num_device_blocks == 2);
    ck_assert(mfst.header.num_used_parcels == 0);
    ck_assert(mfst.header.num_parcel_blocks == 0);
    ck_assert(mfst.alloced_device_blocks == 2);
    for (uint32_t i = 0; i < NUVO_MFST_BLKS_TO_DEVICES(2); i++)
    {
        ck_assert(1 == uuid_is_null(mfst.device_state_media[i].device_uuid));
    }

    nuvo_mfst_parcels_change_unlock(&mfst);
    nuvo_mfst_close(&mfst);
}
END_TEST

void check_expected_parcel_memory(struct nuvo_mfst *mfst, uint32_t n)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    uint_fast32_t num_parcel_blks = NUVO_MFST_PARCELS_TO_BLKS(n);
    uint_fast32_t num_parcel_alloced = NUVO_MFST_BLKS_TO_PARCELS(num_parcel_blks);
    ck_assert(mfst->header.num_used_parcels == 0);
    ck_assert(mfst->header.num_parcel_blocks == num_parcel_blks);
    ck_assert(mfst->alloced_parcel_blocks == num_parcel_blks);
    ck_assert(mfst->num_parcel_indices == num_parcel_alloced);
    ck_assert(n <= num_parcel_alloced);
    for (uint32_t i = 0; i < num_parcel_alloced; i++)
    {
        ck_assert(mfst->parcel_state_media[i].type == NUVO_MFST_PARCEL_ENTRY_UNUSED);
        ck_assert(mfst->parcel_state_mem[i].state == NUVO_MFST_PARCEL_NONE);
        ck_assert(mfst->parcel_state_mem[i].parcel_desc == 0);
        ck_assert(mfst->parcel_state_mem[i].segment_offset == 0);
    }
}

START_TEST(grow_parcels_mem)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);
    nuvo_mfst_parcels_change_lock(&mfst);

    // Grow to 1 parcel.
    rc = nuvo_mfst_grow_parcels_mem(&mfst, 1);
    ck_assert(rc == 0);
    check_expected_parcel_memory(&mfst, 1);
    // Grow by bock sized chunks.
    check_expected_parcel_memory(&mfst, NUVO_MFST_BLKS_TO_PARCELS(1));

    // Grow to 1 block of parcels
    rc = nuvo_mfst_grow_parcels_mem(&mfst, NUVO_MFST_BLKS_TO_PARCELS(1));
    ck_assert(rc == 0);
    check_expected_parcel_memory(&mfst, NUVO_MFST_BLKS_TO_PARCELS(1));

    // Grow to 5 blocks of parcels
    rc = nuvo_mfst_grow_parcels_mem(&mfst, NUVO_MFST_BLKS_TO_PARCELS(5));
    ck_assert(rc == 0);
    check_expected_parcel_memory(&mfst, NUVO_MFST_BLKS_TO_PARCELS(5));

    // Growing to a smaller size should not do anything.
    rc = nuvo_mfst_grow_parcels_mem(&mfst, NUVO_MFST_BLKS_TO_PARCELS(3));
    ck_assert(rc == 0);
    check_expected_parcel_memory(&mfst, NUVO_MFST_BLKS_TO_PARCELS(5));

    // Fail memory alloc.
    aligned_alloc_control.fail = true;
    rc = nuvo_mfst_grow_parcels_mem(&mfst, NUVO_MFST_BLKS_TO_PARCELS(5) + 1);
    ck_assert(rc == -NUVO_ENOMEM);
    check_expected_parcel_memory(&mfst, NUVO_MFST_BLKS_TO_PARCELS(5));

    nuvo_mfst_parcels_change_unlock(&mfst);
    nuvo_mfst_close(&mfst);
}
END_TEST

nuvo_return_t compare_device_to_mfst(struct nuvo_mfst *mfst,
                                     struct nuvo_mfst_insert_device_info *device)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    uint_fast32_t index;
    nuvo_mfst_in_core_lock(mfst);
    nuvo_return_t rc = nuvo_mfst_find_device_index(mfst, device->device_uuid, &index);
    nuvo_mfst_in_core_unlock(mfst);
    if (rc != 0)
    {
        ck_assert(rc == -NUVO_ENOENT);
        return rc;
    }
    ck_assert(0 == uuid_compare(device->device_uuid,
                                mfst->device_state_media[index].device_uuid));
    ck_assert(device->device_class == mfst->device_state_media[index].device_class);
    ck_assert(device->parcel_size_in_blocks == mfst->device_state_media[index].parcel_size_in_blocks);
    return 0;
}

START_TEST(insert_devices)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    struct nuvo_mfst_insert_device_info devices[400];
    uint_fast32_t num_to_alloc = NUVO_MFST_BLKS_TO_DEVICES(2);

    // Generate 2 blocks worth of devices.
    for (uint_fast32_t i = 0; i <= num_to_alloc; i++)
    {
        uuid_generate_random(devices[i].device_uuid);
        devices[i].device_class = i % NUVO_MAX_DATA_CLASSES;
        devices[i].parcel_size_in_blocks = devices[i].device_class * 1024*1024;
        devices[i].device_type = NUVO_DEV_TYPE_SSD;
    }

    // add 10, one at at time
    for (uint_fast32_t i = 0; i < 20; i+=2)
    {
        rc = nuvo_mfst_insert_device(&mfst, devices[i].device_uuid,
            devices[i].device_class, devices[i].device_type, devices[i].parcel_size_in_blocks);
        ck_assert(rc == 0);
    }

    for (uint_fast32_t i = 0; i < 20; i++)
    {
        rc = compare_device_to_mfst(&mfst, &devices[i]);
        if (i % 2)
        {
            ck_assert(rc == -NUVO_ENOENT);
        }
        else
        {
            ck_assert(rc == 0);
        }
    }
    ck_assert(mfst.header.num_used_devices == 10);
    ck_assert(mfst.header.num_device_blocks == NUVO_MFST_DEVICES_TO_BLKS(10));

    // Add the first 20 - this will include repeats
    rc = nuvo_mfst_insert_devices(&mfst, 20, devices);
    ck_assert(rc == 0);
    for (uint_fast32_t i = 0; i < 20; i++)
    {
        rc = compare_device_to_mfst(&mfst, &devices[i]);
        ck_assert(rc == 0);
    }
    ck_assert(mfst.header.num_used_devices == 20);
    ck_assert(mfst.header.num_device_blocks == NUVO_MFST_DEVICES_TO_BLKS(20));

    // Add the first 20 - this will include repeats
    rc = nuvo_mfst_insert_devices(&mfst, num_to_alloc, devices);
    ck_assert(rc == 0);
    for (uint_fast32_t i = 0; i < num_to_alloc; i++)
    {
        rc = compare_device_to_mfst(&mfst, &devices[i]);
        ck_assert(rc == 0);
    }
    ck_assert(mfst.header.num_used_devices == num_to_alloc);
    ck_assert(mfst.header.num_device_blocks == NUVO_MFST_DEVICES_TO_BLKS(num_to_alloc));

    // We added 2 blocks worth, so next will cause an alloc.
    aligned_alloc_control.fail = true;
    rc = nuvo_mfst_insert_devices(&mfst, 1, &devices[num_to_alloc]);
    ck_assert(rc == -NUVO_ENOMEM);

    // confirm all are still in right place
    ck_assert(mfst.header.num_used_devices == num_to_alloc);
    for (uint_fast32_t i = 0; i < num_to_alloc; i++)
    {
        rc = compare_device_to_mfst(&mfst, &devices[i]);
        ck_assert(rc == 0);
    }
    rc = compare_device_to_mfst(&mfst, &devices[num_to_alloc]);
    ck_assert(rc == -NUVO_ENOENT);

    // Add a list with the same device repeated.
    // Confirm that we only add one entry.
    aligned_alloc_control.fail = false;
    uuid_t repeat_uuid;
    uuid_generate_random(repeat_uuid);
    for (uint_fast32_t i = num_to_alloc; i < num_to_alloc + 4; i++)
    {
        uuid_copy(devices[i].device_uuid, repeat_uuid);
        devices[i].device_class = 0;
        devices[i].device_type = NUVO_DEV_TYPE_HDD;
        devices[i].parcel_size_in_blocks = 1024*1024;
    }
    rc = nuvo_mfst_insert_devices(&mfst, 4, &devices[num_to_alloc]);
    ck_assert(rc == 0);
    ck_assert(mfst.header.num_used_devices == num_to_alloc + 1);

    nuvo_mfst_close(&mfst);
}
END_TEST

START_TEST(insert_device_fails)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    struct nuvo_mfst_insert_device_info new_device;

    uuid_generate_random(new_device.device_uuid);
    new_device.device_class = NUVO_MAX_DATA_CLASSES;
    new_device.parcel_size_in_blocks = new_device.device_class * 1024*1024;
    new_device.device_type = NUVO_DEV_TYPE_SSD;

    rc = nuvo_mfst_insert_device(&mfst, new_device.device_uuid,
            new_device.device_class, new_device.device_type, new_device.parcel_size_in_blocks);
    ck_assert(rc == -NUVO_E_DEVICE_CLASS_BAD);

    rc = nuvo_mfst_insert_device(&mfst, new_device.device_uuid,
            NUVO_DATA_CLASS_A, new_device.device_type, new_device.parcel_size_in_blocks);
    ck_assert(rc == 0);

    rc = nuvo_mfst_insert_device(&mfst, new_device.device_uuid,
            NUVO_DATA_CLASS_B, new_device.device_type, new_device.parcel_size_in_blocks);
    ck_assert(rc == -NUVO_E_DEVICE_CLASS_CHANGED);

    nuvo_mfst_close(&mfst);
}
END_TEST

void make_parcel_req_for_device(struct nuvo_mfst_parcel_insert_info *req,
                                struct nuvo_mfst *mfst,
                                uint_fast32_t index,
                                uint_fast32_t segment_size_bytes)
{
    uuid_copy(req->device_uuid, mfst->device_state_media[index].device_uuid);
    req->segment_size_bytes = segment_size_bytes;
    req->number_segments = ((uint64_t) mfst->device_state_media[index].parcel_size_in_blocks * NUVO_BLOCK_SIZE) / req->segment_size_bytes;
}

// Insert parcels
START_TEST(insert_parcels)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    // First need some devices
    struct nuvo_mfst_insert_device_info devices[10];
    uint_fast32_t num_devices = 10;
    for (uint_fast32_t i = 0; i < num_devices; i++)
    {
        uuid_generate_random(devices[i].device_uuid);
        devices[i].device_class = i % NUVO_MAX_DATA_CLASSES;
        devices[i].device_type = NUVO_DEV_TYPE_HDD;
        devices[i].parcel_size_in_blocks = (devices[i].device_class + 1) * 512 * 1024;  // 2GB - 6GB
    }
    rc = nuvo_mfst_insert_devices(&mfst, 10, devices);
    ck_assert(rc == 0);

    struct nuvo_mfst_parcel_insert_info parcel;
    uuid_generate_random(parcel.parcel_uuid);
    parcel.pd = NUVO_VOL_PD_UNUSED;
    // Try inserting a parcel that has too many segments
    make_parcel_req_for_device(&parcel, &mfst, 3, NUVO_SEGMENT_MIN_SIZE_BYTES);
    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcel);
    ck_assert(rc == -NUVO_EINVAL);
    // Try inserting a parcel that has too few segments
    parcel.number_segments = 0;
    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcel);
    ck_assert(rc == -NUVO_EINVAL);
    // Try inserting a parcel with segments too big
    make_parcel_req_for_device(&parcel, &mfst, 3, NUVO_SEGMENT_MAX_SIZE_BYTES * 2);
    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcel);
    ck_assert(rc == -NUVO_EINVAL);
    // Try inserting with segments not multiple of chunks size.
    make_parcel_req_for_device(&parcel, &mfst, 3, NUVO_SEGMENT_MAX_SIZE_BYTES - 2);
    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcel);
    ck_assert(rc == -NUVO_EINVAL);
    // Try inserting device with segments of size 0.
    make_parcel_req_for_device(&parcel, &mfst, 3, NUVO_SEGMENT_MAX_SIZE_BYTES);
    parcel.segment_size_bytes = 0;
    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcel);
    ck_assert(rc == -NUVO_EINVAL);
    // Try inserting device with too much segment space for device.
    make_parcel_req_for_device(&parcel, &mfst, 3, NUVO_SEGMENT_MAX_SIZE_BYTES);
    parcel.number_segments++;
    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcel);
    ck_assert(rc == -NUVO_EINVAL);


    // Now let's build some some parcels to add for real.
    uint_fast32_t num_parcels = 0;
    struct nuvo_mfst_parcel_insert_info parcels[1000];

    struct nuvo_mfst_parcel_insert_info parcels_to_add[1000];
    // adding 10 over first 6 devices.
    uint_fast32_t num_to_alloc = 20;
    for (uint_fast32_t i = 0; i < num_to_alloc; i++)
    {
        uuid_generate_random(parcels_to_add[i].parcel_uuid);
        parcels_to_add[i].pd = NUVO_VOL_PD_UNUSED;
        make_parcel_req_for_device(&parcels_to_add[i], &mfst, i % 4, NUVO_SEGMENT_MAX_SIZE_BYTES);
    }

    rc = nuvo_mfst_insert_parcels(&mfst, num_to_alloc, parcels_to_add);
    ck_assert(rc == 0);

    for (uint_fast32_t i = 0; i < num_to_alloc; i++, num_parcels++)
    {
        memcpy(&parcels[num_parcels], &parcels_to_add[i], sizeof(parcels[num_parcels]));
    }
    ck_assert(mfst.header.num_used_parcels == num_parcels);

    // Try re-adding a parcel.
    rc = nuvo_mfst_insert_parcels(&mfst, 1, parcels_to_add);
    ck_assert(rc == -NUVO_EEXIST);
    ck_assert(mfst.header.num_used_parcels == num_parcels);

    nuvo_mfst_in_core_lock(&mfst);
    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        uint_fast32_t parcel_index;
        rc = nuvo_mfst_find_parcel_index(&mfst, parcels[i].parcel_uuid, &parcel_index);
        ck_assert(rc == 0);
        ck_assert(mfst.parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_PARCEL);
        uint_fast32_t device_index = mfst.parcel_state_media[parcel_index].normal.device_idx;
        ck_assert(0 == uuid_compare(parcels[i].parcel_uuid, mfst.parcel_state_media[parcel_index].normal.parcel_uuid));
        ck_assert(0 != mfst.device_state_media[device_index].alloced_parcels);
        ck_assert(mfst.device_state_media[device_index].parcel_size_in_blocks * NUVO_BLOCK_SIZE >=
                    parcels[i].segment_size_bytes * parcels[i].number_segments);
        ck_assert(0 == uuid_compare(parcels[i].device_uuid, mfst.device_state_media[device_index].device_uuid));
        ck_assert(parcels[i].segment_size_bytes == nuvo_mfst_parcel_segment_size_get(&mfst, parcel_index));
        ck_assert(parcels[i].number_segments == nuvo_mfst_parcel_segment_number_get(&mfst, parcel_index));
    }
    nuvo_mfst_in_core_unlock(&mfst);
    nuvo_mfst_free_manifest(&mfst);   // TODO - nuvo_mfst_close?
}
END_TEST

/*
 * Goal of this test is to start with realtively limited space, and then
 * try to allocate parcels and devices, and ensure we don't grow larger than
 * the available space.
 */
START_TEST(insert_parcels_devices_limit)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    // 5 blocks = 1 header + 2 lun + 1 dev + 1 parcel
    nuvo_sb_init(&sb, vol_uuid, 5, 128);

    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    // First need some devices and parcels.
    struct nuvo_mfst_insert_device_info devices[500];
    uint_fast32_t num_devices = 500;
    struct nuvo_mfst_parcel_insert_info parcels_to_add[500];
    struct nuvo_mfst_parcel_insert_info *next_parcel;
    uint_fast32_t num_parcels = 500;

    for (uint_fast32_t i = 0; i < num_devices; i++)
    {
        uuid_generate_random(devices[i].device_uuid);
        devices[i].device_class = i % NUVO_MAX_DATA_CLASSES;
        devices[i].device_type = NUVO_DEV_TYPE_HDD;
        devices[i].parcel_size_in_blocks = (devices[i].device_class + 1) * 256 *1024;  // 1-4GB
    }
    rc = nuvo_mfst_insert_devices(&mfst, 10, devices);
    ck_assert(rc == 0);

    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        uuid_generate_random(parcels_to_add[i].parcel_uuid);
        parcels_to_add[i].pd = NUVO_VOL_PD_UNUSED;
        make_parcel_req_for_device(&parcels_to_add[i], &mfst, devices[i].device_class, NUVO_SEGMENT_MAX_SIZE_BYTES);
    }

    // Have enough space for a few of each.
    rc = nuvo_mfst_insert_parcels(&mfst, 10, parcels_to_add);
    ck_assert(rc == 0);
    next_parcel = parcels_to_add + 10;

    rc = nuvo_mfst_insert_devices(&mfst, NUVO_MFST_BLKS_TO_DEVICES(1), devices);
    ck_assert(rc == 0);
    rc = nuvo_mfst_insert_parcels(&mfst, NUVO_MFST_BLKS_TO_PARCELS(1) - 10, next_parcel);
    ck_assert(rc == 0);
    next_parcel += NUVO_MFST_BLKS_TO_PARCELS(1) - 10;

    rc = nuvo_mfst_insert_devices(&mfst, NUVO_MFST_BLKS_TO_DEVICES(1) + 1, devices);
    ck_assert(rc == -ENOSPC);
    rc = nuvo_mfst_insert_parcels(&mfst, 1 , next_parcel);
    ck_assert(rc == -ENOSPC);

    // TODO: test segment limits.

    nuvo_mfst_free_manifest(&mfst);   // TODO - nuvo_mfst_close?
}
END_TEST

// Test copies of the segments data.
struct parcel_segments {
    uint32_t offsets[16];
    struct nuvo_mfst_segment_entry segments[16];
};

void validate_segments(struct nuvo_mfst *mfst,
                       uint_fast32_t num_parcels,
                       struct nuvo_mfst_parcel_insert_info *parcels,
                       struct parcel_segments *parcel_segments)
{
    nuvo_mfst_in_core_lock(mfst);
    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        if (uuid_is_null(parcels[i].parcel_uuid))
        {
            continue;
        }
        for (uint_fast32_t seg = 0; seg < parcels[i].number_segments; seg++)
        {
            // shouldn't used i as parcel index
            uint_fast32_t parcel_index;
            (void) nuvo_mfst_find_parcel_index(mfst, parcels[i].parcel_uuid, &parcel_index);

            uint_fast32_t seg_idx = nuvo_mfst_seg_idx(mfst, parcel_index, parcel_segments[i].offsets[seg]);
            if (parcel_segments[i].segments[seg].seg_age != mfst->segment_state_media[seg_idx].seg_age) {
                 ck_assert(parcel_segments[i].segments[seg].seg_age == mfst->segment_state_media[seg_idx].seg_age);
            }
            ck_assert(parcel_segments[i].segments[seg].seg_blks_used == mfst->segment_state_media[seg_idx].seg_blks_used);
            ck_assert(parcel_segments[i].segments[seg].seg_reserved == 0);
        }
    }
    nuvo_mfst_in_core_unlock(mfst);
}

void clear_parcel_blks(struct nuvo_mfst *mfst,
                       struct nuvo_mfst_parcel_insert_info *parcel,
                       struct parcel_segments *parcel_segment)
{
    uint_fast32_t parcel_index;
    nuvo_return_t rc;
    rc = nuvo_mfst_find_parcel_index(mfst, parcel->parcel_uuid, &parcel_index);
    ck_assert(rc == 0);
    for (uint_fast32_t seg = 0; seg < parcel->number_segments; seg++) {
        uint_fast32_t seg_idx = nuvo_mfst_seg_idx(mfst, parcel_index, parcel_segment->offsets[seg]);
        mfst->segment_state_media[seg_idx].seg_blks_used = 0;
        mfst->segment_state_media[seg_idx].seg_age = 0;
    }
}

void init_segment(struct nuvo_mfst *mfst,
                  struct parcel_segments *parcel_segment,
                  uint_fast32_t seg_size,
                  uint_fast32_t seed,
                  uint_fast32_t number_segments)
{
    for (uint_fast32_t seg = 0; seg < number_segments; seg++)
    {
        ck_assert(number_segments <= 16);
        parcel_segment->offsets[seg] = seg * seg_size / NUVO_BLOCK_SIZE;
        parcel_segment->segments[seg].seg_age = seed * 1000 + seg;
        parcel_segment->segments[seg].seg_blks_used = 100 * seed + seg;
        parcel_segment->segments[seg].seg_reserved = 0;
        nuvo_mfst_in_core_lock(mfst);
        uint_fast32_t seg_idx = nuvo_mfst_seg_idx(mfst, seed, parcel_segment->offsets[seg]);
        mfst->segment_state_media[seg_idx].seg_age = parcel_segment->segments[seg].seg_age;
        mfst->segment_state_media[seg_idx].seg_blks_used = parcel_segment->segments[seg].seg_blks_used;
        nuvo_mfst_in_core_unlock(mfst);
    }
}

START_TEST(segment_table)
{
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);
    struct nuvo_mfst mfst;

    uint32_t test_parcel_size_blocks = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 16;

    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    // TEST SETUP
    // First need a device
    struct nuvo_mfst_insert_device_info device;
    uuid_generate_random(device.device_uuid);
    device.device_class = NUVO_DATA_CLASS_A;
    device.device_type = NUVO_DEV_TYPE_SSD;
    device.parcel_size_in_blocks = test_parcel_size_blocks;
    rc = nuvo_pm_device_format("blah", device.device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device.device_uuid, device.device_type);
    ck_assert(rc == 0);
    rc = nuvo_mfst_insert_devices(&mfst, 1, &device);
    ck_assert(rc == 0);

    uint_fast32_t num_parcels = 100;
    struct nuvo_mfst_parcel_insert_info parcels[100];
    struct parcel_segments parcel_segments[100];
    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        // 1,2,4,8 or 16 segments.
        make_parcel_req_for_device(&parcels[i], &mfst, 0,
                test_parcel_size_blocks * NUVO_BLOCK_SIZE / (1 << (i % 5)));
        uuid_clear(parcels[i].parcel_uuid);
        parcels[i].pd = NUVO_VOL_PD_UNUSED;
        rc = nuvo_pr_sync_parcel_alloc(parcels[i].parcel_uuid,
                                       device.device_uuid,
                                       vol_uuid);
        ck_assert(rc == 0);
    }
    // Have enough space for a few of each.
    rc = nuvo_mfst_insert_parcels(&mfst, num_parcels, parcels);
    ck_assert(rc == 0);

    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        init_segment(&mfst, &parcel_segments[i], parcels[i].segment_size_bytes, i, parcels[i].number_segments);
    }

    validate_segments(&mfst, num_parcels, parcels, parcel_segments);

    // Set up by remove a parcel that is in use, then stop using.
    rc = nuvo_mfst_remove_parcels(&mfst, 1, &parcels[2].parcel_uuid, false);
    ck_assert(rc == - NUVO_E_PARCEL_IN_USE);
    nuvo_mfst_parcels_change_lock(&mfst);
    clear_parcel_blks(&mfst, &parcels[2], &parcel_segments[2]);
    nuvo_mfst_parcels_change_unlock(&mfst);
    rc = nuvo_mfst_remove_parcels(&mfst, 1, &parcels[2].parcel_uuid, false);
    assert(rc == 0);
    uuid_clear(parcels[2].parcel_uuid);

    validate_segments(&mfst, num_parcels, parcels, parcel_segments);

    uuid_t random_parcel;
    uuid_generate_random(random_parcel);
    rc = nuvo_mfst_remove_parcels(&mfst, 1, &random_parcel, false);
    ck_assert(rc == -NUVO_ENOENT);

    nuvo_mfst_in_core_lock(&mfst);
        //Setting up some map operations.
        struct nuvo_map_entry map[3];
        uint_fast32_t parcel_index;
        map[0].type = NUVO_ME_MEDIA;
        map[0].cow  = NUVO_MAP_ENTRY_NONE;
        nuvo_mfst_find_parcel_index(&mfst, parcels[4].parcel_uuid, &parcel_index);
        map[0].media_addr.parcel_index = parcel_index;
        map[0].media_addr.block_offset = 0;

        map[1].type = NUVO_ME_CONST;
        map[1].cow  = NUVO_MAP_ENTRY_NONE;
         nuvo_mfst_find_parcel_index(&mfst, parcels[5].parcel_uuid, &parcel_index);
        map[1].media_addr.parcel_index = parcel_index;
        map[1].media_addr.block_offset = 0;

        map[2].type = NUVO_ME_MEDIA;
        map[2].cow  = NUVO_MAP_ENTRY_NONE;
        nuvo_mfst_find_parcel_index(&mfst, parcels[6].parcel_uuid, &parcel_index);
        map[2].media_addr.parcel_index = parcel_index;
        map[2].media_addr.block_offset =
            parcel_segments[6].offsets[parcels[6].number_segments - 1];

        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[0].media_addr.parcel_index, map[0].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[1].media_addr.parcel_index, map[1].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[2].media_addr.parcel_index, map[2].media_addr.block_offset));
    nuvo_mfst_in_core_unlock(&mfst);

    // Try pin and open.  Won't work because the parcels are not yet usable - we haven't written out manifest.
    uint_fast32_t parcel_descs[3];
    rc = nuvo_mfst_pin_open(&mfst, 3, map, parcel_descs);
    ck_assert(rc == -NUVO_E_PARCEL_UNUSABLE);

    // Pretend we wrote it out.
    nuvo_mfst_freeze_at_seqno(&mfst, 5);
    nuvo_mfst_writing_thaw(&mfst);

    // Do pin and open. This should open parcels and return descriptors.
    // Make sure the actual parcels got used, while the entry that was not media was ignored.
    rc = nuvo_mfst_pin_open(&mfst, 3, map, parcel_descs);
    ck_assert(rc == 0);
    ck_assert(parcel_descs[0] != NUVO_VOL_PD_UNUSED);
    ck_assert(fake_pr_parcel_descriptor_valid(parcel_descs[0]));
    ck_assert(parcel_descs[1] == NUVO_VOL_PD_UNUSED);
    ck_assert(parcel_descs[2] != NUVO_VOL_PD_UNUSED);
    ck_assert(fake_pr_parcel_descriptor_valid(parcel_descs[2]));

    nuvo_mfst_in_core_lock(&mfst);
        // Checking results.
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, map[0].media_addr.parcel_index, map[0].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[1].media_addr.parcel_index, map[1].media_addr.block_offset));
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, map[2].media_addr.parcel_index, map[2].media_addr.block_offset));
    nuvo_mfst_in_core_unlock(&mfst);

    // Do another pin and make sure we get back the same parcel descriptors (no re-opens)
    uint_fast32_t parcel_descs_repeat[3];
    rc = nuvo_mfst_pin_open(&mfst, 3, map, parcel_descs_repeat);
    ck_assert(rc == 0);
    ck_assert(parcel_descs[0] == parcel_descs_repeat[0]);
    ck_assert(parcel_descs[1] == parcel_descs_repeat[1]);
    ck_assert(parcel_descs[2] == parcel_descs_repeat[2]);

    nuvo_mfst_in_core_lock(&mfst);
        // Checking results.
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, map[0].media_addr.parcel_index, map[0].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[1].media_addr.parcel_index, map[1].media_addr.block_offset));
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, map[2].media_addr.parcel_index, map[2].media_addr.block_offset));
    nuvo_mfst_in_core_unlock(&mfst);

    // Check that the first un-pin of each works, but leaves segments pinned.
    nuvo_mfst_unpin(&mfst, 3, map);
    nuvo_mfst_in_core_lock(&mfst);
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, map[0].media_addr.parcel_index, map[0].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[1].media_addr.parcel_index, map[1].media_addr.block_offset));
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, map[2].media_addr.parcel_index, map[2].media_addr.block_offset));
    nuvo_mfst_in_core_unlock(&mfst);

    // Check that the second up-pin works and leaves segments unpinned.
    nuvo_mfst_unpin(&mfst, 3, map);
    nuvo_mfst_in_core_lock(&mfst);
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[0].media_addr.parcel_index, map[0].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[1].media_addr.parcel_index, map[1].media_addr.block_offset));
        ck_assert(!nuvo_segment_io_pin_count_get(&mfst, map[2].media_addr.parcel_index, map[2].media_addr.block_offset));
    nuvo_mfst_in_core_unlock(&mfst);
    validate_segments(&mfst, num_parcels, parcels, parcel_segments);

    // Now insert a new 2 - this will take the vacated slot.
    parcels[2].number_segments = 16;
    parcels[2].segment_size_bytes = test_parcel_size_blocks * NUVO_BLOCK_SIZE / parcels[2].number_segments;
    uuid_clear(parcels[2].parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(parcels[2].parcel_uuid, device.device_uuid, vol_uuid);
    ck_assert(rc == 0);

    rc = nuvo_mfst_insert_parcels(&mfst, 1, &parcels[2]);
    ck_assert(rc == 0);

    init_segment(&mfst, &parcel_segments[2], parcels[2].segment_size_bytes, 2, parcels[2].number_segments);

    validate_segments(&mfst, num_parcels, parcels, parcel_segments);

    // Free blocks.
    nuvo_mfst_segment_free_blks(&mfst, 3, map);


    // Hmmm.   Don't assert, or do this test.  Choose.
#if 0
    struct nuvo_map_entry map_out_of_range;

    map_out_of_range.type = NUVO_ME_MEDIA;
    map_out_of_range.media_addr.parcel_index = mfst.num_parcel_indices;
    map_out_of_range.media_addr.block_offset = 0;
    uint_fast32_t no_pd;
    rc = nuvo_mfst_pin_open(&mfst, 1, &map_out_of_range, &no_pd);
    ck_assert(rc == -NUVO_E_PARCEL_RANGE);
#endif

    // TODO cross-check the actual numbers.
    nuvo_mfst_free_manifest(&mfst);   // TODO - nuvo_mfst_close?
}
END_TEST

// Open parcels, close parcels.
START_TEST(open_close_parcels)
{
    uuid_t vol_uuid;
    uint32_t num_devices = 2;
    uuid_t device_uuid[2];
    uint32_t num_parcels = 6;
    uuid_t parcel_uuid[6];

    /*
     * Build devices and some parcels.
     */
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);

    /*
     * Now need a manifest.
     */
    struct nuvo_mfst mfst;
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    // First need some devices
    for (uint_fast32_t i = 0; i < num_devices; i++)
    {
        uuid_generate(device_uuid[i]);
        rc = nuvo_pm_device_format("blah", device_uuid[i], 32*1024*1024);
        ck_assert(rc == 0);
        rc = nuvo_pm_device_open("blah", device_uuid[i], NUVO_DEV_TYPE_SSD);
        ck_assert(rc == 0);
        rc = nuvo_mfst_insert_device(&mfst, device_uuid[i], NUVO_DATA_CLASS_A, NUVO_DEV_TYPE_SSD, 32*1024*1024/NUVO_BLOCK_SIZE);
        ck_assert(rc == 0);
    }
    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        uuid_generate_random(parcel_uuid[i]);
        rc = nuvo_pr_sync_parcel_alloc(parcel_uuid[i], device_uuid[i % num_devices], vol_uuid);
        ck_assert(rc == 0);
        uint16_t num_segments_added = 0;
        uint8_t data_class_added;
        rc = nuvo_mfst_insert_parcel(&mfst,
                                    device_uuid[i % num_devices],
                                    parcel_uuid[i],
                                    4*1024*1024,
                                   &num_segments_added,
                                   &data_class_added,
                                    NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);
        ck_assert(data_class_added == NUVO_DATA_CLASS_A);
    }

    // Haven't written out manifest, so parcels are UNUSABLE
    for (uint_fast32_t i = 0 ; i < num_parcels; i++)
    {
        uint_fast32_t parcel_desc;
        rc = nuvo_mfst_open_parcel_sync(&mfst, i, &parcel_desc);
        ck_assert(rc == -NUVO_E_PARCEL_UNUSABLE);
    }
    // pretend we wrote this out.
    nuvo_mfst_freeze_at_seqno(&mfst, 5);
    nuvo_mfst_writing_thaw(&mfst);
    for (uint_fast32_t i = 0 ; i < num_parcels; i++)
    {
        uint_fast32_t parcel_desc;
        rc = nuvo_mfst_open_parcel_sync(&mfst, i, &parcel_desc);
        ck_assert(rc == 0);
    }

    // Check and make sure we cannot remove an open parcel.
    rc = nuvo_mfst_remove_parcels(&mfst, 1, &parcel_uuid[0], false);
    ck_assert(rc == - NUVO_E_PARCEL_IN_USE);

    // Now close.
    for (uint_fast32_t i = 0 ; i < num_parcels; i++)
    {
        rc = nuvo_mfst_close_parcel(&mfst, i);
        ck_assert(rc == 0);
    }

    // Now let's send three separate OPENs at the same time.  Should handle properly.
    fake_pr_suspend_replies();

    nuvo_mutex_t sync_signal[3];
    struct nuvo_mfst_open_parcel open[3];
    for (unsigned int i = 0; i < 3; i++)
    {
        ck_assert(0 == nuvo_mutex_init(&sync_signal[i]));
        open[i].mfst = &mfst;
        open[i].idx = 2;
        open[i].callback = nuvo_mfst_open_parcel_sync_cb;
        open[i].tag.ptr = &sync_signal[i];
        nuvo_mutex_lock(&sync_signal[i]);
        nuvo_mfst_open_parcel_start(&open[i]);
    }

    fake_pr_unsuspend_replies();

    for (unsigned int i = 0; i < 3; i++)
    {
        // By nature of the fake, this lock unlock dance is unnecessary....
        nuvo_mutex_lock(&sync_signal[i]);
        nuvo_mutex_unlock(&sync_signal[i]);
        nuvo_mutex_destroy(&sync_signal[i]);
        ck_assert(open[i].status == 0);
    }
    ck_assert(fake_pr_get_last_descriptor() == open[0].parcel_desc);
    ck_assert(open[0].parcel_desc == open[1].parcel_desc);
    ck_assert(open[0].parcel_desc == open[2].parcel_desc);

    // Check that another open still gives back same result.
    uint_fast32_t parcel_desc;
    rc = nuvo_mfst_open_parcel_sync(&mfst, 2, &parcel_desc);
    ck_assert(rc == 0);
    ck_assert(parcel_desc == open[0].parcel_desc);

    // Add a nonexistent parcel and then try to open it.
    uuid_t nonexistent_parcel;
    uuid_generate_random(nonexistent_parcel);
    uint16_t num_segments_added = 0;
    uint8_t data_class_added;
    rc = nuvo_mfst_insert_parcel(&mfst,
                                 device_uuid[0],
                                 nonexistent_parcel,
                                 4*1024*1024,
                                &num_segments_added,
                                &data_class_added,
                                 NUVO_VOL_PD_UNUSED);

    ck_assert(rc == 0);
    ck_assert(data_class_added == NUVO_DATA_CLASS_A);

    // pretend we wrote this out.
    nuvo_mfst_freeze_at_seqno(&mfst, 5);
    nuvo_mfst_writing_thaw(&mfst);

    uint_fast32_t parcel_index;
    nuvo_mfst_in_core_lock(&mfst);
    rc = nuvo_mfst_find_parcel_index(&mfst, nonexistent_parcel, &parcel_index);
    nuvo_mfst_in_core_unlock(&mfst);
    ck_assert(rc == 0);
    rc = nuvo_mfst_open_parcel_sync(&mfst, parcel_index, &parcel_desc);
    ck_assert(rc != 0);
    ck_assert(mfst.parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_USABLE);

    nuvo_mfst_close(&mfst);
}
END_TEST

/*
 * Test reading and writing the superblock,
 * and making sure that we properly handle cases of bad hash.
 */
START_TEST(super_block)
{
    // First let's create a device.
    uuid_t device_uuid, parcel_uuid, vol_uuid;
    uuid_generate(device_uuid);
    uuid_generate(parcel_uuid);
    uuid_generate(vol_uuid);
    // Set up the device, parcel and parcel descriptor
    nuvo_return_t rc = nuvo_pm_device_format("blah", device_uuid, 64*1024*1024);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    ck_assert(rc == 0);

    uuid_clear(parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    uint_fast32_t pd;
    rc = nuvo_pr_sync_parcel_open(&pd, parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);

    uint8_t *parcel_data = fake_pr_parcel_data(pd);
    memset(parcel_data, 0 , 2 * NUVO_BLOCK_SIZE);

    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);
    rc = nuvo_sb_sync_write(&sb, pd);
    ck_assert(rc == 0);

    struct nuvo_sb_superblock sb_read;
    rc = nuvo_sb_sync_read(&sb_read, pd);
    ck_assert(rc == 0);
    ck_assert(0 == memcmp(&sb, &sb_read, sizeof(sb)));
    ck_assert(sb.generation == 1);

    rc = nuvo_sb_sync_write(&sb, pd);
    ck_assert(rc == 0);
    rc = nuvo_sb_sync_read(&sb_read, pd);
    ck_assert(rc == 0);
    ck_assert(0 == memcmp(&sb, &sb_read, sizeof(sb)));
    ck_assert(sb.generation == 2);

    // scribble on even block, read should return block 1.
    parcel_data[16] = ~parcel_data[NUVO_SB_BLOCK_OFFSET_0 * NUVO_BLOCK_SIZE + 16];
    rc = nuvo_sb_sync_read(&sb_read, pd);
    ck_assert(rc == 0);
    ck_assert(sb_read.generation == 1);

    // three more writes to get good blocks out.
    rc = nuvo_sb_sync_write(&sb, pd);
    ck_assert(rc == 0);
    rc = nuvo_sb_sync_write(&sb, pd);
    ck_assert(rc == 0);
    rc = nuvo_sb_sync_write(&sb, pd);
    ck_assert(rc == 0);
    ck_assert(sb.generation == 5);
    rc = nuvo_sb_sync_read(&sb_read, pd);
    ck_assert(rc == 0);
    ck_assert(sb_read.generation == 5);
    //scibble on odd block, read should return 4.
    parcel_data[NUVO_SB_BLOCK_OFFSET_1 * NUVO_BLOCK_SIZE + 16] =
        ~parcel_data[NUVO_SB_BLOCK_OFFSET_1 * NUVO_BLOCK_SIZE + 16];
    rc = nuvo_sb_sync_read(&sb_read, pd);
    ck_assert(rc == 0);
    ck_assert(sb_read.generation == 4);
    // Now scribble on even, read should return error.
    parcel_data[16] = ~parcel_data[16];
    rc = nuvo_sb_sync_read(&sb_read, pd);
    ck_assert(rc == -NUVO_E_NO_SUPERBLOCK);
}
END_TEST

void compare_mfsts(struct nuvo_mfst *mfst1, struct nuvo_mfst *mfst2)
{
    mfst1->header.hash = 0;
    mfst2->header.hash = 0;

    ck_assert(mfst1->num_parcel_indices == mfst2->num_parcel_indices);
    ck_assert(mfst1->num_segment_allocated_indices == mfst2->num_segment_allocated_indices);
    ck_assert(mfst1->num_segment_indices == mfst2->num_segment_indices);
    ck_assert(mfst1->num_device_parcel_blocks == mfst2->num_device_parcel_blocks);
    ck_assert(mfst1->num_segment_table_blocks == mfst2->num_segment_table_blocks);


    ck_assert(0 == memcmp(mfst1->header.data, mfst2->header.data, NUVO_BLOCK_SIZE));

    ck_assert(mfst1->alloced_device_blocks == mfst2->alloced_device_blocks);
    ck_assert(0 == memcmp(mfst1->device_state_media, mfst2->device_state_media, mfst1->alloced_device_blocks * NUVO_BLOCK_SIZE));

    ck_assert(mfst1->alloced_parcel_blocks == mfst2->alloced_parcel_blocks);
    ck_assert(0 == memcmp(mfst1->parcel_state_media, mfst2->parcel_state_media, mfst1->alloced_parcel_blocks * NUVO_BLOCK_SIZE));

    ck_assert(mfst1->alloced_segment_blocks == mfst2->alloced_segment_blocks);
    ck_assert(0 == memcmp(mfst1->segment_state_media, mfst2->segment_state_media, mfst1->alloced_segment_blocks * NUVO_BLOCK_SIZE));

    for (unsigned c = 0; c < NUVO_MAX_DATA_CLASSES; c++) {
        if (mfst1->data_class[c].device_most_free_segs == -1)
        {
            ck_assert(mfst2->data_class[c].device_most_free_segs == -1);
        }
        else
        {
            ck_assert(mfst1->device_state_mem[mfst1->data_class[c].device_most_free_segs].free_segments ==
                      mfst2->device_state_mem[mfst2->data_class[c].device_most_free_segs].free_segments);
        }
        ck_assert(mfst1->data_class[c].available_parcels == mfst2->data_class[c].available_parcels);
        ck_assert(mfst1->data_class[c].free_segments == mfst2->data_class[c].free_segments);
    }
    uint32_t num_devices = NUVO_MFST_BLKS_TO_DEVICES(mfst1->header.num_device_blocks);
    for (unsigned dev_index = 0; dev_index < num_devices; dev_index++)
    {
        ck_assert(mfst1->device_state_mem[dev_index].free_segments ==
                  mfst2->device_state_mem[dev_index].free_segments);
    }

    ck_assert(mfst1->num_parcel_indices == mfst2->num_parcel_indices);
    for (unsigned parcel_index = 0; parcel_index < mfst1->num_parcel_indices; parcel_index++)
    {
        if (mfst1->parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_UNUSED)
        {
            ck_assert(mfst1->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_NONE);
            ck_assert(mfst2->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_NONE);
        }
        if (mfst1->parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_PARCEL)
        {
            ck_assert(mfst1->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_USABLE ||
                      mfst1->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_OPEN);
            ck_assert(mfst2->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_USABLE ||
                      mfst2->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_OPEN);
        }
        if (mfst1->parcel_state_mem[parcel_index].segment_offset !=
                  mfst2->parcel_state_mem[parcel_index].segment_offset)
        ck_assert(mfst1->parcel_state_mem[parcel_index].segment_offset ==
                  mfst2->parcel_state_mem[parcel_index].segment_offset);
    }
}

START_TEST(basic_manifest_init)
{
    nuvo_return_t rc;

    uuid_t device_uuid, root_parcel_uuid, vol_uuid;
    uuid_generate(vol_uuid);
    uint_fast32_t root_parcel_desc;
    uint32_t test_parcel_size_blocks = 2 * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uint64_t lun_size = 1024 * 1024 * 1024;

    // First let's create a device.
    uuid_generate(device_uuid);
    rc = nuvo_pm_device_format("blah", device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    ck_assert(rc == 0);

    // Now get a parcel.
    uuid_clear(root_parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    struct nuvo_sb_superblock sb;
    struct nuvo_mfst mfst;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_A, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 16, 128, lun_size);
    ck_assert(rc == 0);

    nuvo_mfst_in_core_lock(&mfst);
    // Check the devices
    ck_assert(mfst.header.num_used_devices == 1);
    ck_assert(mfst.header.num_device_blocks == 1);
    ck_assert(mfst.alloced_device_blocks == 1);
    ck_assert(0 == uuid_compare(device_uuid, mfst.device_state_media[0].device_uuid));
    ck_assert(mfst.device_state_media[0].target_parcels == 1);
    ck_assert(mfst.device_state_media[0].alloced_parcels == 1);
    ck_assert(mfst.device_state_media[0].parcel_size_in_blocks == test_parcel_size_blocks);

    // Check the parcels
    ck_assert(mfst.header.num_used_parcels == 1);
    ck_assert(mfst.header.num_parcel_blocks == 1);
    ck_assert(mfst.alloced_parcel_blocks == 1);
    ck_assert(mfst.parcel_state_media[0].type == NUVO_MFST_PARCEL_ENTRY_PARCEL);
    ck_assert(0 == uuid_compare(root_parcel_uuid, mfst.parcel_state_media[0].normal.parcel_uuid));
    ck_assert(mfst.parcel_state_media[0].normal.device_idx == 0);
    ck_assert(nuvo_mfst_parcel_segment_size_get(&mfst, 0) == NUVO_SEGMENT_MIN_SIZE_BYTES);
    unsigned num_segments = test_parcel_size_blocks / ( NUVO_SEGMENT_MIN_SIZE_BYTES / NUVO_BLOCK_SIZE );
    ck_assert(nuvo_mfst_parcel_segment_number_get(&mfst, 0) == num_segments);

    // Check the segments
    ck_assert(mfst.header.num_segment_blocks == 1);
    ck_assert(mfst.alloced_segment_blocks == 1);
    for (unsigned i = 0; i < num_segments; i++)
    {
        uint64_t block_offset = i * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
        ck_assert(nuvo_segment_space_pinned_get(&mfst, 0, block_offset) == 0);
        ck_assert(nuvo_segment_io_pin_count_get(&mfst, 0, block_offset) == 0);
        ck_assert(NUVO_SEGMENT_IN_USE(&mfst, i) == (i == 0) ? 1 : 0);
    }

    // Check the lun table
    ck_assert(mfst.header.num_lun_blocks == NUVO_MFST_LUN_TABLE_BLOCKS);
    ck_assert(mfst.header.num_used_luns == 1);
    ck_assert(0 == uuid_compare(mfst.lun_table[0].lun_uuid, vol_uuid));
    ck_assert(mfst.lun_table[0].size == lun_size);
    ck_assert(mfst.lun_table[0].map_height == 4);
    ck_assert(mfst.lun_table[0].snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID);

    // Check the log
    ck_assert(mfst.header.num_used_log_starts == 1);
    ck_assert(mfst.header.log_segments[0].parcel_index == 0);
    ck_assert(mfst.header.log_segments[0].segment_index == 1);

    nuvo_mfst_in_core_unlock(&mfst);

    nuvo_mfst_close(&mfst);
}
END_TEST

START_TEST(read_write_manifest)
{
    nuvo_return_t rc;

    uuid_t device_uuid, root_parcel_uuid, vol_uuid;
    uuid_generate(vol_uuid);
    uint_fast32_t root_parcel_desc;
    uint32_t test_parcel_size_blocks = 2 * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uint64_t lun_size = 1024 * 1024 * 1024;

    // First let's create a device.
    uuid_generate(device_uuid);
    rc = nuvo_pm_device_format("blah", device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    ck_assert(rc == 0);

    // Now get a parcel.
    uuid_clear(root_parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    struct nuvo_sb_superblock sb;
    struct nuvo_mfst mfst;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_A, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 16, 128, lun_size);
    ck_assert(rc == 0);

    // write manifest
    rc = nuvo_mfst_sync_write(&mfst, &sb, 2, 3);
    ck_assert(rc == 0);

    // write superblock
    rc = nuvo_sb_sync_write(&sb, root_parcel_desc);
    ck_assert(rc == 0);
    rc = nuvo_sb_sync_write(&sb, root_parcel_desc);
    ck_assert(rc == 0);

    // read superblock
    struct nuvo_sb_superblock sb_copy;
    struct nuvo_mfst mfst_copy;
    uint_fast32_t root_parcel_desc_copy;

    // read manifest
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc_copy,
                              root_parcel_uuid,
                              device_uuid,
                              vol_uuid);
    ck_assert(rc == 0);

    rc = nuvo_sb_sync_read(&sb_copy, root_parcel_desc_copy);
    ck_assert(rc == 0);
    ck_assert(0 == memcmp(&sb, &sb_copy, sizeof(sb)));
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == 0);

    // compare
    compare_mfsts(&mfst, &mfst_copy);

    // discard second
    nuvo_mfst_free_manifest(&mfst_copy);

    // Check it still works.
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == 0);
    nuvo_mfst_free_manifest(&mfst_copy);

    // Memory errors while reading manifest
    aligned_alloc_control.fail = true;
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == -NUVO_ENOMEM);

    aligned_alloc_control.fail = false;
    aligned_alloc_control.fail_after = 1;
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == -NUVO_ENOMEM);

    aligned_alloc_control.fail = false;
    aligned_alloc_control.fail_after = 2;
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == -NUVO_ENOMEM);

    // Check it still works.
    aligned_alloc_control.fail = false;
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == 0);
    nuvo_mfst_free_manifest(&mfst_copy);

    // IO Errors - Doing a little failure here because this test is set up for
    // actually reading and writing manifests.
    aligned_alloc_control.fail = false;
    fake_pr_fail_next_io(-NUVO_EIO, 0);
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == -NUVO_EIO);

    // Check still works.
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == 0);
    nuvo_mfst_free_manifest(&mfst_copy);

    fake_pr_fail_next_io(-NUVO_EIO, 6);
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == -NUVO_EIO);

    // Check still works.
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == 0);
    nuvo_mfst_free_manifest(&mfst_copy);

    // add some parcels, set some segment info
    // write manifest
    // read second
    // compare
    nuvo_mfst_close(&mfst);
}
END_TEST

START_TEST(manifest_db_init_failure)
{
    nuvo_return_t rc;

    uuid_t device_uuid, root_parcel_uuid, vol_uuid;
    uuid_generate(vol_uuid);
    uint_fast32_t root_parcel_desc;
    uint32_t test_parcel_size_blocks = 1024;
    uint64_t lun_size = 1024 * 1024 * 1024;

    // First let's create a device.
    uuid_generate(device_uuid);
    rc = nuvo_pm_device_format("blah", device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    ck_assert(rc == 0);

    // Now get a parcel.
    uuid_clear(root_parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    struct nuvo_sb_superblock sb;
    struct nuvo_mfst mfst;

    // Data class too large.
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_MAX_DATA_CLASSES, NUVO_SEGMENT_MIN_SIZE_BYTES, 16, 128);
    ck_assert(rc == -NUVO_EINVAL);

    // Segment size too small
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES - NUVO_SEGMENT_SIZE_INCREMENT, 16, 128, lun_size);
    ck_assert(rc == -NUVO_EINVAL);

    // Segment size too big
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MAX_SIZE_BYTES + NUVO_SEGMENT_SIZE_INCREMENT, 16, 128, lun_size);
    ck_assert(rc == -NUVO_EINVAL);

    // Segment size too weird
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES + NUVO_SEGMENT_SIZE_INCREMENT/2, 16, 128, lun_size);
    ck_assert(rc == -NUVO_EINVAL);

    // Not enough space in parcel for table
    // Here have 1024 blocks, need 2 + 2 * (12 + 500)
    // TODO - adjust for needing one additional segment.
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            1024, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 12, 500, lun_size);
    ck_assert(rc == -NUVO_ENOSPC);

    // TODO - check if size is 0
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            1024, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 12, 20, 0);
    ck_assert(rc == -NUVO_EINVAL);
    // TODO - check if size is non-block
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            1024, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 12, 20, 1024*1024 + 1);
    ck_assert(rc == -NUVO_EINVAL);

    // fail in align_alloc.
    aligned_alloc_control.fail = true;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            256*1024, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 12, 20, lun_size);
    ck_assert(rc == -NUVO_ENOMEM);
    aligned_alloc_control.fail = false;
    aligned_alloc_control.fail_after = 1;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            256*1024, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 12, 20, lun_size);
    ck_assert(rc == -NUVO_ENOMEM);

    // Don't fail, but make sure we do not get too many segments.
    aligned_alloc_control.fail = false;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            512*1024, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 12, 20, lun_size);
    ck_assert(rc == 0);
    ck_assert(mfst.num_segment_indices == NUVO_SEGMENT_CNT_MAX);
    nuvo_mfst_close(&mfst);
}
END_TEST

#define BIG_MANIFEST_PARCELS 4000
START_TEST(big_manifest)
{
    nuvo_return_t rc;

    uuid_t device_uuid, root_parcel_uuid, vol_uuid;
    uuid_generate(vol_uuid);
    uint_fast32_t root_parcel_desc;
    uint32_t test_parcel_size_blocks = 256 * 1024 * 1024 / NUVO_BLOCK_SIZE;
    uint64_t lun_size = 512 * 1024 * 1024;

    // First let's create a device.
    uuid_generate(device_uuid);
    rc = nuvo_pm_device_format("blah", device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    ck_assert(rc == 0);

    // Now get a parcel.
    uuid_clear(root_parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    struct nuvo_sb_superblock sb;
    struct nuvo_mfst mfst;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_C, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 300, 4000, lun_size);
    ck_assert(rc == 0);

    // write manifest
    rc = nuvo_mfst_sync_write(&mfst, &sb, 3, 7);
    ck_assert(rc == 0);

    // write superblock
    rc = nuvo_sb_sync_write(&sb, root_parcel_desc);
    ck_assert(rc == 0);

    mfst_validate_free_segments(&mfst, 0);
    for (uint_fast32_t i = 0; i < BIG_MANIFEST_PARCELS; i++)
    {
        uuid_t parcel_uuid;
        uuid_clear(parcel_uuid);
        rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, device_uuid, vol_uuid);
        ck_assert(rc == 0);
        uint16_t num_segments_added = 0;
        uint8_t data_class_added;
        rc = nuvo_mfst_insert_parcel(&mfst, device_uuid,
                parcel_uuid, 4 * 1024 * 1024, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);
        ck_assert(data_class_added == NUVO_DATA_CLASS_C);
    }
    mfst_validate_free_segments(&mfst, 0);
    rc = nuvo_mfst_sync_write(&mfst, &sb, 13, 17);
    ck_assert(rc == 0);
    mfst_validate_free_segments(&mfst, 0);
    nuvo_mfst_in_core_lock(&mfst);
    for (uint_fast32_t i = 0; i < BIG_MANIFEST_PARCELS; i++)
    {
        unsigned num_segments = rand() % 8;
        while (num_segments > 0)
        {
            uint_fast32_t num_segs = nuvo_mfst_parcel_segment_number_get(&mfst, i);
            uint_fast32_t seg_idx = mfst.parcel_state_mem[i].segment_offset + (rand() % num_segs);
            if (!NUVO_SEGMENT_IN_USE(&mfst, seg_idx))
            {
                mfst.segment_state_media[seg_idx].seg_blks_used = 1 + (rand() % 100);
                nuvo_mfst_device_free_segment_change(&mfst, 0, -1, false);
                num_segments--;
            }
        }
    }
    nuvo_mfst_in_core_unlock(&mfst);
    rc = nuvo_mfst_sync_write(&mfst, &sb, 13, 17);
    ck_assert(rc == 0);

    // read superblock
    struct nuvo_sb_superblock sb_copy;
    uint_fast32_t root_parcel_desc_copy;

    // read manifest
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc_copy,
                              root_parcel_uuid,
                              device_uuid,
                              vol_uuid);
    ck_assert(rc == 0);

    rc = nuvo_sb_sync_read(&sb_copy, root_parcel_desc_copy);
    ck_assert(rc == 0);
    ck_assert(0 == memcmp(&sb, &sb_copy, sizeof(sb)));

    struct nuvo_mfst mfst_copy;
    rc = nuvo_mfst_sync_read(&mfst_copy, &sb_copy, root_parcel_desc_copy, false);
    ck_assert(rc == 0);

    // compare
    compare_mfsts(&mfst, &mfst_copy);
    mfst_validate_free_segments(&mfst, 0);
    mfst_validate_free_segments(&mfst_copy, 0);

    // discard both copies.
    nuvo_mfst_free_manifest(&mfst_copy);
    nuvo_mfst_close(&mfst);
}
END_TEST

START_TEST(mfst_start_info)
{
    nuvo_return_t rc;

    uuid_t device_uuid, root_parcel_uuid, vol_uuid;
    uuid_generate(vol_uuid);
    uint_fast32_t root_parcel_desc;
    uint32_t test_parcel_size_blocks = 16 * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uint64_t lun_size = 700 * 1024 * 1024;

    // First let's create a device.
    uuid_generate(device_uuid);
    rc = nuvo_pm_device_format("blah", device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    ck_assert(rc == 0);
    // Now get a parcel.
    uuid_clear(root_parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    uint32_t blocks_in_parcel_0_segs = NUVO_SEGMENT_MIN_SIZE_BLOCKS;

    struct nuvo_sb_superblock sb;
    struct nuvo_mfst mfst;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_SSD, blocks_in_parcel_0_segs * NUVO_BLOCK_SIZE, 16, 128, lun_size);
    ck_assert(rc == 0);

    uint32_t blocks_in_parcel_1_segs = 2 * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uuid_t parcel_uuid;
    uuid_clear(parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    uint16_t num_segments_added = 0;
    uint8_t data_class_added;
    rc = nuvo_mfst_insert_parcel(&mfst, device_uuid, parcel_uuid, blocks_in_parcel_1_segs * NUVO_BLOCK_SIZE, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
    ck_assert(rc == 0);

    uint32_t blocks_in_parcel_2_segs = 2 * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uuid_clear(parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, device_uuid, vol_uuid);
    ck_assert(rc == 0);
    num_segments_added = 0;
    rc = nuvo_mfst_insert_parcel(&mfst, device_uuid, parcel_uuid, blocks_in_parcel_2_segs * NUVO_BLOCK_SIZE, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
    ck_assert(rc == 0);

    struct nuvo_segment log_starts[3];
    log_starts[0].parcel_index = 0;
    log_starts[0].block_offset = 7 * blocks_in_parcel_0_segs;
    log_starts[0].subclass = 0;
    log_starts[1].parcel_index = 1;
    log_starts[1].block_offset = 6 * blocks_in_parcel_1_segs;
    log_starts[1].subclass = 0;
    log_starts[2].parcel_index = 1;
    log_starts[2].block_offset = 3 * blocks_in_parcel_1_segs;
    log_starts[2].subclass = 0;

    nuvo_mfst_log_starts_set(&mfst, 17, log_starts, 3);

    struct nuvo_mfst_lun_entry lun_entry;
    memset(&lun_entry, 0, sizeof(lun_entry));
    lun_entry.lun_state = NUVO_LUN_STATE_VALID;
    lun_entry.root_map_entry.type = NUVO_ME_MEDIA;
    lun_entry.root_map_entry.media_addr.parcel_index = 1;
    lun_entry.root_map_entry.media_addr.block_offset = 1234;  // This should probably be in a log segment?   Blah.
    lun_entry.map_height = 3;
    lun_entry.size = lun_size;
    lun_entry.snap_id = NUVO_MFST_ACTIVE_LUN_SNAPID;  // TODO
    uuid_copy(lun_entry.lun_uuid, vol_uuid);
    nuvo_mfst_set_luns(&mfst, 1, &lun_entry);

    // Have to write it out, otherwise parcel 1 is still in CREATING state.
    rc = nuvo_mfst_sync_write(&mfst, &sb, 17, 23);
    ck_assert(rc == 0);

    // TODO - check sequence numbers in header.

    struct nuvo_lun lun;
    rc = nuvo_mfst_get_active_lun(&mfst, &lun);
    ck_assert(rc == 0);

    ck_assert(lun.root_map_entry.type == lun_entry.root_map_entry.type);
    ck_assert(lun.root_map_entry.media_addr.parcel_index == lun_entry.root_map_entry.media_addr.parcel_index);
    ck_assert(lun.root_map_entry.media_addr.block_offset == lun_entry.root_map_entry.media_addr.block_offset);
    ck_assert(lun.map_height == lun_entry.map_height);
    ck_assert(lun.size == lun_size);

    uint64_t stored_seq_no, stored_segment_seq_no;
    struct nuvo_segment stored_addrs[10];   // only need 3
    unsigned num_stored_segments = 10;
    nuvo_mfst_log_starts_get(&mfst, &stored_seq_no, &stored_segment_seq_no,
                             &num_stored_segments, stored_addrs);
    ck_assert(17 == stored_seq_no);
    ck_assert(23 == stored_segment_seq_no);
    ck_assert(3 == num_stored_segments);
    struct nuvo_segment segment;
    for (unsigned i = 0; i < 3; i++)
    {
        ck_assert(log_starts[i].parcel_index == stored_addrs[i].parcel_index);
        ck_assert(log_starts[i].block_offset == stored_addrs[i].block_offset);
        rc = nuvo_mfst_segment_for_log_replay(&mfst, stored_addrs[i].parcel_index,
                    stored_addrs[i].block_offset, &segment);
        ck_assert(rc == 0);
        uint32_t blocks_in_parcel = (stored_addrs[i].parcel_index == 0) ? blocks_in_parcel_0_segs : blocks_in_parcel_1_segs;
        uint32_t desc = (log_starts[i].parcel_index == 0) ? root_parcel_desc : root_parcel_desc + 1; // Horrible, but correct assumption.
        ck_assert(segment.parcel_index == stored_addrs[i].parcel_index);
        ck_assert(segment.block_count == blocks_in_parcel);
        ck_assert(segment.block_offset == stored_addrs[i].block_offset);
        ck_assert(segment.parcel_desc == desc);
        ck_assert(segment.device_index == 0);
        ck_assert(segment.data_class == NUVO_DATA_CLASS_B);
    }

    /*
     * Go get a parcel that was not in the log starts,
     * like we will after a fork.
     */
    rc = nuvo_mfst_segment_for_log_replay(&mfst, 2, 3 * blocks_in_parcel_2_segs + 4, &segment);
    ck_assert(rc == 0);
    ck_assert(segment.parcel_index == 2);
    ck_assert(segment.block_count == blocks_in_parcel_2_segs);
    ck_assert(segment.block_offset == segment.block_count * 3);
    ck_assert(segment.parcel_desc == root_parcel_desc + 2);  // Horrible, but correct assumption.
    ck_assert(segment.device_index == 0);
    ck_assert(segment.data_class == NUVO_DATA_CLASS_B);

    nuvo_mfst_free_manifest(&mfst);   // TODO - nuvo_mfst_close?
}
END_TEST

enum test_seg_op_types {
    SEG_USE,
    SEG_FREE,
    SEG_AGE
};

struct test_seg_op {
    enum test_seg_op_types type;
    union {
        struct {
            uint64_t age;
            uint32_t parcel_index;
            uint32_t bno;
        };
        struct {
            uint_fast32_t num;
            struct nuvo_map_entry map[NUVO_MAX_IO_BLOCKS];
        };
    };
};

struct {
    struct nuvo_sb_superblock sb_frozen;
    struct nuvo_mfst mfst_frozen;

    struct nuvo_sb_superblock sb_running;
    struct nuvo_mfst mfst_running;

    uuid_t device_uuid;
    uuid_t parcel_uuid[16];   /// Hard coded limit to parcels

    uint32_t num_parcels;
    uint32_t parcel_size_blocks;

    uint32_t num_parcel_indices;

    uint32_t num_segments;
    uint32_t blks_in_parcel;
    enum nuvo_dev_type device_type;
} slog_test_infrastructure;

/*
 * This allocates a device and some parcels and inits two manifests with the same parcels
 * in the same order, so they should have the same "disk" information.
 */
void mfst_test_slog_setup()
{
    nuvo_return_t rc;

    aligned_alloc_control.fail = false;
    fake_pr_init();
    slog_test_infrastructure.parcel_size_blocks = 16 * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    slog_test_infrastructure.device_type = NUVO_DEV_TYPE_SSD;

    uuid_generate(slog_test_infrastructure.device_uuid);
    rc = nuvo_pm_device_format("blah",
                               slog_test_infrastructure.device_uuid,
                               slog_test_infrastructure.parcel_size_blocks * NUVO_BLOCK_SIZE);
    ck_assert(rc == 0);
    rc = nuvo_pm_device_open("blah", slog_test_infrastructure.device_uuid, slog_test_infrastructure.device_type);
    ck_assert(rc == 0);

    // Create a volume with multiple devices of each two types.
    // Now get a parcel.
    uuid_t vol_uuid;
    uuid_generate(vol_uuid);
    slog_test_infrastructure.num_parcels = 16;

    for (unsigned int i = 0; i < slog_test_infrastructure.num_parcels; i++)
    {
        uuid_generate(slog_test_infrastructure.parcel_uuid[i]);
        rc = nuvo_pr_sync_parcel_alloc(slog_test_infrastructure.parcel_uuid[i], slog_test_infrastructure.device_uuid, vol_uuid);
        ck_assert(rc == 0);
    }

    // Init mfst_frozen on these parcels.
    uint_fast32_t root_parcel_desc;
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  slog_test_infrastructure.parcel_uuid[0],
                                  slog_test_infrastructure.device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    uint64_t lun_size = 64 * 1024 * 1024 * 1024ull;
    rc = nuvo_mfst_sb_init(&slog_test_infrastructure.sb_frozen,
                           &slog_test_infrastructure.mfst_frozen,
                           vol_uuid, slog_test_infrastructure.device_uuid, slog_test_infrastructure.parcel_uuid[0], root_parcel_desc,
                           slog_test_infrastructure.parcel_size_blocks, NUVO_DATA_CLASS_B, slog_test_infrastructure.device_type, NUVO_SEGMENT_MIN_SIZE_BYTES, 10, 20, lun_size);
    ck_assert(rc == 0);

    // Init mfst_running on these same parcels - don't write them.  It would be bad.
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  slog_test_infrastructure.parcel_uuid[0],
                                  slog_test_infrastructure.device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    rc = nuvo_mfst_sb_init(&slog_test_infrastructure.sb_running,
                           &slog_test_infrastructure.mfst_running,
                           vol_uuid, slog_test_infrastructure.device_uuid, slog_test_infrastructure.parcel_uuid[0], root_parcel_desc,
                           slog_test_infrastructure.parcel_size_blocks, NUVO_DATA_CLASS_B, slog_test_infrastructure.device_type, NUVO_SEGMENT_MIN_SIZE_BYTES, 10, 20, lun_size);
    ck_assert(rc == 0);

    for (unsigned int i = 1; i < 16; i++)
    {
        uint16_t num_segments_added = 0;
        uint8_t data_class_added;
        rc = nuvo_mfst_insert_parcel(&slog_test_infrastructure.mfst_frozen, slog_test_infrastructure.device_uuid,
                slog_test_infrastructure.parcel_uuid[i], NUVO_SEGMENT_MIN_SIZE_BYTES, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);
        ck_assert(data_class_added == NUVO_DATA_CLASS_B);

        num_segments_added = 0;
        rc = nuvo_mfst_insert_parcel(&slog_test_infrastructure.mfst_running, slog_test_infrastructure.device_uuid,
                slog_test_infrastructure.parcel_uuid[i], NUVO_SEGMENT_MIN_SIZE_BYTES, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);
        ck_assert(data_class_added == NUVO_DATA_CLASS_B);
    }

    // Simulate writing to make parcels usable.
    nuvo_mfst_seg_counts_start(&slog_test_infrastructure.mfst_running);
    nuvo_mfst_freeze_at_seqno(&slog_test_infrastructure.mfst_running, 7);
    nuvo_mfst_writing_thaw(&slog_test_infrastructure.mfst_running);

    nuvo_mfst_seg_counts_start(&slog_test_infrastructure.mfst_frozen);
    nuvo_mfst_freeze_at_seqno(&slog_test_infrastructure.mfst_frozen, 7);
    nuvo_mfst_writing_thaw(&slog_test_infrastructure.mfst_frozen);

    compare_mfsts(&slog_test_infrastructure.mfst_frozen, &slog_test_infrastructure.mfst_running);

    slog_test_infrastructure.num_segments = slog_test_infrastructure.mfst_frozen.num_segment_indices;
}

void mfst_test_slog_teardown() {
    nuvo_mfst_free_manifest(&slog_test_infrastructure.mfst_frozen);
    nuvo_mfst_close(&slog_test_infrastructure.mfst_running);
    fake_pr_teardown();
}

void segment_logger_pinned_set(struct nuvo_mfst* mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    mfst->segment_state_mem[segment_index].seg_space_used = 1;
}

void setup_ops_pinned(struct nuvo_mfst *mfst, uint_fast32_t num_ops, struct test_seg_op *ops)
{
    nuvo_mfst_in_core_lock(mfst);
    for (uint_fast32_t i = 0; i < num_ops; i++)
    {
        switch (ops[i].type)
        {
        case SEG_FREE:
            break;
        case SEG_USE:
            for (uint_fast32_t j = 0; j < ops[i].num; j++)
            {
                if (ops[i].map[j].type == NUVO_ME_MEDIA)
                {
                    segment_logger_pinned_set(mfst, ops[i].map[j].media_addr.parcel_index, ops[i].map[j].media_addr.block_offset);
                }
            }
            break;
        case SEG_AGE:
            // Using the internal function rather than returning a segment structure.
            segment_logger_pinned_set(mfst, ops[i].parcel_index, ops[i].bno);
            break;
        }
    }
    nuvo_mfst_in_core_unlock(mfst);
}

struct client_args {
    struct nuvo_mfst *mfst;
    uint_fast32_t num_ops;
    struct test_seg_op *ops;

    atomic_uint_fast32_t num_played;
};

void *client_thread(void *arg)
{
    struct client_args *args = (struct client_args *) arg;
    struct nuvo_mfst *mfst = args->mfst;
    struct test_seg_op *ops = args->ops;

    for (uint_fast32_t i = 0; i < args->num_ops; i++)
    {
        switch (ops[i].type)
        {
        case SEG_USE:
            for (uint j = 0 ; j < ops[i].num; j++)
            {
                ops[i].map[j].cow = 0;
            }
            nuvo_mfst_segment_use_blks(mfst, ops[i].num, ops[i].map);
            break;
        case SEG_FREE:
            for (uint j = 0 ; j < ops[i].num; j++)
            {
                ops[i].map[j].cow = 0;
            }
            nuvo_mfst_segment_free_blks(mfst, ops[i].num, ops[i].map);
            break;
        case SEG_AGE:
            nuvo_mfst_in_core_lock(mfst);
            // Using the internal function rather than returning a segment structure.
            nuvo_mfst_slog_change_age(mfst, ops[i].parcel_index, ops[i].bno, ops[i].age != 0);
            nuvo_mfst_in_core_unlock(mfst);
            break;
        }
        atomic_store(&args->num_played, 1 + atomic_load(&args->num_played));
    }
    return 0;
}

void do_ops(struct nuvo_mfst *mfst, uint_fast32_t num_ops, struct test_seg_op *ops, bool freeze, struct nuvo_mfst *mfst_base)
{
    if (freeze)
    {
        nuvo_mfst_freeze_at_seqno(mfst, 9);
        // Cheat the freeze segno on the base, so comparison later will work.
        mfst_base->header.log_segment_count_seq_no = 9;
    }

    struct client_args args;
    args.mfst = mfst;
    args.num_ops = num_ops;
    args.ops = ops;
    atomic_init(&args.num_played, 0);

    uint64_t num_waits = mfst->slog.num_waits;

    pthread_t client_id;
    int ret = pthread_create(&client_id, NULL, client_thread, &args);
    ck_assert(ret == 0);

    // Now client is playing ops.
    if (freeze)
    {
        while (true)
        {
            // Wait for all done or stalled
            if (num_ops == atomic_load(&args.num_played))
            {
                break;
            }
            nuvo_mfst_in_core_lock(mfst);
            bool log_full = (num_waits < mfst->slog.num_waits);
            num_waits = mfst->slog.num_waits;
            nuvo_mfst_in_core_unlock(mfst);
            if (log_full)
            {
                break;
            }
            struct timespec tenth;
            tenth.tv_sec = 0;
            tenth.tv_nsec = 100000000;
            nanosleep(&tenth, NULL);
        }
    }
    // Either done or log is full.
    if (freeze)
    {
        // TODO compare mfst and base "disk" state,
        compare_mfsts(mfst, mfst_base);
        nuvo_mfst_writing_thaw(mfst);
    }
    ret = pthread_join(client_id, NULL);
    ck_assert(ret == 0);
}

void test_play_ops(uint_fast32_t num_pre,
                   struct test_seg_op *pre_ops,
                   uint_fast32_t num,
                   struct test_seg_op *ops)
{
    setup_ops_pinned(&slog_test_infrastructure.mfst_frozen, num_pre, pre_ops);
    setup_ops_pinned(&slog_test_infrastructure.mfst_running, num_pre, pre_ops);
    do_ops(&slog_test_infrastructure.mfst_frozen, num_pre, pre_ops, false, NULL);
    do_ops(&slog_test_infrastructure.mfst_running, num_pre, pre_ops, false, NULL);

    setup_ops_pinned(&slog_test_infrastructure.mfst_frozen, num, ops);
    setup_ops_pinned(&slog_test_infrastructure.mfst_running, num, ops);
    do_ops(&slog_test_infrastructure.mfst_frozen, num, ops, true, &slog_test_infrastructure.mfst_running);
    do_ops(&slog_test_infrastructure.mfst_running, num, ops, false, NULL);

    compare_mfsts(&slog_test_infrastructure.mfst_frozen, &slog_test_infrastructure.mfst_running);
}

START_TEST(no_segment_ops)
{
    test_play_ops(0, NULL, 0, NULL);
    ck_assert(0 == slog_test_infrastructure.mfst_frozen.slog.num_waits);
}
END_TEST

START_TEST(simple_ops)
{
    struct test_seg_op pre_op;
    pre_op.type = SEG_USE;
    pre_op.num = 4;
    for (uint_fast32_t i = 0; i < pre_op.num; i++)
    {
        pre_op.map[i].type = NUVO_ME_MEDIA;
        pre_op.map[i].media_addr.parcel_index = 3;
        pre_op.map[i].media_addr.block_offset = 17 + i;
        pre_op.map[i].cow = 0;
    }
    struct test_seg_op post_op;
    post_op.type = SEG_USE;
    post_op.num = 6;
    for (uint_fast32_t i = 0; i < post_op.num ; i++)
    {
        post_op.map[i].type = NUVO_ME_MEDIA;
        post_op.map[i].media_addr.parcel_index = 3;
        post_op.map[i].media_addr.block_offset = 16 + i;
        pre_op.map[i].cow = 0;
    }
    test_play_ops(1, &pre_op, 1, &post_op);
    ck_assert(0 == slog_test_infrastructure.mfst_frozen.slog.num_waits);  // Log never fills
}
END_TEST

START_TEST(simple_ops_no_log)
{
    slog_test_infrastructure.mfst_frozen.slog.max_entries = 0;
    struct test_seg_op pre_op;
    pre_op.type = SEG_USE;
    pre_op.num = 4;
    for (uint_fast32_t i = 0; i < pre_op.num; i++)
    {
        pre_op.map[i].type = NUVO_ME_MEDIA;
        pre_op.map[i].media_addr.parcel_index = 3;
        pre_op.map[i].media_addr.block_offset = 17 + i;
        pre_op.map[i].cow = 0;
    }
    struct test_seg_op post_op;
    post_op.type = SEG_USE;
    post_op.num = 6;
    for (uint_fast32_t i = 0; i < post_op.num ; i++)
    {
        post_op.map[i].type = NUVO_ME_MEDIA;
        post_op.map[i].media_addr.parcel_index = 3;
        post_op.map[i].media_addr.block_offset = 16 + i;
        post_op.map[i].cow = 0;
    }
    ck_assert(0 == slog_test_infrastructure.mfst_frozen.slog.num_waits);
    test_play_ops(1, &pre_op, 1, &post_op);
    ck_assert(1 == slog_test_infrastructure.mfst_frozen.slog.num_waits); // Log was full
}
END_TEST

START_TEST(set_age)
{
    slog_test_infrastructure.mfst_frozen.slog.max_entries = 2;
    struct test_seg_op pre_ops[5] = {
                                        { .type = SEG_AGE, .age = 1, .parcel_index = 3, .bno = 0 },
                                        { .type = SEG_AGE, .age = 2, .parcel_index = 3, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 2},
                                        { .type = SEG_AGE, .age = 3, .parcel_index = 2, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 2},
                                        { .type = SEG_AGE, .age = 4, .parcel_index = 7, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 7},
                                        { .type = SEG_AGE, .age = 5, .parcel_index = 10, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 6},
                                    };
    struct test_seg_op post_ops[5] = {
                                        { .type = SEG_AGE, .age = 11, .parcel_index = 3, .bno = 0 },
                                        { .type = SEG_AGE, .age = 12, .parcel_index = 3, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 2},
                                        { .type = SEG_AGE, .age = 13, .parcel_index = 2, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 2},
                                        { .type = SEG_AGE, .age = 14, .parcel_index = 7, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 7},
                                        { .type = SEG_AGE, .age = 15, .parcel_index = 10, .bno = NUVO_SEGMENT_MIN_SIZE_BLOCKS * 6},
                                     };
    test_play_ops(5, pre_ops, 5, post_ops);
    // TODO - look at actual values
}
END_TEST

START_TEST(multi_ops)
{
    struct test_seg_op pre_ops[] = {
                                     { .type = SEG_USE,
                                       .num = 4,
                                       .map = {
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=17}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=18}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=19}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=20}, .cow = 0},
                                       }
                                     },
                                     { .type = SEG_USE,
                                       .num = 6,
                                       .map = {
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=2048}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=2049}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=2050}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=2051}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=2052}, .cow = 0},
                                         {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=2053}, .cow = 0},
                                       }
                                     },
                                     { .type = SEG_AGE, .age = 1, .parcel_index = 3, .bno=17},
                                     { .type = SEG_AGE, .age = 2, .parcel_index = 3, .bno=2048},
                                     { .type = SEG_FREE,
                                       .num = 4,
                                       .map = {
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=17}, .cow = 0},
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=18}, .cow = 0},
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=19}, .cow = 0},
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=20}, .cow = 0},
                                       }
                                     },
                                     { .type = SEG_USE,
                                       .num = 4,
                                       .map = {
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=17}, .cow = 0},
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=18}, .cow = 0},
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=19}, .cow = 0},
                                          {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=20}, .cow = 0},
                                       }
                                     },
                                  };

    test_play_ops(6, pre_ops, 0, NULL);
}
END_TEST

START_TEST(rollback)
{
    struct test_seg_op pre_ops[] = {
                                     { .type = SEG_USE,
                                       .num = 4,
                                       .map = {
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 2, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 4, .block_offset=0}, .cow = 0},
                                       }
                                     },
                                     { .type = SEG_AGE, .age = 1, .parcel_index = 1, .bno=0},
                                     { .type = SEG_AGE, .age = 2, .parcel_index = 2, .bno=0},
                                     { .type = SEG_AGE, .age = 3, .parcel_index = 3, .bno=0},
                                     { .type = SEG_AGE, .age = 4, .parcel_index = 4, .bno=0},
                                    };
    struct test_seg_op post_ops[] = {
                                     { .type = SEG_USE,
                                       .num = 4,
                                       .map = {
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=0}, .cow = 0},
                                       }
                                     },
                                     { .type = SEG_FREE,
                                       .num = 4,
                                       .map = {
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 1, .block_offset=1}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 2, .block_offset=0}, .cow = 0},
                                            {.type = NUVO_ME_MEDIA, .media_addr = { .parcel_index = 3, .block_offset=0}, .cow = 0},
                                       }
                                     }
                                    };
    slog_test_infrastructure.mfst_frozen.slog.max_entries = 2;
    test_play_ops(5, pre_ops, 2, post_ops);
}
END_TEST

START_TEST(mfst_segment_for_gc)
{
    nuvo_return_t rc = nuvo_segment_free_list_create(&nuvo_global_segment_free_list, 500);
    ck_assert(rc == 0);
    // Make up ages and segment usages for the segments.
    // Keep allocing segments from class 1 until we got them all.  Make sure they are in correct order.
    // Return them.
    // Keep allocing segments from class 2 until we got them all.  Make sure they are in correct order.
    uuid_t vol_uuid;
    uuid_generate_random(vol_uuid);
    struct nuvo_sb_superblock sb;
    nuvo_sb_init(&sb, vol_uuid, 16, 128);
    struct nuvo_mfst mfst;
    rc = nuvo_mfst_alloc_manifest(&mfst);
    ck_assert(rc == 0);
    nuvo_mfst_init_manifest_header(&mfst);
    nuvo_mfst_set_superblock_info(&mfst, &sb);

    // Dev 1, data class 1, 3 parcels (parcel size 64MB, seg size 4MB)
    // Dev 2 data class 2, 2 parcels  (parcel size 512MB, seg size 16MB)
    // Dev 3 data class 1, 1 parcel   (parcel size 64MB, seg size 4MB)
    #define SEG_GC_TEST_NUM_DEVICES 3
    struct {
        uint_fast8_t  device_class;
        enum nuvo_dev_type device_type;
        uint_fast32_t parcel_size_blocks;
        uint_fast32_t num_parcels;
        uint_fast32_t segment_size_blocks;
        uuid_t        device_uuid;
    } devices[SEG_GC_TEST_NUM_DEVICES] = { {NUVO_DATA_CLASS_A, NUVO_DEV_TYPE_SSD, 16384, 3, 1024, {""}},
                                           {NUVO_DATA_CLASS_B, NUVO_DEV_TYPE_HDD, 131072, 2, 4096, {""}},
                                           {NUVO_DATA_CLASS_A, NUVO_DEV_TYPE_SSD, 16384, 1, 1024, {""}}, };

    for (uint_fast8_t i = 0; i < SEG_GC_TEST_NUM_DEVICES; i++)
    {
        uuid_generate_random(devices[i].device_uuid);
        rc = nuvo_pm_device_format("blah", devices[i].device_uuid, devices[i].parcel_size_blocks * NUVO_BLOCK_SIZE);
        ck_assert(rc == 0);
        rc = nuvo_pm_device_open("blah", devices[i].device_uuid, devices[i].device_type);
        ck_assert(rc == 0);

    }

    #define SEG_GC_TEST_NUM_PARCELS 6
    struct {
        uint_fast8_t    device_index;
        uint16_t        number_segments;
        uuid_t          parcel_uuid;
    } parcels[SEG_GC_TEST_NUM_PARCELS] = { {0, 0, {""}},
                                           {1, 0, {""}},
                                           {2, 0, {""}},
                                           {0, 0, {""}},
                                           {1, 0, {""}},
                                           {0, 0, {""}}, };
    for (uint_fast8_t i = 0; i < SEG_GC_TEST_NUM_PARCELS; i++)
    {
        uuid_clear(parcels[i].parcel_uuid);
        rc = nuvo_pr_sync_parcel_alloc(parcels[i].parcel_uuid,
                                       devices[parcels[i].device_index].device_uuid,
                                       vol_uuid);
        ck_assert(rc == 0);
    }

    uint_fast32_t root_parcel_desc;
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  parcels[0].parcel_uuid,
                                  devices[0].device_uuid,
                                  vol_uuid);
    ck_assert(rc == 0);

    uint32_t lun_size = 1024 * 1024 * 1024;
    rc = nuvo_mfst_sb_init(&sb, &mfst,
            vol_uuid, devices[0].device_uuid, parcels[0].parcel_uuid, root_parcel_desc,
            devices[0].parcel_size_blocks, devices[0].device_class, devices[0].device_type, devices[0].segment_size_blocks * NUVO_BLOCK_SIZE, 20, 200, lun_size);
    ck_assert(rc == 0);
    parcels[0].number_segments = devices[0].parcel_size_blocks / devices[0].segment_size_blocks;

    for (uint_fast8_t i = 1; i < SEG_GC_TEST_NUM_DEVICES; i++)
    {
        rc = nuvo_mfst_insert_device(&mfst, devices[i].device_uuid,
            devices[i].device_class, devices[i].device_type, devices[i].parcel_size_blocks);
        ck_assert(rc == 0);
    }

    uint_fast32_t total_number_segments = 0;
    for (uint_fast8_t i = 1; i < SEG_GC_TEST_NUM_PARCELS; i++)
    {
        uint8_t device_class;
        rc = nuvo_mfst_insert_parcel(&mfst,
                                     devices[parcels[i].device_index].device_uuid,
                                     parcels[i].parcel_uuid,
                                     devices[parcels[i].device_index].segment_size_blocks * NUVO_BLOCK_SIZE,
                                     &parcels[i].number_segments,
                                     &device_class,
                                     NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);
        total_number_segments += parcels[i].number_segments;
    }

    // Pretend we've done a first CP.
    nuvo_mfst_writing_freeze(&mfst);
    nuvo_mfst_writing_thaw(&mfst);

    // Make up ages and segment usages for the segments.
    // Have a reserved.  Want some free.
    uint_fast32_t seg_idx = 0;
    nuvo_mutex_lock(&mfst.mfst_mutex);
    for (uint_fast8_t i = 0; i < SEG_GC_TEST_NUM_PARCELS; i++)
    {
        for (uint16_t j = 0; j < parcels[i].number_segments; j++, seg_idx++)
        {
            if (mfst.segment_state_media[seg_idx].seg_reserved)
            {
                continue;
            }
            if (rand() % 3 == 0)
            {
                // Leave some free segments;
                continue;
            }
            uint16_t u = rand() % 100;
            uint32_t age = 1 + (rand() % (2 * total_number_segments));
            mfst.segment_state_media[seg_idx].seg_age = age;
            if (age > mfst.max_segment_age)
            {
                mfst.max_segment_age = age;
            }
            mfst.segment_state_media[seg_idx].seg_blks_used = (u * devices[parcels[i].device_index].segment_size_blocks) / 100;
            if (mfst.segment_state_media[seg_idx].seg_age != 0 ||
                mfst.segment_state_media[seg_idx].seg_blks_used != 0)
            {
                nuvo_mfst_device_free_segment_change(&mfst, parcels[i].device_index, -1, false);
            }
        }
    }
    nuvo_mutex_unlock(&mfst.mfst_mutex);
    for (uint_fast8_t i = 1; i < SEG_GC_TEST_NUM_DEVICES; i++)
    {
        mfst_validate_free_segments(&mfst, i);
    }

    // Keep allocing segments from class 1 until we got them all.  Make sure they are in correct order.
    for (uint8_t dc = NUVO_DATA_CLASS_A; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        struct nuvo_segment *segment;
        uint_fast32_t score = UINT32_MAX;
        (void) score;
        while (0 <= nuvo_mfst_segment_for_gc(&mfst, dc, &segment))
        {
            nuvo_mutex_lock(&mfst.mfst_mutex);
            // TODO make sure not already clean
            // TODO score the segment
            // TODO check worse than last score
            mfst.segment_state_media[nuvo_mfst_seg_idx(&mfst, segment->parcel_index, segment->block_offset)].seg_blks_used = 0;
            nuvo_mutex_unlock(&mfst.mfst_mutex);
            nuvo_mfst_segment_done(&mfst, segment, NUVO_MFST_SEGMENT_REASON_CLEAR_AGE);
            nuvo_segment_free(&nuvo_global_segment_free_list, segment);
        }
    }
    // TODO Did we get the total number expected.
    while (0 != nuvo_mfst_gc_pipeline_total(&mfst))
    {
        nuvo_mfst_gc_starting_cp(&mfst);
        (void) nuvo_mfst_cp_done_for_gc(&mfst);
    }
    nuvo_mfst_return_gc_segments(&mfst);
    nuvo_mfst_free_manifest(&mfst);
    nuvo_segment_free_list_destroy(&nuvo_global_segment_free_list);
}
END_TEST

START_TEST(device_in_free_segment_list)
{
    struct nuvo_mfst mfst;
    memset(&mfst, 0, sizeof(mfst));
    nuvo_mutex_init(&mfst.mfst_mutex);
    nuvo_mutex_lock(&mfst.mfst_mutex);
    mfst.device_state_media = calloc(5, sizeof(struct nuvo_mfst_device_entry));
    for (uint_fast16_t c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
    {
        mfst.data_class[c].device_most_free_segs = NUVO_NO_DEVICE_IN_CLASS;
    }
    mfst.device_state_mem[0].free_segments = 13;
    mfst.device_state_mem[1].free_segments = 12;
    mfst.device_state_mem[2].free_segments = 14;
    mfst.device_state_media[2].device_class = 1;
    mfst.device_state_mem[3].free_segments = 14;
    mfst.device_state_mem[4].free_segments = 11;
    insert_device_in_free_segment_list(&mfst, 0);
    insert_device_in_free_segment_list(&mfst, 1);
    insert_device_in_free_segment_list(&mfst, 2);
    insert_device_in_free_segment_list(&mfst, 3);
    insert_device_in_free_segment_list(&mfst, 4);

    ck_assert(mfst.data_class[0].device_most_free_segs == 3);
    ck_assert(mfst.device_state_mem[3].up_index == 3);
    ck_assert(mfst.device_state_mem[3].down_index == 0);
    ck_assert(mfst.device_state_mem[0].up_index == 3);
    ck_assert(mfst.device_state_mem[0].down_index == 1);
    ck_assert(mfst.device_state_mem[1].up_index == 0);
    ck_assert(mfst.device_state_mem[1].down_index == 4);
    ck_assert(mfst.device_state_mem[4].up_index == 1);
    ck_assert(mfst.device_state_mem[4].down_index == 4);

    ck_assert(mfst.data_class[1].device_most_free_segs == 2);
    ck_assert(mfst.device_state_mem[2].up_index == 2);
    ck_assert(mfst.device_state_mem[2].down_index == 2);
    nuvo_mutex_unlock(&mfst.mfst_mutex);
    nuvo_mutex_destroy(&mfst.mfst_mutex);
    free(mfst.device_state_media);
}
END_TEST

struct {
    struct nuvo_sb_superblock sb;
    struct nuvo_mfst mfst;
    struct nuvo_segment_free_list segment_free_list;
    uint32_t test_parcel_size_blocks;
    uint16_t segments_per_parcel;
} segment_cleaning_test_vars;

void mfst_segment_cleaning_tests_setup() {
    aligned_alloc_control.fail = false;
    aligned_alloc_control.fail_after = 0;
    fake_pr_init();
    nuvo_return_t rc;

    uuid_t device_uuid, root_parcel_uuid, vol_uuid;
    uuid_generate(vol_uuid);
    uint_fast32_t root_parcel_desc;
    segment_cleaning_test_vars.segments_per_parcel = 4;
    segment_cleaning_test_vars.test_parcel_size_blocks = segment_cleaning_test_vars.segments_per_parcel  * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uint32_t test_parcel_size_blocks = segment_cleaning_test_vars.test_parcel_size_blocks;
    uint64_t lun_size = 1024 * 1024 * 1024;

    // First let's create a device.
    uuid_generate(device_uuid);
    rc = nuvo_pm_device_format("blah", device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
    NUVO_ASSERT(rc == 0);
    rc = nuvo_pm_device_open("blah", device_uuid, NUVO_DEV_TYPE_SSD);
    NUVO_ASSERT(rc == 0);

    // Now get a parcel.
    uuid_clear(root_parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, vol_uuid);
    NUVO_ASSERT(rc == 0);
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  device_uuid,
                                  vol_uuid);
    NUVO_ASSERT(rc == 0);

    struct nuvo_sb_superblock *sb = &segment_cleaning_test_vars.sb;
    struct nuvo_mfst *mfst = &segment_cleaning_test_vars.mfst;
    rc = nuvo_mfst_sb_init(sb, mfst,
            vol_uuid, device_uuid, root_parcel_uuid, root_parcel_desc,
            test_parcel_size_blocks, NUVO_DATA_CLASS_A, NUVO_DEV_TYPE_SSD, NUVO_SEGMENT_MIN_SIZE_BYTES, 16, 128, lun_size);
    NUVO_ASSERT(rc == 0);

    for (uint8_t dc = NUVO_DATA_CLASS_A; dc <= NUVO_DATA_CLASS_B; dc++)
    {
        for (uint_fast32_t i = 0; i < 2; i++)
        {
            struct nuvo_mfst_insert_device_info device;
            uuid_generate_random(device.device_uuid);
            device.device_type = NUVO_DEV_TYPE_SSD;
            rc = nuvo_pm_device_format("blah", device.device_uuid, test_parcel_size_blocks * NUVO_BLOCK_SIZE);
            NUVO_ASSERT(rc == 0);
            rc = nuvo_pm_device_open("blah", device.device_uuid, device.device_type);
            NUVO_ASSERT(rc == 0);
            device.device_class = dc;
            device.parcel_size_in_blocks = test_parcel_size_blocks;
            rc = nuvo_mfst_insert_devices(mfst, 1, &device);
            NUVO_ASSERT(rc == 0);
        }
    }

    for (uint_fast32_t i = 0; i < 5; i++)
    {
        for (uint_fast32_t j = 0; j < ((i == 0) ? 1 : 2); j++)
        {
            struct nuvo_mfst_parcel_insert_info parcel_req;
            uuid_generate_random(parcel_req.parcel_uuid);
            parcel_req.pd = NUVO_VOL_PD_UNUSED;
            rc = nuvo_pr_sync_parcel_alloc(parcel_req.parcel_uuid, mfst->device_state_media[i].device_uuid, vol_uuid);
            NUVO_ASSERT(rc == 0);
            make_parcel_req_for_device(&parcel_req, mfst, i, NUVO_SEGMENT_MIN_SIZE_BYTES);
            rc = nuvo_mfst_insert_parcels(mfst, 1, &parcel_req);
            NUVO_ASSERT(rc == 0);
        }
    }
    nuvo_mfst_seg_counts_start(mfst);
    nuvo_mfst_freeze_at_seqno(mfst, 7);
    nuvo_mfst_writing_thaw(mfst);

    rc = nuvo_segment_free_list_create(&nuvo_global_segment_free_list, 50);
    ck_assert(rc == 0);
}

void mfst_segment_cleaning_tests_teardown() {
    nuvo_segment_free_list_destroy(&nuvo_global_segment_free_list);
    struct nuvo_mfst *mfst = &segment_cleaning_test_vars.mfst;
    nuvo_mfst_close(mfst);
    fake_pr_teardown();
}

START_TEST(segments_avail)
{
    nuvo_return_t rc;
    uint16_t segments_per_parcel = segment_cleaning_test_vars.segments_per_parcel;
    struct nuvo_mfst *mfst = &segment_cleaning_test_vars.mfst;

    // Test that nuvo_mfst_segments_avail returns correct stuff
    struct nuvo_mfst_space_info space_info;

    // Every device has two parcels.
    // So 6 parcels, with segments_per_parcel segments each, minus 1 reserved.
    nuvo_mfst_segments_avail(mfst, NUVO_DATA_CLASS_A, &space_info);
    ck_assert(space_info.class_total_segments == 6 * segments_per_parcel);
    ck_assert(space_info.class_free_segments + 1 == 6 * segments_per_parcel);


    // 2 devices, added two parcels on each
    // So 4 parcels, with segments_per_parcel segments each
    nuvo_mfst_segments_avail(mfst, NUVO_DATA_CLASS_B, &space_info);
    ck_assert(space_info.class_total_segments == 4 * segments_per_parcel);
    ck_assert(space_info.class_free_segments == 4 * segments_per_parcel);

    uint16_t pipeline = nuvo_mfst_gc_pipeline_total(mfst);
    ck_assert(pipeline == 0);

    // Now pretend to use some segments.  Use 10 - gets us some from each device.
    for (unsigned i = 0; i < 20; i++)
    {
        struct nuvo_segment *segment = nuvo_segment_alloc(&nuvo_global_segment_free_list);
        ck_assert(segment != NULL);
        rc = nuvo_mfst_segment_get(mfst, NUVO_DATA_CLASS_A, 0, NULL, segment, &space_info);
        ck_assert(rc == 0);
        nuvo_mfst_segment_done(mfst, segment, NUVO_MFST_SEGMENT_REASON_SET_AGE);
        nuvo_segment_free(&nuvo_global_segment_free_list, segment);
    }
    nuvo_mfst_segments_avail(mfst, NUVO_DATA_CLASS_A, &space_info);
    ck_assert(space_info.class_total_segments == 6 * segments_per_parcel);
    ck_assert(space_info.class_free_segments + 1 + 20 == 6 * segments_per_parcel);

    uint_fast16_t pending;
    // now fake cleaning two segments
    for (unsigned i = 0; i < 2; i++)
    {
        struct nuvo_segment *segment;
        rc = nuvo_mfst_segment_for_gc(mfst, NUVO_DATA_CLASS_A, &segment);
        pending = nuvo_mfst_gc_free_next_cp(mfst, segment);
        ck_assert(pending == i + 1);
    }
    pipeline = nuvo_mfst_gc_pipeline_total(mfst);
    ck_assert(pipeline == 2);
    nuvo_mfst_gc_starting_cp(mfst);

    // fake clean three more while in CP
    for (unsigned i = 0; i < 3; i++)
    {
        struct nuvo_segment *segment;
        rc = nuvo_mfst_segment_for_gc(mfst, NUVO_DATA_CLASS_A, &segment);
        NUVO_ASSERT(segment != NULL);
        pending = nuvo_mfst_gc_free_next_cp(mfst, segment);
        ck_assert(pending == i + 1);
    }
    pipeline = nuvo_mfst_gc_pipeline_total(mfst);
    ck_assert(pipeline == 5);

    pending = nuvo_mfst_cp_done_for_gc(mfst);
    ck_assert(pending == 3);
    pipeline = nuvo_mfst_gc_pipeline_total(mfst);
    ck_assert(pipeline == 3);

    nuvo_mfst_gc_starting_cp(mfst);
    pending = nuvo_mfst_cp_done_for_gc(mfst);
    ck_assert(pending == 0);
    pipeline = nuvo_mfst_gc_pipeline_total(mfst);
    ck_assert(pipeline == 0);

    nuvo_mfst_return_gc_segments(mfst);
}
END_TEST

START_TEST(segments_on_device)
{
    // First dirty all the segments in the class
    // normally we won't do this, but ok in this unit test
    nuvo_return_t rc = 0;
    unsigned segments_per_parcel = segment_cleaning_test_vars.segments_per_parcel;
    struct nuvo_mfst *mfst = &segment_cleaning_test_vars.mfst;
    struct nuvo_mfst_space_info space_info;
    while (rc == 0) {
        struct nuvo_segment *segment = nuvo_segment_alloc(&nuvo_global_segment_free_list);
        ck_assert(segment != NULL);
        rc = nuvo_mfst_segment_get(mfst, NUVO_DATA_CLASS_A, 0, NULL, segment, &space_info);
        if (rc == 0)
        {
            nuvo_mutex_lock(&mfst->mfst_mutex);
            uint_fast32_t seg_idx = nuvo_mfst_seg_idx(mfst, segment->parcel_index, segment->block_offset);
            mfst->segment_state_media[seg_idx].seg_blks_used = 1 + (rand() % 512);
            nuvo_mutex_unlock(&mfst->mfst_mutex);
            nuvo_mfst_segment_done(mfst, segment, NUVO_MFST_SEGMENT_REASON_SET_AGE);
        }
        nuvo_segment_free(&nuvo_global_segment_free_list, segment);
    }

    // Now let's get segments to clean from device 1.
    // Ask for one more than is on device.
    struct nuvo_dlist   chosen_segs;
    nuvo_dlist_init(&chosen_segs);
    struct nuvo_segment *segment;
    rc = nuvo_mfst_segments_gc_device(mfst, 1, 2 * segments_per_parcel + 1, 100, &chosen_segs);
    ck_assert(rc == 2 * segments_per_parcel);
    unsigned num_chosen = 0;
    unsigned last_grade = 1000000; // off the limit high.
    while (NULL != (segment = nuvo_dlist_remove_head_object(&chosen_segs, struct nuvo_segment, list_node)))
    {
        num_chosen++;
        ck_assert(last_grade >= segment->gc_grade);
        last_grade = segment->gc_grade;
        nuvo_mfst_gc_free_next_cp(mfst, segment);
    }
    ck_assert(num_chosen == 2 * segments_per_parcel);

    while (0 != nuvo_mfst_gc_pipeline_total(mfst))
    {
        nuvo_mfst_gc_starting_cp(mfst);
        (void) nuvo_mfst_cp_done_for_gc(mfst);
    }

    // Now lets clean half of the segments on device 2.

    nuvo_mfst_return_gc_segments(mfst);
}
END_TEST

START_TEST(total_size)
{
    struct nuvo_simple_parcel_manifest pm;
    memset(&pm, 0, sizeof(pm));
    pm.num_parcels = 3;
    pm.manifest[0].size_in_blocks = 1024;
    pm.manifest[1].size_in_blocks = 2048;
    pm.manifest[2].size_in_blocks = 4096;
    ck_assert((1024 + 2048 + 4096) * NUVO_BLOCK_SIZE == pm_total_size(&pm));
}
END_TEST

Suite * nuvo_mfst_suite(void)
{
    Suite *s = suite_create("Manifest");
    TCase *tc_mfst = tcase_create("Manifest");
    tcase_add_checked_fixture(tc_mfst, mfst_tests_setup, mfst_tests_teardown);
    tcase_add_test(tc_mfst, alloc_mfst);
    tcase_add_test(tc_mfst, grow_devices_mem);
    tcase_add_test(tc_mfst, grow_parcels_mem);
    tcase_add_test(tc_mfst, insert_devices);
    tcase_add_test(tc_mfst, insert_device_fails);
    tcase_add_test(tc_mfst, insert_parcels);
    tcase_add_test(tc_mfst, insert_parcels_devices_limit);
    tcase_add_test(tc_mfst, segment_table);
    tcase_add_test(tc_mfst, open_close_parcels);
    tcase_add_test(tc_mfst, super_block);
    tcase_add_test(tc_mfst, basic_manifest_init);
    tcase_add_test(tc_mfst, read_write_manifest);
    tcase_add_test(tc_mfst, manifest_db_init_failure);
    tcase_add_test(tc_mfst, big_manifest);
    tcase_add_test(tc_mfst, mfst_start_info);
    tcase_add_test(tc_mfst, mfst_segment_for_gc);
    suite_add_tcase(s, tc_mfst);

    TCase *tc_device_space_list = tcase_create("Testing inserts into device list");
    tcase_add_test(tc_device_space_list, device_in_free_segment_list);
    suite_add_tcase(s, tc_device_space_list);

    TCase *tc_slog = tcase_create("Segment log operations");
    tcase_add_checked_fixture(tc_slog, mfst_test_slog_setup, mfst_test_slog_teardown);
    tcase_add_test(tc_slog, no_segment_ops);
    tcase_add_test(tc_slog, simple_ops);
    tcase_add_test(tc_slog, simple_ops_no_log);
    tcase_add_test(tc_slog, set_age);
    tcase_add_test(tc_slog, multi_ops);
    tcase_add_test(tc_slog, rollback);
    suite_add_tcase(s, tc_slog);

    TCase *tc_segment_gc = tcase_create("Support for space management");
    tcase_add_checked_fixture(tc_segment_gc, mfst_segment_cleaning_tests_setup, mfst_segment_cleaning_tests_teardown);
    tcase_add_test(tc_segment_gc, segments_avail);
    tcase_add_test(tc_segment_gc, segments_on_device);
    suite_add_tcase(s, tc_segment_gc);

    TCase *tc_simple_parcel = tcase_create("Coverage whoring.");
    tcase_add_test(tc_simple_parcel, total_size);
    suite_add_tcase(s, tc_simple_parcel);

    return s;
}
