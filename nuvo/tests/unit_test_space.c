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
#include <unistd.h>
#include <stdio.h>

#include "../gc.h"
#include "../logger.h"
#include "../log_volume.h"
#include "../manifest_priv.h"
#include "../nuvo_pr.h"
#include "../nuvo_pr_sync.h"
#include "../nuvo_vol_series.h"
#include "../parcel_manager.h"
#include "../space.h"

#include "fake_pr.h"
#include "fake_rl.h"
#include "nuvo_ck_assert.h"

struct {
    unsigned num_devices;
    struct {
        uuid_t      device_uuid;
        uint64_t    parcel_size;
        enum nuvo_dev_type device_type;
    } devices[10];

    struct nuvo_vol vol;
} test_var;


nuvo_return_t nuvo_log_vol_create_lun_int(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    (void)vol;
    (void)lun_uuid;
    return 0;
}

nuvo_return_t nuvo_log_vol_delete_lun_int(struct nuvo_lun *lun)
{
    (void)lun;
    return 0;
}

/* fake volume lookup */
struct nuvo_vol *nuvo_vol_lookup(const uuid_t vs_uuid)
{
    (void) vs_uuid;
    return &test_var.vol;
}

uint64_t nuvo_log_freeze_map_updates(struct nuvo_vol *vol)
{
    (void) vol;
    return 7;
}

void nuvo_log_unfreeze_map_updates(struct nuvo_vol *vol)
{
    (void) vol;
}

void nuvo_log_get_open_segments(struct nuvo_vol        *vol,
                                uint64_t                sequence_no,
                                struct nuvo_segment    *segments,
                                uint32_t               *segment_count)
{
    (void) vol;
    ck_assert(sequence_no == 7);  // TODO - Do better
    *segment_count = 3;
    segments[0].parcel_index = 1;
    segments[0].block_offset = 1024;
    segments[0].subclass = NUVO_SEGMENT_TYPE_DATA;
    segments[1].parcel_index = 2;
    segments[1].block_offset = 2048;
    segments[1].subclass = NUVO_SEGMENT_TYPE_DATA;
    segments[2].parcel_index = 3;
    segments[2].block_offset = 4096;
    segments[2].subclass = NUVO_SEGMENT_TYPE_DATA;
}

nuvo_return_t nuvo_map_lun_open(struct nuvo_lun *lun, const struct nuvo_map_entry *map_entry)
{
    // Mock routine doesn't do anthing.
    (void) lun;
    (void) map_entry;
    return 0;
}

nuvo_return_t nuvo_map_lun_close(struct nuvo_lun *lun, struct nuvo_map_entry *map_entry)
{
    // Mock routine doesn't do anthing.
    (void) lun;
    (void) map_entry;
    return 0;
}
void nuvo_map_try_flush(struct nuvo_vol * vol)
{
    (void)vol;
}

void space_tests_setup() {
    fake_pr_init();

    nuvo_return_t rc;

    test_var.num_devices = 10;
    for (unsigned int i = 0; i < test_var.num_devices; i++)
    {
        uuid_generate(test_var.devices[i].device_uuid);
        test_var.devices[i].parcel_size = 128 * 1024 * 1024;
        test_var.devices[i].device_type = NUVO_DEV_TYPE_SSD;

        rc = nuvo_pm_device_format("blah", test_var.devices[i].device_uuid, test_var.devices[i].parcel_size);
        ck_assert(rc == 0);
        rc = nuvo_pm_device_open("blah", test_var.devices[i].device_uuid, test_var.devices[i].device_type);
        ck_assert(rc == 0);
    }
    uint64_t lun_size = 1024 * 1024 * 1024;

    // Create our basic volume.
    nuvo_mutex_init(&test_var.vol.mutex);
    uuid_t root_parcel_uuid;
    uuid_generate(root_parcel_uuid);
    uuid_generate(test_var.vol.vs_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, test_var.devices[0].device_uuid, test_var.vol.vs_uuid);
    ck_assert(rc == 0);
    uint_fast32_t root_parcel_desc;
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  test_var.devices[0].device_uuid,
                                  test_var.vol.vs_uuid);
    ck_assert(rc == 0);

    rc = nuvo_mfst_sb_init(&test_var.vol.log_volume.sb, &test_var.vol.log_volume.mfst,
            test_var.vol.vs_uuid, test_var.devices[0].device_uuid, root_parcel_uuid, root_parcel_desc,
            test_var.devices[0].parcel_size/NUVO_BLOCK_SIZE, NUVO_DATA_CLASS_A, test_var.devices[0].device_type, NUVO_SEGMENT_MIN_SIZE_BYTES, 10, 20, lun_size);
    ck_assert(rc == 0);

    // write manifest
    rc = nuvo_mfst_sync_write(&test_var.vol.log_volume.mfst, &test_var.vol.log_volume.sb, 1, 1);
    ck_assert(rc == 0);

    // write superblock
    rc = nuvo_sb_sync_write(&test_var.vol.log_volume.sb, root_parcel_desc);
    ck_assert(rc == 0);

    // Do enough lun init.  Don't just call lun_init, because that pulls a thread of includes.
    memset(&test_var.vol.log_volume.lun, 0, sizeof(test_var.vol.log_volume.lun));
    test_var.vol.log_volume.lun.lun_state = NUVO_LUN_STATE_VALID;
    test_var.vol.log_volume.lun.export_state = NUVO_LUN_EXPORT_WRITABLE;
    rc = nuvo_mutex_init(&test_var.vol.log_volume.lun.mutex);
    ck_assert(rc == 0);
}

void space_tests_teardown() {
    nuvo_mutex_destroy(&test_var.vol.log_volume.lun.mutex);
    nuvo_mfst_close(&test_var.vol.log_volume.mfst);
    nuvo_mutex_destroy(&test_var.vol.mutex);
    fake_pr_teardown();
}

void nuvo_map_checkpoint(struct nuvo_map_checkpoint_req *req)
{
    // pretend we wrote maps
    req->callback(req);
}

void make_sure_cp_done(struct nuvo_space_vol *space)
{
    nuvo_space_trigger_cp(space);
    nuvo_mutex_lock(&space->space_vol_mutex);
    while (space->cp_state != NUVO_VOL_SPACE_CPS_NOT_IN_CP || space->cp_requested)
    {
        nuvo_cond_wait(&space->space_vol_cond, &space->space_vol_mutex);
    }
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

void nuvo_process_segment_io_queue(struct nuvo_logger *logger)
{
    (void) logger;
}

START_TEST(space_vol_init_destroy)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_halt();
    nuvo_space_assert_no_cp_work_needed();
}
END_TEST

START_TEST(space_vol_do_cps)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    nuvo_space_vol_manage_cps_start(space);

    //nuvo_mfst_in_core_lock(&test_var.vol.log_volume.mfst);
    uint64_t old_gen = test_var.vol.log_volume.mfst.header.generation;
    //nuvo_mfst_in_core_unlock(&test_var.vol.log_volume.mfst);

    nuvo_space_trigger_cp(space);
    make_sure_cp_done(space);

    //nuvo_mfst_in_core_lock(&test_var.vol.log_volume.mfst);
    uint64_t new_gen = test_var.vol.log_volume.mfst.header.generation;
    // nuvo_mfst_in_core_unlock(&test_var.vol.log_volume.mfst);

    // Might have done 1 CP or maybe 2, depending on race.
    ck_assert(old_gen + 1 <= new_gen);

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_halt();
    nuvo_space_assert_no_cp_work_needed();
}
END_TEST

/**
 * Get segments from vol.  Confirm we get only the ones we should and fail
 * when we should (like avoiding this device).
 * This test uses a single volume. Segments are only unavailable
 * because they've already been requested.
 */

START_TEST(space_vol_get_segments)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    struct nuvo_segment *segment;
    uint_fast32_t avoid_dev[100];

    /*
     * Get a segment and give it back unused, repeating 50 times. The are fewer than 50 segments
     */
    for (unsigned i = 0; i < 50; i++)
    {
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }
    /*
     * Make sure we are not confused into giving out a segment type we do not have.
     */
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    /*
     * But we still have CLASS_A
     */
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment != NULL);
    nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);

    // Check that avoiding device zero leaves none available.
    avoid_dev[0] = 0;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 1, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);

    // Check that if its urgent we get a device 0, even if avoiding it
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 1, avoid_dev, NUVO_SPACE_SEGMENT_TRY_AVOID);
    ck_assert(segment != NULL);
    nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);

    /*
     * Parcel size is 128MB, and segments 4MB, so 32 segments of which one is reserved.
     * So we should be able to get 31.
     */
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);
    for (unsigned i = 0; i < 31; i++)
    {
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
        nuvo_dlist_insert_tail(&parking, &segment->list_node);
    }
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA,  0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    while (NULL != (segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node)))
    {
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_assert_no_cp_work_needed();
    nuvo_space_halt();
}
END_TEST

// Confirm that setting blocks in use will make segments unavailable.
//     blk_count
//     age
//     io

START_TEST(space_vol_two_parcels)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    uuid_t parcel_uuid;
    uuid_clear(parcel_uuid);
    rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, test_var.devices[0].device_uuid, test_var.vol.vs_uuid);
    ck_assert(rc == 0);

    uint16_t num_segments_added = 0;
    uint8_t data_class_added;
    rc = nuvo_mfst_insert_parcel(&test_var.vol.log_volume.mfst, test_var.devices[0].device_uuid, parcel_uuid,
                                    NUVO_SEGMENT_MIN_SIZE_BYTES, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
    ck_assert(rc == 0);

    // Have not done checkpoint, so we haven't aded any segments, get the first 31.
    struct nuvo_segment *segment;
    uint_fast32_t avoid_dev[4];
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);
    for (unsigned i = 0; i < 31; i++)
    {
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
        ck_assert(segment != NULL);
        nuvo_dlist_insert_tail(&parking, &segment->list_node);
    }
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);

    // Now write the manifest.
    rc = nuvo_mfst_sync_write(&test_var.vol.log_volume.mfst, &test_var.vol.log_volume.sb, 1, 1);
    ck_assert(rc == 0);

    // Should get 32 more.
    for (unsigned i = 0; i < 32; i++)
    {
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
        ck_assert(segment != NULL);
        nuvo_dlist_insert_tail(&parking, &segment->list_node);
    }
    // but no more than that.
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    avoid_dev[0] = 1;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 1, avoid_dev, NUVO_SPACE_SEGMENT_TRY_AVOID);
    ck_assert(segment == NULL);

    // Give it all back
    while (NULL != (segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node)))
    {
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }
    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_assert_no_cp_work_needed();
    nuvo_space_halt();
}
END_TEST

// Add 2 more devices in same data class, add manual parcels, exercise exclusion.
START_TEST(space_three_similar_devices)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    struct nuvo_segment *segment;
    uint_fast32_t avoid_dev[4];
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);

    uint64_t device_size;
    uint64_t parcel_size;
    enum nuvo_dev_type device_type;


    // Mimic what alloc parcels handler does.
    for (unsigned i = 1; i < 3; i++)
    {
        rc = nuvo_pr_sync_dev_info(test_var.devices[i].device_uuid, &device_size, &parcel_size, &device_type);
        ck_assert(rc == 0);
        ck_assert(parcel_size == test_var.devices[i].parcel_size);
        ck_assert(device_type == test_var.devices[i].device_type);

        rc = nuvo_mfst_insert_device(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, NUVO_DATA_CLASS_A, test_var.devices[i].device_type, parcel_size/NUVO_BLOCK_SIZE);
        ck_assert(rc == 0);

        rc = nuvo_mfst_device_parcel_target(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, 1);
        ck_assert(rc == 0);

        uuid_t parcel_uuid;
        uuid_clear(parcel_uuid);
        rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, test_var.devices[i].device_uuid, test_var.vol.vs_uuid);
        ck_assert(rc == 0);

        uint16_t num_segments_added = 0;
        uint8_t data_class_added;
        rc = nuvo_mfst_insert_parcel(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, parcel_uuid,
                                        NUVO_SEGMENT_MIN_SIZE_BYTES, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);

    }

    // write manifest
    rc = nuvo_mfst_sync_write(&test_var.vol.log_volume.mfst, &test_var.vol.log_volume.sb, 1, 1);
    ck_assert(rc == 0);

    // currently 31, 32, 32 free
    avoid_dev[0] = 0;
    avoid_dev[1] = 1;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 2, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment != NULL);
    ck_assert(segment->device_index == 2);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);
    // currently 31, 32, 31 free
    avoid_dev[0] = 0;
    avoid_dev[1] = 2;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 2, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment != NULL);
    ck_assert(segment->device_index == 1);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);
    // currently 31, 31, 31 free
    avoid_dev[0] = 1;
    avoid_dev[1] = 2;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 2, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment != NULL);
    ck_assert(segment->device_index == 0);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);
    // currently 30, 31, 31 free
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment != NULL);
    ck_assert(segment->device_index == 1 || segment->device_index == 2);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);
    uint16_t last_dev = segment->device_index;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment != NULL);
    ck_assert(segment->device_index == 1 || segment->device_index == 2);
    ck_assert(segment->device_index == 3 - last_dev);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    // currently 30, 30, 30 free
    avoid_dev[0] = 0;
    avoid_dev[1] = 2;
    for (unsigned i = 0; i < 30; i++)
    {
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 2, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
        ck_assert(segment != NULL);
        ck_assert(segment->device_index == 1);
        nuvo_dlist_insert_tail(&parking, &segment->list_node);
    }
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 2, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    //

    // Give it all back
    while (NULL != (segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node)))
    {
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_assert_no_cp_work_needed();
    nuvo_space_halt();
}
END_TEST

/**
 * Add 2 more devices in same data class
 * Tests that
 */
START_TEST(manage_parcels)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    struct nuvo_segment *segment;
    uint_fast32_t avoid_dev[4];
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);

    uint64_t device_size;
    uint64_t parcel_size;
    enum nuvo_dev_type device_type;

    // Mimic what alloc parcels handler does.
    for (unsigned i = 1; i < 3; i++)
    {
        rc = nuvo_pr_sync_dev_info(test_var.devices[i].device_uuid, &device_size, &parcel_size, &device_type);
        ck_assert(rc == 0);
        ck_assert(parcel_size == test_var.devices[i].parcel_size);
        ck_assert(device_type == test_var.devices[i].device_type);

        rc = nuvo_mfst_insert_device(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, NUVO_DATA_CLASS_A, test_var.devices[i].device_type, parcel_size/NUVO_BLOCK_SIZE);
        ck_assert(rc == 0);

        rc = nuvo_mfst_device_parcel_target(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, 1);
        ck_assert(rc == 0);
    }

    // write manifest
    rc = nuvo_mfst_sync_write(&test_var.vol.log_volume.mfst, &test_var.vol.log_volume.sb, 1, 1);
    ck_assert(rc == 0);

    // No parcels added yet, so no parcels not on dev 0.
    avoid_dev[0] = 0;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 1, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);

    nuvo_space_vol_manage_parcels_start(space);
    nuvo_space_vol_manage_parcels_suggest(space, NUVO_DATA_CLASS_A);

    // No parcels added yet.
    avoid_dev[0] = 0;
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 1, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    ck_assert(test_var.vol.log_volume.mfst.data_class[NUVO_DATA_CLASS_A].gc_free_current_cp == 0);
    // TODO - would be nice to make absolute assertions about how rapidly we add segments.

    nuvo_space_vol_manage_cps_start(space);

    avoid_dev[0] = 0;
    segment = NULL;
    while (segment == NULL)
    {
        nuvo_space_trigger_cp(space);
        make_sure_cp_done(space);
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 1, avoid_dev, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    }
    ck_assert(segment != NULL);
    ck_assert(segment->device_index != 0);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    // Give it all back
    while (NULL != (segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node)))
    {
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_assert_no_cp_work_needed();
    nuvo_space_halt();
}
END_TEST

// Manage parcels in two classes.
START_TEST(manage_two_classes)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    struct nuvo_segment *segment;
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);

    uint64_t device_size;
    uint64_t parcel_size;
    enum nuvo_dev_type device_type;

    // Mimic what alloc parcels handler does.
    for (unsigned i = 1; i < 5; i++)
    {
        rc = nuvo_pr_sync_dev_info(test_var.devices[i].device_uuid, &device_size, &parcel_size, &device_type);
        ck_assert(rc == 0);
        ck_assert(parcel_size == test_var.devices[i].parcel_size);
        ck_assert(device_type == test_var.devices[i].device_type);

        uint8_t device_class = (i <= 2) ? NUVO_DATA_CLASS_B : NUVO_DATA_CLASS_C;
        rc = nuvo_mfst_insert_device(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, device_class, test_var.devices[i].device_type, parcel_size/NUVO_BLOCK_SIZE);
        ck_assert(rc == 0);
    }
    // No parcels added yet.
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_C, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);

    // Now tell it to use one parcel on device 1, which is class B, and one on device 3 (class C)
    rc = nuvo_mfst_device_parcel_target(&test_var.vol.log_volume.mfst, test_var.devices[1].device_uuid, 1);
    ck_assert(rc == 0);
    rc = nuvo_mfst_device_parcel_target(&test_var.vol.log_volume.mfst, test_var.devices[3].device_uuid, 1);
    ck_assert(rc == 0);

    // Still no segments, since not managing parcels nor doing CPs.
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_C, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);

    nuvo_space_vol_manage_parcels_start(space);

    // Still no segments, since no CPs.
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);
    segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_C, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    ck_assert(segment == NULL);

    nuvo_space_vol_manage_cps_start(space);

    // Now classes B and C should become available.
    segment = NULL;
    while (segment == NULL)
    {
        make_sure_cp_done(space);
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    }
    ck_assert(segment != NULL);
    ck_assert(segment->data_class == NUVO_DATA_CLASS_B);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    segment = NULL;
    while (segment == NULL)
    {
        make_sure_cp_done(space);
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_C, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    }
    ck_assert(segment != NULL);
    ck_assert(segment->data_class == NUVO_DATA_CLASS_C);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    // Siphon off all of classes B and C
    while (NULL != (segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID)))
    {
        ck_assert(segment->data_class == NUVO_DATA_CLASS_B);
        nuvo_dlist_insert_tail(&parking, &segment->list_node);
    }
    while (NULL != (segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_C, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID)))
    {
        ck_assert(segment->data_class == NUVO_DATA_CLASS_C);
        nuvo_dlist_insert_tail(&parking, &segment->list_node);
    }

    // Of course A is still available.
    segment = NULL;
    while (segment == NULL)
    {
        make_sure_cp_done(space);
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_A, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    }
    ck_assert(segment != NULL);
    ck_assert(segment->data_class == NUVO_DATA_CLASS_A);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    // Now tell it to use one more parcel on each.
    rc = nuvo_mfst_device_parcel_target(&test_var.vol.log_volume.mfst, test_var.devices[1].device_uuid, 2);
    ck_assert(rc == 0);
    rc = nuvo_mfst_device_parcel_target(&test_var.vol.log_volume.mfst, test_var.devices[3].device_uuid, 2);
    ck_assert(rc == 0);

    // Now classes B and C should become available.
    segment = NULL;
    while (segment == NULL)
    {
        make_sure_cp_done(space);
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_B, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    }
    ck_assert(segment != NULL);
    ck_assert(segment->data_class == NUVO_DATA_CLASS_B);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    segment = NULL;
    while (segment == NULL)
    {
        make_sure_cp_done(space);
        segment = nuvo_space_vol_segment_get(space, NUVO_DATA_CLASS_C, NUVO_SEGMENT_TYPE_DATA, 0, NULL, NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    }
    ck_assert(segment != NULL);
    ck_assert(segment->data_class == NUVO_DATA_CLASS_C);
    nuvo_dlist_insert_tail(&parking, &segment->list_node);

    // Give it all back
    while (NULL != (segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node)))
    {
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_assert_no_cp_work_needed();
    nuvo_space_halt();
}
END_TEST

// Store and get log starts.
START_TEST(log_starts)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);

    uint64_t segment_size_blocks[3];
    segment_size_blocks[0] = NUVO_SEGMENT_MIN_SIZE_BYTES / NUVO_BLOCK_SIZE;
    segment_size_blocks[1] = 2 * NUVO_SEGMENT_MIN_SIZE_BYTES / NUVO_BLOCK_SIZE;
    segment_size_blocks[2] = 3 * NUVO_SEGMENT_MIN_SIZE_BYTES / NUVO_BLOCK_SIZE;
    // Add 2 parcels on 2 devices
    for (unsigned i = 1; i < 3; i++)
    {
        uint64_t device_size;
        uint64_t parcel_size;
        enum nuvo_dev_type device_type;
        rc = nuvo_pr_sync_dev_info(test_var.devices[i].device_uuid, &device_size, &parcel_size, &device_type);
        ck_assert(rc == 0);
        ck_assert(parcel_size == test_var.devices[i].parcel_size);
        ck_assert(device_type == test_var.devices[i].device_type);

        rc = nuvo_mfst_insert_device(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, NUVO_DATA_CLASS_A + i, test_var.devices[i].device_type, parcel_size/NUVO_BLOCK_SIZE);
        ck_assert(rc == 0);

        uuid_t parcel_uuid;
        uuid_clear(parcel_uuid);
        rc = nuvo_pr_sync_parcel_alloc(parcel_uuid, test_var.devices[i].device_uuid, test_var.vol.vs_uuid);
        ck_assert(rc == 0);

        uint16_t num_segments_added = 0;
        uint8_t data_class_added;
        rc = nuvo_mfst_insert_parcel(&test_var.vol.log_volume.mfst, test_var.devices[i].device_uuid, parcel_uuid,
                                        segment_size_blocks[i] * NUVO_BLOCK_SIZE, &num_segments_added, &data_class_added, NUVO_VOL_PD_UNUSED);
        ck_assert(rc == 0);
        ck_assert(data_class_added == NUVO_DATA_CLASS_A + i);
    }

    struct nuvo_segment log_starts[3];
    log_starts[0].parcel_index = 0;
    log_starts[0].block_offset = 7 * segment_size_blocks[0];
    log_starts[0].subclass = NUVO_SEGMENT_TYPE_DATA;
    log_starts[1].parcel_index = 1;
    log_starts[1].block_offset = 6 * segment_size_blocks[1];
    log_starts[1].subclass = NUVO_SEGMENT_TYPE_DATA;
    log_starts[2].parcel_index = 1;
    log_starts[2].block_offset = 3 * segment_size_blocks[1];
    log_starts[2].subclass = NUVO_SEGMENT_TYPE_DATA;
    nuvo_mfst_log_starts_set(&test_var.vol.log_volume.mfst, 4, log_starts, 3);

    // Now write the manifest.
    rc = nuvo_mfst_sync_write(&test_var.vol.log_volume.mfst, &test_var.vol.log_volume.sb, 4, 16);
    ck_assert(rc == 0);

    unsigned num = NUVO_MFST_NUM_LOG_STARTS;
    struct nuvo_segment get_log_addrs[NUVO_MFST_NUM_LOG_STARTS];
    uint64_t seq_no;
    uint64_t seg_cnt_seq_no;
    nuvo_mfst_log_starts_get(&test_var.vol.log_volume.mfst,
                             &seq_no,
                             &seg_cnt_seq_no,
                             &num,
                             get_log_addrs);
    ck_assert(num == 3);
    ck_assert(seq_no == 4);
    ck_assert(seg_cnt_seq_no == 16);
    for (unsigned i = 0; i < num; i++)
    {
        struct nuvo_segment *segment;
        ck_assert(log_starts[i].parcel_index == get_log_addrs[i].parcel_index);
        ck_assert(log_starts[i].block_offset == get_log_addrs[i].block_offset);
        rc = nuvo_space_vol_segment_log_replay_get(space, get_log_addrs[i].parcel_index, get_log_addrs[i].block_offset, &segment);
        ck_assert(rc == 0);
        ck_assert(segment->block_count == segment_size_blocks[segment->parcel_index]);
        ck_assert(segment->parcel_desc != 0);
        ck_assert(segment->device_index == get_log_addrs[i].parcel_index);   // We put each parcel on its own device.
        ck_assert(segment->data_class == NUVO_DATA_CLASS_A + segment->parcel_index);
        i++;
        nuvo_space_vol_segment_done(space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    }

    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_assert_no_cp_work_needed();
    nuvo_space_halt();
}
END_TEST

// Mock gc

struct {
    unsigned nuvo_gc_read_digest_calls;
    unsigned nuvo_gc_elide_unused_batch_calls;
    unsigned nuvo_gc_move_data_batch_calls;
    unsigned nuvo_gc_move_maps_batch_calls;
    unsigned nuvo_gc_done_calls;
} mock_gc;

nuvo_return_t nuvo_gc_read_digest(struct nuvo_gc *gc)
{
    mock_gc.nuvo_gc_read_digest_calls++;
    if (gc->tag.ptr)
    {
        nuvo_mutex_unlock(gc->tag.ptr);
    }
    return 0;
}

nuvo_return_t nuvo_gc_elide_unused_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    (void) gc_batch;
    mock_gc.nuvo_gc_elide_unused_batch_calls++;
    if (gc->tag.ptr)
    {
        nuvo_mutex_unlock(gc->tag.ptr);
    }
    return 0;
}
nuvo_return_t nuvo_gc_move_data_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    (void) gc_batch;
    mock_gc.nuvo_gc_move_data_batch_calls++;
    if (gc->tag.ptr)
    {
        nuvo_mutex_unlock(gc->tag.ptr);
    }
    return 0;
}

nuvo_return_t nuvo_gc_move_maps_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    (void) gc_batch;
    mock_gc.nuvo_gc_move_maps_batch_calls++;
    if (gc->tag.ptr)
    {
        nuvo_mutex_unlock(gc->tag.ptr);
    }
    return 0;
}

void nuvo_gc_done(struct nuvo_gc *gc)
{
    mock_gc.nuvo_gc_done_calls++;
    if (gc->tag.ptr)
    {
        nuvo_mutex_unlock(gc->tag.ptr);
    }
}

// This walks through the state machine.
// Doesn't use actual GC.
START_TEST(gc_work)
{
    nuvo_return_t rc = nuvo_space_init();
    ck_assert(rc == 0);

    nuvo_mutex_t sync_signal;
    rc = nuvo_mutex_init(&sync_signal);
    ck_assert(rc == 0);

    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    rc = nuvo_space_vol_init(space);
    ck_assert(rc == 0);

    struct nuvo_gc* gc = nuvo_gc_alloc();
    nuvo_gc_init(gc, &test_var.vol, NULL);  // No segment because we're not doing real work.
    gc->tag.ptr = &sync_signal;
    nuvo_mutex_lock(gc->tag.ptr);

    // Segment just so NUVO_LOG messages can print.
    struct nuvo_segment segment;
    segment.parcel_index = 3;
    segment.block_offset = 4096;
    segment.data_class = 0;
    gc->segment = &segment;

    // Now confirm that if we have a gc that is on the work list in the NUVO_SPACE_GC_DIGEST_READING state
    // it gets pulled off list and nuvo_gc_read_digest is called.
    gc->state = NUVO_SPACE_GC_DIGEST_READING;
    unsigned old_calls = mock_gc.nuvo_gc_read_digest_calls;
    nuvo_gc_needs_work(gc);
    nuvo_mutex_lock(gc->tag.ptr); // Wait for space thread to unlock this.
    ck_assert(old_calls + 1 == mock_gc.nuvo_gc_read_digest_calls);
    struct nuvo_gc* gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);

    // Now confirm that if we have a gc that is on the work list in the NUVO_SPACE_GC_DIGEST_ELIDING state
    // it either gets pulled off list and nuvo_gc_elide_unused_batch is called with an available nuvo_gc_batch or
    // it goes on the list needing a nuvo_gc_batch.
    gc->state = NUVO_SPACE_GC_DIGEST_ELIDING;
    struct nuvo_dlist gc_batch_parking;
    nuvo_dlist_init(&gc_batch_parking);
    struct nuvo_gc_batch *gc_batch;
    while (NULL != (gc_batch = nuvo_gc_batch_alloc()))
    {
        nuvo_dlist_insert_tail(&gc_batch_parking, &gc_batch->list_node);
    }

    // There are no nuvo_gc_batch available, so this elide will not get called.
    old_calls = mock_gc.nuvo_gc_elide_unused_batch_calls;
    nuvo_gc_needs_work(gc);
    // TODO - wait until it is on waiting for worker list?
    // gc2 = nuvo_gc_needs_work_get();
    // ck_assert(gc2 == NULL);
    ck_assert(old_calls == mock_gc.nuvo_gc_elide_unused_batch_calls);

    // Now we will free up nuvo_gc_batch's and the elide WILL get called.
    while (NULL != (gc_batch = nuvo_dlist_remove_head_object(&gc_batch_parking, struct nuvo_gc_batch, list_node)))
    {
        nuvo_gc_batch_free(gc_batch);
    }
    // Freeing the gc_batch should have moved gc to the work list.
    nuvo_mutex_lock(gc->tag.ptr); // Wait for space thread to unlock this.
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);
    NUVO_ASSERT(old_calls + 1 == mock_gc.nuvo_gc_elide_unused_batch_calls);

    // Now confirm that if we have a gc that is on the work list in the NUVO_SPACE_GC_MOVING_DATA state
    // it either gets pulled off list and nuvo_gc_move_data_batch is called with an available nuvo_gc_batch or
    // it goes on the list needing a nuvo_gc_batch.
    gc->state = NUVO_SPACE_GC_MOVING_DATA;
    while (NULL != (gc_batch = nuvo_gc_batch_alloc()))
    {
        nuvo_dlist_insert_tail(&gc_batch_parking, &gc_batch->list_node);
    }
    old_calls = mock_gc.nuvo_gc_move_data_batch_calls;
    nuvo_gc_needs_work(gc);
    // TODO - wait until it is on waiting for worker list?
    // gc2 = nuvo_gc_needs_work_get();
    // ck_assert(gc2 == NULL);
    ck_assert(old_calls == mock_gc.nuvo_gc_move_data_batch_calls);

    while (NULL != (gc_batch = nuvo_dlist_remove_head_object(&gc_batch_parking, struct nuvo_gc_batch, list_node)))
    {
        nuvo_gc_batch_free(gc_batch);
    }
    // Freeing the gc_batch should have moved gc to the work list.
    nuvo_mutex_lock(gc->tag.ptr); // Wait for space thread to unlock this.
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);
    NUVO_ASSERT(old_calls + 1 == mock_gc.nuvo_gc_move_data_batch_calls);

    // Now confirm that if we have a gc that is on the work list in the NUVO_SPACE_GC_MOVE_MAPS state
    // it either gets pulled off list and nuvo_gc_move_maps_batch is called with an available nuvo_gc_batch or
    // it goes on the list needing a nuvo_gc_batch.
    gc->state = NUVO_SPACE_GC_MOVE_MAPS;
    while (NULL != (gc_batch = nuvo_gc_batch_alloc()))
    {
        nuvo_dlist_insert_tail(&gc_batch_parking, &gc_batch->list_node);
    }
    old_calls = mock_gc.nuvo_gc_move_maps_batch_calls;
    nuvo_gc_needs_work(gc);
    // TODO - wait until it is on waiting for worker list?
    // gc2 = nuvo_gc_needs_work_get();
    // ck_assert(gc2 == NULL);
    ck_assert(old_calls == mock_gc.nuvo_gc_move_maps_batch_calls);

    while (NULL != (gc_batch = nuvo_dlist_remove_head_object(&gc_batch_parking, struct nuvo_gc_batch, list_node)))
    {
        nuvo_gc_batch_free(gc_batch);
    }
    // Freeing the gc_batch should have moved gc to the work list.
    nuvo_mutex_lock(gc->tag.ptr); // Wait for space thread to unlock this.
    ck_assert(old_calls + 1 == mock_gc.nuvo_gc_move_maps_batch_calls);
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);

    gc->state = NUVO_SPACE_GC_MOVING_DONE;
    old_calls = mock_gc.nuvo_gc_done_calls;

    ck_assert(old_calls == mock_gc.nuvo_gc_done_calls);
    nuvo_gc_needs_work(gc);
    nuvo_mutex_lock(gc->tag.ptr); // Wait for space thread to unlock this.
    ck_assert(old_calls + 1 == mock_gc.nuvo_gc_done_calls);

    nuvo_gc_free(gc);
    nuvo_space_vol_stop_management(space);
    nuvo_space_vol_destroy(space);
    nuvo_space_halt();
}
END_TEST

Suite * nuvo_space_suite(void)
{
    Suite *s = suite_create("Space");
    TCase *tc_space = tcase_create("Space");
    tcase_add_checked_fixture(tc_space, space_tests_setup, space_tests_teardown);

    tcase_add_test(tc_space, space_vol_init_destroy);
    tcase_add_test(tc_space, space_vol_do_cps);
    tcase_add_test(tc_space, space_vol_get_segments);
    tcase_add_test(tc_space, space_vol_two_parcels);
    tcase_add_test(tc_space, space_three_similar_devices);
    tcase_add_test(tc_space, manage_parcels);
    tcase_add_test(tc_space, manage_two_classes);
    tcase_add_test(tc_space, log_starts);
    tcase_add_test(tc_space, gc_work);
    suite_add_tcase(s, tc_space);
    return s;
}
