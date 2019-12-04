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

/* *INDENT_OFF* */

struct {
    unsigned num_devices;
    struct {
        uuid_t      device_uuid;
        uint64_t    parcel_size;
        enum nuvo_dev_type device_type;
    } devices[10];
    uuid_t root_parcel_uuid;
    struct nuvo_vol vol;
} test_var;

bool nuvo_vol_is_fake_paused(const uuid_t vs_uuid)
{
    (void)vs_uuid;
    return false;
}

/* fake volume lookup */
struct nuvo_vol *nuvo_vol_lookup(const uuid_t vs_uuid)
{
    (void) vs_uuid;
    return &test_var.vol;
}

void open_after_mfst(struct nuvo_vol *vol) {
    nuvo_return_t rc;
    rc = nuvo_space_vol_init(&vol->log_volume.space);
    nuvo_ck_assert(rc == 0);
    rc = nuvo_multi_lun_init(vol);
    nuvo_ck_assert(rc == 0);
    nuvo_mfst_get_luns(vol, vol->log_volume.lun_list,
                 NUVO_ARRAY_LENGTH(vol->log_volume.lun_list));
    nuvo_ck_assert(rc == 0);
    //vol->log_volume.lun.id = 0xFFFFFFFF;

    struct nuvo_log_replay_request replay_req;
    replay_req.vol = vol;
    replay_req.segment_count = NUVO_MFST_NUM_LOG_STARTS;
    nuvo_mfst_log_starts_get(&vol->log_volume.mfst,
                             &replay_req.sequence_no,
                             &replay_req.segment_cnt_sequence_no,
                             &replay_req.segment_count,
                             replay_req.replay_segments);

    rc = nuvo_log_init(vol);
    nuvo_ck_assert(rc == 0);

    rc = nuvo_mutex_init(&vol->mutex);
    nuvo_ck_assert(rc == 0);

    nuvo_map_vol_state_init(&vol->log_volume.map_state, vol);

    rc = nuvo_map_multi_luns_open(vol);
    NUVO_ASSERT(rc == 0);

    rc = nuvo_log_sync_replay(&replay_req);
    nuvo_ck_assert(rc == 0);
}

void create_vol(struct nuvo_vol *vol, uuid_t root_parcel_uuid) {
    memset(vol, 0, sizeof(*vol));
    nuvo_return_t rc;

    uint64_t lun_size = 64 * 1024 * 1024;

    // Create our basic volume.
    uuid_generate(vol->vs_uuid);
    rc = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, test_var.devices[0].device_uuid, vol->vs_uuid);
    nuvo_ck_assert(rc == 0);
    uint_fast32_t root_parcel_desc;
    rc = nuvo_pr_sync_parcel_open(&root_parcel_desc,
                                  root_parcel_uuid,
                                  test_var.devices[0].device_uuid,
                                  vol->vs_uuid);
    nuvo_ck_assert(rc == 0);

    rc = nuvo_mfst_sb_init(&vol->log_volume.sb, &vol->log_volume.mfst,
            vol->vs_uuid, test_var.devices[0].device_uuid, root_parcel_uuid, root_parcel_desc,
            test_var.devices[0].parcel_size/NUVO_BLOCK_SIZE, NUVO_DATA_CLASS_A, test_var.devices[0].device_type, NUVO_SEGMENT_MIN_SIZE_BYTES, 10, 20, lun_size);
    nuvo_ck_assert(rc == 0);

    // write manifest
    rc = nuvo_mfst_sync_write(&vol->log_volume.mfst, &vol->log_volume.sb, 1, 1);
    nuvo_ck_assert(rc == 0);

    // write superblock
    rc = nuvo_sb_sync_write(&vol->log_volume.sb, root_parcel_desc);
    nuvo_ck_assert(rc == 0);

    open_after_mfst(vol);
}

void open_vol(struct nuvo_vol  *vol,
              const uuid_t      vs_uuid,
              const uuid_t      root_parcel_uuid) {
    memset(vol, 0, sizeof(*vol));
    uuid_copy(vol->vs_uuid, vs_uuid);
    uint_fast32_t parcel_desc;
    nuvo_return_t rc = nuvo_pr_sync_parcel_open(&parcel_desc, root_parcel_uuid, test_var.devices[0].device_uuid, vs_uuid);
    nuvo_ck_assert(rc == 0);
    rc = nuvo_sb_sync_read(&vol->log_volume.sb, parcel_desc);
    nuvo_ck_assert(rc == 0);
    rc = nuvo_mfst_sync_read(&vol->log_volume.mfst,
                             &vol->log_volume.sb,
                             parcel_desc,
                             false);
    nuvo_ck_assert(rc == 0);
    open_after_mfst(vol);
}

void close_vol(struct nuvo_vol *vol) {

    nuvo_space_vol_stop_management(&vol->log_volume.space);
    nuvo_return_t rc;
    rc = nuvo_map_lun_close(&vol->log_volume.lun, &vol->log_volume.lun.root_map_entry);

    unsigned int lun_max_count = sizeof(vol->log_volume.lun_list)/sizeof(vol->log_volume.lun_list[0]);

    for(unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun * lun = &(vol->log_volume.lun_list[i]);

        if (lun->lun_state != NUVO_LUN_STATE_FREE)
        {
            nuvo_map_lun_close(lun, &lun->root_map_entry);
            nuvo_lun_destroy(lun);
        }

    }
    nuvo_ck_assert(rc == 0);
    nuvo_map_vol_state_destroy(&vol->log_volume.map_state);
    nuvo_mutex_destroy(&vol->mutex);
    nuvo_log_shutdown(vol);
    nuvo_space_vol_destroy(&vol->log_volume.space);
    nuvo_mfst_close(&vol->log_volume.mfst);
    nuvo_lun_destroy(&vol->log_volume.lun);
}

nuvo_return_t nuvo_gc_read_digest(struct nuvo_gc *gc)
{
    (void) gc;
    return 0;
}

nuvo_return_t nuvo_gc_elide_unused_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    (void) gc;
    (void) gc_batch;
    return 0;
}

nuvo_return_t nuvo_gc_move_data_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    (void) gc;
    (void) gc_batch;
    return 0;
}

nuvo_return_t nuvo_gc_move_maps_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    (void) gc;
    (void) gc_batch;
    return 0;
}

void nuvo_gc_done(struct nuvo_gc *gc)
{
    (void) gc;
}

void map_replay_tests_setup() {
    fake_pr_init();
    nuvo_io_concat_pool_init(100);
    nuvo_return_t rc;
    test_var.num_devices = 1;
    for (unsigned int i = 0; i < test_var.num_devices; i++)
    {
        uuid_generate(test_var.devices[i].device_uuid);
        test_var.devices[i].parcel_size = 128 * 1024 * 1024;
        test_var.devices[i].device_type = NUVO_DEV_TYPE_SSD;

        rc = nuvo_pm_device_format("blah", test_var.devices[i].device_uuid, test_var.devices[i].parcel_size);
        nuvo_ck_assert(rc == 0);
        rc = nuvo_pm_device_open("blah", test_var.devices[i].device_uuid, test_var.devices[i].device_type);
        nuvo_ck_assert(rc == 0);
    }
    nuvo_map_init();
    rc = nuvo_space_init();
    nuvo_ck_assert(rc == 0);
}

void map_replay_tests_teardown() {
    // halt map
    nuvo_map_shutdown();
    nuvo_io_concat_pool_destroy();
    fake_pr_teardown();
}

static void fill_data(uint64_t fbn, uint64_t gen, uint64_t *data)
{
    memset(data, 0, NUVO_BLOCK_SIZE);
    data[0] = fbn;
    data[1] = fbn+1;  // Make sure we don't get constant filled by mistake.
    data[2] = gen;
}
static void check_data(uint64_t fbn, uint64_t gen, uint64_t *data)
{
    ck_assert(data[0] == fbn);
    ck_assert(data[1] == fbn+1);
    ck_assert(data[2] == gen);
}

#define CHECK_DATA(fbn, gen, data) do{ \
    if ((data[0] != fbn) || \
        (data[1] != (fbn+1)) || \
        (data[2] != (gen)))  \
    {\
        NUVO_ERROR_PRINT("Check data error:data[0, 1, 2]:recieved:|%u %u %u|"\
                                " expected "\
                                "|%u %u %u|"\
                                " fbn:|%lu|"\
                                " gen:|%lu|\n", \
                                data[0], data[1], data[2],\
                                fbn, fbn + 1, gen,\
                                fbn, gen);\
    }\
    ck_assert_msg(data[0] == (fbn), "data[0]:%u fbn:%lu\n", data[0], fbn);\
    ck_assert_msg(data[1] == (fbn)+1, "data[1]:%u fbn:%lu\n", data[1], fbn + 1);\
    ck_assert_msg(data[2] == (gen), "data[2]:%u gen:%lu\n", data[2], gen);\
}while(0)
START_TEST(basic_snap_io)
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    void* buf_list[128];
    buf_list[0] = buffer;
    //uint32_t lun_blocks = 255;
    uint32_t lun_blocks = 600;

    struct nuvo_vol *vol = &test_var.vol;
    uuid_t root_parcel_uuid;
    uuid_generate(root_parcel_uuid);

    create_vol(vol, root_parcel_uuid);
                             /* this must be from the lun number */
    NUVO_ASSERT(vol->log_volume.lun.snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID);

    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, 1, (uint64_t *) buffer);
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, 1, buf_list);
        nuvo_ck_assert(rc == 0);
    }
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        check_data(bno, 1, ((uint64_t *) buffer));
    }

    uuid_t lun_uuid;
    uuid_generate(lun_uuid);

    // create a snapshot
    nuvo_return_t rc =  nuvo_log_vol_create_lun_int(vol, lun_uuid);
    NUVO_ASSERT(!rc);

    // get the lun pointer for the latest snapshot

    struct nuvo_lun * snap_lun =  nuvo_get_peer_cow_lun(vol, false);
    NUVO_ASSERT(snap_lun);






    //vol->log_volume.lun_list[1] = snap_lun;

    uint8_t buffer2[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    buf_list[0] = buffer2;
    lun_blocks = 300; //only write to first 300 blocks */
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, 2, (uint64_t *) buffer2);
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, 1, buf_list);
        nuvo_ck_assert(rc == 0);
    }

    // now read from active from 0-300 -600 and check it is 2
    uint8_t buffer3[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    buf_list[0] = buffer3;
    //only read from  first 300 blocks */
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        CHECK_DATA(bno, 2 , ((uint64_t *) buffer3));
    }

    // now read from active from 300 -600 and check it is 1
    uint8_t buffer4[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    buf_list[0] = buffer4;
    for (unsigned bno = 300; bno < 600; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        CHECK_DATA(bno, 1, ((uint64_t *) buffer4));
    }
    // now read from snapshot from 600 and check it is 1
    buf_list[0] = buffer4;
    for (unsigned bno = 0; bno < 600; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        CHECK_DATA(bno, 1, ((uint64_t *) buffer4));
    }

    NUVO_ERROR_PRINT("success so far");

    struct nuvo_lun * snap_lun_2 = NULL;

    uuid_t lun_uuid_2;
    uuid_generate(lun_uuid_2);

    rc =  nuvo_log_vol_create_lun_int(vol, lun_uuid_2);
    NUVO_ASSERT(!rc);

    //nuvo_return_t rc = nuvo_lun_init(snap_lun, vol);
    snap_lun_2 =  nuvo_get_peer_cow_lun(vol, false);
    NUVO_ASSERT(snap_lun_2);

    // now read from snapshot from 600 and check it is 1
    buf_list[0] = buffer4;
    for (unsigned bno = 0; bno < 600; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        CHECK_DATA(bno, 1, ((uint64_t *) buffer4));
    }
    uint8_t *read_bufs[32];
    for (int j = 0; j < 32; j++)
    {
        read_bufs[j] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[j], NULL);
    }
    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, 32, (void**)read_bufs, NULL);
        nuvo_ck_assert(rc == 0);
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno < 600); j++)
        {
            CHECK_DATA(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
    }

    /*cp the lun */
    rc = nuvo_map_lun_close(&vol->log_volume.lun, &vol->log_volume.lun.root_map_entry);
    NUVO_ASSERT(!rc);
    /* close the snap lun */
    rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
    NUVO_ASSERT(!rc);
    rc = nuvo_map_lun_close(snap_lun_2, &snap_lun_2->root_map_entry);
    NUVO_ASSERT(!rc);

    /* now open the lun and snap lun
     and make sure data is all good */
    rc = nuvo_map_lun_open(&vol->log_volume.lun, &vol->log_volume.lun.root_map_entry);
    NUVO_ASSERT(!rc);
    rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
    NUVO_ASSERT(!rc);
    rc = nuvo_map_lun_open(snap_lun_2, &snap_lun_2->root_map_entry);
    NUVO_ASSERT(!rc);


    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, 32, (void**)read_bufs, NULL);
        nuvo_ck_assert(rc == 0);
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno <600);  j++)
        {
            CHECK_DATA(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
    }

    uuid_t vs_uuid;
    uuid_copy(vs_uuid, vol->vs_uuid);
    // closed in close vol
    //nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
    //nuvo_lun_destroy(snap_lun);

    // close and reopen for real replay testing
    close_vol(vol);
    open_vol(vol, vs_uuid, root_parcel_uuid);
    close_vol(vol);
    nuvo_space_halt();

    for (int j = 0; j < 32; j++)
    {
        free(read_bufs[j]);
    }
END_TEST
START_TEST(snap_io_multi_lun_read)

    // write to 600 blocks and read back
    // create a snap
    // write to 300 blocks
    // read back from snap
    // the last read half of it would be from snap and half from active
    // close the volume ( if the pin counts are wrong, we get a panic)

    struct nuvo_vol *vol = &test_var.vol;
    uuid_t root_parcel_uuid;
    uuid_generate(root_parcel_uuid);

    create_vol(vol, root_parcel_uuid);
                             /* this must be from the lun number */
    NUVO_ASSERT(vol->log_volume.lun.snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID);
    // 1. write to 600 blocks and read back

    uint8_t *read_bufs[32];
    for (int j = 0; j < 32; j++)
    {
        read_bufs[j] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[j], NULL);
    }
    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno < 600); j++)
        {
            fill_data(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
        int blk_count = (bno + 32 < 600 ? 32 : (600 - bno));
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, blk_count, (void**)read_bufs);
        nuvo_ck_assert(rc == 0);
    }

    // and read back
    for (int j = 0; j < 32; j++)
    {
        memset(read_bufs[j], 0, NUVO_BLOCK_SIZE);
    }

    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        int blk_count = (bno + 32 < 600 ? 32 : (600 - bno));
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, blk_count, (void**)read_bufs, NULL);
        nuvo_ck_assert(rc == 0);
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno < 600); j++)
        {
            CHECK_DATA(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
    }

    // 2. create a snap

    uuid_t lun_uuid;
    uuid_generate(lun_uuid);

    nuvo_return_t rc =  nuvo_log_vol_create_lun_int(vol, lun_uuid);
    NUVO_ASSERT(!rc);

    struct nuvo_lun * snap_lun =  nuvo_get_peer_cow_lun(vol, false);
    NUVO_ASSERT(snap_lun);

    // memset
    for (int j = 0; j < 32; j++)
    {
        memset(read_bufs[j], 0, NUVO_BLOCK_SIZE);
    }

    // 3. write to 300 blocks  (version 2)
    for (unsigned bno = 0; bno < 300; bno+=32)
    {
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno < 300); j++)
        {
            fill_data(tno, 2, ((uint64_t *) read_bufs[j]));
            tno++;
        }
        int blk_count = (bno + 32 < 300 ? 32 : (300 - bno));
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, blk_count, (void**)read_bufs);
        nuvo_ck_assert(rc == 0);
    }

    // 4. read back from snap
    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        int blk_count = (bno + 32 < 600 ? 32 : (600 - bno));
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, blk_count, (void**)read_bufs, NULL);
        nuvo_ck_assert(rc == 0);
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno < 600); j++)
        {
            CHECK_DATA(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
    }

#if 0

    /*cp the lun */
    rc = nuvo_map_lun_close(&vol->log_volume.lun, &vol->log_volume.lun.root_map_entry);
    NUVO_ASSERT(!rc);
    /* close the snap lun */
    rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
    NUVO_ASSERT(!rc);

    /* now open the lun and snap lun
     and make sure data is all good */
    rc = nuvo_map_lun_open(&vol->log_volume.lun, &vol->log_volume.lun.root_map_entry);
    NUVO_ASSERT(!rc);
    rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
    NUVO_ASSERT(!rc);

    // 4. read back from snap after close

    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, 32, (void**)read_bufs, NULL);
        nuvo_ck_assert(rc == 0);
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno <600);  j++)
        {
            CHECK_DATA(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
    }

    // close the vol, pincount bug must cause a panic

    uuid_t vs_uuid;
    uuid_copy(vs_uuid, vol->vs_uuid);
    // closed in close vol
    //nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
    //nuvo_lun_destroy(snap_lun);
#endif

    // close and reopen for real replay testing
    uuid_t vs_uuid;
    uuid_copy(vs_uuid, vol->vs_uuid);
    close_vol(vol);
    open_vol(vol, vs_uuid, root_parcel_uuid);
    // 4. read back from snap
    snap_lun =  nuvo_get_peer_cow_lun(vol, false);
    NUVO_ASSERT(snap_lun);
    for (unsigned bno = 0; bno < 600; bno+=32)
    {
        int blk_count = (bno + 32 < 600 ? 32 : (600 - bno));
        nuvo_return_t rc = nuvo_log_vol_lun_read(snap_lun, bno, blk_count, (void**)read_bufs, NULL);
        nuvo_ck_assert(rc == 0);
        unsigned int tno = bno;
        for (int j = 0; (j < 32 && tno < 600); j++)
        {
            CHECK_DATA(tno, 1, ((uint64_t *) read_bufs[j]));
            tno++;
        }
    }
    close_vol(vol);
    nuvo_space_halt();

    for (int j = 0; j < 32; j++)
    {
        free(read_bufs[j]);
    }
END_TEST
/*
 * Write some data. Just data.  Then replay and check.
 */
START_TEST(basic_data_replay)
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    void* buf_list[128];
    buf_list[0] = buffer;
    uint32_t lun_blocks = 600;

    struct nuvo_vol *vol = &test_var.vol;
    uuid_t root_parcel_uuid;
    uuid_generate(root_parcel_uuid);

    create_vol(vol, root_parcel_uuid);
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, 1, (uint64_t *) buffer);
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, 1, buf_list);
        nuvo_ck_assert(rc == 0);
    }
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        check_data(bno, 1, (uint64_t *) buffer);
    }

    uuid_t vs_uuid;
    uuid_copy(vs_uuid, vol->vs_uuid);
    close_vol(vol);
    open_vol(vol, vs_uuid, root_parcel_uuid);
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        check_data(bno, 1, (uint64_t *) buffer);
    }
    close_vol(vol);
    nuvo_space_halt();
END_TEST

/*
 * Write some data. Just random data.
 */
START_TEST(random_data_replay)
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    void* buf_list[128];
    buf_list[0] = buffer;
    uint64_t gen[1000];
    uint32_t lun_blocks = 600;

    struct nuvo_vol *vol = &test_var.vol;
    uuid_t root_parcel_uuid;
    uuid_generate(root_parcel_uuid);

    create_vol(vol, root_parcel_uuid);
    for (unsigned i = 0; i < lun_blocks; i++)
    {
        gen[i] = 0;
    }
    for (unsigned i = 0; i < 1200; i++)
    {
        uint32_t bno = rand() % lun_blocks;
        gen[bno]++;
        fill_data(bno, gen[bno], (uint64_t *) buffer);
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, 1, buf_list);
        nuvo_ck_assert(rc == 0);
    }
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        if (gen[bno] != 0)
        {
            check_data(bno, gen[bno], (uint64_t *) buffer);
        }
    }

    uuid_t vs_uuid;
    uuid_copy(vs_uuid, vol->vs_uuid);
    close_vol(vol);
    open_vol(vol, vs_uuid, root_parcel_uuid);

    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        if (gen[bno] != 0)
        {
            check_data(bno, gen[bno], (uint64_t *) buffer);
        }
    }

    close_vol(vol);
    nuvo_space_halt();
END_TEST

static void fill_data_cv(uint64_t fbn, uint64_t gen, uint64_t *data)
{
    uint64_t value = fbn + gen;
    for (unsigned i = 0; i < NUVO_BLOCK_SIZE / sizeof(data[0]); i++)
    {
        data[i] = value;
    }
}

static void check_data_cv(uint64_t fbn, uint64_t gen, uint64_t *data)
{
    uint64_t value = fbn + gen;
    for (unsigned i = 0; i < NUVO_BLOCK_SIZE / sizeof(data[0]); i++)
    {
        ck_assert(data[i] == value);
    }
}

/*
 * Write some data. Just data.
 */
START_TEST(basic_cv_data_replay)
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned (NUVO_BLOCK_SIZE)));
    void* buf_list[128];
    buf_list[0] = buffer;

    uint32_t lun_blocks = 600;

    struct nuvo_vol *vol = &test_var.vol;
    uuid_t root_parcel_uuid;
    uuid_generate(root_parcel_uuid);

    create_vol(vol, root_parcel_uuid);
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data_cv(bno, 1, (uint64_t *) buffer);
        nuvo_return_t rc = nuvo_log_vol_write(vol, bno, 1, buf_list);
        nuvo_ck_assert(rc == 0);
    }
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        check_data_cv(bno, 1, (uint64_t *) buffer);
    }

    uuid_t vs_uuid;
    uuid_copy(vs_uuid, vol->vs_uuid);
    close_vol(vol);
    open_vol(vol, vs_uuid, root_parcel_uuid);

    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        nuvo_return_t rc = nuvo_log_vol_lun_read(&vol->log_volume.lun, bno, 1, buf_list, NULL);
        nuvo_ck_assert(rc == 0);
        check_data_cv(bno, 1, (uint64_t *) buffer);
    }
    close_vol(vol);
    nuvo_space_halt();
END_TEST

Suite * nuvo_map_replay_suite(void)
{
    Suite *s = suite_create("map_replay");
    TCase *tc_map_replay = tcase_create("Map replay");
    tcase_add_checked_fixture(tc_map_replay, map_replay_tests_setup, map_replay_tests_teardown);
    tcase_add_test(tc_map_replay, basic_snap_io);
    tcase_add_test(tc_map_replay, snap_io_multi_lun_read);
    tcase_add_test(tc_map_replay, basic_data_replay);
    tcase_add_test(tc_map_replay, random_data_replay);
    tcase_add_test(tc_map_replay, basic_cv_data_replay);
    suite_add_tcase(s, tc_map_replay);
    return s;
}
