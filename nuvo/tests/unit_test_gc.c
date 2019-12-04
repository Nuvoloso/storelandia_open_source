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

// fake map replay vol done
void nuvo_map_replay_vol_done(struct nuvo_vol *vol)
{
    (void)vol;
}

struct
{
    unsigned        num_devices;
    struct
    {
        uuid_t   device_uuid;
        uint64_t parcel_size;
        enum nuvo_dev_type device_type;
    }               devices[10];

    struct nuvo_vol vol;
} test_var;

#define FAKE_MAP_MAX_BLOCKS    1024
#define FAKE_MAP_MAX_MAP       1024
#define FAKE_MAP_MAX_SNAPS     4

struct
{
    struct
    {
        struct nuvo_map_entry data_entry[FAKE_MAP_MAX_BLOCKS];  // Data block pointers
        struct
        {
            bool                  dirty;
            struct nuvo_map_entry map_entry;                    // Level 1 map pointers
        }                     map_blocks[FAKE_MAP_MAX_MAP];
        uint32_t              snap_id;
    }        luns[FAKE_MAP_MAX_SNAPS];
    unsigned maps_used;
    // TODO - keep track of max filled in block.
} fake_map;

void fake_map_init()
{
    memset(&fake_map, 0, sizeof(fake_map));
    fake_map.maps_used = 1;
    fake_map.luns[0].snap_id = NUVO_MFST_ACTIVE_LUN_SNAPID;
}

unsigned fake_map_lun_index(struct nuvo_lun *lun)
{
    for (unsigned index = 0; index < fake_map.maps_used; index++)
    {
        if (fake_map.luns[index].snap_id == lun->snap_id)
        {
            return index;
        }
    }
    ck_assert(0);
    return 0;
}

void fake_map_range_unused(uint32_t parcel_index, uint32_t block_offset, uint32_t num)
{
    for (unsigned i = 0; i < fake_map.maps_used; i++)
    {
        for (unsigned d = 0; d < FAKE_MAP_MAX_BLOCKS; d++)
        {
            struct nuvo_map_entry *entry = &fake_map.luns[i].data_entry[d];
            if (entry->type != NUVO_ME_MEDIA)
            {
                continue;
            }
            NUVO_ASSERT(entry->media_addr.parcel_index != parcel_index ||
                        entry->media_addr.block_offset < block_offset ||
                        entry->media_addr.block_offset > block_offset + num);
        }
        // TODO - check map blocks.
    }

    // TODO - extend to count the usage and make sure it is right even in the active/move fail case?
}

void fake_map_simulate_pit_delete_hole_punching(struct nuvo_lun *lun)
{
    unsigned i = fake_map_lun_index(lun);
    for (unsigned d = 0; d < FAKE_MAP_MAX_BLOCKS; d++)
    {
        struct nuvo_map_entry *entry = &fake_map.luns[i].data_entry[d];
        if (entry->type != NUVO_ME_MEDIA)
        {
            continue;
        }
        nuvo_mfst_segment_free_blks(&test_var.vol.log_volume.mfst, 1, entry);
        memset(entry, 0, sizeof(*entry));
    }
}

void nuvo_map_try_flush(struct nuvo_vol * vol)
{
    (void)vol;
}
/* fake volume lookup */
struct nuvo_vol *nuvo_vol_lookup(const uuid_t vs_uuid)
{
    (void) vs_uuid;
    return &test_var.vol;
}

struct nuvo_lun * nuvo_map_create_snap(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    struct nuvo_lun *snap_lun;

    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    if (!(snap_lun = nuvo_lun_alloc(vol, false)))
    {
        return NULL;
    }
    struct nuvo_lun *active_lun = &vol->log_volume.lun;
    /// set up the lun to be a pit of active lun
    uuid_copy(snap_lun->lun_uuid, lun_uuid);
    snap_lun->snap_id = ++(vol->snap_generation);
    snap_lun->size = active_lun->size;
    snap_lun->map_height = active_lun->map_height;

    uint32_t pit_id = fake_map.maps_used++;
    NUVO_ASSERT(pit_id < FAKE_MAP_MAX_SNAPS);
    NUVO_ASSERT(snap_lun->snap_id == pit_id);

    for (unsigned i = 0; i < FAKE_MAP_MAX_BLOCKS; i++)
    {
        fake_map.luns[pit_id].data_entry[i].cow = NUVO_MAP_ENTRY_SHARED;
        fake_map.luns[pit_id].data_entry[i].type = NUVO_ME_NULL;
        fake_map.luns[0].data_entry[i].cow = NUVO_MAP_ENTRY_COW;
    }
    // Maps should be unused.
    fake_map.luns[pit_id].snap_id = pit_id;

    return snap_lun;
}

// mock function
void nuvo_map_request_init(struct nuvo_map_request *req,
                           struct nuvo_lun         *lun,
                           uint_fast64_t            block_start,
                           uint_fast32_t            block_count)
{
    nuvo_dlist_init(&req->map_list);
    nuvo_dlnode_init(&req->list_node);
    req->block_start = block_start;
    req->block_last = block_start + block_count - 1;
    req->first_map = NULL;
    req->last_map = NULL;
    req->target_level = 0;
    req->status = 0;

    NUVO_ASSERT(lun != NULL);
    req->lun = lun;
}

// mock function
void nuvo_map_reserve(struct nuvo_map_request *req)
{
    // Do nothing - testing caller not map.
    req->status = 0;
}

// mock function
void nuvo_map_reserve_sync(struct nuvo_map_request *req)
{
    // Do nothing - testing caller not map.
    req->status = 0;
}

// mock function
void nuvo_map_fault_in(struct nuvo_map_request *req)
{
    // Do nothing - testing caller not map.
    req->callback(req);
}

// mock function
void nuvo_map_fault_in_sync(struct nuvo_map_request *req)
{
    // Do nothing - testing caller not map.
    (void)req;
}

// mock function
void nuvo_map_read_and_pin_sync(struct nuvo_map_request *req,
                                bool                     pin,
                                struct nuvo_map_entry   *entries,
                                uint_fast32_t           *parcel_descs)
{
    NUVO_ASSERT(req->block_last < FAKE_MAP_MAX_BLOCKS);
    NUVO_ASSERT(req->target_level == 0);
    unsigned lidx = fake_map_lun_index(req->lun);
    for (uint_fast32_t i = 0, bno = req->block_start; bno <= req->block_last; i++, bno++)
    {
        entries[i] = fake_map.luns[lidx].data_entry[bno];
    }
    if (pin)
    {
        nuvo_mfst_pin_open(&test_var.vol.log_volume.mfst, req->block_last - req->block_start + 1, entries, parcel_descs);
    }
}

// mock function
void nuvo_map_multi_lun_read_sync(struct nuvo_map_request *map_req,
                                  bool                    pin,
                                  struct nuvo_map_request *map_req_active,
                                  struct nuvo_map_entry   *entries,
                                  uint_fast32_t           *parcel_descs)
{
    NUVO_ASSERT(map_req->block_last < FAKE_MAP_MAX_BLOCKS);
    NUVO_ASSERT(map_req->target_level == 0);
    unsigned slidx = fake_map_lun_index(map_req->lun);
    unsigned alidx = fake_map_lun_index(map_req_active->lun);
    NUVO_ASSERT(alidx == 0);
    for (uint_fast32_t i = 0, bno = map_req->block_start; bno <= map_req->block_last; i++, bno++)
    {
        uint32_t b_slidx = slidx;
        while (b_slidx < fake_map.maps_used &&
               fake_map.luns[b_slidx].data_entry[bno].cow == NUVO_MAP_ENTRY_SHARED)
        {
            b_slidx++;
        }
        if (b_slidx == fake_map.maps_used)
        {
            b_slidx = alidx;
        }
        entries[i] = fake_map.luns[b_slidx].data_entry[bno];
    }
    if (pin)
    {
        nuvo_mfst_pin_open(&test_var.vol.log_volume.mfst, map_req->block_last - map_req->block_start + 1, entries, parcel_descs);
    }
}

// mock function
void nuvo_map_read_release(struct nuvo_lun       *lun,
                           uint_fast32_t          block_count,
                           struct nuvo_map_entry *entries)
{
    nuvo_mfst_unpin(&lun->vol->log_volume.mfst, block_count, entries);
}

// mock function
void nuvo_map_checkpoint(struct nuvo_map_checkpoint_req *req)
{
    // TODO - something
    (void)req;
}

// mock function
void nuvo_map_rewrite_init(struct nuvo_map_request *map_req,
                           struct nuvo_lun         *lun,
                           uint64_t                 bno,
                           uint_fast16_t            level)
{
    nuvo_dlist_init(&map_req->map_list);
    nuvo_dlnode_init(&map_req->list_node);
    map_req->block_start = bno;
    map_req->block_last = bno;
    map_req->first_map = NULL;
    map_req->last_map = NULL;
    NUVO_ASSERT(level == 0);  // Fake map only supports on map level.
    map_req->target_level = level;
    map_req->status = 0;
    NUVO_ASSERT(lun != NULL);
    map_req->lun = lun;
}

// mock function
void nuvo_map_rewrite(struct nuvo_map_request *map_req)
{
    unsigned lidx = fake_map_lun_index(map_req->lun);
    unsigned midx = map_req->block_start / NUVO_MAP_RADIX;
    struct nuvo_map_entry *map_entry = &fake_map.luns[lidx].map_blocks[midx].map_entry;

    if (map_req->map_entries[0].type == map_entry->type &&
        map_req->map_entries[0].media_addr.parcel_index == map_entry->media_addr.parcel_index &&
        map_req->map_entries[0].media_addr.block_offset == map_entry->media_addr.block_offset)
    {
        fake_map.luns[lidx].map_blocks[midx].dirty = true;
        printf("    rewriting map %lu at parcel %u, offset %u\n",
               map_req->block_start,
               map_req->map_entries[0].media_addr.parcel_index,
               map_req->map_entries[0].media_addr.block_offset);
    }
    else
    {
        printf("    not rewriting map %lu at parcel %u, offset %u\n",
               map_req->block_start,
               map_req->map_entries[0].media_addr.parcel_index,
               map_req->map_entries[0].media_addr.block_offset);
    }
}

// mock function
void nuvo_map_commit_write(struct nuvo_map_request *req,
                           struct nuvo_map_entry   *new_entries)
{
    NUVO_ASSERT(req->block_last < FAKE_MAP_MAX_BLOCKS);
    NUVO_ASSERT(req->target_level == 0);
    nuvo_mfst_segment_use_blks(&test_var.vol.log_volume.mfst, req->block_last - req->block_start + 1, new_entries);
    unsigned lidx = fake_map_lun_index(req->lun);
    struct nuvo_map_entry *map_data_entries = &fake_map.luns[lidx].data_entry[req->block_start];
    nuvo_mfst_segment_free_blks(&test_var.vol.log_volume.mfst, req->block_last - req->block_start + 1, map_data_entries);
    for (uint_fast32_t i = 0, bno = req->block_start; bno <= req->block_last; i++, bno++)
    {
        if (new_entries[i].type == NUVO_ME_MEDIA)
        {
            printf("rewrote %lu at parcel %u, offset %u\n", bno, new_entries[i].media_addr.parcel_index, new_entries[i].media_addr.block_offset);
        }
        map_data_entries[i] = new_entries[i];
    }
}

// mock function
void nuvo_map_commit_gc_write(struct nuvo_map_request *req,
                              struct nuvo_map_entry   *new_entries,
                              struct nuvo_media_addr  *old_media_addrs,
                              uint_fast32_t           *succeeded,
                              uint_fast32_t           *failed)
{
    NUVO_ASSERT(req->block_last < FAKE_MAP_MAX_BLOCKS);
    NUVO_ASSERT(req->target_level == 0);
    *failed = 0;
    *succeeded = 0;
    unsigned               lidx = fake_map_lun_index(req->lun);
    struct nuvo_map_entry *map_data_entries = &fake_map.luns[lidx].data_entry[req->block_start];
    nuvo_mfst_segment_free_blks(&test_var.vol.log_volume.mfst, req->block_last - req->block_start + 1, map_data_entries);
    for (uint_fast32_t i = 0, bno = req->block_start; bno <= req->block_last; i++, bno++)
    {
        NUVO_ASSERT(new_entries[i].type == NUVO_ME_MEDIA);
        if (map_data_entries[i].type == NUVO_ME_MEDIA &&
            map_data_entries[i].media_addr.parcel_index == old_media_addrs[i].parcel_index &&
            map_data_entries[i].media_addr.block_offset == old_media_addrs[i].block_offset)
        {
            printf("moving lun: %u bno: %lu to parcel %u, offset %u\n", req->lun->snap_id, bno, new_entries[i].media_addr.parcel_index, new_entries[i].media_addr.block_offset);
            map_data_entries[i] = new_entries[i];
            nuvo_mfst_segment_use_blks(&test_var.vol.log_volume.mfst, 1, &map_data_entries[i]);
            (*succeeded)++;
        }
        else
        {
            (*failed)++;
        }
    }
}

void nuvo_map_multi_lun_commit_write(struct nuvo_map_request *map_req,
                                     struct nuvo_map_request *map_req_snap,
                                     struct nuvo_map_entry   *new_entries)
{
    unsigned alidx = fake_map_lun_index(map_req->lun);
    unsigned slidx = fake_map_lun_index(map_req_snap->lun);
    for (uint_fast32_t i = 0, bno = map_req->block_start; bno <= map_req->block_last; i++, bno++)
    {
        // Writing in active. If we have a media pointer and it is cowed, then the old pointer goes to
        // the snap (which should be shared) and don't free any blocks.  If it is not cowed, we just write the new and free
        // the old.
        struct nuvo_map_entry *active = &fake_map.luns[alidx].data_entry[bno];
        struct nuvo_map_entry *snap = &fake_map.luns[slidx].data_entry[bno];
        if (active->cow == NUVO_MAP_ENTRY_COW) {
            NUVO_ASSERT(snap->cow == NUVO_MAP_ENTRY_SHARED);
            NUVO_ASSERT(snap->type == NUVO_ME_NULL);
            *snap = *active;
            *active = new_entries[i];
            NUVO_ASSERT(active->cow == NUVO_MAP_ENTRY_NONE);
            nuvo_mfst_segment_use_blks(&test_var.vol.log_volume.mfst, 1, active);
            printf("wrote %lu at (%u, %u), moved (%d, %d) to snap\n", bno,
                    active->media_addr.parcel_index,
                    active->media_addr.block_offset,
                    snap->media_addr.parcel_index,
                    snap->media_addr.block_offset);
        }
        else
        {
            nuvo_mfst_segment_free_blks(&test_var.vol.log_volume.mfst, 1, active);
            *active = new_entries[i];
            nuvo_mfst_segment_use_blks(&test_var.vol.log_volume.mfst, 1, active);
            printf("wrote %lu (no snap) at (%u, %u)\n", bno,
                    active->media_addr.parcel_index,
                    active->media_addr.block_offset);
        }
    }
}

nuvo_return_t nuvo_map_lun_open(struct nuvo_lun *lun, const struct nuvo_map_entry *map_entry)
{
    // TODO
    (void)lun;
    (void)map_entry;
    return 0;
}

nuvo_return_t nuvo_map_lun_close(struct nuvo_lun *lun, struct nuvo_map_entry *map_entry)
{
    // TODO
    NUVO_ASSERT(0);
    (void)lun;
    (void)map_entry;
    return 0;
}

void map_flush_cb(struct nuvo_log_request *log_req)
{
    nuvo_mutex_unlock(log_req->tag.ptr);
}

// made up bullshit function
void map_flush()
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);

    for (unsigned lidx = 0; lidx < fake_map.maps_used; lidx++)
    {
        unsigned m = 0;
        while (m < FAKE_MAP_MAX_MAP)
        {
            // build a batch
            struct nuvo_map_entry old_map_entries[NUVO_MAP_WRITE_BATCH_SIZE];
            __attribute__((aligned(NUVO_BLOCK_SIZE))) uint8_t data[NUVO_MAP_WRITE_BATCH_SIZE][NUVO_BLOCK_SIZE];
            struct nuvo_log_request log_req;
            log_req.operation = NUVO_LOG_OP_MAP;
            log_req.atomic = false;
            log_req.data_class = NUVO_DATA_CLASS_A;
            log_req.tag.ptr = &sync_signal;
            log_req.vs_ptr = &test_var.vol;
            log_req.callback = map_flush_cb;

            unsigned num_blks = 0;
            while (num_blks < NUVO_MAP_WRITE_BATCH_SIZE && m < FAKE_MAP_MAX_MAP)
            {
                if (fake_map.luns[lidx].map_blocks[m].dirty)
                {
                    log_req.log_io_blocks[num_blks].data = data[num_blks];
                    memset(log_req.log_io_blocks[num_blks].data, 0, NUVO_BLOCK_SIZE); // I love you too, valgrind.
                    log_req.log_io_blocks[num_blks].log_entry_type = NUVO_LE_MAP_L0;
                    log_req.log_io_blocks[num_blks].map_is_zero = false;

                    LOG_PIT_INFO_SET_MAP(log_req.log_io_blocks[num_blks].pit_info, fake_map.luns[lidx].snap_id);
                    log_req.log_io_blocks[num_blks].bno = m * NUVO_MAP_RADIX;
                    num_blks++;
                }
                m++;
            }
            if (num_blks > 0)
            {
                printf("writing %u map blocks\n", num_blks);
                log_req.block_count = num_blks;
                nuvo_mutex_lock(log_req.tag.ptr);
                nuvo_log_submit(&log_req);
                nuvo_mutex_lock(log_req.tag.ptr);
                nuvo_mutex_unlock(log_req.tag.ptr);
                for (unsigned i = 0; i < log_req.block_count; i++)
                {
                    unsigned idx = log_req.log_io_blocks[i].bno / NUVO_MAP_RADIX;
                    old_map_entries[i] = fake_map.luns[lidx].map_blocks[idx].map_entry;
                }
                nuvo_mfst_segment_use_blks(&test_var.vol.log_volume.mfst, log_req.block_count, log_req.nuvo_map_entries);
                nuvo_mfst_segment_free_blks(&test_var.vol.log_volume.mfst, log_req.block_count, old_map_entries);
                for (unsigned i = 0; i < log_req.block_count; i++)
                {
                    unsigned idx = log_req.log_io_blocks[i].bno / NUVO_MAP_RADIX;
                    fake_map.luns[lidx].map_blocks[idx].map_entry = log_req.nuvo_map_entries[i];
                    fake_map.luns[lidx].map_blocks[idx].dirty = false;
                    printf("wrote map %lu at parcel %u, offset %u\n", log_req.log_io_blocks[i].bno, log_req.nuvo_map_entries[i].media_addr.parcel_index, log_req.nuvo_map_entries[i].media_addr.block_offset);
                }
                nuvo_log_ack_sno(&log_req);
            }
        }
    }
    nuvo_mutex_destroy(&sync_signal);
}

// temporary mock function
void nuvo_map_replay(struct nuvo_log_request *log_req)
{
    (void)log_req;
    return;
}

bool segment_gcable(uint_fast32_t parcel_index, uint_fast32_t bno)
{
    nuvo_mutex_lock(&test_var.vol.log_volume.mfst.mfst_mutex);
    bool pinned = (0 == nuvo_segment_space_pinned_get(&test_var.vol.log_volume.mfst, parcel_index, bno));
    nuvo_mutex_unlock(&test_var.vol.log_volume.mfst.mfst_mutex);
    return pinned;
}

void test_close_segment(uint_fast32_t parcel_index, uint_fast32_t bno)
{
    struct nuvo_mfst *mfst = &test_var.vol.log_volume.mfst;
    nuvo_mutex_lock(&mfst->mfst_mutex);
    if (nuvo_segment_space_pinned_get(&test_var.vol.log_volume.mfst, parcel_index, bno))
    {
        struct nuvo_segment segment;
        segment.parcel_index = parcel_index;
        segment.block_count = nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE;
        segment.block_offset = bno - (bno % segment.block_count);
        segment.device_index = mfst->parcel_state_media[parcel_index].normal.device_idx;
        segment.data_class = mfst->device_state_media[segment.device_index].device_class;
        nuvo_mutex_unlock(&mfst->mfst_mutex);
        nuvo_log_close_segment(&test_var.vol, &segment, true);
    }
    else
    {
        nuvo_mutex_unlock(&mfst->mfst_mutex);
    }
}

void write_zeros_until_gcable(uint_fast32_t lbn, uint_fast32_t parcel_index, uint_fast32_t bno)
{
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void *buf_list[1];
    buf_list[0] = buffer;
    memset(buffer, 0, NUVO_BLOCK_SIZE);

    test_close_segment(parcel_index, bno);

    while (!segment_gcable(parcel_index, bno))
    {
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, lbn, 1, buf_list);
        ck_assert(rc == 0);
    }
}

// Simple data testing.
#define DATA_GENS_SNAPS_LIMIT 10
#define DATA_GENS_BLOCKS_LIMIT 60
#define DATA_GENS_IO_MAX 60
struct {
    // Plane zero is active data.
    unsigned gen[DATA_GENS_SNAPS_LIMIT][DATA_GENS_BLOCKS_LIMIT];
    unsigned max_snap_id;
    unsigned block_used_limit;

    uint8_t io_buffers[DATA_GENS_IO_MAX][NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void *buf_list[DATA_GENS_IO_MAX];
} data_gens;

void data_gens_init()
{
    memset(&data_gens, 0, sizeof(data_gens));
    for (unsigned i = 0; i < DATA_GENS_IO_MAX; i++)
    {
        data_gens.buf_list[i] = &data_gens.io_buffers[i];
    }
}

void data_gens_create_snap()
{
    data_gens.max_snap_id++;
    NUVO_ASSERT(data_gens.max_snap_id < DATA_GENS_SNAPS_LIMIT);
    for (unsigned i = 0; i < DATA_GENS_BLOCKS_LIMIT; i++)
    {
        data_gens.gen[data_gens.max_snap_id][i] = data_gens.gen[0][i];
    }
    uuid_t lun_uuid;
    uuid_generate(lun_uuid);
    nuvo_mutex_lock(&test_var.vol.mutex);
    nuvo_log_vol_create_lun_int(&test_var.vol, lun_uuid);
    nuvo_mutex_unlock(&test_var.vol.mutex);
}

static void data_gens_fill_data(uint64_t fbn, uint64_t gen, uint64_t *data, bool map)
{
    data[0] = fbn;
    data[1] = gen;
    data[2] = fbn + 1;  // Make sure we don't get constant filled by mistake.
    data[3] = map ? 1 : 0;
}

static void data_gens_check_data(uint64_t fbn, uint64_t gen, uint64_t *data, bool map)
{
    if (gen == 0)
    {
        ck_assert(data[0] == 0);
        NUVO_ASSERT(data[1] == 0);
        ck_assert(data[2] == 0);
        ck_assert(data[3] == 0);
    }
    else
    {
        ck_assert(data[0] == fbn);
        NUVO_ASSERT(data[1] == gen);
        ck_assert(data[2] == fbn + 1);
        ck_assert(data[3] == map ? 1 : 0);
    }
}

void data_gens_write_blocks(unsigned start_bno, unsigned num)
{
    NUVO_ASSERT(start_bno + num < DATA_GENS_BLOCKS_LIMIT);
    NUVO_ASSERT(num < DATA_GENS_IO_MAX);
    if (data_gens.block_used_limit < start_bno + num)
    {
        data_gens.block_used_limit = start_bno + num;
    }
    for (unsigned i = 0, bno = start_bno; i < num; i++, bno++)
    {
        data_gens_fill_data(bno, ++data_gens.gen[0][bno], data_gens.buf_list[i], false);
    }
    nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, start_bno, num, data_gens.buf_list);
    ck_assert(rc == 0);
}

void data_gens_zero_blocks(unsigned start_bno, unsigned num)
{
    NUVO_ASSERT(start_bno + num < DATA_GENS_BLOCKS_LIMIT);
    NUVO_ASSERT(num < DATA_GENS_IO_MAX);
    if (data_gens.block_used_limit < start_bno + num)
    {
        data_gens.block_used_limit = start_bno + num;
    }
    for (unsigned i = 0, bno = start_bno; i < num; i++, bno++)
    {
        memset(data_gens.buf_list[i], 0, NUVO_BLOCK_SIZE);
        data_gens.gen[0][bno] = 0;
    }
    nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, start_bno, num, data_gens.buf_list);
    ck_assert(rc == 0);
}


void data_gens_check_blocks()
{
    for (unsigned snap_id = 0; snap_id <= data_gens.max_snap_id; snap_id++)
    {
        struct nuvo_lun *lun = nuvo_get_lun_by_snapid(&test_var.vol, snap_id != 0 ? snap_id : NUVO_MFST_ACTIVE_LUN_SNAPID, false);
        nuvo_return_t rc = nuvo_log_vol_lun_read(lun, 0, data_gens.block_used_limit , data_gens.buf_list, NULL);
        ck_assert(rc == 0);
        for (unsigned i = 0; i < data_gens.block_used_limit; i++)
        {
            data_gens_check_data(i, data_gens.gen[snap_id][i], data_gens.buf_list[i], false);
        }
    }
}

void gc_tests_setup()
{
    fake_pr_init();
    nuvo_io_concat_pool_init(100);
    fake_map_init();
    data_gens_init();

    nuvo_return_t rc;

    memset(&test_var, 0, sizeof(test_var));

    nuvo_mutex_init(&test_var.vol.mutex);
    //nuvo_rwlock_init(&test_var.vol.rw_lock);

    test_var.num_devices = 1;
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
    uint64_t lun_size = 64 * 1024 * 1024;

    // Create our basic volume.
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
                           test_var.devices[0].parcel_size / NUVO_BLOCK_SIZE, NUVO_DATA_CLASS_A, test_var.devices[0].device_type, NUVO_SEGMENT_MIN_SIZE_BYTES, 10, 20, lun_size);
    ck_assert(rc == 0);

    // write manifest
    rc = nuvo_mfst_sync_write(&test_var.vol.log_volume.mfst, &test_var.vol.log_volume.sb, 1, 1);
    ck_assert(rc == 0);

    // write superblock
    rc = nuvo_sb_sync_write(&test_var.vol.log_volume.sb, root_parcel_desc);
    ck_assert(rc == 0);

    rc = nuvo_space_init(true);
    ck_assert(rc == 0);
    nuvo_space_gc_disable_for_test();

    rc = nuvo_space_vol_init(&test_var.vol.log_volume.space);
    ck_assert(rc == 0);
    rc = nuvo_lun_init(&test_var.vol.log_volume.lun, &test_var.vol);
    nuvo_lun_state_init(&test_var.vol.log_volume.lun, &test_var.vol, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);
    ck_assert(rc == 0);
    rc = nuvo_mfst_get_active_lun(&test_var.vol.log_volume.mfst,
                                  &test_var.vol.log_volume.lun);
    ck_assert(rc == 0);
    NUVO_ASSERT(NUVO_LUN_IS_ACTIVE(&test_var.vol.log_volume.lun));
    struct nuvo_log_replay_request replay_req;
    replay_req.sequence_no = 1;
    replay_req.vol = &test_var.vol;
    replay_req.segment_count = NUVO_MFST_NUM_LOG_STARTS;
    nuvo_mfst_log_starts_get(&test_var.vol.log_volume.mfst,
                             &replay_req.sequence_no,
                             &replay_req.segment_cnt_sequence_no,
                             &replay_req.segment_count,
                             replay_req.replay_segments);

    rc = nuvo_log_init(&test_var.vol);
    ck_assert(rc == 0);

    rc = nuvo_log_sync_replay(&replay_req);
    ck_assert(rc == 0);

    nuvo_mfst_seg_counts_start(&test_var.vol.log_volume.mfst);
}

void gc_tests_teardown()
{
    nuvo_space_vol_stop_management(&test_var.vol.log_volume.space);
    nuvo_log_shutdown(&test_var.vol);
    nuvo_space_vol_destroy(&test_var.vol.log_volume.space);
    nuvo_space_halt();
    nuvo_mfst_free_manifest(&test_var.vol.log_volume.mfst);
    nuvo_lun_destroy(&test_var.vol.log_volume.lun);
    nuvo_mutex_destroy(&test_var.vol.mutex);

    nuvo_io_concat_pool_destroy();
    fake_pr_teardown();
}

START_TEST(gc_queues)
{
    // Test allocing a gc and moving them between queues works.
    struct nuvo_gc *gc;
    gc = nuvo_gc_alloc();
    ck_assert(gc != NULL);
    nuvo_gc_free(gc);

    gc = nuvo_gc_needs_work_get();
    ck_assert(gc == NULL);

    // Get all the gc's and put them on the need work list.
    for (uint_fast16_t i = 0; i < NUVO_SPACE_GC_NUM; i++)
    {
        gc = nuvo_gc_alloc();
        ck_assert(gc != NULL);
        nuvo_gc_needs_work(gc);
    }
    // There should be no gc's left.
    gc = nuvo_gc_alloc();
    ck_assert(gc == NULL);

    // None of them have been put on the list of needing a gc_batch.
    gc = nuvo_gc_needs_batch_get();
    ck_assert(gc == NULL);

    // Now pull one of the gc's that needs work and call nuvo_gc_needs_batch
    // Since there are log maps free, it should go back on the needs_work list,
    // not the needs map.
    gc = nuvo_gc_needs_work_get();
    ck_assert(gc != NULL);
    nuvo_gc_needs_batch(gc);
    gc = nuvo_gc_needs_batch_get();
    ck_assert(gc == NULL);

    // Now steal all of the gc_batches.
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);
    struct nuvo_gc_batch *gc_batch;
    while (NULL != (gc_batch = nuvo_gc_batch_alloc()))
    {
        nuvo_dlist_insert_tail(&parking, &gc_batch->list_node);
    }

    // Now calling nuvo_gc_needs_batch_get should put it on the list.
    gc = nuvo_gc_needs_work_get();
    ck_assert(gc != NULL);
    nuvo_gc_needs_batch(gc);
    struct nuvo_gc *gc2 = nuvo_gc_needs_batch_get();
    ck_assert(gc == gc2);
    // Put it back
    nuvo_gc_needs_batch(gc);

    // Now free the gc_batches
    while (NULL != (gc_batch = nuvo_dlist_remove_head_object(&parking, struct nuvo_gc_batch, list_node)))
    {
        nuvo_gc_batch_free(gc_batch);
    }

    // Now check that the gc is no longer on the needs_map list
    gc2 = nuvo_gc_needs_batch_get();
    ck_assert(NULL == gc2);

    while (NULL != (gc = nuvo_gc_needs_work_get()))
    {
        nuvo_gc_free(gc);
    }
}
END_TEST


static void fill_data(uint64_t fbn, uint64_t *data)
{
    memset(data, 0, NUVO_BLOCK_SIZE);
    data[0] = fbn;
    data[1] = fbn + 1;  // Make sure we don't get constant filled by mistake.
}

static void gc_call_done_cb(struct nuvo_gc *gc)
{
    nuvo_mutex_unlock(gc->tag.ptr);
}

START_TEST(read_digest)
{
    nuvo_mutex_t sync_signal;
    nuvo_mutex_init(&sync_signal);

    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void   *buf_list[128];
    buf_list[0] = buffer;

    for (unsigned bno = 0; bno < 600; bno++)
    {
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }

    // get a nuvo_gc
    struct nuvo_gc *gc;
    gc = nuvo_gc_alloc();
    ck_assert(gc != NULL);

    nuvo_return_t        rc;
    struct nuvo_segment *segment;
    NUVO_ASSERT(segment_gcable(fake_map.luns[0].data_entry[0].media_addr.parcel_index, fake_map.luns[0].data_entry[0].media_addr.block_offset));
    rc = nuvo_space_vol_segment_log_replay_get(&test_var.vol.log_volume.space,
                                            fake_map.luns[0].data_entry[0].media_addr.parcel_index,
                                            fake_map.luns[0].data_entry[0].media_addr.block_offset,
                                            &segment);
    ck_assert(rc == 0);
    nuvo_gc_init(gc, &test_var.vol, segment);
    gc->tag.ptr = &sync_signal;
    gc->phase_callback = gc_call_done_cb;
    nuvo_mutex_lock(gc->tag.ptr);
    rc = nuvo_gc_read_digest(gc);
    nuvo_mutex_lock(gc->tag.ptr);
    ck_assert(gc->state == NUVO_SPACE_GC_DIGEST_ELIDING);
    ck_assert(gc->boffset == 0);
    struct nuvo_gc *gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc == gc2);

    // Should probably free the gc and all that.

    nuvo_space_vol_segment_done(&test_var.vol.log_volume.space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
}
END_TEST

static void test_read_digest(struct nuvo_gc *gc)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);
    gc->tag.ptr = &sync_signal;
    gc->phase_callback = gc_call_done_cb;
    nuvo_mutex_lock(gc->tag.ptr);
    nuvo_return_t rc = nuvo_gc_read_digest(gc);
    ck_assert(rc == 0);
    nuvo_mutex_lock(gc->tag.ptr);
    ck_assert(gc->state == NUVO_SPACE_GC_DIGEST_ELIDING);
    ck_assert(gc->boffset == 0);
    ck_assert(gc->gc_batches_outstanding == 0);
    struct nuvo_gc *gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc == gc2);
    nuvo_mutex_destroy(&sync_signal);
}

static void test_elide_digest(struct nuvo_gc *gc)
{
    ck_assert(gc->gc_batches_outstanding == 0);
    nuvo_mutex_t sync_signal;
    nuvo_mutex_init(&sync_signal);
    gc->tag.ptr = &sync_signal;
    gc->phase_callback = gc_call_done_cb;
    nuvo_mutex_lock(gc->tag.ptr);
    struct nuvo_gc *gc2 = NULL;
    nuvo_gc_needs_work(gc);
    while (gc->state == NUVO_SPACE_GC_DIGEST_ELIDING)
    {
        gc2 = nuvo_gc_needs_work_get();
        ck_assert(gc2 == gc);
        struct nuvo_gc_batch *gc_batch = nuvo_gc_batch_alloc();
        ck_assert(gc_batch != NULL);
        nuvo_return_t rc = nuvo_gc_elide_unused_batch(gc, gc_batch);
        ck_assert(rc >= 0);
        if (rc > 0)
        {
            nuvo_mutex_lock(gc->tag.ptr); // Wait for work.
        }
    }
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == gc);
    ck_assert(gc->state == NUVO_SPACE_GC_MOVING_DATA);
    ck_assert(gc->boffset == 0);
    ck_assert(gc->gc_batches_outstanding == 0);
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);
    nuvo_mutex_destroy(&sync_signal);
}

static void test_move_data(struct nuvo_gc *gc, enum nuvo_gc_state final_state)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);
    gc->tag.ptr = &sync_signal;
    gc->phase_callback = gc_call_done_cb;
    nuvo_mutex_lock(gc->tag.ptr);
    struct nuvo_gc *gc2 = NULL;
    nuvo_gc_needs_work(gc);
    while (gc->state == NUVO_SPACE_GC_MOVING_DATA)
    {
        gc2 = nuvo_gc_needs_work_get();
        ck_assert(gc2 == gc);
        struct nuvo_gc_batch *gc_batch = nuvo_gc_batch_alloc();
        ck_assert(gc_batch != NULL);
        nuvo_return_t rc = nuvo_gc_move_data_batch(gc, gc_batch);
        ck_assert(rc >= 0);
        if (rc > 0)
        {
            nuvo_mutex_lock(gc->tag.ptr);  // Moved stuff.  Wait for move.
        }
    }
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == gc);
    ck_assert(gc->state == final_state);
    switch (final_state) {
    case NUVO_SPACE_GC_MOVE_MAPS:
        ck_assert(gc->boffset == 0);
        ck_assert(gc->gc_batches_outstanding == 0);
        break;
    case NUVO_SPACE_GC_MOVE_FAILED:
        ck_assert(gc->gc_batches_outstanding == 0);
        break;
    default:
        ck_assert(false);
    }
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);
    nuvo_mutex_destroy(&sync_signal);
}

static void test_move_maps(struct nuvo_gc *gc)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);
    gc->tag.ptr = &sync_signal;
    gc->phase_callback = gc_call_done_cb;
    nuvo_mutex_lock(gc->tag.ptr);
    struct nuvo_gc *gc2 = NULL;
    nuvo_gc_needs_work(gc);
    while (gc->state == NUVO_SPACE_GC_MOVE_MAPS)
    {
        gc2 = nuvo_gc_needs_work_get();
        ck_assert(gc2 == gc);
        struct nuvo_gc_batch *gc_batch = nuvo_gc_batch_alloc();
        ck_assert(gc_batch != NULL);
        nuvo_return_t rc = nuvo_gc_move_maps_batch(gc, gc_batch);
        ck_assert(rc >= 0);
        if (rc > 0)
        {
            nuvo_mutex_lock(gc->tag.ptr);  // Moved stuff.  Wait for move.
        }
    }
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == gc);
    ck_assert(gc->state == NUVO_SPACE_GC_MOVING_DONE);
    map_flush();
    ck_assert(gc->gc_batches_outstanding == 0);
    gc2 = nuvo_gc_needs_work_get();
    ck_assert(gc2 == NULL);
    nuvo_mutex_destroy(&sync_signal);
}

/*
 * Write some data.  Just data.  Garbage collect a segment.
 */
START_TEST(basic_data_gc)
{
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void *buf_list[128];
    buf_list[0] = buffer;
    uint32_t lun_blocks = 600;

    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }
    // Now rewrite all but multiples of 3.
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        if ((bno % 3) == 0)
        {
            continue;
        }
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }

    // get a nuvo_gc
    struct nuvo_gc *gc;
    gc = nuvo_gc_alloc();
    ck_assert(gc != NULL);

    nuvo_return_t        rc;
    struct nuvo_segment *segment;
    unsigned             lidx = fake_map_lun_index(nuvo_get_lun_by_snapid(&test_var.vol, NUVO_MFST_ACTIVE_LUN_SNAPID,false));
    NUVO_ASSERT(segment_gcable(fake_map.luns[lidx].data_entry[0].media_addr.parcel_index, fake_map.luns[lidx].data_entry[0].media_addr.block_offset));
    rc = nuvo_space_vol_segment_log_replay_get(&test_var.vol.log_volume.space,
                                            fake_map.luns[lidx].data_entry[0].media_addr.parcel_index,
                                            fake_map.luns[lidx].data_entry[0].media_addr.block_offset,
                                            &segment);
    ck_assert(rc == 0);

    nuvo_gc_init(gc, &test_var.vol, segment);

    test_read_digest(gc);

    // cycle through digest.  Every block in it that is multiple of
    // 3 should have same address in the map.  Every one that is not
    // multiple of 3 should have different address since we rewrote it.
    unsigned num_left = 0;
    for (unsigned boffset = 0; boffset < gc->digest.footer.used_block_count; boffset++)
    {
        if (gc->digest.table[boffset].log_entry_type != NUVO_LE_DATA)
        {
            continue;
        }
        uint_fast32_t pbno = segment->block_offset + boffset;
        uint_fast32_t bno = gc->digest.table[boffset].data.bno;
        bool          moved = (fake_map.luns[lidx].data_entry[bno].media_addr.parcel_index != segment->parcel_index ||
                            fake_map.luns[lidx].data_entry[bno].media_addr.block_offset != pbno);
        bool should_moved = (0 != (bno % 3));
        if (!moved)
        {
            num_left++;
            ck_assert(!should_moved);
        }
        else
        {
            ck_assert(should_moved);
        }
    }
    // Now elide.
    test_elide_digest(gc);

    // Only blocks left in the digest should be multiples of 3.
    unsigned num_left_after = 0;
    for (unsigned boffset = 0; boffset < gc->digest.footer.used_block_count; boffset++)
    {
        uint_fast32_t bno = gc->digest.table[boffset].data.bno;
        if (gc->block_state[boffset] == NUVO_GC_BLOCK_UNUSED ||
            gc->block_state[boffset] == NUVO_GC_BLOCK_UNKNOWN)
        {
            continue;
        }
        ck_assert(bno % 3 == 0);
        num_left_after++;
    }
    ck_assert(num_left == num_left_after);

    ck_assert(0 != test_var.vol.log_volume.mfst.segment_state_media[1].seg_blks_used);
    test_move_data(gc, NUVO_SPACE_GC_MOVE_MAPS);
    ck_assert(0 == test_var.vol.log_volume.mfst.segment_state_media[1].seg_blks_used);

    // This test only writes data, so we're done.

    // Check the data.
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        uint8_t read_buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
        buf_list[0] = &read_buffer;
        nuvo_return_t rc = nuvo_log_vol_lun_read(&test_var.vol.log_volume.lun, bno, 1, buf_list, NULL);
        ck_assert(rc == 0);
        uint64_t *data = (uint64_t *)read_buffer;
        ck_assert(data[0] == bno && data[1] == bno + 1);
    }

    // Don't continue the gc state machine.  Do that in later tests.
    nuvo_space_vol_segment_done(&test_var.vol.log_volume.space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
    nuvo_gc_free(gc);
}
END_TEST

/*
 * Write some data and some map data. Garbage collect a segment.
 */
START_TEST(basic_map_gc)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);

    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void   *buf_list[128];
    buf_list[0] = buffer;
    uint32_t lun_blocks = 600;
    unsigned lidx = fake_map_lun_index(nuvo_get_lun_by_snapid(&test_var.vol, NUVO_MFST_ACTIVE_LUN_SNAPID, false));
    for (unsigned i = 0; i < 100; i++)
    {
        fake_map.luns[lidx].map_blocks[i].dirty = true;
    }
    map_flush();
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }
    // Now rewrite all but multiples of 3.
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        if ((bno % 3) == 0)
        {
            continue;
        }
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }

    // get a nuvo_gc
    struct nuvo_gc *gc;
    gc = nuvo_gc_alloc();
    ck_assert(gc != NULL);

    nuvo_return_t        rc;
    struct nuvo_segment *segment;
    NUVO_ASSERT(segment_gcable(fake_map.luns[lidx].data_entry[0].media_addr.parcel_index, fake_map.luns[lidx].data_entry[0].media_addr.block_offset));
    rc = nuvo_space_vol_segment_log_replay_get(&test_var.vol.log_volume.space,
                                            fake_map.luns[lidx].data_entry[0].media_addr.parcel_index,
                                            fake_map.luns[lidx].data_entry[0].media_addr.block_offset,
                                            &segment);
    ck_assert(rc == 0);

    nuvo_gc_init(gc, &test_var.vol, segment);

    test_read_digest(gc);

    // cycle through digest.  Every block in it that is multiple of
    // 3 should have same address in the map.  Every one that is not
    // multiple of 3 should have different address since we rewrote it.
    unsigned num_left = 0;
    for (unsigned boffset = 0; boffset < gc->digest.footer.used_block_count; boffset++)
    {
        if (gc->digest.table[boffset].log_entry_type != NUVO_LE_DATA)
        {
            continue;
        }
        uint_fast32_t pbno = segment->block_offset + boffset;
        uint_fast32_t bno = gc->digest.table[boffset].data.bno;
        bool          moved = (fake_map.luns[lidx].data_entry[bno].media_addr.parcel_index != segment->parcel_index ||
                            fake_map.luns[lidx].data_entry[bno].media_addr.block_offset != pbno);
        bool should_moved = (0 != (bno % 3));
        if (!moved)
        {
            num_left++;
            ck_assert(!should_moved);
        }
        else
        {
            ck_assert(should_moved);
        }
    }
    // Now elide.
    test_elide_digest(gc);

    // Only data blocks left in the digest should be multiples of 3.
    unsigned num_left_after = 0;
    for (unsigned boffset = 0; boffset < gc->digest.footer.used_block_count; boffset++)
    {
        uint_fast32_t bno = gc->digest.table[boffset].data.bno;
        if (gc->block_state[boffset] == NUVO_GC_BLOCK_MOVE_DATA)
        {
            ck_assert(bno % 3 == 0);
            num_left_after++;
        }
    }
    ck_assert(num_left == num_left_after);
    ck_assert(0 != test_var.vol.log_volume.mfst.segment_state_media[1].seg_blks_used);

    test_move_data(gc, NUVO_SPACE_GC_MOVE_MAPS);

    test_move_maps(gc);

    // Need to move the maps.

    ck_assert(0 == test_var.vol.log_volume.mfst.segment_state_media[1].seg_blks_used);

    // Check the data.
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        uint8_t read_buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
        buf_list[0] = &read_buffer;
        nuvo_return_t rc = nuvo_log_vol_lun_read(&test_var.vol.log_volume.lun, bno, 1, buf_list, NULL);
        ck_assert(rc == 0);
        uint64_t *data = (uint64_t *)read_buffer;
        ck_assert(data[0] == bno && data[1] == bno + 1);
    }

    // When gc is done the segment goes onto the list waiting for the next CP.
    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[segment->data_class].gc_free_next_cp == 0);
    nuvo_gc_done(gc);
    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[segment->data_class].gc_free_next_cp == 1);

    struct nuvo_segment *segment2 = nuvo_dlist_remove_head_object(&test_var.vol.log_volume.mfst.segments_free_in_next_cp, struct nuvo_segment, list_node);
    ck_assert(segment == segment2);
    test_var.vol.log_volume.mfst.data_class[segment->data_class].gc_free_next_cp--;  // TODO - just fake the mfst call?

    // Check that we are on the correct segments_free_next_cp
    nuvo_space_vol_segment_done(&test_var.vol.log_volume.space, segment, NUVO_MFST_SEGMENT_REASON_CLEAR_AGE);
}
END_TEST

/*
 * Write some data and some map data.
 * Carefully arrange that there will be even batchs of data and map left to test edge cases.
 * Garbage collect the segment.
 */
START_TEST(even_batches_gc)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);

    unsigned lidx = fake_map_lun_index(nuvo_get_lun_by_snapid(&test_var.vol, NUVO_MFST_ACTIVE_LUN_SNAPID, false));

    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void   *buf_list[128];
    buf_list[0] = buffer;
    uint32_t lun_blocks = 600;

    for (unsigned i = 0; i < 128; i++)
    {
        fake_map.luns[lidx].map_blocks[i].dirty = true;
    }
    map_flush();
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }
    // Now rewrite above 128.
    for (unsigned bno = 128; bno < lun_blocks; bno++)
    {
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }

    // get a nuvo_gc
    struct nuvo_gc *gc;
    gc = nuvo_gc_alloc();
    ck_assert(gc != NULL);

    nuvo_return_t        rc;
    struct nuvo_segment *segment;
    NUVO_ASSERT(segment_gcable(fake_map.luns[lidx].data_entry[0].media_addr.parcel_index, fake_map.luns[lidx].data_entry[0].media_addr.block_offset));
    rc = nuvo_space_vol_segment_log_replay_get(&test_var.vol.log_volume.space,
                                            fake_map.luns[lidx].data_entry[0].media_addr.parcel_index,
                                            fake_map.luns[lidx].data_entry[0].media_addr.block_offset,
                                            &segment);
    ck_assert(rc == 0);

    nuvo_gc_init(gc, &test_var.vol, segment);

    test_read_digest(gc);

    unsigned num_left = 0;
    for (unsigned boffset = 0; boffset < gc->digest.footer.used_block_count; boffset++)
    {
        if (gc->digest.table[boffset].log_entry_type != NUVO_LE_DATA)
        {
            continue;
        }
        uint_fast32_t pbno = segment->block_offset + boffset;
        uint_fast32_t bno = gc->digest.table[boffset].data.bno;
        bool          moved = (fake_map.luns[lidx].data_entry[bno].media_addr.parcel_index != segment->parcel_index ||
                            fake_map.luns[lidx].data_entry[bno].media_addr.block_offset != pbno);
        bool should_moved = (bno >= 128);
        if (!moved)
        {
            num_left++;
            ck_assert(!should_moved);
        }
        else
        {
            ck_assert(should_moved);
        }
    }
    // Now elide.
    test_elide_digest(gc);

    // Only blocks left in the digest should be multiples of 0-127
    unsigned num_left_after = 0;
    for (unsigned boffset = 0; boffset < gc->digest.footer.used_block_count; boffset++)
    {
        uint_fast32_t bno = gc->digest.table[boffset].data.bno;
        if (gc->block_state[boffset] != NUVO_GC_BLOCK_MOVE_DATA)
        {
            continue;
        }
        ck_assert(bno < 128);
        num_left_after++;
    }
    ck_assert(num_left == num_left_after);
    ck_assert(0 != test_var.vol.log_volume.mfst.segment_state_media[1].seg_blks_used);

    test_move_data(gc, NUVO_SPACE_GC_MOVE_MAPS);

    test_move_maps(gc);

    // Need to move the maps.

    ck_assert(0 == test_var.vol.log_volume.mfst.segment_state_media[1].seg_blks_used);

    // Check the data.
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        uint8_t read_buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
        buf_list[0] = &read_buffer;
        nuvo_return_t rc = nuvo_log_vol_lun_read(&test_var.vol.log_volume.lun, bno, 1, buf_list, NULL);
        ck_assert(rc == 0);
        uint64_t *data = (uint64_t *)read_buffer;
        ck_assert(data[0] == bno && data[1] == bno + 1);
    }

    // When gc is done the segment goes onto the list waiting for the next CP.
    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[segment->data_class].gc_free_next_cp == 0);
    nuvo_gc_done(gc);
    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[segment->data_class].gc_free_next_cp == 1);

    struct nuvo_segment *segment2 = nuvo_dlist_remove_head_object(&test_var.vol.log_volume.mfst.segments_free_in_next_cp, struct nuvo_segment, list_node);
    ck_assert(segment == segment2);
    test_var.vol.log_volume.mfst.data_class[segment->data_class].gc_free_next_cp--;

    // Check that we are on the correct segments_free_next_cp
    nuvo_space_vol_segment_done(&test_var.vol.log_volume.space, segment, NUVO_MFST_SEGMENT_REASON_CLEAR_AGE);
}
END_TEST

/*
 * Write some data and some map data. Garbage collect a segment.
 * Let the space management thread do the driving.
 */
START_TEST(basic_map_gc_space_loop)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);

    unsigned lidx = fake_map_lun_index(nuvo_get_lun_by_snapid(&test_var.vol, NUVO_MFST_ACTIVE_LUN_SNAPID, false));

    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    void   *buf_list[128];
    buf_list[0] = buffer;
    uint32_t lun_blocks = 600;

    for (unsigned i = 0; i < 100; i++)
    {
        fake_map.luns[lidx].map_blocks[i].dirty = true;
    }
    map_flush();
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }
    // Now rewrite all but multiples of 3.
    for (unsigned bno = 0; bno < lun_blocks; bno++)
    {
        if ((bno % 3) == 0)
        {
            continue;
        }
        fill_data(bno, (uint64_t *)buffer);
        nuvo_return_t rc = nuvo_log_vol_write(&test_var.vol, bno, 1, buf_list);
        ck_assert(rc == 0);
    }

    nuvo_space_gc_enable_for_test();
    // Steal all of the gcs
    struct nuvo_dlist parking;
    nuvo_dlist_init(&parking);
    struct nuvo_gc *stolen_gc;
    while (NULL != (stolen_gc = nuvo_gc_alloc()))
    {
        nuvo_dlist_insert_tail(&parking, &stolen_gc->list_node);
    }
    nuvo_space_vol_manage_gc_start(&test_var.vol.log_volume.space);
    nuvo_space_vol_need_empty_segments(&test_var.vol.log_volume.space, NUVO_DATA_CLASS_A);

   // Confirm our volume goes onto the needs_struct list.
    while (&test_var.vol.log_volume.space != nuvo_gc_peek_vol_needs_gc_struct())
    {
        struct timespec tenth;
        tenth.tv_sec = 0;
        tenth.tv_nsec = 100000000;
        nanosleep(&tenth, NULL);
    }
    // Now free the gc_batches
    while (NULL != (stolen_gc = nuvo_dlist_remove_head_object(&parking, struct nuvo_gc, list_node)))
    {
        nuvo_gc_free(stolen_gc);
    }
    while (&test_var.vol.log_volume.space == nuvo_gc_peek_vol_needs_gc_struct())
    {
        struct timespec tenth;
        tenth.tv_sec = 0;
        tenth.tv_nsec = 100000000;
        nanosleep(&tenth, NULL);
    }
    while (test_var.vol.log_volume.space.gc_data_class[NUVO_DATA_CLASS_A].gc_needed != 0 ||
           test_var.vol.log_volume.space.gc_data_class[NUVO_DATA_CLASS_A].gc_in_progress != 0)
    {
        struct timespec tenth;
        tenth.tv_sec = 0;
        tenth.tv_nsec = 100000000;
        nanosleep(&tenth, NULL);
    }

    // Pretend to do CP's to make the gc segments drain and free.
    struct nuvo_mfst *mfst = &test_var.vol.log_volume.mfst;
    while (0 != nuvo_mfst_gc_pipeline_total(mfst))
    {
        nuvo_mfst_gc_starting_cp(mfst);
        (void) nuvo_mfst_cp_done_for_gc(mfst);
    }

    nuvo_space_vol_manage_gc_stop(&test_var.vol.log_volume.space);
}
END_TEST

void simulate_cp_segment_freeing()
{
    struct nuvo_space_vol *space = &test_var.vol.log_volume.space;
    struct nuvo_mfst *mfst = &test_var.vol.log_volume.mfst;
    struct nuvo_segment *seg;
    while (NULL != (seg = nuvo_dlist_remove_head_object(&mfst->segments_free_in_next_cp, struct nuvo_segment, list_node)))
    {
        NUVO_ASSERT(mfst->data_class[seg->data_class].gc_free_next_cp > 0);
        mfst->data_class[seg->data_class].gc_free_next_cp--;
        nuvo_space_vol_segment_done(space, seg, NUVO_MFST_SEGMENT_REASON_CLEAR_AGE);
    }
}

// Takes segment with parcel index and block offset, fills in rest of segment.  Returns gc.
struct nuvo_gc *test_clean_segment_plan(uint32_t parcel_index, uint32_t block_offset)
{
    struct nuvo_segment *segment;
    NUVO_ASSERT(segment_gcable(parcel_index, block_offset));
    nuvo_return_t rc = nuvo_space_vol_segment_log_replay_get(&test_var.vol.log_volume.space, parcel_index, block_offset, &segment);
    ck_assert(rc == 0);

    struct nuvo_gc *gc;
    gc = nuvo_gc_alloc();
    ck_assert(gc != NULL);

    nuvo_gc_init(gc, &test_var.vol, segment);

    test_read_digest(gc);

    test_elide_digest(gc);

    return gc;
}

void test_clean_segment_execute(struct nuvo_gc *gc, bool active_interference)
{
    // gc and gc->segment go away in the middle of this.   squirrel away info from them.
    uint8_t data_class = gc->segment->data_class;
    uint32_t parcel_index = gc->segment->data_class;
    uint32_t block_offset = gc->segment->block_offset;

    if (!active_interference)
    {
        test_move_data(gc, NUVO_SPACE_GC_MOVE_MAPS);
        ck_assert(gc->actives_failed == 0);
    }
    else
    {
        test_move_data(gc, NUVO_SPACE_GC_MOVE_FAILED);
        ck_assert(gc->state == NUVO_SPACE_GC_MOVE_FAILED);
        // TODO redrive
        nuvo_gc_re_init(gc);
        test_read_digest(gc);
        test_elide_digest(gc);
        test_move_data(gc, NUVO_SPACE_GC_MOVE_MAPS);
    }

    ck_assert(gc->state == NUVO_SPACE_GC_MOVE_MAPS);
    test_move_maps(gc);

    // When gc is done the segment goes onto the list waiting for the next CP.
    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[data_class].gc_free_next_cp == 0);
    nuvo_gc_done(gc);

    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[data_class].gc_free_next_cp == 1);
    simulate_cp_segment_freeing();
    NUVO_ASSERT(test_var.vol.log_volume.mfst.data_class[data_class].gc_free_next_cp == 0);

    nuvo_mutex_lock(&test_var.vol.log_volume.mfst.mfst_mutex);
    uint_fast32_t seg_idx = nuvo_mfst_seg_idx(&test_var.vol.log_volume.mfst, parcel_index, block_offset);
    nuvo_mutex_unlock(&test_var.vol.log_volume.mfst.mfst_mutex);
    if (!active_interference)
    {
        fake_map_range_unused(parcel_index, block_offset, 1024);
    }
    NUVO_ASSERT(!NUVO_SEGMENT_IN_USE(&test_var.vol.log_volume.mfst, seg_idx));
    (void) seg_idx;
}

void test_clean_segment(uint32_t parcel_index, uint32_t block_offset)
{
    struct nuvo_gc *gc = test_clean_segment_plan(parcel_index, block_offset);
    test_clean_segment_execute(gc, false);
}

// Simple data test
// Write some data.
// Overwrite some.
// Overwrite some in new segment.
// clean first segment, check data.
// clean second segment, check data.
// clean gc segment, check data.
START_TEST(simple_data_test)
{
    #define SIMPLE_DATA_TEST_IO 10
    #define SIMPLE_DATA_TEST_BLOCKS 50
    unsigned bno = 0;
    unsigned num;
    NUVO_ASSERT(SIMPLE_DATA_TEST_BLOCKS + SIMPLE_DATA_TEST_IO <= DATA_GENS_BLOCKS_LIMIT);

    while (bno < SIMPLE_DATA_TEST_BLOCKS)
    {
        num = rand() % SIMPLE_DATA_TEST_IO + 1;  // May go beyond 50.
        data_gens_write_blocks(bno, num);
        bno += num;
    }
    uint_fast32_t first_seg_parcel = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint_fast32_t first_seg_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;

    for (unsigned range = 0; range < 5; range++)
    {
        bno = rand() % SIMPLE_DATA_TEST_BLOCKS;
        num = (rand() % (SIMPLE_DATA_TEST_IO / 2)) + 1;
        data_gens_write_blocks(bno, num);
    }

    data_gens_check_blocks();
    test_close_segment(first_seg_parcel, first_seg_block_offset);

    for (unsigned range = 0; range < 5; range++)
    {
        bno = rand() % SIMPLE_DATA_TEST_BLOCKS;
        num = rand() % (SIMPLE_DATA_TEST_IO / 2) + 1;
        data_gens_write_blocks(bno, num);
    }
    uint_fast32_t second_seg_parcel = fake_map.luns[0].data_entry[bno].media_addr.parcel_index;
    uint_fast32_t second_seg_block_offset = fake_map.luns[0].data_entry[bno].media_addr.block_offset;

    test_clean_segment(first_seg_parcel, first_seg_block_offset);

    // GC second segment.
    write_zeros_until_gcable(200, second_seg_parcel, second_seg_block_offset);
    test_clean_segment(second_seg_parcel, second_seg_block_offset);
    // GC  GC segment
    uint_fast32_t third_seg_parcel = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint_fast32_t third_seg_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(200, third_seg_parcel, third_seg_block_offset);
    test_clean_segment(third_seg_parcel, third_seg_block_offset);
    data_gens_check_blocks();
}
END_TEST

// Very simple pit data test.
// Will write five blocks with (bno and 1).
// Then will create snap and overwrite first and last two. with (bno, 2)
// Then will create snap and overwrite first and last. with (bno, 3)
//
// So...
// active should see       : (0,3) (1,2) (2,1) (3,2) (4,3)
// snap 2 and 3 should see : (0,2) (1,2) (2,1) (3,2) (4,2)
// snap 1 should see       : (0,1) (1,1) (2,1) (3,1) (4,1)
void simple_snap_data_test_build()
{
    data_gens_write_blocks(0, 5);
    data_gens_create_snap();
    data_gens_write_blocks(0, 2);
    data_gens_write_blocks(3, 2);
    data_gens_create_snap();
    data_gens_create_snap();
    data_gens_write_blocks(0, 1);
    data_gens_write_blocks(4, 1);
}

START_TEST(simple_snap_data_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // GC the segment.
    uint32_t segment_parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t segment_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, segment_parcel_index, segment_block_offset);
    test_clean_segment(segment_parcel_index, segment_block_offset);
    data_gens_check_blocks();

    // Now close new segment, read the log summary of the new segment and verify that each
    // block got the proper gc added?

    // Now gc the gc segment.  Data has moved.  Get the new location.
    segment_parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    segment_block_offset= fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, segment_parcel_index, segment_block_offset);
    test_clean_segment(segment_parcel_index, segment_block_offset);
    data_gens_check_blocks();

    // Test replay?
}
END_TEST

START_TEST(simple_snap_data_race_move_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // Now start a new gc

    // After we have decided what to move, overwrite the blocks in the active.
    // This forces some into snapshot and frees some.
    // Overwrites should fail.  GC should go into the "stuff moved out from under me state."
    uint32_t parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, parcel_index, block_offset);
    struct nuvo_gc *gc = test_clean_segment_plan(parcel_index, block_offset);
    // Now overwrite active.
    data_gens_write_blocks(0, 5);
    // Execute should hit moved blocks.
    test_clean_segment_execute(gc, true);

    data_gens_check_blocks();

    gc = test_clean_segment_plan(parcel_index, block_offset);
    test_clean_segment_execute(gc, false);

    data_gens_check_blocks();

    // Now close new segment, read the log summary of the new segment and verify that each
    // block got the proper gc added?

    // Test replay?
}
END_TEST

START_TEST(simple_snap_data_race_zero_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // Now start a new gc

    // After we have decided what to move, overwrite the blocks in the active with zeros.
    // This forces some into snapshot and frees some.
    // Overwrites should fail.  GC should go into the "stuff moved out from under me state."
    uint32_t parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, parcel_index, block_offset);
    struct nuvo_gc *gc = test_clean_segment_plan(parcel_index, block_offset);
    // Now overwrite active.
    data_gens_zero_blocks(0, 5);
    // Execute should hit zeroed blocks.
    test_clean_segment_execute(gc, true);

    data_gens_check_blocks();

    gc = test_clean_segment_plan(parcel_index, block_offset);
    test_clean_segment_execute(gc, false);

    data_gens_check_blocks();

    // Now close new segment, read the log summary of the new segment and verify that each
    // block got the proper gc added?

    // Test replay?
}
END_TEST

START_TEST(deleting_snap_data_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // Now let's simulate deleting the last snap
    test_var.vol.log_volume.lun_list[1].lun_state = NUVO_LUN_STATE_DELETING;
    // Now gc will not move the data blocks from the first snapshot.

    // GC the segment.
    uint32_t segment_parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t segment_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, segment_parcel_index, segment_block_offset);
    test_clean_segment(segment_parcel_index, segment_block_offset);
    data_gens_check_blocks();

    // Test replay?
}
END_TEST

START_TEST(deleting_snap_blocks_freed_data_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // Now let's simulate deleting the last snap
    test_var.vol.log_volume.lun_list[1].lun_state = NUVO_LUN_STATE_DELETING;
    fake_map_simulate_pit_delete_hole_punching(&test_var.vol.log_volume.lun_list[1]);
    // Now gc will not move the data blocks from the first snapshot.

    // GC the segment.
    uint32_t segment_parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t segment_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, segment_parcel_index, segment_block_offset);
    test_clean_segment(segment_parcel_index, segment_block_offset);
    //data_gens_check_blocks();  // TODO - tries to read deleted snapshot

    // Test replay?
}
END_TEST

START_TEST(deleting_drain_snap_data_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // Now let's simulate deleting the last snap
    test_var.vol.log_volume.lun_list[1].lun_state = NUVO_LUN_STATE_DELETING_DRAIN;
    fake_map_simulate_pit_delete_hole_punching(&test_var.vol.log_volume.lun_list[1]);
    // Now gc will not move the data blocks from the first snapshot.

    // GC the segment.
    uint32_t segment_parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t segment_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, segment_parcel_index, segment_block_offset);
    test_clean_segment(segment_parcel_index, segment_block_offset);
    //data_gens_check_blocks();  // TODO - tries to read deleted snapshot

    // Test replay?
}
END_TEST

START_TEST(deleted_snap_data_test)
{
    simple_snap_data_test_build();
    data_gens_check_blocks();

    // Now let's simulate deleting the last snap
    test_var.vol.log_volume.lun_list[1].lun_state = NUVO_LUN_STATE_DELETED;
    fake_map_simulate_pit_delete_hole_punching(&test_var.vol.log_volume.lun_list[1]);
    test_var.vol.log_volume.lun_list[2].lun_state = NUVO_LUN_STATE_DELETING;
    // Now gc will not move the data blocks from the first snapshot.

    // GC the segment.
    uint32_t segment_parcel_index = fake_map.luns[0].data_entry[0].media_addr.parcel_index;
    uint32_t segment_block_offset = fake_map.luns[0].data_entry[0].media_addr.block_offset;
    write_zeros_until_gcable(6, segment_parcel_index, segment_block_offset);
    test_clean_segment(segment_parcel_index, segment_block_offset);
    //data_gens_check_blocks();  // TODO - tries to read deleted snapshot

    // Test replay?
}
END_TEST

Suite *nuvo_gc_suite(void)
{
    Suite *s = suite_create("GC");
    TCase *tc_gc = tcase_create("GC");

    nuvo_log.mfst.level = 0;
    nuvo_log.space.level = 50;
    tcase_add_checked_fixture(tc_gc, gc_tests_setup, gc_tests_teardown);

    tcase_add_test(tc_gc, gc_queues);
    tcase_add_test(tc_gc, read_digest);
    tcase_add_test(tc_gc, basic_data_gc);
    tcase_add_test(tc_gc, basic_map_gc);
    tcase_add_test(tc_gc, even_batches_gc);
    tcase_add_test(tc_gc, basic_map_gc_space_loop);

    tcase_add_test(tc_gc, simple_data_test);
    tcase_add_test(tc_gc, simple_snap_data_test);
    tcase_add_test(tc_gc, simple_snap_data_race_move_test);
    tcase_add_test(tc_gc, simple_snap_data_race_zero_test);
    tcase_add_test(tc_gc, deleting_snap_data_test);
    tcase_add_test(tc_gc, deleting_snap_blocks_freed_data_test);
    tcase_add_test(tc_gc, deleting_drain_snap_data_test);
    tcase_add_test(tc_gc, deleted_snap_data_test);

    suite_add_tcase(s, tc_gc);

    return s;
}
