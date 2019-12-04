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

/* common functions for map ut */

#include <errno.h>
#include <fcntl.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lun.h"
#include "nuvo_vol_series.h"
#include "map_priv.h"
#include "nuvo_lock.h"
#include "nuvo_range_lock.h"
#include "nuvo_ck_assert.h"

extern struct nuvo_vol my_vol;

void nuvo_map_test_log_cb(struct nuvo_log_request *log_req);

void __nuvo_map_create_snap(struct nuvo_lun * active_lun,
                                  struct nuvo_lun *snap_lun)
{
    NUVO_ASSERT(active_lun->vol == snap_lun->vol);
    struct nuvo_vol *vol = active_lun->vol;

    NUVO_LOG(map, 1, "create snap for snap lun(%d)", snap_lun->snap_id);

    nuvo_mutex_lock(&vol->mutex); // for the checkpoint_gen and write out
    uint_fast64_t checkpoint_gen = vol->log_volume.map_state.checkpoint_gen;
    nuvo_mutex_lock(&active_lun->mutex);
    nuvo_mutex_lock(&active_lun->root_map->mutex);
    struct nuvo_map_track  *root_map =  active_lun->root_map;
    nuvo_mutex_unlock(&active_lun->mutex);

    nuvo_mutex_lock(&snap_lun->mutex);
    nuvo_mutex_lock(&snap_lun->root_map->mutex);
    struct nuvo_map_track  *snap_root_map =  snap_lun->root_map;
    nuvo_mutex_unlock(&snap_lun->mutex);

    // mark the MEs in root map as COW
    // and that in snapshot root map as SHARED
    // note:  no media addr copy optmization yet.

    for(uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        root_map->entries[i].cow = NUVO_MAP_ENTRY_COW;
        snap_root_map->entries[i].cow = NUVO_MAP_ENTRY_SHARED;
        snap_root_map->entries[i].type = NUVO_ME_NULL;

    }
    NUVO_MAP_SET_COW(root_map);
    NUVO_MAP_SET_SHARED(snap_root_map);
    root_map->snap_gen = snap_lun->snap_id; // the latest snap gen

    // snap_gen is not useful for snap luns,
    // they must be equal for parent child and every map for a snap lun

    // the latest snap gen must be set by the lun open
    NUVO_ASSERT(snap_root_map->snap_gen == snap_lun->snap_id);

    //root map always get shadowed in CP
    // just update the live tree
    // we have the volume lock so a cp cant begin between this
    NUVO_ASSERT(snap_lun->root_map->cp_gen == checkpoint_gen);
    NUVO_ASSERT(active_lun->root_map->cp_gen == checkpoint_gen);

    // Note that we do not dirty the root maps at this point of time.
    // we have already set the map entry to shared/cow correctly.
    // if no writes happen from here, CP would have this root map entry
    // going to lun table
    // for snapshots it is a shared map entry with no media address at this time.

    // if writes happen the new address update must change this
    // address to COW/NONE with a new media adress at root map entry

    // it is not a mistake to dirty , it would cause an additonal extraneous write.
    // In todays implementation we dont update the new address as COW/NONE if
    // the exisiting block is SHARED/COW
    // as writes must imply the new block as NONE/COW.
    // this is just the nature of implementation, read the code at map_entry_update()
    // and map_parent_entry_update_nl for the details.


    /*    snap_lun->root_map->is_dirty = 1;   TODO - dead code - remove?
          active_lun->root_map->is_dirty = 1;
    */

    nuvo_mutex_unlock(&snap_lun->root_map->mutex);
    nuvo_mutex_unlock(&active_lun->root_map->mutex);
    nuvo_mutex_unlock(&vol->mutex);
}

void log_ut_snap_op(struct nuvo_vol *vol, struct nuvo_lun *lun, int op)
{
    nuvo_mutex_t sync_signal;
    nuvo_mutex_init(&sync_signal);

    struct nuvo_log_request log_req;
    log_req.status = 0;

    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = op;
    log_req.atomic = true;
    log_req.tag.ptr = &sync_signal;
    log_req.vs_ptr = vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = 0;
    uuid_copy(log_req.pit_uuid, lun->lun_uuid);
    log_req.pit_id = lun->snap_id;

    nuvo_mutex_lock(&sync_signal);
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    nuvo_mutex_lock(&sync_signal);
    NUVO_ASSERT(!log_req.status);
    nuvo_log_ack_sno(&log_req);
    nuvo_mutex_unlock(&sync_signal);
}

// fake log a snap create
void map_ut_log_create_snap(struct nuvo_vol *vol, struct nuvo_lun *lun)
{
    log_ut_snap_op(vol, lun, NUVO_LOG_OP_CREATE_SNAP);

}
//fake log a snap delete
void map_ut_log_delete_lun(struct nuvo_vol *vol, struct nuvo_lun *lun)
{
    log_ut_snap_op(vol, lun, NUVO_LOG_OP_DELETE_SNAP);
}
struct nuvo_lun * map_ut_create_snap(struct nuvo_vol *vol)
{
    uuid_t lun_uuid;
    uuid_generate(lun_uuid);

    struct nuvo_lun * snap_lun = nuvo_map_create_snap(vol, lun_uuid);
    NUVO_ASSERT(snap_lun);

    // now (fake) log the op
    map_ut_log_create_snap(vol, snap_lun);
    return snap_lun;
}
int random_map[8192];
void map_ut_init_active(struct nuvo_vol *vol)
{
    struct nuvo_lun *lun = &vol->log_volume.lun;
    nuvo_ck_assert_int_eq(nuvo_mutex_init(&lun->mutex), 0);
    lun->vol = vol;

    lun->size = 1ull << 36;
    lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(lun);
    // get a root map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    nuvo_return_t ret = nuvo_map_lun_open(lun, &root_map_entry);
    NUVO_ASSERT(!ret);
}

//do the vol inits
void map_ut_vol_init(struct nuvo_vol *vol)
{
    struct nuvo_space_vol * space_vol = &vol->log_volume.space;
    nuvo_return_t rc = nuvo_space_vol_init(space_vol);
    NUVO_ASSERT(!rc);
    nuvo_map_vol_state_init(&vol->log_volume.map_state, vol);

    // create and init vol
    rc = nuvo_mutex_init(&vol->mutex);
    NUVO_ASSERT(!rc);

    nuvo_map_writer_init(&vol->log_volume.map_state.writer, vol);
}

void map_ut_multi_write(struct nuvo_lun *active_lun, struct nuvo_lun *snap_lun, int max_iter, uint32_t num_blocks, 
                            bool seq, int *seed)
{
    struct nuvo_map_request map_req;
    struct nuvo_map_request map_req_snap;

    uint8_t *write_bufs[32];
    for(unsigned i = 0; i < num_blocks; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        NUVO_ASSERT(write_bufs[i] != NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
    }

    if (seq)
    {
        max_iter = (max_iter > 256) ? max_iter/256 : 1; // in terms of map offsets, we have only 128x256 parcel addresses
    }

    if (!seq)
    {
        if (!(*seed))
        {
            *seed = time(NULL);
            srand(*seed);
        }
        else
        {
            srand(*seed);
        }
    }

    int iter = 0;
    uint32_t block_num;
    uint32_t max_block_no = active_lun->size/4096;
    //TODO a way to overwrite with the same random seed
    seq ? (block_num = 0) : (block_num = rand() % max_block_no);

    int i = 0;
    memset(random_map, 0 , sizeof(random_map)); 

    while(1)
    {
        // get some data to write to active
        // do map request
    
        random_map[i++] = block_num;
        nuvo_map_request_init(&map_req, active_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        if (snap_lun)
        {
            nuvo_map_request_init(&map_req_snap, snap_lun, block_num, num_blocks);
            nuvo_map_reserve_sync(&map_req_snap);
            NUVO_ASSERT(!map_req_snap.status);
        }
        // start logger
        nuvo_mutex_t log_signal;
        nuvo_ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        struct nuvo_log_request log_req0;
        nuvo_dlnode_init(&log_req0.list_node);
        log_req0.operation = NUVO_LOG_OP_DATA;
        log_req0.atomic = true;
        log_req0.tag.ptr = &log_signal;
        log_req0.vs_ptr = &my_vol;
        log_req0.data_class = NUVO_DATA_CLASS_A;
        log_req0.block_count = num_blocks;
        for(unsigned i = 0; i < num_blocks; i++)
        {
            log_req0.log_io_blocks[i].data = write_bufs[i];
            log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req0.log_io_blocks[i].bno = map_req.block_start + i;

            LOG_PIT_INFO_SET_DATA(log_req0.log_io_blocks[i].pit_info, 1, 0);
        }
        log_req0.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req0);
        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        if (snap_lun)
        {
            nuvo_map_fault_in_sync(&map_req_snap);
            NUVO_ASSERT(!map_req_snap.status);
        }
        // wait for logger
        nuvo_mutex_lock(&log_signal);
        // commit map
        if (snap_lun)
        {
            NUVO_LOG(map, 10 , "UT(multi_lun) write to map :%p offset:%lu num_blocks:%d", map_req_snap.first_map, 
                                                                map_req_snap.first_map->base_offset, 
                                                                num_blocks);
            nuvo_map_multi_lun_commit_write(&map_req, &map_req_snap,  log_req0.nuvo_map_entries);
        }
        else
        {
            NUVO_LOG(map, 10, "UT(single_lun) write to map :%p offset:%lu num_blocks:%d", map_req.first_map, 
                                                                map_req.first_map->base_offset, 
                                                                num_blocks);
            nuvo_map_commit_write(&map_req, log_req0.nuvo_map_entries);
        }
        // verify that all maps were freed on the map_req
        // ack to the logger
        struct nuvo_map_track *map;
        map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
        NUVO_ASSERT(map == NULL);
        nuvo_log_ack_sno(&log_req0);

        seq ? (block_num += 256) : (block_num = rand() % max_block_no);

        iter++;

        if (iter >= max_iter)
        {
            break;
        }
    }

    for(unsigned i = 0; i < num_blocks; i++)
    {
        free(write_bufs[i]);
    }
}


void map_ut_set_map_cleaning(struct nuvo_map_track *map)
{
    nuvo_mutex_lock(&map->parent->mutex);
    nuvo_mutex_lock(&map->mutex);
    // assert no children
    NUVO_ASSERT(!map->child_count);
    nuvo_mutex_lock(&nuvo_map->list_mutex); 
    nuvo_map_mixed_remove(map);
    map->state = NUVO_MAP_CLEANING;
    nuvo_mutex_unlock(&nuvo_map->list_mutex); 
    nuvo_map_writer_add_map(map, NUVO_MW_FLUSH_NONE);
    nuvo_mutex_unlock(&map->parent->mutex);
}
void map_ut_reserve_fault_in_intermediate(struct nuvo_map_request *map_req, struct nuvo_lun * lun,  uint64_t block, int target_level)
{
    nuvo_map_request_init(map_req, lun, block, 1);
    map_req->target_level = target_level;
    nuvo_map_reserve_sync(map_req);
    NUVO_ASSERT(map_req->status == 0);
    nuvo_map_fault_in_sync(map_req);
}

void map_ut_reserve_fault_in(struct nuvo_map_request *map_req, struct nuvo_lun * lun,  uint64_t bno)
{
    nuvo_map_request_init(map_req, lun, bno, 1);
    nuvo_map_reserve_sync(map_req);
    NUVO_ASSERT(map_req->status == 0);
    nuvo_map_fault_in_sync(map_req);
}

void map_ut_read_map(struct nuvo_map_request *map_req, struct nuvo_lun * lun,  uint64_t bno)
{
    // reserve and fault in the map
    map_ut_reserve_fault_in(map_req, lun, bno);
    // read lock and unlock to release the pins on the map
    nuvo_map_read_lock(map_req);
    nuvo_map_read_unlock(map_req);
}
void map_ut_evict(struct nuvo_map_track *map)
{
    struct nuvo_map_track *parent = map->parent;
    nuvo_mutex_lock(&nuvo_map->list_mutex); 
    nuvo_mutex_lock(&parent->mutex); 
    nuvo_mutex_lock(&map->mutex); 
    nuvo_map_evict_table(map);
    nuvo_mutex_unlock(&map->mutex); 
    nuvo_mutex_unlock(&parent->mutex); 
    nuvo_mutex_unlock(&nuvo_map->list_mutex); 
}

extern int in_replay;

//do the delete lun work, no logging
//use map_ut_log_delete_lun with this for logging + work for delete lun

nuvo_return_t map_ut_delete_lun_int(struct nuvo_lun *lun)
{
    struct nuvo_vol *vol = lun->vol;

    nuvo_mutex_lock(&vol->mutex);
    nuvo_mutex_lock(&lun->mutex);
    nuvo_mutex_lock(&vol->log_volume.space.space_vol_mutex);

    lun->lun_state = NUVO_LUN_STATE_DELETING;

    memset(lun->lun_uuid, 0, sizeof(*lun->lun_uuid));

    // add a work to the space thread indicating that there is work.
    // and wake up the space thread.
    if (!in_replay) 
    {
        nuvo_vol_new_needs_work_mfl(&vol->log_volume.space);
    }

    nuvo_mutex_unlock(&vol->log_volume.space.space_vol_mutex);
    nuvo_mutex_unlock(&lun->mutex);
    nuvo_mutex_unlock(&vol->mutex);
    return 0;
}

// force clean the map
// flush = true if the map needs to be written out
void map_ut_force_clean(struct nuvo_map_track *map, bool flush)
{
    struct nuvo_vol * vol = map->vol;
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_mutex_lock(&vol->mutex);
    nuvo_mutex_lock(&map->mutex);
    nuvo_map_mixed_remove(map);
    map->state = NUVO_MAP_CLEANING;
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
    //add_map releases the map mutex
    nuvo_map_writer_add_map(map, NUVO_MW_FLUSH_NONE);
    nuvo_mutex_unlock(&vol->mutex);

    //trigger a flush now
    //
    if (flush)
    {
        nuvo_map_writer_lock(vol);
        nuvo_map_writer_flush(vol);
    }
}

// wait for a CLEANING map to be written out
void map_ut_wait_clean(struct nuvo_map_track *map)
{
    nuvo_mutex_lock(&map->mutex);
    while(map->state == NUVO_MAP_CLEANING)
    {
        //sleep 10ms at a time.
        nuvo_mutex_unlock(&map->mutex);
        usleep(10000);
        nuvo_mutex_lock(&map->mutex);
    }
    nuvo_mutex_unlock(&map->mutex);
}

// do reserve and fault in
void map_ut_reserve_and_fault_in(struct nuvo_map_request *req, struct nuvo_lun *lun, uint64_t bno, uint64_t num_blocks)
{
    nuvo_map_request_init(req, lun, bno, num_blocks);
    nuvo_map_reserve_sync(req);
    nuvo_map_fault_in_sync(req);
}

