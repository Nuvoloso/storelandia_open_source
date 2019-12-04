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
#include "nuvo_vol_series.h"
#include "lun.h"
#include "map_priv.h"
#include "resilience.h"
#include "map_replay.h"

void nuvo_map_replay_evict(struct nuvo_map_request *map_req, bool unpin)
{
    struct nuvo_log_request  *log_req = (struct nuvo_log_request *)map_req->tag.ptr;
    struct nuvo_log_io_block *log_block = &log_req->log_io_blocks[log_req->replay_count];

    NUVO_ASSERT(log_block->log_entry_type >= NUVO_LE_MAP_L0);

    struct nuvo_vol *vol = log_req->vs_ptr;
    struct nuvo_lun *lun = map_req->lun;

    struct nuvo_map_track *map = map_req->first_map;

    //make sure basics are alright after a possible callback
    struct nuvo_map_entry *map_entry = &map->parent->entries[nuvo_map_get_table_index(map_req->block_start, map->level + 1)];
    NUVO_ASSERT(map_entry->type == NUVO_ME_IN_MEM);
    NUVO_ASSERT(map_entry->ptr == map);

    uint8_t cow = map_entry->cow; // save cow, might be required
    struct nuvo_map_track *parent = map->parent;

    NUVO_ASSERT(!map->child_count);

    map->is_dirty = 0; //clean like the flush is done.

    //free for the old entry
    nuvo_mfst_segment_free_blks(&vol->log_volume.mfst, 1, &map->map_entry);
    //copy the log entry media addr to the map without losing the cow bit
    if (!NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr))
    {
        log_req->nuvo_map_entries[log_req->replay_count].cow = map->map_entry.cow;
    }
    map->map_entry = log_req->nuvo_map_entries[log_req->replay_count];
    // use the new entry
    // TODO: think of cow bit and pits
    nuvo_mfst_segment_use_blks(&vol->log_volume.mfst, 1, &map->map_entry);

    // The below can happen if the order of ops is
    // map updated(data write), snap creation,  map written out.
    // say D, S, M in the log.
    // since the written out map was never visited after snap, it will have a snap_gen less than
    // the parent
    // So we shouldnt lose the cow bit in this case, so restore the cow bit

    if (map->snap_gen < parent->snap_gen && !NUVO_LUN_MFL_IN_PROGRESS(lun))
    {
        map->map_entry.cow = cow;
    }
    map->is_new_entry = 1;

    // We can get a replay map block for a parent that is in memory
    // Since it is possible that CP and data ops were happening in parallel
    // So the data op got logged and now the map path for that including LO
    // got loaded in memory
    // And a new address for the parent appeared from the concurrent CP

    // This can also happen with GC dirtying an intermediate map to write out for CP
    // and who get children later due to data ops.

    // We cant evict the intermediate maps.
    // sooner or later we will get a child map entry for the data op and a corresponding
    // parent entry if they are in the log (depending on the crash)
    // If the crash happens before the L0 and this parent got written out,
    // we leave the state in memory as it is.

    if (unpin)
    {
        NUVO_ASSERT(NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr));

        nuvo_mutex_lock(&nuvo_map->list_mutex);
        nuvo_map_unpin_table_locked(map);
        nuvo_map_unpin_table_locked(map);
        nuvo_mutex_unlock(&nuvo_map->list_mutex);

        //since clean maps during replay to go clean list and we still have map lock
        NUVO_ASSERT(map->state == NUVO_MAP_CLEAN_LIST);
    }

    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_evict_table(map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
}

void nuvo_map_replay_rsv_cb(struct nuvo_map_request *map_req)
{
    // reserve has finished, now do fault-in
    map_req->callback = nuvo_map_replay_fault_cb;
    nuvo_map_fault_in(map_req);
}

void nuvo_map_data_replay_active_fault_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_log_request *log_req = map_req->tag.ptr;
    struct nuvo_map_request *map_req_snap = &log_req->map_req_snap;

    //  fault in the snap  lun map
    map_req_snap->tag.ptr = log_req;
    map_req_snap->callback = nuvo_map_replay_fault_cb;
    nuvo_map_fault_in(map_req_snap);
}

void nuvo_map_data_replay_snap_rsv_cb(struct nuvo_map_request *map_req_snap)
{
    // we got the snap lun reserve
    // now lets do the fault in for the active
    struct nuvo_log_request *log_req = map_req_snap->tag.ptr;
    // get active map request
    struct nuvo_map_request *map_req = &log_req->map_req;

    map_req_snap->tag.ptr = log_req;
    map_req->callback = nuvo_map_data_replay_active_fault_cb;
    // fault in the active lun
    nuvo_map_fault_in(map_req);
}

/*Documented in header */
void nuvo_map_replay_vol_done(struct nuvo_vol *vol)
{
    nuvo_mutex_lock(&nuvo_map->list_mutex);

    /*note we that dont set the per map is_in_replay_stash_list bit
     * now to avoid walking this list */
    if (vol->map_replay_stash_list_count)
    {
        NUVO_ERROR_PRINT("moving %d maps from replay_stash_list to mixed lru for vol:" NUVO_LOG_UUID_FMT,
                         vol->map_replay_stash_list_count, NUVO_LOG_UUID(vol->vs_uuid));
        nuvo_map->mixed_count += vol->map_replay_stash_list_count;
        vol->map_replay_stash_list_count = 0;
        nuvo_dlist_insert_list_head(&nuvo_map->mixed_lru_list, &vol->map_replay_stash_list);
    }
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
}

void map_cmp_log(struct nuvo_map_track *m1, struct nuvo_map_track *m2, int log_level)
{
    NUVO_LOG(map, log_level, "replay mismatch between on media and mem map:%p state:%d mfl:%d "
             "m1 map_entry(%lu:%lu) m2 addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d "
             "map lun(%d)",
             m1, m1->state, m1->mfl,
             m1->map_entry.media_addr.parcel_index,
             m1->map_entry.media_addr.block_offset,
             m2->map_entry.media_addr.parcel_index,
             m2->map_entry.media_addr.block_offset,
             m1->base_offset, m1->level, m1->is_dirty, m1->lun->snap_id);
}

//returns true on mismatch */
nuvo_return_t map_cmp(struct nuvo_map_track *m1, struct nuvo_map_track *m2)
{
    if (!memcmp(m1->entries, m2->entries, NUVO_BLOCK_SIZE))
    {
        return (0);
    }

    bool mismatch = false;

    for (unsigned int i = 0; i < NUVO_MAP_RADIX; i++)
    {
        struct nuvo_map_entry *e1 = &m1->entries[i];
        struct nuvo_map_entry *e2 = &m2->entries[i];

        if (e1->cow != e2->cow)
        {
            map_cmp_log(m1, m2, 30);
            NUVO_LOG(map, 30, "index:%d e1->cow:%d e2->cow:%d", i, e1->cow, e2->cow);
            mismatch = true;
            break;
        }

        if (e1->type != e2->type)
        {
            map_cmp_log(m1, m2, 0);
            NUVO_PRINT("index:%d e1->type:%d e2->type:%d", i, e1->type, e2->type);
            mismatch = true;
            break;
        }

        if (e1->unused != e2->unused)
        {
            map_cmp_log(m1, m2, 0);
            NUVO_PRINT("index:%d e1->unused:%d e2->unused:%d", i, e1->unused, e2->unused);
        }

        if (!NUVO_MEDIA_ADDR_EQUAL(&e1->media_addr, &e2->media_addr))
        {
            map_cmp_log(m1, m2, 0);
            NUVO_PRINT("index:%d e1 media_addr(%u %u) e2 media_addr(%u %u)", i,
                       e1->media_addr.parcel_index, e1->media_addr.block_offset,
                       e2->media_addr.parcel_index, e2->media_addr.block_offset);
            mismatch = true;
            break;
        }

        if (e1->hash != e2->hash)
        {
            map_cmp_log(m1, m2, 0);
            NUVO_PRINT("index:%d e1->hash:%llu e2->hash:%llu", i,
                       e1->hash, e2->hash);
            mismatch = true;
            break;
        }
    }

    return ((mismatch == true) ? NUVO_EINVAL : 0);
}

/* we read the map from disk
 * compare to the map in mem
 * if same, evict
 */
void nuvo_map_replay_cmp_io_done_cb(struct nuvo_io_request *io_req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);

    struct nuvo_map_request *map_req = io_req->tag.ptr;
    struct nuvo_log_request *log_req = (struct nuvo_log_request *)map_req->tag.ptr;

    struct nuvo_map_track *map = map_req->first_map;
    struct nuvo_map_track *map_on_media = map_req->last_map;
    struct nuvo_map_track *parent = map->parent;

    //reacquire the locks.
    nuvo_mutex_lock(&parent->mutex);
    nuvo_mutex_lock(&map->mutex);

    NUVO_ASSERT(parent->pinned);
    NUVO_ASSERT(map->pinned);

    nuvo_return_t ret = map_cmp(map, map_on_media);

    nuvo_map_unpin_table(map, &comp_list);

    if (!ret)
    {
        // unpin is only needed if map was loaded explictly for MFL
        // but this callback is called only for map cmp reads,( which we dont during MFL replay)
        // so we know that we dont need to upin
        nuvo_map_replay_evict(map_req, /*unpin = */ false);
    }
    else
    {
        NUVO_LOG(map, 0, "Cannot EVICT(hash mismatch) --  map:%p state:%d child_count:%d mfl:%d media_addr:(%lu:%lu cow:%d) "
                 "map_on_media addr(%lu:%lu cow:%d) offset:%lu "
                 "level:%d map->is_dirty:%d lun(%d)",
                 map, map->state, map->child_count, map->mfl,
                 map->map_entry.media_addr.parcel_index,
                 map->map_entry.media_addr.block_offset,
                 map->map_entry.cow,
                 map_on_media->map_entry.media_addr.parcel_index,
                 map_on_media->map_entry.media_addr.block_offset,
                 map_on_media->map_entry.cow,
                 map->base_offset, map->level, map->is_dirty, map->lun->snap_id);
    }

    nuvo_pr_client_req_free(io_req);

    //put the allocaed map for read on the same request after use
    nuvo_dlist_insert_head(&map_req->map_list, &map_on_media->list_node);

    // we hold on to the mutex during the i/o
    // this is replay and noone should care about this map
    nuvo_mutex_unlock(&map->mutex);
    /* else we have a hash mismatch, so we dont evict the map */

    nuvo_map_unpin_table(parent, &comp_list);
    nuvo_map_unpin_table(parent, &comp_list);
    nuvo_mutex_unlock(&parent->mutex);

    // free any map tables that are the on the map_req list
    map_request_free(map_req, &comp_list);

    struct nuvo_map_alloc_req *alloc_req;
    while ((alloc_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        alloc_req->callback(alloc_req);
    }

    log_req->replay_count++;
    if (log_req->replay_count < log_req->block_count)
    {
        nuvo_map_replay_next(log_req);
    }
    else
    {
        // we're done replaying this log req, ack it
        nuvo_log_ack_sno(log_req);
    }
}

void nuvo_map_replay_cmp_req_alloc_cb(struct nuvo_pr_req_alloc *req_alloc)
{
    struct nuvo_map_request *map_req = req_alloc->tag.ptr;
    struct nuvo_map_track   *map = map_req->last_map;
    // get a pointer to the map request that triggered this read
    struct nuvo_io_request *io_req = req_alloc->req;

    NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_NONE);
    NUVO_LOG(map, 30, "io req allocated, ssue i/o for (%u:%u) ", map->map_entry.media_addr.parcel_index,
             map->map_entry.media_addr.block_offset);
    io_req->tag.ptr = map_req;
    io_req->callback = nuvo_map_replay_cmp_io_done_cb;
    io_req->rw.parcel_desc = map_req->fault_parcel_desc;
    io_req->rw.block_offset = map->map_entry.media_addr.block_offset;
    io_req->rw.block_count = 1;
    io_req->rw.iovecs[0].iov_base = map->entries;
    io_req->rw.iovecs[0].iov_len = sizeof(struct nuvo_map_table);
    io_req->rw.vol = map_req->lun->vol;

    nuvo_rl_submit_req(io_req);
}

void nuvo_map_replay_pin_req_cb(struct nuvo_mfst_map_open *open_req)
{
    NUVO_ASSERT(open_req->status >= 0);
    struct nuvo_map_request *map_req = open_req->tag.ptr;

    struct nuvo_pr_req_alloc *req_alloc = &map_req->pr_req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);
    req_alloc->callback = nuvo_map_replay_cmp_req_alloc_cb;
    req_alloc->tag.ptr = map_req;
    NUVO_LOG(map, 30, "continue issue i/o for (%u:%u) ",
             map_req->last_map->map_entry.media_addr.parcel_index,
             map_req->last_map->map_entry.media_addr.block_offset);
    nuvo_pr_client_req_alloc_cb(req_alloc);
}

void nuvo_map_replay_cmp_read_map(struct nuvo_map_request *map_req, struct nuvo_map_entry *map_entry)
{
    NUVO_ASSERT(map_entry->type == NUVO_ME_MEDIA);
    // issue a read for the map on disk at map_entry and load onto map->entries
    struct nuvo_map_track *map = nuvo_dlist_remove_head_object(&map_req->map_list, struct nuvo_map_track, list_node);
    NUVO_ASSERT(map != NULL); // should have one map in the request
    map_req->last_map = map;  //using the last_map to stash the read map

    map->map_entry = *map_entry;

    map->vol = map_req->lun->vol; //need map->vol for read to work

    NUVO_LOG(map, 30, "issue i/o for (%u:%u) ", map->map_entry.media_addr.parcel_index,
             map->map_entry.media_addr.block_offset);

    struct nuvo_mfst_map_open *pin_req = &map_req->pin_req;
    pin_req->mfst = &map->vol->log_volume.mfst;
    pin_req->tag.ptr = map_req;
    pin_req->num_map_entries = 1;
    pin_req->map_entry = map_entry;
    pin_req->pds = &map_req->fault_parcel_desc;
    pin_req->callback = nuvo_map_replay_pin_req_cb;

    nuvo_mfst_open_async(pin_req);
}
