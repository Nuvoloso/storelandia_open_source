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
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "manifest.h"
#include "nuvo_vol_series.h"
#include "map_priv.h"
#include "map_replay.h"
#include "nuvo_range_lock.h"
#include "lun.h"
#include "resilience.h"
#include "map_free_lun.h"
#include "fault_inject.h"

#include <stdlib.h>

extern inline void  nuvo_map_writer_lock(struct nuvo_vol *vol);
extern inline void  nuvo_map_writer_unlock(struct nuvo_vol *vol);
extern inline uint64_t nuvo_map_get_block_at_index(uint_fast64_t base_offset,
                                                   uint_fast32_t index, uint_fast8_t level);

/**
 * @file map.h
 * @brief Implementation of the map.
 */

bool nuvo_validate_shadow(struct nuvo_map_track *map);

#define NUVO_MAP_INVALID_CP_GEN    (UINT64_MAX)

extern inline uint64_t nuvo_map_get_vol_cp(struct nuvo_vol *vol);

inline uint64_t nuvo_map_get_vol_cp(struct nuvo_vol *vol)
{
    return (vol->log_volume.map_state.checkpoint_gen);
}

struct nuvo_map *nuvo_map;

nuvo_return_t nuvo_map_init()
{
    return (nuvo_map_init_mem(NUVO_MAP_MEMORY_SIZE));
}

nuvo_return_t nuvo_map_init_mem(uint64_t map_size)
{
    nuvo_return_t          ret;
    struct nuvo_map_track *map;

    if (map_size < 2 * NUVO_MAP_WRITE_BATCH_SIZE * NUVO_MAP_WRITE_BATCHES * NUVO_BLOCK_SIZE)
    {
        // the map must have at least 2x the maps that could be pinned for cleaning
        ret = -NUVO_EINVAL;
        goto exit_check_size;
    }

    // alloc memory
    nuvo_map = malloc(sizeof(*nuvo_map));
    if (nuvo_map == NULL)
    {
        ret = -NUVO_ENOMEM;
        goto exit_map_alloc;
    }

    nuvo_map->map_table_count = map_size / sizeof(struct nuvo_map_table);
    nuvo_map->map_tracking = malloc(nuvo_map->map_table_count * sizeof(struct nuvo_map_track));

    if (nuvo_map->map_tracking == NULL)
    {
        ret = -NUVO_ENOMEM;
        goto exit_map_track_alloc;
    }

    uint_fast64_t map_alloc_size = nuvo_map->map_table_count * NUVO_BLOCK_SIZE;
    nuvo_map->map_tables = aligned_alloc(NUVO_BLOCK_SIZE, map_alloc_size);

    if (nuvo_map->map_tables == NULL)
    {
        ret = -NUVO_ENOMEM;
        goto exit_map_table_alloc;
    }

    ret = nuvo_mutex_init(&nuvo_map->list_mutex);
    if (ret < 0)
    {
        ret = -NUVO_ENOMEM;
        goto exit_list_mutex;
    }

    nuvo_dlist_init(&nuvo_map->mixed_lru_list);
    nuvo_dlist_init(&nuvo_map->clean_lru_list);
    nuvo_dlist_init(&nuvo_map->pinned_list);
    nuvo_dlist_init(&nuvo_map->alloc_list);
    nuvo_map->alloc_remaining = 0;

    nuvo_map->mixed_count = 0;
    nuvo_map->clean_count = 0;
    nuvo_map->pinned_count = 0;

    // put map tables on lru
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    uint_fast32_t table_index = 0;
    for (table_index = 0; table_index < nuvo_map->map_table_count; table_index++)
    {
        map = &nuvo_map->map_tracking[table_index];

        ret = nuvo_map_track_init(map);
        if (ret < 0)
        {
            nuvo_mutex_unlock(&nuvo_map->list_mutex);
            ret = -NUVO_ENOMEM;
            goto exit_tables;
        }
        map->parent = NULL;
        map->vol = NULL;
        map->lun = NULL;
        map->state = NUVO_MAP_CLEAN_LIST;
        nuvo_map_clean_insert_noalloc(map);
    }
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    return (0);

exit_tables:
    while ((map = nuvo_dlist_remove_head_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node)) != NULL)
    {
        nuvo_map_track_destroy(map);
    }
    nuvo_mutex_destroy(&nuvo_map->list_mutex);
exit_list_mutex:
    free(nuvo_map->map_tables);
exit_map_table_alloc:
    free(nuvo_map->map_tracking);
exit_map_track_alloc:
    free(nuvo_map);
exit_map_alloc:
exit_check_size:

    return (ret);
}

void nuvo_map_shutdown()
{
    struct nuvo_map_track *map;


    NUVO_ASSERT(nuvo_map->mixed_count == 0);
    NUVO_ASSERT(nuvo_map->pinned_count == 0);
    NUVO_ASSERT(nuvo_map->clean_count == (int)nuvo_map->map_table_count);

    uint_fast32_t table_index = 0;
    for (table_index = 0; table_index < nuvo_map->map_table_count; table_index++)
    {
        map = &nuvo_map->map_tracking[table_index];
        NUVO_ASSERT(map->state == NUVO_MAP_CLEAN_LIST);
        nuvo_map_track_destroy(map);
    }

    nuvo_mutex_destroy(&nuvo_map->list_mutex);
    free(nuvo_map->map_tables);
    free(nuvo_map->map_tracking);
    free(nuvo_map);
}

void nuvo_map_vol_state_init(struct nuvo_map_vol_state *vol_state, struct nuvo_vol *vol)
{
    vol_state->checkpoint_gen = 0;
    vol_state->flush_replay_count = 0;

    nuvo_map_writer_init(&vol_state->writer, vol);

    nuvo_dlist_init(&vol->map_replay_stash_list);
    vol->map_replay_stash_list_count = 0;
}

void nuvo_map_vol_state_destroy(struct nuvo_map_vol_state *vol_state)
{
    nuvo_map_writer_destroy(&vol_state->writer);
}

#define  NUVO_MAP_ASSERT_WRITER_MUTEX_HELD(vol)    do {                     \
        struct nuvo_map_writer *writer = &vol->log_volume.map_state.writer; \
        NUVO_ASSERT_MUTEX_HELD(&writer->writer_flush_mutex);                \
}   while (0);

void nuvo_map_writer_init(struct nuvo_map_writer *writer, struct nuvo_vol *vol)
{
    nuvo_return_t ret = nuvo_mutex_init(&writer->writer_flush_mutex);

    NUVO_ASSERT(ret == 0);

    writer->free_batch_count = NUVO_ARRAY_LENGTH(writer->batches);
    writer->write_count = 0;
    writer->batches_completed = 0;

    for (unsigned i = 0; i < NUVO_ARRAY_LENGTH(writer->batches); i++)
    {
        writer->batches[i].state = NUVO_MAP_BATCH_FREE;
        nuvo_dlist_init(&writer->batches[i].map_list);
        writer->batches[i].vol = vol;
    }

    nuvo_dlist_init(&writer->write_queue);
    nuvo_dlist_init(&writer->batch_comp_list);

    return;
}

void nuvo_map_writer_destroy(struct nuvo_map_writer *writer)
{
    NUVO_ASSERT(writer->free_batch_count == NUVO_ARRAY_LENGTH(writer->batches));
    NUVO_ASSERT(writer->write_count == 0);
}

void nuvo_map_writer_wait_batch_comp(struct nuvo_vol *vol, struct nuvo_map_writer_wait_req *req)
{
    NUVO_MAP_ASSERT_WRITER_MUTEX_HELD(vol);
    nuvo_dlist_insert_head(&vol->log_volume.map_state.writer.batch_comp_list, &req->list_node);
}

void nuvo_map_request_init(struct nuvo_map_request *req, struct nuvo_lun *lun, uint_fast64_t block_start, uint_fast32_t block_count)
{
    nuvo_dlist_init(&req->map_list);
    nuvo_dlnode_init(&req->list_node);
    NUVO_ASSERT(lun->snap_id);
    req->lun = lun;
    req->block_start = block_start;
    req->block_last = block_start + block_count - 1;
    req->first_map = NULL;
    req->last_map = NULL;
    req->target_level = 0;

    nuvo_mutex_lock(&lun->vol->mutex);
    req->snap_gen = lun->root_map->snap_gen;
    req->cp_commit_gen = NUVO_MAP_INVALID_CP_GEN;

    nuvo_mutex_unlock(&lun->vol->mutex);
    req->op = NUVO_MAP_REQUEST_OP_DEFAULT;
}

void map_request_free(struct nuvo_map_request *req, struct nuvo_dlist *comp_list)
{
    map_release_maps(&req->map_list, comp_list);
}

void map_release_maps(struct nuvo_dlist *map_list, struct nuvo_dlist *comp_list)
{
    // clean up anything left over on this req
    if (nuvo_dlist_get_head(map_list) != NULL)
    {
        struct nuvo_map_track *map;
        nuvo_mutex_lock(&nuvo_map->list_mutex);
        while ((map = nuvo_dlist_remove_head_object(map_list, struct nuvo_map_track, list_node)) != NULL)
        {
            nuvo_map_clean_insert_tail_noalloc(map);
        }
        // check if there are any waiting allocation requests that can be serviced
        if (comp_list)
        {
            nuvo_map_alloc_run_locked(comp_list);
        }
        nuvo_mutex_unlock(&nuvo_map->list_mutex);
    }
}

void nuvo_map_mixed_remove(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_MIXED_LIST);

    if (map->is_in_replay_stash_list && !nuvo_logger_is_running(&map->vol->log_volume.logger))
    {
        nuvo_map_replay_stash_list_remove(map);
        return;
    }

    NUVO_ASSERT(nuvo_map->mixed_count > 0);
    nuvo_map->mixed_count--;
    nuvo_dlist_remove(&map->list_node);
}

void nuvo_map_replay_stash_list_remove(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->vol->map_replay_stash_list_count > 0);
    map->vol->map_replay_stash_list_count--;
    map->is_in_replay_stash_list = 0;
    nuvo_dlist_remove(&map->list_node);
}

void nuvo_map_replay_stash_list_insert(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_MIXED_LIST);
    map->vol->map_replay_stash_list_count++;
    map->is_in_replay_stash_list = 1;
    nuvo_dlist_insert_head(&map->vol->map_replay_stash_list, &map->list_node);
}

void nuvo_map_clean_remove(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_CLEAN_LIST);

    NUVO_ASSERT(nuvo_map->clean_count > 0);
    nuvo_map->clean_count--;
    nuvo_dlist_remove(&map->list_node);

    nuvo_map_balance_lists();
}

void nuvo_map_pinned_remove(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_PINNED);

    NUVO_ASSERT(nuvo_map->pinned_count > 0);
    nuvo_map->pinned_count--;
    nuvo_dlist_remove(&map->list_node);
}

bool nuvo_map_mixed_insert_noalloc(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_MIXED_LIST);

    //All mixed inserts during replay go to the per volume stash list.
    // We used to check for dirty here because we only cared about dirty maps
    //not going into the mixed list as they werent flushable and not reusable.
    //However map code takes the map lock, releases the pincounts
    // and then sets the dirty. This would cause us to miss some of the dirty ones.
    // Since all replay does is write ops, we can expect all L0 maps to be dirty

    if (!nuvo_logger_is_running(&map->vol->log_volume.logger))
    {
        NUVO_ASSERT(map->is_dirty);
        nuvo_map_replay_stash_list_insert(map);
        return (false);
    }

    nuvo_map->mixed_count++;
    NUVO_ASSERT(nuvo_map->mixed_count <= (int_fast32_t)nuvo_map->map_table_count);
    nuvo_dlist_insert_head(&nuvo_map->mixed_lru_list, &map->list_node);
    nuvo_map_balance_lists();
    return (true);
}

void nuvo_map_mixed_insert(struct nuvo_map_track *map, struct nuvo_dlist *comp_list)
{
    if (nuvo_map_mixed_insert_noalloc(map))
    {
        nuvo_map_alloc_run_locked(comp_list);
    }
}

void map_clean_reset(struct nuvo_map_track *map)
{
    map->is_in_replay_stash_list = 0;
    map->mfl = 0;
}

void nuvo_map_clean_insert_noalloc(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_CLEAN_LIST);

    map->is_in_replay_stash_list = 0;

    nuvo_map->clean_count++;
    NUVO_ASSERT(nuvo_map->clean_count <= (int_fast32_t)nuvo_map->map_table_count);
    nuvo_dlist_insert_head(&nuvo_map->clean_lru_list, &map->list_node);
}

void nuvo_map_clean_insert_tail_noalloc(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_CLEAN_LIST);
    NUVO_ASSERT(map->shadow_link == NULL);
    // reset the maps that are in stashed replay list
    // that are left over in the global mixed lru list
    // so that all maps are clean before the next replay
    map->is_in_replay_stash_list = 0;

    nuvo_map->clean_count++;
    NUVO_ASSERT(nuvo_map->clean_count <= (int_fast32_t)nuvo_map->map_table_count);
    nuvo_dlist_insert_tail(&nuvo_map->clean_lru_list, &map->list_node);
}

void nuvo_map_clean_insert_tail(struct nuvo_map_track *map, struct nuvo_dlist *comp_list)
{
    nuvo_map_clean_insert_tail_noalloc(map);
    nuvo_map_alloc_run_locked(comp_list);
}

void nuvo_map_pinned_insert(struct nuvo_map_track *map)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_PINNED || map->state == NUVO_MAP_SHADOW);

    nuvo_map->pinned_count++;
    NUVO_ASSERT(nuvo_map->pinned_count <= (int_fast32_t)nuvo_map->map_table_count);
    nuvo_dlist_insert_head(&nuvo_map->pinned_list, &map->list_node);
}

nuvo_return_t nuvo_map_track_init(struct nuvo_map_track *map)
{
    nuvo_return_t ret;
    uint_fast32_t index = map - nuvo_map->map_tracking;

    NUVO_ASSERT(index < nuvo_map->map_table_count);

    map->entries = nuvo_map->map_tables[index].entries;

    ret = nuvo_mutex_init(&map->mutex);
    if (ret < 0)
    {
        return (-NUVO_ENOMEM);
    }

    nuvo_dlist_init(&map->wait_list);
    nuvo_dlnode_init(&map->list_node);

    map->is_dirty = 0;
    map->child_count = 0;
    map->is_new_entry = 0;
    map->shadow_link = NULL;
    map->pinned = 0;
    map->level = -1;
    map->snap_gen = 0;
    map->mfl = false;
    map->cleaning_shadow = 0;

    // maps without a LUN are free
    map->lun = NULL;
    map->vol = NULL;
    map->parent = NULL;

    return (0);
}

void nuvo_map_track_destroy(struct nuvo_map_track *map)
{
    map->lun = NULL;
    map->vol = NULL;
    map->parent = NULL;
    nuvo_mutex_destroy(&map->mutex);
}

static struct test_fi_info map_fi_info;

struct test_fi_info *nuvo_map_get_test_fi()
{
    return (&map_fi_info);
}

void map_inject_fi_panic(struct nuvo_map_track *map)
{
    nuvo_return_t err = -5;

    if (map->lun->snap_id == map_fi_info.multiuse1 &&
        map->base_offset == map_fi_info.multiuse2 &&
        !map->level && map->mfl && map->lun->mfl_state &&
        test_fi_inject_rc(TEST_FI_MAP_MFL_ERR, &map_fi_info, &err))
    {
        NUVO_LOG(map, 0, "map fi panic hit  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) "
                 "offset:%lu level:%d map->is_dirty:%d lun(%d)",
                 map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                 map->map_entry.media_addr.block_offset,
                 map->base_offset, map->level, map->is_dirty, map->lun->snap_id);

        NUVO_ASSERT(0);
    }
}

// if this is a shadow of an intermediate table, we
//  walk through the live map's children and update
//  their is_new_entry fields
//  written are not false positives for being written out again

void map_reset_new_entries(struct nuvo_map_track *shadow_map, struct nuvo_map_track *live_map)
{
    NUVO_ASSERT_MUTEX_HELD(&live_map->mutex);

    NUVO_ASSERT(live_map->level);              //intermediate maps only
    NUVO_ASSERT(shadow_map->state == NUVO_MAP_SHADOW);
    NUVO_ASSERT(shadow_map->child_count == 0); // we just wrote this map out

    for (unsigned int i = 0; i < NUVO_MAP_RADIX; i++)
    {
        if (live_map->entries[i].type == NUVO_ME_IN_MEM)
        {
            struct nuvo_map_track  *child_map = live_map->entries[i].ptr;
            struct nuvo_media_addr *shadow_child_media_addr = &shadow_map->entries[i].media_addr;

            nuvo_mutex_lock(&child_map->mutex);

            // check the addresses so that we dont race with a new cleaning lower level map
            //
            if (NUVO_MEDIA_ADDR_EQUAL(&child_map->map_entry.media_addr, shadow_child_media_addr))
            {
                child_map->is_new_entry = 0;
            }
            nuvo_mutex_unlock(&child_map->mutex);
        }
    }
}

void nuvo_map_writer_flush_cb(struct nuvo_log_request *log_req)
{
    struct nuvo_dlist     comp_list;
    struct nuvo_map_entry old_entries[NUVO_ARRAY_LENGTH(log_req->nuvo_map_entries)];

    nuvo_dlist_init(&comp_list);
    struct nuvo_vol *vol = log_req->vs_ptr;
    // writing of the map tables has completed, possibly successfully
    // we need to update the media addresses for the tables written out
    // if they have been shadowed, update the media address, unpin shadow page,
    // and free original map

    // TODO: we need to have a way to shutdown a particular volume if it has
    //      errors while leaving the rest running
    if (log_req->status < 0)
    {
        NUVO_PANIC("Map writer's segment logger request failed.");
    }

    // get reference to this batch
    struct nuvo_map_writer_batch *batch = (struct nuvo_map_writer_batch *)log_req->tag.ptr;

    // mark blocks in segment usage table
    // Calling "use" blocks for mfl-ed map  should be ok, since the mfl addrs are not media addrs but constants
    // and "use" blocks for consts are no ops
    nuvo_mfst_segment_use_blks(&batch->vol->log_volume.mfst, log_req->block_count, log_req->nuvo_map_entries);

    // get first map
    struct nuvo_map_track *map;
    uint_fast32_t          map_index = 0;


    while ((map = nuvo_dlist_remove_head_object(&batch->map_list, struct nuvo_map_track, list_node)) != NULL)
    {
        nuvo_mutex_lock(&vol->mutex);
        nuvo_mutex_lock(&map->mutex);

        NUVO_LOG_COND(map, 30, (!map->base_offset && NUVO_LUN_IS_ACTIVE(map->lun)),
                      "MAP FLUSH cb map:%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) -> new media_addr(%lu:%lu)"
                      " offset:%lu level:%d map->is_dirty:%d lun(%d) lun_state:%d lun_mfl_state:%d vol:%p",
                      map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                      map->map_entry.media_addr.block_offset,
                      log_req->nuvo_map_entries[map_index].media_addr.parcel_index,
                      log_req->nuvo_map_entries[map_index].media_addr.block_offset,
                      map->base_offset, map->level, map->is_dirty,
                      map->lun->snap_id, map->lun->lun_state, map->lun->mfl_state, map->lun->vol);
        map_inject_fi_panic(map);

        // see if it is shadowed or not
        if (map->state == NUVO_MAP_SHADOW)
        {
            struct nuvo_map_track *live_map;
            live_map = map->shadow_link;
            nuvo_mutex_lock(&live_map->mutex);

            // save old map entry for freeing later
            // MFL this could be used to the free old
            old_entries[map_index] = map->map_entry;

            // Dont lose the cow bit of the live map
            log_req->nuvo_map_entries[map_index].cow = map->map_entry.cow;
            map->map_entry = log_req->nuvo_map_entries[map_index];

            if (map->mfl)
            {
                NUVO_LOG(map, 80, "map mfl is true :%p level:%d shadow_link:%p base_offset:%lu", map, map->level, map->shadow_link, map->base_offset);
                struct nuvo_map_entry *me = &log_req->nuvo_map_entries[map_index];
                NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(me)); // assert that logger gave us a zero address

                // cant assert that live map is clean as the live (intermediate) map can have evictions
                // while we were writing out // causing it to de dirty
                // NUVO_ASSERT(!live_map->is_dirty); //no more updates after mfl, please.
            }
            // all the cow an map entry update is now handled in map_entry_update */
            map_entry_update(map, live_map);

            // update the lun mfl state to DONE when the root map block is written out
            struct nuvo_lun *lun = live_map->lun;
            if (live_map == lun->root_map)
            {
                lun->root_map_entry = live_map->map_entry;
                if (lun->mfl_state == NUVO_LUN_MFL_CP_IN_PROGRESS)
                {
                    NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&lun->root_map_entry));
                    lun->mfl_state = NUVO_LUN_MFL_CP_DONE;
                }
            }

            map->is_new_entry = 1;
            live_map->is_new_entry = 1;

            // propagate map entry upward
            // only if the shadow originated in this cp.
            // We could have intersecting cleaning shadows from last CP
            // We shouldnt make these addresses part of the map tree as they could
            // have later writes that need to be part of CP.
            // Not propagating upwards help this map still be in the tree and be considered for CP
            // again.
            // This should fix CUM-2460 and the intersecting cleaning shadow problems for L0 maps

            bool shadow_in_this_cp = false;
            if (live_map->cp_gen == nuvo_map_get_vol_cp(vol))
            {
                shadow_in_this_cp = true;
            }
            else
            {
                // It is necessary that this is cleaning shadow, but not sufficient
                // as cleaning shadows could originate in this CP as well.
                NUVO_ASSERT(map->cleaning_shadow);

                // live map cp gen cant be greater than the volume CP.
                NUVO_DEBUG_ASSERT((live_map->cp_gen < nuvo_map_get_vol_cp(vol)),
                                  "map cp_gen:%u vol cp:%u map:%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) "
                                  " offset:%lu level:%d map->is_dirty:%d lun(%d) vol:%p",
                                  live_map->cp_gen, nuvo_map_get_vol_cp(vol),
                                  live_map->cp_gen, live_map, live_map->state, live_map->shadow_link,
                                  live_map->mfl, live_map->map_entry.media_addr.parcel_index,
                                  live_map->map_entry.media_addr.block_offset,
                                  live_map->base_offset, live_map->level, live_map->lun->snap_id, live_map->vol);
            }

            // if this is a shadow of an intermediate table, we run
            // through the live map's children and update
            // their is_new_entry fields so those who match what was
            // written are not false positives for being written out again
            if (map->level && shadow_in_this_cp)
            {
                map_reset_new_entries(map, live_map);
            }

            nuvo_mutex_unlock(&live_map->mutex);

            if (shadow_in_this_cp && (map->parent != NULL))
            {
                // get parent lock to check for shadow and unpin for this shadow
                nuvo_mutex_lock(&map->parent->mutex);
                if (map->parent->shadow_link != NULL &&
                    map->parent->shadow_link->cp_gen == map->cp_gen)
                {
                    struct nuvo_map_track *parent_shadow = map->parent->shadow_link;
                    nuvo_mutex_lock(&parent_shadow->mutex);
                    nuvo_mutex_unlock(&map->parent->mutex);
                    NUVO_ASSERT(map->is_new_entry);
                    // update the parent shadow, parent will be delayed updated

                    // if this map got NONE in active or COW in snapshot
                    // lets update the parent to NONE/COW
                    // if parent shadow has no children, queue it for write out
                    if (!map_parent_entry_update_nl(map, parent_shadow))
                    {
                        // TODO: generally we should drop all locks when
                        // calling functions that can call callbacks, but we've
                        // also removed all ways to reach the shadow map we're
                        // cleaning up...
                        nuvo_map_writer_add_map(parent_shadow, NUVO_MW_FLUSH_AUTO);
                    }
                    else
                    {
                        nuvo_mutex_unlock(&parent_shadow->mutex);
                    }
                }
                else
                {
                    nuvo_mutex_unlock(&map->parent->mutex);
                }
            }

            // map should not be used by anyone else, make sure of it
            nuvo_mutex_lock(&live_map->mutex);
            //note that live map->shadow cord is cut during the last unpin of
            // the shadow in nuvo_map_shadow_unpin_table below.
            nuvo_map_shadow_unpin_table(map, NULL);
            nuvo_mutex_unlock(&live_map->mutex);
        }
        else if (map->state == NUVO_MAP_CLEANING)
        {
            // map is not shadowed, just update the map

            // save old map entry for freeing later
            old_entries[map_index] = map->map_entry;

            // lets not lose the cow bit in memory
            log_req->nuvo_map_entries[map_index].cow = map->map_entry.cow;
            map->map_entry = log_req->nuvo_map_entries[map_index];
            //just keeping the lun root_map_entry updated.
            // not very used , but useful in UTs/debugging.
            if (map == map->lun->root_map)
            {
                map->lun->root_map_entry = map->map_entry;
            }

            map->is_new_entry = 1;

            NUVO_LOG_COND(map, 80, (!map->base_offset), "CLEANING cb map :%p offset:%d mfl:%d level:%d parent:%p lun(%d)",
                          map, map->base_offset, map->mfl, map->level, map->parent, map->lun->snap_id);

            // assert that we got a zero map entry for an mfled map
            NUVO_ASSERT(!map->mfl || (NUVO_ME_IS_MFL_DONE(&log_req->nuvo_map_entries[map_index])));

            // we need to unpin the map, but if it ends up being completely
            // unpinned, we want to put it on the top of the clean list
            map->is_dirty = 0; // we just cleaned it
            if (--map->pinned == 0)
            {
                map->state = NUVO_MAP_CLEAN_LIST;
                nuvo_mutex_lock(&nuvo_map->list_mutex);
                nuvo_map_clean_insert_noalloc(map);
                nuvo_mutex_unlock(&nuvo_map->list_mutex);
            }
            else
            {
                map->state = NUVO_MAP_PINNED;
                nuvo_mutex_lock(&nuvo_map->list_mutex);
                nuvo_map_pinned_insert(map);
                nuvo_mutex_unlock(&nuvo_map->list_mutex);
            }
        }
        else
        {
            NUVO_PANIC("Cleaned map is in an incorrect state after cleaning!");
        }
        nuvo_mutex_unlock(&map->mutex);
        nuvo_mutex_unlock(&vol->mutex);
        map_index++;
    }
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_alloc_run_locked(&comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    NUVO_ASSERT(map_index == log_req->block_count);

    // free the maps we are no longer using
    nuvo_mfst_segment_free_blks(&batch->vol->log_volume.mfst, map_index, old_entries);

    // let the logger know we're done updating the map
    nuvo_log_ack_sno(log_req);

    // free the batch
    nuvo_map_writer_lock(batch->vol);

    struct nuvo_dlist wait_comp_list;
    nuvo_dlist_init(&wait_comp_list);
    struct nuvo_map_writer *writer = &batch->vol->log_volume.map_state.writer;
    batch->state = NUVO_MAP_BATCH_FREE;
    writer->free_batch_count++;

    nuvo_dlist_insert_list_head(&wait_comp_list, &writer->batch_comp_list);

    writer->batches_completed++;

    // check if the write queue is deep enough for a full batch
    if (writer->write_count >= NUVO_MAP_WRITE_BATCH_SIZE)
    {
        // start another write out
        nuvo_map_writer_flush(batch->vol);
    }
    else
    {
        nuvo_map_writer_unlock(batch->vol);
    }

    // run callbacks on any completed requests
    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }

    struct nuvo_map_writer_wait_req *wait_comp_req;
    while ((wait_comp_req = nuvo_dlist_remove_head_object(&wait_comp_list, struct nuvo_map_writer_wait_req, list_node)) != NULL)
    {
        wait_comp_req->callback(wait_comp_req);
    }
}

// flush the dirty maps previously added with "nuvo_map_writer_add_map"
// Note: must not hold vol mutex
// and must hold map writer mutex
// the function would release map writer mutex on return
//

void nuvo_map_writer_flush(struct nuvo_vol *vol)
{
    NUVO_MAP_ASSERT_WRITER_MUTEX_HELD(vol);
    // if there are any maps queued onto the write queue, write them
    // out via the logger

    struct nuvo_map_writer *writer = &vol->log_volume.map_state.writer;
    if (writer->write_count == 0)
    {
        nuvo_map_writer_unlock(vol);
        return;
    }
    // if we are out of free batches return
    // the consumers will do a flush as and when new batches are available
    // we also do a flush in the map flush callback when new batches are available.
    // Also read CUM-1108

    if (!writer->free_batch_count)
    {
        nuvo_map_writer_unlock(vol);
        return;
    }

    // find a free batch
    struct nuvo_map_writer_batch *batch;
    for (uint_fast32_t i = 0; i < NUVO_MAP_WRITE_BATCHES; i++)
    {
        if (writer->batches[i].state == NUVO_MAP_BATCH_FREE)
        {
            batch = &writer->batches[i];
            break;
        }
    }

    // double check that the batch list is empty
    NUVO_ASSERT(nuvo_dlist_get_head(&batch->map_list) == NULL);

    // fill out the log request
    struct nuvo_log_request *log_req = &batch->log_req;

    // populate the map list
    struct nuvo_map_track *map;
    log_req->block_count = 0;
    while ((map = nuvo_dlist_remove_head_object(&writer->write_queue, struct nuvo_map_track, list_node)) != NULL)
    {
        writer->write_count--;
        nuvo_dlist_insert_tail(&batch->map_list, &map->list_node);
        log_req->log_io_blocks[log_req->block_count].map_is_zero = false;

        if (map->mfl)
        {
            log_req->log_io_blocks[log_req->block_count].map_is_zero = true;
        }

        NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(map->lun) && !map->base_offset), "SUBMIT MAP TO LOGGER  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                      map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                      map->map_entry.media_addr.block_offset,
                      map->base_offset, map->level, map->is_dirty);



        log_req->log_io_blocks[log_req->block_count].data = map->entries;
        log_req->log_io_blocks[log_req->block_count].log_entry_type = NUVO_LE_MAP_L0 + map->level;
        LOG_PIT_INFO_SET_MAP(log_req->log_io_blocks[log_req->block_count].pit_info, map->lun->snap_id);

        log_req->log_io_blocks[log_req->block_count].bno = map->base_offset;
        log_req->block_count++;
        // break out if we hit the max per batch
        if (log_req->block_count == NUVO_MAP_WRITE_BATCH_SIZE)
        {
            break;
        }
    }

    log_req->operation = NUVO_LOG_OP_MAP;
    log_req->atomic = false;
    log_req->data_class = NUVO_DATA_CLASS_A; // TODO: need to determine map's media class policy
    log_req->tag.ptr = batch;
    log_req->vs_ptr = vol;
    log_req->callback = nuvo_map_writer_flush_cb;

    batch->state = NUVO_MAP_BATCH_WRITING;
    batch->vol = vol;
    writer->free_batch_count--;

    // submit
    nuvo_map_writer_unlock(vol);
    nuvo_log_submit(log_req);
}

/* Documented in header */

void nuvo_map_try_flush(struct nuvo_vol *vol)
{
    nuvo_map_writer_lock(vol);
    struct nuvo_map_writer *writer = &vol->log_volume.map_state.writer;
    while (writer->write_count >= NUVO_MAP_WRITE_BATCH_SIZE &&
           writer->free_batch_count > 0)
    {
        nuvo_map_writer_flush(vol);
        nuvo_map_writer_lock(vol);
    }
    nuvo_map_writer_unlock(vol);
}

// Add a dirty map to the flusher writer queue

// Note: must hold vol mutex
// and must not hold map writer mutex
// the function would release map writer mutex on return
//
void nuvo_map_writer_add_map(struct nuvo_map_track          *map,
                             enum nuvo_map_writer_flush_mode flush)
{
    struct nuvo_vol *vol = map->vol;

    NUVO_ASSERT_MUTEX_HELD(&map->mutex);

    struct nuvo_map_writer *writer = &vol->log_volume.map_state.writer;
    NUVO_ASSERT_MUTEX_NOT_HELD_BYME(&writer->writer_flush_mutex);

    nuvo_map_writer_lock(vol);

    map->pinned++;
    nuvo_dlist_insert_tail(&writer->write_queue, &map->list_node);
    writer->write_count++;

    nuvo_mutex_unlock(&map->mutex);
    if (flush == NUVO_MW_FLUSH_FORCE ||
        (flush == NUVO_MW_FLUSH_AUTO && writer->write_count >= NUVO_MAP_WRITE_BATCH_SIZE))
    {
        // we've filled up the batch, flush it
        nuvo_map_writer_flush(vol);
    }
    else
    {
        nuvo_map_writer_unlock(vol);
    }
}

uint_fast32_t nuvo_map_get_table_index(uint_fast64_t block_num, uint_fast8_t level)
{
    return ((block_num >> (level * NUVO_MAP_RADIX_BITS)) & ((1ull << NUVO_MAP_RADIX_BITS) - 1ull));
}

uint_fast64_t nuvo_map_get_base_offset(uint_fast64_t block_num, uint_fast8_t level)
{
    return (block_num & ~((1ull << (NUVO_MAP_RADIX_BITS * (level + 1))) - 1ull));
}

void nuvo_map_balance_lists()
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);

    // do we need to balance the lists?
    if (nuvo_map->clean_count < nuvo_map->mixed_count)
    {
        struct nuvo_vol *vol_list[NUVO_MAP_WRITE_BATCH_SIZE];
        uint_fast32_t    vol_list_used = 0;

        // in general
        // if clean_count < mixed_count
        //      pull from mixed list, clean, put on clean list

        uint_fast32_t          dirty_maps_cleaned = 0;
        uint_fast32_t          clean_maps_moved = 0;
        struct nuvo_map_track *cur_map = nuvo_dlist_get_tail_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);
        while (dirty_maps_cleaned < NUVO_MAP_WRITE_BATCH_SIZE &&
               clean_maps_moved < NUVO_MAP_BALANCE_MAPS_MAX &&
               cur_map != NULL)
        {
            if (nuvo_mutex_trylock(&cur_map->mutex) == 0)
            {
                cur_map = nuvo_dlist_get_prev_object(&nuvo_map->mixed_lru_list, cur_map, struct nuvo_map_track, list_node);
                continue;
            }
            NUVO_ASSERT(cur_map->state == NUVO_MAP_MIXED_LIST);

            NUVO_ASSERT(cur_map->child_count == 0);

            // check if dirty
            if (cur_map->is_dirty)
            {
                // try to lock the vol
                if (nuvo_mutex_trylock(&cur_map->vol->mutex) == 0)
                {
                    nuvo_mutex_unlock(&cur_map->mutex);
                    cur_map = nuvo_dlist_get_prev_object(&nuvo_map->mixed_lru_list, cur_map, struct nuvo_map_track, list_node);
                    continue;
                }

                if (!nuvo_logger_is_running(&cur_map->vol->log_volume.logger))
                {
                    // logger is not running possibly in replay , we cant flush this dirty map
                    cur_map->vol->log_volume.map_state.flush_replay_count++;
                    nuvo_mutex_unlock(&cur_map->vol->mutex);
                    nuvo_mutex_unlock(&cur_map->mutex);
                    cur_map = nuvo_dlist_get_prev_object(&nuvo_map->mixed_lru_list, cur_map, struct nuvo_map_track, list_node);
                    continue;
                }

                // check if the lun has available batch slots
                if (cur_map->vol->log_volume.map_state.writer.free_batch_count == 0)
                {
                    // the vol does not have any open slots
                    // move onto the next map in list
                    nuvo_mutex_unlock(&cur_map->vol->mutex);
                    nuvo_mutex_unlock(&cur_map->mutex);
                    cur_map = nuvo_dlist_get_prev_object(&nuvo_map->mixed_lru_list, cur_map, struct nuvo_map_track, list_node);
                    continue;
                }

                // try to lock the parent
                if (nuvo_mutex_trylock(&cur_map->parent->mutex) == 0)
                {
                    // move on to next map in list
                    nuvo_mutex_unlock(&cur_map->vol->mutex);
                    nuvo_mutex_unlock(&cur_map->mutex);
                    cur_map = nuvo_dlist_get_prev_object(&nuvo_map->mixed_lru_list, cur_map, struct nuvo_map_track, list_node);
                    continue;
                }

                // parent and vol are locked
                // queue up this map to be cleaned
                nuvo_map_mixed_remove(cur_map);
                cur_map->state = NUVO_MAP_CLEANING;
                struct nuvo_vol *vol = cur_map->vol;
                nuvo_mutex_unlock(&nuvo_map->list_mutex);

                NUVO_LUN_STAT_DIRTY_COUNT(cur_map->lun);

                {
                    struct nuvo_map_track *map = cur_map;
                    NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(map->lun) && !map->base_offset), "BALANCE LIST CLEAN map to logger  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                                  map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                                  map->map_entry.media_addr.block_offset,
                                  map->base_offset, map->level, map->is_dirty);
                }

                nuvo_map_writer_add_map(cur_map, NUVO_MW_FLUSH_AUTO);
                nuvo_mutex_unlock(&cur_map->parent->mutex);
                nuvo_mutex_unlock(&vol->mutex);
                nuvo_mutex_lock(&nuvo_map->list_mutex);
                dirty_maps_cleaned++;

                // add the vol to our vol list if it isn't on there already
                bool vol_found = false;
                for (unsigned i = 0; i < vol_list_used; i++)
                {
                    if (vol_list[i] == cur_map->vol)
                    {
                        // we have the vol already
                        vol_found = true;
                        break;
                    }
                }
                if (!vol_found)
                {
                    // vol was not in the list, so we must add it
                    vol_list[vol_list_used] = cur_map->vol;
                    vol_list_used++;
                }

                cur_map = nuvo_dlist_get_tail_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);
            }
            else
            {
                // TODO: check for checkpoints/parent shadow

                // move to clean list
                nuvo_map_mixed_remove(cur_map);
                cur_map->state = NUVO_MAP_CLEAN_LIST;
                nuvo_map_clean_insert_noalloc(cur_map);

                nuvo_mutex_unlock(&cur_map->mutex);
                cur_map = nuvo_dlist_get_tail_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);

                clean_maps_moved++;
            }
        }
        // submit any queued up writer maps
        if (vol_list_used != 0)
        {
            nuvo_mutex_unlock(&nuvo_map->list_mutex);
            for (unsigned i = 0; i < vol_list_used; i++)
            {
                nuvo_map_writer_lock(vol_list[i]);
                nuvo_map_writer_flush(vol_list[i]);
            }
            nuvo_mutex_lock(&nuvo_map->list_mutex);
        }
    }
}

void nuvo_map_pin_table(struct nuvo_map_track *table)
{
    NUVO_ASSERT_MUTEX_HELD(&table->mutex);

    if (table->pinned++ == 0)
    {
        NUVO_ASSERT(table->state == NUVO_MAP_MIXED_LIST || table->state == NUVO_MAP_CLEAN_LIST);
        // remove from LRU list and put onto pinned list
        nuvo_mutex_lock(&nuvo_map->list_mutex);

        if (table->state == NUVO_MAP_MIXED_LIST)
        {
            nuvo_map_mixed_remove(table);
        }
        else
        {
            nuvo_map_clean_remove(table);
        }

        table->state = NUVO_MAP_PINNED;
        nuvo_map_pinned_insert(table);

        nuvo_mutex_unlock(&nuvo_map->list_mutex);
    }
}

void nuvo_map_shadow_unpin_table(struct nuvo_map_track *table, struct nuvo_dlist *comp_list)
{
    NUVO_ASSERT_MUTEX_HELD(&table->mutex); // need lock on the shadow
    NUVO_ASSERT(table->state == NUVO_MAP_SHADOW);
    struct nuvo_map_track *map_primary = table->shadow_link;
    NUVO_ASSERT_MUTEX_HELD(&map_primary->mutex); // need lock on the live map

    // no chain shadows, the shadow_links must mutually point to each other
    NUVO_ASSERT(map_primary->shadow_link == table);

    //no one should know or have pincounts on CP shadows.
    //so assert
    if (!table->cleaning_shadow)
    {
        NUVO_ASSERT(table->pinned == 1);
    }

    if (--table->pinned == 0)
    {
        NUVO_ASSERT(table->child_count == 0);
        table->lun = NULL;
        table->vol = NULL;
        table->parent = NULL;
        table->pinned = 0;
        table->state = NUVO_MAP_CLEAN_LIST;
        table->shadow_link = NULL;
        table->is_dirty = 0; //since shadows can be dirty now
        table->cleaning_shadow = 0;

        nuvo_mutex_lock(&nuvo_map->list_mutex);

        if (comp_list)
        {
            nuvo_map_clean_insert_tail(table, comp_list);
        }
        else
        {
            nuvo_map_clean_insert_tail_noalloc(table);
        }

        map_primary->shadow_link = NULL;
        nuvo_map_unpin_table_locked(map_primary);
        nuvo_mutex_unlock(&nuvo_map->list_mutex);
    }
}

void nuvo_map_unpin_table(struct nuvo_map_track *table, struct nuvo_dlist *comp_list)
{
    NUVO_ASSERT_MUTEX_HELD(&table->mutex);
    NUVO_ASSERT(table->pinned > 0);

    if (--table->pinned == 0)
    {
        NUVO_ASSERT(table->state == NUVO_MAP_PINNED);
        // remove from pinned list and put onto LRU list
        nuvo_mutex_lock(&nuvo_map->list_mutex);
        nuvo_map_pinned_remove(table);

        if (!table->is_dirty && !nuvo_logger_is_running(&table->vol->log_volume.logger))
        {
            table->state = NUVO_MAP_CLEAN_LIST;
            nuvo_map_clean_insert_tail(table, comp_list);
        }
        else
        {
            table->state = NUVO_MAP_MIXED_LIST;
            nuvo_map_mixed_insert(table, comp_list);
        }

        nuvo_mutex_unlock(&nuvo_map->list_mutex);
    }
}

void nuvo_map_unpin_table_locked(struct nuvo_map_track *table)
{
    NUVO_ASSERT_MUTEX_HELD(&table->mutex);
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT(table->pinned > 0);

    if (--table->pinned == 0)
    {
        NUVO_ASSERT(table->state == NUVO_MAP_PINNED);
        // remove from pinned list and put onto LRU list
        nuvo_map_pinned_remove(table);

        if (!table->is_dirty && !nuvo_logger_is_running(&table->vol->log_volume.logger))
        {
            table->state = NUVO_MAP_CLEAN_LIST;
            nuvo_map_clean_insert_noalloc(table);
        }
        else
        {
            table->state = NUVO_MAP_MIXED_LIST;
            nuvo_map_mixed_insert_noalloc(table);
        }
    }
}

bool nuvo_map_evict_table(struct nuvo_map_track *table)
{
    bool ret = true;

    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    NUVO_ASSERT_MUTEX_HELD(&table->mutex);

    NUVO_ASSERT(table->is_dirty == 0);

    if (table->parent != NULL)
    {
        struct nuvo_map_track *parent = table->parent;
        NUVO_ASSERT_MUTEX_HELD(&parent->mutex);
        uint_fast32_t parent_index = nuvo_map_get_table_index(table->base_offset, parent->level);
        NUVO_ASSERT(parent->entries[parent_index].ptr == table);

        struct nuvo_map_track *map = table;

        NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(map->lun) && !map->base_offset), "EVICT map to logger  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                      map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                      map->map_entry.media_addr.block_offset,
                      map->base_offset, map->level, map->is_dirty);


        map_parent_entry_update_nl(table, parent);

        // CUM 1073 Eviction must remove the map entry from the parent shadow as well if one exists,
        // The evicted map entry is stale and cause potential corruptions and hangs on CP.
        if (parent->shadow_link)
        {
            NUVO_ASSERT_MUTEX_HELD(&parent->shadow_link->mutex);
            if (parent->shadow_link->entries[parent_index].ptr == table)
            {
                // if this is the last child unlinked from the parent shadow
                // write out the parent shadow
                if (!map_parent_entry_update_nl(table, parent->shadow_link))
                {
                    nuvo_map_writer_add_map(parent->shadow_link, NUVO_MW_FLUSH_AUTO);
                    // tell the caller that we lost the lock
                    ret = false;
                }
            }
        }

        nuvo_map_unpin_table_locked(table->parent);
        table->parent = NULL;
    }


    NUVO_ASSERT(table->shadow_link == NULL);

    // move to the end of the clean list
    if (table->state == NUVO_MAP_MIXED_LIST)
    {
        nuvo_map_mixed_remove(table);
    }
    else if (table->state == NUVO_MAP_CLEAN_LIST)
    {
        nuvo_map_clean_remove(table);
    }
    else
    {
        NUVO_PANIC("Map being evicted is in an incorrect state.");
    }

    table->lun = NULL;
    table->vol = NULL;
    table->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_tail_noalloc(table);
    return (ret);
}

void nuvo_map_alloc_run()
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_alloc_run_locked(&comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    struct nuvo_map_alloc_req *req;
    while ((req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        req->callback(req);
    }
}

void nuvo_map_alloc_run_locked(struct nuvo_dlist *comp_list)
{
    NUVO_ASSERT_MUTEX_HELD(&nuvo_map->list_mutex);
    struct nuvo_map_track     *cur_map = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    struct nuvo_map_alloc_req *alloc_req;

    // The alloc_req is removed from the list while it's actively being worked on. This is done because
    // it's possible the nuvo_map->list_mutex is released if a map is evicted which may call nuvo_map_balance_lists.
    // If the request can't be completely filled it's put back on the alloc_list.
    while ((alloc_req = nuvo_dlist_remove_head_object(&nuvo_map->alloc_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        while (alloc_req->count > 0 && cur_map != NULL)
        {
            // try current table
            if (nuvo_mutex_trylock(&cur_map->mutex) == 0)
            {
                // failed, move onto the next table
                cur_map = nuvo_dlist_get_prev_object(&nuvo_map->clean_lru_list, cur_map, struct nuvo_map_track, list_node);
                continue;
            }

            NUVO_ASSERT(!cur_map->is_dirty); // clean list must have only clean maps
            // check if map has a parent
            if (cur_map->parent != NULL)
            {
                struct nuvo_map_track *parent_table = (struct nuvo_map_track *)cur_map->parent;
                // try to lock the parent
                if (nuvo_mutex_trylock(&parent_table->mutex) == 0)
                {
                    // failed parent, move onto the next table
                    nuvo_mutex_unlock(&cur_map->mutex);
                    struct nuvo_map_track *next_map = nuvo_dlist_get_prev_object(&nuvo_map->clean_lru_list, cur_map, struct nuvo_map_track, list_node);
                    cur_map = next_map;
                    continue;
                }
                NUVO_ASSERT(parent_table->lun == cur_map->lun);

                if (parent_table->shadow_link)
                {
                    NUVO_ASSERT(parent_table->shadow_link->lun == cur_map->lun);

                    if (nuvo_mutex_trylock(&parent_table->shadow_link->mutex) == 0)
                    {
                        nuvo_mutex_unlock(&cur_map->mutex);
                        nuvo_mutex_unlock(&parent_table->mutex);
                        struct nuvo_map_track *next_map = nuvo_dlist_get_prev_object(&nuvo_map->clean_lru_list, cur_map, struct nuvo_map_track, list_node);
                        cur_map = next_map;
                        continue;
                    }
                }

                // both tables locked, evict this map
                bool ret = nuvo_map_evict_table(cur_map);
                if (ret && parent_table->shadow_link)
                {
                    nuvo_mutex_unlock(&parent_table->shadow_link->mutex);
                }
                nuvo_mutex_unlock(&parent_table->mutex);
            }

            nuvo_map_clean_remove(cur_map);

            // put on alloc list
            map_clean_reset(cur_map);
            nuvo_dlist_insert_head(alloc_req->map_list, &cur_map->list_node);
            nuvo_mutex_unlock(&cur_map->mutex);

            alloc_req->count--;

            cur_map = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
        }
        if (alloc_req->count == 0)
        {
            // we fulfilled the current request, so complete it
            nuvo_dlist_insert_tail(comp_list, &alloc_req->list_node);
        }
        else
        {
            // we ran out of available tables, break out
            // insert it back at the head so it gets picked up next.
            nuvo_dlist_insert_head(&nuvo_map->alloc_list, &alloc_req->list_node);
            break;
        }
    }
}

nuvo_return_t nuvo_map_alloc_tables(struct nuvo_map_alloc_req *req, bool pinned)
{
    // prep alloc request
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    nuvo_dlnode_init(&req->list_node);

    // grab lock so we can insert the request
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    // if we're holding pinned tables, we only proceed with the request
    // if we are the head request.  Otherwise we return so the tables can
    // be unpinned first
    if (pinned && nuvo_dlist_get_head(&nuvo_map->alloc_list) != NULL)
    {
        nuvo_mutex_unlock(&nuvo_map->list_mutex);
        return (-NUVO_EAGAIN);
    }

    // insert request on list
    nuvo_dlist_insert_tail(&nuvo_map->alloc_list, &req->list_node);
    // run the allocator, it might be able to service the request right away
    nuvo_map_alloc_run_locked(&comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    // run callbacks on any completed requests
    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }

    return (0);
}

static void nuvo_map_reserve_sync_cb(struct nuvo_map_request *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t *)req->tag.ptr;

    nuvo_mutex_unlock(sync_signal);
}

void nuvo_map_reserve_sync(struct nuvo_map_request *req)
{
    nuvo_return_t ret;
    nuvo_mutex_t  sync_signal;

    ret = nuvo_mutex_init(&sync_signal);
    if (ret < 0)
    {
        req->status = -NUVO_ENOMEM;
        return;
    }
    nuvo_mutex_lock(&sync_signal);

    req->callback = nuvo_map_reserve_sync_cb;
    req->tag.ptr = &sync_signal;
    nuvo_map_reserve(req);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);
}

static void nuvo_map_reserve_cb(struct nuvo_map_alloc_req *req)
{
    struct nuvo_map_request *map_req = (struct nuvo_map_request *)req->tag.ptr;

    map_req->status = 0;
    map_req->callback(map_req);
}

/**
 * \brief Copy the cow bits down first time for maps that are already in mem after a snap create
 *  (aka percolate)
 * if a snapshot got created lately(i.e after a page was already faulted in)
 * update the already INMEM maps with COW bit on active
 * The map snap gen is used to track whether this map has been updated for the first time.
 * This function is invoked during the reserve path where we encounter already faulted in maps.
 *  The function is also invoked during the fault in phase, since we cannot always do percolate in reserve phase,
 *  since percolate may require mem allocations, sometimes.
 *
 * For snap luns , fault in would copy the shared bit to the child entries
 * Handling already in mem pages are  a non issue for snap luns as the new snap lun's maps are not IN-MEM during create.
 * And the old lun's inmem pages are not affected by the change.
 *
 * We also do similar stuff on the fault in path (i.e reading from media code path) too, where we know that
 * a child map is cow if the parent is cow. This is handled in map_percolate_cow_for_fault_in
 *
 * To reiterate, if this map was traversed for the first time after a snap create
 * mark the inmem child as cow.
 *
 * \param req map request
 * \param map map to percolate
 * \param reserve_phase is the caller reserve or fault in ?
 * \param comp_list list for freed maps
 * \param map pointer to the live map after percolate
 */

// notes for CUM 1315/CUM 1699

// Before writing to intermediate maps, we check whether the map state is CLEANING or maps need
// shadowing/tree shadowing for an ongoing CP.
// A map in CLEANING state is updated to SHADOW state. And a new live map is inserted in the tree.
// The map requests which have a pointer to the original CLEANING map, would now see a SHADOW map
// and the onus is on those requests to switch to the live map.
//
// This must also fix the assert in CUM 1699, where the assert wasn't happy to see an unpercolated map.
// Before the fix for CUM-1315/1699, only reserve code path did percolation. But reserve path did not handle
// CLEANING maps. Hence, we would see unpercolated intermediate maps, leading to the assert.
//
// In the fix, we attempt percolation if it doesn't require memory allocation or the map is a SHADOW map.
// If mem allocation is required, we return error to reserve. Now we allocate the necessary maps (including that for shadowing)
// and continue with the fault in code path. Now the fault in code path will
//  --switch to a live map from SHADOW if necessary

// And the percolate function below will
//  --convert CLEANING maps to shadow maps (and their parents if necessary)
//  -- Create a new live map
//  -- handle an ongoing CP. If the map being updated needs to be in a CP, shadow the map.
// -- If the child count is zero for the shadow map and we are in CP, initiate the write out

bool map_percolate_cow_for_inmem_intermediate(struct nuvo_map_request *req,
                                              struct nuvo_map_track   *map,
                                              bool                     reserve_phase,
                                              struct nuvo_dlist       *comp_list)
{
    bool             rc = true; // we succeed mostly unless reserve_phase needs mem allocation
    struct nuvo_vol *vol = map->vol;

    if (!reserve_phase)
    {
        NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    }
    NUVO_ASSERT_MUTEX_HELD(&map->mutex);

    // Note : the percolate update is done here only for intermediate maps  (L1 and above)
    // ( also referred to as parent maps)
    //  For the L0 maps, percolate is  is done in commit/write code path
    // ( specifically in map_snap_update_entries())
    // This is because, we also need to worry about shadow/cleaning etc  for L0 maps
    // before percolating.
    // So the commit code does shadow/changes cleaning to shadow etc, finds the right map
    // and does percolate work before updating it to dirty.
    //  Also note that : if the read path encounters an yet updated L0 map block
    // it doesn't do percolate work. But instead the read path fakes the cow bit now because
    // read paths is wary of doing dirties/shadowing etc
    //


    if (NUVO_LUN_IS_ACTIVE(map->lun) && (map->snap_gen < req->snap_gen) && map->level)
    {
        // We need a static cp_gen to stamp here on the maps. Let's say we are stamping cp gen 4.
        // We need to make sure that a cp from 4-5 doesn't finish under us.
        // When this cp 5 finishes all maps with cp_gen == 4 must be seen and cped by cp.
        // The holding of the map lock prevents us from CP not crossing us,
        // as cp cannot cross this map, while we are holding the map lock.
        // If the cp gen numbers went up during this, we might end up stamping a "lower cp_gen".
        // But CP would see and include this map as if it were in the previous cp.
        // So that is OK.
        // so we dont take the vol lock for the case, we know that we have the map lock.

        // But for the cleaning/racing with a CP case, we might need to shadow the whole path.
        // Shadow_path now could race with CP, because we are letting go of locks in shadow path.
        // So we take the vol lock to get a consistent cp_gen to stamp.
        // I have also added an assert in shadow_path that vol lock is held

        // Also, to make sure we have no lock inversion, the locking order is:
        // vol, parent map, child map.
        // By the way, talking of lock order, following is an issue I noticed.

        // TODO - Opened bug CUM-1711 for this.
        // nuvo_map_shadow_path may shadow the whole path holding the L0 map lock.
        // So this could deadlock with a thread coming down the tree.
        // This is already an issue in nuvo_map_commit_lock and should be fixed separately.
        // For now, we should be okay with consistent CP numbers because of vol lock

        uint64_t checkpoint_gen = nuvo_map_get_vol_cp(map->vol);
        NUVO_ASSERT(map->cp_gen <= checkpoint_gen);

        if ((map->state == NUVO_MAP_CLEANING) || (map->cp_gen < checkpoint_gen) ||
            (map->state == NUVO_MAP_SHADOW))
        {
            if (reserve_phase)
            {
                NUVO_LOG(map, 80, "map in CLEANING map:%p", map);
                rc = false;
                goto _out;
            }
            // assert since we can see a shadow here only in the reserve phase.
            // in the fault in phase, we switch to the live one if we see a shadow
            // if we saw a cleaning map, we must have created a live map and switched to
            // it by now.
            // so we shouldnt see CLEANING or SHADOW here in fault in phase
            NUVO_ASSERT(map->state != NUVO_MAP_SHADOW);
            NUVO_ASSERT(map->state != NUVO_MAP_CLEANING);

            // in reserve phase we also hold the parent lock
            // but guess what: this is not reserve phase
            // We also let go of parent lock of CLEANING maps after use
            //
            NUVO_ASSERT_MUTEX_NOT_HELD_BYME(&map->parent->mutex);
            nuvo_mutex_unlock(&map->mutex); //unlock so that we can acquire parent lock

            // acquire the locks in the holy order of vol, parent and map
            // But know that, from now on, we are good about losing map locks,
            // since we have the vol lock.
            // So CP cannot race with this map update.
start_commit:
            NUVO_ASSERT_MUTEX_HELD(&map->vol->mutex);
            checkpoint_gen = nuvo_map_get_vol_cp(map->vol);
            nuvo_mutex_lock(&map->parent->mutex);
            nuvo_mutex_lock(&map->mutex);

            // shadow and write out the dirty maps with no children
            // Note: Why don't we check map->is_dirty here, as we do for L0 maps in nuvo_map_commit_lock ?
            // We must shadow this map, irrespective of whether the map is clean or dirty,
            // since this is an intermediate map and it may have dirty children.

            if (map->cp_gen < checkpoint_gen)
            {
                // map being cleaned needs to be put in the checkpoint shadow tree
                if (map->parent->shadow_link == NULL)
                {
                    nuvo_mutex_unlock(&map->mutex);
                    nuvo_map_shadow_path(req, map->parent, checkpoint_gen, comp_list);
                    // we lost locks, retry:
                    goto start_commit;
                }

                nuvo_return_t ret = nuvo_map_shadow_reg(&req->map_list, map);
                NUVO_ASSERT(ret >= 0);

                nuvo_mutex_lock(&map->shadow_link->mutex);

                if (map->shadow_link->child_count == 0) //write out if no children, else cp would do the job
                {
                    nuvo_map_writer_add_map(map->shadow_link, NUVO_MW_FLUSH_AUTO);
                }
                else
                {
                    nuvo_mutex_unlock(&map->shadow_link->mutex);
                }
            }

            MAP_SET_CP(map, checkpoint_gen);
            nuvo_mutex_unlock(&map->parent->mutex);
        }
        // if we have a snapshot created , if we fault in a parent map or the parent map
        // was already in mem
        // the parent map must be all cow
        NUVO_MAP_SET_COW(map);
        // now do the real percolate !!
        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            map->entries[i].cow = NUVO_MAP_ENTRY_COW;
        }
        map->is_dirty = 1;
        NUVO_ASSERT(map->cp_gen == checkpoint_gen);
        map->snap_gen = req->snap_gen; //percolated !!
    }
_out:
    if (!rc)
    {
        NUVO_LOG(map, 25, "percolate map:%p rc:%d", map, rc);
    }
    NUVO_ASSERT_MUTEX_HELD(&map->mutex);
    return (rc);
}

void map_percolate_cow_for_inmem_L0(struct nuvo_map_request *req, struct nuvo_map_track *map)
{
    if (NUVO_LUN_IS_ACTIVE(map->lun) && map->snap_gen < req->snap_gen)
    {
        NUVO_MAP_SET_COW(map);

        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            map->entries[i].cow = NUVO_MAP_ENTRY_COW;
        }
        map->is_dirty = 1;
        map->snap_gen = req->snap_gen;
    }
}

void nuvo_map_reserve(struct nuvo_map_request *req)
{
    // traverse the in-memory pages of the map
    // stop when we either reach level 0, or a non-in-memory page
    nuvo_mutex_lock(&req->lun->mutex);
    uint_fast32_t maps_needed = 0;

    // traverse map for both first and last block
    uint_fast8_t           level = req->lun->map_height - 1;
    uint_fast8_t           common_level;
    struct nuvo_map_track *root_map = req->lun->root_map;
    struct nuvo_map_track *map = root_map;
    uint_fast32_t          first_index = nuvo_map_get_table_index(req->block_start, level);
    uint_fast32_t          last_index = nuvo_map_get_table_index(req->block_last, level);
    nuvo_mutex_lock(&map->mutex);
    nuvo_mutex_unlock(&req->lun->mutex);

    // go down tree until either: first and last diverge or there is no more tree
    while (first_index == last_index &&
           map->entries[first_index].type == NUVO_ME_IN_MEM &&
           level > req->target_level)
    {
        struct nuvo_map_track *next_map_table = map->entries[first_index].ptr;
        nuvo_mutex_lock(&next_map_table->mutex);
        if (!map_percolate_cow_for_inmem_intermediate(req, next_map_table, true, NULL))
        {
            //TODO think how cow percolate should work for CLEANING maps
            // we don't pin pages that are actively being cleaned
            // these pages must first be shadowed, which requires allocation
            // so we let the fault-in process handle shadowing pages
            // that are being cleaned
            nuvo_mutex_unlock(&next_map_table->mutex);
            break;
        }
        nuvo_mutex_unlock(&map->mutex);
        map = next_map_table;
        level--;
        first_index = nuvo_map_get_table_index(req->block_start, level);
        last_index = nuvo_map_get_table_index(req->block_last, level);
    }
    common_level = level;

    // try to traverse rest of tree for first
    struct nuvo_map_track *first_map_table = map;
    uint_fast32_t          first_level = level;
    while (first_map_table->entries[first_index].type == NUVO_ME_IN_MEM &&
           first_level > req->target_level)
    {
        struct nuvo_map_track *next_map_table = first_map_table->entries[first_index].ptr;
        nuvo_mutex_lock(&next_map_table->mutex);
        if (!map_percolate_cow_for_inmem_intermediate(req, next_map_table, true, NULL))
        {
            // we don't pin pages that are actively being cleaned
            // these pages must first be shadowed, which requires allocation
            // so we let the fault-in process handle shadowing pages
            // that are being cleaned
            nuvo_mutex_unlock(&next_map_table->mutex);
            break;
        }
        // don't unlock where the first/last diverged
        if (first_map_table != map)
        {
            nuvo_mutex_unlock(&first_map_table->mutex);
        }
        first_map_table = next_map_table;
        first_level--;
        first_index = nuvo_map_get_table_index(req->block_start, first_level);
    }
    nuvo_map_pin_table(first_map_table);
    req->first_map = first_map_table;
    if (first_map_table != map)
    {
        nuvo_mutex_unlock(&first_map_table->mutex);
    }

    // try to traverse rest of tree for last
    struct nuvo_map_track *last_map_table = map;
    uint_fast32_t          last_level = level;
    while (last_map_table->entries[last_index].type == NUVO_ME_IN_MEM &&
           last_level > req->target_level)
    {
        struct nuvo_map_track *next_map_table = last_map_table->entries[last_index].ptr;
        nuvo_mutex_lock(&next_map_table->mutex);
        if (!map_percolate_cow_for_inmem_intermediate(req, next_map_table, true, NULL))
        {
            // we don't pin pages that are actively being cleaned
            // these pages must first be shadowed, which requires allocation
            // so we let the fault-in process handle shadowing pages
            // that are being cleaned
            nuvo_mutex_unlock(&next_map_table->mutex);
            break;
        }
        nuvo_mutex_unlock(&last_map_table->mutex);
        last_map_table = next_map_table;
        last_level--;
        last_index = nuvo_map_get_table_index(req->block_last, last_level);
    }
    nuvo_map_pin_table(last_map_table);
    req->last_map = last_map_table;
    nuvo_mutex_unlock(&last_map_table->mutex);

    // calculate the maps needed
    if (first_map_table != last_map_table)
    {
        // maps for finishing fault-in
        maps_needed = (first_level + last_level - 2 * req->target_level);

        // additional maps in case we have to shadow the tree
        maps_needed += 2 * (req->lun->map_height - req->target_level) -
                       (req->lun->map_height - 1 - common_level);
    }
    else
    {
        maps_needed = (first_level + req->lun->map_height) - 2 * req->target_level;
        for (uint_fast8_t i = first_level; i > req->target_level; i--)
        {
            first_index = nuvo_map_get_table_index(req->block_start, i);
            last_index = nuvo_map_get_table_index(req->block_last, i);
            if (first_index != last_index)
            {
                maps_needed += (i - req->target_level) * 2;
                break;
            }
        }
    }

    // we always need at least 1 map in case of checkpoints
    NUVO_ASSERT(maps_needed != 0);

    // try to allocate map tables and put on request map_list
    // we might need two shadows
    // we might need parent shadows + 2 child shadows;
    // so height + 2 - 1 = height + 1
    req->map_alloc_req.count = maps_needed;
    req->map_alloc_req.map_list = &req->map_list;
    req->map_alloc_req.callback = nuvo_map_reserve_cb;
    req->map_alloc_req.tag.ptr = req;
    nuvo_return_t ret = nuvo_map_alloc_tables(&req->map_alloc_req, true);
    if (ret < 0)
    {
        // this should not be common, however we need to do this to assure
        // that there is no chance of a deadlock
        struct nuvo_dlist comp_list;
        nuvo_dlist_init(&comp_list);

        // unpin tables to release resources to others
        nuvo_mutex_lock(&req->first_map->mutex);
        nuvo_map_unpin_table(req->first_map, &comp_list);
        nuvo_mutex_unlock(&req->first_map->mutex);

        nuvo_mutex_lock(&req->last_map->mutex);
        nuvo_map_unpin_table(req->last_map, &comp_list);
        nuvo_mutex_unlock(&req->last_map->mutex);

        struct nuvo_map_alloc_req *comp_req;
        while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
        {
            comp_req->callback(comp_req);
        }
        // the root map of a lun is always present, lets start there
        req->first_map = root_map;
        req->last_map = root_map;
        nuvo_mutex_lock(&root_map->mutex);
        nuvo_map_pin_table(req->last_map);
        nuvo_map_pin_table(req->first_map);
        nuvo_mutex_unlock(&root_map->mutex);

        // now we try to allocate worst case tables, blocking if not
        // enough are available
        req->map_alloc_req.count = req->lun->map_height * 4 - 2;
        ret = nuvo_map_alloc_tables(&req->map_alloc_req, false);
        NUVO_ASSERT(ret >= 0); // non-pinned version should never fail
    }
}

void nuvo_map_request_complete(struct nuvo_map_request *req, bool free_maps)
{
    // clean up anything left over on this req
    if (free_maps)
    {
        map_request_free(req, NULL);
    }
    // do the req callback
    req->callback(req);
}

void nuvo_map_fault_in_int_io_cb(struct nuvo_io_request *io_req);
void nuvo_map_fault_in_int_req_cb(struct nuvo_pr_req_alloc *req_alloc);

void nuvo_map_fault_in_int_pin_cb(struct nuvo_mfst_map_open *pin_req)
{
    struct nuvo_dlist alloc_comp_list;
    struct nuvo_dlist req_comp_list;

    nuvo_dlist_init(&alloc_comp_list);
    nuvo_dlist_init(&req_comp_list);
    struct nuvo_map_track   *map = (struct nuvo_map_track *)pin_req->tag.ptr;
    struct nuvo_map_request *map_req, *next_map_req;

    if (pin_req->status < 0)
    {
        // some parcel failed to open
        // unpin the segments the blocks is in
        nuvo_mfst_unpin(&map->parent->vol->log_volume.mfst, 1, &map->map_entry);
        // run through all pending map requests in parent that are for this map
        // and complete them with an error
        nuvo_mutex_lock(&map->parent->mutex);
        map_req = nuvo_dlist_get_head_object(&map->parent->wait_list, struct nuvo_map_request, list_node);
        while (map_req != NULL)
        {
            next_map_req = nuvo_dlist_get_next_object(&map->parent->wait_list, map_req, struct nuvo_map_request, list_node);
            if (nuvo_map_get_base_offset(map_req->fault_block_num, map->level) == map->base_offset)
            {
                nuvo_dlist_remove(&map_req->list_node);
                nuvo_dlist_insert_head(&req_comp_list, &map_req->list_node);
                // unpin the parent for each request we're completing
                nuvo_map_unpin_table(map->parent, &alloc_comp_list);
            }
            map_req = next_map_req;
        }
        // reset the parent map entry
        map->parent->entries[nuvo_map_get_table_index(map->base_offset, map->parent->level)].type = NUVO_ME_MEDIA;
        nuvo_mutex_unlock(&map->parent->mutex);

        // call the callbacks now that we're not in a lock
        while ((map_req = nuvo_dlist_remove_head_object(&req_comp_list, struct nuvo_map_request, list_node)) != NULL)
        {
            map_req->status = -NUVO_EIO;
            nuvo_map_request_complete(map_req, true);
        }

        // free the current map
        map->parent = NULL;
        nuvo_mutex_lock(&nuvo_map->list_mutex);
        nuvo_map_clean_insert_tail_noalloc(map);

        // run the allocator since we've potentially freed many maps
        nuvo_map_alloc_run_locked(&alloc_comp_list);
        nuvo_mutex_unlock(&nuvo_map->list_mutex);
        struct nuvo_map_alloc_req *comp_req;
        while ((comp_req = nuvo_dlist_remove_head_object(&alloc_comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
        {
            comp_req->callback(comp_req);
        }

        return;
    }

    // get the map request that issued this pin req, and use it's
    // pr alloc req to issue the io request allocation
    map_req = nuvo_containing_object(pin_req, struct nuvo_map_request, pin_req);

    // send the req allocation
    struct nuvo_pr_req_alloc *req_alloc = &map_req->pr_req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);
    req_alloc->callback = nuvo_map_fault_in_int_req_cb;
    req_alloc->tag.ptr = map;
    nuvo_pr_client_req_alloc_cb(req_alloc);
}

void nuvo_map_fault_in_int_req_cb(struct nuvo_pr_req_alloc *req_alloc)
{
    struct nuvo_map_track *map = (struct nuvo_map_track *)req_alloc->tag.ptr;
    // get a pointer to the map request that triggered this read
    struct nuvo_map_request *map_req = nuvo_containing_object(req_alloc, struct nuvo_map_request, pr_req_alloc);
    struct nuvo_io_request  *io_req = req_alloc->req;

    NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
    io_req->tag.ptr = map;
    io_req->callback = nuvo_map_fault_in_int_io_cb;
    io_req->rw.parcel_desc = map_req->fault_parcel_desc;
    io_req->rw.block_offset = map->map_entry.media_addr.block_offset;
    io_req->rw.block_count = 1;
    io_req->rw.iovecs[0].iov_base = map->entries;
    io_req->rw.iovecs[0].iov_len = sizeof(struct nuvo_map_table);
    io_req->rw.vol = map_req->lun->vol;

    nuvo_rl_submit_req(io_req);
}

/* copy cow entries to child in the fault in from media code path */
void map_percolate_cow_on_fault_in(struct nuvo_map_track *map, const struct nuvo_map_entry *map_entry)
{
    if (NUVO_LUN_IS_ACTIVE(map->lun) && map_entry->cow)
    {
        // since the parent entries ME was copied to this map->map_entry
        NUVO_ASSERT(map_entry->cow == NUVO_MAP_ENTRY_COW);
        // CUM 1749 The map_entry from parent to child, was copied before the map read from disk was initiated.
        // It is possible that a snap got created and a parent got percolated, while the i/o was in progress.
        // So we re-update the child map COW bit here.
        map->map_entry.cow = NUVO_MAP_ENTRY_COW;
        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            map->entries[i].cow = map_entry->cow;
        }
    }
}

void nuvo_map_fault_in_int_io_cb(struct nuvo_io_request *io_req)
{
    struct nuvo_dlist        req_comp_list;
    struct nuvo_dlist        alloc_comp_list;
    struct nuvo_map_request *map_req, *next_map_req;
    struct nuvo_map_track   *map = (struct nuvo_map_track *)io_req->tag.ptr;

    nuvo_dlist_init(&req_comp_list);
    nuvo_dlist_init(&alloc_comp_list);

    // handle this map's read completion
    nuvo_mfst_unpin(&map->parent->vol->log_volume.mfst, 1, &map->map_entry);

    nuvo_return_t ret = io_req->status;
    nuvo_hash_t   req_hash = io_req->rw.block_hashes[0];
    nuvo_pr_client_req_free(io_req);

    nuvo_mutex_lock(&map->parent->mutex);
    struct nuvo_map_entry *map_entry = &map->parent->entries[nuvo_map_get_table_index(map->base_offset, map->parent->level)];
    // Since we switched the live parent map, during the creation of the shadow
    // we cannot see a SHADOW or CLEANING parent now

    NUVO_ASSERT(map->parent->state != NUVO_MAP_SHADOW);
    NUVO_ASSERT(map->parent->state != NUVO_MAP_CLEANING);

    if (ret < 0)
    {
        // reset the parent map entry
        map_entry->type = NUVO_ME_MEDIA;
        ret = -NUVO_EIO;
        goto exit;
    }
    // if request was successful, set return to 0
    ret = 0;

    // check the hash
    if (map_entry->hash != req_hash)
    {
        // reset the parent map entry
        map_entry->type = NUVO_ME_MEDIA;
        ret = -NUVO_E_BAD_HASH;
        goto exit;
    }

    // we got raw table, init in-core data
    map->state = NUVO_MAP_PINNED;
    map->lun = map->parent->lun;
    map->vol = map->parent->vol;
    map->is_dirty = 0;
    map->child_count = 0;
    map->is_new_entry = 0;
    map->pinned = 1;
    map->parent->child_count++;
    // re-populate maps cp gen as cp_gen could have changed
    // due to CP/pit create while we were faulting in
    // while we were busy faulting in
    MAP_SET_CP(map, map->parent->cp_gen);

    // put on pinned list
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_pinned_insert(map);
    // unpin parent once, since we're going to advance one of the map reqs past it
    nuvo_map_unpin_table(map->parent, &alloc_comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    // update entry, and wake any waiters

    // on active, propagate cow down

    map_percolate_cow_on_fault_in(map, map_entry);

    map_entry->type = NUVO_ME_IN_MEM;
    map_entry->ptr = map;


exit:

    // wake up all waiters
    map_req = nuvo_dlist_get_head_object(&map->parent->wait_list, struct nuvo_map_request, list_node);
    while (map_req != NULL)
    {
        next_map_req = nuvo_dlist_get_next_object(&map->parent->wait_list, map_req, struct nuvo_map_request, list_node);
        if (nuvo_map_get_base_offset(map_req->fault_block_num, map->level) == map->base_offset)
        {
            nuvo_dlist_remove(&map_req->list_node);
            nuvo_dlist_insert_head(&req_comp_list, &map_req->list_node);
        }
        map_req = next_map_req;
    }
    nuvo_mutex_unlock(&map->parent->mutex);

    // progress map requests if IO was successful, or complete with error if not
    if (ret >= 0)
    {
        // advance one of the map requests so that the map table will be unpinned
        map_req = nuvo_dlist_remove_head_object(&req_comp_list, struct nuvo_map_request, list_node);
        NUVO_ASSERT(map_req != NULL);
        NUVO_ASSERT(map_req->fault_map == map->parent);

        map_req->fault_map = map;

        // grab vol lock and set cp gen
        nuvo_mutex_lock(&map_req->fault_map->vol->mutex);
        // lock fault map interlocked with vol
        nuvo_mutex_lock(&map_req->fault_map->mutex);

        nuvo_map_fault_in_int(map_req);

        // When shadoowing table, change any entries in loading stte to on-media state.
        // this is handled in nuvo_map_shadow_reg()
        while ((map_req = nuvo_dlist_remove_head_object(&req_comp_list, struct nuvo_map_request, list_node)) != NULL)
        {
            // grab vol lock and set cp gen
            nuvo_mutex_lock(&map_req->fault_map->vol->mutex);
            // lock fault map interlocked with vol
            nuvo_mutex_lock(&map_req->fault_map->mutex);

            nuvo_map_fault_in_int(map_req);
        }
    }
    else
    {
        //TODO fault inject code to test this error path
        // call the callbacks now that we're not in a lock
        while ((map_req = nuvo_dlist_remove_head_object(&req_comp_list, struct nuvo_map_request, list_node)) != NULL)
        {
            map_req->status = ret;
            nuvo_map_request_complete(map_req, true);
            // unpin the parent for each request we're completing
            NUVO_ASSERT_MUTEX_NOT_HELD_BYME(&map->parent->mutex);
            nuvo_mutex_lock(&map->parent->mutex);
            nuvo_map_unpin_table(map->parent, &alloc_comp_list);
            nuvo_mutex_unlock(&map->parent->mutex);
        }
    }

    // if there was an error, free the current map
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    if (ret < 0)
    {
        map->parent = NULL;
        nuvo_map_clean_insert_tail_noalloc(map);
    }

    // run the allocator since we've potentially freed many maps
    nuvo_map_alloc_run_locked(&alloc_comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&alloc_comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }
}

void nuvo_map_fault_in_int(struct nuvo_map_request *req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    struct nuvo_map_track *next_map;
    uint64_t checkpoint_gen;

    // we expect the caller to get a vol mutex
    // only held on during in mem map ops
    // we need this for interlocking with a cp to stamp a consistent cp gen
    // on the map
    // if we need to fault in for i/o we let go of the lock
    // and the callback calls this function again
    //
    struct nuvo_vol *vol = req->fault_map->vol;
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    bool vol_locked = true;

    // Need parent locks to handle CLEANING maps
    // So acquire in order.
    //
    // we let go of the parent lock (that is about to be taken)
    // once we process the child map that is in CLEANING.
    // Also be careful not to take the parent lock
    // if we aren't going to do any CLEANING processing.
    // (ie we already go the map what we wanted)
    // (See also CUM-2383)
    //
    if ((req->fault_map->level > req->target_level) &&
        (req->fault_map->state == NUVO_MAP_CLEANING))
    {
        nuvo_mutex_unlock(&req->fault_map->mutex);
        nuvo_mutex_lock(&req->fault_map->parent->mutex);
        nuvo_mutex_lock(&req->fault_map->mutex);
    }

    while (req->fault_map->level > req->target_level)
    {
        struct nuvo_map_track *map = req->fault_map;

start_commit:
        checkpoint_gen = nuvo_map_get_vol_cp(vol);

        if (map->state == NUVO_MAP_SHADOW)
        {
            map = map_get_live_map(req, map, &comp_list);
        }

        // CUM-1970,1923: Let's not fault in children for intermediate maps
        // who are CLEANING. Since the CLEANING map is writing to disk
        // we shouldn't be touching its contents. (caused checksum
        // errors in 1970)
        // So, make a copy in a live map and fault in the children
        // with the live map as the parent.
        //

        if (map->state == NUVO_MAP_CLEANING)
        {
            NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
            // cleaning maps cannot have children
            NUVO_ASSERT(map->child_count == 0);

            // checking of checkpoint_gen and stamping needs to be atomic
            // to avoid the case of we stamping cp_gen = X and cp took the cp_gen from X to X + 1
            // the map locks prevent this, but we need to let go lock of the map
            // locks for the shadow path to avoid inversion since shadow_path is done from top
            // to bottom
            // But we hold on to the vol lock to ensure cp_gen doesnt change .
            // Alternatively, retry until you get it right like a spin lock would also work.

            if (map->cp_gen < checkpoint_gen)
            {
                if (map->parent->shadow_link == NULL)
                {
                    nuvo_mutex_unlock(&map->mutex);
                    nuvo_map_shadow_path(req, map->parent, checkpoint_gen, &comp_list);
                    nuvo_mutex_lock(&map->parent->mutex);
                    nuvo_mutex_lock(&map->mutex);
                    goto start_commit;
                }
            }

            nuvo_map_shadow_cleaning(req, &map, &comp_list);

            MAP_SET_CP(map, checkpoint_gen);

            NUVO_ASSERT_MUTEX_HELD(&map->parent->mutex);
            nuvo_mutex_unlock(&map->parent->mutex);
        }

        req->fault_map = map;

        bool rc = map_percolate_cow_for_inmem_intermediate(req, map, false /* not reserve */,
                                                           &comp_list);

        if (!rc)
        {
            NUVO_PANIC("percolate failed in fault in phase map:%p block:%lu last_block:%lu",
                       req->fault_map,
                       req->block_start, req->block_last);
        }

        // either we switched to live map from SHADOW
        // or made a live map out of a CLEANING map

        NUVO_ASSERT((map->state != NUVO_MAP_SHADOW));
        NUVO_ASSERT((map->state != NUVO_MAP_CLEANING));
        NUVO_ASSERT(map->snap_gen >= req->snap_gen); // since we percolated

        struct nuvo_map_entry *map_entry = &req->fault_map->entries[nuvo_map_get_table_index(req->fault_block_num, req->fault_map->level)];

        NUVO_ASSERT_MUTEX_HELD(&req->fault_map->mutex);

        switch (map_entry->type)
        {
        case NUVO_ME_CONST:
            // we should create a top level page and propagate the
            // const value down
            next_map = nuvo_dlist_remove_head_object(&req->map_list, struct nuvo_map_track, list_node);
            NUVO_ASSERT(next_map != NULL);     //Reservation ran out of map tables!

            nuvo_mutex_lock(&next_map->mutex);
            next_map->snap_gen = req->snap_gen;
            next_map->state = NUVO_MAP_PINNED;
            next_map->base_offset = nuvo_map_get_base_offset(req->fault_block_num, req->fault_map->level - 1);
            next_map->lun = req->fault_map->lun;
            next_map->vol = req->fault_map->vol;
            next_map->parent = req->fault_map;
            next_map->is_dirty = 0;
            next_map->child_count = 0;
            next_map->is_new_entry = 0;
            next_map->pinned = 1;
            next_map->level = req->fault_map->level - 1;
            // note the cp_gen is copied from the parent cp_gen instead of the request cp_gen
            // read the note during case:NUVO_ME_MEDIA  below on cp_gen
            MAP_SET_CP(next_map, next_map->parent->cp_gen);
            next_map->map_entry = *map_entry;

            for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
            {
                next_map->entries[i] = *map_entry;
            }

            map_entry->type = NUVO_ME_IN_MEM;
            map_entry->ptr = next_map;

            req->fault_map->child_count++;

            // pin parent since it has another child table now
            nuvo_map_pin_table(req->fault_map);

            nuvo_mutex_lock(&nuvo_map->list_mutex);
            nuvo_map_pinned_insert(next_map);
            nuvo_mutex_unlock(&nuvo_map->list_mutex);
            break;

        case NUVO_ME_MEDIA:
            // we need to fetch the table from media
            next_map = nuvo_dlist_remove_head_object(&req->map_list, struct nuvo_map_track, list_node);
            NUVO_ASSERT(next_map != NULL);     //Reservation ran out of map tables!

            // copy down original map entry
            next_map->parent = req->fault_map;
            next_map->map_entry = *map_entry;
            next_map->base_offset = nuvo_map_get_base_offset(req->fault_block_num, req->fault_map->level - 1);
            next_map->level = req->fault_map->level - 1;

            // note : set child's cp_gen from parent's cp_gen  instead of the reqeusts' cp_gen
            // The request cp_gen is the latest target cp_gen from the volume
            // Setting the faulted in childs to the target cp_gen could cause the assert
            // of map->cp_gen == req->prev gen assert to fire, during CP.
            // Explanation below

            //Lets take an example of a parent at 3 and the cp begins now from 3->4.
            // So the request gets a cp of 4.
            // And if we use the request's cp_gen, the child faulted in also gets a cp_gen of 4.
            // Now if CP comes along and shadows the parent at 3, it will have an inmem child at 4.
            // This would cause the map->cp_gen == req->prev_gen asssert during CP fire.

            MAP_SET_CP(next_map, next_map->parent->cp_gen);
            next_map->snap_gen = req->snap_gen;

            // set entry to loading state
            map_entry->type = NUVO_ME_LOADING;

            // pin parent since it will have another child table
            nuvo_map_pin_table(req->fault_map);

            // add this req to the list of waiting reqs on the parent
            nuvo_dlist_insert_tail(&req->fault_map->wait_list, &req->list_node);

            // pin the segments the blocks are in
            nuvo_mfst_pin(&req->fault_map->vol->log_volume.mfst, 1, &next_map->map_entry);

            // we can now release the parent lock while we do our read
            nuvo_mutex_unlock(&req->fault_map->mutex);

            nuvo_mutex_unlock(&vol->mutex);
            vol_locked = false;

            // pin block and get parcel desc
            struct nuvo_mfst_map_open *pin_req = &req->pin_req;
            pin_req->mfst = &req->fault_map->vol->log_volume.mfst;
            pin_req->tag.ptr = next_map;
            pin_req->num_map_entries = 1;
            pin_req->map_entry = &next_map->map_entry;
            pin_req->pds = &req->fault_parcel_desc;
            pin_req->callback = nuvo_map_fault_in_int_pin_cb;
            nuvo_mfst_open_async(pin_req);

            goto exit;
            break;

        case NUVO_ME_IN_MEM:

            next_map = map_entry->ptr;
            nuvo_mutex_lock(&next_map->mutex);

            nuvo_map_pin_table(next_map);
            break;

        case NUVO_ME_LOADING:
            // the map table we need is currently loading, add ourselves
            // to the parent's wait list and break out
            nuvo_dlist_insert_tail(&req->fault_map->wait_list, &req->list_node);
            nuvo_mutex_unlock(&req->fault_map->mutex);

            goto exit;
            break;

        case NUVO_ME_NULL:

            next_map = nuvo_dlist_remove_head_object(&req->map_list, struct nuvo_map_track, list_node);
            NUVO_ASSERT(next_map != NULL);     //Reservation ran out of map tables!

            nuvo_mutex_lock(&next_map->mutex);
            next_map->state = NUVO_MAP_PINNED;
            next_map->base_offset = nuvo_map_get_base_offset(req->fault_block_num, req->fault_map->level - 1);
            next_map->lun = req->fault_map->lun;
            next_map->vol = req->fault_map->vol;
            next_map->parent = req->fault_map;
            next_map->is_dirty = 0;
            next_map->child_count = 0;
            next_map->is_new_entry = 0;
            next_map->pinned = 1;
            next_map->level = req->fault_map->level - 1;
            // note the cp_gen is copied from the parent cp_gen instead of the request cp_gen
            // read the note during case:NUVO_ME_MEDIA  above on cp_gen
            MAP_SET_CP(next_map, next_map->parent->cp_gen);
            next_map->map_entry = *map_entry;
            next_map->snap_gen = req->snap_gen;

            // Children of shared are shared

            for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
            {
                next_map->entries[i] = *map_entry;
            }

            map_entry->type = NUVO_ME_IN_MEM;
            map_entry->ptr = next_map;

            req->fault_map->child_count++;

            // pin parent since it has another child table now
            nuvo_map_pin_table(req->fault_map);

            nuvo_mutex_lock(&nuvo_map->list_mutex);
            nuvo_map_pinned_insert(next_map);
            nuvo_mutex_unlock(&nuvo_map->list_mutex);

            break;

        default:
            NUVO_PANIC("Unrecognized map entry type.");
        }
        nuvo_map_unpin_table(req->fault_map, &comp_list);

        // We need to hold on to the parent lock to handle CLEANING maps in the loop
        // So, dont let go if the map is in CLEANING
        // unless we are getting out of this loop (CUM-2234) and got our map.
        // The parent map lock is released after we handle the CLEANING map

        if ((next_map->state != NUVO_MAP_CLEANING) ||
            (next_map->level == req->target_level))
        {
            nuvo_mutex_unlock(&req->fault_map->mutex);
        }
        NUVO_ASSERT(next_map->pinned > 0);
        req->fault_map = next_map;
    }

    nuvo_mutex_unlock(&req->fault_map->mutex);

    nuvo_mutex_unlock(&vol->mutex);
    vol_locked = false;

    // check if we've finished a path
    if (req->fault_map->level == req->target_level)
    {
        // we've finished a path
        if (req->fault_path == NUVO_MAP_PATH_FIRST)
        {
            // go down last path
            req->first_map = req->fault_map;
            req->fault_map = req->last_map;
            req->fault_block_num = req->block_last;
            req->fault_path = NUVO_MAP_PATH_LAST;

            // grab vol lock
            nuvo_mutex_lock(&vol->mutex);
            // lock fault map
            nuvo_mutex_lock(&req->fault_map->mutex);
            nuvo_map_fault_in_int(req);
        }
        else if (req->fault_path == NUVO_MAP_PATH_LAST)
        {
            req->last_map = req->fault_map;
            req->status = 0;
            nuvo_map_request_complete(req, false);
        }
        else
        {
            NUVO_PANIC("Invalid fault path value.");
        }
    }

exit:

    if (vol_locked)
    {
        nuvo_mutex_unlock(&vol->mutex);
    }

    // run allocator since complete call above could have freed maps without
    // running allocator
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_alloc_run_locked(&comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }
}

void nuvo_map_fault_in(struct nuvo_map_request *req)
{
    req->fault_path = NUVO_MAP_PATH_FIRST;
    req->fault_map = req->first_map;
    req->fault_block_num = req->block_start;

    // grab vol lock and set cp gen
    nuvo_mutex_lock(&req->fault_map->vol->mutex);
    // lock fault map interlocked with vol
    nuvo_mutex_lock(&req->fault_map->mutex);

    nuvo_map_fault_in_int(req);
}

void nuvo_map_fault_in_sync_cb(struct nuvo_map_request *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t *)req->tag.ptr;

    nuvo_mutex_unlock(sync_signal);
}

// differ fault in  functions

void nuvo_map_fault_in_differ_cb(struct nuvo_map_request *req)
{
    struct nuvo_map_diff_request *mdr = (struct nuvo_map_diff_request *)req->tag.ptr;

    //NUVO_ASSERT(req->first_map == req->last_map); // cant be true as we fault in only for last pathA

    mdr->status = req->status;
    mdr->map = req->last_map;

    nuvo_mutex_lock(&mdr->fault_in_mutex);
    mdr->fault_in_cnt--;
    if (!mdr->fault_in_cnt)
    {
        nuvo_cond_signal(&mdr->fault_in_done_cond);
    }

    //TODO multi fault in clean ups in the caller if we ever do multi fault in

    nuvo_mutex_unlock(&mdr->fault_in_mutex);
}

void nuvo_map_reserve_differ(struct nuvo_map_diff_request *mdr, struct nuvo_map_track *fault_map)
{
    struct nuvo_map_request *req = &mdr->map_req;
    bool alloc_done = false;
    struct nuvo_map_track *child_map;

alloc:
    //give memory to the map request for the future child map
    child_map =
        nuvo_dlist_remove_head_object(&mdr->map_list, struct nuvo_map_track, list_node);

    if (!child_map)
    {
        NUVO_ASSERT(alloc_done == false);
        map_diff_alloc_mem_sync(mdr);
        alloc_done = true;
        goto alloc;
    }
    ///pin the parent for each fault in of child (once)
    nuvo_map_pin_table(fault_map);
    nuvo_dlist_insert_head(&req->map_list, &child_map->list_node);
    return;
}

void nuvo_map_fault_in_differ(struct nuvo_map_diff_request *mdr,
                              struct nuvo_map_track        *map)
{
    struct nuvo_map_request *req = &mdr->map_req;

    req->first_map = map;
    req->last_map = map;
    req->target_level = map->level - 1;
    mdr->fault_in_cnt++;
    req->callback = nuvo_map_fault_in_differ_cb;
    //req->tag.ptr = &sync_signal;
    req->tag.ptr = mdr;

    //TODO pin the map
    req->fault_path = NUVO_MAP_PATH_LAST;
    req->fault_map = map;
    req->fault_block_num = req->block_start;

    // grab vol lock and set cp gen
    nuvo_mutex_lock(&req->fault_map->vol->mutex);
    // lock fault map interlocked with vol
    nuvo_mutex_unlock(&req->fault_map->vol->mutex);

    nuvo_map_fault_in_int(req);

    return;
}

nuvo_return_t nuvo_map_wait_fault_in_differ(struct nuvo_map_diff_request *mdr)
{
    nuvo_mutex_lock(&mdr->fault_in_mutex);
    while (mdr->fault_in_cnt)
    {
        nuvo_cond_wait(&mdr->fault_in_done_cond, &mdr->fault_in_mutex);
    }
    nuvo_mutex_unlock(&mdr->fault_in_mutex);
    return (mdr->status);
}

void nuvo_map_fault_in_sync(struct nuvo_map_request *req)
{
    nuvo_return_t ret;
    nuvo_mutex_t  sync_signal;

    ret = nuvo_mutex_init(&sync_signal);
    if (ret < 0)
    {
        req->status = -NUVO_ENOMEM;
        return;
    }
    req->callback = nuvo_map_fault_in_sync_cb;
    req->tag.ptr = &sync_signal;
    nuvo_mutex_lock(&sync_signal);
    nuvo_map_fault_in(req);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);

    nuvo_mutex_destroy(&sync_signal);
}

/*
 * \brief move the children from the shadow to the new parent
 *  claim the children of the shadow and give them the new parent
 *  and do a pseudo evict from shadow
 *  Also move the map requests from the wait list to the new parent's wait list
 *
 * \param req map request
 * \parent new parent
 * \shadow original parent, which is being converted to a shadow
 * \comp_list list to collect the freed maps
 * \sa nuvo_map_cleaning_shadow
 */


void map_adopt_children_from_shadow(struct nuvo_map_request *req, struct nuvo_map_track *parent,
                                    struct nuvo_map_track *shadow, struct nuvo_dlist *comp_list)
{
    (void)req;
    NUVO_ASSERT_MUTEX_HELD(&shadow->mutex);
    NUVO_ASSERT_MUTEX_HELD(&parent->mutex);
    NUVO_ASSERT(parent->level == shadow->level && shadow->level);
    NUVO_ASSERT(shadow->state == NUVO_MAP_SHADOW); //handle user error

    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        if (shadow->entries[i].type == NUVO_ME_IN_MEM)
        {
            struct nuvo_map_track *map = shadow->entries[i].ptr;
            nuvo_mutex_lock(&map->mutex);
            NUVO_ASSERT(map->parent == shadow);
            // change parent to the new parent
            map->parent = parent;
            nuvo_mutex_unlock(&map->mutex);
            // we already copied the map entries in the calling function.
            // so map entry in the parent must point us to us.
            struct nuvo_map_entry *map_entry = &parent->entries[nuvo_map_get_table_index(map->base_offset, parent->level)];
            NUVO_ASSERT(map_entry->ptr == map); //since we must have already copied this.

            shadow->child_count--;
            nuvo_map_shadow_unpin_table(shadow, comp_list);
        }
        else if (shadow->entries[i].type == NUVO_ME_LOADING)
        {
            // if the entries are loading, we need to transfer the wait list to the new parent.
            struct nuvo_map_request *next_map_req;
            struct nuvo_map_request *map_req = nuvo_dlist_get_head_object(&shadow->wait_list, struct nuvo_map_request, list_node);

            while (map_req != NULL)
            {
                // move the map reqs to the new parent from the shadow
                next_map_req = nuvo_dlist_get_next_object(&shadow->wait_list, map_req, struct nuvo_map_request, list_node);
                nuvo_dlist_remove(&map_req->list_node);
                nuvo_dlist_insert_tail(&parent->wait_list, &map_req->list_node);
                // change the fault map to the new parent
                NUVO_ASSERT(map_req->fault_map == shadow);
                map_req->fault_map = parent;
                // and unpin the old parent
                nuvo_map_shadow_unpin_table(shadow, comp_list);
                map_req = next_map_req;
            }
        }
    }

    NUVO_ASSERT(shadow->pinned > 0);       // shadow is getting written out and must have a pincount
    NUVO_ASSERT(shadow->child_count == 0); // we must have moved all the children
}

void nuvo_map_shadow_cleaning(struct nuvo_map_request *req, struct nuvo_map_track **map, struct nuvo_dlist *comp_list)
{
    struct nuvo_map_track *cur_map = *map;

    NUVO_ASSERT_MUTEX_HELD(&cur_map->mutex);
    NUVO_ASSERT_MUTEX_HELD(&cur_map->parent->mutex);
    NUVO_ASSERT(cur_map->state == NUVO_MAP_CLEANING)
    uint16_t unpin_count;

    // if map is cleaning, we turn the current map into shadow
    // otherwise we allocate a new map as the shadow

    struct nuvo_map_track *parent = cur_map->parent;
    struct nuvo_map_entry *map_entry = &parent->entries[nuvo_map_get_table_index(cur_map->base_offset, cur_map->level + 1)];

    NUVO_ASSERT(cur_map->shadow_link == NULL);

    struct nuvo_map_track *shadow_map = cur_map;
    cur_map = nuvo_dlist_remove_head_object(&req->map_list, struct nuvo_map_track, list_node);
    NUVO_ASSERT(cur_map != NULL);

    nuvo_mutex_lock(&cur_map->mutex);
    cur_map->state = NUVO_MAP_PINNED;
    cur_map->level = shadow_map->level;
    cur_map->base_offset = shadow_map->base_offset;
    cur_map->lun = shadow_map->lun;
    cur_map->vol = shadow_map->vol;
    cur_map->parent = shadow_map->parent;
    cur_map->map_entry = shadow_map->map_entry;
    cur_map->mfl = shadow_map->mfl;
    MAP_SET_CP(cur_map, shadow_map->cp_gen);
    cur_map->is_dirty = 0;
    cur_map->child_count = shadow_map->child_count;
    cur_map->is_new_entry = 0;

    // Note on pincount :
    // See also CUM-1335
    // We transfer all the shadow pins to the live map
    // the folks who have pincounts will eventually get to commit_lock() path
    // and realize that the map is now a shadow and will call map_get_live_map().
    // This would chip away the pincounts from shadow map
    // and they get to a live map which they already have pincounts transferred.

    // the live map has an extra pin for being the shadow.
    // this is removed during the flush callback

    cur_map->pinned = shadow_map->pinned;
    cur_map->snap_gen = shadow_map->snap_gen;
    memcpy(cur_map->entries, shadow_map->entries, sizeof(struct nuvo_map_table));

    map_entry->ptr = cur_map;


    struct nuvo_map_track *parent_shadow = parent->shadow_link;

    //if there is a parent shadow , it would point to the new shadow
    // make the parent shadow point to the live map instead
    // checkpoint code gets to the shadow map from the live map

    if (parent_shadow && (parent_shadow->state == NUVO_MAP_SHADOW) &&
        (parent_shadow->cp_gen == shadow_map->cp_gen))
    {
        nuvo_mutex_lock(&parent_shadow->mutex);
        struct nuvo_map_entry *map_entry_shadow = &parent_shadow->entries[nuvo_map_get_table_index(cur_map->base_offset,
                                                                                                   cur_map->level + 1)];
        if (map_entry_shadow->ptr == shadow_map)
        {
            map_entry_shadow->ptr = cur_map;
        }
        nuvo_mutex_unlock(&parent_shadow->mutex);
    }

    cur_map->shadow_link = shadow_map;
    shadow_map->shadow_link = cur_map;
    shadow_map->state = NUVO_MAP_SHADOW;
    shadow_map->cleaning_shadow = 1; //to distinguish this from the CP shadow
                                     // CP shadows have only pincount and we would like to assert that

    if (cur_map->level)
    {
        // lets adopt the shadow's children
        // also adopt the wait list of the shadow
        map_adopt_children_from_shadow(req, cur_map, shadow_map, comp_list);
    }

    //Since we are switching to the live map, let go of the shadow pincounts.
    unpin_count = (!shadow_map->level && req->first_map == req->last_map) ? 2 : 1;

    nuvo_map_shadow_unpin_multiple(shadow_map, unpin_count, comp_list);
    NUVO_ASSERT(shadow_map->pinned > 0); // since the shadow map is getting cleaned, it must have one pincount

    nuvo_mutex_unlock(&shadow_map->mutex);

    // put map on the pinned list
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_pinned_insert(cur_map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    *map = cur_map;
}

nuvo_return_t nuvo_map_shadow_reg(struct nuvo_dlist *map_list, struct nuvo_map_track *map)
{
    struct nuvo_map_track *cur_map = map;

    NUVO_ASSERT_MUTEX_HELD(&cur_map->mutex);
    NUVO_ASSERT(cur_map->state != NUVO_MAP_SHADOW);
    NUVO_ASSERT(cur_map->state != NUVO_MAP_CLEANING);

    // if map is cleaning, we turn the current map into shadow
    // otherwise we allocate a new map as the shadow

    struct nuvo_map_track *shadow_map = nuvo_dlist_remove_head_object(map_list, struct nuvo_map_track, list_node);
    if (shadow_map == NULL)
    {
        return (-NUVO_ENOMEM);
    }

    NUVO_ASSERT((shadow_map->state == NUVO_MAP_CLEAN_LIST) ||
                (shadow_map->state == NUVO_MAP_MIXED_LIST));
    NUVO_ASSERT(!(shadow_map->shadow_link));
    NUVO_ASSERT(!(cur_map->shadow_link));

    shadow_map->state = NUVO_MAP_SHADOW;
    shadow_map->cleaning_shadow = 0;
    shadow_map->level = cur_map->level;
    shadow_map->base_offset = cur_map->base_offset;
    shadow_map->lun = cur_map->lun;
    shadow_map->vol = cur_map->vol;
    shadow_map->parent = cur_map->parent;
    shadow_map->map_entry = cur_map->map_entry;
    shadow_map->mfl = cur_map->mfl;
    // shadows must be always on the prev gen of the CP.
    // CP is incremented on the live map always after the shadow
    // and hence the assert
    NUVO_ASSERT(cur_map->cp_gen == (nuvo_map_get_vol_cp(cur_map->vol) - 1));
    shadow_map->cp_gen = cur_map->cp_gen;
    MAP_SET_CP(shadow_map, cur_map->cp_gen);

    shadow_map->is_new_entry = 0;
    shadow_map->pinned = 0;

    //  Mark the current map clean, so that this map is not considered dirty, again for
    //  next CP. In addition, if this map is revisited again in this CP ( which is a bug in itself)
    //  we do not want this map to look dirty.
    //  Ideally we should be setting this in the flush done callback post the
    //  shadow write-out.
    //  But more dirties can come in before the flush cb. So, it would need
    //  more state maintenance in the map to clear this during the flush cb.

    //  If the shadow write out fails for some reason, we panic in the flush cb.
    //  So it is a fair assumption that once shadowed, the write out would succeed or the CP would fail.

    // With snapshots and GC, intermediate maps can be dirty without child being dirty
    // so we need to dirty the shadow on shadow itself
    shadow_map->is_dirty = cur_map->is_dirty;
    cur_map->is_dirty = 0;

    NUVO_LOG(map, 300, "vol:%p CLEAN map offset:%lu level:%d lun(%d)", map->lun->vol, map->base_offset,
             map->level, map->lun->snap_id);

    // clearing dirty during shadow avoids writing the same dirty blocks
    // repeatedly in CP.
    // Unforunately writes on clean L0 clean maps transfer the map address to the parent shadow entry for this child
    // so we cannot clear dirty on L0 maps without getting a new address.
    // So we need a better mechanism for L0 maps
    // Here we clean the parent maps is_dirty on shadow

    shadow_map->child_count = cur_map->child_count;
    shadow_map->is_new_entry = 0;
    shadow_map->pinned = 0;
    shadow_map->snap_gen = cur_map->snap_gen;

    cur_map->shadow_link = shadow_map;
    shadow_map->shadow_link = cur_map;

    memcpy(shadow_map->entries, cur_map->entries, sizeof(struct nuvo_map_table));

#ifdef MAP_DEBUG
    // Debug code to check the sanity of the entries array and the child count
    // must not contain shadows and child count must match the number of
    // inmem entries
    {
        int child_cnt = 0;

        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            if (shadow_map->entries[i].type == NUVO_ME_IN_MEM)
            {
                child_cnt++;
                NUVO_ASSERT(shadow_map->entries[i].ptr->state != NUVO_MAP_SHADOW);
            }
        }
        NUVO_ASSERT(child_cnt == shadow_map->child_count);
    }
#endif

    // if a parent is getting shadowed , it is possible that some of the children
    // are  "LOADING" from disk.
    // We dont want to write the entries on disk as LOADING because
    // a read on the loading children would get stuck.
    // so flip LOADING entries to MEDIA.

    if (shadow_map->level)
    {
        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            struct nuvo_map_entry *map_entry = &shadow_map->entries[i];

            if (map_entry->type == NUVO_ME_LOADING)
            {
                map_entry->type = NUVO_ME_MEDIA;
            }
        }
    }
    // pin cur map for the shadow link
    nuvo_map_pin_table(cur_map);

    return (0);
}

/* update leaf map entries for both active and peer cow lun
 * This is called in the multi lun case, needed for updating the snap lun
 * and is aware of the cow bit manipulation
 */
int map_snap_update_entries(struct nuvo_map_request *req,
                            struct nuvo_map_track   *map,
                            uint64_t                 checkpoint_gen,
                            uint_fast32_t            block_count,
                            struct nuvo_map_entry   *entries,
                            struct nuvo_map_entry   *new_entries,
                            struct nuvo_map_entry   *snap_entries)
{
    // save old entries if we are snap
    // on active
    // cow ->NONE

    struct nuvo_lun *lun = req->lun;
    int snap_update_count = 0;

    if (NUVO_LUN_IS_ACTIVE(lun))
    {
        /* percolate for L0 maps must have been done with commit lock*/
        NUVO_ASSERT(map->snap_gen >= req->snap_gen);
        for (uint_fast32_t i = 0; i < block_count; i++)
        {
            snap_entries[i].cow = NUVO_MAP_ENTRY_NONE; // initialize

            // Note if an entry is marked COW, use_blks and free_blks would ignore it
            // cow -> none, Dont free the old, But use the new block
            if (entries[i].cow == NUVO_MAP_ENTRY_COW)
            {
                snap_entries[i] = entries[i];
                snap_entries[i].cow = NUVO_MAP_ENTRY_COW; // apply this to snapshot and dont free the old
                new_entries[i].cow = NUVO_MAP_ENTRY_NONE; // use the new block
                snap_update_count++;
            }
            //none ->none, do free and do use
            else if (entries[i].cow == NUVO_MAP_ENTRY_NONE)
            {
                snap_entries[i] = entries[i];
            }

            entries[i] = new_entries[i];
            entries[i].cow = NUVO_MAP_ENTRY_NONE;
        }

        if (snap_update_count)
        {
            NUVO_MAP_SET_NONE(map);
        }

        nuvo_mfst_segment_use_blks(&map->vol->log_volume.mfst, block_count, new_entries);
        nuvo_mfst_segment_free_blks_for_cow(&map->vol->log_volume.mfst, block_count, snap_entries);
    }
    else
    {
        // dont dirty mfl-ed maps
        if (map->mfl || (NUVO_ME_IS_MFL_DONE(&map->map_entry)))
        {
            return (block_count);
        }

        for (uint_fast32_t i = 0; i < block_count; i++)
        {
            if (new_entries[i].cow == NUVO_MAP_ENTRY_COW)
            {
                // since we dont explictily prevent i/os after an unexport
                // Here we dont update a snap lun after it is freed.
                // cow writes happen only on shared entries
                NUVO_ASSERT(entries[i].cow == NUVO_MAP_ENTRY_SHARED);

                if (entries[i].cow == NUVO_MAP_ENTRY_SHARED)
                {
                    entries[i] = new_entries[i];
                    entries[i].cow = NUVO_MAP_ENTRY_COW;
                    snap_update_count++;
                }
            }
        }
        if (snap_update_count)
        {
            NUVO_MAP_SET_COW(map);
        }
    }

    //TODO TODO_SNAP re-check does a change always happen?

    // nuvo_map_commit lock must have set the cp_gen to the current cp_gen
    // and hence the assert below
    NUVO_ASSERT(map->cp_gen == checkpoint_gen);
    // mark table as dirty
    NUVO_LOG_COND(map, 100, true, "vol:%p DIRTY on lun(%d) map:%p media_addr:(%lu:%lu) offset:%lu "
                  "level:%d map->is_dirty:%d",
                  map->lun->vol, map->lun->snap_id, map,
                  map->map_entry.media_addr.parcel_index, map->map_entry.media_addr.block_offset,
                  map->base_offset, map->level, map->is_dirty);


    map->is_dirty = 1;
    return (snap_update_count);
}

void nuvo_map_shadow_path(struct nuvo_map_request *req, struct nuvo_map_track *map, uint64_t new_cp_gen, struct nuvo_dlist *comp_list)
{
    nuvo_return_t ret = 0;

    NUVO_ASSERT_MUTEX_HELD(&map->mutex);
    NUVO_ASSERT_MUTEX_HELD(&map->vol->mutex); // since this code path lets go of all the map locks
                                              // we cannot afford to stamp stale cp gens.
    uint_fast64_t target_offset = map->base_offset;
    uint_fast32_t target_level = map->level;

    struct nuvo_map_track *cur_map = map->lun->root_map;
    (void)comp_list;

    nuvo_mutex_unlock(&map->mutex);
    nuvo_mutex_lock(&cur_map->mutex);

    while (cur_map->level > target_level)
    {
        if (cur_map->shadow_link == NULL)
        {
            NUVO_ASSERT(cur_map->state != NUVO_MAP_CLEANING);

            ret = nuvo_map_shadow_reg(&req->map_list, cur_map);
            NUVO_ASSERT(ret >= 0);

            MAP_SET_CP(cur_map, new_cp_gen);
        }
        struct nuvo_map_track *next_map = cur_map->entries[nuvo_map_get_table_index(target_offset, cur_map->level)].ptr;

        nuvo_mutex_lock(&next_map->mutex);
        nuvo_mutex_unlock(&cur_map->mutex);

        cur_map = next_map;
    }
    if (cur_map->shadow_link == NULL)
    {
        NUVO_ASSERT(cur_map->state != NUVO_MAP_CLEANING);

        ret = nuvo_map_shadow_reg(&req->map_list, cur_map);
        NUVO_ASSERT(ret >= 0);

        MAP_SET_CP(cur_map, new_cp_gen);
    }

    NUVO_ASSERT(cur_map == map);
    // validate the shadow, debug op, can remove someday
    nuvo_validate_shadow(map->shadow_link);
    //let go of the map lock, the caller will reacquire the locks
    nuvo_mutex_unlock(&map->mutex);
}

/* unpdate leaf map entries */

uint_fast32_t  map_update_entries(struct nuvo_map_request *req,
                                  struct nuvo_map_track   *map,
                                  uint64_t                 checkpoint_gen,
                                  uint_fast32_t            block_count,
                                  struct nuvo_map_entry   *entries,
                                  struct nuvo_map_entry   *new_entries,
                                  struct nuvo_map_entry   *snap_entries,
                                  struct nuvo_media_addr  *old_media_addrs,
                                  bool                     do_cow_updates,
                                  uint_fast32_t           *succeeded_gc,
                                  uint_fast32_t           *failed_gc)
{
    NUVO_ASSERT_MUTEX_HELD(&map->mutex);
    NUVO_ASSERT(failed_gc == NULL || old_media_addrs != NULL);
    uint_fast32_t snap_count = 0;
    uint_fast32_t table_index = nuvo_map_get_table_index(req->block_start, 0);
    NUVO_LOG_COND(map, 30, !(map->base_offset),
                  "MAP UPDATE ENTRIES cb map:%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu)  (index:%d block_count:)%u"
                  " offset:%lu level:%d map->is_dirty:%d lun(%d) lun_state:%d lun_mfl_state:%d vol:%p",
                  map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                  map->map_entry.media_addr.block_offset, table_index,
                  block_count,
                  map->base_offset, map->level, map->is_dirty,
                  map->lun->snap_id, map->lun->lun_state, map->lun->mfl_state, map->lun->vol);

    if (old_media_addrs == NULL) //data update path
    {
        //only GC is allowed to come in after mfl

        if (!do_cow_updates)
        {
            //assert since nuvo_map_commit_lock must have bumped up the
            // cp for us.
            NUVO_ASSERT(map->cp_gen == checkpoint_gen);

            // mark table as dirty

            NUVO_LOG(map, 300, "vol:%p offset:%lu lun(%d)", map->lun->vol, map->base_offset, map->lun->snap_id);

            map->is_dirty = 1;

            nuvo_mfst_segment_use_blks(&map->vol->log_volume.mfst, block_count, new_entries);
            nuvo_mfst_segment_free_blks(&map->vol->log_volume.mfst, block_count, entries);

            // update the map
            for (uint_fast32_t i = 0; i < block_count; i++)
            {
                entries[i] = new_entries[i];
            }
        }
        else
        {
            snap_count = map_snap_update_entries(req, map, checkpoint_gen, block_count, entries, new_entries, snap_entries);
        }
    }
    else //GC update path
    {
        // TODO Possible optimization - It is possible that we will not end up dirtying the map
        // here.  That is a rare case so not optimizing yet since I don't want to think whether I
        // am missing something here and there is some assumption in the calling code that might break.
        // update the checkpoint_gen to current
        NUVO_ASSERT(map->cp_gen == checkpoint_gen);
        // if the map is marked for mfl, consider it as all freed by next cp
        // gc could be racing with a mfl
        // if mfl has happened, gc could consider the move a success.
        if (map->mfl || (!NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_ME_IS_MFL_DONE(&map->map_entry)))
        {
            (*succeeded_gc) += block_count;
            return (0);
        }
        // Conditionally update if the current entry is the same as the address we are moving data
        // from.  Otherwise don't.  This handles the case where a block was overwritten between the
        // time we decided to move the data and the call to update the media addr.

        for (uint_fast32_t i = 0; i < block_count; i++)
        {
            struct nuvo_map_entry  *entry = &entries[i];
            struct nuvo_map_entry  *new_entry = &new_entries[i];
            struct nuvo_media_addr *old_media_addr = &old_media_addrs[i];
            NUVO_ASSERT(new_entry->type == NUVO_ME_MEDIA);

            if (entry->type == NUVO_ME_MEDIA &&
                entry->media_addr.parcel_index == old_media_addr->parcel_index &&
                entry->media_addr.block_offset == old_media_addr->block_offset)
            {
                nuvo_mfst_segment_use_blks(&map->vol->log_volume.mfst, 1, new_entry);
                nuvo_mfst_segment_free_blks(&map->vol->log_volume.mfst, 1, entry);
                NUVO_ASSERT(entry->hash == new_entry->hash);
                entry->media_addr = new_entry->media_addr;
                (*succeeded_gc)++;
                // mark table as dirty
                map->is_dirty = 1;
            }
            else
            {
                (*failed_gc)++;
            }
        }
    }

    return (snap_count);
}

/* update sideways from shadow to live map
 * only called for intermediate maps
 * so can trust the shadow map (mostly).
 *
 * The not mostly case is as described below.
 * It is possible that an eviction updated the live map while
 * the shadow map update was in progress.
 * If the eviction updated the map to NONE/COW, we dont overwrite from shadow
 * If the eviction didnt touch the map because child was all COW/SHARED
 * shadow couldnt have been NONE/COW and we wont touch it in this case
 * neither would the shadow touch it
 *
 * Also note that:
 * a snap creation can make live all COW while shadow was created/written to disk
 * In this case, ie snap_gen of live map > snap_gen of shadow
 * We dont update the live map in this case
 * The shadow maps address and cow bit is however propgagated to the parent shadow
 * The ondisk image from CP must look like snapshot didnt happen at all
 * since the snapshot happened after the CP began
 *
 */
void map_entry_update(struct nuvo_map_track *shadow_link, struct nuvo_map_track *map)
{
    // regarding cow bit for L0 ,blindly trust the L0

    //  for L1 trust the one with the higher snap gen
    //  if they are equal,trust the shadow
    //  as shadow means the updated write out result

    //  => if a snap got created in the middle of the write out,
    //  the live map will have a higher snap gen
    //  and we wont overwrite the live map

    NUVO_ASSERT(shadow_link->snap_gen <= map->snap_gen);

    uint8_t cow = map->map_entry.cow;
    map->map_entry = shadow_link->map_entry;
    map->map_entry.cow = cow;

    if (!map->level) // for L0, there is no reason to touch the map
    {
        return;
    }

    // for interediate maps, preseve the map if they have a recent snap gen */

    if (shadow_link->snap_gen != map->snap_gen)
    {
        return;
    }

    if (NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_MAP_IS_NONE(shadow_link))
    {
        NUVO_MAP_SET_NONE(map);
    }
    else if (!NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_MAP_IS_COW(shadow_link))
    {
        NUVO_MAP_SET_COW(map);
    }
}

// roll up logic
// when do we mark the parent as mfl?
// when the last child count drops to zero and all entries are mfl done

int  map_parent_get_mfl_child_count(struct nuvo_map_track *parent)
{
    NUVO_ASSERT_MUTEX_HELD(&parent->mutex);
    NUVO_ASSERT(parent->level);
    uint_fast32_t mfl_cnt = 0;

    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        struct nuvo_map_entry *child_map_entry = &parent->entries[i];
        NUVO_ASSERT(child_map_entry->type != NUVO_ME_IN_MEM);

        if (NUVO_MEDIA_ADDR_FREE(&child_map_entry->media_addr))
        {
            mfl_cnt++;
        }
    }

    return (mfl_cnt);
}

/* update updwards, from a map to its parent or its shadow */
int map_parent_entry_update_nl(struct nuvo_map_track *map, struct nuvo_map_track *parent)
{
    NUVO_ASSERT_MUTEX_HELD(&map->mutex);
    NUVO_ASSERT_MUTEX_HELD(&parent->mutex);
    NUVO_ASSERT(map->snap_gen <= parent->snap_gen); //snap_gen travels from top to bottom

    struct nuvo_map_entry *entry = &parent->entries[nuvo_map_get_table_index(map->base_offset, parent->level)];
    uint8_t cow = entry->cow; // save cow , need to preseve if parent has the latest snap gen

    NUVO_ASSERT(map->map_entry.type != NUVO_ME_IN_MEM);
    NUVO_ASSERT(map->map_entry.type != NUVO_ME_LOADING);

    /* it is possible that a fault in and CP raced.
     * lets say cp is from cp gen 3->4
     * So parent loaded at 3  goes to fault in a child at 3
     * now Cp comes along and makes the parent at 4 and shadow at 3.
     * However the parent shadow doesnt have the child that is being faulted in
     * So when the child at 3 is being written it would try to copy the address
     * to the parent shadow. This entry exists as media/shared on parent
     * Henece a check and return and instead of an assert
     */
    //NUVO_ASSERT(entry->type == NUVO_ME_IN_MEM);
    //
    // CUM-2840 notes. In addition to the condition above,
    // the following condition is also pertinent to L>0 intersecting cleaning shadows.
    // This is since the intersecting cleaning shadow for a parent can begin and finish
    // later after a child shadow (albeit rarely).
    // In this case, the child shadow won't find its entry as a memory pointer
    // in the parent shadow, since the child must have been born after the birth
    // of the parent shadow. ( Note: Cleaning shadows have no children when we start writing them out)
    // So everything in the cleaning shadow must be of type "MEDIA ADDR"
    // So we will find that is entry is not "IN MEM" and we wont touch the shadow and return.
    if (entry->type != NUVO_ME_IN_MEM)
    {
        // a non zero value so that we dont attempt to flush for this case
        // if the value is zero we attempt to flush
        // zero should be returned by the last one who sees child count as zero
        // and we should only flush once to avoid double queueing.

        return (parent->child_count ? parent->child_count : 1);
    }

    NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(map->lun) && !map->base_offset), "PARENT-UPDATE map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d parent:%p offset:%lu level:%d \
                     is_dirty:%d mfl:%d lun snap_id:%d lun_mfl_state:%d",
                  map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                  map->map_entry.media_addr.block_offset,
                  map->base_offset, map->level, map->is_dirty,
                  parent, parent->base_offset, parent->level, parent->is_dirty, parent->mfl,
                  map->lun->snap_id, map->lun->mfl_state);

    // comments on why the below asserts arent necesarily true for map->mfl
    //if (map->mfl)
    //
    //       CUM-1843 The reported problem hits the following assert.
    //       The fix is to remove the assert.
    //       Think of vol close for a lun which is mfl in progress.
    //       A map gets mfled, map->mfl = 1 and is_dirty = 1, so map entry is
    //       mfl pending
    //       Now, close lun -> evict maps and we come here and the assert fires,
    //       so disabling this
    //       Also, we can't even check for is_dirty because close unconditionally cleans
    //       all the maps before evicting
    //       NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&map->map_entry));
    //
    //       double free assert: (parent is updated with zero map entry twice)
    //       This is possible in the following case.
    //       --a zero address map got replayed
    //       --we update the parent to have a zero map entry
    //       --lun delete continues, so the new mfl task would mark the map now again as
    //       mfl. An eviction is a double free now
    //
    //      NUVO_ASSERT(!NUVO_ME_IS_MFL_DONE(entry)); // no double free

    //      //!parent->mfl assert
    //      we might have to do redo MFL for parts of the tree.
    //      We might have updated the parent already during replay
    //      but repeating mfl would take us to a parent which is already MFLed
    //      NUVO_ASSERT(!parent->mfl);
    //}

    //roll up the child entry (normally a logger addres) to the parent map entry
    *entry = map->map_entry;

    NUVO_ASSERT(parent->child_count);
    parent->child_count--;
    parent->is_dirty |= map->is_new_entry;

    if (!parent->child_count && NUVO_LUN_MFL_IN_PROGRESS(map->lun))
    {
        int mfl_child_count = map_parent_get_mfl_child_count(parent);

        NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(parent->lun) && (mfl_child_count == NUVO_MAP_RADIX)),
                      "PARENT-MFLed :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d "
                      "map->is_dirty:%d parent:%p offset:%lu level:%d "
                      "is_dirty:%d mfl:%d lun(%d) lun_mfl_state:%d local mfl_child_count:%d child_count:%d",
                      map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                      map->map_entry.media_addr.block_offset,
                      map->base_offset, map->level, map->is_dirty,
                      parent, parent->base_offset, parent->level, parent->is_dirty, parent->mfl,
                      map->lun->snap_id, map->lun->mfl_state, mfl_child_count, parent->child_count);

        // during CP-rollup, the child count dropping must get all the MFLed children back
        // since CP roll up state would be set only for the CP after the L0 phase is over
        // However we cant determine the mfl_state correctly during replay
        // as we dont know whether the L0s were done by MFL
        // We can do this by logging the L0 done event
        // and resuming correctly
        // That is not done today and it is probably not necessary

        NUVO_ASSERT(map->lun->mfl_state != NUVO_LUN_MFL_CP_IN_PROGRESS || (mfl_child_count == NUVO_MAP_RADIX) ||
                    NUVO_LOGGER_IN_REPLAY(&map->vol->log_volume.logger))

        if (mfl_child_count == NUVO_MAP_RADIX)
        {
            // would have loved to have this assert
            // but this is not possible because GC can load and evict this map again
            // while roll up is going on
            // upper level maps have no op context
            // also think of replay where we repeat the mfl l0 works after replaying some of the parent maps
            //NUVO_ASSERT(!parent->mfl);
            parent->mfl = true;
            // if you are thinking why cant the logger do this for us,
            // then think of eviction code path where we may roll up with no logger
            // Also we shouldnt do this for dirty maps, because dirty maps must go through
            // the logger, lest we wont free the space in callback
            if (!parent->is_dirty)
            {
                if (!NUVO_MEDIA_ADDR_FREE(&parent->map_entry.media_addr))
                {
                    parent->is_dirty = true;
                }
                else
                {
                    NUVO_ME_SET_MFL_DONE(&parent->map_entry);
                }
            }
        }
    }

    // and fix up the cow bits of the parent map entry appropriately
    if (map->snap_gen == parent->snap_gen && !parent->mfl)
    {
        if ((NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_MAP_IS_NONE(map)))
        {
            NUVO_MAP_SET_NONE(parent);
        }
        else if (!NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_MAP_IS_COW(map))
        {
            NUVO_MAP_SET_COW(parent);
        }
    }
    else if (!parent->mfl) // parent has a higher snapgen, so restore COW bit
    {
        entry->cow = cow;
    }

    return (parent->child_count);
}

struct nuvo_map_track *map_get_live_map(struct nuvo_map_request *req, struct nuvo_map_track *map, struct nuvo_dlist *comp_list)
{
    uint_fast16_t unpin_count = 1;

    NUVO_ASSERT_MUTEX_HELD(&map->mutex);

    if (!map->level && req->first_map == req->last_map)
    {
        unpin_count = 2; //since there are two paths pointing here from fault in
    }

    // Note on pincount :
    // See also CUM-1335
    // When the shadow cleaning map is created, We had transferred all the shadow pins to the live map
    // the folks who have pincounts will eventually get to commit_lock() path
    // and realize that the map is now a shadow and will call map_get_live_map().
    // This would chip away the pincounts from shadow map  as we see below.
    // and they get to a live map which they already have pincounts transferred.

    // Note that we only need one hop to the live shadow.
    // We avoid the chain shadow (massacre:)) by making sure that the live map
    // is pinned and gets the shadow map's pincount which was taken for flushing itself (taken during nuvo_map_writer_add_map)
    // All of the pincount of the shadow including this one, is transferred to the live map.
    // So the live map cant go into the mixed list until the write out is complete.
    // So live map cant become CLEANING/SHADOW when it has a shadow  and this avoids the chain shadows.

    NUVO_ASSERT(map->state == NUVO_MAP_SHADOW);

    struct nuvo_map_track *map_primary = map->shadow_link;
    nuvo_mutex_unlock(&map->mutex);
    nuvo_mutex_lock(&map_primary->mutex);
    nuvo_mutex_lock(&map->mutex);

    // re-assert now that we lost the lock.
    // things should be fine since we havent lost the pincounts on the shadow yet.
    // the shadow live map link is detached on the last pincount of the shadow

    NUVO_ASSERT(map_primary->shadow_link == map);

    // if primary has a shadow, it should not be cleaning or shadow
    // refer to the note on chain shadow above
    NUVO_ASSERT(map_primary->state != NUVO_MAP_CLEANING);
    NUVO_ASSERT(map_primary->state != NUVO_MAP_SHADOW);

    // unpin the shadow map
    // free it if there are no other users
    nuvo_map_shadow_unpin_multiple(map, unpin_count, comp_list);

    nuvo_mutex_unlock(&map->mutex);
    return (map_primary);
}

// debug code written to validate the child maps of parent shadow.
// validates the cp gen of each child as well as the
// parent shadows child count
// useful for debugging req->prev_gen == map_cp_gen panic.
// may be called anytime on a parent shadow.


bool nuvo_validate_shadow(struct nuvo_map_track *map)
{
    (void)map;

#ifndef NDEBUG
    int child_count = 0;
    struct nuvo_map_track *live_map = map->shadow_link;
    NUVO_ASSERT_MUTEX_HELD(&live_map->mutex);
    bool do_locked = false;

    nuvo_mutex_lock(&map->mutex);

    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        struct nuvo_map_entry *entry = &map->entries[i];
        if (entry->type == NUVO_ME_IN_MEM)
        {
            do_locked = false;
            child_count++;
            struct nuvo_map_track *child_map = entry->ptr;
            if (child_map->mutex.owner != pthread_self())
            {
                nuvo_mutex_lock(&child_map->mutex);
                do_locked = true;
            }
            NUVO_ASSERT(child_map->state != NUVO_MAP_SHADOW);
            if (!child_map->shadow_link)
            {
                NUVO_ASSERT(child_map->cp_gen == (nuvo_map_get_vol_cp(map->vol) - 1));
            }
            else if (!child_map->shadow_link->cleaning_shadow)
            {
                NUVO_ASSERT(child_map->cp_gen == (nuvo_map_get_vol_cp(map->vol)));
            }
            if (do_locked)
            {
                nuvo_mutex_unlock(&child_map->mutex);
            }
        }
    }

    NUVO_ASSERT(child_count == map->child_count);
    nuvo_mutex_unlock(&map->mutex);
#endif
    return (true);
}

void nuvo_map_shadow_unpin_multiple(struct nuvo_map_track *map, uint_fast16_t unpin_count, struct nuvo_dlist *comp_list)
{
    // unpin and unlock the map
    NUVO_ASSERT_MUTEX_HELD(&map->mutex);
    NUVO_ASSERT(map->state == NUVO_MAP_SHADOW);

    for (uint_fast16_t i = 0; i < unpin_count; i++)
    {
        nuvo_map_shadow_unpin_table(map, comp_list);
    }
}

void nuvo_map_commit_lock(struct nuvo_map_request *req)
{
    // This interface is only to be used for L0 maps
    // see also nuvo_map_rewrite_lock for why

    NUVO_ASSERT(req->first_map->level == req->last_map->level);
    NUVO_ASSERT(!req->first_map->level);
    // We need to lock the map tables in the write range, and then copy
    //  the new map entries into the map.
    // We must also need inform the segment table of the newly used blocks,
    //  and the previous blocks that end up being un-mapped.

    // lock the volume map state so we can check gen
    nuvo_return_t     ret = 0;
    struct nuvo_dlist comp_list;
    nuvo_dlist_init(&comp_list);
    uint64_t checkpoint_gen = NUVO_MAP_INVALID_CP_GEN;


    struct nuvo_vol *vol = req->first_map->vol;
start_commit:
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    // assert that checkpoint didnt change when we retry on losing map locks
    // we have vol lock held, checkpoint_gen shouldnt change, but
    // assert to confirm
    if (checkpoint_gen == NUVO_MAP_INVALID_CP_GEN)
    {
        checkpoint_gen = nuvo_map_get_vol_cp(vol);
    }
    else
    {
        NUVO_ASSERT(checkpoint_gen == nuvo_map_get_vol_cp(vol));
    }


    // we have two paths, depending on whether the first and last map
    //  are the same
    if (req->first_map == req->last_map)
    {
        // verify maps are same, though it is implied
        NUVO_ASSERT(nuvo_map_get_base_offset(req->block_start, 0) == nuvo_map_get_base_offset(req->block_last, 0));
        uint_fast32_t block_count = req->block_last - req->block_start + 1;
        uint_fast32_t table_index = nuvo_map_get_table_index(req->block_start, 0);
        // double check that we don't span tables
        NUVO_ASSERT(table_index + block_count <= NUVO_MAP_RADIX);

        // all entries are within one map
        struct nuvo_map_track *map = req->first_map;

        nuvo_mutex_lock(&map->parent->mutex);
        //NUVO_MUTEX_LOCK_IF_REQD(&map->parent->mutex, multi_lun);

        nuvo_mutex_lock(&map->mutex);

        // make sure we are at the right level of the table
        //NUVO_ASSERT(map->level == 0);
        // double check that this is the right table
        NUVO_ASSERT(map->base_offset == nuvo_map_get_base_offset(req->block_start, map->level));

        // check if we are the shadow
        if (map->state == NUVO_MAP_SHADOW)
        {
            // switch us over to the primary
            map = map_get_live_map(req, map, &comp_list);
            // update request proactively, if we have to retry on losing locks after shadow_path
            req->first_map = map;
            req->last_map = map;
        }

        if (map->state == NUVO_MAP_CLEANING)
        {
            // map is being cleaned, we must shadow it before we modify it
            // determine if the map being cleaned is part of the old checkpoint
            if (map->cp_gen < checkpoint_gen)
            {
                // map being cleaned needs to be put in the checkpoint shadow tree
                if (map->parent->shadow_link == NULL)
                {
                    nuvo_mutex_unlock(&map->mutex);
                    nuvo_map_shadow_path(req, map->parent, checkpoint_gen, &comp_list);
                    goto start_commit;
                }
            }

            nuvo_map_shadow_cleaning(req, &map, &comp_list);
            // update request proactively, if we have to retry on losing locks after shadow_path
            req->first_map = map;
            req->last_map = map;

            MAP_SET_CP(map, checkpoint_gen);
        }
        else
        {
            if (map->cp_gen < checkpoint_gen)
            {
                // map was last modified before last checkpoint
                if (map->is_dirty != 0)
                {
                    // map is dirty, so we must shadow it
                    if (map->parent->shadow_link == NULL)
                    {
                        // parent has no shadow, needs to be shadowed
                        nuvo_mutex_unlock(&map->mutex);
                        nuvo_map_shadow_path(req, map->parent, checkpoint_gen, &comp_list);
                        goto start_commit;
                    }
                    ret = nuvo_map_shadow_reg(&req->map_list, map);
                    NUVO_ASSERT(ret >= 0);

                    // we should start write out here
                    nuvo_mutex_lock(&map->shadow_link->mutex);
                    nuvo_map_writer_add_map(map->shadow_link, NUVO_MW_FLUSH_AUTO);
                }
                else
                {
                    // map is clean, we need to save the map_entry for this map
                    // in the parent's shadow
                    if (map->parent->shadow_link == NULL)
                    {
                        // parent has no shadow, needs to be shadowed
                        nuvo_mutex_unlock(&map->mutex);
                        nuvo_map_shadow_path(req, map->parent, checkpoint_gen, &comp_list);
                        goto start_commit;
                    }

                    // save map entry
                    nuvo_mutex_lock(&map->parent->shadow_link->mutex);
                    if (!map_parent_entry_update_nl(map, map->parent->shadow_link))
                    {
                        nuvo_map_writer_add_map(map->parent->shadow_link, NUVO_MW_FLUSH_AUTO);
                    }
                    else
                    {
                        nuvo_mutex_unlock(&map->parent->shadow_link->mutex);
                    }
                }
                // do this proactively during commit lock itself
                // because snap luns may not get written
                // if the active doesnt have any cows.
                // so you dont want the maps to be shadowed but not cp_gen updated.

                MAP_SET_CP(map, checkpoint_gen);
            }

            NUVO_ASSERT(map->cp_gen == checkpoint_gen);
        }


        // we're done with the parent, unlock it
        nuvo_mutex_unlock(&map->parent->mutex);

        req->first_map = map;
        req->last_map = map;
    }
    else
    {
        // entries are split between two maps
        uint_fast32_t first_index = nuvo_map_get_table_index(req->block_start, 0);
        uint_fast32_t first_count = NUVO_MAP_RADIX - first_index;

        uint_fast32_t last_index = nuvo_map_get_table_index(req->block_last, 0);
        uint_fast32_t last_count = last_index + 1;

        NUVO_ASSERT(first_count + last_count == req->block_last - req->block_start + 1);

        struct nuvo_map_track *first_map = req->first_map;
        struct nuvo_map_track *last_map = req->last_map;

        nuvo_mutex_lock(&first_map->parent->mutex);

        if (last_map->parent != first_map->parent)
        {
            nuvo_mutex_lock(&last_map->parent->mutex);
        }

        nuvo_mutex_lock(&first_map->mutex);
        nuvo_mutex_lock(&last_map->mutex);

        // make sure we are at the right level of the table
        NUVO_ASSERT(first_map->level == 0);
        NUVO_ASSERT(last_map->level == 0);
        // double check that this is the right table
        NUVO_ASSERT(first_map->base_offset == nuvo_map_get_base_offset(req->block_start, 0));
        NUVO_ASSERT(last_map->base_offset == nuvo_map_get_base_offset(req->block_last, 0));

        // check if we are the shadow

        if (first_map->state == NUVO_MAP_SHADOW)
        {
            // switch us over to the primary
            first_map = map_get_live_map(req, first_map, &comp_list);
            req->first_map = first_map;
        }
        while (last_map->state == NUVO_MAP_SHADOW)
        {
            // switch us over to the primary
            last_map = map_get_live_map(req, last_map, &comp_list);
            req->last_map = last_map;
        }

        // check if we need to shadow the map
        if (first_map->state == NUVO_MAP_CLEANING)
        {
            // map is being cleaned, we must shadow it before we modify it
            if (first_map->cp_gen < checkpoint_gen)
            {
                // map being cleaned needs to be put in the checkpoint shadow tree
                if (first_map->parent->shadow_link == NULL)
                {
                    nuvo_mutex_unlock(&req->first_map->mutex);
                    nuvo_mutex_unlock(&req->last_map->mutex);
                    if (last_map->parent != first_map->parent)
                    {
                        nuvo_mutex_unlock(&last_map->parent->mutex);
                    }

                    nuvo_map_shadow_path(req, first_map->parent, checkpoint_gen, &comp_list);

                    goto start_commit;
                }
            }
            nuvo_map_shadow_cleaning(req, &first_map, &comp_list);
            MAP_SET_CP(first_map, checkpoint_gen);
            req->first_map = first_map;
        }
        else
        {
            if (first_map->cp_gen < checkpoint_gen)
            {
                // map was last modified before last checkpoint
                if (first_map->is_dirty != 0)
                {
                    // map is dirty, so we must shadow it
                    if (first_map->parent->shadow_link == NULL)
                    {
                        // parent has no shadow, needs to be shadowed
                        nuvo_mutex_unlock(&first_map->mutex);
                        nuvo_mutex_unlock(&last_map->mutex);
                        if (last_map->parent != first_map->parent)
                        {
                            nuvo_mutex_unlock(&last_map->parent->mutex);
                        }

                        nuvo_map_shadow_path(req, first_map->parent, checkpoint_gen, &comp_list);
                        goto start_commit;
                    }
                    ret = nuvo_map_shadow_reg(&req->map_list, first_map);
                    NUVO_ASSERT(ret >= 0);
                    // we should start write out here
                    nuvo_mutex_lock(&first_map->shadow_link->mutex);
                    nuvo_map_writer_add_map(first_map->shadow_link, NUVO_MW_FLUSH_AUTO);
                }
                else
                {
                    // map is clean, we need to save the map_entry for this map
                    // in the parent's shadow
                    if (first_map->parent->shadow_link == NULL)
                    {
                        // parent has no shadow, needs to be shadowed
                        nuvo_mutex_unlock(&first_map->mutex);
                        nuvo_mutex_unlock(&last_map->mutex);
                        if (last_map->parent != first_map->parent)
                        {
                            nuvo_mutex_unlock(&last_map->parent->mutex);
                        }

                        nuvo_map_shadow_path(req, first_map->parent, checkpoint_gen, &comp_list);
                        goto start_commit;
                    }

                    nuvo_mutex_lock(&first_map->parent->shadow_link->mutex);

                    if (!map_parent_entry_update_nl(first_map, first_map->parent->shadow_link))
                    {
                        nuvo_map_writer_add_map(first_map->parent->shadow_link, NUVO_MW_FLUSH_AUTO);
                    }
                    else
                    {
                        nuvo_mutex_unlock(&first_map->parent->shadow_link->mutex);
                    }
                }
            }
            MAP_SET_CP(first_map, checkpoint_gen);
        }

        // check if we need to shadow the map
        if (last_map->state == NUVO_MAP_CLEANING)
        {
            // map is being cleaned, we must shadow it before we modify it
            if (last_map->cp_gen < checkpoint_gen)
            {
                // map being cleaned needs to be put in the checkpoint shadow tree
                if (last_map->parent->shadow_link == NULL)
                {
                    nuvo_mutex_unlock(&req->first_map->mutex);
                    nuvo_mutex_unlock(&req->last_map->mutex);
                    if (last_map->parent != first_map->parent)
                    {
                        nuvo_mutex_unlock(&req->first_map->parent->mutex);
                    }

                    nuvo_map_shadow_path(req, last_map->parent, checkpoint_gen, &comp_list);
                    goto start_commit;
                }
            }
            nuvo_map_shadow_cleaning(req, &last_map, &comp_list);
            req->last_map = last_map;
            MAP_SET_CP(last_map, checkpoint_gen);
        }
        else
        {
            if (last_map->cp_gen < checkpoint_gen)
            {
                // map was last modified before last checkpoint
                if (last_map->is_dirty != 0)
                {
                    // map is dirty, so we must shadow it
                    if (last_map->parent->shadow_link == NULL)
                    {
                        // parent has no shadow, needs to be shadowed
                        nuvo_mutex_unlock(&req->first_map->mutex);
                        nuvo_mutex_unlock(&req->last_map->mutex);

                        if (last_map->parent != first_map->parent)
                        {
                            nuvo_mutex_unlock(&req->first_map->parent->mutex);
                        }

                        nuvo_map_shadow_path(req, last_map->parent, checkpoint_gen, &comp_list);
                        goto start_commit;
                    }
                    ret = nuvo_map_shadow_reg(&req->map_list, last_map);
                    NUVO_ASSERT(ret >= 0);
                    // we should start write out here
                    nuvo_mutex_lock(&last_map->shadow_link->mutex);
                    nuvo_map_writer_add_map(last_map->shadow_link, NUVO_MW_FLUSH_AUTO);
                }
                else
                {
                    // map is clean, we need to save the map_entry for this map
                    // in the parent's shadow
                    if (last_map->parent->shadow_link == NULL)
                    {
                        // parent has no shadow, needs to be shadowed
                        nuvo_mutex_unlock(&req->first_map->mutex);
                        nuvo_mutex_unlock(&req->last_map->mutex);
                        if (last_map->parent != first_map->parent)
                        {
                            nuvo_mutex_unlock(&req->first_map->parent->mutex);
                        }

                        nuvo_map_shadow_path(req, last_map->parent, checkpoint_gen, &comp_list);
                        goto start_commit;
                    }

                    // save map entry
                    nuvo_mutex_lock(&last_map->parent->shadow_link->mutex);
                    if (!map_parent_entry_update_nl(last_map, last_map->parent->shadow_link))
                    {
                        nuvo_map_writer_add_map(last_map->parent->shadow_link, NUVO_MW_FLUSH_AUTO);
                    }
                    else
                    {
                        nuvo_mutex_unlock(&last_map->parent->shadow_link->mutex);
                    }
                }
            }
            MAP_SET_CP(last_map, checkpoint_gen);
        }


        // we're done with the parents, we can unlock them

        nuvo_mutex_unlock(&first_map->parent->mutex);

        if (first_map->parent != last_map->parent)
        {
            nuvo_mutex_unlock(&last_map->parent->mutex);
        }

        // unlock the maps, and we're done

        // we were proactive to update the req maps
        // double check
        NUVO_ASSERT(req->first_map == first_map);
        NUVO_ASSERT(req->last_map == last_map);
    }


    // the maps must be on the latest cp
    // Also req->cp_commit_gen must be the latest cp
    // since we hold a vol lock across nuvo_map_commit_lock
    // on the active and the pit lun

    map_percolate_cow_for_inmem_L0(req, req->first_map);

    NUVO_ASSERT(req->first_map->cp_gen == req->cp_commit_gen);
    NUVO_ASSERT(req->first_map->cp_gen == nuvo_map_get_vol_cp(req->first_map->vol));

    if (req->first_map != req->last_map)
    {
        map_percolate_cow_for_inmem_L0(req, req->last_map);

        NUVO_ASSERT(req->last_map->cp_gen == req->cp_commit_gen);
        NUVO_ASSERT(req->last_map->cp_gen == nuvo_map_get_vol_cp(req->last_map->vol));
    }
}

void nuvo_map_request_unlock(struct nuvo_map_request *req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);

    nuvo_map_unpin_table(req->first_map, &comp_list);
    nuvo_map_unpin_table(req->last_map, &comp_list);

    nuvo_mutex_unlock(&req->last_map->mutex);

    if (req->first_map != req->last_map)
    {
        nuvo_mutex_unlock(&req->first_map->mutex);
    }
    // clean up anything left over on this req
    map_request_free(req, &comp_list);

    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }
}

void nuvo_map_commit_unlock(struct nuvo_map_request *req)
{
    NUVO_ASSERT(!req->first_map->level);

    nuvo_map_request_unlock(req);
}

// GC uses this interface to lock the maps prior to dirtying the maps
// The need of a different interface is primarily because GC may also need to dirty
// intermediate maps(L>0) and nuvo_map_commit_lock cannot handle the shadowing and cleaning
// for L>0 maps.
// It works only for L0 maps primarily because the map shadow for the current cp
// is written out immediately.
// For L>0 maps, all the children must be written out.

// This also could cause parents getting written out before children making map replay unhappy.
// See the replay stack in CUM-1318 where we see map entries which have already children
// aka the assert for child count must be zero

// Refer to map_percolate_cow_for_inmem_intermediate() which needs to do this for L>0 maps
// post a pit create.
// And cp would do top to bottom shadowing correctly.

// Thankfully, GC only needs to dirty the interemdiate maps
// and GC would be happy even if the next CP picks it up as GC fires a CP after dirty ops
// So we just lock and dirty the map
// so dirty both for L0 and L>0 maps
//
// We also dont handle CLEANING L>0 maps as of today.
// This is a bug (CUM-1315)
// And this shouldnt affect the map_rewrite functionality though
// as shadows and cleaning will already have a different address.
// And this is the case for L0 maps already

void nuvo_map_rewrite_lock(struct nuvo_map_request *req)
{
    // We know that GC always asks for one block as it wants a given a map.
    // But still it is possible that req->first_map != req->last_map,
    // as it is possible that one map is SHADOW and the other is not.
    // This is because fault in code does two fault ins, one for fault-in for the starting address
    // and one for the last address.
    // This is not atomic since another write/fault in can come in the middle of the two fault ins.
    // We handle this in the below code and dont assume req->first_map == req->last_map.

    // The only requirement for map_rewrite is that map be written to a new location which
    // is the default case of SHADOW maps
    // as SHADOWs are getting written out as we speak.

    nuvo_mutex_lock(&req->first_map->mutex);

    if (req->first_map != req->last_map)
    {
        nuvo_mutex_lock(&req->last_map->mutex);
    }

    // we dont care if this is a SHADOW or CLEANING map.
    // gc just wants these map to be written out and get a new address
    // if the maps are SHADOW or CLEANING, they would anway get a new address.

    // The caller will mark the map as dirty even though this is SHADOW/CLEANING.
    // For CLEANING it is guaranteed that a flush callback will clear the dirty.
    // For shadow, we would call unpins in nuvo_map_rewrite_unlock
    // which would clear the dirty
}

void nuvo_map_rewrite_unlock(struct nuvo_map_request *req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    // unpin and unlock

    struct nuvo_map_track *map = req->first_map;

    for (int i = 0; i < 2; i++)  // twice, one for first_map and one for last_map
    {
        if (map->state == NUVO_MAP_SHADOW)
        {
            nuvo_map_shadow_unpin_table(map, &comp_list);
        }
        else
        {
            nuvo_map_unpin_table(map, &comp_list);
        }
        map = req->last_map;
    }
    nuvo_mutex_unlock(&req->first_map->mutex);

    if (req->first_map != req->last_map)
    {
        nuvo_mutex_unlock(&req->last_map->mutex);
    }

    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }
}

static void nuvo_map_read_and_pin_sync_cb(struct nuvo_map_request *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t *)req->tag.ptr;

    nuvo_mutex_unlock(sync_signal);
}

void nuvo_map_read_and_pin_sync(struct nuvo_map_request *req,
                                bool                     pin,
                                struct nuvo_map_entry   *entries,
                                uint_fast32_t           *parcel_descs)
{
    nuvo_map_read_and_pin_sync_impl(req, NULL, pin, entries, parcel_descs, false /*multi_lun*/);
}

void nuvo_map_multi_lun_read_sync(struct nuvo_map_request *map_req,
                                  bool                     pin,
                                  struct nuvo_map_request *map_req_active,
                                  struct nuvo_map_entry   *entries,
                                  uint_fast32_t           *parcel_descs)
{
    nuvo_map_read_and_pin_sync_impl(map_req, map_req_active, pin /*pin*/,
                                    entries, parcel_descs, true /*multi_lun*/);
}

void nuvo_map_read_and_pin_sync_impl(struct nuvo_map_request *map_req_snap,
                                     struct nuvo_map_request *map_req_active,
                                     bool                     pin,
                                     struct nuvo_map_entry   *entries,
                                     uint_fast32_t           *parcel_descs,
                                     bool                     multi_lun)
{
    nuvo_return_t ret;
    nuvo_mutex_t  sync_signal;

    ret = nuvo_mutex_init(&sync_signal);
    if (ret < 0)
    {
        map_req_snap->status = -NUVO_ENOMEM;
        return;
    }
    nuvo_mutex_lock(&sync_signal);

    map_req_snap->callback = nuvo_map_read_and_pin_sync_cb;
    map_req_snap->tag.ptr = &sync_signal;

    if (multi_lun)
    {
        nuvo_map_multi_lun_read(map_req_snap, map_req_active, entries, pin);
    }
    else
    {
        nuvo_map_single_lun_read(map_req_snap, entries, pin);
    }
    nuvo_map_read_get_parcel_desc_async(map_req_snap, entries, parcel_descs);

    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);
}

void nuvo_map_read_and_pin_cb(struct nuvo_mfst_map_open *pin_req)
{
    struct nuvo_map_request *map_req = (struct nuvo_map_request *)pin_req->tag.ptr;

    // if it failed, unpin and return error
    if (pin_req->status < 0)
    {
        nuvo_mfst_unpin(pin_req->mfst, pin_req->num_map_entries, pin_req->map_entry);
        map_req->status = pin_req->status;
    }
    else
    {
        map_req->status = 0;
    }

    nuvo_map_request_complete(map_req, true);
    // run allocator since we've probably freed some maps
    nuvo_map_alloc_run();
}

void
nuvo_map_read_get_parcel_desc_async(struct nuvo_map_request *req,
                                    struct nuvo_map_entry   *entries,
                                    uint_fast32_t           *parcel_descs)
{
    uint_fast64_t block_count = req->block_last - req->block_start + 1;
    // open parcel descriptors to the parcels we will need to read from
    struct nuvo_mfst_map_open *pin_req = &req->pin_req;

    pin_req->mfst = &req->first_map->vol->log_volume.mfst;
    pin_req->tag.ptr = req;
    pin_req->num_map_entries = block_count;
    pin_req->map_entry = entries;
    pin_req->pds = parcel_descs;
    pin_req->callback = nuvo_map_read_and_pin_cb;
    nuvo_mfst_open_async(pin_req);
}

void nuvo_map_read_lock(struct nuvo_map_request *req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);

    // both tables should now be pinned, need to lock them
    if (req->first_map == req->last_map)
    {
        nuvo_mutex_lock(&req->first_map->mutex);

        // check if we are the shadow
        uint_fast16_t unpin_count = 2;
        while (req->first_map->state == NUVO_MAP_SHADOW)
        {
            // switch us over to the primary
            struct nuvo_map_track *map_primary = req->first_map->shadow_link;
            nuvo_mutex_unlock(&req->first_map->mutex);
            nuvo_mutex_lock(&map_primary->mutex);
            nuvo_mutex_lock(&req->first_map->mutex);
            // if primary has a shadow, it should not be cleaning
            NUVO_ASSERT(map_primary->state != NUVO_MAP_CLEANING);

            // unpin the shadow map
            // free it if there are no other users
            req->first_map->pinned -= unpin_count;
            unpin_count = 1;
            if (req->first_map->pinned == 0)
            {
                // shadow is now unused, free it
                req->first_map->lun = NULL;
                req->first_map->vol = NULL;
                req->first_map->parent = NULL;

                req->first_map->state = NUVO_MAP_CLEAN_LIST;
                nuvo_mutex_lock(&nuvo_map->list_mutex);
                nuvo_map_clean_insert_tail(req->first_map, &comp_list);
                if (map_primary->shadow_link == req->first_map)
                {
                    map_primary->shadow_link = NULL;
                }
                nuvo_mutex_unlock(&nuvo_map->list_mutex);
            }

            nuvo_mutex_unlock(&req->first_map->mutex);

            req->first_map = map_primary;
            req->last_map = map_primary;
        }
    }
    else
    {
        nuvo_mutex_lock(&req->first_map->mutex);
        nuvo_mutex_lock(&req->last_map->mutex);

        // check if we are the shadow
        while (req->first_map->state == NUVO_MAP_SHADOW)
        {
            // switch us over to the primary
            struct nuvo_map_track *map_primary = req->first_map->shadow_link;
            nuvo_mutex_unlock(&req->first_map->mutex);
            nuvo_mutex_lock(&map_primary->mutex);
            nuvo_mutex_lock(&req->first_map->mutex);
            // if primary has a shadow, it should not be cleaning
            NUVO_ASSERT(map_primary->state != NUVO_MAP_CLEANING);

            // unpin the shadow map
            // free it if there are no other users
            req->first_map->pinned--;
            if (req->first_map->pinned == 0)
            {
                // shadow is now unused, free it
                req->first_map->lun = NULL;
                req->first_map->vol = NULL;
                req->first_map->parent = NULL;

                req->first_map->state = NUVO_MAP_CLEAN_LIST;
                nuvo_mutex_lock(&nuvo_map->list_mutex);
                nuvo_map_clean_insert_tail(req->first_map, &comp_list);
                if (map_primary->shadow_link == req->first_map)
                {
                    map_primary->shadow_link = NULL;
                }
                nuvo_mutex_unlock(&nuvo_map->list_mutex);
            }

            nuvo_mutex_unlock(&req->first_map->mutex);

            req->first_map = map_primary;
        }
        while (req->last_map->state == NUVO_MAP_SHADOW)
        {
            // switch us over to the primary
            struct nuvo_map_track *map_primary = req->last_map->shadow_link;
            nuvo_mutex_unlock(&req->last_map->mutex);
            nuvo_mutex_lock(&map_primary->mutex);
            nuvo_mutex_lock(&req->last_map->mutex);
            // if primary has a shadow, it should not be cleaning
            NUVO_ASSERT(map_primary->state != NUVO_MAP_CLEANING);

            // unpin the shadow map
            // free it if there are no other users
            req->last_map->pinned--;
            if (req->last_map->pinned == 0)
            {
                // shadow is now unused, free it
                req->last_map->lun = NULL;
                req->last_map->vol = NULL;
                req->last_map->parent = NULL;

                req->last_map->state = NUVO_MAP_CLEAN_LIST;
                nuvo_mutex_lock(&nuvo_map->list_mutex);
                nuvo_map_clean_insert_tail(req->last_map, &comp_list);
                if (map_primary->shadow_link == req->last_map)
                {
                    map_primary->shadow_link = NULL;
                }
                nuvo_mutex_unlock(&nuvo_map->list_mutex);
            }

            nuvo_mutex_unlock(&req->last_map->mutex);

            req->last_map = map_primary;
        }
    }

    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }
}

void nuvo_map_read_unlock(struct nuvo_map_request *req)
{
    nuvo_map_request_unlock(req);
}

bool
map_read_entry(struct nuvo_map_request *req, struct nuvo_map_track *map,
               struct nuvo_map_entry *map_entry,
               struct nuvo_map_entry *entry, /*output entry*/
               bool multi_lun, bool pin)
{
    bool is_cow = false;
    bool do_pin = false;

    if (!NUVO_LUN_IS_ACTIVE(req->lun))
    {
        *entry = *map_entry;
        is_cow = ((entry->cow == NUVO_MAP_ENTRY_COW));

        // on snap luns, pin if cow
        if (is_cow)
        {
            do_pin = true;
        }
    }
    else
    {
        /* in multi lun the snap entry must be already read ,
         * it must be SHARED or COW */
        if (multi_lun)
        {
            NUVO_ASSERT((entry->cow == NUVO_MAP_ENTRY_SHARED) ||
                        (entry->cow == NUVO_MAP_ENTRY_COW));
        }

        uint8_t cow = map_entry->cow;

        /* fabricated cow bit for not yet updated leaf maps*/

        /* note that this is read path
         * so we dont bother to dirty the child map
         * and play a trick of fabricating the cow bit if the gen numbers dont match
         * as if the child were right in memory
         */
        if (req->snap_gen > map->snap_gen)
        {
            cow = NUVO_MAP_ENTRY_COW;
        }

        // multi lun read is a ror read
        // So the shared entry on snap must be COW on active
        if (!multi_lun || (entry->cow == NUVO_MAP_ENTRY_SHARED))
        {
            if (multi_lun && (entry->cow == NUVO_MAP_ENTRY_SHARED))
            {
                NUVO_ASSERT(cow == NUVO_MAP_ENTRY_COW);
            }

            *entry = *map_entry;
            entry->cow = cow;
            is_cow = ((cow == NUVO_MAP_ENTRY_COW));
        }
        // on active always pin a non multi lun read
        // on active pin a cow multi lun read

        if (!multi_lun || is_cow)
        {
            do_pin = true;
        }
    }

    // pin when we are asked to pin and need to pin
    // specifically none blocks on a multi lun redirected read must not be pinned
    if (pin && do_pin)
    {
        NUVO_ASSERT(req->op != NUVO_MAP_REQUEST_OP_DIFF);
        nuvo_mfst_pin(&req->first_map->vol->log_volume.mfst, 1, entry);
    }
    return (is_cow);
}

uint_fast32_t  nuvo_map_read_entries(struct nuvo_map_request *req,
                                     struct nuvo_map_entry   *entries,
                                     bool                     pin,
                                     bool                     multi_lun)
{
    uint_fast64_t block_count = req->block_last - req->block_start + 1;
    uint_fast32_t cow_cnt = 0;

    // both tables should now be pinned, need to lock them
    if (req->first_map == req->last_map)
    {
        // read entries for request and pin the blocks
        NUVO_ASSERT(nuvo_map_get_base_offset(req->block_start, 0) == nuvo_map_get_base_offset(req->block_last, 0));
        uint_fast32_t table_index = nuvo_map_get_table_index(req->block_start, 0);
        // double check that we don't span tables
        NUVO_ASSERT(table_index + block_count <= NUVO_MAP_RADIX);
        // make sure we are at the right level of the table
        NUVO_ASSERT(req->first_map->level == 0);
        // double check that this is the right table
        NUVO_ASSERT(req->first_map->base_offset == nuvo_map_get_base_offset(req->block_start, 0));
        // copy the map entries to return array
        for (uint_fast32_t i = 0; i < block_count; i++)
        {
            struct nuvo_map_entry *map_entry = &req->first_map->entries[table_index + i];
            cow_cnt += map_read_entry(req, req->first_map, map_entry, &entries[i], multi_lun, pin);
        }
    }
    else
    {
        // read entries for request and pin the blocks
        uint_fast32_t first_index = nuvo_map_get_table_index(req->block_start, 0);
        uint_fast32_t last_index = nuvo_map_get_table_index(req->block_last, 0);
        uint_fast32_t first_count = NUVO_MAP_RADIX - first_index;
        uint_fast32_t last_count = last_index + 1;

        NUVO_ASSERT(first_count + last_count == block_count);
        // make sure we are at the right level of the table
        NUVO_ASSERT(req->first_map->level == 0);
        NUVO_ASSERT(req->last_map->level == 0);
        // double check that this is the right table
        NUVO_ASSERT(req->first_map->base_offset == nuvo_map_get_base_offset(req->block_start, 0));
        NUVO_ASSERT(req->last_map->base_offset == nuvo_map_get_base_offset(req->block_last, 0));

        // copy the map entries to return array
        for (uint_fast32_t i = 0; i < first_count; i++)
        {
            struct nuvo_map_entry *map_entry = &req->first_map->entries[first_index + i];
            struct nuvo_map_entry *entry = &entries[i];
            cow_cnt += map_read_entry(req, req->first_map, map_entry, entry, multi_lun, pin);
        }

        for (uint_fast32_t i = 0; i < last_count; i++)
        {
            struct nuvo_map_entry *map_entry = &req->last_map->entries[i];
            struct nuvo_map_entry *entry = &entries[i + first_count];
            cow_cnt += map_read_entry(req, req->last_map, map_entry, entry, multi_lun, pin);
        }
    }

    return (cow_cnt);
}

void nuvo_map_read_release(struct nuvo_lun       *lun,
                           uint_fast32_t          block_count,
                           struct nuvo_map_entry *entries)
{
    nuvo_mfst_unpin(&lun->vol->log_volume.mfst, block_count, entries);
}

int nuvo_map_final_map_entries(struct nuvo_lun *lun, uint64_t block_offset, uint32_t block_count,
                               struct nuvo_map_entry *final_entries, bool abort_on_non_zero)
{
    struct nuvo_map_entry   map_entries[NUVO_MAX_IO_BLOCKS];
    struct nuvo_map_request map_req;
    uint_fast32_t           parcel_descs[NUVO_MAX_IO_BLOCKS];
    bool rw_locked = false;

    int_fast64_t ret = 0;

    NUVO_ASSERT(block_count <= NUVO_MAX_IO_BLOCKS);

    if (NUVO_LUN_IS_ACTIVE(lun))
    {
        nuvo_rwlock_rdlock(&lun->vol->rw_lock);
        rw_locked = true;
    }

    nuvo_map_request_init(&map_req, lun, block_offset, block_count);
    map_req.op = NUVO_MAP_REQUEST_OP_DIFF;

    nuvo_map_reserve_sync(&map_req);
    if (map_req.status < 0)
    {
        ret = ENOMEM;
        goto _out;
    }
    nuvo_map_fault_in_sync(&map_req);
    if (map_req.status < 0)
    {
        ret = ENOMEM;
        goto _out;
    }

    if (nuvo_is_peer_cow_lun(map_req.lun))
    {
        struct nuvo_map_request map_req_active;
        nuvo_map_request_init(&map_req_active, &(lun->vol->log_volume.lun), block_offset, block_count);
        map_req_active.op = NUVO_MAP_REQUEST_OP_DIFF;
        nuvo_map_reserve_sync(&map_req_active);

        if (map_req_active.status < 0)
        {
            ret = ENOMEM;
            goto _out;
        }
        nuvo_map_fault_in_sync(&map_req_active);
        if (map_req_active.status < 0)
        {
            ret = ENOMEM;
            goto _out;
        }
        nuvo_map_multi_lun_read_sync(&map_req, false, &map_req_active, map_entries, parcel_descs);
    }
    else
    {
        nuvo_map_read_and_pin_sync(&map_req, false, map_entries, parcel_descs);
    }

    if (map_req.status < 0)
    {
        // TODO: need error codes
        ret = ENOMEM;
        goto _out;
    }

    uint32_t resolved_count = 0;
    bool     aborting = false;
    for (uint_fast32_t i = 0; i < block_count; i++)
    {
        if (final_entries[i].cow != NUVO_MAP_ENTRY_SHARED)
        {
            // already resolved
            resolved_count++;
            continue;
        }
        if (map_entries[i].cow != NUVO_MAP_ENTRY_SHARED)
        {
            final_entries[i] = map_entries[i];  // Copy the entry into the final
            resolved_count++;
            if (abort_on_non_zero &&
                ((map_entries[i].type != NUVO_ME_CONST) || (map_entries[i].pattern != 0)))
            {
                aborting = true;
                break;
            }
        }
    }
    if ((resolved_count != block_count) && !aborting)
    {
        struct nuvo_lun *lun_next;

        NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(lun));
        lun_next = nuvo_get_next_younger_lun(lun, false);
        NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(lun_next));
        ret = nuvo_map_final_map_entries(lun_next, block_offset, block_count,
                                         final_entries, abort_on_non_zero);
    }

_out:
    if (rw_locked)
    {
        nuvo_rwlock_unlock(&lun->vol->rw_lock);
    }

    if (ret < 0)
    {
        NUVO_ERROR_PRINT("map error on lun %d, offset %d, len %d", lun->snap_id, block_offset, block_count);
    }
    return (ret);
}

static void nuvo_map_alloc_tables_sync_cb(struct nuvo_map_alloc_req *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t *)req->tag.ptr;

    nuvo_mutex_unlock(sync_signal);
}

nuvo_return_t nuvo_map_lun_open(struct nuvo_lun *lun, const struct nuvo_map_entry *map_entry)
{
    nuvo_return_t ret = 0;
    // create a map from the map entry, reading if necessary
    struct nuvo_dlist alloc_list;

    nuvo_dlist_init(&alloc_list);

    // first alloc the root map table
    struct nuvo_map_alloc_req alloc_req;
    nuvo_mutex_t sync_signal;
    nuvo_mutex_init(&sync_signal);
    nuvo_mutex_lock(&sync_signal);
    alloc_req.count = 1;
    alloc_req.map_list = &alloc_list;
    alloc_req.callback = nuvo_map_alloc_tables_sync_cb;
    alloc_req.tag.ptr = &sync_signal;
    ret = nuvo_map_alloc_tables(&alloc_req, false);
    NUVO_ASSERT(ret >= 0); // non-pinned version should never fail
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    struct nuvo_map_track *map = nuvo_dlist_remove_head_object(&alloc_list, struct nuvo_map_track, list_node);
    NUVO_ASSERT(map != NULL);

    nuvo_mutex_lock(&lun->vol->mutex);
    uint_fast64_t checkpoint_gen = lun->vol->log_volume.map_state.checkpoint_gen;
    uint32_t      snap_gen = lun->vol->snap_generation;
    nuvo_mutex_lock(&lun->mutex);

    map->cp_gen = checkpoint_gen;
    map->snap_gen = snap_gen;
    nuvo_mutex_unlock(&lun->vol->mutex);

    // fill-in the root map table depending on the type of root map entry
    switch (map_entry->type)
    {
    case NUVO_ME_CONST:
    case NUVO_ME_NULL:

        if (map_entry->type == NUVO_ME_NULL)
        {
            NUVO_ASSERT(map_entry->cow == NUVO_MAP_ENTRY_SHARED);
        }
        map->state = NUVO_MAP_PINNED;
        map->level = lun->map_height - 1;
        map->base_offset = nuvo_map_get_base_offset(0, map->level);
        map->lun = lun;
        map->vol = lun->vol;
        map->parent = NULL;
        map->is_dirty = 0;
        map->child_count = 0;
        map->is_new_entry = 0;
        map->shadow_link = NULL;
        map->pinned = 1;
        map->map_entry = *map_entry;

        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            map->entries[i] = *map_entry;
        }

        break;

    case NUVO_ME_MEDIA:
        map->map_entry = *map_entry;

        // create mutex that will be used for sync calls
        nuvo_mutex_t sync_signal;
        nuvo_mutex_init(&sync_signal);
        if (ret < 0)
        {
            // free the map we allocated
            ret = -NUVO_ENOMEM;
            break;
        }

        struct nuvo_mfst *mfst = &lun->vol->log_volume.mfst;

        // pin block and get parcel desc
        uint_fast32_t parcel_desc;
        ret = nuvo_mfst_pin_open(mfst, 1, map_entry, &parcel_desc);
        if (ret < 0)
        {
            nuvo_mutex_destroy(&sync_signal);
            // free the map we allocated
            ret = -NUVO_ENOENT;
            break;
        }

        // alloc a req
        struct nuvo_io_request *io_req = nuvo_pr_sync_client_req_alloc(&sync_signal);
        NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->rw.vol = lun->vol;
        io_req->rw.parcel_desc = parcel_desc;
        io_req->rw.block_offset = map_entry->media_addr.block_offset;
        io_req->rw.block_count = 1;
        io_req->rw.iovecs[0].iov_base = map->entries;
        io_req->rw.iovecs[0].iov_len = sizeof(struct nuvo_map_table);

        nuvo_mutex_unlock(&lun->mutex);

        nuvo_rl_sync_submit(io_req, &sync_signal);
        nuvo_mutex_destroy(&sync_signal);

        nuvo_return_t req_status = io_req->status;
        nuvo_hash_t   req_hash = io_req->rw.block_hashes[0];
        nuvo_pr_client_req_free(io_req);
        nuvo_mfst_unpin(mfst, 1, map_entry);

        nuvo_mutex_lock(&lun->mutex);
        if (req_status < 0)
        {
            // free the map we allocated
            ret = -NUVO_EIO;
            break;
        }

        if (map_entry->hash != req_hash)
        {
            ret = -NUVO_E_BAD_HASH;
            break;
        }

        // we got raw table, init in-core data
        map->state = NUVO_MAP_PINNED;
        map->level = lun->map_height - 1;
        map->base_offset = nuvo_map_get_base_offset(0, map->level);
        map->lun = lun;
        map->vol = lun->vol;
        map->parent = NULL;
        map->is_dirty = 0;
        map->child_count = 0;
        map->is_new_entry = 0;
        map->shadow_link = NULL;
        map->pinned = 1;
        // COW on active would need percolating the COW entries to the root block
        map_percolate_cow_on_fault_in(map, map_entry);
        break;

    default:
        ret = -1;
        NUVO_ASSERT(ret != -1);
        break;
    }

    nuvo_mutex_lock(&nuvo_map->list_mutex);
    if (ret < 0)
    {
        map->state = NUVO_MAP_CLEAN_LIST;
        map->pinned = 0;
        map->is_dirty = 0;
        map->child_count = 0;
        map->is_new_entry = 0;
        map->shadow_link = NULL;
        map->lun = NULL;
        map->vol = NULL;
        map->parent = NULL;
        nuvo_map_clean_insert_tail_noalloc(map);
        nuvo_mutex_unlock(&nuvo_map->list_mutex);
        nuvo_mutex_unlock(&lun->mutex);
        nuvo_map_alloc_run();
        return (ret);
    }

    nuvo_map_pinned_insert(map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    lun->root_map = map;
    nuvo_mutex_unlock(&lun->mutex);

    return (0);
}

void nuvo_map_lun_checkpoint_complete(struct nuvo_map_checkpoint_req *req)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);
    // first free all left over maps
    struct nuvo_map_track *map;
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    while ((map = nuvo_dlist_remove_head_object(&req->map_list, struct nuvo_map_track, list_node)) != NULL)
    {
        nuvo_map_clean_insert_tail_noalloc(map);
    }
    // check if there are any waiting allocation requests that can be serviced
    nuvo_map_alloc_run_locked(&comp_list);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    req->status = 0;

    // if a lun was never dirtied, cp wouldnt do any mfl(hole punching)
    // work on a lun.
    // So lets transform those luns to mfl complete/deleting donea

    // The idea is that the lun root map cant be in shared
    // if a CP happened.
    // CP_IN_PROGRESS is set before the next cp after L0 punching
    // So we arent going to be concurrent with a CP

    if (NUVO_MAP_IS_SHARED(req->lun->root_map) &&
        (req->lun->lun_state == NUVO_LUN_STATE_DELETING_DRAIN) &&
        (req->lun->mfl_state == NUVO_LUN_MFL_CP_IN_PROGRESS))
    {
        NUVO_ASSERT(req->lun->mfl_state);
        NUVO_ME_SET_MFL_DONE(&req->lun->root_map->map_entry);
    }

    // lun->root_map_entry isnt used once we load the lun/map tree during open lun
    // in any case, we copy the last cp map entry to the lun root map entry
    // useful for debugging
    req->lun->root_map_entry = req->lun->root_map->map_entry;
    req->lun_cp_map_entry[req->lun_cnt].snap_id = req->lun->snap_id;
    req->lun_cp_map_entry[req->lun_cnt].root_map_entry = req->lun->root_map->map_entry;
    req->lun_cnt++;

    NUVO_ERROR_PRINT("map cp done for lun(%d) lun_state:%d mfl_state:%d cp(%llu) root_map:%p entry:type:%d addr<%lu:%lu> "
                     "cp dirty_count:%d mfl dirty count:%d",
                     req->lun->snap_id, req->lun->lun_state, req->lun->mfl_state,
                     req->cp_gen, req->lun->root_map,
                     req->lun->root_map->map_entry.type,
                     req->lun->root_map->map_entry.media_addr.parcel_index,
                     req->lun->root_map->map_entry.media_addr.block_offset,
                     req->lun->lun_stats.dirty_cnt,
                     req->lun->lun_stats.mfl_dirty_cnt);
    NUVO_LUN_STAT_RESET(req->lun);
    struct nuvo_lun *lun = nuvo_lun_get_next(req->vol, req->lun, false);

    // CP doesnt need a lun pincount
    // as CP is the one which moves the lun state to DELETING_DRAIN->DELETED etc
    if (!lun)
    {
        req->callback(req);
    }
    else
    {
        req->lun = lun;
        /*start fresh , unlock the vol mutex */
        nuvo_map_lun_checkpoint(req);
    }
}

void nuvo_map_checkpoint_int(struct nuvo_map_checkpoint_req *req);

void nuvo_map_checkpoint_writer_wait_free_cb(struct nuvo_map_writer_wait_req *req)
{
    struct nuvo_map_checkpoint_req *checkpoint_req = (struct nuvo_map_checkpoint_req *)req->tag.ptr;
    struct nuvo_map_writer         *writer = &checkpoint_req->vol->log_volume.map_state.writer;

    nuvo_map_writer_lock(checkpoint_req->vol);
    if (writer->free_batch_count == 0)
    {
        // no more batches, wait for some to complete
        checkpoint_req->writer_wait_req.callback = nuvo_map_checkpoint_writer_wait_free_cb;
        checkpoint_req->writer_wait_req.tag.ptr = checkpoint_req;
        nuvo_map_writer_wait_batch_comp(checkpoint_req->vol, &checkpoint_req->writer_wait_req);
        nuvo_map_writer_unlock(checkpoint_req->vol);
    }
    else
    {
        // looks like a batch completed since we last checked
        // run the checkpoint func again
        nuvo_map_writer_unlock(checkpoint_req->vol);
        nuvo_map_checkpoint_int(checkpoint_req);
    }
}

void nuvo_map_checkpoint_writer_wait_cb(struct nuvo_map_writer_wait_req *req)
{
    struct nuvo_map_checkpoint_req *checkpoint_req = (struct nuvo_map_checkpoint_req *)req->tag.ptr;

    // run the checkpoint func again
    nuvo_map_checkpoint_int(checkpoint_req);
}

nuvo_return_t nuvo_map_checkpoint_rc(struct nuvo_map_checkpoint_req *req, struct nuvo_map_track *map, struct nuvo_map_track **parent_map)
{
    NUVO_ASSERT_MUTEX_HELD(&(*parent_map)->mutex);
    NUVO_ASSERT_MUTEX_HELD(&req->vol->mutex);

    struct nuvo_map_track *shadow_map = NULL;
    nuvo_return_t          ret = 0;

    nuvo_mutex_lock(&map->mutex);
    NUVO_ASSERT(map->state != NUVO_MAP_SHADOW);

    // check if map has a shadow
    if (map->shadow_link != NULL)
    {
        shadow_map = map->shadow_link;

        NUVO_ASSERT_LOG((map->level == shadow_map->level),
                        "shadow map lock is held by thread id %d\n",
                        shadow_map->mutex.owner);
        nuvo_mutex_lock(&shadow_map->mutex);
        nuvo_mutex_unlock(&map->mutex);
        map = shadow_map;
    }

    if (map->child_count == 0)
    {
        // if the map is shadowed, that means a pending operation is
        // outstanding and will take care of it eventually
        if (map->state != NUVO_MAP_SHADOW)
        {
            if (map->state == NUVO_MAP_CLEANING)
            {
                // if the map is being cleaned, we let it be handled by the
                // cleaning completion handler
            }
            else
            {
                // if the map is dirty, shadow and start write-out
                if (map->is_dirty != 0)
                {
                    // if the map has been modified since the checkpoint, it should
                    // have been shadowed or propagated up
                    NUVO_ASSERT(map->cp_gen >= req->prev_gen);
                    NUVO_DEBUG_ASSERT(map->cp_gen == req->prev_gen, "map cp_gen :%u prev_gen:%u "
                                      "map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) "
                                      " offset:%lu level:%d map->is_dirty:%d lun(%d) vol:%p",
                                      map->cp_gen, req->prev_gen, map->state, map->shadow_link,
                                      map->mfl, map->map_entry.media_addr.parcel_index,
                                      map->map_entry.media_addr.block_offset,
                                      map->base_offset, map->level, map->lun->snap_id, map->vol);

                    // we need to shadow this map and queue it for write out
                    // first lets see if the map writer queue is already full
                    if (req->vol->log_volume.map_state.writer.write_count >=
                        NUVO_MAP_WRITE_BATCH_SIZE * req->vol->log_volume.map_state.writer.free_batch_count)
                    {
                        // map writer already has a full queue
                        // we'll just return that it's busy, and wait until
                        // space is available
                        ret = -NUVO_EBUSY;
                        nuvo_mutex_unlock(&map->mutex);
                        goto exit;
                    }

                    ret = nuvo_map_shadow_reg(&req->map_list, map);
                    if (ret < 0)
                    {
                        nuvo_mutex_unlock(&map->mutex);
                        goto exit;
                    }

                    // now we need to schedule the shadow for writing out

                    // note (suresh) : moved the cp update before the add map
                    // because add_map can cause a flush and we could lose the vol lock
                    // and a writer could see a non updated cp and try to shadow

                    MAP_SET_CP(map, req->cp_gen);

                    nuvo_mutex_lock(&map->shadow_link->mutex);

                    NUVO_LUN_STAT_DIRTY_COUNT(map->lun);

                    NUVO_LOG_COND(map, 120, (!NUVO_LUN_IS_ACTIVE(map->lun)),
                                  "cp WRITER_ADD_MAP  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) "
                                  " offset:%lu level:%d map->is_dirty:%d lun(%d)",
                                  map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                                  map->map_entry.media_addr.block_offset,
                                  map->base_offset, map->level, map->is_dirty, map->lun->snap_id);
                    nuvo_map_writer_add_map(map->shadow_link, NUVO_MW_FLUSH_NONE);

                    ret = 1;
                }
                else
                {
                    NUVO_ASSERT((*parent_map)->state == NUVO_MAP_SHADOW);

                    MAP_SET_CP(map, req->cp_gen);
                    NUVO_LOG_COND(map, 120, (!NUVO_LUN_IS_ACTIVE(map->lun)),
                                  "cp CLEAN_PARENT_UPDATE_ADD_MAP  map :%p state:%d shadow_link:%p mfl:%d "
                                  "media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d lun(%d)",
                                  map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                                  map->map_entry.media_addr.block_offset,
                                  map->base_offset, map->level, map->is_dirty, map->lun->snap_id);

                    map_parent_entry_update_nl(map, *parent_map);


                    ret = 1;
                }
            }
        }
        nuvo_mutex_unlock(&map->mutex);
    }
    else
    {
        // if this map is not shadowed, shadow it first
        if (map->state != NUVO_MAP_SHADOW)
        {
            NUVO_DEBUG_ASSERT(map->cp_gen == req->prev_gen, "invalid cp gen map:%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d map->cp_gen:%lu vol checkpoint_gen:%lu req->prev_gen:%lu",
                              map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                              map->map_entry.media_addr.block_offset,
                              map->base_offset, map->level, map->is_dirty, map->cp_gen,
                              map->vol->log_volume.map_state.checkpoint_gen,
                              req->prev_gen);
            NUVO_ASSERT(map->cp_gen >= req->prev_gen);
            NUVO_DEBUG_ASSERT(map->cp_gen == req->prev_gen, "map cp_gen :%u prev_gen:%u "
                              "map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) "
                              " offset:%lu level:%d map->is_dirty:%d lun(%d) vol:%p",
                              map->cp_gen, req->prev_gen, map->state, map->shadow_link,
                              map->mfl, map->map_entry.media_addr.parcel_index,
                              map->map_entry.media_addr.block_offset,
                              map->base_offset, map->level, map->lun->snap_id, map->vol);
            ret = nuvo_map_shadow_reg(&req->map_list, map);
            if (ret < 0)
            {
                nuvo_mutex_unlock(&map->mutex);
                goto exit;
            }
            MAP_SET_CP(map, req->cp_gen);
            shadow_map = map->shadow_link;
            nuvo_mutex_lock(&shadow_map->mutex);
            nuvo_mutex_unlock(&map->mutex);
            map = shadow_map;
        }

        // sweep through the children
        for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
        {
            struct nuvo_map_entry *entry = &map->entries[i];
            if (entry->type == NUVO_ME_IN_MEM)
            {
                struct nuvo_map_track *child_map = entry->ptr;
                nuvo_return_t          child_ret = nuvo_map_checkpoint_rc(req, child_map, &map);
                if (child_ret < 0)
                {
                    ret = child_ret;
                    nuvo_mutex_unlock(&map->mutex);
                    goto exit;
                }
                else if (child_ret > 0)
                {
                    ret = child_ret;
                }
            }
        }

        if (map->child_count == 0)
        {
            // since this was a non-leaf map that we've modified, it
            // should be a shadow
            NUVO_ASSERT(map->state == NUVO_MAP_SHADOW);

            ret = 1;

            // map count went to zero, either write out map if dirty, or
            // propagate map entry upward
            if (map->is_dirty)
            {
                // add map to write out list
                NUVO_LUN_STAT_DIRTY_COUNT(map->lun);
                NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(map->lun) && !map->base_offset), "CP DIRTY MAP ADD (LEAF)  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                              map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                              map->map_entry.media_addr.block_offset,
                              map->base_offset, map->level, map->is_dirty);

                nuvo_map_writer_add_map(map, NUVO_MW_FLUSH_NONE);
            }
            else
            {
                // just propagate the map entry and evict if it is a shadow map
                NUVO_ASSERT((*parent_map)->state == NUVO_MAP_SHADOW);
                NUVO_LOG_COND(map, 80, (!NUVO_LUN_IS_ACTIVE(map->lun) && !map->base_offset), "cp CLEAN_PARENT_UPDATE_ADD_MAP(child count = 0)  map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                              map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                              map->map_entry.media_addr.block_offset,
                              map->base_offset, map->level, map->is_dirty);

                // populate the current map's entry to shadow parent
                map_parent_entry_update_nl(map, *parent_map);

                // if map is a shadow, unlink and evict it
                NUVO_ASSERT(map->state == NUVO_MAP_SHADOW);

                // check if we will need to unlink it
                if (map->pinned == 0)
                {
                    // we need to unlink it
                    struct nuvo_map_track *map_pair = map->shadow_link;
                    nuvo_mutex_unlock(&map->mutex);
                    nuvo_mutex_lock(&map_pair->mutex);
                    nuvo_mutex_lock(&map->mutex);
                    nuvo_mutex_lock(&nuvo_map->list_mutex);

                    // check if the other map still links to us
                    if (map_pair->shadow_link == map)
                    {
                        map_pair->shadow_link = NULL;
                    }
                    nuvo_map_unpin_table_locked(map_pair);
                    nuvo_mutex_unlock(&map_pair->mutex);

                    // free the shadow map since we're done with it
                    map->parent = NULL;
                    map->vol = NULL;
                    map->lun = NULL;
                    map->state = NUVO_MAP_CLEAN_LIST;
                    map->shadow_link = NULL;
                    nuvo_map_clean_insert_tail_noalloc(map);
                    nuvo_mutex_unlock(&nuvo_map->list_mutex);
                }
                nuvo_mutex_unlock(&map->mutex);
            }
        }
        else
        {
            nuvo_mutex_unlock(&map->mutex);
        }
    }

exit:

    return (ret);
}

void nuvo_map_checkpoint_alloc_cb(struct nuvo_map_alloc_req *req)
{
    struct nuvo_map_checkpoint_req *checkpoint_req = (struct nuvo_map_checkpoint_req *)req->tag.ptr;

    // we've gotten more maps, run the main checkpoint function again
    nuvo_map_checkpoint_int(checkpoint_req);
}

/*SNAP_WORK CP * do it recusively  with a counter */
void nuvo_map_checkpoint_int(struct nuvo_map_checkpoint_req *req)
{
    // the start of the checkpoint tree traversal

    // lock the root, depth first run through the children
    // if dirty prev-gen maps are found, write them out
    // if the map writer has no available batches left, return out of
    //  recursion and wait for a batch to be available


    // SNAP_WORK CP checkpoint all the luns , maybe recursively in the callbacks? */
    nuvo_return_t ret = 0;
    bool          first = false;

    nuvo_mutex_lock(&req->vol->mutex);
    struct nuvo_map_track *root_map = req->lun->root_map->shadow_link;

    // if there is no shadow, that means the checkpoint is complete
    if (root_map == NULL)
    {
        // if the current lun is done ( req->lun)
        // move on to the next lun in the callback
        // when  all luns are checkpointed, we are done with checkpointing */

        // bump up the cp if we are begining the cp
        //
        // note we increment the cp_gen only after the resource allocation
        // Else during the window of resource/mem allocation, we could have a snap create
        // which would need to dirty the root_map and make the cp gen current

        // here is the race between snap create and mem allocation in cp.

        // we bump up the cp_gen here
        // wait for memory
        // snap_create sets the root map cp_gen to current cp_gen
        // the cp after mem allocation thinks that the CP is done now that the root map live map cp_gen = current

        // so we dont bump up the cp_gen here, but we set a flag saying cp_begin = true.
        // cp_begin flag causes the cp_gen bump up during root map shadow

        if (req->cp_begin)
        {
            req->prev_gen = req->vol->log_volume.map_state.checkpoint_gen++;
            req->cp_gen = req->vol->log_volume.map_state.checkpoint_gen;
            req->cp_begin = false;
            NUVO_LOG(map, 1, "map cp begin at %llu\n", req->cp_gen);
        }
        if (req->lun->root_map->cp_gen == req->cp_gen)
        {
            // the root shadow has been written out
            // complete the checkpoint request
            nuvo_mutex_unlock(&req->vol->mutex);
            NUVO_LOG(map, 1, "map cp done for lun(%d) cp(%llu)", req->lun->snap_id, req->cp_gen);
            nuvo_map_lun_checkpoint_complete(req);
            return;
        }
        else
        {
            // the root map has not been cp'd, need to shadow it to start the
            // cp process
            struct nuvo_map_track *map = req->lun->root_map;
            nuvo_mutex_lock(&map->mutex);
            NUVO_ASSERT(map->cp_gen == req->prev_gen);
            ret = nuvo_map_shadow_reg(&req->map_list, map);
            // this should never fail since this should be the first thing we do
            NUVO_ASSERT(ret >= 0);

            MAP_SET_CP(map, req->cp_gen);
            root_map = map->shadow_link;
            nuvo_mutex_unlock(&map->mutex);

            first = true;
        }
    }

    nuvo_mutex_lock(&root_map->mutex);
    uint_fast64_t batches_completed = req->vol->log_volume.map_state.writer.batches_completed;
    if (root_map->child_count > 0 || first == true)
    {
        ret = 1;
        while (ret == 1)
        {
            ret = 0;
            for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
            {
                struct nuvo_map_entry *entry = &root_map->entries[i];
                if (entry->type == NUVO_ME_IN_MEM)
                {
                    struct nuvo_map_track *child_map = entry->ptr;
                    nuvo_return_t          child_ret = nuvo_map_checkpoint_rc(req, child_map, &root_map);
                    if (child_ret < 0)
                    {
                        ret = child_ret;
                        break;
                    }
                    if (child_ret > 0)
                    {
                        ret = child_ret;
                    }
                }
            }
        }
        ;
        // check if we reduced the children to zero
        if (root_map->child_count == 0)
        {
            ret = 1;

            // map count went to zero, either write out map if dirty, or
            // propagate map entry upward
            if (root_map->is_dirty)
            {
                // add map to write out list
                nuvo_map_writer_add_map(root_map, NUVO_MW_FLUSH_NONE);

                /* root might be the only thing you have to write out
                 * if a snap create is the only that happened
                 * between CPs
                 */
                ret = 0; /* force a flush below */
            }
            else
            {
                NUVO_ASSERT(root_map->pinned == 0);
                // we need to unlink it
                struct nuvo_map_track *live_map = root_map->shadow_link;
                nuvo_mutex_unlock(&root_map->mutex);
                nuvo_mutex_lock(&live_map->mutex);
                nuvo_mutex_lock(&root_map->mutex);
                nuvo_mutex_lock(&nuvo_map->list_mutex);

                // check if the other map still links to us
                if (live_map->shadow_link == root_map)
                {
                    live_map->shadow_link = NULL;
                }
                nuvo_map_unpin_table_locked(live_map);
                nuvo_mutex_unlock(&live_map->mutex);

                // free the shadow map since we're done with it
                root_map->parent = NULL;
                root_map->vol = NULL;
                root_map->lun = NULL;
                root_map->state = NUVO_MAP_CLEAN_LIST;
                root_map->shadow_link = NULL;
                root_map->is_dirty = 0;
                nuvo_map_clean_insert_tail_noalloc(root_map);
                nuvo_mutex_unlock(&nuvo_map->list_mutex);

                // we are done with the checkpoint
                nuvo_mutex_unlock(&root_map->mutex);
                nuvo_mutex_unlock(&req->vol->mutex);

                // complete the checkpoint request
                NUVO_LOG(map, 1, "map(%d) cp done for lun(%d) cp(%llu)", __LINE__, req->lun->snap_id, req->cp_gen);
                nuvo_map_lun_checkpoint_complete(req);
                return;
            }
        }
        else
        {
            nuvo_mutex_unlock(&root_map->mutex);
        }
    }
    else
    {
        nuvo_mutex_unlock(&root_map->mutex);
    }

    // if we've queued up enough maps for full writer batches, flush them
    nuvo_mutex_unlock(&req->vol->mutex);
    nuvo_map_writer_lock(req->vol);
    struct nuvo_map_writer *writer = &req->vol->log_volume.map_state.writer;
    while (writer->write_count >= NUVO_MAP_WRITE_BATCH_SIZE &&
           writer->free_batch_count > 0)
    {
        nuvo_map_writer_flush(req->vol);
        nuvo_map_writer_lock(req->vol);
    }

    // run the allocator since nuvo_map_checkpoint_rc can free maps without
    // running the allocator
    nuvo_map_writer_unlock(req->vol);
    nuvo_mutex_lock(&req->vol->mutex);
    nuvo_map_alloc_run();

    if (ret == -NUVO_ENOMEM)
    {
        nuvo_mutex_unlock(&req->vol->mutex);
        // we ran out of map tables on our freelist, get another batch
        req->map_alloc_req.callback = nuvo_map_checkpoint_alloc_cb;
        req->map_alloc_req.count = req->vol->log_volume.lun.map_height * 8;
        req->map_alloc_req.map_list = &req->map_list;
        req->map_alloc_req.tag.ptr = req;

        nuvo_map_alloc_tables(&req->map_alloc_req, false);
    }
    else if (ret == -NUVO_EBUSY)
    {
        // we ran out of writer batches, wait for some to complete
        nuvo_map_writer_lock(req->vol);
        struct nuvo_map_writer *writer = &req->vol->log_volume.map_state.writer;
        if (writer->free_batch_count == 0)
        {
            // no more batches, wait for some to complete
            nuvo_dlnode_init(&req->writer_wait_req.list_node);
            req->writer_wait_req.callback = nuvo_map_checkpoint_writer_wait_free_cb;
            req->writer_wait_req.tag.ptr = req;
            nuvo_map_writer_wait_batch_comp(req->vol, &req->writer_wait_req);
            nuvo_map_writer_unlock(req->vol);
            nuvo_mutex_unlock(&req->vol->mutex);
        }
        else
        {
            // looks like a batch completed since we last checked
            // run the checkpoint func again
            nuvo_map_writer_unlock(req->vol);
            nuvo_mutex_unlock(&req->vol->mutex);
            nuvo_map_checkpoint_int(req);
            return;
        }
    }
    else if (ret == 0)
    {
        // nothing could be done, we must wait for some maps to be written out
        // check if there are any pending writes, if not flush
        nuvo_map_writer_lock(req->vol);
        struct nuvo_map_writer *writer = &req->vol->log_volume.map_state.writer;
        if (writer->free_batch_count == NUVO_MAP_WRITE_BATCHES &&
            batches_completed == req->vol->log_volume.map_state.writer.batches_completed)
        {
            NUVO_ASSERT(nuvo_dlist_get_head(&writer->write_queue) != NULL);
            /* cant hold vol lock with flush */
            nuvo_mutex_unlock(&req->vol->mutex);
            nuvo_map_writer_flush(req->vol);
            nuvo_mutex_lock(&req->vol->mutex);
            nuvo_map_writer_lock(req->vol);
        }

        // check if any batches completed while we were looking at the tree
        if (batches_completed == req->vol->log_volume.map_state.writer.batches_completed)
        {
            nuvo_dlnode_init(&req->writer_wait_req.list_node);
            req->writer_wait_req.callback = nuvo_map_checkpoint_writer_wait_cb;
            req->writer_wait_req.tag.ptr = req;
            nuvo_map_writer_wait_batch_comp(req->vol, &req->writer_wait_req);
            nuvo_map_writer_unlock(req->vol);
            nuvo_mutex_unlock(&req->vol->mutex);
        }
        else
        {
            // looks like a batch completed since we last checked
            // run the checkpoint func again
            nuvo_map_writer_unlock(req->vol);
            nuvo_mutex_unlock(&req->vol->mutex);
            nuvo_map_checkpoint_int(req);
        }
    }
    else
    {
        NUVO_PANIC("Unrecognized return code during checkpointing ret:%d", ret);
    }
}

void nuvo_map_checkpoint(struct nuvo_map_checkpoint_req *req)
{
    // to checkpoing a volume's map, we first incrememt the checkpoing gen
    // in the volume's map state.  Then we must traverse the map tree depth
    // first and write out all dirty maps from the previous gen and construct
    // and write out higher level maps until we have a new root map.
    // This must all be accomplished while we continue to take new writes to
    // the volume.  To accomplish this we keep data about the previous
    // checkpoint gen in temporary shadow maps.

    // increment the checkpoint gen
    // note we increment the cp_gen only after the resource allocation
    // Else during the window of resource/mem allocation, we could have a snap create
    // which would need to dirty the root_map and make the cp gen current

    // here is the race between snap create and mem allocation in cp.

    // we bump up the cp_gen here
    // wait for memory
    // snap_create sets the root map cp_gen to current cp_gen
    // the cp after mem allocation thinks that the CP is done now that the root map live map cp_gen = current

    // so we dont bump up the cp_gen here, but we set a flag saying cp_begin = true.
    // cp_begin flag causes the cp_gen bump up during root map shadow


    nuvo_mutex_lock(&req->vol->mutex);


    req->cp_begin = true;
    nuvo_mutex_unlock(&req->vol->mutex);

    nuvo_dlist_init(&req->map_list);
    req->lun_cnt = 0;
    req->lun = &req->vol->log_volume.lun;
    NUVO_ASSERT(req->lun->lun_state < NUVO_LUN_STATE_DELETED);
    nuvo_map_lun_checkpoint(req);
}

void nuvo_map_lun_checkpoint(struct nuvo_map_checkpoint_req *req)
{
    req->map_alloc_req.callback = nuvo_map_checkpoint_alloc_cb;
    /* SNAP_WORK CP current lun */
    req->map_alloc_req.count = req->lun->map_height * NUVO_MAP_CP_ALLOC_BATCH;
    req->map_alloc_req.map_list = &req->map_list;
    req->map_alloc_req.tag.ptr = req;

    nuvo_map_alloc_tables(&req->map_alloc_req, false);
}

void nuvo_map_checkpoint_sync_cb(struct nuvo_map_checkpoint_req *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t *)req->tag.ptr;

    nuvo_mutex_unlock(sync_signal);
}

void nuvo_map_replay_fault_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_log_request  *log_req = (struct nuvo_log_request *)map_req->tag.ptr;
    struct nuvo_log_io_block *log_block = &log_req->log_io_blocks[log_req->replay_count];
    struct nuvo_vol          *vol = log_req->vs_ptr;
    struct nuvo_map_track    *parent = map_req->first_map;
    struct nuvo_map_track    *map_mfl = NULL;
    int        target_level = map_req->target_level;
    static int g_replay_count = 0;

    struct nuvo_lun *lun = map_req->lun;

    NUVO_ASSERT(map_req->lun->snap_id && map_req->first_map->lun->snap_id);

    // We only load upto L1.
    // From the L1 map entry we detect that this is a zero map entry
    // we also load the child map so that we can "mfl" it

    // fault-in is complete, depending on the log block type, do the update
    switch (log_block->log_entry_type)
    {
    case NUVO_LE_DATA:
        // TODO: need to handle pinning all dirty maps during replay
        // yes, else we may end up flushing during replay
        // we need a flag in the map request to indicate replay possibly
        // or add the maps to a pinned array log req of sorts.
        if (log_req->operation == NUVO_LOG_OP_GC)
        {
            NUVO_ASSERT((log_block->pit_info.active && map_req->lun->snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID) ||
                        (!log_block->pit_info.active && map_req->lun->snap_id == log_block->pit_info.pit_id))
            uint_fast32_t succeeded = 0;
            uint_fast32_t failed = 0;
            nuvo_map_commit_gc_write(map_req,
                                     &log_req->nuvo_map_entries[log_req->replay_count],
                                     &log_block->gc_media_addr, &succeeded, &failed);
        }
        else if (vol->snap_generation)
        {
            NUVO_ASSERT(log_block->pit_info.active);
            // commit map on both the luns atomically
            struct nuvo_map_request *map_req_snap = &log_req->map_req_snap;
            struct nuvo_map_request *map_req_active = &log_req->map_req;
            nuvo_map_multi_lun_commit_write(map_req_active, map_req_snap,
                                            &log_req->nuvo_map_entries[log_req->replay_count]);
        }
        else
        {
            NUVO_ASSERT(log_block->pit_info.active);
            nuvo_map_commit_write(map_req, &log_req->nuvo_map_entries[log_req->replay_count]);
        }
        break;

    case NUVO_LE_MAP_L0:
    case NUVO_LE_MAP_L1:
    case NUVO_LE_MAP_L2:
    case NUVO_LE_MAP_L3:
    case NUVO_LE_MAP_L4:
    {
        // maps L0 level are loaded only for MFL replays.
        // validate zero address map entries from logger
        //TODO enable this after we test on the repro lun
        if (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr))
        {
            NUVO_ASSERT(log_req->nuvo_map_entries[log_req->replay_count].pattern
                        == NUVO_MAP_IS_ZERO_PATTERN);
        }
        // maps L0 level are loaded only for MFL replays.
        if (!map_req->first_map->level)
        {
            NUVO_ASSERT(map_req->target_level == 0);
            NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&log_req->nuvo_map_entries[log_req->replay_count]));
            NUVO_ASSERT(lun->lun_state == NUVO_LUN_STATE_DELETING);

            map_mfl = map_req->first_map;
            parent = map_mfl->parent;
            target_level = map_req->target_level + 1;
        }
        struct nuvo_dlist comp_list;
        nuvo_dlist_init(&comp_list);

        // we need to update the map entry in the existing map at the
        // logical location that the map we are replaying is at

        // we need to update the map entry for this map in the parent to
        // the new map entry we got from replay
        // if the map is in memory, we simply free the in-memory map that
        // was there

        // NOTE: the map in the map_req should be the parent
        NUVO_ASSERT(map_req->first_map == map_req->last_map);
        nuvo_mutex_lock(&parent->mutex);

        struct nuvo_map_entry *map_entry = &parent->entries[nuvo_map_get_table_index(map_req->block_start, target_level)];

        // L0 mfl => we must have the map loaded in mem
        if (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr) &&
            log_block->log_entry_type == NUVO_LE_MAP_L0)
        {
            NUVO_ASSERT(map_entry->type == NUVO_ME_IN_MEM);
        }

        NUVO_LOG_COND(map, 0, ((g_replay_count++ % 5000) == 0), "map_replay  g_replay_count:%d map:%p state:%d mfl:%d "
                      "map_entry(%lu:%lu) logger addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d "
                      "map_mfl:%p map lun(%d)",
                      g_replay_count,
                      parent, parent->state, parent->mfl,
                      map_entry->media_addr.parcel_index,
                      map_entry->media_addr.block_offset,
                      log_req->nuvo_map_entries[log_req->replay_count].media_addr.parcel_index,
                      log_req->nuvo_map_entries[log_req->replay_count].media_addr.block_offset,
                      parent->base_offset, parent->level, parent->is_dirty, map_mfl, parent->lun->snap_id);

        switch (map_entry->type)
        {
        case NUVO_ME_IN_MEM:
        {
            struct nuvo_map_track *map = map_entry->ptr;
            NUVO_ASSERT((map_mfl == NULL) || (map_mfl == map));

            nuvo_mutex_lock(&map->mutex);

            // if in mem, we need to free the in memory map
            // easiest way to do this is to pretend like we've just
            // written this map out, mark it clean, update map entry,
            // and evict it

            // in the case that the existing map is dirty, we also need
            //  to check if it was modified more recently than the map we are
            //  replaying.  If the in memory map is more recent, then we leave
            //  the dirty map marked as dirty.
            //  we do this by checking the hash of the applied map vs the one in memory

            NUVO_LOG_COND(map, 100, (!map->is_dirty && !map->level), "map:%p offset:%lu level:%d logger addr(%lu:%lu)",
                          map, map->base_offset, map->level,
                          log_req->nuvo_map_entries[log_req->replay_count].media_addr.parcel_index,
                          log_req->nuvo_map_entries[log_req->replay_count].media_addr.block_offset);



            if (!(NUVO_MEDIA_ADDR_EQUAL(&map->map_entry.media_addr,
                                        &log_req->nuvo_map_entries[log_req->replay_count].media_addr)) ||
                (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr)))
            {
                // if this an MFL replay , lets set up the lun and map state
                if (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr))
                {
                    // this must be a deleting pit
                    NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(lun));
                    NUVO_ASSERT(lun->lun_state == NUVO_LUN_STATE_DELETING);
                    // keep roll up mfl aware,
                    // CP_IN_PROGRESS can be set only after mfl is
                    // fully done, we dont know whether cp is fully
                    // done during replay unless we get a zero root map
                    // for roll up to trigger lun->mfl_state has to be non zero
                    lun->mfl_state = NUVO_LUN_MFL_L0_IN_PROGRESS;
                    // TODO -> rethink. it is possible we write out mfled maps mutlitple times during rollup?

                    if (!map->level)
                    {
                        // assert only for L0 blocks, since evictions could have made L1 maps already mfl
                        NUVO_DEBUG_ASSERT(!map->mfl, "CUM-2242 MFL-REPLAY-DOUBLE-FREE-- "
                                          "  map:%p state:%d mfl:%d media_addr:(%lu:%lu) offset:%lu ",
                                          "level:%d map->is_dirty:%d map_mfl:%p lun(%d)",
                                          map, map->state, map->mfl, map->map_entry.media_addr.parcel_index,
                                          map->map_entry.media_addr.block_offset,
                                          map->base_offset, map->level, map->is_dirty,
                                          map_mfl, map->lun->snap_id);
                        map_mfl_free_entries(map);
                    }
                }

                if (map->child_count)
                {
                    NUVO_LOG(map, 0, "CANNOT EVICT(child_count !=0)   map:%p state:%d child_count:%d "
                             "mfl:%d media_addr:(%lu:%lu) offset:%lu "
                             "level:%d map->is_dirty:%d map_mfl:%p lun(%d)",
                             map, map->state, map->child_count, map->mfl, map->map_entry.media_addr.parcel_index,
                             map->map_entry.media_addr.block_offset,
                             map->base_offset, map->level, map->is_dirty, map_mfl, map->lun->snap_id);
                    goto done;
                }

                map_req->first_map = map;
                map_req->last_map = map;

                // dont evict if there is a hash mismatch of the ondsk map block
                // and the inmem data.
                // unless we have a zero address replay where we dont zero the entries
                if (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr) == false)
                {
                    uint64_t    cv;
                    int         is_cv;
                    nuvo_hash_t hash;

                    hash = nuvo_hash_cv(map->entries, NUVO_BLOCK_SIZE, &cv, &is_cv);

                    if (hash != log_req->nuvo_map_entries[log_req->replay_count].hash)
                    {
                        NUVO_LOG(map, 30, "hash mismatch. issuing a read to check (new block?) --  map:%p state:%d child_count:%d mfl:%d media_addr:(%lu:%lu) offset:%lu "
                                 "level:%d map->is_dirty:%d map_mfl:%p lun(%d)",
                                 map, map->state, map->child_count, map->mfl, map->map_entry.media_addr.parcel_index,
                                 map->map_entry.media_addr.block_offset,
                                 map->base_offset, map->level, map->is_dirty, map_mfl, map->lun->snap_id);

                        // we have a hash mismatch
                        // We issue an async read to check map in memory and disk

                        // Note: this is somewhat of debug code and the read can be evenutally disabled.`
                        // If our code was bug free , all the hash mismatches are normal and expected because
                        // of the concurrent map updates with map flush.
                        // In CUM-2240, we had a bug in logger sending us map entries with usused value not inited.
                        // So this caused spurious hash fails,
                        // so this code reads the map entry from disk and goes ahead with the evict
                        // if the mismatch is spurious.

                        nuvo_map_pin_table(map);         //and pin before you unlock
                        nuvo_mutex_unlock(&map->mutex);
                        // let go of locks
                        nuvo_mutex_unlock(&parent->mutex);

                        struct nuvo_map_entry *map_entry_replay = &log_req->nuvo_map_entries[log_req->replay_count];

                        NUVO_LOG(map, 30, "replay read for map cmp issue i/o for (%u:%u) ",
                                 map_entry_replay->media_addr.parcel_index,
                                 map_entry_replay->media_addr.block_offset);
                        nuvo_map_replay_cmp_read_map(map_req, map_entry_replay);
                        return;
                    }
                }

                if (map_mfl)
                {
                    NUVO_ASSERT(NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr));
                }

                nuvo_map_replay_evict(map_req, map_mfl ? true : false);
            }
done:
            nuvo_mutex_unlock(&map->mutex);
        }
        break;

        case NUVO_ME_MEDIA:
            // if previous on media, tell the segment usage stats that
            // we're not using it anymore
            nuvo_mfst_segment_free_blks(&map_req->lun->vol->log_volume.mfst, 1, map_entry);
            // update the map entry and mark the parent as dirty
            // preseve the parent cow bit as parent cow bit must be correct
            // as the child is correct.
            NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(map_req->lun) || parent->snap_gen == vol->snap_generation);

            // no data op loaded the map into memory, since the map entry type is not INMEM
            // This must mean that the map was dirtied by an op before the cp
            // So the address in the tree we have must be same as the address we got.
            // But then GC updates maps without a corresponding data op
            // So we must take the new address and update the parent.

            int cow = map_entry->cow;
            *map_entry = log_req->nuvo_map_entries[log_req->replay_count];
            nuvo_mfst_segment_use_blks(&map_req->lun->vol->log_volume.mfst, 1, map_entry);
            map_entry->cow = cow;
            parent->is_dirty = 1;

            // If this is an mfl block replay and if we dont mark the parent as mfl,
            // a logger flush could give this map a a non zero address.
            // So we mark the parent as MFL is this is the last of the zero child blocks.
            // Applies only to L>0 maps, as L0 maps need to be explicltiy loaded into memory
            // for hole punching, as we see in the code above
            if (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr))
            {
                int mfl_child_count = map_parent_get_mfl_child_count(parent);
                if (mfl_child_count == NUVO_MAP_RADIX)
                {
                    parent->mfl = true;
                }
            }
            break;

        case NUVO_ME_NULL:
            NUVO_ASSERT(map_entry->cow == NUVO_MAP_ENTRY_SHARED);

            // shared blocks cannot be updated with a valid media addr
            // so we update the cow bit correctly.
            // In any case, we dont know how we got here, read the comments below.

            if (NUVO_LUN_IS_ACTIVE(parent->lun))
            {
                cow = NUVO_MAP_ENTRY_NONE;
            }
            else
            {
                cow = NUVO_MAP_ENTRY_COW;
            }

            // no data op loaded the map into memory, since the map entry type is not INMEM.
            // This must mean that the map was dirtied by an op before the cp
            // If that is the case, the map cannot be NULL(SHARED)
            NUVO_ASSERT(0);

        /* fall through */
        case NUVO_ME_CONST:
            // We see a constant parent map entry for a map that is getting replayed.
            // No data op could have loaded the map into memory, since the map entry type is not INMEM.
            // This must mean that the map was dirtied by an op before the cp
            // If that is the case, the map cannot be CONST

            // However we hit this case in CUM 1515.
            // This is explained by the following scenario. (which doesnt apply to pits and hence to shared map entries)

            // read an offset on active which is unwritten.
            // create a pit.
            // Re-read the original offset. Since this is after a pit was created, and the path was visited for the first time
            // on an already loaded path, reserve map part of the read would dirty the L>0 maps.
            // now close the lun. The L>0 maps above would be written out.
            // now reopen and replay the lun. The L>0 maps would be replayed. The parent map entry must be CONSTANT.

            // In the fix, we update the parent map entry with the replayed address and mark the parent as dirty

            // save map entry from parent if we are const
            // else we have already decided the cow bit.

            if (map_entry->type == NUVO_ME_CONST)
            {
                cow = map_entry->cow;
            }
            *map_entry = log_req->nuvo_map_entries[log_req->replay_count];
            map_entry->cow = cow;
            parent->is_dirty = 1;
            break;

        case NUVO_ME_LOADING:
        default:
            NUVO_PANIC("Invalid map entry type during map replay.");
            break;
        }

        if (!map_mfl)     // !map_mfl => we only loaded the parent, unpin the parent
        {
            nuvo_map_unpin_table(parent, &comp_list);
            nuvo_map_unpin_table(parent, &comp_list);
        }

        nuvo_mutex_unlock(&parent->mutex);

        // free any map tables that are the on the map_req list
        map_request_free(map_req, &comp_list);

        struct nuvo_map_alloc_req *req;
        while ((req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
        {
            req->callback(req);
        }
    }
    break;

    default:
        NUVO_PANIC("Invalid log block entry type in replay fault in.");
        break;
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

void nuvo_map_data_replay_rsv_cb(struct nuvo_map_request *map_req)
{
    // reserve has finished, now do fault-in
    // if there is a snap shot, lets get do the reserve for
    // the snap lun as well

    struct nuvo_log_request *log_req = map_req->tag.ptr;
    struct nuvo_vol         *vol = log_req->vs_ptr;

    if (vol->snap_generation) // if we have at least one snapshot
    {
        // note :peer-cow is another word of the youngest/latest lun
        // if snap_generation is non zero, we at least have one snapshot.
        // ideally we can pre check by reading the active L0 map whether the write will cause
        // COWs and load the maps in the peer-cow lun only if it is needed
        // But optmizating perf for replay is not a top concern at the moment.
        struct nuvo_lun *snap_lun = nuvo_get_peer_cow_lun(vol, false);
        NUVO_ASSERT(snap_lun); // since we have snap_generation as non zero
        struct nuvo_map_request *map_req_snap = &log_req->map_req_snap;
        uint_fast32_t            block_count = map_req->block_last - map_req->block_start + 1;

        nuvo_map_request_init(map_req_snap, snap_lun, map_req->block_start, block_count);
        map_req_snap->tag.ptr = log_req;
        map_req_snap->callback = nuvo_map_data_replay_snap_rsv_cb;
        nuvo_map_reserve(map_req_snap);
        return;
    }
    // if there is no snapshot, proceed with active.

    map_req->callback = nuvo_map_replay_fault_cb;
    nuvo_map_fault_in(map_req);
}

void nuvo_map_gc_data_replay_rsv_cb(struct nuvo_map_request *map_req)
{
    map_req->callback = nuvo_map_replay_fault_cb;
    nuvo_map_fault_in(map_req);
}

void nuvo_map_replay_next(struct nuvo_log_request *log_req)
{
    // for a first stab we can just do each block one at a time
    //  TODO: to optimize this a bit, it would be nice to group logically

    //          contiguous operations together
    // prepare a map request for the next block in the log req
    struct nuvo_log_io_block *log_block = &log_req->log_io_blocks[log_req->replay_count];
    struct nuvo_map_request  *map_req = &log_req->map_req;

    switch (log_block->log_entry_type)
    {
    case NUVO_LE_EMPTY:
    case NUVO_LE_FORK:
    case NUVO_LE_HEADER:
    case NUVO_LE_DESCRIPTOR:
        // just move onto the next block
        log_req->replay_count++;
        nuvo_map_replay_next(log_req);
        break;

    case NUVO_LE_DATA:
    {
        struct nuvo_lun *lun;
        if (log_req->operation == NUVO_LOG_OP_DATA)
        {
            // prep and start a regular data fault-in
            // there may be a snap lun, anyway first reserve for the active lun
            lun = &log_req->vs_ptr->log_volume.lun;
            nuvo_map_request_init(map_req, lun, log_block->bno, 1);
            map_req->tag.ptr = log_req;
            map_req->callback = nuvo_map_data_replay_rsv_cb;
            nuvo_map_reserve(map_req);
        }
        else
        {
            NUVO_ASSERT(log_req->operation == NUVO_LOG_OP_GC);
            lun = log_block->pit_info.active ?
                  &log_req->vs_ptr->log_volume.lun :
                  nuvo_get_lun_by_snapid(log_req->vs_ptr, log_block->pit_info.pit_id, false);
            // Pick the correct lun
            nuvo_map_request_init(map_req, lun, log_block->bno, 1);
            map_req->op = NUVO_MAP_REQUEST_OP_GC;
            map_req->tag.ptr = log_req;
            map_req->callback = nuvo_map_gc_data_replay_rsv_cb;
            nuvo_map_reserve(map_req);
        }
    }
    break;

    case NUVO_LE_MAP_L0:
    case NUVO_LE_MAP_L1:
    case NUVO_LE_MAP_L2:
    case NUVO_LE_MAP_L3:
    case NUVO_LE_MAP_L4:
    {
        struct nuvo_vol *vol = log_req->vs_ptr;
        struct nuvo_lun *lun = nuvo_get_lun_by_snapid(vol, log_block->pit_info.active ? NUVO_MFST_ACTIVE_LUN_SNAPID : log_block->pit_info.pit_id, false);
        NUVO_ASSERT(lun);
        nuvo_map_request_init(map_req, lun, log_block->bno, 1);
        // override the level in the map req to be the map's parent
        // unless this is a case of L0 mfl
        // for which, we must load the L0 to free the map entries
        map_req->target_level = log_block->log_entry_type - NUVO_LE_MAP_L0 + 1;

        if (NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr) &&
            log_block->log_entry_type == NUVO_LE_MAP_L0)
        {
            map_req->target_level = 0;
        }

        // check if this happens to be the root map
        if ((unsigned)map_req->target_level == map_req->lun->map_height)
        {
            // if that's the case, we can just update the root map here
            struct nuvo_map_track *root_map = map_req->lun->root_map;

            // The in-mem map tree is re-created by the set of replay ops which update the map (both data and GC)
            // If the root map (or any intermediate) has children, we don't evict the root map, but trust the in-mem tree.
            // And every map block that is replayed, we evict the in-mem map, if
            // -- the hash of the logger map entry matches with that of the computed hash of the in-mem map block.
            // -- if the in-mem map has no children (since we can't even compute the hash correctly and we know that
            // we didnt get a replay for a child map since it isn't evicted)

            if (root_map->child_count)     // if the rest of the tree isn't evicted, don't take logger's replay address.
            {
                goto replay_next;
            }

            uint64_t    cv;
            int         is_cv;
            nuvo_hash_t hash;

            if (!NUVO_MEDIA_ADDR_FREE(&log_req->nuvo_map_entries[log_req->replay_count].media_addr))
            {
                hash = nuvo_hash_cv(root_map->entries, NUVO_BLOCK_SIZE, &cv, &is_cv);
                NUVO_ASSERT(!is_cv);     // since, map blocks cannot be all constant

                // To be sure that what we have in memory matches what
                // was in the log, we should probably re-read the root map
                // table here. We do a hash check here and accept the on-disk map only
                // when they match
                //
                // So, dont replay if there is a hash mismatch of the on-media map block
                // and the in-mem data.
                if (hash != log_req->nuvo_map_entries[log_req->replay_count].hash)
                {
                    goto replay_next;
                }
            }

            nuvo_mutex_lock(&root_map->mutex);
            root_map->is_new_entry = 1;
            root_map->is_dirty = 0;

            NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(lun) || (root_map->snap_gen == vol->snap_generation));

            int cow = root_map->map_entry.cow;
            //copy the log entry media addr to the map without losing the cow bit
            log_req->nuvo_map_entries[log_req->replay_count].cow = root_map->map_entry.cow;
            root_map->map_entry = log_req->nuvo_map_entries[log_req->replay_count];
            root_map->map_entry.cow = cow;
            nuvo_mutex_unlock(&root_map->mutex);

            // if we get a root map replay for mfl
            // call the lun as DELETING DONE
            if (NUVO_ME_IS_MFL_DONE(&root_map->map_entry))
            {
                nuvo_mutex_lock(&lun->mutex);
                // we must get the lun state right by now
                NUVO_ASSERT(lun->lun_state == NUVO_LUN_STATE_DELETING);
                lun->mfl_state = NUVO_LUN_MFL_CP_DONE;
                NUVO_LOG(lun, 0, "set lun(%d) mfl_state to MFL_CP_DONE", lun->snap_id);
                nuvo_mutex_unlock(&lun->mutex);
            }


replay_next:
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
        else
        {
            map_req->tag.ptr = log_req;
            map_req->callback = nuvo_map_replay_rsv_cb;
            nuvo_map_reserve(map_req);
        }
    }
    break;

    default:
        NUVO_PANIC("Unrecognized log block entry type in replay.");
    }
}

void nuvo_map_replay(struct nuvo_log_request *log_req)
{
    NUVO_ASSERT(log_req->block_count > 0);
    // we need to replay this log request
    log_req->replay_count = 0;

    nuvo_map_replay_next(log_req);

    return;
}

nuvo_return_t nuvo_map_checkpoint_sync(struct nuvo_vol *vol, struct nuvo_map_entry *map_entry)
{
    nuvo_return_t ret = 0;
    nuvo_mutex_t  sync_signal;
    struct nuvo_map_checkpoint_req cp_req;

    ret = nuvo_mutex_init(&sync_signal);
    if (ret < 0)
    {
        return (ret);
    }

    cp_req.tag.ptr = &sync_signal;
    cp_req.callback = nuvo_map_checkpoint_sync_cb;
    cp_req.vol = vol;

    nuvo_mutex_lock(&sync_signal);
    nuvo_map_checkpoint(&cp_req);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    *map_entry = cp_req.lun_cp_map_entry[0].root_map_entry;

    return (cp_req.status);
}

void nuvo_map_lun_close_rc(struct nuvo_map_track *map)
{
    // free any children of this map if present, then fee this map

    nuvo_mutex_lock(&map->mutex);
    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        struct nuvo_map_entry *map_entry = &map->entries[i];
        if (map_entry->type == NUVO_ME_IN_MEM)
        {
            nuvo_map_lun_close_rc(map_entry->ptr);
        }
    }
    // maps should not have shadows when we are shutting down
    NUVO_ASSERT(map->shadow_link == NULL);

    nuvo_mutex_lock(&nuvo_map->list_mutex);

    // mark tables as clean, regardless of their actual state
    map->is_dirty = 0;
    nuvo_map_evict_table(map);

    nuvo_mutex_unlock(&nuvo_map->list_mutex);
    nuvo_mutex_unlock(&map->mutex);
}

// to close a lun, we need to clean out the dirty maps
// this is implemented through CP today for the active LUN.
// And we  dont yet implement CP for snap luns
// Since CP will be soon implemented for snap LUNs
// it is futile at this point of time to clean out
// the dirty maps by hand at the time of lun close
// The side effect of this is that you lose some data
// across shutdown and restart of the volume
// This will be soon fixed with the CP for snap luns

nuvo_return_t nuvo_map_lun_close(struct nuvo_lun *lun, struct nuvo_map_entry *map_entry)
{
    nuvo_return_t     ret = 0;
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);

    NUVO_LOG(map, 0, "vol:%p lun(%d) close lun lun_state:%d export_state:%d export_cnt on vol:%d",
             lun->vol,
             lun->snap_id,
             lun->lun_state,
             lun->export_state,
             lun->vol->export_cnt);

    if (NUVO_LUN_IS_EXPORTED(lun))
    {
        if (lun->vol->shutdown_in_progress)
        {
            char uuid_str[UUID_UNPARSED_LEN];
            uuid_unparse(lun->lun_uuid, uuid_str);
            NUVO_ERROR_PRINT("Exported Lun %s detected during shutdown.",
                             uuid_str);
            // The shutdown process will clean up after us.
            // nuvo_free_fs() will cleanup the directory entries
            ret = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);
            NUVO_ASSERT(ret == 0);
        }
        else
        {
            return (-NUVO_E_LUN_EXPORTED);
        }
    }

    // can close the lun only once.
    NUVO_ASSERT(NUVO_MAP_IS_LUN_OPEN(lun));

    // to close a lun's map, we first checkpoint it, and then free the maps
    // in the tree
    // Note(suresh): We dont need to checkpoint the lun on lun close unless it is active.
    // This is because  lun close is called for two reasons
    // 1) a volume series is closed on the node. In this case, the active LUN close
    // will checkpoint all the luns
    // 2) delete pit-> In this case we dont need to checkpoint as we are deleting the pit
    if (NUVO_LUN_IS_ACTIVE(lun))
    {
        ret = nuvo_map_checkpoint_sync(lun->vol, map_entry);
        if (ret < 0)
        {
            return (ret);
        }
    }

    struct nuvo_map_track *root_map = lun->root_map;
    lun->root_map = NULL;

    // traverse and free the tree
    nuvo_mutex_lock(&root_map->mutex);
    for (uint_fast16_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        struct nuvo_map_entry *child_entry = &root_map->entries[i];
        if (child_entry->type == NUVO_ME_IN_MEM)
        {
            nuvo_map_lun_close_rc(child_entry->ptr);
        }
    }

    // make clean, regardless of real state
    root_map->is_dirty = 0;
    *map_entry = root_map->map_entry;

    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_unpin_table_locked(root_map);
    nuvo_map_evict_table(root_map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    nuvo_mutex_unlock(&root_map->mutex);

    nuvo_map_alloc_run();
    return (0);
}

//allocate mem for lun root map. do this before getting the vol lock
// hold the vol lock
// alloc new lun, and open for new snap
// update the active map root map
// release the vol lock
struct nuvo_lun *nuvo_map_create_snap(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    struct nuvo_map_track *root_map = nuvo_map_alloc_map_sync();

    if (!root_map)
    {
        return (NULL);
    }

    nuvo_mutex_lock(&vol->mutex);
    struct nuvo_lun *lun = nuvo_map_lun_alloc_and_open_nl(vol, lun_uuid, root_map);
    if (!lun)
    {
        //release the allocated map memory
        goto _out;
    }

    struct nuvo_lun *active_lun = &vol->log_volume.lun;
    nuvo_map_snap_update_active_nl(active_lun, lun);
    nuvo_mutex_unlock(&vol->mutex);
    return (lun);

_out:

    nuvo_mutex_unlock(&vol->mutex);
    root_map->state = NUVO_MAP_CLEAN_LIST;
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_clean_insert_tail_noalloc(root_map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
    return (NULL);
}

struct nuvo_map_track *nuvo_map_alloc_map_sync()
{
    // first alloc the root map table
    struct nuvo_dlist alloc_list;

    nuvo_dlist_init(&alloc_list);
    struct nuvo_map_alloc_req alloc_req;
    nuvo_mutex_t sync_signal;

    nuvo_return_t rc = nuvo_mutex_init(&sync_signal);
    NUVO_ASSERT(!rc);

    nuvo_mutex_lock(&sync_signal);
    alloc_req.count = 1;
    alloc_req.map_list = &alloc_list;
    alloc_req.callback = nuvo_map_alloc_tables_sync_cb;
    alloc_req.tag.ptr = &sync_signal;
    rc = nuvo_map_alloc_tables(&alloc_req, false);
    NUVO_ASSERT(rc >= 0); // non-pinned version should never fail
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    struct nuvo_map_track *map = nuvo_dlist_remove_head_object(&alloc_list, struct nuvo_map_track, list_node);
    NUVO_ASSERT(map != NULL);

    return (map);
}

// create a map from the map entry, reading if necessary
// now lock
// alloc the lun entry
// set up the lun root map
// copy the shared entries to the child entries in the root map
// pin the root map etc
struct nuvo_lun *nuvo_map_lun_alloc_and_open_nl(struct nuvo_vol *vol, const uuid_t lun_uuid, struct nuvo_map_track *map)
{
    struct nuvo_lun *lun;

    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    if (!(lun = nuvo_lun_alloc(vol, false)))
    {
        return (NULL);
    }

    struct nuvo_map_entry *map_entry = &lun->root_map_entry;

    map_entry->type = NUVO_ME_NULL;
    map_entry->cow = NUVO_MAP_ENTRY_SHARED;

    struct nuvo_lun *active_lun = &vol->log_volume.lun;
    /// set up the lun to be a pit of active lun
    uuid_copy(lun->lun_uuid, lun_uuid);
    lun->snap_id = ++(vol->snap_generation);
    lun->size = active_lun->size;
    lun->map_height = active_lun->map_height;

    map->cp_gen = lun->vol->log_volume.map_state.checkpoint_gen;
    map->snap_gen = lun->vol->snap_generation;
    map->state = NUVO_MAP_PINNED;
    map->level = lun->map_height - 1;
    map->base_offset = nuvo_map_get_base_offset(0, map->level);
    map->lun = lun;
    map->vol = lun->vol;
    map->parent = NULL;
    map->is_dirty = 0;
    map->child_count = 0;
    map->is_new_entry = 0;
    map->shadow_link = NULL;
    map->pinned = 1;

    map->map_entry = *map_entry;

    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        map->entries[i] = *map_entry;
    }
    lun->root_map = map;
    NUVO_PRINT("create lun(%d)", lun->snap_id);

    // create the snap , ie udpate the active root map to COWs
    // we have done all the work on the snap lun
    //nuvo_map_create_snap_nl(active_lun, lun);
    //nuvo_map_snap_update_active_nl

    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_pinned_insert(map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
    //nuvo_mutex_unlock(&vol->mutex);
    return (lun);
}

// update the active root map in mem
// make all childr entries as COW
void nuvo_map_snap_update_active_nl(struct nuvo_lun *active_lun,
                                    struct nuvo_lun *snap_lun)
{
    NUVO_ASSERT(active_lun->vol == snap_lun->vol);

    struct nuvo_vol *vol = active_lun->vol;
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    //NUVO_LOG(map, 1, "create snap for snap lun(%d)", snap_lun->snap_id);

    uint_fast64_t checkpoint_gen = vol->log_volume.map_state.checkpoint_gen;
    nuvo_mutex_lock(&active_lun->mutex);
    nuvo_mutex_lock(&active_lun->root_map->mutex);
    struct nuvo_map_track *root_map = active_lun->root_map;
    nuvo_mutex_unlock(&active_lun->mutex);

    struct nuvo_map_track *snap_root_map = snap_lun->root_map;

    // mark the MEs in root map as COW
    // and that in snapshot root map as SHARED
    // note:  no media addr copy optmization yet.

    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        root_map->entries[i].cow = NUVO_MAP_ENTRY_COW;
        NUVO_ASSERT(snap_root_map->entries[i].cow == NUVO_MAP_ENTRY_SHARED);
        NUVO_ASSERT(snap_root_map->entries[i].type == NUVO_ME_NULL);
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


    /*    snap_lun->root_map->is_dirty = 1;
     *    active_lun->root_map->is_dirty = 1;
     */

    //nuvo_mutex_unlock(&snap_lun->root_map->mutex);
    nuvo_mutex_unlock(&active_lun->root_map->mutex);
}

void nuvo_map_multi_lun_commit_write(struct nuvo_map_request *map_req,
                                     struct nuvo_map_request *map_req_snap,
                                     struct nuvo_map_entry   *new_entries)
{
    struct nuvo_vol *vol = map_req->lun->vol;

    // we hold the volume lock across nuvo_map_commit lock
    // so that cp_gen doesnt change across the calls.
    // and both the updates are in the same cp.

    nuvo_mutex_lock(&vol->mutex);
    uint64_t checkpoint_gen = vol->log_volume.map_state.checkpoint_gen;

    map_req->cp_commit_gen = checkpoint_gen;
    map_req_snap->cp_commit_gen = checkpoint_gen;

    // lock the paths in both the luns
    // commit on both
    // release both
    nuvo_map_commit_lock(map_req_snap);
    nuvo_map_commit_lock(map_req);

    nuvo_mutex_unlock(&vol->mutex);

    struct nuvo_map_entry snap_entries[NUVO_MAX_IO_BLOCKS];

    if (nuvo_map_update_entries(map_req, new_entries, snap_entries,
                                NULL /*old media addrs*/,
                                true /*(multi_lun*/,
                                NULL /* succeeded updates */,
                                NULL /* failed_updates */))
    {
        // snap entries from active are new entries for the snap lun
        nuvo_map_update_entries(map_req_snap, snap_entries /* new entries */,
                                NULL /* snap entries */,
                                NULL /* old media addrs*/,
                                true /*multi lun*/,
                                NULL /* succeeded updates */,
                                NULL /* failed_updates */);
    }

    nuvo_map_commit_unlock(map_req);
    nuvo_map_commit_unlock(map_req_snap);
}

void nuvo_map_single_lun_read(struct nuvo_map_request *req,
                              struct nuvo_map_entry   *entries,
                              bool                     pin)
{
    nuvo_map_read_lock(req);
    nuvo_map_read_entries(req, entries, pin, false /*multi_lun*/);
    nuvo_map_read_unlock(req);
}

void nuvo_map_multi_lun_read(struct nuvo_map_request *map_req_snap,
                             struct nuvo_map_request *map_req_active,
                             struct nuvo_map_entry   *entries,
                             bool                     pin)
{
    // lock the paths in both the luns
    // read on both
    // release both
    nuvo_map_read_lock(map_req_snap);
    nuvo_map_read_lock(map_req_active);

    uint_fast32_t block_count = (uint_fast32_t)(map_req_snap->block_last - map_req_snap->block_start + 1);
    uint_fast32_t read_cnt = nuvo_map_read_entries(map_req_snap, entries, pin, true /* multi lun */);

    NUVO_ASSERT(read_cnt <= block_count);

    if (read_cnt != block_count)
    {
        // snap entries from active are new entries for the snap lun
        int ror_active_cnt = nuvo_map_read_entries(map_req_active, entries, pin, true /* multi lun */);

        NUVO_ASSERT(ror_active_cnt + read_cnt == block_count);  //we must read everything
    }

    nuvo_map_read_unlock(map_req_snap);
    nuvo_map_read_unlock(map_req_active);
}

void nuvo_map_commit_write(struct nuvo_map_request *req,
                           struct nuvo_map_entry   *new_entries)
{
    struct nuvo_vol *vol = req->lun->vol;

    nuvo_mutex_lock(&vol->mutex);
    uint64_t checkpoint_gen = vol->log_volume.map_state.checkpoint_gen;

    req->cp_commit_gen = checkpoint_gen;

    nuvo_map_commit_lock(req);
    nuvo_mutex_unlock(&vol->mutex);
    nuvo_map_update_entries(req, new_entries,
                            NULL /*snap_entries */,
                            NULL,
                            false /*multi_lun*/,
                            NULL /* succeeded updates */,
                            NULL /* failed_updates */);
    nuvo_map_commit_unlock(req);
}

void nuvo_map_commit_gc_write(struct nuvo_map_request *req,
                              struct nuvo_map_entry   *new_entries,
                              struct nuvo_media_addr  *old_media_addrs,
                              uint_fast32_t           *succeeded,
                              uint_fast32_t           *not_applied)
{
    struct nuvo_vol *vol = req->lun->vol;

    nuvo_mutex_lock(&vol->mutex);
    uint64_t checkpoint_gen = vol->log_volume.map_state.checkpoint_gen;

    req->cp_commit_gen = checkpoint_gen;

    nuvo_map_commit_lock(req);
    nuvo_mutex_unlock(&vol->mutex);
    *not_applied = 0;
    *succeeded = 0;
    nuvo_map_update_entries(req,
                            new_entries,
                            NULL /*snap_entries */,
                            old_media_addrs,
                            false /*multi_lun*/,
                            succeeded,
                            not_applied);
    nuvo_map_commit_unlock(req);
}

uint_fast32_t nuvo_map_update_entries(struct nuvo_map_request *req,
                                      struct nuvo_map_entry   *new_entries,
                                      struct nuvo_map_entry   *snap_entries,
                                      struct nuvo_media_addr  *old_media_addrs,
                                      bool                     multi_lun,
                                      uint_fast32_t           *succeeded_gc,
                                      uint_fast32_t           *failed_gc)
{
    uint_fast32_t snap_count = 0;

    if (req->first_map == req->last_map)
    {
        struct nuvo_map_track *map = req->first_map;
        uint_fast32_t          block_count = req->block_last - req->block_start + 1;
        uint_fast32_t          table_index = nuvo_map_get_table_index(req->block_start, 0);
        NUVO_ASSERT(nuvo_map_get_base_offset(req->block_start, 0) == nuvo_map_get_base_offset(req->block_last, 0));
        // double check that we don't span tables
        NUVO_ASSERT(table_index + block_count <= NUVO_MAP_RADIX);

        snap_count += map_update_entries(req, map, req->cp_commit_gen,
                                         block_count, &map->entries[table_index], new_entries,
                                         snap_entries, old_media_addrs, multi_lun, succeeded_gc, failed_gc);
    }
    else
    {
        // entries are split between two maps
        uint_fast32_t first_index = nuvo_map_get_table_index(req->block_start, 0);
        uint_fast32_t first_count = NUVO_MAP_RADIX - first_index;

        uint_fast32_t last_index = nuvo_map_get_table_index(req->block_last, 0);
        uint_fast32_t last_count = last_index + 1;

        NUVO_ASSERT(first_count + last_count == req->block_last - req->block_start + 1);

        struct nuvo_map_track *first_map = req->first_map;
        struct nuvo_map_track *last_map = req->last_map;

        snap_count += map_update_entries(req, first_map, req->cp_commit_gen, first_count,
                                         &first_map->entries[first_index],
                                         new_entries,
                                         snap_entries,
                                         old_media_addrs,
                                         multi_lun, succeeded_gc, failed_gc);
        snap_count += map_update_entries(req, last_map, req->cp_commit_gen, last_count,
                                         &last_map->entries[0],
                                         &new_entries[first_count],
                                         snap_entries == NULL ? NULL : &snap_entries[first_count],
                                         old_media_addrs == NULL ? NULL : &old_media_addrs[first_count],
                                         multi_lun, succeeded_gc, failed_gc);
    }

    return (snap_count);
}

/*Documented in header */
bool nuvo_map_is_cow_reqd(struct nuvo_map_request *req)
{
    return (map_entries_are_cow_or_shared(req, NUVO_MAP_ENTRY_COW));
}

/*Documented in header */
bool nuvo_map_is_ror_reqd(struct nuvo_map_request *req)
{
    return (map_entries_are_cow_or_shared(req, NUVO_MAP_ENTRY_SHARED));
}

bool map_entries_are_cow_or_shared(struct nuvo_map_request *req, nuvo_map_entry_snap_type entry_type)
{
    // we have two paths, depending on whether the first and last map
    //  are the same
    bool ret = false;

    NUVO_ASSERT(entry_type != NUVO_MAP_ENTRY_NONE); //code is supported only for cow or shared, as of now
    nuvo_map_read_lock(req);

    if (req->first_map == req->last_map)
    {
        // verify maps are same, though it is implied
        NUVO_ASSERT(nuvo_map_get_base_offset(req->block_start, 0) == nuvo_map_get_base_offset(req->block_last, 0));
        uint_fast32_t block_count = req->block_last - req->block_start + 1;
        uint_fast32_t table_index = nuvo_map_get_table_index(req->block_start, 0);
        // double check that we don't span tables
        NUVO_ASSERT(table_index + block_count <= NUVO_MAP_RADIX);

        // all entries are within one map
        struct nuvo_map_track *map = req->first_map;


        // make sure we are at the right level of the table
        NUVO_ASSERT(map->level == 0);
        // double check that this is the right table
        NUVO_ASSERT(map->base_offset == nuvo_map_get_base_offset(req->block_start, 0));

        struct nuvo_map_entry *entries = &map->entries[table_index];

        uint8_t cow = NUVO_MAP_ENTRY_NONE;
        /* fabricated cow since L0 is not updated yet */

        if (NUVO_LUN_IS_ACTIVE(map->lun) && (map->snap_gen < req->snap_gen))
        {
            cow = NUVO_MAP_ENTRY_COW;
        }

        for (uint_fast32_t i = 0; i < block_count; i++)
        {
            if ((cow == entry_type) || (entries[i].cow == entry_type))
            {
                ret = true;
                break;
            }
        }
    }
    else
    {
        // entries are split between two maps
        uint_fast32_t first_index = nuvo_map_get_table_index(req->block_start, 0);
        uint_fast32_t first_count = NUVO_MAP_RADIX - first_index;

        uint_fast32_t last_index = nuvo_map_get_table_index(req->block_last, 0);
        uint_fast32_t last_count = last_index + 1;

        NUVO_ASSERT(first_count + last_count == req->block_last - req->block_start + 1);

        struct nuvo_map_track *first_map = req->first_map;
        struct nuvo_map_track *last_map = req->last_map;


        // make sure we are at the right level of the table
        NUVO_ASSERT(first_map->level == 0);
        NUVO_ASSERT(last_map->level == 0);
        // double check that this is the right table
        NUVO_ASSERT(first_map->base_offset == nuvo_map_get_base_offset(req->block_start, 0));
        NUVO_ASSERT(last_map->base_offset == nuvo_map_get_base_offset(req->block_last, 0));

        struct nuvo_map_entry *first_entries = &first_map->entries[first_index];
        struct nuvo_map_entry *last_entries = &last_map->entries[0];

        uint8_t cow = NUVO_MAP_ENTRY_NONE;

        /* fabricated cow since L0 is not updated yet */

        if (NUVO_LUN_IS_ACTIVE(first_map->lun) && (first_map->snap_gen != req->snap_gen))
        {
            cow = NUVO_MAP_ENTRY_COW;
        }

        for (uint_fast32_t i = 0; i < first_count; i++)
        {
            if ((cow == entry_type) || (first_entries[i].cow == entry_type))
            {
                ret = true;
                goto _out;
            }
        }
        cow = NUVO_MAP_ENTRY_NONE;

        if (NUVO_LUN_IS_ACTIVE(last_map->lun) && (last_map->snap_gen != req->snap_gen))
        {
            cow = NUVO_MAP_ENTRY_COW;
        }
        for (uint_fast32_t i = 0; i < last_count; i++)
        {
            if ((cow == entry_type) || (last_entries[i].cow == entry_type))
            {
                ret = true;
                break;
            }
        }
    }
_out:
    nuvo_map_read_unlock(req);
    return (ret);
}

// Documented in header
void nuvo_map_rewrite_init(struct nuvo_map_request *map_req,
                           struct nuvo_lun         *lun,
                           uint64_t                 bno,
                           uint_fast16_t            level)
{
    nuvo_map_request_init(map_req, lun, bno, 1);
    map_req->target_level = level;
}

// Documented in header
void nuvo_map_rewrite(struct nuvo_map_request *map_req)
{
    NUVO_ASSERT(map_req->map_entries[0].type == NUVO_ME_MEDIA);
    NUVO_ASSERT(map_req->first_map == map_req->last_map);
    NUVO_ASSERT(map_req->target_level == map_req->first_map->level);

    struct nuvo_vol *vol = map_req->lun->vol;
    NUVO_LOG(space, 55, "nuvo_map_rewrite " NUVO_LOG_UUID_FMT ", called to free map (level %d) address (%d, %d) at next CP.",
             NUVO_LOG_UUID(vol->vs_uuid), map_req->target_level, map_req->first_map->map_entry.media_addr.parcel_index, map_req->first_map->map_entry.media_addr.block_offset);

    nuvo_mutex_lock(&vol->mutex);
    nuvo_map_rewrite_lock(map_req);
    nuvo_mutex_unlock(&vol->mutex);

    struct nuvo_map_track *map = map_req->first_map;
    // MFL note: if this map is mfled and rolled up and written out, the address wouldn't match the
    // current address GC is trying to rewrite from
    // else map must be mfl in memory and hence the check below
    if (map->map_entry.media_addr.parcel_index == map_req->map_entries[0].media_addr.parcel_index &&
        map->map_entry.media_addr.block_offset == map_req->map_entries[0].media_addr.block_offset)
    {
        NUVO_LOG(space, 25, "nuvo_map_rewrite " NUVO_LOG_UUID_FMT ", freeing map (level %d) address (%d, %d) at next CP.",
                 NUVO_LOG_UUID(vol->vs_uuid), map_req->target_level, map->map_entry.media_addr.parcel_index, map->map_entry.media_addr.block_offset);
        // mark table as dirty
        // cp_gen is not handled, if this is in a previous cp, next CP would write out.
        // is_dirty would consider

        //
        // Assert GC isnt doing anything crazy like rewriting from a zero address.
        NUVO_ASSERT(!NUVO_ME_IS_MFL_DONE(&map->map_entry));

        if (!map->mfl) //dont rewrite mfl ed maps. Can cause double zero writes to the logger
        {
            map->is_dirty = 1;
        }
    }

    nuvo_map_rewrite_unlock(map_req);
    map_request_free(map_req, NULL); // TODO? lets try calling the alloc from here someday with a comp_list
    map_req->status = 0;
}

bool map_mfl_free_entries(struct nuvo_map_track *map)
{
    bool is_dirty = false;

    NUVO_ASSERT(map->level == 0);
    NUVO_ASSERT_MUTEX_HELD(&map->mutex);

    // We might MFL free an L0 block again because of replay
    // MFL L0 happens -> we write out the map block
    // and we restart the MFL during replay.

    // Also, is snap lun check to keep UT happy (yes, that sucks)

    if (!NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_ME_IS_MFL_DONE(&map->map_entry))
    {
        NUVO_LOG_COND(map, 80, true, "MAP_FREE_LUN L0 DIRTY already mfled  is_dirty:%d map :%p me type:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                      is_dirty, map, map->map_entry.type, map->map_entry.media_addr.parcel_index,
                      map->map_entry.media_addr.block_offset,
                      map->base_offset, map->level, map->is_dirty);
        map->mfl = true; //but not dirty
        goto _out;
    }

    //If GC sees an MFLed map block it would pretend that
    //the block is written out and consider it as success.

    //
    // The map can be already mfl during replay because replay could have
    // replayed some of these mfl maps and mark them as mfled
    // We start the hole punching from offset = 0 for luns who arent deleting done
    // hence we can see map->mfl during restart of lun deletion post replay
    if (map->mfl)
    {
        NUVO_ASSERT(map->is_dirty);
        NUVO_LOG(map, 25, "map already freed:%p possibly during replay offset:%u", map, map->base_offset);
        goto _out;
    }

    for (uint_fast32_t i = 0; i < NUVO_MAP_RADIX; i++)
    {
        if (map->entries[i].type == NUVO_ME_MEDIA)
        {
            nuvo_mfst_segment_free_blks(&map->vol->log_volume.mfst, 1, &(map->entries[i]));
            is_dirty = true;
            memset(&map->entries[i], 0, sizeof(struct nuvo_map_entry));
        }
        else if (map->entries[i].cow == NUVO_MAP_ENTRY_COW) //const blocks cowed to the map
        {
            is_dirty = true;
        }
    }

    map->mfl = true; // it is possible that map can be mfl but not dirty.
                     // clean maps are rolled back but not written out through logger.
    if (is_dirty)
    {
        // some sanity checks.
        // if the map has a media addr it must be cow
        // on active it must be none. Active lun is only used by UT.
        NUVO_ASSERT(NUVO_MEDIA_ADDR_FREE(&map->map_entry.media_addr) ||
                    (!NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_MAP_IS_COW(map)) ||
                    (NUVO_LUN_IS_ACTIVE(map->lun) && NUVO_MAP_IS_NONE(map)));
        // if the map has data entries with valid media addresses, the map must be already cow
        // and has a valid address
        // OR it must be dirty or must be in shadow.
        NUVO_ASSERT((!NUVO_MEDIA_ADDR_FREE(&map->map_entry.media_addr)) || map->is_dirty || map->shadow_link);

        NUVO_LOG(map, 80, "MAP_FREE_LUN L0 DIRTY vol:%p is_dirty:%d map :%p me type:%d "
                 "media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                 map->vol, is_dirty, map, map->map_entry.type, map->map_entry.media_addr.parcel_index,
                 map->map_entry.media_addr.block_offset,
                 map->base_offset, map->level, map->is_dirty);

        map->is_dirty = 1;
        NUVO_LUN_STAT_MFL_COUNT(map->lun);
    }
    else
    {
        // the active check is to keep UT happy.
        NUVO_ASSERT(NUVO_MAP_IS_SHARED(map) || NUVO_LUN_IS_ACTIVE(map->lun));
        NUVO_ASSERT(NUVO_MEDIA_ADDR_FREE(&map->map_entry.media_addr));
        //Below, we are mfl setting a shared clean map entry
        // we are hand setting as this would not go through the logger
        // it is easy to do roll up counting if we do this.
        NUVO_ME_SET_MFL_DONE(&map->map_entry);
    }
_out:

    return (is_dirty);
}
