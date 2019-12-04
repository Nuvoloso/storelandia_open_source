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

#include <stdlib.h>


void nuvo_map_mfl_req_init(struct nuvo_map_free_lun_request *mfl_req, struct nuvo_lun *lun)
{
    mfl_req->lun = lun;
    mfl_req->offset = 0;
    mfl_req->free_offset = 0;
    mfl_req->map_mfl_cnt = 0;
    mfl_req->map_load_cnt = 0;
    mfl_req->state = MFL_IN_PROGRESS;
    mfl_req->work_state = MFL_WORK_LOAD_MAPS;
    mfl_req->dirty_cnt = 0;
    NUVO_PRINT("mfl work begin on lun(%d) lun_state:%d", lun->snap_id, lun->lun_state);
}

bool nuvo_map_mfl_is_paused(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT_MUTEX_HELD(&mfl_req->mutex);
    return (mfl_req->state == MFL_PAUSED);
}

void nuvo_map_mfl_pause(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT_MUTEX_HELD(&mfl_req->mutex);
    mfl_req->state = MFL_PAUSED;
}

static int nuvo_map_mfl_dirty_cnt_threshold = NUVO_MAP_MFL_DIRTY_CNT_THRESHOLD;

void nuvo_map_mfl_set_dirty_cnt_threshold(int threshold)
{
    NUVO_PRINT("setting global mfl dirty cnt threshold:%d", threshold);
    nuvo_map_mfl_dirty_cnt_threshold = threshold;
}

bool nuvo_map_mfl_need_pausing(struct nuvo_map_free_lun_request *mfl_req)
{
    if (mfl_req->dirty_cnt > nuvo_map_mfl_dirty_cnt_threshold)
    {
        NUVO_PRINT("pause mfl:%p work_state:%d lun(%d) vol:%p dirty_cnt:%d threshold:%d vol uuid:" NUVO_LOG_UUID_FMT,
                   mfl_req, mfl_req->work_state, mfl_req->lun->snap_id, mfl_req->lun->vol,
                   mfl_req->dirty_cnt, nuvo_map_mfl_dirty_cnt_threshold,
                   NUVO_LOG_UUID(mfl_req->lun->vol->vs_uuid));
        return (true);
    }
    // Test the pointers along the way because they are NULL in unit test :()
    if (mfl_req->lun && mfl_req->lun->vol && nuvo_mfst_slog_filling(mfl_req->lun->vol))
    {
        NUVO_PRINT("pause mfl:%p work_state:%d lun(%d) vol:%p slog full vol uuid:" NUVO_LOG_UUID_FMT,
                   mfl_req, mfl_req->work_state, mfl_req->lun->snap_id, mfl_req->lun->vol,
                   NUVO_LOG_UUID(mfl_req->lun->vol->vs_uuid));
        return (true);
    }
    return (false);
}

void nuvo_map_mfl_init(struct nuvo_map_free_lun_request *mfl_req)
{
    nuvo_mutex_init(&mfl_req->mutex);
    nuvo_cond_init(&mfl_req->cond);
    mfl_req->state = MFL_HALTED;
    mfl_req->work_state = MFL_WORK_NONE;
}

void nuvo_map_mfl_start(struct nuvo_map_free_lun_request *mfl_req)
{
    nuvo_mutex_lock(&mfl_req->mutex);
    mfl_req->state = MFL_NONE;
    nuvo_mutex_unlock(&mfl_req->mutex);
    struct nuvo_space_vol *space = nuvo_containing_object(mfl_req, struct nuvo_space_vol, mfl_req);

    nuvo_mutex_lock(&space->space_vol_mutex);
    nuvo_vol_new_needs_work_mfl(space);
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

void nuvo_map_mfl_stop(struct nuvo_map_free_lun_request *mfl_req)
{
    nuvo_mutex_lock(&mfl_req->mutex);
    while (mfl_req->state != MFL_HALTED)
    {
        //if paused, lets not bother
        if (nuvo_map_mfl_is_paused(mfl_req) || (mfl_req->state == MFL_NONE))
        {
            mfl_req->state = MFL_HALTED;
            break;
        }
        // if running, halt mfl
        nuvo_map_mfl_trigger_halting(mfl_req);
        nuvo_map_mfl_wait_for_halt(mfl_req);
    }
    nuvo_mutex_unlock(&mfl_req->mutex);
}

void nuvo_map_mfl_kick(struct nuvo_map_free_lun_request *mfl_req)
{
    bool kick = false;

    // Note : dont need the lock here.
    // If we read the state here as MFL_NONE, the mfl is not in progress/hasnt begun.
    // If another mfl begin raced with us, the only concern here is that we missed
    // seeing a PAUSED state(which is unlikely, given the time from NONE->PAUSED)
    // And in any case, if we miss seeing a PAUSED state, the task would get kicked again at the
    // end of next CP

    if (mfl_req->state == MFL_NONE)
    {
        return;
    }

    nuvo_mutex_lock(&mfl_req->mutex);
    mfl_req->dirty_cnt = 0;
    if (mfl_req->state == MFL_PAUSED)
    {
        // assert since you cant pause in free entries.
        NUVO_ASSERT(mfl_req->work_state == MFL_WORK_LOAD_MAPS);
        mfl_req->state = MFL_IN_PROGRESS;
        kick = true;
    }
    nuvo_mutex_unlock(&mfl_req->mutex);

    if (kick)
    {
        NUVO_PRINT("kick mfl:%p work_state:%d lun(%d) vol:%p vol uuid:" NUVO_LOG_UUID_FMT, mfl_req,
                   mfl_req->work_state, mfl_req->lun->snap_id, mfl_req->lun->vol,
                   NUVO_LOG_UUID(mfl_req->lun->vol->vs_uuid));
        nuvo_mutex_lock(&mfl_req->lun->vol->log_volume.space.space_vol_mutex);
        nuvo_vol_needs_work_mfl(&mfl_req->lun->vol->log_volume.space);
        nuvo_mutex_unlock(&mfl_req->lun->vol->log_volume.space.space_vol_mutex);
    }
}

void nuvo_map_mfl_inc_dirty_cnt(struct nuvo_map_free_lun_request *mfl_req)
{
    nuvo_mutex_lock(&mfl_req->mutex);
    mfl_req->dirty_cnt++;
    nuvo_mutex_unlock(&mfl_req->mutex);
}

void nuvo_map_mfl_req_reset(struct nuvo_map_free_lun_request *mfl_req)
{
    nuvo_mutex_lock(&mfl_req->mutex);
    NUVO_ASSERT(mfl_req->map_mfl_cnt == mfl_req->map_load_cnt);
    mfl_req->lun = NULL;
    mfl_req->offset = 0;
    mfl_req->free_offset = 0;
    mfl_req->map_mfl_cnt = 0;
    mfl_req->map_load_cnt = 0;

    // if we are halting, let's not change the state
    // the mfl engine will handle a pending halt after mfl done
    if (mfl_req->state == MFL_IN_PROGRESS)
    {
        mfl_req->state = MFL_NONE;
    }
    mfl_req->work_state = MFL_WORK_NONE;
    mfl_req->dirty_cnt = 0;
    nuvo_mutex_unlock(&mfl_req->mutex);
}

void nuvo_map_mfl_batch_done(struct nuvo_parallel_op *par_ops)
{
    NUVO_ASSERT(!par_ops->status); // TODO error handle->abort mfl?
    // TODO if in errror mark mfl_req in error
    // and let the next state handle it

    struct nuvo_map_free_lun_request *mfl_req = nuvo_containing_object(par_ops, struct nuvo_map_free_lun_request, par_ops);
    NUVO_LOG(map, 80, "mfl batch done lun:%d lun_state:%d offset:%lu free_offset:%lu",
             mfl_req->lun->snap_id, mfl_req->lun->lun_state,
             mfl_req->offset, mfl_req->free_offset);
    nuvo_parallel_op_destroy(par_ops);

    nuvo_mutex_lock(&mfl_req->lun->vol->log_volume.space.space_vol_mutex);
    mfl_req->work_state = MFL_WORK_FREE_ENTRIES;
    nuvo_vol_needs_work_mfl(&mfl_req->lun->vol->log_volume.space);
    nuvo_mutex_unlock(&mfl_req->lun->vol->log_volume.space.space_vol_mutex);
}

void nuvo_map_mfl_fault_in_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_map_free_lun_request *mfl = map_req->tag.ptr;

    NUVO_ASSERT(map_req->first_map->pinned > 0);
    struct nuvo_map_track *map = map_req->first_map;
    NUVO_LOG_COND(map, 80, (!map->base_offset), "FAULT-IN map map :%p state:%d shadow_link:%p mfl:%d media_addr:(%lu:%lu) offset:%lu level:%d map->is_dirty:%d",
                  map, map->state, map->shadow_link, map->mfl, map->map_entry.media_addr.parcel_index,
                  map->map_entry.media_addr.block_offset,
                  map->base_offset, map->level, map->is_dirty);
    nuvo_parallel_op_done(&mfl->par_ops, map_req->status);
}

bool nuvo_map_mfl_is_halting(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT_MUTEX_HELD(&mfl_req->mutex);
    return ((mfl_req->state == MFL_HALTING));
}

bool nuvo_map_mfl_is_halted(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT_MUTEX_HELD(&mfl_req->mutex);
    return ((mfl_req->state == MFL_HALTED));
}

bool nuvo_map_mfl_is_done(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT(mfl_req->offset == mfl_req->free_offset);
    return (mfl_req->offset >= (mfl_req->lun->size / NUVO_BLOCK_SIZE));
}

void nuvo_map_mfl_trigger_halting(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT_MUTEX_HELD(&mfl_req->mutex);
    NUVO_ASSERT(mfl_req->state == MFL_IN_PROGRESS);   // must be in progress
    mfl_req->state = MFL_HALTING;
}

void nuvo_map_mfl_wait_for_halt(struct nuvo_map_free_lun_request *mfl_req)
{
    nuvo_cond_wait(&mfl_req->cond, &mfl_req->mutex);
}

void nuvo_map_mfl_halt(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT_MUTEX_HELD(&mfl_req->mutex);

    struct nuvo_lun       *lun = mfl_req->lun;
    struct nuvo_space_vol *space_vol = nuvo_containing_object(mfl_req, struct nuvo_space_vol, mfl_req);

    if (lun)
    {
        nuvo_mutex_lock(&lun->mutex);
        nuvo_lun_unpin(lun);
        nuvo_mutex_unlock(&lun->mutex);
    }

    mfl_req->state = MFL_HALTED;
    mfl_req->work_state = MFL_WORK_NONE;

    NUVO_LOG(space, 25, "mfl halted, wake up the waiter vol uuid:"NUVO_LOG_UUID_FMT,
             NUVO_LOG_UUID(nuvo_containing_object(space_vol, struct nuvo_vol, log_volume.space)->vs_uuid));
    nuvo_cond_signal(&mfl_req->cond);
}

void nuvo_map_mfl_done(struct nuvo_map_free_lun_request *mfl_req)
{
    struct nuvo_lun *lun = mfl_req->lun;

    NUVO_LOG(map, 0, "mfl L0 done moving to lun to DELETING_DRAIN lun(%d) state:%d lun->mfl_state:%d offset:%lu",
             lun->snap_id, lun->lun_state, lun->mfl_state, mfl_req->offset);

    NUVO_ASSERT(mfl_req->work_state == MFL_WORK_LOAD_MAPS);

    nuvo_map_mfl_req_reset(mfl_req);

    nuvo_mutex_lock(&lun->mutex);
    lun->mfl_state = NUVO_LUN_MFL_CP_PENDING;
    nuvo_lun_unpin(lun);

    // done with L0 punching, roll up pending.

    // Glossary MFL means  "map free lun" aka hole punching work.
    //
    // Right now, we are done with L0 maps. And now we go from DELETING-> DELETING_DRAIN.
    // We are yet to free L>0 map blocks.
    // "Deleting Drain" ensures that no more new GCs would come in.
    // Ongoing gcs can handle MFLed or to be MFLed blocks.
    // MFLed blocks are returned success to GC.
    // Future MFL blocks are just dirted by GC
    // But since MFL has already dirtied all the L0 maps
    // L>0 maps must necessarily (including the maps that are marked for rewrite
    // by GC) should get MFL-ed in the next CP.

    // CP would roll up the deleting on the map tree.
    // Deleting drain ->deleted happens when roll up is done.
    // Setting the state to DELETING drain right after L0 maps are punched, helps space thread
    // to decide not to pick up the lun again
    // The downside is that GC will not do any new work on the intemediate maps
    // But gc would expect the maps to be free/written out by the next cp.
    // Since we trigger cp after the deleting drain, and since gc would wait
    // for the next cp to finish, the expectation that maps would be deleted by the next cp
    // is valid.


    nuvo_return_t rc = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_DELETING_DRAIN, NUVO_LUN_EXPORT_UNEXPORTED);
    NUVO_ASSERT(rc == 0);

    nuvo_mutex_unlock(&lun->mutex);



    //trigger a CP , cp would roll up the upper level maps.
    struct nuvo_space_vol *space_vol = &lun->vol->log_volume.space;
    nuvo_space_trigger_cp(space_vol);

    // We are done with this lun.
    // We need to check whether we need to do more luns
    // So, requeue work to the space thread, who would check for
    // mfl work for more luns

    nuvo_mutex_lock(&space_vol->space_vol_mutex);
    nuvo_vol_new_needs_work_mfl(space_vol);
    nuvo_mutex_unlock(&space_vol->space_vol_mutex);
}

void nuvo_map_mfl_work(struct nuvo_map_free_lun_request *req)
{
    //do the hole punching for the maps we loaded
    if (req->work_state == MFL_WORK_FREE_ENTRIES)
    {
        nuvo_map_mfl_free_entries(req);
        req->work_state = MFL_WORK_LOAD_MAPS;
    }
    // we can only halt, pause after calling the "free_entries" above
    // so that we dont halt/pause holding map pins
    NUVO_ASSERT(req->work_state == MFL_WORK_LOAD_MAPS);

    // if we are done , mfl state changes from PROGRESS -> NONE
    //  If a PROGRESS -> HALTING happens in the middle, mfl_done
    //  doesnt touch the state
    //  and HALTING is handled subsequently
    if (nuvo_map_mfl_is_done(req))
    {
        nuvo_map_mfl_done(req);
    }
    // if we are are told to halt, halt
    nuvo_mutex_lock(&req->mutex);
    if (nuvo_map_mfl_is_halting(req))
    {
        nuvo_map_mfl_halt(req);
    }


    if (nuvo_map_mfl_is_halted(req))
    {
        goto _out;
    }

    if (nuvo_map_mfl_need_pausing(req))
    {
        // pause can be only done before loading maps
        nuvo_map_mfl_pause(req);
        goto _out;
    }

    if (!nuvo_map_mfl_is_paused(req) && (req->work_state == MFL_WORK_LOAD_MAPS))
    {
        //now go and load the next set of maps
        nuvo_mutex_unlock(&req->mutex);
        nuvo_map_mfl_load_maps(req);
        return;
    }

_out:
    nuvo_mutex_unlock(&req->mutex);
    return;
}

void nuvo_map_mfl_load_maps(struct nuvo_map_free_lun_request *mfl_req)
{
    //assert that the map is in i/o done
    //assert that the offset is a multiple of radix etc
    nuvo_mutex_lock(&mfl_req->mutex);
    struct nuvo_parallel_op *par_ops = &mfl_req->par_ops;
    nuvo_return_t            rc = nuvo_parallel_op_init(par_ops);
    NUVO_ASSERT(!rc);
    par_ops->callback = nuvo_map_mfl_batch_done;
    uint64_t lun_offset_max = mfl_req->lun->size / NUVO_BLOCK_SIZE;

    // load the maps.
    // the parallel op cb gets called when we are done loading
    // which would switch us to the "free entries" phase where
    // we do the free work.

    // Note: if we are halting, we stop loading maps.
    // the state machine in mfl_work would handle halting eventually

    for (unsigned i = 0;
         (i < NUVO_MFL_BATCH_SIZE && mfl_req->offset < lun_offset_max && !nuvo_map_mfl_is_halting(mfl_req));
         i++, mfl_req->offset += NUVO_MAP_RADIX)
    {
        struct nuvo_map_request *map_req = &mfl_req->map_reqs[i];
        nuvo_map_request_init(map_req, mfl_req->lun, mfl_req->offset, 1);

        nuvo_map_reserve_sync(map_req);
        NUVO_ASSERT(!map_req->status);

        map_req->tag.ptr = mfl_req;
        map_req->callback = nuvo_map_mfl_fault_in_cb;
        mfl_req->map_load_cnt++;

        nuvo_parallel_op_submitting(par_ops);
        nuvo_mutex_unlock(&mfl_req->mutex);
        nuvo_map_fault_in(map_req);
        NUVO_ASSERT(!map_req->status);
        nuvo_mutex_lock(&mfl_req->mutex);
    }

    nuvo_mutex_unlock(&mfl_req->mutex);

    nuvo_parallel_op_finalize(par_ops);
}

void nuvo_map_mfl_free_entries(struct nuvo_map_free_lun_request *mfl_req)
{
    NUVO_ASSERT(mfl_req->offset); //if we have something to work, mfl must have loaded some maps

    NUVO_ASSERT(mfl_req->free_offset <= mfl_req->offset);

    for (unsigned int i = 0; (i < NUVO_MFL_BATCH_SIZE && mfl_req->free_offset < mfl_req->offset);
         i++, mfl_req->free_offset += NUVO_MAP_RADIX)
    {
        struct nuvo_map_request *map_req = &mfl_req->map_reqs[i];
        // hold the vol lock across map lock so that volume cp_gen doesnt change
        // during map_commit_lock
        struct nuvo_vol *vol = map_req->lun->vol;
        nuvo_mutex_lock(&vol->mutex);
        map_req->cp_commit_gen = vol->log_volume.map_state.checkpoint_gen;
        nuvo_map_commit_lock(map_req);
        nuvo_mutex_unlock(&vol->mutex);

        NUVO_ASSERT(map_req->first_map == map_req->last_map);
        NUVO_ASSERT(map_req->first_map->level == 0);
        // assert that the map we are working on is the map we intend to work on
        NUVO_ASSERT(map_req->first_map->base_offset == mfl_req->free_offset);

        bool is_dirty = map_mfl_free_entries(map_req->first_map);

        if (is_dirty)
        {
            nuvo_map_mfl_inc_dirty_cnt(mfl_req);
        }

        mfl_req->map_mfl_cnt++;
        nuvo_map_commit_unlock(map_req);
    }

    NUVO_ASSERT(mfl_req->offset == mfl_req->free_offset);
}
