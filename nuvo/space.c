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
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "gc.h"
#include "logger.h"
#include "map.h"
#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "nuvo_pr_sync.h"
#include "nuvo_vol_series.h"
#include "parallel.h"
#include "replay.h"
#include "segment.h"
#include "space.h"

/**
 * @file space.c
 * @brief The space management code.
 *
 * This service manages space in volumes.  It manages allocation
 * and freeing of parcels,  drives cleaning of segments and
 * supplies clean segments to the logger.
 */
struct {
    nuvo_mutex_t         space_mutex;                                /** Have this lock while stopping or changing the needs_work lists. */
    nuvo_cond_t          space_cond;                                 /** Waiting for something to do.                               */
    struct nuvo_dlist    vol_needs_work_cp;                          /** Set of volumes that have asked for cp work.     */
    struct nuvo_dlist    vol_needs_work_parcel;                      /** Set of volumes that have asked for parcel work. */
    struct nuvo_dlist    vol_needs_work_gc;                          /** Set of volumes that have asked for gc.          */
    struct nuvo_dlist    vol_needs_gc_struct;                        /** Set of volumes that have asked for gc, but found no struct */
    struct nuvo_dlist    vol_needs_work_mfl;                         /** Set of volumes that need map free lun work */

    bool                 halting;                                    /** Halting all work.          */
    pthread_t            thread_id;                                  /** Thread for managing space. */

    nuvo_mutex_t         gc_mutex;                                   /** Mutex protecting the gc lists. */
    struct nuvo_gc       gc[NUVO_SPACE_GC_NUM];                      /** The gc structures */
    struct nuvo_dlist    gc_free_list;                               /** List of free gc's */
    struct nuvo_dlist    gc_needs_work;                              /** A gc needs to be moved along. */
    struct nuvo_dlist    gc_needs_gc_batch;                          /** A gc needs a log map struct to move along. */
    unsigned             gc_total;                                   /** How many gc's are there. */
    bool                 gc_processing_enabled;                      /** Disable For testing. */

    nuvo_mutex_t         gc_free_batch_mutex;                        /** Mutex to protect list of nuvo_gc_batch */
    struct nuvo_dlist    gc_free_batches;                            /** The list of free nuvo_gc_batch */
    struct nuvo_gc_batch gc_batches[NUVO_SPACE_GC_BATCHES];          /** The table of nuvo_gc_batch */
} nuvo_space_ctl;

void nuvo_space_vol_segments_release(struct nuvo_space_vol *space);

// Documented in header.
nuvo_return_t nuvo_space_vol_init(struct nuvo_space_vol *space)
{
    nuvo_return_t rc;

    rc = nuvo_mutex_init(&space->space_vol_mutex);
    if (rc < 0)
    {
        return (-NUVO_ENOMEM);
    }
    rc = nuvo_cond_init(&space->space_vol_cond);
    if (rc < 0)
    {
        rc = -NUVO_ENOMEM;
        goto destroy_mutex;
    }
    rc = nuvo_cond_init(&space->space_write_permission);
    if (rc < 0)
    {
        goto destroy_cond;
    }
    space->space_writes_ok = true;
    space->space_snap_frozen = false;
    rc = nuvo_mutex_init(&space->cp_sync_signal);
    if (rc < 0)
    {
        goto destroy_write_cond;
    }
    rc = nuvo_pr_parallel_init(&space->cp_par_io);
    if (rc < 0)
    {
        goto destroy_sync_signal;
    }

    nuvo_dlnode_init(&space->cp_node);
    nuvo_dlnode_init(&space->parcel_node);
    nuvo_dlnode_init(&space->gc_node);
    nuvo_dlnode_init(&space->mfl_node);

    nuvo_dlist_init(&space->completed_io_reqs);

    space->cp_state = NUVO_VOL_SPACE_CPS_HALTED;
    space->cp_requested = false;
    space->cp_halting = false;

    nuvo_map_mfl_init(&space->mfl_req);

    space->parcel_state = NUVO_VOL_SPACE_PARCELS_HALTED;
    for (uint_fast16_t c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
    {
        space->parcel_class[c].check_for_parcels = false;
    }
    space->parcel_add_in_progress = 0;

    space->gc_state = NUVO_VOL_SPACE_GC_HALTED;
    for (unsigned dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        space->gc_data_class[dc].gc_needed = false;
        space->gc_data_class[dc].gc_in_progress = 0;
    }
    NUVO_LOG(space, 10, "Initialized space for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    return (0);

destroy_sync_signal:
    nuvo_mutex_destroy(&space->cp_sync_signal);
destroy_write_cond:
    nuvo_cond_destroy(&space->space_write_permission);
destroy_cond:
    nuvo_cond_destroy(&space->space_vol_cond);
destroy_mutex:
    nuvo_mutex_destroy(&space->space_vol_mutex);
    return (rc);
}

// Documented in header
void nuvo_space_vol_stop_management(struct nuvo_space_vol *space)
{
    NUVO_LOG(space, 10, "Stopping space management for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    nuvo_space_vol_manage_mfl_stop(space);
    nuvo_space_vol_manage_gc_stop(space);
    nuvo_space_vol_manage_parcels_stop(space);
    nuvo_space_vol_manage_cps_stop(space);
}

// Documented in header
void nuvo_space_vol_destroy(struct nuvo_space_vol *space)
{
    NUVO_LOG(space, 10, "Destroying space for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));

    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_ASSERT(space->gc_state == NUVO_VOL_SPACE_GC_HALTED);
    NUVO_ASSERT(space->parcel_state == NUVO_VOL_SPACE_PARCELS_HALTED);
    NUVO_ASSERT(space->parcel_add_in_progress == 0);
    NUVO_ASSERT(space->cp_state == NUVO_VOL_SPACE_CPS_HALTED);
    nuvo_mutex_unlock(&space->space_vol_mutex);

    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    NUVO_ASSERT(!nuvo_dlnode_on_list(&space->cp_node));
    NUVO_ASSERT(!nuvo_dlnode_on_list(&space->parcel_node));
    NUVO_ASSERT(!nuvo_dlnode_on_list(&space->gc_node));
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);

    nuvo_cond_destroy(&space->space_vol_cond);
    nuvo_cond_destroy(&space->space_write_permission);
    nuvo_mutex_destroy(&space->space_vol_mutex);
    nuvo_pr_parallel_destroy(&space->cp_par_io);
    nuvo_mutex_destroy(&space->cp_sync_signal);;
    NUVO_LOG(space, 10, "Destroyed space for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
}

/**
 * \brief internal routine to place volume on the needs-work list.
 */
static void vol_needs_cp_work(struct nuvo_space_vol *space)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    if (!nuvo_dlnode_on_list(&space->cp_node) && space->cp_state != NUVO_VOL_SPACE_CPS_HALTED)
    {
        NUVO_LOG(space, 40, "Volume " NUVO_LOG_UUID_FMT " needs cp work.", NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_work_cp, &space->cp_node);
    }
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

/**
 * \brief internal routine to place volume on the needs-work list.
 */
static void vol_needs_parcel_work(struct nuvo_space_vol *space, bool halting_ok)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    if ((space->parcel_state == NUVO_VOL_SPACE_PARCELS_RUNNING || halting_ok) && !nuvo_dlnode_on_list(&space->parcel_node))
    {
        NUVO_LOG(space, 40, "Volume " NUVO_LOG_UUID_FMT " needs parcel work.", NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_work_parcel, &space->parcel_node);
    }
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

/**
 * \brief internal routine to place volume on the needs-work list.
 */
static void vol_needs_gc_work(struct nuvo_space_vol *space)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    if (space->gc_state != NUVO_VOL_SPACE_GC_HALTED && !nuvo_dlnode_on_list(&space->gc_node))
    {
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_work_gc, &space->gc_node);
    }
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

/**
 * \brief Push MFL work item for a new lun which got deleted
 *  If work is in progress for another lun, this lun would be picked
 *  up for after the current lun is complete
 * \param space space_vol struct for the vol
 */

void nuvo_vol_new_needs_work_mfl(struct nuvo_space_vol *space)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    bool mfl_none;

    struct nuvo_map_free_lun_request *mfl_req = &space->mfl_req;

    // Queue work only if the volume is not doing any mfl work
    // NONE is the only state when new lun work can come in
    // If PROGRESS -> HALTING occurs, no work will be submitted.

    nuvo_mutex_lock(&mfl_req->mutex);
    mfl_none = (mfl_req->state == MFL_NONE);
    if (mfl_none)
    {
        NUVO_ASSERT(mfl_req->work_state == MFL_WORK_NONE);
    }
    nuvo_mutex_unlock(&mfl_req->mutex);

    if (mfl_none)
    {
        nuvo_vol_needs_work_mfl(space);
    }
}

/**
 * \brief Push the space vol for MFL work to the space thread
 * To be used by a LUN whose MFL work is known to be already in progress.
 * New luns use the api above (nuvo_vol_new_needs_work_mfl)
 * \param space space_vol struct for the vol
 */
void nuvo_vol_needs_work_mfl(struct nuvo_space_vol *space)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    // if an existing delete is in progress for this volume, return
    // the map free lun done will walk the lun list and trigger the next map free lun
    if (!nuvo_dlnode_on_list(&space->mfl_node))
    {
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_work_mfl, &space->mfl_node);
        NUVO_LOG(space, 40, "Volume " NUVO_LOG_UUID_FMT " needs mfl work",
                 NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
        nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    }
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

/**
 * \brief internal routine to place volume on the needs-gc-struct list.
 *
 * \param space The nuvo_space_vol that needs a struct.
 */
static void vol_needs_gc_struct(struct nuvo_space_vol *space)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    if (space->gc_state == NUVO_VOL_SPACE_GC_RUNNING && !nuvo_dlnode_on_list(&space->gc_node))
    {
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_gc_struct, &space->gc_node);
    }
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

static bool should_freeze_ios(struct nuvo_space_vol *space_vol, struct nuvo_mfst_space_info *space_info);

/**
 * \brief Callback for when the manifest writing is done for a cp.
 *
 * This is done and then it mucks with the volumes space
 * structures to mark it as done a CP.
 * Wakes up anyone waiting on the volume space_vol_cond.
 * Pokes the thread via vol_needs_cp_work.
 *
 * \param par_io The parallel io that finished.
 */
void nuvo_space_vol_cp_cb(struct nuvo_parallel_io *par_io)
{
    NUVO_ASSERT(par_io->status == 0);
    struct nuvo_space_vol      *space = (struct nuvo_space_vol *)par_io->tag.ptr;
    struct nuvo_vol            *vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);
    struct nuvo_mfst_space_info space_info;

    nuvo_lun_move_pending_free_to_free(vol);
    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_ASSERT(space->cp_state == NUVO_VOL_SPACE_CPS_WRITING_MFST);
    nuvo_mfst_writing_thaw(&vol->log_volume.mfst);
    NUVO_LOG(space, 20, "CP done");
    space->cp_state = NUVO_VOL_SPACE_CPS_NOT_IN_CP;

    if (nuvo_mfst_cp_done_for_gc(&vol->log_volume.mfst) >= 3)
    {
        space->cp_requested = true;
    }

    nuvo_mfst_segments_avail(&vol->log_volume.mfst, NUVO_DATA_CLASS_A, &space_info);    // TODO - when we have multiple classes, change this.
    if (!should_freeze_ios(space, &space_info))
    {
        nuvo_space_write_permit(space, true);
    }

    vol_needs_gc_work(space);            // TODO: Really only need if segments_free_current_cp_num was non-zero coming in.
    vol_needs_cp_work(space);            // TODO - Do this only if we need to.
    vol_needs_parcel_work(space, false); // TODO - Do this only if we need to.

    // TODO  - I'm uncomfortable with this needing to be here, and precisely here.
    nuvo_cond_broadcast(&space->space_vol_cond);

    nuvo_mutex_unlock(&space->space_vol_mutex);

    // A bit of overkill kicking at the end of each CP, but this relieves temporary out of segment problems.
    nuvo_process_segment_io_queue(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.logger);
}

static void nuvo_space_vol_start_cp_io(struct nuvo_space_vol *space, uint64_t freeze_seq_no)
{
    space->cp_par_io.ios_outstanding = 1;
    space->cp_par_io.status = 0;
    space->cp_par_io.callback = nuvo_space_vol_cp_cb;
    space->cp_par_io.tag.ptr = space;

    nuvo_mfst_write_start(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst,
                          &nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.sb,
                          &space->cp_par_io, &space->cp_sync_signal, freeze_seq_no);

    // TODO - Broke this into two pieces so we could start writing tables first and then
    // write the maps at the same time and only do the committing write when both are done.
    // leaving this broken apart so when we come up with a better segment count solution we
    // can use it.

    nuvo_mfst_write_final_writes(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst,
                                 &nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.sb,
                                 &space->cp_par_io, &space->cp_sync_signal);

    nuvo_pr_parallel_finalize(&space->cp_par_io);
}

static void nuvo_space_map_checkpoint_cb(struct nuvo_map_checkpoint_req *req)
{
    struct nuvo_space_vol *space = (struct nuvo_space_vol *)req->tag.ptr;

    NUVO_ASSERT(req->status >= 0);  // TODO handle failure.

    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_ASSERT(space->cp_state == NUVO_VOL_SPACE_CPS_WAITING_MAP);
    NUVO_LOG(space, 20, "CP map writes done");
    space->cp_state = NUVO_VOL_SPACE_CPS_MAP_DONE;
    vol_needs_cp_work(space);
    nuvo_mutex_unlock(&space->space_vol_mutex);
    // Don't do anything with req since it is embedded in the space struct and lun info.
}

static void nuvo_space_map_checkpoint_done(struct nuvo_space_vol *space)
{
    struct nuvo_vol *vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);
    // + 1 to include active lun as well
    struct nuvo_mfst_lun_entry  lun_entry_list[NUVO_MFST_MAX_LUNS];
    struct nuvo_mfst_lun_entry *lun_entry = lun_entry_list;

    NUVO_ASSERT(space->cp_map_checkpoint_req.lun_cnt <= NUVO_MFST_MAX_LUNS);

    for (uint32_t i = 0; i < space->cp_map_checkpoint_req.lun_cnt; i++)
    {
        struct nuvo_lun *lun;
        uint64_t         snap_id;

        snap_id = space->cp_map_checkpoint_req.lun_cp_map_entry[i].snap_id;
        NUVO_ASSERT(snap_id);

        if (i == 0)
        {
            NUVO_ASSERT(snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID);
            lun = &vol->log_volume.lun;
        }
        else
        {
            // get the lun, we need the UUID
            lun = nuvo_get_lun_by_snapid(vol, snap_id, false);
            NUVO_ASSERT(lun->snap_id == snap_id);
        }
        NUVO_ASSERT(lun);
        nuvo_mutex_lock(&lun->mutex);

        enum nuvo_lun_state_e lun_state = lun->lun_state;

        switch (lun_state)
        {
        case NUVO_LUN_STATE_VALID:
        case NUVO_LUN_STATE_DELETING:
            break;

        case NUVO_LUN_STATE_DELETING_DRAIN:
            // gc is still running, which means we could be getting log updates
            // which will be ignored by map on reboot, but this allows us to ignore in
            // "normal" way.
            lun_state = NUVO_LUN_STATE_DELETING;
            break;

        case NUVO_LUN_STATE_DELETED:
        case NUVO_LUN_STATE_FREE_PENDING:
        case NUVO_LUN_STATE_FREE:
            // These states are not included in writing out luns.
            NUVO_PANIC("Attempting to write out invalid lun state");
            break;
        }

        NUVO_ASSERT(lun_state == NUVO_LUN_STATE_VALID || lun_state == NUVO_LUN_STATE_DELETING);

        memset(lun_entry, 0, sizeof(*lun_entry));
        lun_entry->lun_state = lun_state;
        lun_entry->root_map_entry = space->cp_map_checkpoint_req.lun_cp_map_entry[i].root_map_entry;
        lun_entry->map_height = vol->log_volume.lun.map_height;
        lun_entry->size = vol->log_volume.lun.size;
        lun_entry->snap_id = snap_id;

        uuid_copy(lun_entry->lun_uuid, lun->lun_uuid);
        lun_entry++;

        nuvo_mutex_unlock(&lun->mutex);
    }

    nuvo_mfst_set_luns(&vol->log_volume.mfst, lun_entry - lun_entry_list, lun_entry_list);

    // Now get a sequence number and freeze the segment table for writes.
    uint64_t freeze_seq_no;
    freeze_seq_no = nuvo_log_freeze_map_updates(vol);
    NUVO_LOG(space, 20, "Starting CP writes and freezing segment counts at seq no %d", freeze_seq_no);
    nuvo_space_vol_start_cp_io(space, freeze_seq_no);   // Starts the ios, they will call nuvo_space_vol_cp_cb.
    nuvo_log_unfreeze_map_updates(vol);

    //kick any mfl work that may be paused.
    nuvo_map_mfl_kick(&space->mfl_req);
}

/**
 * \brief Start a cp on the volume.
 *
 * Internal function called by the space management thread
 * to initiate a cp on a volume.
 *
 * \param space The volume to start a cp on.
 */
static void nuvo_space_vol_start_cp(struct nuvo_space_vol *space)
{
    struct nuvo_vol *vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);

    nuvo_mutex_lock(&vol->mutex);
    // Moving these in this order causes each snapshot to spend one CP in each state.
    nuvo_lun_move_to_mfl_cp_in_progress(vol);
    nuvo_lun_move_to_free_pending(vol);
    nuvo_lun_move_to_deleted(vol);
    nuvo_mutex_unlock(&vol->mutex);

    uint64_t cp_seq_no = nuvo_log_freeze_map_updates(vol);

    struct nuvo_segment segments[NUVO_MFST_NUM_LOG_STARTS];
    uint32_t            segment_count;

    nuvo_log_get_open_segments(vol, cp_seq_no, segments, &segment_count);
    nuvo_mfst_log_starts_set(&vol->log_volume.mfst, cp_seq_no, segments, segment_count);
    NUVO_LOG(space, 20, "Starting CP at seq_no %d with %d segments", cp_seq_no, segment_count);
    nuvo_mfst_gc_starting_cp(&vol->log_volume.mfst);

    // Tell the map to start writing out
    struct nuvo_map_checkpoint_req *req = &space->cp_map_checkpoint_req;
    req->vol = vol;
    req->tag.ptr = space;
    req->callback = nuvo_space_map_checkpoint_cb;
    nuvo_map_checkpoint(req);

    nuvo_log_unfreeze_map_updates(vol);
}

/**
 * \brief Trigger a cp on the volume.
 *
 * Triggers a CP on the volume, poking the space thread
 * to get it done.  Probably need a version that waits
 * for the CP to complete, but refusing to write it until
 * needed.
 *
 * \param space The volume to start a cp on.
 */
void nuvo_space_trigger_cp(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    space->cp_requested = true;
    vol_needs_cp_work(space);
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

/**
 * \brief Start managing CPs on a volume
 *
 * This turns on CPs on the associated volume.
 * \param space The volume to do CPs on.
 */
void nuvo_space_vol_manage_cps_start(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_LOG(space, 10, "Starting managing cps for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    NUVO_ASSERT(space->cp_state == NUVO_VOL_SPACE_CPS_HALTED);
    space->cp_state = NUVO_VOL_SPACE_CPS_NOT_IN_CP;
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

/**
 * \brief Stop managing CPs on a volume
 *
 * This turns off CPs on the associated volume.
 * Sets the state to HALTING and then waits for it to
 * be halted.
 *
 * \param space The volume to do CPs on.
 */
void nuvo_space_vol_manage_cps_stop(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_LOG(space, 10, "Stopping managing cps for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    if (space->cp_state != NUVO_VOL_SPACE_CPS_HALTED)
    {
        space->cp_halting = true;
        while (space->cp_state != NUVO_VOL_SPACE_CPS_HALTED)
        {
            vol_needs_cp_work(space);
            nuvo_cond_wait(&space->space_vol_cond, &space->space_vol_mutex);
        }
    }
    NUVO_ASSERT(space->cp_state == NUVO_VOL_SPACE_CPS_HALTED);
    NUVO_LOG(space, 10, "Stopped managing cps for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

/**
 * \brief Finish up the allocation of a parcel.
 *
 * This gets called twice per added parcel.  Once when the ALLOC returns and once when the
 * OPEN returns.  When the alloc returns, we turn around and open it (yes it might be nice if
 * one call did both, but that would be an intrusive change).  When the Open comes back
 * we add the parcel and pd to the manifest.
 *
 * \param space The volume's space structure.
 * \param req The io request.
 */
static void nuvo_space_vol_handle_parcel_req(struct nuvo_space_vol *space, struct nuvo_io_request *req)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_return_t rc = req->status;
    if (rc != 0)
    {
        space->parcel_add_in_progress--;
        NUVO_ERROR_PRINT("Failed to alloc/open parcel");
        nuvo_pr_client_req_free(req);
        return;
    }

    uuid_t   parcel_uuid;
    uuid_t   device_uuid;
    uuid_t   vs_uuid;
    uint16_t num_segments;
    uint8_t  data_class;

    switch (req->operation)
    {
    case NUVO_OP_ALLOC:
        uuid_copy(parcel_uuid, req->alloc.parcel_uuid);
        uuid_copy(device_uuid, req->alloc.device_uuid);
        uuid_copy(vs_uuid, req->alloc.volume_uuid);
        req->operation = NUVO_OP_OPEN;
        uuid_copy(req->open.parcel_uuid, parcel_uuid);
        uuid_copy(req->open.device_uuid, device_uuid);
        uuid_copy(req->open.volume_uuid, vs_uuid);
        req->open.reopen_flag = 0;
        req->status = 0;
        // Have to drop lock incase pr immediately calls back.
        nuvo_mutex_unlock(&space->space_vol_mutex);
        nuvo_pr_submit_req(req);
        nuvo_mutex_lock(&space->space_vol_mutex);
        return;

    case NUVO_OP_OPEN:
        space->parcel_add_in_progress--;
        num_segments = 0;
        rc = nuvo_mfst_insert_parcel(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst,
                                     req->open.device_uuid,
                                     req->open.parcel_uuid,
                                     NUVO_SEGMENT_MIN_SIZE_BYTES,
                                     &num_segments,
                                     &data_class,
                                     req->open.parcel_desc);
        if (rc >= 0)
        {
            NUVO_LOG(space, 20, "Volume " NUVO_LOG_UUID_FMT " added parcel " NUVO_LOG_UUID_FMT " on device " NUVO_LOG_UUID_FMT,
                     NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid),
                     NUVO_LOG_UUID(req->open.parcel_uuid),
                     NUVO_LOG_UUID(req->open.device_uuid));
            // Get more parcels in this class.
            space->parcel_class[data_class].check_for_parcels = true;
            vol_needs_parcel_work(space, false);
            space->cp_requested = true;
        }
        else
        {
            NUVO_ERROR_PRINT("Volume " NUVO_LOG_UUID_FMT " failed to add parcel " NUVO_LOG_UUID_FMT " on device " NUVO_LOG_UUID_FMT " - leaking space.",
                             NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid),
                             NUVO_LOG_UUID(req->open.parcel_uuid),
                             NUVO_LOG_UUID(req->open.device_uuid));
        }
        vol_needs_cp_work(space);
        nuvo_pr_client_req_free(req);
        return;

    default:
        NUVO_PANIC("Incorrect OP return from parcel router.");
    }
}

/**
 * \brief Callback for parcel alloc request.
 *
 * This is the callback for a parcel alloc.  It puts the
 * nuvo_io_request on the volumes space management for processing
 * by the space thread.
 *
 * \param req The request.
 */
static void nuvo_space_vol_parcel_alloc_cb(struct nuvo_io_request *req)
{
    struct nuvo_space_vol *space = (struct nuvo_space_vol *)req->tag.ptr;

    nuvo_mutex_lock(&space->space_vol_mutex);
    nuvo_dlist_insert_tail(&space->completed_io_reqs, &req->list_node);
    vol_needs_parcel_work(space, true);
    nuvo_mutex_unlock(&space->space_vol_mutex);
    NUVO_LOG(space, 20, "Allocating parcel: callback for volume " NUVO_LOG_UUID_FMT,
             NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));

    // TODO - need this?
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

/*
 * Routines managing the creation of free segments.
 */

/**
 * - CUM-1199 - make these up a bit more rationally.   Keep them in order though.
 */

/**
 * The numbers below are for how many segments to have before we take action.
 * So at some point we start trying to clean segments and if we get lower we
 * try to get more parcels and then if we get even lower we pause incoming IOs.
 * The non-"FRAC"s are number of segments.
 * The "FRAC"s are fractions of total segments. So we start cleaning segments
 * if we get to 20 free or we get to 1/50th of total free.
 */
#define NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FROZEN         6
#define NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC_FROZEN    300
#define NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO                14
#define NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC           200
#define NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS             15
#define NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS_FRAC        100
#define NUVO_SPACE_SEGMENTS_LOW_GET_SEGMENTS            20
#define NUVO_SPACE_SEGMENTS_LOW_GET_SEGMENTS_FRAC       50
static_assert(NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FROZEN < NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO,
              "Frozen pause IO should be less than pause IO");
static_assert(NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC_FROZEN > NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC,
              "Frozen pause IO should be less than pause IO");
static_assert(NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO < NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS,
              "Should get parcels before pausing IOs");
static_assert(NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC > NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS_FRAC,
              "Should get parcels before pausing IOs");
static_assert(NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS < NUVO_SPACE_SEGMENTS_LOW_GET_SEGMENTS,
              "Should be low on segments before getting parcels.");
static_assert(NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS_FRAC > NUVO_SPACE_SEGMENTS_LOW_GET_SEGMENTS_FRAC,
              "Should be low on segments before getting parcels.");


/**
 * \brief Return whether we should pause IOs
 * Makes the decision based on whether the absolute number of free
 * segments or the fraction of the total is too low.
 */
static inline bool should_freeze_ios(struct nuvo_space_vol *space_vol, struct nuvo_mfst_space_info *space_info)
{
    NUVO_ASSERT_MUTEX_HELD(&space_vol->space_vol_mutex);
    // If the volume is desperate, allow deeper eating into the reserve.
    uint_fast32_t free_segment_limit;
    if (space_vol->space_snap_frozen)
    {
        free_segment_limit = NUVO_MAX((uint32_t)NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FROZEN, space_info->class_total_segments / NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC_FROZEN);
    }
    else
    {
        free_segment_limit = NUVO_MAX((uint32_t)NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO, space_info->class_total_segments / NUVO_SPACE_SEGMENTS_LOW_PAUSE_IO_FRAC);
    }

    bool result = space_info->class_free_segments < free_segment_limit;
    return (result);
}

nuvo_return_t nuvo_space_snap_frozen_set(struct nuvo_space_vol *space_vol, bool frozen)
{
    NUVO_ERROR_PRINT("Setting frozen to %d", (unsigned)frozen);
    nuvo_mutex_lock(&space_vol->space_vol_mutex);
    space_vol->space_snap_frozen = frozen;
    nuvo_mutex_unlock(&space_vol->space_vol_mutex);
    return (0);
}

bool nuvo_space_snap_frozen_get(struct nuvo_space_vol *space_vol)
{
    nuvo_mutex_lock(&space_vol->space_vol_mutex);
    bool res = space_vol->space_snap_frozen;
    nuvo_mutex_unlock(&space_vol->space_vol_mutex);
    return (res);
}

/**
 * \brief Return whether we should get more parcels.
 * Now says get parcels if you can.
 *
 * Used to ,akes the decision based on whether the absolute number of free
 * segments or the fraction of the total is too low:
 *
 *   uint_fast32_t free_segments = space_info->class_free_segments +
 *                                 space_info->class_free_this_cp +
 *                                 space_info->class_free_next_cp;
 *   return (free_segments < NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS ||
 *           NUVO_SPACE_SEGMENTS_LOW_GET_PARCELS_FRAC * free_segments < space_info->class_total_segments);
 */
static inline bool should_get_parcels(struct nuvo_mfst_space_info *space_info)
{
    return (space_info->available_parcels > 0);
}

/**
 * \brief Return whether we should clean segments.
 * Makes the decision based on whether the absolute number of free
 * segments or the fraction of the total is too low.
 */
static inline bool should_get_segments(struct nuvo_mfst_space_info *space_info)
{
    uint_fast32_t free_segments = space_info->class_free_segments +
                                  space_info->class_free_this_cp +
                                  space_info->class_free_next_cp;

    return (free_segments < NUVO_SPACE_SEGMENTS_LOW_GET_SEGMENTS ||
            NUVO_SPACE_SEGMENTS_LOW_GET_SEGMENTS_FRAC * free_segments < space_info->class_total_segments);
}

/**
 * \brief Try to allocate a parcel on a volume.
 *
 * Tries to allocate a parcel for a volume.
 * Ask the manifest for a suggestion on a device to allocate
 * a parcel on.  The manifest gives its best guess.  This routine
 * decides whether to actually allocate a parcel.  Tries to
 * get a parcel request.  Might fail.
 *
 * \param space The volume's space structure.
 * \param data_class The data class we'd like a new parcel for.
 * \returns 0 if request submitted, negative if not.
 */
static nuvo_return_t nuvo_space_vol_parcel_alloc(struct nuvo_space_vol *space, uint8_t data_class)
{
    // Pick device to alloc a parcel on.
    uuid_t       device_uuid;
    int_fast32_t free_segments = 0;

    nuvo_mfst_choose_device_for_new_parcel(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst,
                                           data_class,
                                           device_uuid,
                                           &free_segments);

    if (uuid_is_null(device_uuid))
    {
        return (-1);                                                                      // TODO Better status.
    }

    NUVO_LOG(space, 50, "Allocating parcel on device: " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(device_uuid));

    struct nuvo_io_request *req = nuvo_pr_client_req_alloc();
    if (req == NULL)
    {
        return (-1);  // TODO Better status.
    }

    nuvo_mutex_lock(&space->space_vol_mutex);
    space->parcel_add_in_progress++;
    nuvo_mutex_unlock(&space->space_vol_mutex);
    NUVO_LOG(space, 20, "Allocating parcel for volume " NUVO_LOG_UUID_FMT,
             NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));

    req->operation = NUVO_OP_ALLOC;
    memset(&req->alloc, 0, sizeof(req->alloc));
    uuid_clear(req->alloc.parcel_uuid);
    uuid_copy(req->alloc.device_uuid, device_uuid);
    uuid_copy(req->alloc.volume_uuid, nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid);
    req->callback = nuvo_space_vol_parcel_alloc_cb;
    req->tag.ptr = (void *)space;
    nuvo_dlnode_init(&req->list_node);
    nuvo_pr_submit_req(req);
    return (0);
}

void nuvo_space_vol_manage_mfl_start(struct nuvo_space_vol *space)
{
    NUVO_LOG(space, 10, "Starting mfl work or volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));

    // move the finished volumes in order to DELETED
    // they would eventually take the karmic wheel to end up as FREED
    // This also avoids restarting mfl on those.

    struct nuvo_vol *vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);

    nuvo_mutex_lock(&vol->mutex);
    nuvo_lun_move_to_deleted_on_replay(vol);
    nuvo_mutex_unlock(&vol->mutex);

    // kick the mfl engine
    nuvo_map_mfl_start(&space->mfl_req);
}

// Documented in header
void nuvo_space_vol_manage_parcels_start(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_LOG(space, 10, "Starting managing parcels for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    NUVO_ASSERT(space->parcel_state == NUVO_VOL_SPACE_PARCELS_HALTED);
    for (uint_fast16_t c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
    {
        space->parcel_class[c].check_for_parcels = true;
    }
    NUVO_ASSERT(space->parcel_add_in_progress == 0);
    space->parcel_state = NUVO_VOL_SPACE_PARCELS_RUNNING;

    vol_needs_parcel_work(space, true);
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

// Documented in header
void nuvo_space_vol_manage_parcels_stop(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_LOG(space, 10, "Stopping managing parcels for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    if (space->parcel_state != NUVO_VOL_SPACE_PARCELS_HALTED)
    {
        NUVO_ASSERT(space->parcel_state != NUVO_VOL_SPACE_PARCELS_HALTING);
        vol_needs_parcel_work(space, true);
        space->parcel_state = NUVO_VOL_SPACE_PARCELS_HALTING;
        while (space->parcel_state != NUVO_VOL_SPACE_PARCELS_HALTED)
        {
            nuvo_cond_wait(&space->space_vol_cond, &space->space_vol_mutex);
        }
    }
    NUVO_ASSERT(space->parcel_state == NUVO_VOL_SPACE_PARCELS_HALTED);
    NUVO_ASSERT(space->parcel_add_in_progress == 0);
    NUVO_LOG(space, 10, "Stopped managing parcels for volume " NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

// Documented in header
void nuvo_space_vol_manage_parcels_suggest(struct nuvo_space_vol *space, uint8_t data_class)
{
    nuvo_mutex_lock(&space->space_vol_mutex);

    NUVO_LOG(space, 40, "Suggesting looking for parcels " NUVO_LOG_UUID_FMT,
             NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));

    space->parcel_class[data_class].check_for_parcels = true;
    vol_needs_parcel_work(space, false);
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

void nuvo_space_vol_manage_gc_start(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    NUVO_ASSERT(space->gc_state == NUVO_VOL_SPACE_GC_HALTED);
    for (uint_fast16_t c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
    {
        space->gc_data_class[c].gc_needed = false;
        space->gc_data_class[c].gc_in_progress = 0;
    }
    space->gc_state = NUVO_VOL_SPACE_GC_RUNNING;
    vol_needs_gc_work(space);
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

void nuvo_space_vol_manage_mfl_stop(struct nuvo_space_vol *space)
{
    nuvo_map_mfl_stop(&space->mfl_req);
}

void nuvo_space_vol_manage_gc_stop(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    if (space->gc_state != NUVO_VOL_SPACE_GC_HALTED)
    {
        NUVO_ASSERT(space->gc_state != NUVO_VOL_SPACE_GC_HALTING);
        vol_needs_gc_work(space);
        space->gc_state = NUVO_VOL_SPACE_GC_HALTING;
        // TODO - move urgent and pending back to manifest.
        while (space->gc_state != NUVO_VOL_SPACE_GC_HALTED)
        {
            nuvo_cond_wait(&space->space_vol_cond, &space->space_vol_mutex);
        }
    }
    NUVO_ASSERT(space->gc_state == NUVO_VOL_SPACE_GC_HALTED);
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

/**
 * Notify the space thread it needs to supply segments somehow, someway.
 *
 * Usually it gets them via gc.  If gc is not running it falls back to
 * parcel allocation.
 *
 * \param space The space structure of the volume.
 * \param data_class The data class we need a parcel on.
 */
void nuvo_space_vol_need_empty_segments(struct nuvo_space_vol *space, uint8_t data_class)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    if (space->gc_state == NUVO_VOL_SPACE_GC_RUNNING)
    {
        if (!space->gc_data_class[data_class].gc_needed &&
            space->gc_data_class[data_class].gc_in_progress == 0)
        {
            space->gc_data_class[data_class].gc_needed = true;
            vol_needs_gc_work(space);
            nuvo_mutex_unlock(&space->space_vol_mutex);
            return;
        }
    }
    else
    {
        nuvo_mutex_unlock(&space->space_vol_mutex);
        nuvo_space_vol_manage_parcels_suggest(space, data_class);
        return;
    }
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

/**
 * Routines for clients (i.e. the logger) to get segments.
 */

/**
 *  Create some new segments.
 */
void nuvo_space_trigger_segment_creation(struct nuvo_space_vol      *space,
                                         uint8_t                     data_class,
                                         struct nuvo_mfst_space_info space_info)
{
    if (should_get_parcels(&space_info))
    {
        nuvo_space_vol_manage_parcels_suggest(space, data_class);
    }
    if (should_get_segments(&space_info))
    {
        nuvo_space_vol_need_empty_segments(space, data_class);
    }
}

// Documented in header.
struct nuvo_segment *nuvo_space_vol_segment_get(struct nuvo_space_vol  *space,
                                                uint8_t                 data_class,
                                                uint8_t                 data_type,
                                                unsigned                num,
                                                uint_fast16_t          *avoid_dev,
                                                enum nuvo_space_urgency urgency)
{
    (void)data_type;
    struct nuvo_mfst_space_info space_info;
    struct nuvo_segment        *segment = nuvo_segment_alloc(&nuvo_global_segment_free_list);
    if (segment == NULL)
    {
        NUVO_ERROR_PRINT("Failed allocating a segment structure");
        return (NULL);
    }

    nuvo_return_t rc = nuvo_mfst_segment_get(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst,
                                             data_class, num, avoid_dev, segment, &space_info);

    nuvo_mutex_lock(&space->space_vol_mutex);
    if (should_freeze_ios(space, &space_info))
    {
        nuvo_space_write_permit(space, false);
    }
    nuvo_mutex_unlock(&space->space_vol_mutex);
    nuvo_space_trigger_segment_creation(space, data_class, space_info);

    NUVO_LOG(space, 80, "Total segments: %d, free segments %d", space_info.class_total_segments, space_info.class_free_segments);

    if (rc >= 0)
    {
        NUVO_LOG(space, 40, "Allocated a segment (%d, %d) for " NUVO_LOG_UUID_FMT,
                 segment->parcel_index, segment->block_offset,
                 NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
        return (segment);
    }
    NUVO_ASSERT(rc == -NUVO_E_NO_FREE_SEGMENTS);

    if (urgency != NUVO_SPACE_SEGMENT_DEFINITELY_AVOID &&
        space_info.devices_skipped != 0)
    {
        bool complain = (space_info.segmentless_devices != 0);
        rc = nuvo_mfst_segment_get(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst, data_class, 0, avoid_dev, segment, &space_info);
        NUVO_ASSERT(rc >= 0); // TODO
        if (complain)
        {
            /*
             * Only print this out if we actually had a device with no segments.
             * Suppressing this because printing it was apparently "too scary".
             * Hopefully suppressing it will not also be "too scary".
             */
            NUVO_LOG(space, 40, "Allocated a desperation segment (%d, %d) for " NUVO_LOG_UUID_FMT,
                     segment->parcel_index, segment->block_offset,
                     NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
        }
        return (segment);
    }
    nuvo_segment_free(&nuvo_global_segment_free_list, segment);
    return (NULL);
}

// Documented in header.
nuvo_return_t nuvo_space_vol_segment_log_replay_get(struct nuvo_space_vol *space,
                                                    uint32_t               parcel_index,
                                                    uint32_t               block_offset,
                                                    struct nuvo_segment  **segment)
{
    *segment = nuvo_segment_alloc(&nuvo_global_segment_free_list);
    if (*segment == NULL)
    {
        NUVO_ERROR_PRINT("Failed allocating a segment structure for log replay");
        return (-NUVO_E_OUT_OF_SEGMENT_STRUCTS);
    }
    NUVO_LOG(space, 40, "Allocated a segment structure for log replay on volume " NUVO_LOG_UUID_FMT,
             NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    return (nuvo_mfst_segment_for_log_replay(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst, parcel_index, block_offset, *segment));
}

/**
 * Get a segment from the manifest to clean on this class.
 * \param space The space structure.
 * \param data_class The data class of parcel to get a segment on.
 * \param segment To return the allocated segment structure with pinned segment.
 * \returns percent utilization of segment chosen or negative on error
 */
nuvo_return_t nuvo_space_vol_segment_gc_get(struct nuvo_space_vol *space,
                                            uint8_t                data_class,
                                            struct nuvo_segment  **segment)
{
    nuvo_return_t rc = nuvo_mfst_segment_for_gc(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst, data_class, segment);

    if (rc >= 0)
    {
        NUVO_ASSERT((*segment)->parcel_index != 0 || (*segment)->block_offset);
        NUVO_LOG(space, 40, "Allocated a gc segment (%d, %d) for " NUVO_LOG_UUID_FMT,
                 (*segment)->parcel_index, (*segment)->block_offset,
                 NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
    }
    return (rc);
}

// Documented in header
void nuvo_space_vol_segment_done(struct nuvo_space_vol          *space,
                                 struct nuvo_segment            *seg,
                                 enum nuvo_mfst_segment_reason_t reason)
{
    NUVO_LOG(space, 40, "Done with segment (%d, %d) for " NUVO_LOG_UUID_FMT " reason: %d",
             seg->parcel_index, seg->block_offset,
             NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid),
             reason);

    nuvo_mfst_segment_done(&nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->log_volume.mfst, seg, reason);
    nuvo_segment_free(&nuvo_global_segment_free_list, seg);
}

// Documented in header
nuvo_return_t nuvo_space_init()
{
    nuvo_return_t rc;

    rc = nuvo_mutex_init(&nuvo_space_ctl.space_mutex);
    if (rc < 0)
    {
        return (-NUVO_ENOMEM);
    }
    rc = nuvo_cond_init(&nuvo_space_ctl.space_cond);
    if (rc < 0)
    {
        goto destroy_mutex;
    }
    rc = nuvo_mutex_init(&nuvo_space_ctl.gc_mutex);
    if (rc < 0)
    {
        goto destroy_cond;
    }
    rc = nuvo_mutex_init(&nuvo_space_ctl.gc_free_batch_mutex);
    if (rc < 0)
    {
        goto destroy_gc_mutex;
    }


    if (nuvo_segment_free_list_create(&nuvo_global_segment_free_list, 1000) < 0)
    {
        goto destroy_gc_free_batch_mutex;
    }

    rc = nuvo_gc_batchs_init();
    if (rc < 0)
    {
        goto destroy_segment_list;
    }

    nuvo_space_ctl.gc_total = NUVO_SPACE_GC_NUM;
    nuvo_space_ctl.gc_processing_enabled = true;
    nuvo_dlist_init(&nuvo_space_ctl.gc_free_list);
    nuvo_dlist_init(&nuvo_space_ctl.gc_needs_work);
    nuvo_dlist_init(&nuvo_space_ctl.gc_needs_gc_batch);
    for (unsigned i = 0; i < nuvo_space_ctl.gc_total; i++)
    {
        (void)nuvo_mutex_init(&nuvo_space_ctl.gc[i].gc_mutex);   // TODO - handle failure
        nuvo_dlnode_init(&nuvo_space_ctl.gc[i].list_node);
        nuvo_dlist_insert_head(&nuvo_space_ctl.gc_free_list, &nuvo_space_ctl.gc[i].list_node);
    }

    nuvo_space_ctl.halting = false;

    nuvo_dlist_init(&nuvo_space_ctl.vol_needs_work_cp);
    nuvo_dlist_init(&nuvo_space_ctl.vol_needs_work_parcel);
    nuvo_dlist_init(&nuvo_space_ctl.vol_needs_work_gc);
    nuvo_dlist_init(&nuvo_space_ctl.vol_needs_gc_struct);
    nuvo_dlist_init(&nuvo_space_ctl.vol_needs_work_mfl);
    rc = -pthread_create(&nuvo_space_ctl.thread_id, NULL, nuvo_space_thread, NULL);
    if (rc != 0)
    {
        goto destroy_gc_batches;
    }
    NUVO_LOG(space, 10, "Initialized space");
    return (0);

destroy_gc_batches:
    nuvo_gc_batchs_destroy();
destroy_segment_list:
    nuvo_segment_free_list_destroy(&nuvo_global_segment_free_list);
destroy_gc_free_batch_mutex:
    nuvo_mutex_destroy(&nuvo_space_ctl.gc_free_batch_mutex);
destroy_gc_mutex:
    nuvo_mutex_destroy(&nuvo_space_ctl.gc_mutex);
destroy_cond:
    nuvo_cond_destroy(&nuvo_space_ctl.space_cond);
destroy_mutex:
    nuvo_mutex_destroy(&nuvo_space_ctl.space_mutex);
    return (rc);
}

// Documented in header
void nuvo_space_gc_disable_for_test()
{
    nuvo_space_ctl.gc_processing_enabled = false;
}

// Documented in header
void nuvo_space_gc_enable_for_test()
{
    nuvo_space_ctl.gc_processing_enabled = true;
}

//Documented in header
void nuvo_space_halt(void)
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    NUVO_LOG(space, 10, "Halting space");
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_cp));
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_parcel));
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_gc));
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_gc_struct));
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.gc_needs_work));
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_mfl));
    nuvo_space_ctl.halting = true;
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);

    pthread_join(nuvo_space_ctl.thread_id, NULL);
    nuvo_segment_free_list_destroy(&nuvo_global_segment_free_list);
    nuvo_cond_destroy(&nuvo_space_ctl.space_cond);
    nuvo_mutex_destroy(&nuvo_space_ctl.space_mutex);
    NUVO_LOG(space, 10, "Halted space");
}

/*
 * Get nuvo_gc structure and initialize it as working on vol and segment.
 */
struct nuvo_gc *nuvo_gc_alloc()
{
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    struct nuvo_gc *gc = nuvo_dlist_remove_head_object(&nuvo_space_ctl.gc_free_list, struct nuvo_gc, list_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
    return (gc);
}

void nuvo_gc_init(struct nuvo_gc *gc, struct nuvo_vol *vol, struct nuvo_segment *segment)
{
    gc->vol = vol;
    gc->segment = segment;
    gc->state = NUVO_SPACE_GC_DIGEST_READING;
    gc->moving_log.num_used = 0;
    nuvo_mutex_lock(&vol->mutex);
    gc->starting_next_create_pit_id = vol->snap_generation + 1;
    nuvo_mutex_unlock(&vol->mutex);
    gc->pinned_lun = nuvo_get_lun_oldest(vol);
    NUVO_ASSERT(gc->pinned_lun == NULL || gc->pinned_lun->snap_id < gc->starting_next_create_pit_id);
    gc->phase_callback = NULL;
    gc->moving_callback = NULL;
    memset(&gc->stats, 0, sizeof(gc->stats));
}

void nuvo_gc_re_init(struct nuvo_gc *gc)
{
    gc->state = NUVO_SPACE_GC_DIGEST_READING;
    nuvo_mutex_lock(&gc->vol->mutex);
    if (gc->pinned_lun)
    {
        nuvo_mutex_lock(&gc->pinned_lun->mutex);
        nuvo_lun_unpin(gc->pinned_lun);
        nuvo_mutex_unlock(&gc->pinned_lun->mutex);
    }
    gc->starting_next_create_pit_id = gc->vol->snap_generation + 1;
    nuvo_mutex_unlock(&gc->vol->mutex);
    gc->pinned_lun = nuvo_get_lun_oldest(gc->vol);
    NUVO_ASSERT(gc->pinned_lun == NULL || gc->pinned_lun->snap_id < gc->starting_next_create_pit_id);
    gc->phase_callback = NULL;  // Why?
    gc->stats.reinits++;
}

void nuvo_gc_free(struct nuvo_gc *gc)
{
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    nuvo_dlist_insert_head(&nuvo_space_ctl.gc_free_list, &gc->list_node);
    struct nuvo_space_vol *waiting = nuvo_dlist_remove_head_object(&nuvo_space_ctl.vol_needs_gc_struct, struct nuvo_space_vol, gc_node);
    if (waiting != NULL)
    {
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_work_gc, &waiting->gc_node);
        nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    }
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
}

struct nuvo_space_vol *nuvo_gc_peek_vol_needs_gc_struct()
{
    return (nuvo_dlist_get_head_object(&nuvo_space_ctl.vol_needs_gc_struct, struct nuvo_space_vol, gc_node));
}

void nuvo_gc_needs_work(struct nuvo_gc *gc)
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    if (gc->list_node.next == NULL)
    {
        nuvo_dlist_insert_tail(&nuvo_space_ctl.gc_needs_work, &gc->list_node);
    }
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

struct nuvo_gc *nuvo_gc_needs_work_get()
{
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    struct nuvo_gc *gc = nuvo_dlist_remove_head_object(&nuvo_space_ctl.gc_needs_work, struct nuvo_gc, list_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
    return (gc);
}

void nuvo_gc_needs_batch(struct nuvo_gc *gc)
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.gc_free_batch_mutex);
    if (gc->list_node.next == NULL)
    {
        if (NULL == nuvo_dlist_get_head(&nuvo_space_ctl.gc_free_batches))
        {
            nuvo_dlist_insert_tail(&nuvo_space_ctl.gc_needs_gc_batch, &gc->list_node);
        }
        else
        {
            nuvo_dlist_insert_tail(&nuvo_space_ctl.gc_needs_work, &gc->list_node);
        }
    }
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_free_batch_mutex);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}

struct nuvo_gc *nuvo_gc_needs_batch_get()
{
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    struct nuvo_gc *gc = nuvo_dlist_remove_head_object(&nuvo_space_ctl.gc_needs_gc_batch, struct nuvo_gc, list_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
    return (gc);
}

/*
 * Keep a pool of log/map reqs that can be used by gc's.
 */
nuvo_return_t nuvo_gc_batchs_init()
{
    nuvo_return_t rc = nuvo_mutex_init(&nuvo_space_ctl.gc_free_batch_mutex);

    if (rc != 0)
    {
        return (-NUVO_ENOMEM);
    }
    nuvo_dlist_init(&nuvo_space_ctl.gc_free_batches);
    for (uint_fast16_t i = 0; i < NUVO_SPACE_GC_BATCHES; i++)
    {
        struct nuvo_gc_batch *gc_batch = &nuvo_space_ctl.gc_batches[i];
        rc = nuvo_mutex_init(&gc_batch->sync_signal);
        if (rc != 0)
        {
            for (uint_fast16_t j = 0; j < i; j++)
            {
                nuvo_mutex_destroy(&nuvo_space_ctl.gc_batches[j].sync_signal);
            }
            nuvo_mutex_destroy(&nuvo_space_ctl.gc_free_batch_mutex);
            return (-NUVO_ENOMEM);
        }
        nuvo_dlnode_init(&gc_batch->list_node);
        nuvo_dlist_insert_head(&nuvo_space_ctl.gc_free_batches, &gc_batch->list_node);
    }
    return (0);
}

void nuvo_gc_batchs_destroy()
{
    nuvo_mutex_destroy(&nuvo_space_ctl.gc_free_batch_mutex);
}

struct nuvo_gc_batch *nuvo_gc_batch_alloc()
{
    nuvo_mutex_lock(&nuvo_space_ctl.gc_free_batch_mutex);
    struct nuvo_gc_batch *gc_batch = nuvo_dlist_remove_head_object(&nuvo_space_ctl.gc_free_batches, struct nuvo_gc_batch, list_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_free_batch_mutex);
    return (gc_batch);
}

void nuvo_gc_batch_free(struct nuvo_gc_batch *gc_batch)
{
    nuvo_mutex_lock(&nuvo_space_ctl.gc_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.gc_free_batch_mutex);
    nuvo_dlist_insert_tail(&nuvo_space_ctl.gc_free_batches, &gc_batch->list_node);
    nuvo_dlist_insert_list_tail(&nuvo_space_ctl.gc_needs_work, &nuvo_space_ctl.gc_needs_gc_batch);
    nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_free_batch_mutex);
    nuvo_mutex_unlock(&nuvo_space_ctl.gc_mutex);
}

// Documented in header
unsigned nuvo_space_gc_state_work()
{
    nuvo_return_t         rc;
    struct nuvo_gc_batch *gc_batch;

    unsigned count = 0;
    bool     did_work = true;

    NUVO_LOG(space, 25, "nuvo_space_gc_state_work");

    while (did_work && nuvo_space_ctl.gc_processing_enabled)
    {
        did_work = false;
        // Get a gc that is ready for work.
        struct nuvo_gc *gc = nuvo_gc_needs_work_get();
        if (gc != NULL)
        {
            did_work = true;
            count++;
            switch (gc->state)
            {
            case NUVO_SPACE_GC_MOVE_FAILED:
                nuvo_gc_re_init(gc);

            /* FALLTHROUGH */
            case NUVO_SPACE_GC_DIGEST_READING:
                NUVO_LOG(space, 30, "GC reading for volume " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                         NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
                rc = nuvo_gc_read_digest(gc);   // read completion will requeue this for work.
                NUVO_ASSERT(rc == 0);           // TODO handle mutex init failure.
                break;

            case NUVO_SPACE_GC_DIGEST_ELIDING:
                gc_batch = nuvo_gc_batch_alloc();
                if (gc_batch == NULL)
                {
                    nuvo_gc_needs_batch(gc);
                }
                else
                {
                    NUVO_LOG(space, 30, "GC eliding for volume " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
                    rc = nuvo_gc_elide_unused_batch(gc, gc_batch);
                    NUVO_ASSERT(rc >= 0 || rc == -NUVO_EAGAIN);
                    if (rc == -NUVO_EAGAIN)
                    {
                        nuvo_gc_needs_work(gc);
                    }
                }
                break;

            case NUVO_SPACE_GC_MOVING_DATA:
                gc_batch = nuvo_gc_batch_alloc();
                if (gc_batch == NULL)
                {
                    nuvo_gc_needs_batch(gc);
                }
                else
                {
                    NUVO_LOG(space, 30, "GC moving data for volume " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
                    rc = nuvo_gc_move_data_batch(gc, gc_batch);
                    NUVO_ASSERT(rc >= 0);
                }
                break;

            case NUVO_SPACE_GC_MOVE_MAPS:
                // if map batches are backlogged, attempt a flush
                // this is a best effort attempt, now that we don't panic when are out of free batches
                // And we can keep accumulating more dirty maps.
                // if there are free batches and we have more than a batch size, attempt flush
                // until the backlog is less than the batch size
                // CUM-1352, TODO:We must do a more comprehensive fix in the context of CUM-1352
                nuvo_map_try_flush(gc->vol);

                gc_batch = nuvo_gc_batch_alloc();
                if (gc_batch == NULL)
                {
                    nuvo_gc_needs_batch(gc);
                }
                else
                {
                    NUVO_LOG(space, 30, "GC moving maps for volume " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
                    rc = nuvo_gc_move_maps_batch(gc, gc_batch);
                    NUVO_ASSERT(rc >= 0);
                }
                break;

            case NUVO_SPACE_GC_MOVING_DONE:
                // TODO check status

                // this is a best effort attempt, now that we don't panic when are out of free batches
                // And we can keep accumulating more dirty maps.
                // if there are free batches and we have more than a batch size, attempt flush
                // until the backlog is less than the batch size
                // CUM-1352, TODO:We must do a more comprehensive fix in the context of CUM-1352
                nuvo_map_try_flush(gc->vol);

                NUVO_LOG(space, 30, "GC done for volume " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                         NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
                struct nuvo_space_vol *space_vol = &gc->vol->log_volume.space;
                uint8_t data_class = gc->segment->data_class;
                struct nuvo_mfst_space_info space_info;
                nuvo_gc_done(gc);
                nuvo_mfst_segments_avail(&gc->vol->log_volume.mfst, data_class, &space_info);
                nuvo_space_trigger_segment_creation(space_vol, data_class, space_info);
                break;

            case NUVO_SPACE_GC_UNUSED:
                NUVO_PANIC("Trying to work on unused nuvo_gc");
            }
        }
    }
    return (count);
}

static struct nuvo_space_vol *get_vol_needs_gc()
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    struct nuvo_space_vol *space_vol = nuvo_dlist_remove_head_object(&nuvo_space_ctl.vol_needs_work_gc, struct nuvo_space_vol, gc_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
    return (space_vol);
}

void nuvo_space_gc_vol_work()
{
    NUVO_LOG(space, 25, "nuvo_space_gc_vol_work");
    struct nuvo_space_vol *space_vol;
    while (NULL != (space_vol = get_vol_needs_gc()))
    {
        unsigned total_in_progress;

        nuvo_mutex_lock(&space_vol->space_vol_mutex);
        struct nuvo_vol *vol = nuvo_containing_object(space_vol, struct nuvo_vol, log_volume.space);
        switch (space_vol->gc_state)
        {
        case NUVO_VOL_SPACE_GC_RUNNING:
            for (unsigned dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
            {
                if (!space_vol->gc_data_class[dc].gc_needed)
                {
                    continue;
                }
                struct nuvo_gc *gc = nuvo_gc_alloc();
                if (gc != NULL)
                {
                    // Pick the best segment to gc
                    struct nuvo_segment *segment;
                    space_vol->gc_data_class[dc].gc_needed = false;
                    nuvo_return_t rc = nuvo_space_vol_segment_gc_get(space_vol, dc, &segment);

                    /*
                     * Non-negative rc is percent fullness of segment.
                     * First decide if this worth cleaning, then decide if we should get more parcels.
                     */
                    if (rc >= 0)
                    {
                        NUVO_LOG(space, 25, "Cleaning segment with utilization %d", segment->gc_utilization);
                        space_vol->gc_data_class[dc].gc_in_progress++;
                        nuvo_mutex_unlock(&space_vol->space_vol_mutex);
                        nuvo_gc_init(gc, vol, segment);
                        nuvo_mutex_lock(&space_vol->space_vol_mutex);
                        nuvo_gc_needs_work(gc);
                    }
                    else
                    {
                        NUVO_ERROR_PRINT("Didn't clean segment utilization/error: %d", rc);
                        nuvo_space_vol_segment_done(space_vol, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
                        nuvo_gc_free(gc);
                        // TODO - record known hopeless.
                    }
                    if (rc < 0 || rc > 50)  // - CUM-1199 evil constant - when having to clean full-ish stuff get more parcels.
                    {
                        // Locking is preventing me from calling nuvo_space_vol_manage_parcels_suggest
                        space_vol->parcel_class[dc].check_for_parcels = true;
                        vol_needs_parcel_work(space_vol, false);
                    }
                }
                else
                {
                    NUVO_LOG(space, 25, "Vol needs to wait for GC");
                    vol_needs_gc_struct(space_vol);
                }
            }
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            break;

        case NUVO_VOL_SPACE_GC_HALTING:
            // Drain in progress GC's
            total_in_progress = 0;
            for (unsigned dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
            {
                total_in_progress += space_vol->gc_data_class[dc].gc_in_progress;
                total_in_progress += nuvo_mfst_gc_pipeline_total(&vol->log_volume.mfst);
            }
            if (total_in_progress != 0)
            {
                space_vol->cp_requested = true;
                vol_needs_cp_work(space_vol);
            }
            else
            {
                nuvo_mfst_return_gc_segments(&vol->log_volume.mfst);
                space_vol->gc_state = NUVO_VOL_SPACE_GC_HALTED;
                nuvo_cond_broadcast(&space_vol->space_vol_cond);
            }
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            break;

        case NUVO_VOL_SPACE_GC_HALTED:
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            break;
        }
    }
}

void nuvo_space_write_permission(struct nuvo_space_vol *space)
{
    nuvo_mutex_lock(&space->space_vol_mutex);
    while (!space->space_writes_ok)
    {
        NUVO_LOG(space, 20, "Pausing client write\n");
        nuvo_cond_wait(&space->space_write_permission, &space->space_vol_mutex);
    }
    nuvo_mutex_unlock(&space->space_vol_mutex);
}

void nuvo_space_write_permit(struct nuvo_space_vol *space,
                             bool                   allow)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    NUVO_ERROR_PRINT("Called nuvo_space_write_permit");
    if (space->space_writes_ok == false && allow == true)
    {
        NUVO_LOG(space, 20, "Unpausing client write\n");
        nuvo_cond_broadcast(&space->space_write_permission);
    }
    space->space_writes_ok = allow;
}

static struct nuvo_space_vol *get_vol_needs_parcel()
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    struct nuvo_space_vol *space_vol = nuvo_dlist_remove_head_object(&nuvo_space_ctl.vol_needs_work_parcel, struct nuvo_space_vol, parcel_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
    return (space_vol);
}

void nuvo_space_parcel_work()
{
    NUVO_LOG(space, 25, "nuvo_space_parcel_work");
    struct nuvo_space_vol *space_vol;
    while (NULL != (space_vol = get_vol_needs_parcel()))
    {
        nuvo_mutex_lock(&space_vol->space_vol_mutex);
        if (space_vol->cp_state == NUVO_VOL_SPACE_CPS_NOT_IN_CP ||
            space_vol->cp_state == NUVO_VOL_SPACE_CPS_HALTED)
        {
            struct nuvo_io_request *io_req;
            while (NULL != (io_req = nuvo_dlist_remove_head_object(&space_vol->completed_io_reqs, struct nuvo_io_request, list_node)))
            {
                NUVO_ASSERT(space_vol->parcel_add_in_progress > 0);
                nuvo_space_vol_handle_parcel_req(space_vol, io_req);
                nuvo_cond_broadcast(&space_vol->space_vol_cond);
            }
        }

        switch (space_vol->parcel_state)
        {
        case NUVO_VOL_SPACE_PARCELS_RUNNING:
            if (space_vol->parcel_add_in_progress == 0)
            {
                for (uint_fast16_t c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
                {
                    if (space_vol->parcel_class[c].check_for_parcels)
                    {
                        nuvo_mutex_unlock(&space_vol->space_vol_mutex);
                        nuvo_return_t rc = nuvo_space_vol_parcel_alloc(space_vol, c);
                        if (rc != 0)
                        {
                            space_vol->parcel_class[c].check_for_parcels = false;
                        }
                        nuvo_mutex_lock(&space_vol->space_vol_mutex); // TODO - badly placed fix me.
                    }
                }
            }
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            break;

        case NUVO_VOL_SPACE_PARCELS_HALTING:
            if (!space_vol->parcel_add_in_progress)
            {
                space_vol->parcel_state = NUVO_VOL_SPACE_PARCELS_HALTED;
                nuvo_cond_broadcast(&space_vol->space_vol_cond);
            }
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            break;

        case NUVO_VOL_SPACE_PARCELS_HALTED:
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            break;
        }
    }
}

static struct nuvo_space_vol *get_vol_needs_cp()
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    struct nuvo_space_vol *space_vol = nuvo_dlist_remove_head_object(&nuvo_space_ctl.vol_needs_work_cp, struct nuvo_space_vol, cp_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
    return (space_vol);
}

static struct nuvo_space_vol *get_vol_needs_mfl()
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    struct nuvo_space_vol *space_vol = nuvo_dlist_remove_head_object(&nuvo_space_ctl.vol_needs_work_mfl, struct nuvo_space_vol, mfl_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);

    return (space_vol);
}

void nuvo_space_cp_work()
{
    NUVO_LOG(space, 25, "nuvo_space_cp_work");
    struct nuvo_space_vol *space_vol;

    while (NULL != (space_vol = get_vol_needs_cp()))
    {
        nuvo_mutex_lock(&space_vol->space_vol_mutex);

        switch (space_vol->cp_state)
        {
        case NUVO_VOL_SPACE_CPS_NOT_IN_CP:
            if (space_vol->cp_requested)
            {
                space_vol->cp_requested = false;
                space_vol->cp_state = NUVO_VOL_SPACE_CPS_WAITING_MAP;
                nuvo_mutex_unlock(&space_vol->space_vol_mutex);
                nuvo_space_vol_start_cp(space_vol);
                nuvo_mutex_lock(&space_vol->space_vol_mutex);
            }
            else if (space_vol->cp_halting)
            {
                NUVO_ASSERT_MUTEX_HELD(&space_vol->space_vol_mutex);
                if (!nuvo_dlnode_on_list(&space_vol->cp_node))
                {
                    space_vol->cp_state = NUVO_VOL_SPACE_CPS_HALTED;
                }
                nuvo_cond_broadcast(&space_vol->space_vol_cond);
            }
            break;

        case NUVO_VOL_SPACE_CPS_MAP_DONE:
            space_vol->cp_state = NUVO_VOL_SPACE_CPS_WRITING_MFST;
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            nuvo_space_map_checkpoint_done(space_vol);
            nuvo_mutex_lock(&space_vol->space_vol_mutex);
            nuvo_cond_broadcast(&space_vol->space_vol_cond);
            break;

        case NUVO_VOL_SPACE_CPS_WAITING_MAP:
        case NUVO_VOL_SPACE_CPS_WRITING_MFST:
        case NUVO_VOL_SPACE_CPS_HALTED:
            break;
        }

        nuvo_mutex_unlock(&space_vol->space_vol_mutex);
    }
}

static inline bool space_work_pending()
{
    return (NULL != nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_cp) ||
            NULL != nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_parcel) ||
            NULL != nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_gc) ||
            NULL != nuvo_dlist_get_head(&nuvo_space_ctl.gc_needs_work) ||
            NULL != nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_mfl));
}

void nuvo_space_mfl_work()
{
    struct nuvo_space_vol *space_vol;

    while (NULL != (space_vol = get_vol_needs_mfl()))
    {
        nuvo_mutex_lock(&space_vol->space_vol_mutex);
        struct nuvo_vol *vol = nuvo_containing_object(space_vol, struct nuvo_vol, log_volume.space);
        struct nuvo_map_free_lun_request *mfl_req = &space_vol->mfl_req;

        NUVO_LOG(space, 25, "There is mfl work to do, mfl_state:%d lun:%p "
                 "lun(%d) lun mfl state:%d",
                 mfl_req->state, mfl_req->lun,
                 mfl_req->lun ? mfl_req->lun->snap_id : 0,
                 mfl_req->lun ? mfl_req->lun->mfl_state : 0);

        nuvo_mutex_lock(&mfl_req->mutex);

        if (mfl_req->state == MFL_NONE)
        {
            // below is new lun work
            NUVO_ASSERT(!mfl_req->work_state);

            struct nuvo_lun *lun = nuvo_get_next_lun_to_delete(vol);

            if (!lun)
            {
                nuvo_mutex_unlock(&mfl_req->mutex);
                nuvo_mutex_unlock(&space_vol->space_vol_mutex);
                continue;
            }

            nuvo_mutex_lock(&lun->mutex);
            NUVO_ASSERT(lun->lun_state == NUVO_LUN_STATE_DELETING);
            lun->mfl_state = NUVO_LUN_MFL_L0_IN_PROGRESS;
            nuvo_mutex_unlock(&lun->mutex);
            nuvo_map_mfl_req_init(mfl_req, lun);
        }

        if (mfl_req->work_state)
        {
            nuvo_mutex_unlock(&mfl_req->mutex);
            nuvo_mutex_unlock(&space_vol->space_vol_mutex);
            // trigger or resume mfl
            nuvo_map_mfl_work(mfl_req);
            continue;
        }

        nuvo_mutex_unlock(&mfl_req->mutex);
        nuvo_mutex_unlock(&space_vol->space_vol_mutex);
    }
}

/**
 * \brief Thread for handling space management.
 */
void *nuvo_space_thread(void *arg)
{
    (void)arg;

    while (1)
    {
        nuvo_space_gc_state_work();
        nuvo_space_gc_vol_work();
        nuvo_space_parcel_work();
        nuvo_space_cp_work();
        nuvo_space_mfl_work();

        nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
        if (nuvo_space_ctl.halting)
        {
            NUVO_ASSERT(!space_work_pending());
            nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
            break;
        }
        if (!space_work_pending())   // TODO - might be in GC HALTING (or PARCEL)
        {
            nuvo_cond_wait(&nuvo_space_ctl.space_cond, &nuvo_space_ctl.space_mutex);
        }
        nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
    }

    pthread_exit(0);
    return (NULL);
}

void nuvo_space_assert_no_cp_work_needed()
{
    NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_cp));
}
