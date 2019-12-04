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
#pragma once
#include "manifest.h"
#include "map.h"
#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "nuvo_pr_parallel.h"
#include "segment.h"
#include "status.h"
#include "map_free_lun.h"

/**
 * @file space.h
 * @brief The space management code.
 *
 * This service manages space in volumes.  It manages allocation
 * and freeing of parcels,  drives cleaning of segments and
 * supplies clean segments to the logger.
 */

enum nuvo_space_vol_checkpoint_state
{
    NUVO_VOL_SPACE_CPS_HALTED,
    NUVO_VOL_SPACE_CPS_NOT_IN_CP,
    NUVO_VOL_SPACE_CPS_WAITING_MAP,
    NUVO_VOL_SPACE_CPS_MAP_DONE,
    NUVO_VOL_SPACE_CPS_WRITING_MFST
};

enum nuvo_space_vol_parcel_state
{
    NUVO_VOL_SPACE_PARCELS_HALTED,
    NUVO_VOL_SPACE_PARCELS_RUNNING,
    NUVO_VOL_SPACE_PARCELS_HALTING
};

enum nuvo_space_vol_gc_state
{
    NUVO_VOL_SPACE_GC_HALTED,
    NUVO_VOL_SPACE_GC_RUNNING,
    NUVO_VOL_SPACE_GC_HALTING
};

/**
 * \brief This is the space management control for a volume.
 * This will be embedded within the volume.
 *
 * Thinking - this needs to have explicit or implicit states:
 *   - when we can start cleaning
 *   - when it is ok to get more parcels
 */
struct nuvo_space_vol {
    nuvo_mutex_t       space_vol_mutex;               /** Mutex protecting this structure. */
    nuvo_cond_t        space_vol_cond;                /** Condition variable for waiting for something to happen on this volume. */

    struct nuvo_dlnode cp_node;                       /** on list of all volumes that need some cp work. */
    struct nuvo_dlnode parcel_node;                   /** on list of all volumes that need parcel work (e.g. alloc) */
    struct nuvo_dlnode gc_node;                       /** on list of all volumes that need gc work. */
    struct nuvo_dlnode mfl_node;                      /** on list of all volumes that need map free lun work*/

    // Anonymous structures just to group things.
    struct {
        enum nuvo_space_vol_checkpoint_state cp_state;          /** State of driving CPs. */
        bool                                 cp_requested;      /** Has a CP been requested from outside? */
        bool                                 cp_halting;        /** Should halt. */
        struct nuvo_parallel_io              cp_par_io;         /** Parallel IO for writing manifest. */
        nuvo_mutex_t                         cp_sync_signal;    /** Sync signal to use for allocing ios. */
        struct nuvo_map_checkpoint_req       cp_map_checkpoint_req;
    };
    struct {
        enum nuvo_space_vol_parcel_state parcel_state;              /** State of managing parcels. */
        struct nuvo_dlist                completed_io_reqs;         /** Parcel ops that pr has completed. */
        struct {
            bool check_for_parcels;                                 /** Should we check for some reason? */
        }                                parcel_class[NUVO_MAX_DATA_CLASSES];
        unsigned                         parcel_add_in_progress;    /** How many parcel ops in progress. */
    };

    struct {
        enum nuvo_space_vol_gc_state gc_state;                  /** State for garbage collection. */
        struct {
            bool     gc_needed;                                 /** Needed for this volume/class. */
            uint16_t gc_in_progress;                            /** How many are in progress. */
        }                            gc_data_class[NUVO_MAX_DATA_CLASSES];
    };
    /* lun delete mfl attributes*/
    struct {
        struct nuvo_map_free_lun_request mfl_req;
    };

    nuvo_cond_t        space_write_permission;            /** Condition variable for waiting for write permission */
    bool               space_writes_ok;                   /** Are client writes allowed */
    bool               space_snap_frozen;
};

/**
 * \brief Thread for handling space management.
 */
void *nuvo_space_thread(void *arg);

/**
 * \brief Initialize space management for the system.
 *
 * Initialize space management.
 *
 * \retval -NUVO_ENOMEM Failed to initialize a mutex.
 * \retval -NUVO_EAGAIN Failure to initialize the thread.
 * \retval -NUVO_EINVAL Failure to initialize the thread.
 */
nuvo_return_t nuvo_space_init();

/**
 * \brief nuvo_space_gc_disable_for_test does what it says
 */
void nuvo_space_gc_disable_for_test();

/**
 * \brief nuvo_space_gc_enable_for_test does what it says
 */
void nuvo_space_gc_enable_for_test();

/**
 * \brief Shutdown the space management system.
 */
void nuvo_space_halt(void);

struct nuvo_vol;

/**
 * \brief Start running space management on a volume.
 *
 * Consider just passing in the volume.
 *
 * \param space The nuvo_space_vol.
 * \return 0 on success, negative on failure.
 * \retval -ENOMEM Failure to init mutex.
 */
nuvo_return_t nuvo_space_vol_init(struct nuvo_space_vol *space);

/**
 * \brief Stop all space management on volume.
 *
 * This is a synchronous call to stop space management.
 * \param space The space tracking structure for the volume.
 */
void nuvo_space_vol_stop_management(struct nuvo_space_vol *space);

/**
 * \brief Tear down the volume space structure.
 *
 * Stops all running of the volume space management.
 * First stops managing parcels, then stops managing CPs,
 * then removes from lists.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_destroy(struct nuvo_space_vol *space);

/**
 * \brief Start managing parcels on the volume.
 *
 * Tells the thread to start managing parcels on the
 * volume,such as allocating parcels to create free segments.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_manage_parcels_start(struct nuvo_space_vol *space);

/**
 * \brief Start up the mfl work machinery
 *
 * We don't do mfl work during replay
 * so we begin the volume as MFL paused. The below would kick start MFL work
 *
 *
 * \param space The nuvo_space_vol.
 */

void  nuvo_space_vol_manage_mfl_start(struct nuvo_space_vol *space);

/**
 * \brief Stop managing parcels on the volume.
 *
 * Tells the thread to stop managing parcel on the volume
 * and waits for in progress operations to drain before
 * returning.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_manage_parcels_stop(struct nuvo_space_vol *space);

/**
 * \brief Suggest space management might be able to allocate a parcel.
 *
 * This nudges the space management that for some reason
 * it might be able to allocate a parcel if one was needed.
 * In particular, alloc_parcels calls this when a target_parcel
 * has changed.
 *
 * This is not strictly needed, just a friendly heads up.
 *
 * \param space The nuvo_space_vol.
 * \param data_class The class we might be able to get parcels in.
 */
void nuvo_space_vol_manage_parcels_suggest(struct nuvo_space_vol *space, uint8_t data_class);

/**
 * \brief Start managing GC on the volume
 *
 * This starts GC on a volume.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_manage_gc_start(struct nuvo_space_vol *space);

/**
 * \brief Stop managing GC on the volume
 *
 * This stops GC on a volume. Waits for in-progress gc to drain.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_manage_gc_stop(struct nuvo_space_vol *space);

/**
 * \brief Stop managing MFL on the volume
 *
 * This stops MFL on a volume. Waits for in-progress MFL to drain.
 *
 * \param space The nuvo_space_vol.
 */

void nuvo_space_vol_manage_mfl_stop(struct nuvo_space_vol *space);

/**
 * \brief Start managing CPs on the volume
 *
 * This starts CPs on a volume.  The space thread may
 * self-initiate CPs or start them based on outside requests.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_manage_cps_start(struct nuvo_space_vol *space);

/**
 * \brief Stop managing CPs on the volume
 *
 * This stop CPs on a volume.  This will wait for an
 * in-progress CP to complete.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_vol_manage_cps_stop(struct nuvo_space_vol *space);

/**
 * \brief Trigger a CP on the volume.
 *
 * This triggers a CP on the volume.  It does not wait
 * for it to complete.
 *
 * \param space The nuvo_space_vol.
 */
void nuvo_space_trigger_cp(struct nuvo_space_vol *space);

/**
 * How desperate callers to get segments are.
 *
 * NUVO_SPACE_SEGMENT_DEFINITELY_AVOID indicates the caller
 * would rather get back no segment than one on the list of
 * devices to avoid.
 *
 * NUVO_SPACE_SEGMENT_TRY_AVOID indicates the caller would
 * rather get a segment on a device to avoid to getting no segment.
 *
 * This is an enum rather than boolean, because I expect
 * more values (I don't care if it is the wrong type) later.
 */
enum nuvo_space_urgency
{
    NUVO_SPACE_SEGMENT_DEFINITELY_AVOID,
    NUVO_SPACE_SEGMENT_TRY_AVOID
};

/**
 * Notify the space thread it needs to supply segments somehow, someway.
 *
 * \param space The space structure of the volume.
 * \param data_class The data class we need a parcel on.
 */
void nuvo_space_vol_need_empty_segments(struct nuvo_space_vol *space, uint8_t data_class);

/**
 * \brief Get a segment from the free list.
 *
 * This tries to get a segment off the free list for the
 * class.  It will not return a segment that is in the list
 * of \p num_avoid segments to avoid, \p avoid_dev.
 *
 * \param space The space management structure.
 * \param data_class The data class of segment needed.
 * \param data_subclass The subclass type of segment needed.
 * \param num_avoid The number of devices to avoid.
 * \param avoid_dev The list of devices to avoid.
 * \param urgency How flexible or desperate the caller is for a segment.
 * \returns segment for use by logger
 * \retval NULL No segment available that does not conflict.
 */
struct nuvo_segment *nuvo_space_vol_segment_get(struct  nuvo_space_vol *space,
                                                uint8_t                 data_class,
                                                uint8_t                 data_subclass,
                                                unsigned                num_avoid,
                                                uint_fast32_t          *avoid_dev,
                                                enum nuvo_space_urgency urgency);

/**
 * \brief Get a nuvo_segment for a log segment encountered during replay.
 *
 * This is for log segments not contained in the manifest, but forked to
 * from those or later segments.  For those, the logger
 * calls this, which returns a segment structure pointer via
 * \p segment.  This fills in the segment and does the customary
 * opening of the parcel.
 *
 * \param space The space structure.
 * \param parcel_index The parcel holding the segment.
 * \param block_offset The block offset of the start of the segment.
 * \param segment The pointer to return the pointer to the alloced segment.
 * \returns 0 on success, negative on failure.
 * \retval -NUVO_E_OUT_OF_SEGMENT_STRUCTS Ran out of structures.
 * \retval whatever parcel router returns on failure to open.
 */
nuvo_return_t nuvo_space_vol_segment_log_replay_get(struct nuvo_space_vol *space,
                                                    uint32_t               parcel_index,
                                                    uint32_t               block_offset,
                                                    struct nuvo_segment  **segment);

/**
 * \brief Return a segment to space, and thence to the manifest.
 *
 * This is called when the logger (or garbage collecting) is
 * done with a segment.  If the caller has not changed the
 * segment it should call with set_age false.  If it has changed
 * the segment it should set a non-zero age.
 *
 * \param space The space structure.
 * \param seg The segment structure.
 * \param set_age Whether or not to set the age.
 * \param age The age to set, if set_age is set.
 */
void nuvo_space_vol_segment_done(struct nuvo_space_vol          *space,
                                 struct nuvo_segment            *seg,
                                 enum nuvo_mfst_segment_reason_t reason);

/**
 * \brief Get a targeted segment to gc for testing.
 *
 * \param space The space structure.
 * \param parcel_index The parcel holding the segment.
 * \param segment_index The segment index within the parcel.
 * \returns 0 gc successfully started.
 * \returns negative - nope.
 */
nuvo_return_t nuvo_space_vol_gc_seg_debug(struct nuvo_space_vol *space,
                                          uint32_t               parcel_index,
                                          uint32_t               segment_index,
                                          bool                   no_cp);

/**
 * \brief Read a digest for debug purposes
 *
 * Try to read a digest. Can fail because segment is not valid,
 * because the io failed, because the segment digest was invalid.
 * Will clarify and extend error codes as needed.
 *
 * \param space The space structure.
 * \param parcel_index The parcel holding the segment.
 * \param segment_index The segment index within the parcel.
 * \param digest The digest to fill.
 * \returns 0 or an error.
 */
nuvo_return_t nuvo_space_read_digest_debug(struct nuvo_space_vol      *space,
                                           uint32_t                    parcel_index,
                                           uint32_t                    segment_index,
                                           struct nuvo_segment_digest *digest);

void nuvo_space_write_permission(struct nuvo_space_vol *space);

void nuvo_space_write_permit(struct nuvo_space_vol *space,
                             bool                   allow);

/**
 * \brief work the GC state machines.
 *
 * This takes any gc operations that need to have work done (messages dispatched)
 * and moves them along in the state machine.
 */
unsigned nuvo_space_gc_state_work();

/**
 * \brief Assert that no cp work is needed.
 *
 * This exists because the state is internal and I want ot have hard-core asserts
 * in the unit tests.
 */
void nuvo_space_assert_no_cp_work_needed();

/**
 * \brief Peek onto the list of vols needing gc structs for testing purposes
 *
 * The list is in a local structure, so the test cannot look directly.
 * \returns The nuvo_space_vol at the front of the list.
 */
struct nuvo_space_vol *nuvo_gc_peek_vol_needs_gc_struct();

/**
 * \brief Push MFL work item for a new lun which got deleted
 *  If work is in progress for another lun, this lun would be picked
 *  up for after the current lun is complete
 *
 * \param space space_vol struct for the vol
 */
void nuvo_vol_new_needs_work_mfl(struct nuvo_space_vol *space);

/**
 * \brief Push the space vol for MFL work to the space thread
 * To be used by a LUN whose MFL work is known to be already in progress
 * New luns are to use the api above (nuvo_vol_new_needs_work_mfl)
 *
 * \param space space_vol struct for the vol
 */
void nuvo_vol_needs_work_mfl(struct nuvo_space_vol *space);

/**
 * \brief Set whether we are freezing the fs.
 *
 * When set to true, this allows us to eat more deeply into the
 * reserve to avoid running out of space while doing the fs freeze flush.
 */
nuvo_return_t nuvo_space_snap_frozen_set(struct nuvo_space_vol *space_vol, bool frozen);

/**
 * \brief Get whether a volume is allowing freeze to eat into reserve.
 */
bool nuvo_space_snap_frozen_get(struct nuvo_space_vol *space_vol);
