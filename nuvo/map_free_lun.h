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
#include "lun.h"
#include "map.h"

#define NUVO_MFL_BATCH_SIZE    (16)

/* state transition for the mfl task:
 *
 * start in HALTED, we dont want mfl to be running during replay
 * HALTED -> NONE after replay. We are ready for new work items in NONE
 * NONE -> PROGRESS when a new work item is accepted and work begins
 * PROGRESS-> NONE if this luns work item is done
 * PROGRESS -> PAUSED if there is a pause requested on the work.
 * PAUSED -> PROGRESS on resume
 * PROGRESS -> HALTING -> HALTED on halt
 *
 * note : We earlier used HALTING -> NONE. But, since NONE -> PROGRESS is a valid transition,
 * the task could go back back to PROGRESS after HALTING, thus causing resoure busy issues, during shutdown
 * So added a HALTED state
 */

enum mfl_task_state_t
{
    MFL_NONE = 0,    // not running, but ready to accept new luns
    MFL_IN_PROGRESS, // in progress
    MFL_PAUSED,      // in progress but paused for throttling.
    MFL_HALTING,     // halting in progress
    MFL_HALTED       // halt complete, no more new work possible.
};

/* the state of an inprogress task */
enum mfl_work_state_t
{
    MFL_WORK_NONE,        // start state
    MFL_WORK_LOAD_MAPS,   // load the next set of maps
    MFL_WORK_FREE_ENTRIES // punch holes in the loaded maps
};

#define NUVO_MAP_MFL_DIRTY_CNT_THRESHOLD    (1024) // number of maps that can be dirtied before mfl is paused.
                                                   // mfl will get kicked at the next of next cp

struct nuvo_map_free_lun_request {
    enum mfl_task_state_t   state;
    enum mfl_work_state_t   work_state;
    nuvo_mutex_t            mutex;
    nuvo_cond_t             cond;        // wait on this for halting
    uint64_t                offset;      // map load offset
    uint64_t                free_offset; // map free work done offset
    struct nuvo_lun        *lun;
    struct nuvo_map_request map_reqs[NUVO_MFL_BATCH_SIZE];
    struct nuvo_parallel_op par_ops;                                   /** The parallel map ops for faulting in. */
    int                     map_load_cnt;
    int                     map_mfl_cnt;
    int                     dirty_cnt;
};

#define NUVO_MFL_HALTED(mfl_req)    (((mfl_req)->state == MFL_HALTED))

/*
 * \brief init the mfl machinery, started in PAUSED.
 * \param mfl_req
 */
void nuvo_map_mfl_init(struct nuvo_map_free_lun_request *mfl_req);

/*
 * \brief start the mfl machinery, called after replay
 * \param mfl_req
 */
void nuvo_map_mfl_start(struct nuvo_map_free_lun_request *mfl_req);

/*
 * \brief init the mfl req
 * \param mfl_req
 */
void nuvo_map_mfl_req_init(struct nuvo_map_free_lun_request *mfl_req, struct nuvo_lun *lun);

/*
 * \brief the engine function for mfl, do the hole punching, load maps etc
 * \param mfl_req
 */
void nuvo_map_mfl_work(struct nuvo_map_free_lun_request *req);

/*
 * \brief fault in the mfl maps
 * \param mfl_req
 */
void nuvo_map_mfl_load_maps(struct nuvo_map_free_lun_request *mfl_req);

/*
 * \brief punch holes in the loaded maps
 * \param mfl req
 */
void nuvo_map_mfl_free_entries(struct nuvo_map_free_lun_request *mfl_req);

/*
 * \brief peek to see mfl is paused
 * \param mfl_req
 */
bool nuvo_map_mfl_is_paused(struct nuvo_map_free_lun_request *mfl_req);

/*
 * \brief check to see whether the conditions of mfl pausing are met.
 * \param mfl_req
 */
bool nuvo_map_mfl_need_pausing(struct nuvo_map_free_lun_request *mfl_req);

/*
 * \brief pause mfl, will restart at the end of next CP.
 * \param mfl_req
 */
void nuvo_map_mfl_pause(struct nuvo_map_free_lun_request *mfl_req); //

/*
 * \brief restart a paused MFL task
 * \param mfl_req
 */
void nuvo_map_mfl_kick(struct nuvo_map_free_lun_request *mfl_req); //
void nuvo_map_mfl_inc_dirty_cnt(struct nuvo_map_free_lun_request *mfl_req);

bool nuvo_map_mfl_is_halting(struct nuvo_map_free_lun_request *mfl_req);      // if mfl work halting in progress
bool nuvo_map_mfl_is_halted(struct nuvo_map_free_lun_request *mfl_req);       // if mfl work is halted
void nuvo_map_mfl_trigger_halting(struct nuvo_map_free_lun_request *mfl_req); //intitate halting proceedings
void nuvo_map_mfl_halt(struct nuvo_map_free_lun_request *mfl_req);            // do internal halt
void nuvo_map_mfl_wait_for_halt(struct nuvo_map_free_lun_request *mfl_req);   // wait for halting to be done
void nuvo_map_mfl_set_dirty_cnt_threshold(int threshold);                     //set the mfl dirty cnt threshold which throttles mfl
void nuvo_map_mfl_stop(struct nuvo_map_free_lun_request *mfl_req);            // close vol work for mfl
