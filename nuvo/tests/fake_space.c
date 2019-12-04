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
#include "map_diff.h"

struct
{
    nuvo_mutex_t         space_mutex;                                /** Have this lock while stopping or changing the needs_work lists. */
    nuvo_cond_t          space_cond;                                 /** Waiting for something to do.                               */
    struct nuvo_dlist    vol_needs_work_mfl;                         /** Set of volumes that need map free lun work */
    bool                 halting;                                    /** Halting all work.          */
} nuvo_space_ctl;

static struct nuvo_space_vol *get_vol_needs_mfl()
{
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    struct nuvo_space_vol *space_vol = nuvo_dlist_remove_head_object(&nuvo_space_ctl.vol_needs_work_mfl, struct nuvo_space_vol, mfl_node);
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);

    return (space_vol);
}
void nuvo_vol_needs_work_mfl(struct nuvo_space_vol *space)
{
    nuvo_vol_new_needs_work_mfl(space);
}

void nuvo_vol_new_needs_work_mfl(struct nuvo_space_vol *space)
{
    NUVO_ASSERT_MUTEX_HELD(&space->space_vol_mutex);
    nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
    // if an existing delete is in progress for this volume, return
    // the map free lun done will walk the lun list and trigger the next map free lun
    if (!nuvo_dlnode_on_list(&space->mfl_node))
    {
        nuvo_dlist_insert_tail(&nuvo_space_ctl.vol_needs_work_mfl, &space->mfl_node);
        NUVO_LOG(space, 40, "Volume " NUVO_LOG_UUID_FMT " needs mfl work" , 
            NUVO_LOG_UUID(nuvo_containing_object(space, struct nuvo_vol, log_volume.space)->vs_uuid));
        nuvo_cond_broadcast(&nuvo_space_ctl.space_cond);
    }
    nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
}
void nuvo_fake_space_mfl_work()
{
    struct nuvo_space_vol *space_vol;
    while (NULL != (space_vol = get_vol_needs_mfl()))
    {
        nuvo_mutex_lock(&space_vol->space_vol_mutex);
        struct nuvo_vol * vol = nuvo_containing_object(space_vol, struct nuvo_vol, log_volume.space);
        struct nuvo_map_free_lun_request *mfl_req = &space_vol->mfl_req;

        NUVO_LOG(space, 25 , "There is mfl work to do, mfl_state:%d lun:%p "
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
            lun->mfl_state = 1;
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

static inline bool fake_space_work_pending()
{
    return (NULL != nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_mfl));
}

void *nuvo_fake_space_thread(void *arg)
{
    (void)arg;

    NUVO_LOG(space, 40, "fake space thread begin");

    while (1)
    {
        nuvo_fake_space_mfl_work();

        nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
        if (nuvo_space_ctl.halting)
        {
            nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
            break;
        }
        if (!fake_space_work_pending())   // TODO - might be in GC HALTING (or PARCEL)
        {
            nuvo_cond_wait(&nuvo_space_ctl.space_cond, &nuvo_space_ctl.space_mutex);
        }
        nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
    }

    NUVO_LOG(space, 40, "fake space thread exit");

    pthread_exit(0);
    return (NULL);
}

static pthread_t fake_space_thread_id;
nuvo_return_t nuvo_space_init()
{
    nuvo_mutex_init(&nuvo_space_ctl.space_mutex);
    nuvo_cond_init(&nuvo_space_ctl.space_cond);
    nuvo_dlist_init(&nuvo_space_ctl.vol_needs_work_mfl);
    nuvo_space_ctl.halting = false;

    nuvo_return_t rc = -pthread_create(&fake_space_thread_id, NULL, nuvo_fake_space_thread, NULL);
    NUVO_ASSERT(!rc);
    return rc;
}

void nuvo_space_halt()
{
   nuvo_mutex_lock(&nuvo_space_ctl.space_mutex);
   NUVO_LOG(space, 10, "Halting space");
   NUVO_ASSERT(NULL == nuvo_dlist_get_head(&nuvo_space_ctl.vol_needs_work_mfl));
   nuvo_space_ctl.halting = true;
   nuvo_mutex_unlock(&nuvo_space_ctl.space_mutex);
   nuvo_cond_signal(&nuvo_space_ctl.space_cond); 
   pthread_join(fake_space_thread_id, NULL);
}
nuvo_return_t nuvo_space_vol_init(struct nuvo_space_vol * space_vol)
{
    nuvo_return_t rc = nuvo_mutex_init(&space_vol->space_vol_mutex);
    NUVO_ASSERT(!rc);
    nuvo_dlnode_init(&space_vol->mfl_node);
    nuvo_mutex_init(&space_vol->mfl_req.mutex);
    space_vol->mfl_req.state = MFL_NONE;
    return rc;
}
