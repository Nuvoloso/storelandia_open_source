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
#include <string.h>

#include "lun.h"
#include "nuvo_vol_series.h"
#include "log_volume.h"

nuvo_return_t nuvo_log_vol_create_lun_int(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    struct nuvo_lun *lun = NULL;
    nuvo_return_t    ret = 0;
    // allocate the new lun
    nuvo_mutex_t sync_signal;

    ret = nuvo_mutex_init(&sync_signal);
    NUVO_ASSERT(!ret);

    nuvo_rwlock_wrlock(&vol->rw_lock);

    lun = nuvo_map_create_snap(vol, lun_uuid);

    if (!lun)
    {
        ret = -NUVO_ENOMEM;
        goto _out;
    }

    // log the snapshot create request
    struct nuvo_log_request log_req;
    log_req.status = 0;

    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_CREATE_SNAP;
    log_req.atomic = true;
    log_req.tag.ptr = &sync_signal;
    log_req.vs_ptr = vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    uuid_copy(log_req.pit_uuid, lun_uuid);
    log_req.pit_id = lun->snap_id;

    nuvo_mutex_lock(&sync_signal);
    log_req.callback = nuvo_log_vol_log_cb;
    nuvo_log_submit(&log_req);

    nuvo_mutex_lock(&sync_signal);
    NUVO_ASSERT(!log_req.status);
    nuvo_log_ack_sno(&log_req);
    nuvo_mutex_unlock(&sync_signal);

_out:
    nuvo_mutex_destroy(&sync_signal);

    nuvo_rwlock_unlock(&vol->rw_lock);
    return (ret);
}

//TODO CUM-1197 : mock function, free the blocks is pending
// currently deallocates the lun
nuvo_return_t nuvo_log_vol_delete_lun_int(struct nuvo_lun *lun)
{
    struct nuvo_vol *vol = lun->vol;

    NUVO_PRINT("delete lun int lun(%d) lun_state(%d) -> DELETING", lun->snap_id, lun->lun_state);

    nuvo_mutex_lock(&lun->mutex);
    nuvo_mutex_lock(&vol->log_volume.space.space_vol_mutex);
    nuvo_return_t rc = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_DELETING, NUVO_LUN_EXPORT_UNEXPORTED);
    NUVO_ASSERT(rc == 0);
    memset(lun->lun_uuid, 0, sizeof(*lun->lun_uuid));

    // add a work to the space thread indicating that there is possible mfl work.
    // and wake up the space thread.

    nuvo_vol_new_needs_work_mfl(&vol->log_volume.space);

    nuvo_mutex_unlock(&vol->log_volume.space.space_vol_mutex);
    nuvo_mutex_unlock(&lun->mutex);

    return (0);
}
