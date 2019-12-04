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

#include "log_volume.h"

#include <uuid/uuid.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "fault_inject.h"
#include "nuvo.h"
#include "nuvo_fuse.h"
#include "nuvo_vol_series.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "map.h"
#include "nuvo_range_lock.h"
#include "cache.h"
#include "device_type.h"
#include "nuvo_api.h"
#include <version_nuvo.h>

/**
 * @file log_volume.c
 * @brief Routines around log volumes
 */

/**
 * \brief Initialize a nuvo_vol for use.
 *
 * \param nvs_p The pointer to the structure.
 */
void nuvo_log_vol_init(struct nuvo_vol *nvs_p)
{
    memset(nvs_p, 0, sizeof(*nvs_p));
}

/**
 * \brief Does the tail end of open or create.
 *
 * This is to be called after a manifest is successfully loaded
 * (either by creation or by reading from disk), and moves the
 * volume to the OPEN state.
 *
 * \param vol The volume that we are opening.
 */
nuvo_return_t open_after_mfst(struct nuvo_vol *vol)
{
    nuvo_return_t ret;

    ret = nuvo_mutex_init(&vol->mutex);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Init vol mutex failed.");
        return (ret);
    }
    ret = nuvo_rwlock_init(&vol->rw_lock);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Init vol rw_lock failed.");
        goto destroy_mutex;
    }
    ret = nuvo_mutex_init(&vol->state_mutex);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Init vol state mutex failed.");
        goto destroy_rw_lock;
    }
    nuvo_map_vol_state_init(&vol->log_volume.map_state, vol);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Initializing map state failed.");
        goto destroy_state_mutex;
    }
    ret = nuvo_space_vol_init(&vol->log_volume.space);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Initializing space management on volume failed.");
        goto destroy_map_state;
    }

    struct nuvo_log_replay_request replay_req;
    replay_req.vol = vol;
    replay_req.segment_count = NUVO_MFST_NUM_LOG_STARTS;
    nuvo_mfst_log_starts_get(&vol->log_volume.mfst,
                             &replay_req.sequence_no,
                             &replay_req.segment_cnt_sequence_no,
                             &replay_req.segment_count,
                             replay_req.replay_segments);
    NUVO_ASSERT(replay_req.segment_cnt_sequence_no >= replay_req.sequence_no);
    ret = nuvo_log_init(vol);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Initializing logger failed.");
        goto destroy_space;
    }

    // mem init all the luns resources */
    ret = nuvo_multi_lun_init(vol);
    NUVO_ASSERT(0 == ret);
    // load the snap luns from the manifest
    // and init the luns
    nuvo_mfst_get_luns(vol, vol->log_volume.lun_list, vol->log_volume.mfst.header.num_used_luns);
    // open all the luns */
    ret = nuvo_map_multi_luns_open(vol);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Opening maps failed.");
        goto destroy_luns;
    }

    ret = nuvo_mfst_sb_update_replay_count(&vol->log_volume.mfst, &vol->log_volume.sb, NUVO_SB_REPLAY_COUNT_INCR);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Incrementing superblock replay count failed");
        goto close_map_luns;
    }

    ret = nuvo_log_sync_replay(&replay_req);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Volume replay failed.");
        goto close_map_luns;
    }

    ret = nuvo_mfst_sb_update_replay_count(&vol->log_volume.mfst, &vol->log_volume.sb, NUVO_SB_REPLAY_COUNT_ZERO);
    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Resetting superblock replay count failed");
        goto close_map_luns;
    }

    NUVO_ASSERT(vol->type == NUVO_VOL_LOG_VOL);

    nuvo_mutex_lock(&vol_table.mutex);
    vol->vol_state = NUVO_VOL_STATE_HEALTHY;
    nuvo_mutex_unlock(&vol_table.mutex);

    nuvo_space_vol_manage_cps_start(&vol->log_volume.space);
    //lets kick off mfl before gc so that we can possibly change
    // some luns to DELETED
    nuvo_space_vol_manage_mfl_start(&vol->log_volume.space);
    nuvo_space_vol_manage_gc_start(&vol->log_volume.space);
    nuvo_space_vol_manage_parcels_start(&vol->log_volume.space);

    return (0);

close_map_luns:
    nuvo_map_luns_close(vol);
destroy_luns:
    nuvo_luns_destroy(vol);
    nuvo_log_shutdown(vol);
destroy_space:
    nuvo_space_vol_destroy(&vol->log_volume.space);
destroy_map_state:
    nuvo_map_vol_state_destroy(&vol->log_volume.map_state);
destroy_state_mutex:
    nuvo_mutex_destroy(&vol->state_mutex);
destroy_rw_lock:
    nuvo_rwlock_destroy(&vol->rw_lock);
destroy_mutex:
    nuvo_mutex_destroy(&vol->mutex);
    return (ret);
}

/* mock delete pit to keep FT happy */
nuvo_return_t nuvo_log_vol_delete_pit(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    struct nuvo_lun *lun;
    nuvo_return_t    ret;
    nuvo_mutex_t     sync_signal;

    if (!(lun = nuvo_get_lun_by_uuid(vol, lun_uuid, true)))
    {
        return (-NUVO_ENOENT);
    }

    nuvo_mutex_lock(&lun->mutex);
    ret = 0;
    if (lun->lun_state != NUVO_LUN_STATE_VALID)
    {
        ret = -NUVO_ENOENT;
    }
    else if (vol->type == NUVO_VOL_LOG_VOL && nuvo_space_snap_frozen_get(&vol->log_volume.space))
    {
        ret = -NUVO_EBUSY;
    }
    else if (lun->export_state != NUVO_LUN_EXPORT_UNEXPORTED)
    {
        ret = -NUVO_E_LUN_EXPORTED;
    }
    else
    {
        ret = nuvo_mutex_init(&sync_signal);
    }
    if (ret != 0)
    {
        nuvo_lun_unpin(lun);
        nuvo_mutex_unlock(&lun->mutex);
        return (ret);
    }

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DELETE_SNAP;
    log_req.atomic = true;
    log_req.tag.ptr = &sync_signal;
    log_req.vs_ptr = vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    uuid_copy(log_req.pit_uuid, lun->lun_uuid);
    log_req.pit_id = lun->snap_id;
    nuvo_mutex_unlock(&lun->mutex);

    nuvo_mutex_lock(&sync_signal);
    log_req.callback = nuvo_log_vol_log_cb;
    nuvo_log_submit(&log_req);

    // wait for logger completion
    nuvo_mutex_lock(&sync_signal);

    ret = nuvo_log_vol_delete_lun_int(lun);
    NUVO_ASSERT(ret == 0);

    nuvo_log_ack_sno(&log_req);

    nuvo_mutex_lock(&lun->mutex);
    nuvo_lun_unpin(lun);
    nuvo_mutex_unlock(&lun->mutex);

    nuvo_mutex_destroy(&sync_signal);

    return (ret);
}

//documented in header
nuvo_return_t nuvo_log_vol_create_pit(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    //TODO implement real pause io
    if (vol->type != NUVO_VOL_LOG_VOL || !nuvo_space_snap_frozen_get(&vol->log_volume.space))
    {
        return (-NUVO_EBUSY);
    }
    if (nuvo_get_lun_by_uuid(vol, lun_uuid, false))
    {
        return (-NUVO_EEXIST);
    }

    return (nuvo_log_vol_create_lun_int(vol, lun_uuid));
}

nuvo_return_t nuvo_log_vol_create_work(struct nuvo_vol *nvs_p, const uuid_t device_uuid, uint8_t root_device_class,
                                       uuid_t root_parcel_uuid, uint64_t size)
{
    nuvo_return_t ret = 0;

    NUVO_LOG(api, 0, "Vol create " NUVO_LOG_UUID_FMT " (%u - %u)",
             NUVO_LOG_UUID(nvs_p->vs_uuid), pthread_self(), nuvo_vol_index_lookup(nvs_p));

    NUVO_ASSERT(nvs_p->type == NUVO_VOL_LOG_VOL);
    NUVO_ASSERT(nvs_p->op_state == NUVO_VOL_OP_STATE_UNINITIALIZED);
    nvs_p->vol_state = NUVO_VOL_STATE_UNINITIALIZED;

    // initialize tracking structures for optional cache allocation
    ret = nuvo_cache_vol_init(nvs_p);
    if (ret != 0)
    {
        goto free_volume;
    }

    uint64_t           device_size, parcel_size;
    enum nuvo_dev_type root_device_type;
    ret = nuvo_pr_sync_dev_info(device_uuid, &device_size, &parcel_size, &root_device_type);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Get device info failed.");
        ret = -NUVO_E_NO_DEVICE;
        goto free_cache;
    }

    ret = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, nvs_p->vs_uuid);
    if (ret != 0)
    {
        // TODO better return
        NUVO_ERROR_PRINT("Allocating a root parcel failed.");
        goto free_cache;
    }
    uint_fast32_t parcel_desc;
    ret = nuvo_pr_sync_parcel_open(&parcel_desc, root_parcel_uuid, device_uuid, nvs_p->vs_uuid);
    if (ret != 0)
    {
        // TODO better return
        NUVO_ERROR_PRINT("Opening root parcel failed.");
        goto free_root_parcel;
    }

    ret = nuvo_mfst_sb_init(&nvs_p->log_volume.sb,
                            &nvs_p->log_volume.mfst,
                            nvs_p->vs_uuid,
                            device_uuid,
                            root_parcel_uuid,
                            parcel_desc,
                            parcel_size / NUVO_BLOCK_SIZE,
                            root_device_class,
                            root_device_type,
                            NUVO_SEGMENT_MIN_SIZE_BYTES,  // TODO - tunable first segment size
                            16,                           // TODO - tunable blocks reserved for tables.
                            100,
                            size);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Creating manifest failed.");
        // TODO complain if fail.
        (void)nuvo_pr_sync_parcel_close(parcel_desc);
        goto free_root_parcel;
    }
    ret = nuvo_mfst_sync_write(&nvs_p->log_volume.mfst, &nvs_p->log_volume.sb, 1, 1);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Writing manifest failed.");
        goto destroy_manifest;
    }
    ret = nuvo_sb_sync_write(&nvs_p->log_volume.sb, parcel_desc);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Writing superblock failed.");
        goto destroy_manifest;
    }
    // We' starting a fresh volume, so enable segment count updates.
    nuvo_mfst_seg_counts_start(&nvs_p->log_volume.mfst);

    ret = open_after_mfst(nvs_p);

    if (ret == 0)
    {
        nuvo_mutex_lock(&vol_table.mutex);
        nvs_p->op_state = NUVO_VOL_OP_STATE_INITIALIZED;
        nuvo_mutex_unlock(&vol_table.mutex);
        return (0);
    }

destroy_manifest:
    nuvo_mfst_close(&nvs_p->log_volume.mfst);
free_root_parcel:
    // TODO complain if fail.
    (void)nuvo_pr_sync_parcel_free(root_parcel_uuid, device_uuid, nvs_p->vs_uuid);
free_cache:
    nuvo_cache_vol_destroy(nvs_p);
free_volume:
    // currently implied since we "allocate" by changing the type from NUVO_VOL_FREE
    return (ret);
}

/**
 * \brief Alloc parcels to a log volume - only sets target.
 */
nuvo_return_t nuvo_log_vol_alloc_parcels(struct nuvo_vol *nvs_p, const uuid_t dev_uuid, uint8_t device_class, uint64_t num)
{
    nuvo_return_t ret = 0;

    NUVO_ASSERT(nvs_p->type == NUVO_VOL_LOG_VOL);

    // Make sure we have the device in our manifest.
    ret = nuvo_mfst_device_parcel_target(&nvs_p->log_volume.mfst, dev_uuid, num);
    if (ret == -NUVO_ENOENT)
    {
        uint64_t           device_size, parcel_size;
        enum nuvo_dev_type device_type;
        ret = nuvo_pr_sync_dev_info(dev_uuid, &device_size, &parcel_size, &device_type);
        if (ret < 0)
        {
            NUVO_ERROR_PRINT("Get device info failed.");
            return (ret);
        }
        ret = nuvo_mfst_insert_device(&nvs_p->log_volume.mfst, dev_uuid, device_class, device_type, parcel_size / NUVO_BLOCK_SIZE);
        if (ret < 0)
        {
            NUVO_ERROR_PRINT("Adding device to manifest failed.");
            return (ret);
        }
        ret = nuvo_mfst_device_parcel_target(&nvs_p->log_volume.mfst, dev_uuid, num);
        if (ret < 0)
        {
            NUVO_ERROR_PRINT("Device not in manifest.");
            return (ret);
        }
    }
    if (ret == 0)
    {
        nuvo_space_vol_manage_parcels_suggest(&nvs_p->log_volume.space, device_class);
        nuvo_space_trigger_cp(&nvs_p->log_volume.space);
    }
    return (ret);
}

/**
 * \brief Load manifest for a volume
 *
 * This is used when opening and destroying a volume. Before this function is called,
 * the API dispatcher thread already allocated the volume structure in the volume table.
 */
nuvo_return_t open_manifest(struct nuvo_vol *vol,
                            const uuid_t     device_uuid,
                            const uuid_t     root_parcel_uuid,
                            bool             open_parcels)
{
    nuvo_return_t rc;

    NUVO_LOG(api, 0, "Opening manifest for " NUVO_LOG_UUID_FMT " (%u - %u)",
             NUVO_LOG_UUID(vol->vs_uuid), pthread_self(), nuvo_vol_index_lookup(vol));

    NUVO_ASSERT(vol->type == NUVO_VOL_LOG_VOL);
    NUVO_ASSERT(vol->op_state == NUVO_VOL_OP_STATE_UNINITIALIZED);

    // initialize tracking structures for optional cache allocation
    rc = nuvo_cache_vol_init(vol);
    if (rc != 0)
    {
        goto free_volume;
    }

    uint_fast32_t parcel_desc;
    rc = nuvo_pr_sync_parcel_open(&parcel_desc, root_parcel_uuid, device_uuid, vol->vs_uuid);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Opening root parcel failed.");
        goto free_cache;
    }
    rc = nuvo_sb_sync_read(&vol->log_volume.sb, parcel_desc);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Unable to read superblock.");
        // TODO complain if fail.
        (void)nuvo_pr_sync_parcel_close(parcel_desc);
        goto free_cache;
    }
    rc = nuvo_mfst_sync_read(&vol->log_volume.mfst,
                             &vol->log_volume.sb,
                             parcel_desc,
                             open_parcels);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Unable to read manifest.");
        goto destroy_manifest;
    }

    vol->cmd_queue = &vol_table.queue[nuvo_vol_index_lookup(vol)];

    return (0);

destroy_manifest:
    nuvo_mfst_close(&vol->log_volume.mfst);
free_cache:
    nuvo_cache_vol_destroy(vol);
free_volume:
    // currently implied since we "allocate" by changing the type from NUVO_VOL_FREE
    return (rc);
}

/**
 * \brief Check if there's been excessive attempts to recover the volume without success.
 *
 * If the replay count is > 0 it means the previous volume replay failed.
 * On restart, if the replay count exceeds NUVO_MAX_REPLAY_ATTEMPTS
 * the volume will not be recovered and the volume will remain offline.
 * If the software's git commit hash has changed recovery is attempted
 * regardless of the current replay count.
 *
 * \param vol Pointer to the volume
 * \return true if NUVO_MAX_REPLAY_ATTEMPTS is exceeded and git commit hash is the same, otherwise false.
 */
bool log_vol_replays_exceeded(struct nuvo_vol *vol)
{
    NUVO_ASSERT(vol != NULL);
    bool replays_exceeded = false;
    struct nuvo_sb_superblock *sb = &vol->log_volume.sb;

    if (sb->git_hash == nuvo_short_git_hash())
    {
        if (sb->replay_count >= NUVO_MAX_REPLAY_ATTEMPTS)
        {
            NUVO_ERROR_PRINT("Volume "NUVO_LOG_UUID_FMT ". The maximum recovery attempt count has been exceeded. %u of %u.",
                             NUVO_LOG_UUID(vol->vs_uuid), sb->replay_count, NUVO_MAX_REPLAY_ATTEMPTS);
            replays_exceeded = true;
        }
        else if (sb->replay_count > 0)
        {
            NUVO_ERROR_PRINT("Volume "NUVO_LOG_UUID_FMT ". Previous recovery attempt failed. Retry %u of %u",
                             NUVO_LOG_UUID(vol->vs_uuid), sb->replay_count, NUVO_MAX_REPLAY_ATTEMPTS - 1);
        }
    }
    return (replays_exceeded);
}

// documented in header
nuvo_return_t nuvo_log_vol_open_work(struct nuvo_vol *nvs_p,
                                     const uuid_t     device_uuid,
                                     const uuid_t     root_parcel_uuid)
{
    nuvo_return_t rc = open_manifest(nvs_p, device_uuid, root_parcel_uuid, true);

    if (rc < 0)
    {
        return (rc);
    }

    if (log_vol_replays_exceeded(nvs_p))
    {
        NUVO_ERROR_PRINT("volume "NUVO_LOG_UUID_FMT "could not be opened after multiple recovery attempts. volume is offline",
                         NUVO_LOG_UUID(nvs_p->vs_uuid));
        rc = -NUVO_E_REPLAYS_EXCEEDED;
    }
    else
    {
        rc = open_after_mfst(nvs_p);
    }

    if (rc == 0)
    {
        nuvo_mutex_lock(&vol_table.mutex);
        nvs_p->op_state = NUVO_VOL_OP_STATE_INITIALIZED;
        nuvo_mutex_unlock(&vol_table.mutex);
        return (0);
    }

    nuvo_mfst_close(&nvs_p->log_volume.mfst);

    return (rc);
}

void nuvo_vol_force_unexport_lun(struct nuvo_lun *lun)
{
    nuvo_return_t rc = nuvo_fuse_stop(lun);

    if (rc != 0)
    {
        // We're exiting, not much we can do.
        NUVO_ERROR_PRINT("Failed to force unexport lun.");
    }
}

void nuvo_vol_force_unexport_all(struct nuvo_vol *vol)
{
    nuvo_mutex_lock(&vol->mutex);
    NUVO_ASSERT(vol->shutdown_in_progress);
    if (!vol->shutdown_in_progress)
    {
        goto _out;
    }
    struct nuvo_lun *active_lun = &vol->log_volume.lun;

    if (NUVO_LUN_IS_EXPORTED(active_lun))
    {
        nuvo_return_t rc = nuvo_fuse_stop(active_lun);
        (void)rc;
        nuvo_mutex_lock(&active_lun->mutex);
        NUVO_ASSERT(active_lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED);
        nuvo_mutex_unlock(&active_lun->mutex);
    }
    uint_fast32_t lun_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);

    for (uint_fast32_t i = 1; i < lun_count; i++)
    {
        struct nuvo_lun *lun = &vol->log_volume.lun_list[i];
        if (lun->lun_state <= NUVO_LUN_STATE_FREE || lun->lun_state >= NUVO_LUN_STATE_DELETED)
        {
            continue;
        }
        if (NUVO_LUN_IS_EXPORTED(lun))
        {
            nuvo_return_t rc = nuvo_fuse_stop(lun);
            (void)rc;
            nuvo_mutex_lock(&lun->mutex);
            NUVO_ASSERT(lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED);
            nuvo_mutex_unlock(&lun->mutex);
        }
    }
    NUVO_ASSERT(vol->export_cnt == 0);
_out:
    nuvo_mutex_unlock(&vol->mutex);
    return;
}

/*SNAP_WORK close and destroy all luns */
nuvo_return_t nuvo_log_vol_close(struct nuvo_vol *nvs_p)
{
    nuvo_return_t ret = 0;

    nuvo_mutex_lock(&vol_table.mutex);

    NUVO_ASSERT(nvs_p->type == NUVO_VOL_LOG_VOL);
    NUVO_ASSERT(nvs_p->op_state == NUVO_VOL_OP_STATE_INITIALIZED);
    nvs_p->op_state = NUVO_VOL_OP_STATE_CLOSING;

    // Need to make sure we have no luns
    if (nvs_p->export_cnt)
    {
        if (nvs_p->shutdown_in_progress)
        {
            NUVO_ERROR_PRINT("Lun(s) still exported during shutdown, active lun export_state:%d export_cnt:%d vol uuid:"
                             NUVO_LOG_UUID_FMT,
                             nvs_p->log_volume.lun.export_state,
                             nvs_p->export_cnt,
                             NUVO_LOG_UUID(nvs_p->vs_uuid));
            nuvo_vol_force_unexport_all(nvs_p);
        }
        else
        {
            NUVO_ERROR_PRINT("Lun(s) still exported during close vol, active lun export_state:%d export_cnt:%d vol uuid:"
                             NUVO_LOG_UUID_FMT,
                             nvs_p->log_volume.lun.export_state,
                             nvs_p->export_cnt,
                             NUVO_LOG_UUID(nvs_p->vs_uuid));
            ret = -NUVO_E_LUN_EXPORTED;
            goto out;
        }
    }

    // Unlock volume table mutex before starting operations that may
    // trigger connection recovery in parcel router (CUM-2531).
    // Relock volume table mutex after these operations are completed.
    // During the time the volume table mutex is unlocked, node status
    // and list volumes may occur but will not attempt to pick up this
    // volume because the volume is not in initialized state.
    nuvo_mutex_unlock(&vol_table.mutex);

    nuvo_space_vol_stop_management(&nvs_p->log_volume.space);

    ret = nuvo_map_luns_close(nvs_p);
    if (ret != 0)
    {
        nuvo_mutex_lock(&vol_table.mutex);
        goto out;
    }

    nuvo_map_vol_state_destroy(&nvs_p->log_volume.map_state);

    nuvo_log_shutdown(nvs_p);
    nuvo_cache_vol_destroy(nvs_p);
    nuvo_space_vol_destroy(&nvs_p->log_volume.space);
    nuvo_mfst_close(&nvs_p->log_volume.mfst);

    // Done with operations that may trigger parcel router connection recovery.
    // Reacquire volume table mutex before destroying volume mutex.
    nuvo_mutex_lock(&vol_table.mutex);

    nuvo_rwlock_destroy(&nvs_p->rw_lock);
    nuvo_mutex_destroy(&nvs_p->mutex);
    nuvo_mutex_destroy(&nvs_p->state_mutex);
    nuvo_luns_destroy(nvs_p);

out:
    // If failed to close, set operational state back to stable as the volume
    // entry will not be removed from volume table.
    if (ret != 0)
    {
        nvs_p->op_state = NUVO_VOL_OP_STATE_INITIALIZED;
    }
    nuvo_mutex_unlock(&vol_table.mutex);
    return (ret);
}

nuvo_return_t nuvo_log_vol_get_manifest(struct nuvo_vol *vol, Nuvo__Manifest *msg, bool short_reply)
{
    return (nuvo_mfst_get_manifest(&vol->log_volume.mfst, msg, short_reply));
}

static struct test_fi_info vol_ops_fi_info;

struct test_fi_info *nuvo_vol_ops_test_fi()
{
    return (&vol_ops_fi_info);
}

// Documented in header
int nuvo_log_vol_destroy(struct nuvo_vol *nvs_p,
                         const uuid_t     root_device_uuid,
                         const uuid_t     root_parcel_uuid)
{
    nuvo_return_t rc;

    rc = nuvo_mutex_init(&nvs_p->state_mutex);
    if (rc < 0)
    {
        NUVO_ERROR_PRINT("Init vol state mutex failed for " NUVO_LOG_UUID_FMT " %d",
                         NUVO_LOG_UUID(nvs_p->vs_uuid), rc);
        goto out;
    }

    rc = open_manifest(nvs_p, root_device_uuid, root_parcel_uuid, false);
    if (rc < 0)
    {
        goto destroy_state_mutex;
    }
    // Loop through all parcels other than root, freeing them.
    uuid_t parcel_uuid;
    uuid_t device_uuid;
    while (0 < nuvo_mfst_find_highest_parcel_index(&nvs_p->log_volume.mfst, parcel_uuid, device_uuid))
    {
        rc = nuvo_pr_sync_parcel_free(parcel_uuid, device_uuid, nvs_p->vs_uuid);
        if (rc < 0)
        {
            NUVO_ERROR_PRINT("Unable to remove parcel. Leaking space");
        }
        rc = nuvo_mfst_remove_parcels(&nvs_p->log_volume.mfst, 1, &parcel_uuid, true);
        NUVO_ASSERT(rc >= 0);
    }

    // Close the manifest
    nuvo_mfst_close(&nvs_p->log_volume.mfst);

    if (test_fi_inject_rc(TEST_FI_VOL_DESTROY, &vol_ops_fi_info, &rc))
    {
        NUVO_ERROR_PRINT("Returning failure of vol destroy after freeing all parcels.");
        rc = -1;
        goto destroy_state_mutex;
    }

    // Free the root.
    rc = nuvo_pr_sync_parcel_free(root_parcel_uuid, root_device_uuid, nvs_p->vs_uuid);
    if (rc < 0)
    {
        NUVO_ERROR_PRINT("Unable to remove parcel. Leaking space");
    }
    // TODO - make sure we do not leak parcels

    // Terminate the worker thread
    nuvo_api_queue_submit_ctrl(nvs_p->cmd_queue, QUEUE_CTRL_TERMINATE);

    rc = 0;

destroy_state_mutex:
    nuvo_mutex_destroy(&nvs_p->state_mutex);
out:
    return (rc);
}
