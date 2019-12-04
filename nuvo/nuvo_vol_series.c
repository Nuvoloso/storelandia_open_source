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
#include <uuid/uuid.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "cache.h"
#include "log_volume.h"
#include "nuvo.h"
#include "nuvo_vol_series.h"
#include "nuvo_pr.h"
#include "parcel_vol.h"
#include "passthrough_vol.h"

/**
 * @file nuvo_vol_series.c
 * @brief Routines around vol series.
 */

/**
 * \brief Table containing opened volumes and API request queues.
 */
struct nuvo_vol_table vol_table;

/**
 * \brief The API request queue for non volume-specific commands.
 */
struct nuvo_api_queue nonvol_queue;

/* The pool of API requests */
static struct nuvo_api_req_pool vol_api_req_pool;

unsigned int nuvo_vol_index_lookup(const struct nuvo_vol *vol)
{
    unsigned int idx;

    NUVO_ASSERT(vol != NULL);
    idx = vol - &vol_table.vol[0];
    NUVO_ASSERT(idx < (intptr_t)NUVO_ARRAY_LENGTH(vol_table.vol));
    return (idx);
}

unsigned int nuvo_api_queue_index_lookup(const struct nuvo_api_queue *queue)
{
    unsigned int idx;

    NUVO_ASSERT(queue != NULL);
    idx = queue - &vol_table.queue[0];
    NUVO_ASSERT(idx < (intptr_t)NUVO_ARRAY_LENGTH(vol_table.queue));
    return (idx);
}

/**
 * \brief Lookup a volume from uuid without using lock.
 */
struct nuvo_vol *nuvo_vol_lookup_int(const uuid_t vs_uuid)
{
    for (unsigned int i = 0; i < NUVO_MAX_VOL_SERIES_OPEN; i++)
    {
        if (0 == uuid_compare(vs_uuid, vol_table.vol[i].vs_uuid) &&
            vol_table.vol[i].type != NUVO_VOL_FREE)
        {
            return (&vol_table.vol[i]);
        }
    }
    return (NULL);
}

/**
 * \brief Lookup a volume from uuid.
 */
struct nuvo_vol *nuvo_vol_lookup(const uuid_t vs_uuid)
{
    struct nuvo_vol *nvs_p = NULL;

    nuvo_mutex_lock(&vol_table.mutex);
    nvs_p = nuvo_vol_lookup_int(vs_uuid);
    nuvo_mutex_unlock(&vol_table.mutex);
    return (nvs_p);
}

/**
 * \brief List non-free and initialized volumes. Caller lock volume table_mutex.
 */
int nuvo_vol_list_vols(struct nuvo_vol **nuvo_vol_list)
{
    int cnt = 0;

    for (unsigned int i = 0; i < NUVO_MAX_VOL_SERIES_OPEN; i++)
    {
        if (NUVO_VOL_FREE != vol_table.vol[i].type &&
            NUVO_VOL_OP_STATE_INITIALIZED == vol_table.vol[i].op_state)
        {
            nuvo_vol_list[cnt++] = &vol_table.vol[i];
        }
    }
    return (cnt);
}

struct nuvo_vol *nuvo_vol_alloc_int()
{
    for (unsigned int i = 0; i < NUVO_MAX_VOL_SERIES_OPEN; i++)
    {
        if (NUVO_VOL_FREE == vol_table.vol[i].type)
        {
            return (&vol_table.vol[i]);
        }
    }
    NUVO_ERROR_PRINT("Maximum number of open volumes reached.");
    return (NULL);
}

nuvo_return_t nuvo_vol_series_close_vol(struct nuvo_vol *nvs_p)
{
    nuvo_return_t ret;

    if (!nvs_p)
    {
        return (-NUVO_E_NO_VOLUME);
    }

    switch (nvs_p->type)
    {
    case NUVO_VOL_PASSTHROUGH:
        ret = nuvo_passthrough_close_vol(nvs_p);
        break;

    case NUVO_VOL_PARCEL:
        ret = nuvo_parcel_vol_close(nvs_p);
        break;

    case NUVO_VOL_LOG_VOL:
        ret = nuvo_log_vol_close(nvs_p);
        break;

    default:
        NUVO_PANIC("API worker (%u - %u) vol " NUVO_LOG_UUID_FMT " unexpected volume type %u",
                   pthread_self(), nuvo_vol_index_lookup(nvs_p), NUVO_LOG_UUID(nvs_p->vs_uuid), nvs_p->type);
    }

    // Shutdown per-vol worker thread if close was successful
    if (!ret)
    {
        nuvo_api_queue_submit_ctrl(nvs_p->cmd_queue, QUEUE_CTRL_TERMINATE);
    }
    else
    {
        NUVO_LOG(api, 0, "API worker (%u - %u) vol " NUVO_LOG_UUID_FMT " close failed %u",
                 pthread_self(), nuvo_vol_index_lookup(nvs_p), NUVO_LOG_UUID(nvs_p->vs_uuid), ret);
    }
    return (ret);
}

/**
 * \brief Close all volumes for shutdown.
 *
 * Terminate all worker threads and close all open volumes.
 */
void nuvo_series_close_vols()
{
    struct nuvo_vol *nvs_p;

    // At this point nuvo is shutting down. API dispatcher thread and
    // non volume-specific worker already terminated.
    nuvo_mutex_lock(&vol_table.mutex);
    NUVO_LOG(api, 0, "nuvo_series_close_vols started");
    for (unsigned int i = 0; i < NUVO_MAX_VOL_SERIES_OPEN; i++)
    {
        if (vol_table.vol[i].type != NUVO_VOL_FREE)
        {
            // Submit ctrl req to worker's queue to close vol and terminate worker thread.
            // This ctrl req will be the last in queue because dispatcher already terminated.
            // There may be a prior close vol req pending on the same vol/queue. This
            // is ok because the prior close vol will destroy the queue after closing the
            // vol, turning this ctrl req into a noop.
            nvs_p = &vol_table.vol[i];
            NUVO_LOG(api, 0, "Submit close and terminate ctrl req to vol at index %u", i);
            nuvo_api_queue_submit_ctrl(nvs_p->cmd_queue, QUEUE_CTRL_CLOSE_VOL_TERMINATE);
        }
    }
    nuvo_mutex_unlock(&vol_table.mutex);

    // Now wait for all per-volume worker threads to terminate.
    nuvo_mutex_lock(&num_workers.mutex);
    while (num_workers.num != 0)
    {
        NUVO_LOG(api, 0, "Waiting for all per-volume worker threads to terminate, %d pending", num_workers.num);
        nuvo_cond_wait(&num_workers.zero_cond, &num_workers.mutex);
    }
    nuvo_mutex_unlock(&num_workers.mutex);

    NUVO_LOG(api, 0, "nuvo_series_close_vols: All volumes closed");
}

void nuvo_set_vols_in_shutdown()
{
    nuvo_mutex_lock(&vol_table.mutex);
    for (unsigned int i = 0; i < NUVO_MAX_VOL_SERIES_OPEN; i++)
    {
        if (vol_table.vol[i].type != NUVO_VOL_FREE)
        {
            vol_table.vol[i].shutdown_in_progress = true;
        }
    }
    nuvo_mutex_unlock(&vol_table.mutex);
    return;
}

/**
 * \brief Retrieve either read or write io statistics for the specified lun
 *
 * Given a volume uuid fills in and returns current statistics of the specified type in struct nuvo_io_stats_snap.
 * Statistics of the specified may be optionally reset by setting the clear flag.
 *
 * \param vol_uuid The uuid of the volume.
 * \param type Then type of stats to retrieve. Valid values are NUVO_OP_READ or NUVO_OP_WRITE.
 * \param clear If true, the device statics of the specified type will be reset on retrieval.
 * \param stats_snapshot The address of a struct nuvo_io_stats_snap to fill.
 * \return 0 on success, otherwise -errno.
 */

// Documented in header
int64_t nuvo_vol_lun_stats(const uuid_t vol_uuid, const int type, const bool clear, struct nuvo_io_stats_snap *stats_snapshot)
{
    int64_t          ret = 0;
    struct nuvo_lun *lun;

    NUVO_ASSERT(uuid_is_null(vol_uuid) == 0);
    NUVO_ASSERT(stats_snapshot != NULL);

    struct nuvo_vol *vol = nuvo_vol_lookup(vol_uuid);
    if (!vol)
    {
        return (-NUVO_E_NO_VOLUME);
    }

    switch (vol->type)
    {
    case NUVO_VOL_PASSTHROUGH:
        lun = &vol->ptvol.lun;
        break;

    case NUVO_VOL_PARCEL:
        lun = &vol->parvol.lun;
        break;

    case NUVO_VOL_LOG_VOL:
        lun = &vol->log_volume.lun;
        break;

    default:
        NUVO_PANIC("Unknown volume type");
    }

    NUVO_ASSERT(lun);

    switch (type)
    {
    case NUVO__GET_STATS__READ_WRITE__READ:
        nuvo_io_stats_get_snapshot(&lun->read_io_stats, stats_snapshot, clear);
        break;

    case NUVO__GET_STATS__READ_WRITE__WRITE:
        nuvo_io_stats_get_snapshot(&lun->write_io_stats, stats_snapshot, clear);
        break;

    default:
        ret = -EINVAL;
        break;
    }

    return (ret);
}

nuvo_return_t nuvo_vol_cache_stats(const uuid_t vol_uuid, const bool clear, struct nuvo_cache_stats *data, struct nuvo_cache_stats *metadata)
{
    NUVO_ASSERT(uuid_is_null(vol_uuid) == 0);

    struct nuvo_vol *vol = nuvo_vol_lookup(vol_uuid);
    if (!vol)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    if (vol->type != NUVO_VOL_LOG_VOL)
    {
        return (-NUVO_EINVAL);
    }
    nuvo_cache_stats_snap(&vol->log_volume.cache_vol, data, metadata, clear);
    return (0);
}

nuvo_return_t nuvo_vol_get_manifest(struct nuvo_vol *nvs_p, Nuvo__Manifest *msg, bool short_reply)
{
    if (!nvs_p)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    switch (nvs_p->type)
    {
    case NUVO_VOL_PASSTHROUGH:
    case NUVO_VOL_PARCEL:
        break;

    case NUVO_VOL_LOG_VOL:
        return (nuvo_log_vol_get_manifest(nvs_p, msg, short_reply));

    default:
        NUVO_PANIC("Unexpected volume type");
    }
    return (-1);
}

nuvo_return_t nuvo_vol_get_statuses(Nuvo__NodeStatus *msg)
{
    unsigned num_volumes = 0;

    nuvo_mutex_lock(&vol_table.mutex);
    // Count open log volumes
    for (unsigned vol_idx = 0; vol_idx < NUVO_MAX_VOL_SERIES_OPEN; vol_idx++)
    {
        if (vol_table.vol[vol_idx].type == NUVO_VOL_LOG_VOL &&
            vol_table.vol[vol_idx].op_state == NUVO_VOL_OP_STATE_INITIALIZED)
        {
            num_volumes++;
        }
    }
    if (num_volumes == 0)
    {
        nuvo_mutex_unlock(&vol_table.mutex);
        return (0);
    }

    msg->n_volumes = 0;
    msg->volumes = calloc(num_volumes, sizeof(*msg->volumes));
    if (msg->volumes == NULL)
    {
        nuvo_mutex_unlock(&vol_table.mutex);
        return (-NUVO_ENOMEM);
    }
    for (unsigned status_idx = 0, vol_idx = 0; status_idx < num_volumes; status_idx++)
    {
        while (vol_table.vol[vol_idx].type != NUVO_VOL_LOG_VOL ||
               vol_table.vol[vol_idx].op_state != NUVO_VOL_OP_STATE_INITIALIZED)
        {
            vol_idx++;
        }
        msg->volumes[status_idx] = malloc(sizeof(*msg->volumes[status_idx]));
        if (msg->volumes[status_idx] == NULL)
        {
            nuvo_mutex_unlock(&vol_table.mutex);
            return (-NUVO_ENOMEM);
        }
        msg->n_volumes = status_idx + 1;
        nuvo__vol_status__init(msg->volumes[status_idx]);
        msg->volumes[status_idx]->vol_uuid = malloc(UUID_UNPARSED_LEN);
        if (msg->volumes[status_idx]->vol_uuid == NULL)
        {
            nuvo_mutex_unlock(&vol_table.mutex);
            return (-NUVO_ENOMEM);
        }
        uuid_unparse(vol_table.vol[vol_idx].vs_uuid, msg->volumes[status_idx]->vol_uuid);

        nuvo_return_t rc = nuvo_mfst_get_vol_status(&vol_table.vol[vol_idx].log_volume.mfst, msg->volumes[status_idx]);
        if (rc < 0)
        {
            nuvo_mutex_unlock(&vol_table.mutex);
            return (rc);
        }
        vol_idx++;
    }
    nuvo_mutex_unlock(&vol_table.mutex);
    return (0);
}

nuvo_return_t nuvo_vol_update_parcel_status(const uuid_t vs_uuid,
                                            uuid_t       parcel_uuid,
                                            enum nuvo_pr_parcel_status
                                            parcel_status)
{
    nuvo_return_t    ret;
    struct nuvo_vol *vol;
    bool             parcels_healthy;

    // CUM-2531 - consider using the call below that doesn't grab a lock.
    // nuvo_vol_lookup_int(vs_uuid);
    nuvo_mutex_lock(&vol_table.mutex);
    vol = nuvo_vol_lookup_int(vs_uuid);
    if (!vol)
    {
        NUVO_ERROR_PRINT("Unable to find volume " NUVO_LOG_UUID_FMT ". Parcel health update dropped.",
                         NUVO_LOG_UUID(vs_uuid));
        nuvo_mutex_unlock(&vol_table.mutex);
        return (-NUVO_E_NO_VOLUME);
    }

    ret = nuvo_mfst_set_parcel_health(vol, parcel_uuid, parcel_status);
    if (ret < 0)
    {
        nuvo_mutex_unlock(&vol_table.mutex);
        return (ret);
    }

    parcels_healthy = nuvo_mfst_are_all_parcels_healthy(&vol->log_volume.mfst);
    nuvo_mutex_lock(&vol->state_mutex);
    if (parcels_healthy)
    {
        vol->vol_state = NUVO_VOL_STATE_HEALTHY;
    }
    else
    {
        vol->vol_state = NUVO_VOL_STATE_FENCED;
    }
    nuvo_mutex_unlock(&vol->state_mutex);
    nuvo_mutex_unlock(&vol_table.mutex);

    return (0);
}

/**
 * \brief Initializa/start API worker related items.
 *
 * Initialize API request pool, volume table, number of workers, non
 * volume-specific request queue, and start non volume-specific worker thread.
 *
 * */
nuvo_return_t nuvo_vol_api_init(struct nuvo_api_params *api_params)
{
    struct nuvo_api_req_pool *req_pool = &vol_api_req_pool;

    req_pool->used = 0;
    nuvo_dlist_init(&req_pool->free_list);
    nuvo_dlist_init(&req_pool->alloc_list);

    nuvo_return_t ret;
    ret = nuvo_mutex_init(&req_pool->mutex);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("API request pool initialization failed %u", ret);
        ret = -NUVO_ENOMEM;
        goto out;
    }

    ret = nuvo_mutex_init(&vol_table.mutex);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Volume table mutex init failed %u", ret);
        goto destroy_pool_mutex;
    }

    ret = nuvo_mutex_init(&num_workers.mutex);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Num workers mutex init failed %u", ret);
        ret = -NUVO_ENOMEM;
        goto destroy_vol_table_mutex;
    }

    ret = nuvo_cond_init(&num_workers.zero_cond);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Num workers zero cond init failed %u", ret);
        goto destroy_num_workers_mutex;
    }

    ret = nuvo_api_queue_init(&nonvol_queue, NULL);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("nonvol queue init failed %u", ret);
        goto destroy_num_workers_zero_cond;
    }

    // Start non volume-speicific API worker thread
    ret = pthread_create(&nonvol_queue.worker_id, NULL,
                         nuvo_api_thread_worker_nonvol, api_params);
    if (ret)
    {
        NUVO_ERROR_PRINT("Worker thread creation failed for nonvol queue %u", ret);
        goto destroy_nonvol_queue;
    }
    NUVO_LOG(api, 0, "Created worker thread for nonvol queue tid %u",
             pthread_self());

    return (0);

destroy_nonvol_queue:
    nuvo_api_queue_destroy(&nonvol_queue, NULL);
destroy_num_workers_zero_cond:
    nuvo_cond_destroy(&num_workers.zero_cond);
destroy_num_workers_mutex:
    nuvo_mutex_destroy(&num_workers.mutex);
destroy_vol_table_mutex:
    nuvo_mutex_destroy(&vol_table.mutex);
destroy_pool_mutex:
    nuvo_mutex_destroy(&req_pool->mutex);
out:
    return (ret);
}

/**
 * \brief Destroy/stop API worker related items.
 *
 * Terminate all worker threads and close open volumes.
 * */
void nuvo_vol_api_destroy()
{
    struct nuvo_api_req_pool *req_pool = &vol_api_req_pool;
    int api_ret;

    nuvo_api_queue_submit_ctrl(&nonvol_queue, QUEUE_CTRL_TERMINATE);
    api_ret = pthread_join(nonvol_queue.worker_id, NULL);
    NUVO_LOG(api, 0, "nonvol worker thread joined, rc %d", api_ret);

    nuvo_api_queue_destroy(&nonvol_queue, NULL);

    nuvo_set_vols_in_shutdown();
    nuvo_series_close_vols();
    NUVO_LOG(api, 0, "Closed all volumes at shutdown");

    nuvo_cond_destroy(&num_workers.zero_cond);
    nuvo_mutex_destroy(&num_workers.mutex);
    nuvo_mutex_destroy(&vol_table.mutex);
    nuvo_mutex_destroy(&req_pool->mutex);
}

/**
 * \brief Get a free API command request.
 */
struct nuvo_api_req *nuvo_api_req_alloc()
{
    struct nuvo_api_req_pool *req_pool = &vol_api_req_pool;

    nuvo_mutex_lock(&req_pool->mutex);
    struct nuvo_api_req *req = nuvo_dlist_remove_head_object(&req_pool->free_list, struct nuvo_api_req, list_node);
    if (req == NULL)
    {
        if (req_pool->used < NUVO_ARRAY_LENGTH(req_pool->table))
        {
            req = &req_pool->table[req_pool->used++];
            nuvo_dlnode_init(&req->list_node);
        }
    }
    nuvo_mutex_unlock(&req_pool->mutex);
    return (req);
}

/**
 * \brief Free an API command request.
 * */
void nuvo_api_req_free(struct nuvo_api_req *req)
{
    struct nuvo_api_req_pool *req_pool = &vol_api_req_pool;

    NUVO_ASSERT(req != NULL);
    NUVO_ASSERT(req - req_pool->table >= 0);
    NUVO_ASSERT(req - req_pool->table < (intptr_t)NUVO_ARRAY_LENGTH(req_pool->table));

    nuvo_mutex_lock(&req_pool->mutex);
    nuvo_dlist_insert_head(&req_pool->free_list, &req->list_node);
    nuvo_mutex_unlock(&req_pool->mutex);
}

/**
 * \brief Initialize an API command queue structure.
 */
nuvo_return_t nuvo_api_queue_init(struct nuvo_api_queue *queue, struct nuvo_vol *vol)
{
    NUVO_ASSERT(queue != NULL);
    nuvo_return_t rc;

    rc = nuvo_mutex_init(&queue->mutex);
    if (rc != 0)
    {
        goto err_out;
    }

    rc = nuvo_cond_init(&queue->work_cond);
    if (rc != 0)
    {
        goto err_out;
    }

    nuvo_dlist_init(&queue->list);
    queue->length = 0;
    queue->vol = vol;

    if (vol != NULL)
    {
        vol->cmd_queue = queue;
        NUVO_LOG(api, 0, "Initialized API queue at index %u for vol " NUVO_LOG_UUID_FMT " ",
                 nuvo_vol_index_lookup(vol), NUVO_LOG_UUID(vol->vs_uuid));
    }
    else
    {
        NUVO_LOG(api, 0, "Initialied non-vol API queue");
    }

    return (0);

err_out:
    return (-NUVO_ENOMEM);
}

/**
 * \brief Clean up an API queue structure.
 *
 * \param queue The API request queue.
 * \param vol The volume associated with the queue, or NULL if queue is non volume-specific.
 */
void nuvo_api_queue_destroy(struct nuvo_api_queue *queue, struct nuvo_vol *vol)
{
    NUVO_ASSERT(queue != NULL);

    nuvo_cond_destroy(&queue->work_cond);
    nuvo_mutex_destroy(&queue->mutex);
    queue->length = 0;

    if (vol)
    {
        queue->vol = NULL;
        NUVO_LOG(api, 0, "Destroyed API queue at index %u", nuvo_api_queue_index_lookup(queue));
    }
    else
    {
        NUVO_LOG(api, 0, "Destroyed nonvol API queue");
    }
}

/**
 * Submit an API command to a worker queue
 */
void nuvo_api_queue_submit_req(struct nuvo_api_queue *queue, int cmd_socket, Nuvo__Cmd *cmd)
{
    struct nuvo_api_req *api_req = nuvo_api_req_alloc();

    if (!api_req)
    {
        NUVO_PANIC("Out of API request");
    }
    api_req->cmd_socket = cmd_socket;
    api_req->cmd = cmd;
    api_req->vol = queue->vol;
    api_req->ctrl_cmd = QUEUE_CTRL_NONE;

    nuvo_mutex_lock(&queue->mutex);
    nuvo_dlist_insert_tail(&queue->list, &api_req->list_node);
    queue->length++;

    if (queue->vol)
    {
        NUVO_LOG(api, 0, "Submitted API cmd %d to vol " NUVO_LOG_UUID_FMT " at index %u qlen %u",
                 cmd->msg_type, NUVO_LOG_UUID(queue->vol->vs_uuid),
                 nuvo_vol_index_lookup(queue->vol), queue->length);
    }
    else
    {
        NUVO_LOG(api, 30, "Submitted API cmd %d to nonvol queue qlen %u", cmd->msg_type, queue->length);
    }

    nuvo_cond_signal(&queue->work_cond);
    nuvo_mutex_unlock(&queue->mutex);
}

/**
 * Submit a control command to worker thread
 */
void nuvo_api_queue_submit_ctrl(struct nuvo_api_queue *queue, enum api_queue_ctrl_cmd ctrl_cmd)
{
    struct nuvo_api_req *api_req;

    api_req = nuvo_api_req_alloc();
    if (!api_req)
    {
        NUVO_PANIC("Out of API request");
    }
    api_req->ctrl_cmd = ctrl_cmd;

    nuvo_mutex_lock(&queue->mutex);
    nuvo_dlist_insert_tail(&queue->list, &api_req->list_node);
    queue->length++;

    if (queue->vol)
    {
        NUVO_LOG(api, 0, "Submitted ctrl cmd %d to vol " NUVO_LOG_UUID_FMT " at index %u qlen %u",
                 ctrl_cmd, NUVO_LOG_UUID(queue->vol->vs_uuid), nuvo_vol_index_lookup(queue->vol),
                 queue->length);
    }
    else
    {
        NUVO_LOG(api, 0, "Submitted ctrl cmd %d to nonvol queue qlen %u", queue->length);
    }

    nuvo_cond_signal(&queue->work_cond);
    nuvo_mutex_unlock(&queue->mutex);
}

/**
 * Allocate a volume from the volume table for volume create, open, and destroy.
 * Also starts the worker thread.
 */
nuvo_return_t nuvo_vol_alloc(Nuvo__Cmd *cmd, uuid_t vs_uuid, struct nuvo_vol **nvs_p)
{
    struct nuvo_vol       *vol;
    nuvo_return_t          rc;
    pthread_attr_t         tattr;
    unsigned int           index;
    struct nuvo_api_queue *queue;

    NUVO_LOG(api, 0, "Preallocate volume for " NUVO_LOG_UUID_FMT " ",
             NUVO_LOG_UUID(vs_uuid));
    nuvo_mutex_lock(&vol_table.mutex);

    vol = nuvo_vol_lookup_int(vs_uuid);
    if (vol != NULL)
    {
        NUVO_ERROR_PRINT("Volume " NUVO_LOG_UUID_FMT " already exists at index %u",
                         NUVO_LOG_UUID(vs_uuid), nuvo_vol_index_lookup(vol));
        rc = -EEXIST;
        goto out;
    }

    vol = nuvo_vol_alloc_int();
    if (vol == NULL)
    {
        NUVO_ERROR_PRINT("Volume allocation failed for " NUVO_LOG_UUID_FMT " ",
                         NUVO_LOG_UUID(vs_uuid));
        rc = -ENOMEM;
        goto out;
    }

    // Start from clean slate
    memset(vol, 0, sizeof(*vol));

    index = nuvo_vol_index_lookup(vol);
    queue = &vol_table.queue[index];
    uuid_copy(vol->vs_uuid, vs_uuid);

    rc = nuvo_api_queue_init(queue, vol);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("API CMD queue init failed for " NUVO_LOG_UUID_FMT " %u",
                         NUVO_LOG_UUID(vs_uuid), rc);
        goto out;
    }

    rc = pthread_attr_init(&tattr);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Pthread attr init failed for " NUVO_LOG_UUID_FMT " %u",
                         NUVO_LOG_UUID(vs_uuid), rc);
        goto out;
    }

    rc = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Pthread set attribute failed for " NUVO_LOG_UUID_FMT " %u",
                         NUVO_LOG_UUID(vs_uuid), rc);
        goto out;
    }

    rc = pthread_create(&vol->cmd_queue->worker_id, &tattr, nuvo_api_thread_worker_vol, (void *)queue);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Worker thread creation failed for " NUVO_LOG_UUID_FMT " rc %u",
                         NUVO_LOG_UUID(vs_uuid), rc);
        goto out;
    }

    nuvo_mutex_lock(&num_workers.mutex);
    num_workers.num++;
    nuvo_mutex_unlock(&num_workers.mutex);

    if (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ)
    {
        vol->type = NUVO_VOL_PASSTHROUGH;
        NUVO_LOG(api, 0, "Set vol type to NUVO_VOL_PASSTHROUGH for " NUVO_LOG_UUID_FMT " at index %u",
                 NUVO_LOG_UUID(vs_uuid), nuvo_vol_index_lookup(vol));
    }
    else if (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ)
    {
        vol->type = (cmd->open_volume->log_volume ? NUVO_VOL_LOG_VOL : NUVO_VOL_PARCEL);
        NUVO_LOG(api, 0, "Set vol type to %s for " NUVO_LOG_UUID_FMT " at index %u",
                 (cmd->open_volume->log_volume ? "NUVO_VOL_LOG_VOL" : "NUVO_VOL_PARCEL"),
                 NUVO_LOG_UUID(vs_uuid), nuvo_vol_index_lookup(vol));
    }
    else if (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ)
    {
        vol->type = (cmd->create_volume->log_volume ? NUVO_VOL_LOG_VOL : NUVO_VOL_PARCEL);
        NUVO_LOG(api, 0, "Set vol type to %s for " NUVO_LOG_UUID_FMT " at index %u",
                 (cmd->create_volume->log_volume ? "NUVO_VOL_LOG_VOL" : "NUVO_VOL_PARCEL"),
                 NUVO_LOG_UUID(vs_uuid), nuvo_vol_index_lookup(vol));
    }
    else
    {
        NUVO_ASSERT(cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ);
        vol->type = (cmd->destroy_vol->log_volume ? NUVO_VOL_LOG_VOL : NUVO_VOL_PARCEL);
        NUVO_LOG(api, 0, "Set vol type to %s",
                 (cmd->destroy_vol->log_volume ? "NUVO_VOL_LOG_VOL" : "NUVO_VOL_PARCEL"));
    }

    vol->op_state = NUVO_VOL_OP_STATE_UNINITIALIZED;
    *nvs_p = vol;
    NUVO_LOG(api, 0, "Allocated vol struct at index %u for " NUVO_LOG_UUID_FMT " num workers %u",
             nuvo_vol_index_lookup(vol), NUVO_LOG_UUID(vs_uuid), num_workers.num);

out:
    nuvo_mutex_unlock(&vol_table.mutex);

    return (rc);
}
