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

/**
 * @file nuvo_vol_series.h
 * @brief Routines around vol series.
 *
 * Vol series can be opened or not.  If they are opened
 * we know what type of volume it is.  We really only envision
 * one type in the near term shipping, but we have others
 * for temporary and testing purposes.
 *
 * Vol series have luns (active and someday snapshots).
 * Luns can be exported, and given a name at export.
 */
#pragma once
#include <uuid/uuid.h>
#include <nuvo.pb-c.h>

#include "nuvo_lock.h"
#include "manifest.h"
#include "status.h"
#include "map.h"
#include "logger.h"
#include "lun.h"
#include "space.h"
#include "cache.h"
#include "nuvo_api.h"

/**
 * \enum nuvo_vol_type_e
 * \brief For each open volume series, what kind of volume is it.
 */
enum nuvo_vol_type_e
{
    NUVO_VOL_FREE        = 0, /**< Uninitialized */
    NUVO_VOL_PASSTHROUGH = 1, /**< Passthrough to a device or file. */
    NUVO_VOL_PARCEL      = 2, /**< Parcel Volume */
    NUVO_VOL_LOG_VOL     = 3,
};

/**
 * \enum nuvo_vol_state_e
 * \brief For each volume series, what is the current state.
 *
 * UNINITIALIZED - Volume is starting up, replay could be in progress
 * HEALTHY - Volume is ready to serve data
 * FENCED - Volume is not serving data, incoming ops will be queued.
 * Modules should use the FENCED state to stop generating new work.
 */
enum nuvo_vol_state_e
{
    NUVO_VOL_STATE_UNINITIALIZED = 0,
    NUVO_VOL_STATE_HEALTHY       = 1,
    NUVO_VOL_STATE_FENCED        = 2,
};

/**
 * \enum nuvo_vol_op_state_e
 * \brief The operational state of a volume series.
 *
 * UNINITIALIZED - Volume is not initialized yet.
 * INITIALIZED - Volume is initialized.
 * CLOSING - Volume is being closed.
 */
enum nuvo_vol_op_state_e
{
    NUVO_VOL_OP_STATE_UNINITIALIZED = 0,
    NUVO_VOL_OP_STATE_INITIALIZED   = 1,
    NUVO_VOL_OP_STATE_CLOSING       = 2,
};

/**
 * \brief How many volume series can the volume manager have open.
 */
#define NUVO_MAX_VOL_SERIES_OPEN    20

struct nuvo_vol;

#define NUVO_VOL_PD_UNUSED    UINT32_MAX

/**
 * \brief API request queue.
 */
struct nuvo_api_queue {
    struct nuvo_dlist list;             /**< The list of API requests to process */
    uint16_t          length;           /**< Number of requests in queue */
    nuvo_mutex_t      mutex;            /**< Lock for the queue structure */
    nuvo_cond_t       work_cond;        /**< A new request has been added to the queue */
    pthread_t         worker_id;        /**< The API worker thread for this queue */
    struct nuvo_vol  *vol;              /**< The volume associated with this queue */
};

/**
 * \struct nuvo_vol
 * \brief The central data structure for a running volume series.
 */
struct nuvo_vol {
    nuvo_mutex_t             mutex;
    nuvo_rwlock_t            rw_lock;
    uuid_t                   vs_uuid; /**< The uuid of the series. */
    enum nuvo_vol_type_e     type;    /**< What type of volume series is it. */

    nuvo_mutex_t             state_mutex;
    enum nuvo_vol_state_e    vol_state;            /**< Health state of the volume. */
    enum nuvo_vol_op_state_e op_state;             /**< Operational state of the volume. */

    uint64_t                 snap_generation;      /*max snap id till now */
    bool                     shutdown_in_progress; /* Set during nuvo shutdown */
    int                      export_cnt;
    struct nuvo_dlist        map_replay_stash_list;
    int                      map_replay_stash_list_count;
    struct nuvo_api_queue   *cmd_queue;  /**< The API request (command) queue for this volume */

    union
    {
        struct {
            unsigned int    fd;     /**< Passthrough volumes file descriptor. */
            struct nuvo_lun lun;    /**< Passthrough volumes LUN. */
        } ptvol;
        struct {
            struct nuvo_simple_parcel_manifest pm;                             /**< Simple Parcel Manifest */
            uint_fast32_t                      pds[MAX_PARCELS_IN_PARCEL_VOL]; /**< Descriptors of open parcels */
            struct nuvo_lun                    lun;                            /**< Parcel manifest volumes LUN. */
        } parvol;
        struct {
            struct nuvo_sb_superblock sb;
            struct nuvo_mfst          mfst;
            struct nuvo_logger        logger;
            struct nuvo_lun           lun;
            struct nuvo_lun           lun_list[NUVO_MFST_MAX_LUNS];
            struct nuvo_map_vol_state map_state;
            struct nuvo_space_vol     space;
            struct nuvo_cache_vol     cache_vol;
        } log_volume;
    };
};

/**
 * unsigned int nuvo_vol_index_lookup(const struct nuvo_vol *vol)
 * \brief Lookup the index of the volume in the volume table.
 *
 * \param vol The volume to get the index of.
 * \returns The index of the volume in the volume table.
 * \retval index of the volume.
 */
unsigned int nuvo_vol_index_lookup(const struct nuvo_vol *vol);

/**
 * \brief Lookup the open vol series by uuid.
 *
 * \param vs_uuid The uuid to look up.  Duh.
 * \returns Pointer to the volume series.
 * \retval NULL That volume series is not loaded
 */
struct nuvo_vol *nuvo_vol_lookup(const uuid_t vs_uuid);

/**
 * \brief Lookup the open vol series by uuid without locking vol table.
 *
 * \param vs_uuid The uuid to look up.
 * \returns Pointer to the volume series or NULL if volume series not loaded.
 */
struct nuvo_vol *nuvo_vol_lookup_int(const uuid_t vs_uuid);

/**
 * \brief Find a free slot in the volume table.
 *
 * The vol series mutex must be held
 * Marks the allocated lun as allocated.
 */
struct nuvo_vol *nuvo_vol_alloc_int();

/**
 * \brief Allocate a lun from the lun list in volume.
 *
 * Does not actually mark it as allocated. Caller should change type from free to do that.
 * \param vol The volume to alloc a lun on
 * \param pin Whether to pin it before returning.
 * \returns The alloced lun (or NULL)
 */
struct nuvo_lun *nuvo_lun_alloc(struct nuvo_vol *vol, bool pin);

/**
 * \brief get the list of vols objects open on this node
 * \param nuvo_vol_list: the address of an array of nuvo_vols to fill in.
 * The function assumes that the array size >= NUVO_MAX_VOL_SERIES_OPEN
 * \returns Number of open volumes.
 */
int nuvo_vol_list_vols(struct nuvo_vol **nuvo_vol_list);

/**
 * \brief Does the work of closing a volume series.
 *
 * Should succeed unless volume is exported.
 *
 * \param vol The volume structure.
 * \returns 0 or - error code.
 */
nuvo_return_t nuvo_vol_series_close_vol(struct nuvo_vol *vol);

/**
 * \brief Close all open volumes.
 *
 * Attempts to close all open volumes. Used during shutdown.
 */
void nuvo_series_close_vols();

/**
 * \brief Mark the shutdown flag for all volumes.
 *
 * Shutdown flag is for nuvo shutdown, and allows us to bypass certain
 * restrictions (IE: closing a lun which is exported)
 */
void nuvo_set_vols_in_shutdown();

/**
 * \brief Destroy a volume.
 *
 * Destroys a volume.  Only make sense for volumes
 * that have a root parcel.  For now assume the volume
 * is a parcel volume.   Would be nice to have a
 * superblock to guide us.
 */
nuvo_return_t nuvo_vol_destroy(const uuid_t  vs_uuid,
                               const uuid_t  device_uuid,
                               const uuid_t  root_parcel_uuid,
                               nuvo_mutex_t *sync_signal);

/**
 * \brief Collect the stats from a volume.
 *
 * Given a volume uuid fills in and returns current statistics of the specified type in struct nuvo_io_stats_snap.
 * Statistics of the specified may be optionally reset by setting the clear flag.
 *
 * \param vol_uuid The uuid of the volume we want the lun stats from.
 * \param type Then type of stats to retrieve. Valid values are NUVO_OP_READ or NUVO_OP_WRITE.
 * \param clear If true, the device statics of the specified type will be reset on retrieval.
 * \param stats_snapshot The address of a struct nuvo_io_stats_snap to fill.
 * \return 0 on success, otherwise -errno.
 */
nuvo_return_t nuvo_vol_lun_stats(const uuid_t               vol_uuid,
                                 const int                  type,
                                 const bool                 clear,
                                 struct nuvo_io_stats_snap *stats_snapshot);

nuvo_return_t nuvo_vol_cache_stats(const uuid_t             vol_uuid,
                                   const bool               clear,
                                   struct nuvo_cache_stats *data,
                                   struct nuvo_cache_stats *metadata);

/**
 * \brief Fill in an api protobuf with the manifest.
 *
 * This only makes sense for a log volume. It will return an error for any other kind of volume.
 *
 * \param vol The volume structure.
 * \param msg The protobuf.
 * \param short_reply Just get devices (or also parcels and segments).
 */
nuvo_return_t nuvo_vol_get_manifest(struct nuvo_vol *vol, Nuvo__Manifest *msg, bool short_reply);

/**
 * \brief is this volume paused
 * \param vs_uuid volume series uuid
 * \return true or false
 */

bool nuvo_vol_is_fake_paused(const uuid_t vs_uuid);

/**
 * \brief Get node and log volume statuses
 *
 * \param msg The protobuf to fill with status.
 * \return 0 on success, otherwise -errno.
 * \retval -NUVO_ENOMEM malloc error.
 */
nuvo_return_t nuvo_vol_get_statuses(Nuvo__NodeStatus *msg);

/**
 * \brief Handle notifications from the connection manager about parcel health
 *
 * When a connection to a node goes down, those parcels become unavailable.
 * If a volume has any unavailable parcels, it is marked unhealthy.  If all
 * parcels are available the volume is marked healthy.
 *
 * \param vs_uuid The volume uuid.
 * \param parcel_uuid The uuid of the parcel which is healthy/unhealthy
 * \param parcel_status Is the parcel is healthy?
 */
nuvo_return_t nuvo_vol_update_parcel_status(const uuid_t vs_uuid,
                                            uuid_t       parcel_uuid,
                                            enum nuvo_pr_parcel_status
                                            parcel_status);

/**
 * The size of the API request pool for use by all worker threads.
 */
#define NUVO_VOL_API_REQ_POOL_SIZE    (256)

/**
 * \brief A structure for maintaining a pool of API requests
 */
struct nuvo_api_req_pool {
    uint32_t            used;
    nuvo_mutex_t        mutex;
    struct nuvo_dlist   alloc_list;
    struct nuvo_dlist   free_list;
    struct nuvo_api_req table[NUVO_VOL_API_REQ_POOL_SIZE];
};

/**
 * \brief Structure containing opened volumes and API request queues.
 */
struct nuvo_vol_table {
    struct nuvo_vol       vol[NUVO_MAX_VOL_SERIES_OPEN];
    struct nuvo_api_queue queue[NUVO_MAX_VOL_SERIES_OPEN];
    nuvo_mutex_t          mutex;
};

/**
 * \brief Initialize global structures needed for per-volume API thread.
 */
nuvo_return_t nuvo_vol_api_init(struct nuvo_api_params *api_params);

/**
 * \brief Destroy global structures used by per-volume API thread.
 */
void nuvo_vol_api_destroy(void);

/**
 * \brief Get an API request structure.
 */
struct nuvo_api_req *nuvo_api_req_alloc(void);

/**
 * \brief Free an API request structure.
 */
void nuvo_api_req_free(struct nuvo_api_req *req);

/**
 * \brief Initialize an API request queue.
 */
nuvo_return_t nuvo_api_queue_init(struct nuvo_api_queue *queue, struct nuvo_vol *vol);

/**
 * \brief Destroy an API request queue.
 */
void nuvo_api_queue_destroy(struct nuvo_api_queue *queue, struct nuvo_vol *vol);

/**
 * \brief Submit an API command to an API request queue.
 */
void nuvo_api_queue_submit_req(struct nuvo_api_queue *queue, int cmd_socket, Nuvo__Cmd *api_cmd);

/**
 * \brief Submit a control command to an API request queue.
 */
void nuvo_api_queue_submit_ctrl(struct nuvo_api_queue *queue, enum api_queue_ctrl_cmd ctrl_cmd);

/**
 * \brief Allocate a volume structure in the volume table.
 */
nuvo_return_t nuvo_vol_alloc(Nuvo__Cmd *cmd, uuid_t vs_uuid, struct nuvo_vol **nvs_p);

/**
 * \brief The non volume-specific API cmd queue.
 */
extern struct nuvo_api_queue nonvol_queue;

/**
 * \brief The table containing opened volumes and API request queues.
 */
extern struct nuvo_vol_table vol_table;
