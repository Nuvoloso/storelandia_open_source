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
 * @file lun.h
 * @brief Headers for lun
 *
 * Luns can be exported, and given a name at export.
 */
#pragma once
#include "map_entry.h"
#include "nuvo_lock.h"
#include "nuvo_stats.h"
#include "nuvo_range_lock.h"
#include "status.h"

/**
 * A LUN is the thing we export.  It has a map associated with it.
 *  We export it with a name. It can be exported read/write or readonly.
 */

/**
 * \enum nuvo_lun_state_e
 * \brief What state is an in-core lun in?
 * We also write two of these to the manifest: NUVO_LUN_STATE_VALID and NUVO_LUN_STATE_DELETING
 *
 * Luns that are in FREE state are slots that are available for use.
 *
 * When a LUN is created it moves to VALID state.  While in valid statet it
 * may be exported, changing the EXPORT state to WRITABLE or READABLE
 *
 * An unexported lun may be deleted, moving it to DELETING state. In this state the
 * lun is not visible from the outside but still holds onto blocks, and
 * may be indirectly used by older snapshots through shared blocks.
 *
 * After all blocks have been returned, the lun will move to DELETING_DRAIN
 * state. At this time it is waiting for all in core users to release
 * pins. When the pin count goes to zero, the lun is moved to DELETED STATE.
 * A CP while in DELETING_DRAIN state will record the snapshot as DELETING.
 *
 * Once a lun is in DELETED state, teh next CP will record it as FREE. When
 * the write of the manifest lun table starts to carry the FREE to media, the lun is
 * moved to FREE_PENDING state.
 *
 * Any lun in FREE_PENDING state in core will move to FREE in-core at the end of a CP.
 */
enum nuvo_lun_state_e
{
    NUVO_LUN_STATE_FREE           = 0,  // This slot is available
    NUVO_LUN_STATE_VALID          = 1,  // The LUN is valid, exportable
    NUVO_LUN_STATE_DELETING       = 2,  // Freeing blocks going on, usable
    NUVO_LUN_STATE_DELETING_DRAIN = 3,  // Waiting for pins to drain.
    NUVO_LUN_STATE_DELETED        = 4,  // Deleted - go to free in next CP.
    NUVO_LUN_STATE_FREE_PENDING   = 5   // Writing FREE to media.  Can reuse at end of CP.
};

static_assert(NUVO_LUN_STATE_FREE < NUVO_LUN_STATE_VALID &&
              NUVO_LUN_STATE_VALID < NUVO_LUN_STATE_DELETING &&
              NUVO_LUN_STATE_DELETING < NUVO_LUN_STATE_DELETING_DRAIN &&
              NUVO_LUN_STATE_DELETING_DRAIN < NUVO_LUN_STATE_DELETED &&
              NUVO_LUN_STATE_DELETED < NUVO_LUN_STATE_FREE_PENDING,
              "Don't change the order of these states.  We do arithmetic on them.");

/**
 * \enum nuvo_lun_state_e
 * \brief States fo in-core luns.
 */
enum nuvo_lun_export_state_e
{
    NUVO_LUN_EXPORT_UNEXPORTED = 0,
    NUVO_LUN_EXPORT_WRITABLE   = 1,
    NUVO_LUN_EXPORT_READONLY   = 2
};
enum nuvo_lun_mfl_state_e
{
    NUVO_LUN_MFL_FREE           = 0, // initial state before hole punching(mfl) begins.
    NUVO_LUN_MFL_L0_IN_PROGRESS = 1, // L0 hole punching(mfl) in progress
    NUVO_LUN_MFL_CP_PENDING     = 2, // we are done with L0 hole punching, next CP will/must do roll up
    NUVO_LUN_MFL_CP_IN_PROGRESS = 3, // we are in deleted drain and this cp must complete roll up
    NUVO_LUN_MFL_CP_DONE        = 4  // roll up with mfl completed.
};

#define NUVO_LUN_MFL_IN_PROGRESS(lun)    ((lun)->mfl_state != NUVO_LUN_MFL_FREE)

struct lun_stats_st {
    uint32_t mfl_dirty_cnt;
    uint32_t dirty_cnt;
};

/**
 * Definition of our lame internal "file system".  We have one per exported "lun".
 * Each one has one root directory with three entries, ".", ".." and "vol"
 */

typedef enum
{
    NUVO_UNUSED = 0,
    NUVO_REG,
    NUVO_DIR
} nuvo_type_t;

#define NUVO_DIRENT_MAX_NAME    5
typedef struct {
    char         name[NUVO_DIRENT_MAX_NAME];
    unsigned int inum;
} nuvo_dirent_t;

#define NUVO_FUSE_ROOT_INO    1
#define NUVO_FUSE_LUN_INO     2
#define NUVO_FUSE_DIRENTS     3
#define NUVO_FUSE_INODES      3
typedef struct nuvo_node {
    uint8_t         inum;
    mode_t          mode;
    nlink_t         nlink;
    nuvo_type_t     type;
    int             want_stats;
    struct timespec mtim;
    struct timespec ctim;
    union
    {
        struct {
            unsigned int  num_entries;
            nuvo_dirent_t ents[NUVO_FUSE_DIRENTS];   // "..", "." and vol
        } dir;
        struct {
            struct nuvo_lun *lun;
        } file;
    }               u;
} nuvo_node_t;

typedef struct nuvo_fs {
    nuvo_node_t nodes[NUVO_FUSE_INODES];          // 0 == unused, 1 == rootdir, 2 == exported vol
} nuvo_fs_t;

#define MOUNT_POINT_BUFFER_MAX    1024

/**
 * \struct nuvo_lun
 * \brief Data structure for a lun. Right now this is sad.
 */
struct nuvo_lun {
    nuvo_mutex_t                 mutex;
    enum nuvo_lun_state_e        lun_state;                                    /**< Valid, deleting, free, etc. */
    enum nuvo_lun_export_state_e export_state;                                 /**< Exported or not. */
    enum nuvo_lun_mfl_state_e    mfl_state;                                    /**< mfl state, used for roll up decisions */
    uint32_t                     pin_count;                                    /**< Lun is pinned.  Cannot go awy until this goes to 0. */

    uuid_t                       lun_uuid;                                     /**< The uuid of this LUN */
    struct nuvo_vol             *vol;                                          /**< Pointer to the series this belongs to.*/
    uint32_t                     snap_id;
    size_t                       size;                                         /**< Size of the lun. */
    unsigned                     map_height;
    struct nuvo_map_entry        root_map_entry;                               /**< Only for log volume luns. */
    struct nuvo_map_track       *root_map;                                     /**< Only for log volume luns. */

    struct nuvo_range_lock       range_lock;                                   /**< Overlapping I/O protection */
    struct nuvo_io_stats         read_io_stats;                                /**< Collector of read I/O stats */
    struct nuvo_io_stats         write_io_stats;                               /**< Collector of write I/O stats */
    uint_fast64_t                read_latency_min;                             /**< Minimum latency for reads */
    uint_fast64_t                write_latency_min;                            /**< Minimum latency for writes */
    struct lun_stats_st          lun_stats;
    uint32_t                     io_pending_count;                             /**< Number of inflight I/O */
    nuvo_cond_t                  io_pending_count_zero_cond;                   /**< Signaled when io_pending_count == 0 */

    pthread_t                    lun_fuse_thread;                              /**< The fuse thread when this is exported. */
    struct fuse_session         *lun_fuse_session;                             /**< The fuse session when this is exported. */
    nuvo_mutex_t                 lun_fuse_session_mutex;                       /** Protect the setting/NULLing of session */
    struct nuvo_fs               lun_file_system;                              /**< The "file system" when this is exported. */
    char                         lun_fuse_mount_point[MOUNT_POINT_BUFFER_MAX]; /**< Mount point when exported. */
};

#define NUVO_LUN_IS_ACTIVE(lun)           ((lun)->snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID)
#define NUVO_LUN_SET_ACTIVE(lun)          ((lun)->snap_id = NUVO_MFST_ACTIVE_LUN_SNAPID)
#define NUVO_LUN_IS_EXPORTED(lun)         (((lun)->export_state == NUVO_LUN_EXPORT_READONLY) \
                                           || ((lun)->export_state == NUVO_LUN_EXPORT_WRITABLE))

#define NUVO_LUN_STAT_MFL_COUNT(lun)      ((lun)->lun_stats.mfl_dirty_cnt++)
#define NUVO_LUN_STAT_DIRTY_COUNT(lun)    ((lun)->lun_stats.dirty_cnt++)
#define NUVO_LUN_STAT_RESET(lun)          (memset(&((lun)->lun_stats), 0, sizeof((lun)->lun_stats)))

/**
 * \brief Initialize the lun structure, including substructures.
 *
 * Inits the mutex, io_stats and range_lock.  Zero's everything else and
 * sets lun_old_state to NUVO_LUN_UNEXPORTED
 *
 * \param lun the structure to be initialized.
 * \param vol the vol series pointer
 * \returns 0 on success, negative on initialization error.
 * \retval 0 Success
 * \retval -NUVO_ENOMEM Init faile on a mutex.
 */
nuvo_return_t nuvo_lun_init(struct nuvo_lun *lun, struct nuvo_vol *vol);

/**
 * \brief Initialize all the luns of a volume
 * (see nuvo_lun_init for intializing a lun)
 *
 * \param vol The volume to init
 * \retval -NUVO_ENOMEM on nuvo_lun_init fail
 */

nuvo_return_t nuvo_multi_lun_init(struct nuvo_vol *vol);

/**
 * \brief Destroy the lun structure, including substructures.
 *
 * Destroys the mutex, io_stats and range_lock.
 * \param lun the structure to be destroyed.
 */
void nuvo_lun_destroy(struct nuvo_lun *lun);

/**
 * \brief destroy all the luns of the vol, active and snaps
 *
 * Destroys the mutex, io_stats and range_lock of each lun
 * \param vol whose luns are to be destroyed
 */

void nuvo_luns_destroy(struct nuvo_vol *vol);

/**
 * \brief Move the lun to the appropriate lun_state and export state.
 * Can only change lun_state if current exported state is NUVO_LUN_EXPORT_UNEXPORTED.
 * Asserts that you only move to deleted if not pinned.
 *
 * \retval 0 Done
 * \retval -NUVO_E_BAD_STATE_TRANSITION
 */
nuvo_return_t nuvo_lun_state_transition(struct nuvo_lun             *lun,
                                        enum nuvo_lun_state_e        lun_state,
                                        enum nuvo_lun_export_state_e export_state);

/**
 * \brief get a younger snapshot of this lun
 *        active if this lun is the youngest
 * \param lun this lun
 * \param pin Pin the lun - eventually this will go away
 * \returns the next younger lun
 */
struct nuvo_lun *nuvo_get_next_younger_lun(struct nuvo_lun *lun, bool pin);

/**
 * \brief get the peer cow lun of the active.
 *      This is the youngest snapshot of the series
 * \param vol the volume series pointer
 * \param pin Whether to pin the lun before returning.
 * \returns the next younger lun
 */
struct nuvo_lun *nuvo_get_peer_cow_lun(struct nuvo_vol *vol, bool pin);

/*
 * \brief check if this lun is the peer cow lun of the active
 * or check whether this lun is the youngest snap
 *
 * \param lun
 * \returns true or false for the check aboveA
 */
bool nuvo_is_peer_cow_lun(struct nuvo_lun *lun);

/*
 * \brief  get a lun of a given snapid for this volume
 *
 * \param vol
 * \param snap_id snap_id of the lun
 * \param pin Pin the lun - eventually this will go away
 * \returns the lun
 */

struct nuvo_lun *nuvo_get_lun_by_snapid_locked(struct nuvo_vol *vol, uint64_t snap_id, bool pin);

struct nuvo_lun *nuvo_get_lun_oldest(struct nuvo_vol *vol);

/*
 * \brief  list uuids of a given vol
 * \param vol
 * \param uuid_list array of lun uuids (output)
 * \returns the count of luns
 */

int nuvo_vol_list_lun_uuids(struct nuvo_vol *vol, uuid_t *uuid_list);

/*
 * \brief find the oldest lun in NUVO_LUN_STATE_DELETING state
 *
 * \param vol
 * \returns lun
 */

struct nuvo_lun *nuvo_get_next_lun_to_delete(struct nuvo_vol *vol);

struct nuvo_lun *nuvo_get_lun_by_uuid_locked(struct nuvo_vol *vol, const uuid_t uuid, bool pin);

/*
 * \brief  get a lun for a vol and uuid
 *
 * \param  vol volume series pointer
 * \param  uuid lun uuid
 * \param pin Pin the lun - eventually this will go away
 * \returns lun pointer for the uuid, NULL if no such lun exists
 */

struct nuvo_lun *nuvo_get_lun_by_uuid(struct nuvo_vol *vol, const uuid_t uuid, bool pin);


/* brief get the next lun given a current lun
 * currently assumes no deletions in the middle.
 * \param vol
 * \param lun the next lun of this lun would be returned.
 * \param pin Pin the lun - eventually this will go away
 * \returns the lun
 */

struct nuvo_lun *nuvo_lun_get_next(struct nuvo_vol *vol, struct nuvo_lun *lun, bool pin);

/* \brief private to lun module, get the index of the lun in the lun list
 * \param lun
 * \returns the index
 */

int lun_get_index(struct nuvo_lun *lun);

/* \brief get the lun pointer for this snap id
 * \param vol  vol handle
 * \param snap_id snap_id of the lun
 * \param pin Pin the lun - eventually this will go away
 * \returns the lun
 */

struct nuvo_lun *nuvo_get_lun_by_snapid(struct nuvo_vol *vol, uint64_t snap_id, bool pin);

/* \brief init the lun state to unexported, bind the lun to the vol
 * \param lun lun
 * \param vol vol
 */
void nuvo_lun_state_init(struct nuvo_lun *lun, struct nuvo_vol *vol, enum nuvo_lun_state_e lun_state, enum nuvo_lun_export_state_e export_state);

/**
 * \brief Move luns in pending free to free.
 * \param vol The volume whose CP jusst ended.
 */
void nuvo_lun_move_pending_free_to_free(struct nuvo_vol *vol);

/**
 * \brief Move luns DELETING to DELETING_DRAIN
 * If the oldest VALID or DELETING lun is DELETING, move it
 * to DELETING_DRAIN.  Will change when hole-punching
 * for pit delete is done.
 * Repeat.
 *
 * \param vol The volume
 */
void nuvo_lun_move_to_deleting_drain(struct nuvo_vol *vol);

/**
 * \brief Move luns DELETING_DRAIN to DELETED
 * If the oldest VALID or DELETING or DELETING_DRAIN lun is
 * DELETING_DRAIN and its pin_count is 0, move to DELETED.
 * Repeat.
 *
 * \param vol The volume
 */
void nuvo_lun_move_to_deleted(struct nuvo_vol *vol);

/**
 * \brief Move luns DELETED to FREE_PENDING
 * \param vol The volume
 */
void nuvo_lun_move_to_free_pending(struct nuvo_vol *vol);

/**
 * \brief Move luns DELETING and done luns to DELETED after replay
 * \param vol The volume
 */

void nuvo_lun_move_to_deleted_on_replay(struct nuvo_vol *vol);

/**
 * \brief pin a lun
 * Keep the lun from going away.
 *
 * \param lun The lun.
 */
void nuvo_lun_pin(struct nuvo_lun *lun);

/**
 * \brief unpin a lun
 *
 * \param lun The lun.
 */
void nuvo_lun_unpin(struct nuvo_lun *lun);

/**
 * \brief Move luns in "mfl cp pending" to "mfl cp progress"
 * \param vol The volume
 */

void  nuvo_lun_move_to_mfl_cp_in_progress(struct nuvo_vol *vol);
