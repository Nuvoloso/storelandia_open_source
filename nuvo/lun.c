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

#include "map_entry.h"
#include "lun.h"
#include "nuvo_vol_series.h"
#include "map.h"
#include "map_priv.h"


nuvo_return_t nuvo_lun_init(struct nuvo_lun *lun, struct nuvo_vol *vol)
{
    (void)vol;

    memset(lun, 0, sizeof(*lun));

    nuvo_return_t ret = nuvo_mutex_init(&lun->mutex);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Lun mutex init failed.");
        goto mutex_init_failed;
    }
    ret = nuvo_mutex_init(&lun->lun_fuse_session_mutex);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Lun fuse mutex init failed.");
        goto destroy_mutex;
    }

    if ((ret = nuvo_io_stats_init(&lun->read_io_stats)) < 0)
    {
        NUVO_ERROR_PRINT("init read io stats failed.");
        goto destroy_fuse_mutex;
    }
    if ((ret = nuvo_io_stats_init(&lun->write_io_stats)) < 0)
    {
        NUVO_ERROR_PRINT("init write io stats failed.");
        goto destroy_read_stats;
    }
    if ((ret = nuvo_range_lock_init(&lun->range_lock)) < 0)
    {
        NUVO_ERROR_PRINT("init range lock failed.");
        goto destroy_write_stats;
    }
    if ((ret = nuvo_cond_init(&lun->io_pending_count_zero_cond)) != 0)
    {
        NUVO_ERROR_PRINT("init io pending count zero cond failed.");
        goto destroy_range_lock;
    }
    return (0);

destroy_range_lock:
    nuvo_range_lock_destroy(&lun->range_lock);
destroy_write_stats:
    nuvo_io_stats_destroy(&lun->write_io_stats);
destroy_read_stats:
    nuvo_io_stats_destroy(&lun->read_io_stats);
destroy_fuse_mutex:
    nuvo_mutex_destroy(&lun->lun_fuse_session_mutex);
destroy_mutex:
    nuvo_mutex_destroy(&lun->mutex);
mutex_init_failed:
    return (ret);
}

nuvo_return_t nuvo_multi_lun_init(struct nuvo_vol *vol)
{
    nuvo_return_t ret;

    ret = nuvo_lun_init(&vol->log_volume.lun, vol);
    NUVO_ASSERT(!ret);

    nuvo_lun_state_init(&vol->log_volume.lun, vol, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);

    NUVO_LUN_SET_ACTIVE(&(vol->log_volume.lun));

    // someday we will move the active lun to slot 0
    // hence the iteration from i = 1

    for (uint_fast32_t i = 1; i < NUVO_ARRAY_LENGTH(vol->log_volume.lun_list); i++)
    {
        struct  nuvo_lun *lun = &vol->log_volume.lun_list[i];

        // just the mem init like mutex and stats structure init
        // state init must be done after getting the state from mfst.
        ret = nuvo_lun_init(lun, vol);

        NUVO_ASSERT(!ret);
    }

    return (0);
}

void nuvo_lun_destroy(struct nuvo_lun *lun)
{
    nuvo_cond_destroy(&lun->io_pending_count_zero_cond);
    nuvo_range_lock_destroy(&lun->range_lock);
    nuvo_io_stats_destroy(&lun->write_io_stats);
    nuvo_io_stats_destroy(&lun->read_io_stats);
    lun->lun_state = NUVO_LUN_STATE_FREE;
    lun->export_state = NUVO_LUN_EXPORT_UNEXPORTED;
    lun->snap_id = 0;
    lun->vol = NULL;
    nuvo_mutex_destroy(&lun->lun_fuse_session_mutex);
    nuvo_mutex_destroy(&lun->mutex);
}

// lun_list iterations start from index 1
// index 0 in lun_list will be active someday and hence the read from 1
// also lun_table[0] is active, so this is an identity mapping to lun_table
struct nuvo_lun *nuvo_lun_alloc(struct nuvo_vol *vol, bool pin)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    struct nuvo_lun *lun = NULL;
    unsigned int     lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);


    for (unsigned i = 1; i < lun_max_count; i++)
    {
        if (vol->log_volume.lun_list[i].lun_state == NUVO_LUN_STATE_FREE)
        {
            lun = &vol->log_volume.lun_list[i];
            break;
        }
    }

    if (!lun)
    {
        goto _out;
    }

    nuvo_lun_init(lun, vol);
    nuvo_lun_state_init(lun, vol, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);
    if (pin)
    {
        nuvo_mutex_lock(&lun->mutex);
        nuvo_lun_pin(lun);
        nuvo_mutex_unlock(&lun->mutex);
    }

_out:
    return (lun);
}

nuvo_return_t nuvo_map_multi_luns_open(struct nuvo_vol *vol)
{
    uint_fast32_t lun_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    nuvo_return_t ret;
    uint_fast32_t i;

    ret = nuvo_map_lun_open(&vol->log_volume.lun, &vol->log_volume.lun.root_map_entry);

    if (ret < 0)
    {
        return (ret);
    }

    for (i = 1; i < lun_count; i++)
    {
        struct  nuvo_lun *lun = &vol->log_volume.lun_list[i];

        if (lun->lun_state == NUVO_LUN_STATE_FREE)
        {
            continue;
        }


        ret = nuvo_map_lun_open(lun, &lun->root_map_entry);

        if (ret < 0)
        {
            NUVO_ERROR_PRINT("Opening map failed.");
            goto close_luns;
        }
    }

    return (0);

close_luns:
    //SNAP_WORK
    // need checkpoint supaport for snap luns

    lun_count = i;

    for (i = 1; i < lun_count; i++)
    {
        struct nuvo_map_entry map_entry;
        struct  nuvo_lun     *lun = &vol->log_volume.lun_list[i];

        if (lun->lun_state == NUVO_LUN_STATE_FREE)
        {
            continue;
        }
        nuvo_map_lun_close(lun, &map_entry);
    }
    return (ret);
}

// TODO iterator for multi lun close/destroy etc

nuvo_return_t nuvo_map_luns_close(struct nuvo_vol *vol)
{
    nuvo_return_t         ret;
    struct  nuvo_lun     *lun = &vol->log_volume.lun;
    struct nuvo_map_entry map_entry;

    NUVO_ASSERT(NUVO_LUN_IS_ACTIVE(lun));
    NUVO_ASSERT(NUVO_MFL_HALTED(&vol->log_volume.space.mfl_req));

    nuvo_map_lun_close(lun, &map_entry);

    uint_fast32_t lun_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);

    for (uint_fast32_t i = 1; i < lun_count; i++)
    {
        lun = &vol->log_volume.lun_list[i];
        if (lun->lun_state <= NUVO_LUN_STATE_FREE || lun->lun_state >= NUVO_LUN_STATE_DELETED)
        {
            continue;
        }

        NUVO_ASSERT(NUVO_MFL_HALTED(&vol->log_volume.space.mfl_req));

        ret = nuvo_map_lun_close(lun, &map_entry);

        if (ret < 0)
        {
            return (ret);
        }
    }

    return (0);
}

void nuvo_luns_destroy(struct nuvo_vol *vol)
{
    struct  nuvo_lun *lun = &vol->log_volume.lun;

    NUVO_ASSERT(NUVO_LUN_IS_ACTIVE(lun));
    nuvo_lun_destroy(lun);

    uint_fast32_t lun_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);

    for (uint_fast32_t i = 1; i < lun_count; i++)
    {
        lun = &vol->log_volume.lun_list[i];
        if (lun->lun_state == NUVO_LUN_STATE_FREE)
        {
            continue;
        }
        nuvo_lun_destroy(lun);
    }
}

bool nuvo_is_peer_cow_lun(struct nuvo_lun *lun)
{
    return (lun->snap_id == lun->vol->snap_generation);
}

struct nuvo_lun *nuvo_get_peer_cow_lun(struct nuvo_vol *vol, bool pin)
{
    nuvo_mutex_lock(&vol->mutex);
    struct nuvo_lun *lun = nuvo_get_lun_by_snapid_locked(vol, vol->snap_generation, false);

    if (lun)
    {
        if ((lun->lun_state != NUVO_LUN_STATE_VALID) &&
            (lun->lun_state != NUVO_LUN_STATE_DELETING))
        {
            lun = NULL;
        }
    }
    if (lun && pin)
    {
        nuvo_mutex_lock(&lun->mutex);
        nuvo_lun_pin(lun);
        nuvo_mutex_unlock(&lun->mutex);
    }
    nuvo_mutex_unlock(&vol->mutex);

    return (lun);
}

struct nuvo_lun *nuvo_get_next_younger_lun(struct nuvo_lun *lun, bool pin)
{
    struct nuvo_lun *rlun = NULL;

    struct nuvo_vol *vol = lun->vol;

    nuvo_mutex_lock(&vol->mutex);
    uint64_t snap_generation = vol->snap_generation;

    nuvo_mutex_lock(&lun->mutex);
    uint64_t snap_id = lun->snap_id;
    nuvo_mutex_unlock(&lun->mutex);

    NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(lun)); // api only for snap luns

    while (snap_id < vol->snap_generation)
    {
        rlun = nuvo_get_lun_by_snapid_locked(vol, ++snap_id, pin);

        if (rlun)
        {
            goto _out;
        }
    }
    if (snap_id == (snap_generation + 1))
    {
        NUVO_ASSERT(0);  /* we don't need active for this now */
        rlun = nuvo_get_lun_by_snapid_locked(vol, NUVO_MFST_ACTIVE_LUN_SNAPID, pin);
    }

_out:
    nuvo_mutex_unlock(&vol->mutex);
    return (rlun);
}

struct nuvo_lun *
nuvo_get_lun_by_uuid_locked(struct nuvo_vol *vol, const uuid_t uuid, bool pin)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    if (!uuid_compare(vol->log_volume.lun.lun_uuid, uuid))
    {
        return (&vol->log_volume.lun);
    }

    unsigned int lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);

    for (unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);        // The LUN is valid, exportable
        if (lun->lun_state != NUVO_LUN_STATE_VALID)
        {
            continue;
        }
        if (!uuid_compare(lun->lun_uuid, uuid))
        {
            if (pin)
            {
                nuvo_mutex_lock(&lun->mutex);
                nuvo_lun_pin(lun);
                nuvo_mutex_unlock(&lun->mutex);
            }
            return (lun);
        }
    }
    return (NULL);
}

struct nuvo_lun *
nuvo_get_lun_by_uuid(struct nuvo_vol *vol, const uuid_t uuid, bool pin)
{
    nuvo_mutex_lock(&vol->mutex);
    struct nuvo_lun *rlun = nuvo_get_lun_by_uuid_locked(vol, uuid, pin);
    nuvo_mutex_unlock(&vol->mutex);
    return (rlun);
}

struct nuvo_lun *
nuvo_get_lun_by_snapid_locked(struct nuvo_vol *vol, uint64_t snap_id, bool pin)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    struct nuvo_lun *rlun = NULL;

    if (snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID)
    {
        return (&vol->log_volume.lun);
    }

    unsigned int lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);

    for (unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);
        if (lun->lun_state == NUVO_LUN_STATE_FREE)
        {
            continue;
        }
        if (snap_id == lun->snap_id)
        {
            rlun = &vol->log_volume.lun_list[i];
        }
    }
    if (pin && rlun != NULL)
    {
        nuvo_mutex_lock(&rlun->mutex);
        nuvo_lun_pin(rlun);
        nuvo_mutex_unlock(&rlun->mutex);
    }
    return (rlun);
}

struct nuvo_lun *
nuvo_get_lun_by_snapid(struct nuvo_vol *vol, uint64_t snap_id, bool pin)
{
    struct nuvo_lun *lun = NULL;

    nuvo_mutex_lock(&vol->mutex);
    lun = nuvo_get_lun_by_snapid_locked(vol, snap_id, pin);
    nuvo_mutex_unlock(&vol->mutex);

    return (lun);
}

struct nuvo_lun *
nuvo_get_next_lun_to_delete(struct nuvo_vol *vol)
{
    nuvo_mutex_lock(&vol->mutex);
    struct nuvo_lun *oldest = NULL;
    unsigned int     lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    for (uint_fast32_t i = 1; i < lun_max_count; i++)
    {
        struct  nuvo_lun *lun = &vol->log_volume.lun_list[i];

        NUVO_LOG_COND(lun, 0, lun->lun_state, "lun(%d) lun_state:%d", lun->snap_id, lun->lun_state);

        if ((lun->lun_state != NUVO_LUN_STATE_DELETING) &&
            (lun->lun_state != NUVO_LUN_STATE_VALID))
        {
            continue;
        }
        if (oldest == NULL || oldest->snap_id > lun->snap_id)
        {
            oldest = lun;
        }
    }

    if (oldest != NULL && oldest->lun_state != NUVO_LUN_STATE_DELETING)
    {
        oldest = NULL;
    }

    if (oldest)
    {
        nuvo_mutex_lock(&oldest->mutex);
        nuvo_lun_pin(oldest);
        nuvo_mutex_unlock(&oldest->mutex);
    }
    nuvo_mutex_unlock(&vol->mutex);
    return (oldest);
}

struct nuvo_lun *
nuvo_get_lun_oldest(struct nuvo_vol *vol)
{
    nuvo_mutex_lock(&vol->mutex);
    struct nuvo_lun *oldest = NULL;
    unsigned int     lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    for (uint_fast32_t i = 1; i < lun_max_count; i++)
    {
        struct  nuvo_lun *lun = &vol->log_volume.lun_list[i];
        if (lun->lun_state != NUVO_LUN_STATE_VALID && lun->lun_state != NUVO_LUN_STATE_DELETING)
        {
            continue;
        }
        if (oldest == NULL || oldest->snap_id > lun->snap_id)
        {
            oldest = lun;
        }
    }
    if (oldest != NULL)
    {
        nuvo_mutex_lock(&oldest->mutex);
        nuvo_lun_pin(oldest);
        nuvo_mutex_unlock(&oldest->mutex);
    }
    nuvo_mutex_unlock(&vol->mutex);
    return (oldest);
}

int nuvo_vol_list_lun_uuids(struct nuvo_vol *vol, uuid_t *uuid_list)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);

    uint_fast32_t lun_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    int           cnt = 0;

    for (uint_fast32_t i = 1; i < lun_count; i++)
    {
        struct  nuvo_lun *lun = &vol->log_volume.lun_list[i];

        if (lun->lun_state != NUVO_LUN_STATE_VALID)
        {
            continue;
        }
        uuid_copy(uuid_list[cnt++], lun->lun_uuid);
    }
    return (cnt);
}

int lun_get_index(struct nuvo_lun *lun)
{
    return (lun - lun->vol->log_volume.lun_list);
}

/* This function needs to provide every valid lun (once)
 * to CP, in no particular order.
 * since we start from 1 to 64,
 *  we will visit every valid lun and only once
 */
struct nuvo_lun *nuvo_lun_get_next(struct nuvo_vol *vol, struct nuvo_lun *lun, bool pin)
{
    struct nuvo_lun *rlun = NULL;

    nuvo_mutex_lock(&vol->mutex);
    unsigned int lun_index = 0;

    NUVO_ASSERT(lun);

    if (lun == &vol->log_volume.lun)
    {
        lun_index = 0;
    }
    else
    {
        NUVO_ASSERT(lun->vol == vol);
        lun_index = lun_get_index(lun);
        NUVO_ASSERT(lun_index && lun_index < NUVO_MFST_MAX_LUNS);
    }

    unsigned int lun_max_count = sizeof(vol->log_volume.lun_list) / sizeof(vol->log_volume.lun_list[0]);
    NUVO_ASSERT(lun_max_count == NUVO_MFST_MAX_LUNS);

    for (unsigned i = lun_index + 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);
        if (lun->lun_state == NUVO_LUN_STATE_FREE || lun->lun_state >= NUVO_LUN_STATE_DELETED)
        {
            continue;
        }
        rlun = lun;
        break;
    }

    if (pin && rlun != NULL)
    {
        nuvo_mutex_lock(&rlun->mutex);
        nuvo_lun_pin(rlun);
        nuvo_mutex_unlock(&rlun->mutex);
    }
    nuvo_mutex_unlock(&vol->mutex);
    return (rlun);
}

void nuvo_lun_move_pending_free_to_free(struct nuvo_vol *vol)
{
    nuvo_mutex_lock(&vol->mutex);

    unsigned int lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);

    for (unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);
        if (lun->lun_state == NUVO_LUN_STATE_FREE_PENDING)
        {
            NUVO_LOG(lun, 10, "lun(%d) to FREE lun_state(%d)", lun->snap_id, lun->lun_state);
            lun->lun_state = NUVO_LUN_STATE_FREE;
        }
    }
    nuvo_mutex_unlock(&vol->mutex);
}

static int32_t find_oldest_states(struct nuvo_vol *vol, enum nuvo_lun_state_e low_lun_state, enum nuvo_lun_state_e high_lun_state)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    unsigned int lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    int32_t      best_index = -1;
    for (unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);
        if (lun->lun_state < low_lun_state || lun->lun_state > high_lun_state)
        {
            continue;
        }
        if (best_index == -1 || lun->snap_id < vol->log_volume.lun_list[best_index].snap_id)
        {
            best_index = i;
        }
    }
    return (best_index);
}

/*
 * Look for the oldest DELETING. Called after replay
 */
void nuvo_lun_move_to_deleted_on_replay(struct nuvo_vol *vol)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    static int32_t best_index;
    while (-1 != (best_index = find_oldest_states(vol, NUVO_LUN_STATE_VALID, NUVO_LUN_STATE_DELETING)))
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[best_index]);

        NUVO_LOG_COND(lun, 0, lun->lun_state, "lun(%d) lun_state:%d media_addr(%lu:%lu)",
                      lun->snap_id, lun->lun_state,
                      lun->root_map_entry.media_addr.parcel_index,
                      lun->root_map_entry.media_addr.block_offset);

        if ((lun->lun_state != NUVO_LUN_STATE_DELETING) ||
            !NUVO_MAP_LUN_DELETING_DONE(lun))
        {
            break;
        }
        nuvo_mutex_unlock(&vol->mutex); // TODO urgh
        NUVO_LOG(lun, 10, "lun(%d) lun_state:%d -> DELETED", lun->snap_id, lun->lun_state);
        nuvo_mutex_lock(&lun->mutex);
        nuvo_map_lun_close(lun, &lun->root_map_entry);
        nuvo_return_t rc = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_DELETED, NUVO_LUN_EXPORT_UNEXPORTED);
        NUVO_ASSERT(rc == 0);
        nuvo_mutex_unlock(&lun->mutex);
        nuvo_mutex_lock(&vol->mutex);
    }
}

/*
 * Look for the oldest VALID or DELETING or DELETING_DRAIN.  If it is DELETING_DRAIN and pin count is 0 it can got to DELETED.
 * Loop.
 */
void nuvo_lun_move_to_deleted(struct nuvo_vol *vol)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    static int32_t best_index;
    while (-1 != (best_index = find_oldest_states(vol, NUVO_LUN_STATE_VALID, NUVO_LUN_STATE_DELETING_DRAIN)))
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[best_index]);

        // to go from deleting drain to deleted
        // the lun must have no pincounts
        // and mfl(hole punching) must be fully completed and rolled up to the root map.
        if (lun->lun_state != NUVO_LUN_STATE_DELETING_DRAIN || (lun->pin_count != 0) ||
            !NUVO_MAP_LUN_DELETING_DONE(lun))
        {
            break;
        }
        nuvo_mutex_unlock(&vol->mutex); // TODO urgh
        nuvo_mutex_lock(&lun->mutex);
        nuvo_map_lun_close(lun, &lun->root_map_entry);
        NUVO_LOG(lun, 10, "lun(%d)  lun_state:%d -> DELETED ", lun->snap_id, lun->lun_state);
        nuvo_return_t rc = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_DELETED, NUVO_LUN_EXPORT_UNEXPORTED);
        NUVO_ASSERT(rc == 0);
        nuvo_mutex_unlock(&lun->mutex);
        nuvo_mutex_lock(&vol->mutex);
    }
}

/*
 * move luns in MFL_CP_PENDING -> MFL_CP_IN_PROGRESS
 * mfl roll up must complete in MFL_CP_IN_PROGRESS state
 */

void  nuvo_lun_move_to_mfl_cp_in_progress(struct nuvo_vol *vol)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    unsigned int lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    for (unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);
        if ((lun->lun_state == NUVO_LUN_STATE_DELETING_DRAIN) &&
            (lun->mfl_state == NUVO_LUN_MFL_CP_PENDING))
        {
            nuvo_mutex_unlock(&vol->mutex); // TODO urgh
            nuvo_mutex_lock(&lun->mutex);
            NUVO_LOG(lun, 10, "lun(%d) lun_mfl_state:%d -> MFL CP PROGRESS", lun->snap_id, lun->lun_state);
            lun->mfl_state = NUVO_LUN_MFL_CP_IN_PROGRESS;
            nuvo_mutex_unlock(&lun->mutex);
            nuvo_mutex_lock(&vol->mutex);
        }
    }
}

/*
 * Look for any DELETED.  Move to FREE_PENDING.
 */
void nuvo_lun_move_to_free_pending(struct nuvo_vol *vol)
{
    NUVO_ASSERT_MUTEX_HELD(&vol->mutex);
    unsigned int lun_max_count = NUVO_ARRAY_LENGTH(vol->log_volume.lun_list);
    for (unsigned i = 1; i < lun_max_count; i++)
    {
        struct nuvo_lun *lun = &(vol->log_volume.lun_list[i]);

        if (lun->lun_state == NUVO_LUN_STATE_DELETED)
        {
            nuvo_mutex_unlock(&vol->mutex); // TODO urgh
            nuvo_mutex_lock(&lun->mutex);
            NUVO_LOG(lun, 10, "lun(%d) lun_state:%d -> FREE PENDING", lun->snap_id, lun->lun_state);
            nuvo_return_t rc = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_FREE_PENDING, NUVO_LUN_EXPORT_UNEXPORTED);
            NUVO_ASSERT(rc == 0);
            nuvo_mutex_unlock(&lun->mutex);
            nuvo_mutex_lock(&vol->mutex);
        }
    }
}
