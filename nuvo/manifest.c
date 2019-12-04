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
#include <stdlib.h>
#include <stdio.h>

#include "lun.h"
#include "nuvo.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "manifest.h"
#include "manifest_priv.h"
#include "segment.h"
#include "superblock.h"
#include "nuvo_vol_series.h"
#include "map.h"
#include <version_nuvo.h>

/**
 * @file manifest.c
 * @brief Implementation of the manifest.
 */

static void nuvo_mfst_calc_free_segments(struct nuvo_mfst *mfst);

static nuvo_return_t nuvo_mfst_get_active_lun_locked(struct nuvo_mfst *mfst,
                                                     struct nuvo_lun  *active_lun);

// Documented in header
nuvo_return_t nuvo_mfst_alloc_manifest(struct nuvo_mfst *mfst)
{
    memset(mfst, 0, sizeof(*mfst));
    nuvo_return_t ret;
    if (0 != (ret = nuvo_mutex_init(&mfst->mfst_mutex)))
    {
        return (ret);
    }
    if (0 != (ret = nuvo_cond_init(&mfst->cond_frozen)))
    {
        goto failed_cond;
    }

    nuvo_dlist_init(&mfst->pending_opens);
    nuvo_dlist_init(&mfst->unhealthy_parcels);

    memset(&mfst->header, 0, NUVO_BLOCK_SIZE);
    memset(&mfst->lun_table, 0, NUVO_MFST_LUN_TABLE_BLOCKS * NUVO_BLOCK_SIZE);

    nuvo_mfst_slog_init(&mfst->slog, NUVO_MFST_SLOG_MAX_ENTRIES);

    for (uint_fast16_t c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
    {
        mfst->data_class[c].device_most_free_segs = NUVO_NO_DEVICE_IN_CLASS;
    }
    for (uint_fast16_t dev_index = 0; dev_index < NUVO_MFST_DEVICE_LIMIT; dev_index++)
    {
        nuvo_dlist_init(&mfst->device_state_mem[dev_index].segs_for_gc);
    }

    nuvo_dlist_init(&mfst->segments_free_in_current_cp);
    nuvo_dlist_init(&mfst->segments_free_in_next_cp);
    return (0);

failed_cond:
    nuvo_mutex_destroy(&mfst->mfst_mutex);
    return (ret);
}

// Documented in header
void nuvo_mfst_free_manifest(struct nuvo_mfst *mfst)
{
    if (mfst->device_state_media)
    {
        free(mfst->device_state_media);
    }
    if (mfst->parcel_state_media)
    {
        free(mfst->parcel_state_media);
    }
    if (mfst->segment_state_media)
    {
        free(mfst->segment_state_media);
    }
    if (mfst->segment_state_mem)
    {
        free(mfst->segment_state_mem);
    }
    if (mfst->parcel_state_mem)
    {
        free(mfst->parcel_state_mem);
    }
    nuvo_mutex_destroy(&mfst->mfst_mutex);
    nuvo_cond_destroy(&mfst->cond_frozen);
}

// Documented in header
void nuvo_mfst_init_manifest_header(struct nuvo_mfst *mfst)
{
    mfst->header.magic = NUFO_MFST_MAGIC;
    mfst->header.generation = 0;
    mfst->header.num_used_devices = 0;
    mfst->header.num_used_parcels = 0;
    mfst->header.num_used_luns = 0;
    mfst->header.num_used_log_starts = 0;
    mfst->header.num_lun_blocks = NUVO_MFST_LUN_TABLE_BLOCKS;
    mfst->header.num_device_blocks = 0;
    mfst->header.num_parcel_blocks = 0;
    mfst->header.num_segment_blocks = 0;
    mfst->header.log_segment_count_seq_no = 0;
    mfst->header.log_start_seq_no = 0;
}

// Documented in header
void nuvo_mfst_set_superblock_info(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb)
{
    uuid_copy(mfst->vs_uuid, sb->vol_series_uuid);
    mfst->num_device_parcel_blocks =
        (sb->parcel_manifest[0].block_length < sb->parcel_manifest[1].block_length) ?
        sb->parcel_manifest[0].block_length : sb->parcel_manifest[1].block_length;
    mfst->num_segment_table_blocks =
        (sb->segment_table[0].block_length < sb->segment_table[1].block_length) ?
        sb->segment_table[0].block_length : sb->segment_table[1].block_length;
}

// Documented in header
nuvo_return_t nuvo_mfst_grow_devices_mem(struct nuvo_mfst *mfst, uint16_t num_devices)
{
    NUVO_MFST_ASSERT_CHANGING_MEDIA(mfst);
    uint32_t new_blocks = NUVO_MFST_DEVICES_TO_BLKS(num_devices);
    new_blocks = (new_blocks < mfst->header.num_device_blocks) ? mfst->header.num_device_blocks : new_blocks;
    if (new_blocks <= mfst->alloced_device_blocks)
    {
        return (0);
    }
    uint32_t old_size = mfst->alloced_device_blocks * NUVO_BLOCK_SIZE;
    uint32_t new_size = new_blocks * NUVO_BLOCK_SIZE;
    struct nuvo_mfst_device_entry *devices = aligned_alloc(NUVO_BLOCK_SIZE, new_size);
    if (devices == NULL)
    {
        return (-NUVO_ENOMEM);
    }
    if (old_size != 0)
    {
        memcpy(devices, mfst->device_state_media, old_size);
        free(mfst->device_state_media);
    }
    memset(((uint8_t *)devices) + old_size, 0, new_size - old_size);
    mfst->device_state_media = devices;

    mfst->alloced_device_blocks = new_blocks;
    mfst->header.num_device_blocks = new_blocks;

    return (0);
}

// Documented in header
nuvo_return_t nuvo_mfst_grow_segments_mem(struct nuvo_mfst *mfst, uint32_t num_segments)
{
    NUVO_MFST_ASSERT_CHANGING_MEDIA(mfst);
    uint32_t new_blocks = NUVO_MFST_SEGMENTS_TO_BLKS(num_segments);
    num_segments = NUVO_MFST_BLKS_TO_SEGMENTS(new_blocks);

    new_blocks = (new_blocks < mfst->header.num_segment_blocks) ? mfst->header.num_segment_blocks : new_blocks;
    if (new_blocks <= mfst->alloced_segment_blocks)
    {
        return (0);
    }

    uint32_t old_size = mfst->alloced_segment_blocks * NUVO_BLOCK_SIZE;
    uint32_t new_size = new_blocks * NUVO_BLOCK_SIZE;
    struct nuvo_mfst_segment_entry *sgmts = aligned_alloc(NUVO_BLOCK_SIZE, new_size);

    uint32_t old_pin_bytes = mfst->num_segment_allocated_indices * sizeof(struct nuvo_segment_pin_cnts);
    uint32_t new_pin_bytes = num_segments * sizeof(struct nuvo_segment_pin_cnts);
    struct nuvo_segment_pin_cnts *pin_cnts = malloc(new_pin_bytes);

    if (sgmts == NULL || pin_cnts == NULL)
    {
        if (sgmts)
        {
            free(sgmts);
        }
        if (pin_cnts)
        {
            free(pin_cnts);
        }
        return (-NUVO_ENOMEM);
    }
    if (mfst->segment_state_media)
    {
        memcpy(sgmts, mfst->segment_state_media, old_size);
        free(mfst->segment_state_media);
    }
    memset(((uint8_t *)sgmts) + old_size, 0, new_size - old_size);
    if (mfst->segment_state_mem)
    {
        memcpy(pin_cnts, mfst->segment_state_mem, old_pin_bytes);
        free(mfst->segment_state_mem);
    }
    memset(((uint8_t *)pin_cnts) + old_pin_bytes, 0, new_pin_bytes - old_pin_bytes);
    mfst->segment_state_media = sgmts;
    mfst->segment_state_mem = pin_cnts;
    mfst->num_segment_allocated_indices = num_segments;
    mfst->alloced_segment_blocks = new_blocks;
    mfst->header.num_segment_blocks = new_blocks;
    return (0);
}

// Documented in header
nuvo_return_t nuvo_mfst_grow_parcels_mem(struct nuvo_mfst *mfst, uint32_t num_parcels)
{
    NUVO_MFST_ASSERT_CHANGING_MEDIA(mfst);
    uint32_t new_blocks = NUVO_MFST_PARCELS_TO_BLKS(num_parcels);
    num_parcels = NUVO_MFST_BLKS_TO_PARCELS(new_blocks);
    new_blocks = (new_blocks < mfst->header.num_parcel_blocks) ? mfst->header.num_parcel_blocks : new_blocks;
    if (new_blocks <= mfst->alloced_parcel_blocks)
    {
        return (0);
    }

    // Get memory for the new parcels on-disk
    uint32_t old_size = mfst->alloced_parcel_blocks * NUVO_BLOCK_SIZE;
    uint32_t new_size = new_blocks * NUVO_BLOCK_SIZE;
    struct nuvo_mfst_parcel_entry *parcels = aligned_alloc(NUVO_BLOCK_SIZE, new_size);

    // Get memory for the new parcel-info in memory.
    uint32_t old_info_bytes = mfst->num_parcel_indices * sizeof(struct nuvo_mfst_parcel_state_mem);
    uint32_t new_info_bytes = num_parcels * sizeof(struct nuvo_mfst_parcel_state_mem);
    struct nuvo_mfst_parcel_state_mem *info = malloc(new_info_bytes);

    if (info == NULL || parcels == NULL)
    {
        if (info)
        {
            free(info);
        }
        if (parcels)
        {
            free(parcels);
        }
        return (-NUVO_ENOMEM);
    }

    if (mfst->parcel_state_media)
    {
        memcpy(parcels, mfst->parcel_state_media, old_size);
        free(mfst->parcel_state_media);
    }
    memset(((uint8_t *)parcels) + old_size, 0, new_size - old_size);
    if (mfst->parcel_state_mem)
    {
        memcpy(info, mfst->parcel_state_mem, old_info_bytes);
        free(mfst->parcel_state_mem);
    }
    memset(((uint8_t *)info) + old_info_bytes, 0, new_info_bytes - old_info_bytes);
    for (unsigned int i = mfst->num_parcel_indices; i < num_parcels; i++)
    {
        info[i].state = NUVO_MFST_PARCEL_NONE;
        info[i].health_status = NUVO_PR_PARCEL_UNAVAILABLE;
    }
    mfst->parcel_state_media = parcels;
    mfst->parcel_state_mem = info;
    mfst->num_parcel_indices = num_parcels;
    mfst->alloced_parcel_blocks = new_blocks;
    mfst->header.num_parcel_blocks = new_blocks;

    return (0);
}

// Documented in header
nuvo_return_t nuvo_mfst_find_device_index(struct nuvo_mfst *mfst, const uuid_t device_uuid, uint_fast32_t *index)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint32_t num_devices = NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks);
    for (*index = 0; *index < num_devices; (*index)++)
    {
        if (0 == uuid_compare(device_uuid, mfst->device_state_media[*index].device_uuid))
        {
            return (0);
        }
    }
    return (-NUVO_ENOENT);
}

// Documented in header
nuvo_return_t nuvo_mfst_find_parcel_index(struct nuvo_mfst *mfst, uuid_t parcel_uuid, uint_fast32_t *index)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    for (*index = 0; *index < mfst->num_parcel_indices; (*index)++)
    {
        if (mfst->parcel_state_media[*index].type == NUVO_MFST_PARCEL_ENTRY_PARCEL &&
            0 == uuid_compare(parcel_uuid, mfst->parcel_state_media[*index].normal.parcel_uuid))
        {
            return (0);
        }
    }
    return (-NUVO_ENOENT);
}

nuvo_return_t nuvo_mfst_find_highest_parcel_index(struct nuvo_mfst *mfst,
                                                  uuid_t            parcel_uuid,
                                                  uuid_t            device_uuid)
{
    nuvo_return_t index;

    for (index = mfst->num_parcel_indices - 1; index > 0; index--)
    {
        if (mfst->parcel_state_media[index].type != NUVO_MFST_PARCEL_ENTRY_PARCEL)
        {
            continue;
        }
        uuid_copy(parcel_uuid, mfst->parcel_state_media[index].normal.parcel_uuid);
        uuid_copy(device_uuid, mfst->device_state_media[mfst->parcel_state_media[index].normal.device_idx].device_uuid);
        break;
    }
    return (index);
}

/**
 * \brief How many devices in the list are not already in the manifest.
 *
 * This computes how many new devices will be added to the manifest with the
 * addition of the devices in \c devices.  Assumes repeats are possible.
 *
 * \param mfst The manifest.
 * \param num The number of devices on the list.
 * \param devices the list of devices.
 * \returns The number of new devices entries that will be created.
 */
uint_fast32_t nuvo_mfst_count_new_devices(struct nuvo_mfst                    *mfst,
                                          unsigned int                         num,
                                          struct nuvo_mfst_insert_device_info *devices)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t new_devices = 0;
    for (uint_fast32_t i = 0; i < num; i++)
    {
        uint_fast32_t device_index;
        if (0 == nuvo_mfst_find_device_index(mfst, devices[i].device_uuid, &device_index))
        {
            continue;
        }
        bool prev_found = false;
        for (uint_fast32_t j = 0; j < i; j++)
        {
            if (0 == uuid_compare(devices[i].device_uuid, devices[j].device_uuid))
            {
                prev_found = true;
                break;
            }
        }
        if (!prev_found)
        {
            new_devices++;
        }
    }
    return (new_devices);
}

/**
 * \brief Is a given index in the device table in use.
 *
 * \brief mfst The manifest.
 * \brief dev_index The index to check.
 * \retval 0 if unused
 * \retval non-zero if used
 */
static inline int nuvo_mfst_device_in_use(struct nuvo_mfst *mfst, uint_fast32_t dev_index)
{
    return (!uuid_is_null(mfst->device_state_media[dev_index].device_uuid));
}

/**
 * \brief Find and return the index of an unused device.
 *
 * It is assumed that this is only called after ensuring there is space in the device
 * table.  Not finding space is a programming bug, not an expected error condition.
 *
 * \brief mfst The manifest.
 * \returns The index into the device table.
 */
uint_fast32_t nuvo_mfst_find_unused_device(struct nuvo_mfst *mfst)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint32_t num_devices = NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks);
    for (uint_fast32_t i = 0; i < num_devices; i++)
    {
        if (!nuvo_mfst_device_in_use(mfst, i))
        {
            return (i);
        }
    }
    // We grew the table or returned error above to avoid this!
    NUVO_PANIC("No unused device available.");
    return (0);
}

// Documented in header
nuvo_return_t nuvo_mfst_insert_devices(struct nuvo_mfst                    *mfst,
                                       unsigned int                         num,
                                       struct nuvo_mfst_insert_device_info *devices)
{
    nuvo_mfst_parcels_change_lock(mfst);
    nuvo_return_t ret = 0;

    for (uint_fast32_t i = 0; i < num; i++)
    {
        if (devices[i].device_class >= NUVO_MAX_DATA_CLASSES)
        {
            NUVO_ERROR_PRINT("Adding bad device class.");
            ret = -NUVO_E_DEVICE_CLASS_BAD;
            goto unlock;
        }
        if (devices[i].device_type >= NUVO_MAX_DEV_TYPES)
        {
            NUVO_ERROR_PRINT("Adding bad device type.");
            ret = -NUVO_E_DEVICE_TYPE_BAD;
            goto unlock;
        }
        uint_fast32_t dev_index;
        ret = nuvo_mfst_find_device_index(mfst, devices[i].device_uuid, &dev_index);
        if (ret == 0)
        {
            if (mfst->device_state_media[dev_index].device_class != devices[i].device_class)
            {
                NUVO_ERROR_PRINT("Re-adding device with different data class.");
                ret = -NUVO_E_DEVICE_CLASS_CHANGED;
                goto unlock;
            }
        }
    }

    uint_fast32_t new_device_cnt = mfst->header.num_used_devices + nuvo_mfst_count_new_devices(mfst, num, devices);
    uint32_t      blocks_needed = 1 + mfst->header.num_lun_blocks + NUVO_MFST_DEVICES_TO_BLKS(new_device_cnt) + mfst->header.num_parcel_blocks;
    if (blocks_needed > mfst->num_device_parcel_blocks)
    {
        ret = -NUVO_ENOSPC;
        goto unlock;
    }
    // We have a big enough disk space.  Let's get memory.
    ret = nuvo_mfst_grow_devices_mem(mfst, new_device_cnt);
    if (ret != 0)
    {
        goto unlock;
    }

    /*
     * The memory space is big enough now. Let's actually start making changes.
     * We've ensured success.
     */
    for (uint_fast32_t i = 0; i < num; i++)
    {
        uint_fast32_t dev_index;
        ret = nuvo_mfst_find_device_index(mfst, devices[i].device_uuid, &dev_index);
        if (ret != 0)
        {
            NUVO_ASSERT(ret == -NUVO_ENOENT);
            dev_index = nuvo_mfst_find_unused_device(mfst);
            mfst->header.num_used_devices++;
            uuid_copy(mfst->device_state_media[dev_index].device_uuid, devices[i].device_uuid);
            mfst->device_state_media[dev_index].device_class = devices[i].device_class;
            mfst->device_state_media[dev_index].parcel_size_in_blocks = devices[i].parcel_size_in_blocks;
            mfst->device_state_media[dev_index].target_parcels = 0;
            mfst->device_state_media[dev_index].alloced_parcels = 0;
            mfst->device_state_mem[dev_index].free_segments = 0;
            mfst->device_state_mem[dev_index].gc_free_current_cp = 0;
            mfst->device_state_mem[dev_index].gc_free_next_cp = 0;
            mfst->device_state_mem[dev_index].segments_in_gc = 0;
            mfst->device_state_mem[dev_index].device_type = devices[i].device_type;
            NUVO_LOG(mfst, 10, "Adding device:" NUVO_LOG_UUID_FMT ", index: %d, type: %d, class: %d, size: %u blocks", NUVO_LOG_UUID(devices[i].device_uuid), dev_index, devices[i].device_type, devices[i].device_class, devices[i].parcel_size_in_blocks);
            insert_device_in_free_segment_list(mfst, dev_index);
            ret = 0;
        }
    }
    // Have now changed in-core state.
    ret = 0;
unlock:
    nuvo_mfst_parcels_change_unlock(mfst);
    return (ret);
}

// Documented in header
nuvo_return_t nuvo_mfst_insert_device(struct nuvo_mfst        *mfst,
                                      const uuid_t             device_uuid,
                                      const uint8_t            device_class,
                                      const enum nuvo_dev_type device_type,
                                      const uint32_t           parcel_size_blocks)
{
    struct nuvo_mfst_insert_device_info device;

    uuid_copy(device.device_uuid, device_uuid);
    device.device_class = device_class;
    device.parcel_size_in_blocks = parcel_size_blocks;
    device.device_type = device_type;
    return (nuvo_mfst_insert_devices(mfst, 1, &device));
}

/*
 * \brief How many usable blocks do we get per parcel in this device.
 *
 * How many blocks are we going to get when we add a parcel on this device.
 *
 * \param mfst  The manifest
 * \param dev_index The device index in the manifest.
 */
static uint64_t nuvo_mfst_usable_blocks_per_parcel(struct nuvo_mfst *mfst, uint_fast32_t dev_index)
{
    uint32_t segment_size = NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    uint32_t num_segments = mfst->device_state_media[dev_index].parcel_size_in_blocks / segment_size;

    if (num_segments > NUVO_SEGMENT_CNT_MAX)
    {
        num_segments = NUVO_SEGMENT_CNT_MAX;
    }
    return (num_segments * segment_size);
}

// Documented in header
nuvo_return_t nuvo_mfst_device_parcel_target(struct nuvo_mfst *mfst,
                                             const uuid_t      device_uuid,
                                             uint16_t          num)
{
    uint_fast32_t dev_index;

    nuvo_mfst_parcels_change_lock(mfst);
    nuvo_return_t rc = nuvo_mfst_find_device_index(mfst, device_uuid, &dev_index);
    // TODO - would be nice to reject giving back target if we're going to run out of space.
    if (rc == 0)
    {
        int32_t old_available = mfst->device_state_media[dev_index].target_parcels - mfst->device_state_media[dev_index].alloced_parcels;
        old_available = (old_available < 0) ? 0 : old_available;
        int32_t new_available = num - mfst->device_state_media[dev_index].alloced_parcels;
        new_available = (new_available < 0) ? 0 : new_available;
        mfst->data_class[mfst->device_state_media[dev_index].device_class].available_parcels += (new_available - old_available);
        mfst->data_class[mfst->device_state_media[dev_index].device_class].total_parcel_blocks +=
            (num - mfst->device_state_media[dev_index].target_parcels) * nuvo_mfst_usable_blocks_per_parcel(mfst, dev_index);
        mfst->device_state_media[dev_index].target_parcels = num;
    }
    nuvo_mfst_parcels_change_unlock(mfst);
    return (rc);
}

/* Insert parcels */

/**
 * \brief Find an unused parcel index in the manifest and its segment index.
 *
 * This assumes that you have already ensured the search will not fail.
 * This starts searching at index 0 and works from there.  In practice,
 * could probably start at the end.  Doing it this way so when we have holes
 * due to parcel deletion we pack the table.
 *
 * \param mfst The manifest.
 * \param parcel_index To return the parcel index.
 * \param segment_index To return the segment index.
 */
void nuvo_mfst_find_unused_parcel(struct nuvo_mfst *mfst,
                                  uint_fast32_t    *parcel_index,
                                  uint_fast32_t    *segment_index)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    *segment_index = 0;
    for (uint_fast32_t i = 0; i < mfst->num_parcel_indices; i++)
    {
        if (NUVO_MFST_PARCEL_ENTRY_UNUSED == mfst->parcel_state_media[i].type)
        {
            *parcel_index = i;
            return;
        }
        if (NUVO_MFST_PARCEL_ENTRY_PARCEL == mfst->parcel_state_media[i].type)
        {
            *segment_index += nuvo_mfst_parcel_segment_number_get(mfst, i);
        }
    }
    // We grew the table or returned error above to avoid this!
    NUVO_PANIC("No unused parcel available.");
}

// Documented in header
extern inline void nuvo_mfst_parcel_segment_size_set(struct nuvo_mfst *mfst, uint_fast32_t index, uint_fast32_t size);

// Documented in header
extern inline uint32_t nuvo_mfst_parcel_segment_size_get(struct nuvo_mfst *mfst, uint_fast32_t index);

// Documented in header
extern inline void nuvo_mfst_parcel_segment_number_set(struct nuvo_mfst *mfst, uint_fast32_t index, uint_fast32_t number);

// Documented in header
extern inline uint16_t nuvo_mfst_parcel_segment_number_get(struct nuvo_mfst *mfst, uint_fast32_t index);

/*
 * Inserting or removing a parcel at parcel_index.
 *
 * Every segment for every parcel above must move up, or down. If they are moving up, zero every vacated space.
 * Same if they move down.  Moving the segment pin counts and the segments is the easy part.  Then we have to
 * change the segment_offset within each parcel_state_mem that gets changed.
 *
 * If we are moving things up, the hole appears in the middle of the segment table.  If we are moving things
 * down, the hole appears at the end.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index we are adding or removing.  Every segment above is shifting.
 * \param segment_index The first segment index that is shifting.  This could be equal to num_segment_indices.
 * \param segment_cnt How far they are shifting.
 */
void move_segments(struct nuvo_mfst *mfst, uint_fast32_t parcel_index, uint_fast32_t segment_index, int_fast32_t segment_cnt)
{
    NUVO_MFST_ASSERT_CHANGING_MEDIA(mfst);
    NUVO_ASSERT(parcel_index < mfst->num_parcel_indices);

    uint_fast32_t new_sgmt_index = segment_index + segment_cnt;
    uint_fast32_t moved_segments = mfst->num_segment_indices - segment_index;
    memmove(&mfst->segment_state_mem[new_sgmt_index],
            &mfst->segment_state_mem[segment_index],
            moved_segments * sizeof(mfst->segment_state_mem[0]));
    // move on-disk segment info
    memmove(&mfst->segment_state_media[new_sgmt_index],
            &mfst->segment_state_media[segment_index],
            moved_segments * sizeof(mfst->segment_state_media[0]));
    for (uint_fast32_t i = parcel_index + 1; i < mfst->num_parcel_indices; i++)
    {
        if (NUVO_MFST_PARCEL_ENTRY_PARCEL == mfst->parcel_state_media[i].type)
        {
            mfst->parcel_state_mem[i].segment_offset += segment_cnt;
        }
    }

    uint32_t hole, hole_cnt;
    if (segment_cnt > 0)
    {
        hole = segment_index;
        hole_cnt = segment_cnt;
    }
    else
    {
        hole_cnt = -segment_cnt;
        hole = mfst->num_segment_indices + segment_cnt;
    }
    for (int_fast32_t i = 0; i < hole_cnt; i++)
    {
        mfst->segment_state_mem[hole + i].seg_io = 0;
        mfst->segment_state_mem[hole + i].seg_space_used = 0;
        mfst->segment_state_media[hole + i].seg_age = 0;
        mfst->segment_state_media[hole + i].seg_blks_used = 0;
        mfst->segment_state_media[hole + i].seg_reserved = 0;
    }

    mfst->num_segment_indices += segment_cnt;
}

// Documented in header
nuvo_return_t nuvo_mfst_insert_parcels(struct nuvo_mfst                    *mfst,
                                       unsigned int                         num_parcels,
                                       struct nuvo_mfst_parcel_insert_info *parcels)
{
    nuvo_mfst_parcels_change_lock(mfst);
    nuvo_return_t ret;
    // We're supposed to add devices first.
    uint32_t new_segments_needed = mfst->num_segment_indices;
    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        uint_fast32_t dev_index;
        ret = nuvo_mfst_find_device_index(mfst, parcels[i].device_uuid, &dev_index);
        if (ret != 0)
        {
            goto unlock;
        }
        if (parcels[i].segment_size_bytes % NUVO_SEGMENT_SIZE_INCREMENT != 0 ||
            parcels[i].segment_size_bytes < NUVO_SEGMENT_MIN_SIZE_BYTES ||
            parcels[i].segment_size_bytes > NUVO_SEGMENT_MAX_SIZE_BYTES)
        {
            NUVO_ERROR_PRINT("Invalid segment size");
            ret = -NUVO_EINVAL;
            goto unlock;
        }
        // Squirrel away the device_class so caller can know.
        parcels[i].device_class = mfst->device_state_media[dev_index].device_class;
        if (parcels[i].number_segments == 0)
        {
            // This is the "use as many segments as I can fit" case.  If it's too many
            // we'll fail in next test.  Which is good.
            parcels[i].number_segments = (mfst->device_state_media[dev_index].parcel_size_in_blocks * NUVO_BLOCK_SIZE) /
                                         parcels[i].segment_size_bytes;
        }
        if (parcels[i].number_segments < NUVO_SEGMENT_CNT_MIN ||
            parcels[i].number_segments > NUVO_SEGMENT_CNT_MAX)
        {
            NUVO_ERROR_PRINT("Invalid number of segments");
            ret = -NUVO_EINVAL;
            goto unlock;
        }
        if (parcels[i].number_segments * parcels[i].segment_size_bytes >
            mfst->device_state_media[dev_index].parcel_size_in_blocks * NUVO_BLOCK_SIZE)
        {
            NUVO_ERROR_PRINT("Too many/too large parcels for device");
            ret = -NUVO_EINVAL;
            goto unlock;
        }
        new_segments_needed += parcels[i].number_segments;
        uint_fast32_t parcel_index;
        ret = nuvo_mfst_find_parcel_index(mfst, parcels[i].parcel_uuid, &parcel_index);
        if (ret != -NUVO_ENOENT)
        {
            ret = -NUVO_EEXIST;
            goto unlock;
        }
        // TODO - should we check for duplicate parcels within adding list?
    }

    uint_fast32_t new_parcel_cnt = mfst->header.num_used_parcels + num_parcels;
    uint32_t      blocks_needed = 1 + mfst->header.num_lun_blocks + mfst->header.num_device_blocks + NUVO_MFST_PARCELS_TO_BLKS(new_parcel_cnt);
    if (blocks_needed > mfst->num_device_parcel_blocks ||
        NUVO_MFST_SEGMENTS_TO_BLKS(new_segments_needed) > mfst->num_segment_table_blocks)
    {
        ret = -NUVO_ENOSPC;
        goto unlock;
    }

    // We have a big enough disk space.  Let's get memory.
    ret = nuvo_mfst_grow_segments_mem(mfst, new_segments_needed);
    if (ret != 0)
    {
        goto unlock;
    }
    ret = nuvo_mfst_grow_parcels_mem(mfst, new_parcel_cnt);
    if (ret != 0)
    {
        // Todor would really like it if I shrunk the allocated spaced of the segments here.
        goto unlock;
    }

    /*
     * The memory space is big enough now. Let's actually start making changes.
     * We've ensured success.
     */
    ret = 0;
    for (uint_fast32_t i = 0; i < num_parcels; i++)
    {
        uint_fast32_t dev_index;
        ret = nuvo_mfst_find_device_index(mfst, parcels[i].device_uuid, &dev_index);
        NUVO_ASSERT(ret == 0);
        if (mfst->device_state_media[dev_index].alloced_parcels < mfst->device_state_media[dev_index].target_parcels)
        {
            mfst->data_class[mfst->device_state_media[dev_index].device_class].available_parcels--;
        }
        mfst->device_state_media[dev_index].alloced_parcels++;
        mfst->header.num_used_parcels++;

        uint_fast32_t parcel_index;
        uint_fast32_t segment_index;
        nuvo_mfst_find_unused_parcel(mfst, &parcel_index, &segment_index);

        uint_fast32_t seg_idx = (parcel_index == 0) ? 0 : mfst->parcel_state_mem[parcel_index - 1].segment_offset +
                                nuvo_mfst_parcel_segment_number_get(mfst, parcel_index - 1);

        move_segments(mfst, parcel_index, seg_idx, parcels[i].number_segments);

        mfst->parcel_state_media[parcel_index].type = NUVO_MFST_PARCEL_ENTRY_PARCEL;
        uuid_copy(mfst->parcel_state_media[parcel_index].normal.parcel_uuid, parcels[i].parcel_uuid);
        mfst->parcel_state_media[parcel_index].normal.device_idx = dev_index;
        mfst->parcel_state_mem[parcel_index].parcel_desc = parcels[i].pd;
        mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_ADDING;
        mfst->parcel_state_mem[parcel_index].segment_offset = seg_idx;
        nuvo_mfst_parcel_segment_number_set(mfst, parcel_index, parcels[i].number_segments);
        nuvo_mfst_parcel_segment_size_set(mfst, parcel_index, parcels[i].segment_size_bytes);
        NUVO_LOG(mfst, 10, "Adding parcel:" NUVO_LOG_UUID_FMT ", idx: %d, device %d, with %d segments of size %d",
                 NUVO_LOG_UUID(parcels[i].parcel_uuid), parcel_index, dev_index, parcels[i].number_segments, parcels[i].segment_size_bytes);
    }
    // Have now changed in-core state.
unlock:
    nuvo_mfst_parcels_change_unlock(mfst);
    return (ret);
}

// Documented in header
nuvo_return_t nuvo_mfst_insert_parcel(struct nuvo_mfst *mfst,
                                      const uuid_t      device_uuid,
                                      const uuid_t      parcel_uuid,
                                      const uint32_t    segment_size_bytes,
                                      uint16_t         *number_segments,
                                      uint8_t          *device_class,
                                      uint_fast32_t     pd)
{
    struct nuvo_mfst_parcel_insert_info parcel;

    uuid_copy(parcel.device_uuid, device_uuid);
    uuid_copy(parcel.parcel_uuid, parcel_uuid);
    parcel.segment_size_bytes = segment_size_bytes;
    parcel.number_segments = *number_segments;
    parcel.pd = pd;
    nuvo_return_t rc = nuvo_mfst_insert_parcels(mfst, 1, &parcel);
    if (rc >= 0)
    {
        *number_segments = parcel.number_segments;
        *device_class = parcel.device_class;
    }
    return (rc);
}

// Documented in header
nuvo_return_t nuvo_mfst_remove_parcels(struct nuvo_mfst *mfst,
                                       unsigned int      num,
                                       uuid_t           *uuid,
                                       bool              destroying)
{
    nuvo_mfst_parcels_change_lock(mfst);
    nuvo_return_t ret;
    uint_fast32_t parcel_index;
    for (uint_fast32_t i = 0; i < num; i++)
    {
        ret = nuvo_mfst_find_parcel_index(mfst, uuid[i], &parcel_index);
        if (ret != 0)
        {
            goto unlock;
        }
        NUVO_ASSERT(mfst->parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_PARCEL);
        if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_USABLE &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_ADDING)
        {
            ret = -NUVO_E_PARCEL_IN_USE;
            goto unlock;
        }

        /*
         * Check for segments in use, pins and logging currently is
         * protected by the above check on the parcel state, since
         * we cannot close parcels that are in active use.  Checking here
         * anyway, because I'm superstitious and someday parcel descriptors
         * may start failing.
         */
        if (!destroying)
        {
            uint_fast32_t num_segments = nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
            for (i = 0; i < num_segments; i++)
            {
                uint_fast32_t seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset + i;
                if (NUVO_SEGMENT_IN_USE(mfst, seg_idx))
                {
                    ret = -NUVO_E_PARCEL_IN_USE;
                    goto unlock;
                }
            }
        }
    }

    /*
     * Checked that we are all good.  Now do it.
     * Inefficient but correct beats efficient but incorrect.
     * I hope this is the former.  Which guarantees a bug here :(
     */
    for (uint_fast32_t i = 0; i < num; i++)
    {
        ret = nuvo_mfst_find_parcel_index(mfst, uuid[i], &parcel_index);
        NUVO_ASSERT(ret == 0);
        mfst->device_state_media[mfst->parcel_state_media[parcel_index].normal.device_idx].alloced_parcels--;
        mfst->header.num_used_parcels--;

        uint_fast32_t seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset +
                                nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
        int_fast32_t num_segs = -nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);

        mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_NONE;
        mfst->parcel_state_mem[parcel_index].health_status = NUVO_PR_PARCEL_UNAVAILABLE;
        memset(&mfst->parcel_state_media[parcel_index], 0, sizeof(mfst->parcel_state_media[parcel_index]));
        memset(&mfst->parcel_state_mem[parcel_index], 0, sizeof(mfst->parcel_state_mem[parcel_index]));
        mfst->parcel_state_media[parcel_index].type = NUVO_MFST_PARCEL_ENTRY_UNUSED;

        move_segments(mfst, parcel_index, seg_idx, num_segs);
    }
    ret = 0;
unlock:
    nuvo_mfst_parcels_change_unlock(mfst);
    return (ret);
}

nuvo_return_t nuvo_mfst_set_parcel_health(struct nuvo_vol           *vol,
                                          uuid_t                     parcel_uuid,
                                          enum nuvo_pr_parcel_status status)
{
    nuvo_return_t     ret = 0;
    struct nuvo_mfst *mfst = &vol->log_volume.mfst;
    struct nuvo_mfst_parcel_state_mem *mfst_parcel = NULL;
    uint_fast32_t parcel_index;

    nuvo_mfst_in_core_lock(mfst);

    ret = nuvo_mfst_find_parcel_index(mfst, parcel_uuid, &parcel_index);
    if (ret != 0)
    {
        nuvo_mfst_in_core_unlock(mfst);
        return (ret);
    }

    mfst_parcel = &mfst->parcel_state_mem[parcel_index];

    if (status == NUVO_PR_PARCEL_HEALTHY)
    {
        if (nuvo_dlnode_on_list(&mfst_parcel->list_node))
        {
            nuvo_dlist_remove(&mfst_parcel->list_node);
        }
        else
        {
            NUVO_LOG(mfst, 20, "Vol " NUVO_LOG_UUID_FMT " unhealthy parcel list did not contain parcel %u. Parcel already healthy.",
                     NUVO_LOG_UUID(vol->vs_uuid), mfst_parcel->parcel_desc);
        }
    }
    else if (status == NUVO_PR_PARCEL_UNAVAILABLE)
    {
        if (nuvo_dlnode_on_list(&mfst_parcel->list_node))
        {
            NUVO_LOG(mfst, 20, "Vol " NUVO_LOG_UUID_FMT " already has unhealthy parcel %u in list.",
                     NUVO_LOG_UUID(vol->vs_uuid), mfst_parcel->parcel_desc);
        }
        else
        {
            nuvo_dlist_insert_tail(&mfst->unhealthy_parcels,
                                   &mfst_parcel->list_node);
        }
    }
    else
    {
        NUVO_ASSERT(!"Invalid Parcel State");
    }
    mfst_parcel->health_status = status;

    nuvo_mfst_in_core_unlock(mfst);

    return (ret);
}

bool nuvo_mfst_are_all_parcels_healthy(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);
    if (nuvo_dlist_empty(&mfst->unhealthy_parcels))
    {
        nuvo_mfst_in_core_unlock(mfst);
        return (true);
    }

    nuvo_mfst_in_core_unlock(mfst);
    return (false);
}

void nuvo_mfst_open_parcel_start(struct nuvo_mfst_open_parcel *op);
void nuvo_mfst_open_parcel_alloc_cb(struct nuvo_pr_req_alloc *req);
void nuvo_mfst_open_parcel_io_cb(struct nuvo_io_request *io_req);

// Documented in header.
void nuvo_mfst_open_parcel_start(struct nuvo_mfst_open_parcel *op)
{
    nuvo_dlnode_init(&op->node);
    nuvo_mfst_in_core_lock(op->mfst);
    switch (op->mfst->parcel_state_mem[op->idx].state)
    {
    case NUVO_MFST_PARCEL_USABLE:
        op->mfst->parcel_state_mem[op->idx].state = NUVO_MFST_PARCEL_OPENING;
        uuid_copy(op->vs_uuid, op->mfst->vs_uuid);
        uuid_copy(op->device_uuid, op->mfst->device_state_media[op->mfst->parcel_state_media[op->idx].normal.device_idx].device_uuid);
        uuid_copy(op->parcel_uuid, op->mfst->parcel_state_media[op->idx].normal.parcel_uuid);
        op->req_alloc.callback = nuvo_mfst_open_parcel_alloc_cb;
        op->req_alloc.tag.ptr = op;
        nuvo_mfst_in_core_unlock(op->mfst);
        nuvo_pr_client_req_alloc_cb(&op->req_alloc);
        return;

    case NUVO_MFST_PARCEL_OPENING:
        nuvo_dlist_insert_tail(&op->mfst->pending_opens, &op->node);
        goto no_callback;

    case NUVO_MFST_PARCEL_OPEN:
        op->status = 0;
        op->parcel_desc = op->mfst->parcel_state_mem[op->idx].parcel_desc;
        goto do_callback;

    default:
        op->status = -NUVO_E_PARCEL_UNUSABLE;  // Todor would prefer death here.
        goto do_callback;
    }
no_callback:
    nuvo_mfst_in_core_unlock(op->mfst);
    return;

do_callback:
    nuvo_mfst_in_core_unlock(op->mfst);
    op->callback(op);
}

// Documented in header.
void nuvo_mfst_open_parcel_alloc_cb(struct nuvo_pr_req_alloc *req)
{
    struct nuvo_mfst_open_parcel *op = (struct nuvo_mfst_open_parcel *)req->tag.ptr;

    op->io_req = op->req_alloc.req;
    op->io_req->operation = NUVO_OP_OPEN;
    uuid_copy(op->io_req->open.volume_uuid, op->vs_uuid);
    uuid_copy(op->io_req->open.device_uuid, op->device_uuid);
    uuid_copy(op->io_req->open.parcel_uuid, op->parcel_uuid);
    op->io_req->open.reopen_flag = 0;
    op->io_req->callback = nuvo_mfst_open_parcel_io_cb;
    op->io_req->tag.ptr = op;
    nuvo_pr_submit_req(op->io_req);
}

// Documented in header.
void nuvo_mfst_open_parcel_io_cb(struct nuvo_io_request *io_req)
{
    struct nuvo_mfst_open_parcel *op = (struct nuvo_mfst_open_parcel *)io_req->tag.ptr;

    op->status = io_req->status;

    nuvo_mfst_in_core_lock(op->mfst);

    if (op->status == 0)
    {
        op->mfst->parcel_state_mem[op->idx].parcel_desc = io_req->open.parcel_desc;
        op->parcel_desc = io_req->open.parcel_desc;
        op->mfst->parcel_state_mem[op->idx].state = NUVO_MFST_PARCEL_OPEN;
    }
    else
    {
        op->mfst->parcel_state_mem[op->idx].state = NUVO_MFST_PARCEL_USABLE;
    }

    nuvo_pr_client_req_free(io_req);

    struct nuvo_dlist done_list;
    nuvo_dlist_init(&done_list);
    struct nuvo_mfst_open_parcel *cur_req = nuvo_dlist_get_head_object(&op->mfst->pending_opens, struct nuvo_mfst_open_parcel, node);
    while (cur_req != NULL)
    {
        struct nuvo_mfst_open_parcel *next_req = nuvo_dlist_get_next_object(&op->mfst->pending_opens, cur_req, struct nuvo_mfst_open_parcel, node);
        if (cur_req->idx == op->idx)
        {
            nuvo_dlist_remove(&cur_req->node);
            nuvo_dlist_insert_tail(&done_list, &cur_req->node);
            cur_req = next_req;
        }
    }

    nuvo_mfst_in_core_unlock(op->mfst);

    while (NULL != (cur_req = nuvo_dlist_remove_head_object(&done_list, struct nuvo_mfst_open_parcel, node)))
    {
        cur_req->status = op->status;
        cur_req->parcel_desc = op->parcel_desc;
        cur_req->callback(cur_req);
    }
    op->callback(op);
}

// Documented in header.
void nuvo_mfst_open_parcel_sync_cb(struct nuvo_mfst_open_parcel *open)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)open->tag.ptr);
}

// Documented in header.
nuvo_return_t nuvo_mfst_open_parcel_sync(struct nuvo_mfst *mfst, uint_fast32_t parcel_index, uint_fast32_t *parcel_desc)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (-NUVO_ENOMEM);
    }
    struct nuvo_mfst_open_parcel open;
    open.mfst = mfst;
    open.idx = parcel_index;
    open.callback = nuvo_mfst_open_parcel_sync_cb;
    open.tag.ptr = &sync_signal;
    nuvo_mutex_lock(&sync_signal);
    nuvo_mfst_open_parcel_start(&open);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);
    *parcel_desc = open.parcel_desc;
    return (open.status);
}

// Documented in header.
nuvo_return_t nuvo_mfst_close_parcel(struct nuvo_mfst *mfst, uint_fast32_t parcel_index)
{
    nuvo_return_t rc;

    nuvo_mfst_in_core_lock(mfst);
    if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
    {
        rc = -NUVO_E_PARCEL_NOT_OPEN;
        goto unlock;
    }
    NUVO_ASSERT(mfst->parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_PARCEL);
    for (uint_fast32_t i = 0; i < nuvo_mfst_parcel_segment_number_get(mfst, parcel_index); i++)
    {
        uint_fast32_t segment_index = mfst->parcel_state_mem[parcel_index].segment_offset + i;
        if (0 != mfst->segment_state_mem[segment_index].seg_io ||
            0 != mfst->segment_state_mem[segment_index].seg_space_used)
        {
            // Don't close out from under users.  It's not polite.
            NUVO_ERROR_PRINT("CLOSING WITH SEGMENT IN USE!");
            rc = -NUVO_E_PARCEL_IN_USE;
            goto unlock;
        }
    }

    uint_fast32_t parcel_desc = mfst->parcel_state_mem[parcel_index].parcel_desc;
    mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_USABLE;
    mfst->parcel_state_mem[parcel_index].parcel_desc = NUVO_VOL_PD_UNUSED;
    nuvo_mfst_in_core_unlock(mfst);
    // If it fails, there is really nothing we can do.
    return (nuvo_pr_sync_parcel_close(parcel_desc));

unlock:
    nuvo_mfst_in_core_unlock(mfst);
    return (rc);
}

nuvo_return_t nuvo_mfst_close_all_parcels(struct nuvo_mfst *mfst)
{
    nuvo_return_t rc;

    nuvo_mfst_in_core_lock(mfst);
    for (unsigned parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
    {
        // Only calling during close volume.
        // TODO - handle ADDING OR OPENING?
        NUVO_ASSERT(mfst->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_USABLE ||
                    mfst->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_NONE ||
                    mfst->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_OPEN);
        if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
        {
            continue;
        }
        nuvo_mfst_in_core_unlock(mfst);
        rc = nuvo_mfst_close_parcel(mfst, parcel_index);
        NUVO_ASSERT(rc >= 0);
        if (rc < 0)
        {
            return (rc);
        }
        nuvo_mfst_in_core_lock(mfst);
    }
    for (unsigned parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
    {
        NUVO_ASSERT(mfst->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_USABLE ||
                    mfst->parcel_state_mem[parcel_index].state == NUVO_MFST_PARCEL_NONE);
    }
    nuvo_mfst_in_core_unlock(mfst);
    return (0);
}

nuvo_return_t nuvo_mfst_close(struct nuvo_mfst *mfst)
{
    NUVO_ASSERT(!mfst->frozen);
    nuvo_return_t rc = nuvo_mfst_close_all_parcels(mfst);
    NUVO_ASSERT(rc >= 0);
    nuvo_mfst_free_manifest(mfst);
    return (rc);
}

/**
 * \brief hash the manifest header, device table, parcel table and segment table.
 *
 * Hash the entire allocated memory for each of the parts of the overall manifest.
 * Zeros the hash field in the header before calculating.
 *
 * \param mfst If you don't know, you haven't been paying attention.
 */
nuvo_hash_t nuvo_mfst_hash(struct nuvo_mfst *mfst)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    nuvo_hash_state_t state;
    nuvo_hash_reset(&state);
    mfst->header.hash = 0;
    nuvo_hash_update(&state, &mfst->header, NUVO_BLOCK_SIZE);
    nuvo_hash_update(&state, mfst->lun_table, NUVO_BLOCK_SIZE * mfst->header.num_lun_blocks);
    nuvo_hash_update(&state, mfst->device_state_media, NUVO_BLOCK_SIZE * mfst->header.num_device_blocks);
    nuvo_hash_update(&state, mfst->parcel_state_media, NUVO_BLOCK_SIZE * mfst->header.num_parcel_blocks);
    nuvo_hash_update(&state, mfst->segment_state_media, NUVO_BLOCK_SIZE * mfst->header.num_segment_blocks);

    return (nuvo_hash_digest(&state));
}

/**
 * \brief Parallel write out data from an in-core buffer
 *
 * The writes \p num_blocks worth of data from address \p data
 * to parcel \p parcel_desc offset \p parcel_offset using the
 * \p par_io and using \p sync_signal to allocate io_reqs.
 *
 * The writes are async.  \p par_io and \p sync_signal should have been
 * initialized before calling.
 *
 * \param parcel_desc The descriptor to write to.
 * \param parcel_offset The offset to write to.
 * \param data The data to write.
 * \param num_blocks The number of blocks to write.
 * \param par_io The nuvo_parallel_io struct
 * \param sync_signal The mutex to use with nuvo_pr_sync_client_req_alloc.
 */
static void mfst_send_writes(struct nuvo_vol         *nvs_p,
                             uint_fast32_t            parcel_desc,
                             uint_fast32_t            parcel_offset,
                             uint8_t                 *data,
                             uint_fast32_t            num_blocks,
                             struct nuvo_parallel_io *par_io,
                             nuvo_mutex_t            *sync_signal)
{
    while (num_blocks > 0)
    {
        struct nuvo_io_request *io_req = nuvo_pr_sync_client_req_alloc(sync_signal);
        NUVO_SET_IO_TYPE(io_req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->rw.parcel_desc = parcel_desc;
        io_req->rw.block_offset = parcel_offset;
        io_req->rw.block_count = num_blocks < NUVO_MAX_IO_BLOCKS ? num_blocks : NUVO_MAX_IO_BLOCKS;
        io_req->rw.vol = nvs_p;

        for (uint_fast32_t i = 0; i < io_req->rw.block_count; i++, data += NUVO_BLOCK_SIZE)
        {
            io_req->rw.iovecs[i].iov_base = data;
            io_req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            io_req->rw.block_hashes[i] = nuvo_hash(io_req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
        }
        num_blocks -= io_req->rw.block_count;
        parcel_offset += io_req->rw.block_count;
        nuvo_pr_parallel_submit(par_io, io_req);
    }
}

// Documented in header
void nuvo_mfst_write_start(struct nuvo_mfst          *mfst,
                           struct nuvo_sb_superblock *sb,
                           struct nuvo_parallel_io   *par_io,
                           nuvo_mutex_t              *sync_signal,
                           uint64_t                   freeze_seq_no)
{
    nuvo_mfst_freeze_at_seqno(mfst, freeze_seq_no); // locks and then unlocks
    nuvo_mfst_in_core_lock(mfst);
    mfst->header.generation++;
    nuvo_mfst_in_core_unlock(mfst);

    const struct nuvo_sb_table_location *hldp_tables = nuvo_sb_get_parcel_manifest_addr(sb, mfst->header.generation % 2);
    const struct nuvo_sb_table_location *segment_table = nuvo_sb_get_segment_table_addr(sb, mfst->header.generation % 2);

    uint32_t         parcel_desc = mfst->parcel_state_mem[hldp_tables->parcel_index].parcel_desc;
    struct nuvo_vol *nvs_p = nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst);

    // Send off the device table
    mfst_send_writes(nvs_p, parcel_desc, hldp_tables->block_offset + 1 + mfst->header.num_lun_blocks,
                     (uint8_t *)mfst->device_state_media, mfst->alloced_device_blocks, par_io, sync_signal);

    // Send off the parcel table
    mfst_send_writes(nvs_p, parcel_desc, hldp_tables->block_offset + 1 + mfst->header.num_lun_blocks + mfst->alloced_device_blocks,
                     (uint8_t *)mfst->parcel_state_media, mfst->alloced_parcel_blocks, par_io, sync_signal);

    parcel_desc = mfst->parcel_state_mem[segment_table->parcel_index].parcel_desc;

    // Send off the segment table
    mfst_send_writes(nvs_p, parcel_desc, segment_table->block_offset,
                     (uint8_t *)mfst->segment_state_media, mfst->alloced_segment_blocks, par_io, sync_signal);
}

// Documented in the header
void nuvo_mfst_write_final_writes(struct nuvo_mfst          *mfst,
                                  struct nuvo_sb_superblock *sb,
                                  struct nuvo_parallel_io   *par_io,
                                  nuvo_mutex_t              *sync_signal)
{
    nuvo_mfst_in_core_lock(mfst);
    const struct nuvo_sb_table_location *hldp_tables = nuvo_sb_get_parcel_manifest_addr(sb, mfst->header.generation % 2);
    mfst->header.hash = nuvo_mfst_hash(mfst);
    nuvo_mfst_in_core_unlock(mfst);

    uint32_t         parcel_desc = mfst->parcel_state_mem[hldp_tables->parcel_index].parcel_desc;
    struct nuvo_vol *nvs_p = nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst);

    mfst_send_writes(nvs_p, parcel_desc, hldp_tables->block_offset,
                     (uint8_t *)&mfst->header, 1, par_io, sync_signal);

    mfst_send_writes(nvs_p, parcel_desc, hldp_tables->block_offset + 1,
                     (uint8_t *)mfst->lun_table, mfst->header.num_lun_blocks, par_io, sync_signal);
}

static void nuvo_mfst_sync_write_cb(struct nuvo_parallel_io *par_io)
{
    nuvo_mutex_unlock(par_io->tag.ptr);
}

// Documented in header
nuvo_return_t nuvo_mfst_sync_write(struct nuvo_mfst          *mfst,
                                   struct nuvo_sb_superblock *sb,
                                   uint64_t                   log_seq_no,
                                   uint64_t                   seg_seq_no)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (-NUVO_ENOMEM);
    }
    struct nuvo_parallel_io par_io;
    nuvo_return_t           rc = nuvo_pr_parallel_init(&par_io);
    if (rc != 0)
    {
        return (rc);
    }
    par_io.callback = nuvo_mfst_sync_write_cb;
    par_io.tag.ptr = &sync_signal;

    nuvo_mfst_in_core_lock(mfst);
    mfst->header.log_start_seq_no = log_seq_no;
    nuvo_mfst_in_core_unlock(mfst);
    nuvo_mfst_write_start(mfst, sb, &par_io, &sync_signal, seg_seq_no);

    /*
     * If this were used for something other than init and testing
     * we would need to get the map roots and replay starts here.
     */
    nuvo_mfst_write_final_writes(mfst, sb, &par_io, &sync_signal);
    nuvo_mutex_lock(&sync_signal);
    nuvo_pr_parallel_finalize(&par_io);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mfst_writing_thaw(mfst);
    return (0);
}

/*
 * Read the device table and manifest.
 * Reading is not done while we are doing IO to the volume,
 * so make this much simpler for now.
 */
static nuvo_return_t read_device_parcel_header(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb, int zero_one, uint_fast32_t root_parcel_desc)
{
    const struct nuvo_sb_table_location *pm_loc = nuvo_sb_get_parcel_manifest_addr(sb, zero_one);

    nuvo_mutex_t  sync_signal;
    nuvo_return_t rc = nuvo_mutex_init(&sync_signal);

    if (rc != 0)
    {
        return (-ENOMEM);
    }

    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);

    NUVO_SET_IO_TYPE(req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
    req->rw.vol = nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst);
    req->rw.parcel_desc = root_parcel_desc;
    req->rw.block_offset = pm_loc->block_offset;
    req->rw.block_count = 1;
    req->rw.iovecs[0].iov_base = &mfst->header;
    req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;
    nuvo_pr_sync_submit(req, &sync_signal);
    rc = req->status;
    nuvo_pr_client_req_free(req);
    nuvo_mutex_destroy(&sync_signal);
    return (rc);
}

static nuvo_return_t read_device_parcel(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb, int zero_one, uint_fast32_t root_parcel_desc)
{
    const struct nuvo_sb_table_location *pm_loc = nuvo_sb_get_parcel_manifest_addr(sb, zero_one);
    const struct nuvo_sb_table_location *st_loc = nuvo_sb_get_segment_table_addr(sb, zero_one);

    nuvo_return_t rc;
    uint_fast32_t block_offset = pm_loc->block_offset;

    rc = nuvo_pr_sync_read(root_parcel_desc, block_offset, 1, mfst->header.data);
    if (rc != 0)
    {
        goto failed_sb_read;
    }
    if (mfst->header.magic != NUFO_MFST_MAGIC)
    {
        rc = -NUVO_E_BAD_MAGIC;
        goto failed_magic;
    }

    if (1 + mfst->header.num_device_blocks + mfst->header.num_parcel_blocks > pm_loc->block_length)
    {
        // I'd like to panic, but I don't like to panic on structures coming back from disk.
        NUVO_ERROR_PRINT("Device and parcel header claims more blocks than superblock.");
        rc = -NUVO_EINVAL;
        goto failed_invalid;
    }
    if (mfst->header.num_segment_blocks > st_loc->block_length)
    {
        // I'd like to panic, but I don't like to panic on structures coming back from disk.
        NUVO_ERROR_PRINT("Segment table header claims more blocks than superblock.");
        rc = -NUVO_EINVAL;
        goto failed_invalid;
    }
    NUVO_ASSERT(mfst->device_state_media == NULL);
    rc = nuvo_mfst_grow_devices_mem(mfst, mfst->header.num_used_devices);
    if (rc != 0)
    {
        rc = -NUVO_ENOMEM;
        goto failed_grow_devices;
    }
    NUVO_ASSERT(mfst->parcel_state_media == NULL);
    NUVO_ASSERT(mfst->parcel_state_mem == NULL);
    rc = nuvo_mfst_grow_parcels_mem(mfst, mfst->header.num_used_parcels);
    if (rc != 0)
    {
        rc = -NUVO_ENOMEM;
        goto failed_grow_parcels;
    }
    rc = nuvo_mfst_grow_segments_mem(mfst, NUVO_MFST_BLKS_TO_SEGMENTS(mfst->header.num_segment_blocks));
    if (rc != 0)
    {
        rc = -NUVO_ENOMEM;
        goto failed_grow_segments;
    }

    block_offset++;
    NUVO_ASSERT(mfst->header.num_lun_blocks == NUVO_MFST_LUN_TABLE_BLOCKS);
    rc = nuvo_pr_sync_read(root_parcel_desc, block_offset, mfst->header.num_lun_blocks, (uint8_t *)&mfst->lun_table);
    if (rc != 0)
    {
        goto failed_io;
    }
    block_offset += mfst->header.num_lun_blocks;
    rc = nuvo_pr_sync_read(root_parcel_desc, block_offset, mfst->header.num_device_blocks, (uint8_t *)mfst->device_state_media);
    if (rc != 0)
    {
        goto failed_io;
    }
    block_offset += mfst->header.num_device_blocks;
    rc = nuvo_pr_sync_read(root_parcel_desc, block_offset, mfst->header.num_parcel_blocks, (uint8_t *)mfst->parcel_state_media);
    if (rc != 0)
    {
        goto failed_io;
    }
    block_offset = st_loc->block_offset;
    rc = nuvo_pr_sync_read(root_parcel_desc, block_offset, mfst->header.num_segment_blocks, (uint8_t *)mfst->segment_state_media);
    if (rc != 0)
    {
        goto failed_io;
    }
    nuvo_hash_t media_hash = mfst->header.hash;

    if (media_hash == nuvo_mfst_hash(mfst))
    {
        return (0);
    }
    rc = NUVO_E_BAD_HASH;

failed_io:
    free(mfst->segment_state_mem);
    mfst->segment_state_mem = NULL;
    free(mfst->segment_state_media);
    mfst->segment_state_media = NULL;
    mfst->num_segment_allocated_indices = 0;
    mfst->alloced_segment_blocks = 0;
failed_grow_segments:
    free(mfst->parcel_state_mem);
    mfst->parcel_state_mem = NULL;
    free(mfst->parcel_state_media);
    mfst->parcel_state_media = NULL;
    mfst->alloced_parcel_blocks = 0;
    mfst->num_parcel_indices = 0;
failed_grow_parcels:
    free(mfst->device_state_media);
    mfst->device_state_media = NULL;
    mfst->alloced_device_blocks = 0;
failed_grow_devices:
failed_invalid:
failed_magic:
failed_sb_read:
    return (rc);
}

nuvo_return_t nuvo_mfst_sync_read(struct nuvo_mfst          *mfst,
                                  struct nuvo_sb_superblock *sb,
                                  uint_fast32_t              root_parcel_desc,
                                  bool                       open_parcels)
{
    nuvo_return_t rc = nuvo_mfst_alloc_manifest(mfst);

    if (rc != 0)
    {
        return (rc);
    }
    nuvo_mfst_parcels_change_lock(mfst);
    nuvo_mfst_set_superblock_info(mfst, sb);

    uint64_t generation[2];
    for (uint32_t i = 0; i < 2; i++)
    {
        rc = read_device_parcel_header(mfst, sb, i, root_parcel_desc);
        if (rc != 0)
        {
            goto error_out;
        }
        generation[i] = mfst->header.generation;
    }

    uint_fast32_t order[2];
    order[0] = (generation[1] > generation[0]) ? 1 : 0;
    order[1] = (generation[1] > generation[0]) ? 0 : 1;

    for (uint32_t i = 0; i < 2; i++)
    {
        rc = read_device_parcel(mfst, sb, order[i], root_parcel_desc);
        if (rc == 0)
        {
            break;
        }
    }
    if (rc == 0)
    {
        // Setting up in-core state.  Would this be better in it's own routine?
        for (unsigned dev_index = 0; dev_index < NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks); dev_index++)
        {
            if (uuid_is_null(mfst->device_state_media[dev_index].device_uuid))
            {
                continue;
            }
            if (mfst->device_state_media[dev_index].target_parcels >
                mfst->device_state_media[dev_index].alloced_parcels)
            {
                mfst->data_class[mfst->device_state_media[dev_index].device_class].available_parcels +=
                    (mfst->device_state_media[dev_index].target_parcels -
                     mfst->device_state_media[dev_index].alloced_parcels);
            }
            uint64_t           device_size, parcel_size;
            enum nuvo_dev_type device_type;
            rc = nuvo_pr_sync_dev_info(mfst->device_state_media[dev_index].device_uuid, &device_size, &parcel_size, &device_type);
            if (rc != 0)
            {
                NUVO_ERROR_PRINT_ERRNO(rc, "Failed to get device info for device " NUVO_LOG_UUID_FMT " at index %d", NUVO_LOG_UUID(mfst->device_state_media[dev_index].device_uuid), dev_index);
                goto error_out;
            }
            mfst->device_state_mem[dev_index].device_type = device_type;
        }
        mfst->parcel_state_mem[0].state = NUVO_MFST_PARCEL_OPEN;
        mfst->parcel_state_mem[0].parcel_desc = root_parcel_desc;
        mfst->num_segment_indices = 0;
        for (unsigned parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
        {
            if (mfst->parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_UNUSED)
            {
                mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_NONE;
                mfst->parcel_state_mem[parcel_index].health_status = NUVO_PR_PARCEL_UNAVAILABLE;
            }
            if (mfst->parcel_state_media[parcel_index].type == NUVO_MFST_PARCEL_ENTRY_PARCEL)
            {
                if (parcel_index == 0)
                {
                    mfst->parcel_state_mem[0].state = NUVO_MFST_PARCEL_OPEN;
                    mfst->parcel_state_mem[0].parcel_desc = root_parcel_desc;
                }
                else if (open_parcels)
                {
                    uint_fast32_t pd;
                    nuvo_return_t rc = nuvo_pr_sync_parcel_open(&pd,
                                                                mfst->parcel_state_media[parcel_index].normal.parcel_uuid,
                                                                mfst->device_state_media[mfst->parcel_state_media[parcel_index].normal.device_idx].device_uuid,
                                                                mfst->vs_uuid);
                    if (rc < 0)
                    {
                        // We tried.  Ordinary code will have to do.
                        NUVO_ERROR_PRINT("Failed to open parcel at vol open");
                        mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_USABLE;
                        mfst->parcel_state_mem[parcel_index].parcel_desc = NUVO_VOL_PD_UNUSED;
                    }
                    else
                    {
                        NUVO_LOG(mfst, 20, "Opened parcel at vol open");
                        mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_OPEN;
                        mfst->parcel_state_mem[parcel_index].parcel_desc = pd;
                    }
                }
                else
                {
                    mfst->parcel_state_mem[parcel_index].state = NUVO_MFST_PARCEL_USABLE;
                    mfst->parcel_state_mem[parcel_index].parcel_desc = NUVO_VOL_PD_UNUSED;
                }
                mfst->parcel_state_mem[parcel_index].segment_offset = mfst->num_segment_indices;
                mfst->num_segment_indices += nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
            }
        }
        nuvo_mfst_calc_free_segments(mfst);
    }
error_out:
    nuvo_mfst_parcels_change_unlock(mfst);
    if (rc != 0)
    {
        nuvo_mfst_free_manifest(mfst);
    }
    return (rc);
}

/******************************************************************************************
 *    IO supporting operations.  Pin and unpin.
 */

/**
 * Fast path to get parcel descriptor for the typical case parcel is open.
 */
extern inline nuvo_return_t nuvo_mfst_pd_get(struct nuvo_mfst *mfst, uint32_t parcel_index, uint32_t *pd)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    NUVO_ASSERT(parcel_index < mfst->num_parcel_indices);
    if (parcel_index >= mfst->num_parcel_indices)
    {
        return (-NUVO_E_PARCEL_RANGE);
    }
    if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
    {
        return (-NUVO_E_PARCEL_NOT_OPEN);
    }
    *pd = mfst->parcel_state_mem[parcel_index].parcel_desc;
    return (0);
}

// Inlines defined in header.
extern uint_fast32_t nuvo_mfst_seg_idx(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);
extern uint16_t nuvo_segment_get_blks_used(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);
extern uint16_t nuvo_segment_io_pin_count_get(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);
extern void nuvo_segment_io_pin_count_inc(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);
extern void nuvo_segment_io_pin_count_dec(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);
extern uint16_t nuvo_segment_space_pinned_get(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);
extern void nuvo_segment_space_pinned_clear(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset);

// TODO Rename this!
void nuvo_mfst_pinning_int(struct nuvo_mfst            *mfst,
                           uint_fast32_t                num,
                           const struct nuvo_map_entry *map_entry,
                           bool                         pin)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    for (unsigned int i = 0; i < num; i++)
    {
        if (map_entry[i].type != NUVO_ME_MEDIA)
        {
            continue;
        }
        NUVO_ASSERT((map_entry[i].cow != NUVO_MAP_ENTRY_SHARED) &&
                    (map_entry[i].type != NUVO_ME_NULL));

        if (pin)
        {
            nuvo_segment_io_pin_count_inc(mfst, map_entry[i].media_addr.parcel_index, map_entry[i].media_addr.block_offset);
        }
        else
        {
            nuvo_segment_io_pin_count_dec(mfst, map_entry[i].media_addr.parcel_index, map_entry[i].media_addr.block_offset);
        }
    }
}

void nuvo_mfst_map_request_open_cb(struct nuvo_mfst_open_parcel *op);

void send_map_open_request_next_open(struct nuvo_mfst_map_open *map_open_req)
{
    NUVO_ASSERT(map_open_req->working_on < map_open_req->num_map_entries);
    map_open_req->open.mfst = map_open_req->mfst;
    map_open_req->open.idx = map_open_req->map_entry[map_open_req->working_on].media_addr.parcel_index;
    map_open_req->open.callback = nuvo_mfst_map_request_open_cb;
    map_open_req->open.tag.ptr = map_open_req;
    nuvo_mfst_open_parcel_start(&map_open_req->open);
}

void nuvo_mfst_map_request_open_cb(struct nuvo_mfst_open_parcel *op)
{
    struct nuvo_mfst_map_open *map_open_req = (struct nuvo_mfst_map_open *)op->tag.ptr;

    if (op->status != 0)
    {
        map_open_req->status = op->status;
        map_open_req->callback(map_open_req);
        return;
    }

    map_open_req->pds[map_open_req->working_on] = op->parcel_desc;
    map_open_req->working_on++;

    for (unsigned int i = map_open_req->working_on; i < map_open_req->num_map_entries; i++)
    {
        if (map_open_req->map_entry[i].type == NUVO_ME_MEDIA &&
            map_open_req->map_entry[i].media_addr.parcel_index == op->idx)
        {
            map_open_req->pds[i] = op->parcel_desc;
        }
    }

    while (map_open_req->working_on < map_open_req->num_map_entries &&
           (map_open_req->map_entry[map_open_req->working_on].type != NUVO_ME_MEDIA ||
            map_open_req->pds[map_open_req->working_on] != NUVO_VOL_PD_UNUSED))
    {
        map_open_req->working_on++;
    }
    if (map_open_req->working_on < map_open_req->num_map_entries)
    {
        send_map_open_request_next_open(map_open_req);
    }
    else
    {
        map_open_req->status = 0;
        map_open_req->callback(map_open_req);
    }
}

/**
 * \brief Standard unlock the mutex callback for sync calls.
 */
void nuvo_mfst_map_open_callback(struct nuvo_mfst_map_open *req)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)req->tag.ptr);
}

// Documented in header
void nuvo_mfst_open_async(struct nuvo_mfst_map_open *map_open_req)
{
    nuvo_return_t ret = 0;

    for (unsigned int i = 0; i < map_open_req->num_map_entries; i++)
    {
        map_open_req->pds[i] = NUVO_VOL_PD_UNUSED;
    }

    // Fast path - if parcels are already open, get in and get out.
    nuvo_mfst_in_core_lock(map_open_req->mfst);
    for (unsigned int i = 0; i < map_open_req->num_map_entries; i++)
    {
        if (map_open_req->map_entry[i].type != NUVO_ME_MEDIA)
        {
            map_open_req->pds[i] = NUVO_VOL_PD_UNUSED;
            continue;
        }
        uint32_t pd;
        ret = nuvo_mfst_pd_get(map_open_req->mfst, map_open_req->map_entry[i].media_addr.parcel_index, &pd);
        if (ret != 0)
        {
            // Typically this means the parcel is not yet open.
            break;
        }
        map_open_req->pds[i] = pd;
    }
    if (ret == 0)
    {
        map_open_req->status = 0;
        goto unlock_and_callback;
    }
    else if (ret != -NUVO_E_PARCEL_NOT_OPEN)
    {
        // Fast path crushing defeat.  Something horrible occurred.  Run away.
        map_open_req->status = ret;
        goto unlock_and_callback;
    }

    // Slow path.
    map_open_req->working_on = 0;
    nuvo_mfst_in_core_unlock(map_open_req->mfst);
    send_map_open_request_next_open(map_open_req);
    return;

unlock_and_callback:
    nuvo_mfst_in_core_unlock(map_open_req->mfst);
    map_open_req->callback(map_open_req);
}

// Documented in header
nuvo_return_t nuvo_mfst_pin_open(struct nuvo_mfst            *mfst,
                                 uint_fast32_t                num_map_entries,
                                 const struct nuvo_map_entry *map_entry,
                                 uint_fast32_t               *pds)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t ret = nuvo_mutex_init(&sync_signal);

    if (ret != 0)
    {
        return (-NUVO_ENOMEM);
    }

    nuvo_mfst_pin(mfst, num_map_entries, map_entry);

    struct nuvo_mfst_map_open map_open_req;
    map_open_req.mfst = mfst;
    map_open_req.num_map_entries = num_map_entries;
    map_open_req.map_entry = map_entry;
    map_open_req.pds = pds;
    map_open_req.callback = nuvo_mfst_map_open_callback;
    map_open_req.tag.ptr = &sync_signal;

    nuvo_mutex_lock(&sync_signal);
    nuvo_mfst_open_async(&map_open_req);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);
    if (map_open_req.status < 0)
    {
        nuvo_mfst_unpin(mfst, num_map_entries, map_entry);
    }
    return (map_open_req.status);
}

// Documented in header
void nuvo_mfst_pin(struct nuvo_mfst            *mfst,
                   uint_fast32_t                num,
                   const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_in_core_lock(mfst);
    nuvo_mfst_pinning_int(mfst, num, map_entry, true);
    nuvo_mfst_in_core_unlock(mfst);
}

// Documented in header
void nuvo_mfst_unpin(struct nuvo_mfst            *mfst,
                     uint_fast32_t                num,
                     const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_in_core_lock(mfst);
    nuvo_mfst_pinning_int(mfst, num, map_entry, false);
    nuvo_mfst_in_core_unlock(mfst);
}

// Documented in header
void nuvo_mfst_segment_free_blks(struct nuvo_mfst            *mfst,
                                 uint_fast32_t                num,
                                 const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_segment_change_blks(mfst, num, map_entry, false, false);
}

// Documented in header
void nuvo_mfst_segment_use_blks(struct nuvo_mfst            *mfst,
                                uint_fast32_t                num,
                                const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_segment_change_blks(mfst, num, map_entry, true, false);
}

// free blocks for the COW(divergence) code path which could involve cow blocks.
// We don't want to free COW blocks in the divergent code path since
// these blocks will be used by the snap lun
void nuvo_mfst_segment_free_blks_for_cow(struct nuvo_mfst            *mfst,
                                         uint_fast32_t                num,
                                         const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_segment_change_blks(mfst, num, map_entry, false, true);
}

// Documented in header
void nuvo_mfst_parcels_change_lock(struct nuvo_mfst *mfst)
{
    nuvo_mutex_lock(&mfst->mfst_mutex);
    while (mfst->frozen)
    {
        nuvo_cond_wait(&mfst->cond_frozen, &mfst->mfst_mutex);
    }
    NUVO_ASSERT(!mfst->dirtying_media);
    mfst->dirtying_media = true;
}

// Documented in header
void nuvo_mfst_parcels_change_unlock(struct nuvo_mfst *mfst)
{
    NUVO_ASSERT(mfst->dirtying_media);
    mfst->dirtying_media = false;
    nuvo_mutex_unlock(&mfst->mfst_mutex);
}

// Documented in header
void nuvo_mfst_in_core_lock(struct nuvo_mfst *mfst)
{
    nuvo_mutex_lock(&mfst->mfst_mutex);
    NUVO_ASSERT(!mfst->dirtying_media);
}

// Documented in header
void nuvo_mfst_in_core_unlock(struct nuvo_mfst *mfst)
{
    NUVO_ASSERT(!mfst->dirtying_media);
    nuvo_mutex_unlock(&mfst->mfst_mutex);
}

void nuvo_mfst_seg_counts_start(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);
    NUVO_LOG(mfst, 20, "Starting to count segment changes\n");
    mfst->enable_segment_count_changes = true;
    nuvo_mfst_in_core_unlock(mfst);
}

void nuvo_mfst_freeze_at_seqno(struct nuvo_mfst *mfst, uint64_t next_seq_no)
{
    nuvo_mfst_in_core_lock(mfst);
    NUVO_ASSERT(!mfst->frozen);
    mfst->frozen = true;
    mfst->header.log_segment_count_seq_no = next_seq_no;
    NUVO_ASSERT(!mfst->dirtying_media);
    nuvo_mfst_in_core_unlock(mfst);
}

// Documented in header
void nuvo_mfst_writing_freeze(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);
    NUVO_ASSERT(!mfst->frozen);
    mfst->frozen = true;
    NUVO_ASSERT(!mfst->dirtying_media);
    nuvo_mfst_in_core_unlock(mfst);
}

// Documented in header
void nuvo_mfst_writing_thaw(struct nuvo_mfst *mfst)
{
    nuvo_mutex_lock(&mfst->mfst_mutex);
    NUVO_ASSERT(mfst->frozen);
    mfst->frozen = false;
    NUVO_ASSERT(!mfst->dirtying_media);
    for (uint_fast32_t index = 0; index < mfst->num_parcel_indices; index++)
    {
        if (mfst->parcel_state_mem[index].state == NUVO_MFST_PARCEL_ADDING)
        {
            // If someone kindly gave us a pd already, jump straight to OPEN
            mfst->parcel_state_mem[index].state = (mfst->parcel_state_mem[index].parcel_desc == NUVO_VOL_PD_UNUSED) ?
                                                  NUVO_MFST_PARCEL_USABLE : NUVO_MFST_PARCEL_OPEN;
            nuvo_mfst_device_free_segment_change(mfst, mfst->parcel_state_media[index].normal.device_idx,
                                                 nuvo_mfst_parcel_segment_number_get(mfst, index), true);
            mfst->data_class[mfst->device_state_media[mfst->parcel_state_media[index].normal.device_idx].device_class].total_mfst_blocks +=
                nuvo_mfst_parcel_segment_number_get(mfst, index) * (nuvo_mfst_parcel_segment_size_get(mfst, index) / NUVO_BLOCK_SIZE);
        }
    }
    nuvo_mfst_slog_replay(mfst);
    nuvo_cond_broadcast(&mfst->cond_frozen);
    nuvo_mutex_unlock(&mfst->mfst_mutex);
}

static void move_device_down_free_rankings(struct nuvo_mfst *mfst, uint16_t old_higher)
{
    NUVO_ASSERT(mfst->device_state_mem[old_higher].down_index != old_higher);
    uint16_t old_lower = mfst->device_state_mem[old_higher].down_index;
    NUVO_ASSERT(mfst->device_state_mem[old_lower].up_index == old_higher);
    uint8_t class = mfst->device_state_media[old_higher].device_class;

    // First get the node above old_higher correct.
    if (mfst->device_state_mem[old_higher].up_index == old_higher)
    {
        // old higher was top.
        mfst->data_class[class].device_most_free_segs = old_lower;
        mfst->device_state_mem[old_lower].up_index = old_lower;
    }
    else
    {
        //old higher had one above it.
        mfst->device_state_mem[mfst->device_state_mem[old_higher].up_index].down_index = old_lower;
        mfst->device_state_mem[old_lower].up_index = mfst->device_state_mem[old_higher].up_index;
    }

    // Now get the node below old_lower correct.
    if (mfst->device_state_mem[old_lower].down_index == old_lower)
    {
        // old lower was last.
        mfst->device_state_mem[old_higher].down_index = old_higher;
    }
    else
    {
        mfst->device_state_mem[mfst->device_state_mem[old_lower].down_index].up_index = old_higher;
        mfst->device_state_mem[old_higher].down_index = mfst->device_state_mem[old_lower].down_index;
    }

    mfst->device_state_mem[old_lower].down_index = old_higher;
    mfst->device_state_mem[old_higher].up_index = old_lower;
}

// documented in header
void nuvo_mfst_device_free_segment_change(struct nuvo_mfst *mfst, uint16_t device_index, int16_t num, bool total)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    mfst->device_state_mem[device_index].free_segments += num;
    NUVO_ASSERT(mfst->device_state_mem[device_index].free_segments >= 0);

    uint8_t data_class = mfst->device_state_media[device_index].device_class;
    if (total)
    {
        mfst->data_class[data_class].total_segments += num;
        NUVO_ASSERT(mfst->data_class[data_class].total_segments >= 0);
    }
    else
    {
        // TODO - Simulating free blocks by counting when allocating/freeing segments.  Change this with gc.
        mfst->data_class[data_class].used_blocks -= num * NUVO_SEGMENT_MIN_SIZE_BLOCKS;
    }
    mfst->data_class[data_class].free_segments += num;
    NUVO_ASSERT(mfst->data_class[data_class].free_segments >= 0);

    if (num < 0)
    {
        // Move down
        while (mfst->device_state_mem[device_index].free_segments <
               mfst->device_state_mem[mfst->device_state_mem[device_index].down_index].free_segments)
        {
            move_device_down_free_rankings(mfst, device_index);
        }
    }
    else
    {
        // Move up
        while (mfst->device_state_mem[device_index].free_segments >
               mfst->device_state_mem[mfst->device_state_mem[device_index].up_index].free_segments)
        {
            move_device_down_free_rankings(mfst, mfst->device_state_mem[device_index].up_index);
        }
    }
}

void insert_device_in_free_segment_list(struct nuvo_mfst *mfst, uint16_t dev_index)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint8_t class = mfst->device_state_media[dev_index].device_class;
    if (mfst->data_class[class].device_most_free_segs == NUVO_NO_DEVICE_IN_CLASS)
    {
        mfst->data_class[class].device_most_free_segs = dev_index;
        mfst->device_state_mem[dev_index].up_index = dev_index;
        mfst->device_state_mem[dev_index].down_index = dev_index;
        return;
    }
    // Insert at the top and move down.
    mfst->device_state_mem[dev_index].up_index = dev_index;
    mfst->device_state_mem[dev_index].down_index = mfst->data_class[class].device_most_free_segs;
    mfst->device_state_mem[mfst->data_class[class].device_most_free_segs].up_index = dev_index;
    mfst->data_class[class].device_most_free_segs = dev_index;
    while (mfst->device_state_mem[dev_index].free_segments <
           mfst->device_state_mem[mfst->device_state_mem[dev_index].down_index].free_segments)
    {
        move_device_down_free_rankings(mfst, dev_index);
    }
}

static void nuvo_mfst_calc_free_segments(struct nuvo_mfst *mfst)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint32_t num_devices = NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks);
    for (unsigned c = 0; c < NUVO_MAX_DATA_CLASSES; c++)
    {
        mfst->data_class[c].device_most_free_segs = NUVO_NO_DEVICE_IN_CLASS;
        mfst->data_class[c].available_parcels = 0;
        mfst->data_class[c].total_segments = 0;
        mfst->data_class[c].free_segments = 0;
        mfst->data_class[c].gc_free_current_cp = 0;
        mfst->data_class[c].gc_free_next_cp = 0;

        mfst->data_class[c].used_blocks = 0;
        mfst->data_class[c].total_mfst_blocks = 0;
        mfst->data_class[c].total_parcel_blocks = 0;
    }

    for (unsigned dev_index = 0; dev_index < num_devices; dev_index++)
    {
        mfst->device_state_mem[dev_index].free_segments = 0;
        mfst->device_state_mem[dev_index].gc_free_current_cp = 0;
        mfst->device_state_mem[dev_index].gc_free_next_cp = 0;
    }
    for (uint_fast32_t parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
    {
        if (mfst->parcel_state_media[parcel_index].type != NUVO_MFST_PARCEL_ENTRY_PARCEL)
        {
            continue;
        }
        if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_USABLE &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPENING &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
        {
            continue;
        }
        uint8_t       class = mfst->device_state_media[mfst->parcel_state_media[parcel_index].normal.device_idx].device_class;
        uint_fast32_t num_segs = nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
        for (uint_fast32_t i = 0; i < num_segs; i++)
        {
            mfst->data_class[class].total_segments++;
            uint_fast32_t seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset + i;
            mfst->data_class[class].total_mfst_blocks += nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE;
            if (NUVO_SEGMENT_IN_USE(mfst, seg_idx))
            {
                // TODO - change this when we have GC allowing block level accounting.
                mfst->data_class[class].used_blocks += nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE;
                if (mfst->max_segment_age < mfst->segment_state_media[seg_idx].seg_age)
                {
                    mfst->max_segment_age = mfst->segment_state_media[seg_idx].seg_age;
                }
            }
            else
            {
                mfst->device_state_mem[mfst->parcel_state_media[parcel_index].normal.device_idx].free_segments++;
                mfst->data_class[class].free_segments++;
            }
        }
    }

    for (unsigned dev_index = 0; dev_index < num_devices; dev_index++)
    {
        if (!nuvo_mfst_device_in_use(mfst, dev_index))
        {
            continue;
        }
        insert_device_in_free_segment_list(mfst, dev_index);
        uint8_t  class = mfst->device_state_media[dev_index].device_class;
        uint64_t blocks_in_parcel = nuvo_mfst_usable_blocks_per_parcel(mfst, dev_index);
        mfst->data_class[class].total_parcel_blocks += blocks_in_parcel * mfst->device_state_media[dev_index].target_parcels;
        if (mfst->device_state_media[dev_index].alloced_parcels < mfst->device_state_media[dev_index].target_parcels)
        {
            mfst->data_class[class].available_parcels +=
                (mfst->device_state_media[dev_index].target_parcels - mfst->device_state_media[dev_index].alloced_parcels);
        }
    }
}

void nuvo_mfst_choose_device_for_new_parcel(struct nuvo_mfst *mfst,
                                            uint8_t           data_class,
                                            uuid_t            device_uuid,
                                            int_fast32_t     *free_segments)
{
    uuid_clear(device_uuid);
    for (uint_fast16_t device_index = 0; device_index < NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks); device_index++)
    {
        if (!nuvo_mfst_device_in_use(mfst, device_index) ||
            mfst->device_state_media[device_index].device_class != data_class ||
            mfst->device_state_media[device_index].alloced_parcels >= mfst->device_state_media[device_index].target_parcels)
        {
            continue;
        }
        if (uuid_is_null(device_uuid) || *free_segments > mfst->device_state_mem[device_index].free_segments)
        {
            uuid_copy(device_uuid, mfst->device_state_media[device_index].device_uuid);
            *free_segments = mfst->device_state_mem[device_index].free_segments;
        }
    }
    return;
}

const struct nuvo_map_entry empty_map_entry = { .cow        = 0,
                                                .type       = 0,
                                                .unused     = 0,
                                                .media_addr = { .parcel_index = 0,.block_offset                    = 0 },
                                                { .pattern  = 0 } };

// Documented in header
nuvo_return_t nuvo_mfst_sb_init(struct nuvo_sb_superblock *sb,
                                struct nuvo_mfst          *mfst,
                                const uuid_t               vol_uuid,
                                const uuid_t               root_device_uuid,
                                uuid_t                     root_parcel_uuid,
                                uint_fast32_t              root_parcel_desc,
                                uint32_t                   parcel_size_blocks,
                                uint8_t                    device_class,
                                uint8_t                    device_type,
                                uint32_t                   segment_size_bytes,  // TODO World would be happier if blks was unit.
                                uint32_t                   blks_for_parcels,
                                uint32_t                   blks_for_segments,
                                uint64_t                   lun_size)
{
    nuvo_return_t rc;
    uint16_t      num_segments = (parcel_size_blocks * (uint64_t)NUVO_BLOCK_SIZE) / segment_size_bytes;
    uint32_t      blks_needed = 2 * (1 + NUVO_MFST_LUN_TABLE_BLOCKS + blks_for_parcels + blks_for_segments);

    NUVO_LOG(mfst, 1, "Initializing manifest vol: " NUVO_LOG_UUID_FMT ", root device: " NUVO_LOG_UUID_FMT ", root parcel: " NUVO_LOG_UUID_FMT " size: %" PRIu64,
             NUVO_LOG_UUID(vol_uuid), NUVO_LOG_UUID(root_device_uuid), NUVO_LOG_UUID(root_parcel_uuid), lun_size);

    if (segment_size_bytes < NUVO_SEGMENT_MIN_SIZE_BYTES ||
        segment_size_bytes > NUVO_SEGMENT_MAX_SIZE_BYTES ||
        segment_size_bytes % NUVO_SEGMENT_SIZE_INCREMENT != 0)
    {
        return (-NUVO_EINVAL);
    }
    if (lun_size == 0 || lun_size % NUVO_BLOCK_SIZE != 0)
    {
        return (-NUVO_EINVAL);
    }
    if (device_class >= NUVO_MAX_DATA_CLASSES)
    {
        return (-NUVO_EINVAL);
    }
    // Need to leave one segment for first log segment.
    if (blks_needed > parcel_size_blocks - (segment_size_bytes / NUVO_BLOCK_SIZE))
    {
        return (-NUVO_ENOSPC);
    }
    if (num_segments > NUVO_SEGMENT_CNT_MAX)
    {
        num_segments = NUVO_SEGMENT_CNT_MAX;
    }
    rc = nuvo_mfst_alloc_manifest(mfst);
    if (rc < 0)
    {
        goto failed_alloc_manifest_init;
    }

    nuvo_mfst_init_manifest_header(mfst);
    nuvo_sb_init(sb, vol_uuid, blks_for_parcels, blks_for_segments);
    nuvo_mfst_set_superblock_info(mfst, sb);

    rc = nuvo_mfst_insert_device(mfst,
                                 root_device_uuid,
                                 device_class,
                                 device_type,
                                 parcel_size_blocks);
    if (rc < 0)
    {
        goto failed_device_insert;
    }
    rc = nuvo_mfst_device_parcel_target(mfst, root_device_uuid, 1);  // Implicitly we get a parcel
    NUVO_ASSERT(rc == 0);

    uint8_t device_class_returned;
    NUVO_ASSERT(NUVO_VOL_PD_UNUSED != root_parcel_desc);
    rc = nuvo_mfst_insert_parcel(mfst,
                                 root_device_uuid,
                                 root_parcel_uuid,
                                 segment_size_bytes,
                                 &num_segments,
                                 &device_class_returned,
                                 root_parcel_desc);
    if (rc < 0)
    {
        goto failed_parcel_insert;
    }
    NUVO_ASSERT(device_class == device_class_returned);
    nuvo_mfst_parcels_change_lock(mfst);
    uint_fast32_t num_reserved = 0;
    while (num_reserved < num_segments &&
           num_reserved * segment_size_bytes < blks_needed * NUVO_BLOCK_SIZE)
    {
        mfst->segment_state_media[num_reserved].seg_reserved = 1;
        num_reserved++;
    }
    NUVO_ASSERT(mfst->parcel_state_mem[0].state == NUVO_MFST_PARCEL_ADDING);
    // Chicken and egg.  We have to make the first parcel
    // Open.  Write out the manifest first thing.
    mfst->parcel_state_mem[0].state = NUVO_MFST_PARCEL_OPEN;
    mfst->device_state_mem[0].free_segments = nuvo_mfst_parcel_segment_number_get(mfst, 0) - num_reserved;
    mfst->data_class[device_class].total_segments = nuvo_mfst_parcel_segment_number_get(mfst, 0);
    mfst->data_class[device_class].free_segments = mfst->device_state_mem[0].free_segments;
    mfst->data_class[device_class].used_blocks = num_reserved * (nuvo_mfst_parcel_segment_size_get(mfst, 0) / NUVO_BLOCK_SIZE);
    mfst->data_class[device_class].total_mfst_blocks = nuvo_mfst_parcel_segment_number_get(mfst, 0) * nuvo_mfst_parcel_segment_size_get(mfst, 0) / NUVO_BLOCK_SIZE;
    mfst->data_class[device_class].total_parcel_blocks = mfst->data_class[device_class].total_mfst_blocks;
    insert_device_in_free_segment_list(mfst, 0);

    mfst->header.num_used_luns = 1;
    uuid_copy(mfst->lun_table[0].lun_uuid, vol_uuid);
    memcpy(&mfst->lun_table[0].root_map_entry, &empty_map_entry, sizeof(mfst->lun_table[0].root_map_entry));
    mfst->lun_table[0].lun_state = NUVO_LUN_STATE_VALID;
    mfst->lun_table[0].map_height = 4;   // TODO - optimize to size?
    mfst->lun_table[0].size = lun_size;
    mfst->lun_table[0].snap_id = NUVO_MFST_ACTIVE_LUN_SNAPID;

    mfst->header.num_used_log_starts = 1;
    mfst->header.log_segments[0].parcel_index = 0;
    NUVO_ASSERT(num_reserved <= mfst->parcel_state_media[0].normal.number_segments_minus_1);
    mfst->header.log_segments[0].segment_index = num_reserved;

    nuvo_mfst_parcels_change_unlock(mfst);
    return (0);

failed_parcel_insert:
    free(mfst->device_state_media);
    mfst->device_state_media = NULL;
    mfst->alloced_device_blocks = 0;
failed_device_insert:
    nuvo_mfst_free_manifest(mfst);
failed_alloc_manifest_init:
    return (rc);
}

// Documented in header
nuvo_return_t nuvo_mfst_sb_update_replay_count(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb, enum nuvo_sb_update_op_t op)
{
    NUVO_ASSERT(mfst != NULL);
    NUVO_ASSERT(sb != NULL);

    uint_fast32_t parcel_desc = mfst->parcel_state_mem[0].parcel_desc;
    NUVO_ASSERT(mfst->parcel_state_mem[0].state == NUVO_MFST_PARCEL_OPEN);

    switch (op)
    {
    case NUVO_SB_REPLAY_COUNT_INCR:
        sb->replay_count += 1;
        break;

    case NUVO_SB_REPLAY_COUNT_ZERO:
        sb->replay_count = 0;
        break;

    default:
        NUVO_PANIC("Invalid operation");
    }
    sb->git_hash = nuvo_short_git_hash();

    return (nuvo_sb_sync_write(sb, parcel_desc));
}

// Documented in header
nuvo_return_t nuvo_mfst_get_active_lun(struct nuvo_mfst *mfst,
                                       struct nuvo_lun  *active_lun)
{
    nuvo_return_t ret;

    nuvo_mfst_in_core_lock(mfst);  // Locking is really just needed for asserts.
    ret = nuvo_mfst_get_active_lun_locked(mfst, active_lun);
    nuvo_mfst_in_core_unlock(mfst);

    return (ret);
}

nuvo_return_t nuvo_mfst_get_active_lun_locked(struct nuvo_mfst *mfst,
                                              struct nuvo_lun  *active_lun)
{
    NUVO_ASSERT(mfst->lun_table[0].snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID);
    active_lun->snap_id = mfst->lun_table[0].snap_id;
    NUVO_ASSERT(mfst->lun_table[0].lun_state == NUVO_LUN_STATE_VALID);
    active_lun->lun_state = mfst->lun_table[0].lun_state;
    active_lun->size = mfst->lun_table[0].size;
    active_lun->root_map_entry = mfst->lun_table[0].root_map_entry;
    active_lun->map_height = mfst->lun_table[0].map_height;

    return (0);
}

nuvo_return_t nuvo_mfst_get_luns(struct nuvo_vol *vol,
                                 struct nuvo_lun *luns,
                                 int              lun_count)
{
    uint32_t          snap_generation = 0;
    struct nuvo_mfst *mfst = &vol->log_volume.mfst;

    nuvo_mfst_in_core_lock(mfst);

    nuvo_mfst_get_active_lun_locked(mfst, &vol->log_volume.lun);
    nuvo_lun_state_init(&vol->log_volume.lun, vol, vol->log_volume.lun.lun_state, NUVO_LUN_EXPORT_UNEXPORTED);

    for (int i = 1; i < lun_count; i++)
    {
        if (mfst->lun_table[i].snap_id)
        {
            luns[i].vol = vol;
            luns[i].size = mfst->lun_table[i].size;
            luns[i].root_map_entry = mfst->lun_table[i].root_map_entry;
            luns[i].map_height = mfst->lun_table[i].map_height;
            luns[i].snap_id = mfst->lun_table[i].snap_id;
            luns[i].lun_state = mfst->lun_table[i].lun_state;
            uuid_copy(luns[i].lun_uuid, mfst->lun_table[i].lun_uuid);
            NUVO_ASSERT(luns[i].lun_state == NUVO_LUN_STATE_VALID || luns[i].lun_state == NUVO_LUN_STATE_DELETING);
            nuvo_lun_state_init(&luns[i], vol, luns[i].lun_state, NUVO_LUN_EXPORT_UNEXPORTED);

            // get the highest snap_id
            snap_generation = NUVO_MAX(snap_generation, luns[i].snap_id);
        }
    }

    vol->snap_generation = snap_generation;

    nuvo_mfst_in_core_unlock(mfst);
    return (0);
}

// Documented in header
void nuvo_mfst_set_luns(struct nuvo_mfst           *mfst,
                        uint_fast16_t               num_luns,
                        struct nuvo_mfst_lun_entry *entries)
{
    nuvo_mfst_in_core_lock(mfst);
    mfst->header.num_used_luns = num_luns;
    for (uint_fast16_t i = 0; i < num_luns; i++)
    {
        NUVO_ASSERT(entries[i].lun_state == NUVO_LUN_STATE_VALID || entries[i].lun_state == NUVO_LUN_STATE_DELETING);
        memcpy(&mfst->lun_table[i], &entries[i], sizeof(mfst->lun_table[0]));
    }
    nuvo_mfst_in_core_unlock(mfst);
}

/**
 * \brief Fill in a nuvo_segment field for handing off to logger/replay.
 *
 * For a given parcel and length do everything to get nuvo_segment ready to
 * hand off to the logger and/or replay.
 *
 * \param mfst The manifest
 * \param parcel_index The parcel index of the segment.
 * \param block_offset The block offset of the segment.
 * \param seg The segment to fill.
 * \param for_gc Whether this for gc or for the logger.
 * \returns 0 on success, negative if problem opening parcel.
 */
static void nuvo_mfst_fill_nuvo_segment(struct nuvo_mfst    *mfst,
                                        uint32_t             parcel_index,
                                        uint32_t             block_offset,
                                        struct nuvo_segment *seg,
                                        bool                 for_gc)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    seg->parcel_index = parcel_index;
    seg->block_count = nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE;
    seg->block_offset = block_offset - (block_offset % seg->block_count);
    seg->device_index = mfst->parcel_state_media[parcel_index].normal.device_idx;
    seg->data_class = mfst->device_state_media[seg->device_index].device_class;
    seg->device_type = mfst->device_state_mem[seg->device_index].device_type;

    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    NUVO_ASSERT(mfst->segment_state_mem[segment_index].seg_space_used == 0);
    NUVO_ASSERT(mfst->segment_state_media[segment_index].seg_reserved == 0);
    if (!NUVO_SEGMENT_IN_USE(mfst, segment_index))
    {
        nuvo_mfst_device_free_segment_change(mfst, seg->device_index, -1, false);
    }
    NUVO_ASSERT(0 == nuvo_segment_space_pinned_get(mfst, seg->parcel_index, seg->block_offset));
    NUVO_ASSERT(0 == mfst->segment_state_mem[segment_index].seg_space_used);
    mfst->segment_state_mem[segment_index].seg_space_used = 1;
    if (for_gc)
    {
        mfst->device_state_mem[seg->device_index].segments_in_gc++;
        seg->user = NUVO_SEGMENT_USER_GC;
    }
    else
    {
        seg->user = NUVO_SEGMENT_USER_LOGGER;
    }
}

/**
 * \brief Open a segment for the logger.
 *
 * Make sure the parcel is open and get the parcel descriptor.
 * Outside all the rest of the segment filling because this does per io, so
 * we don't want to hold the manifest lock.
 *
 * \param mfst The manifest
 * \param seg  The segment we need fill with a parcel descriptor
 */
static nuvo_return_t open_segment_parcel(struct nuvo_mfst *mfst, struct nuvo_segment *seg)
{
    struct nuvo_map_entry map_entry;

    map_entry.type = NUVO_ME_MEDIA;
    map_entry.cow = NUVO_MAP_ENTRY_NONE;
    map_entry.media_addr.parcel_index = seg->parcel_index;
    map_entry.media_addr.block_offset = seg->block_offset;
    uint_fast32_t pd;
    nuvo_return_t rc = nuvo_mfst_pin_open(mfst, 1, &map_entry, &pd);
    if (rc == 0)
    {
        seg->parcel_desc = pd;
    }
    return (rc);
}

void mfst_validate_free_segments(struct nuvo_mfst *mfst,
                                 uint32_t          dev_index)
{
    uint32_t free_segments = 0;

    for (uint_fast32_t parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
    {
        if (mfst->parcel_state_media[parcel_index].normal.device_idx != dev_index)
        {
            continue;
        }
        if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_USABLE &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPENING &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
        {
            continue;
        }
        uint_fast32_t num_segs = nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
        for (uint_fast32_t i = 0; i < num_segs; i++)
        {
            uint_fast32_t seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset + i;
            if (!NUVO_SEGMENT_IN_USE(mfst, seg_idx))
            {
                free_segments++;
            }
        }
    }
    NUVO_ASSERT(mfst->device_state_mem[dev_index].free_segments == free_segments);
}

/**
 * \brief Find a segment on the device for the mfst to use.  Fill in the nuvo_segment.
 *
 * Find a segment on the device to hand off to the logger.  This finds it and fills it
 * in, but does not open the segment (because we're holding the mfst lock).
 *
 * \param mfst The manifest
 * \param dev_index The index of the device on which to find a segment.
 * \param seg The segment to fill.
 */
static void nuvo_mfst_find_segment(struct nuvo_mfst    *mfst,
                                   uint32_t             dev_index,
                                   struct nuvo_segment *seg)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    NUVO_ASSERT(mfst->device_state_mem[dev_index].free_segments > 0);
    // CUM-1199 need better searching.  Bulk.  Keep track of location.  Something.
    // See note in manifest that we could squirrel away info there.
    for (uint_fast32_t parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
    {
        if (mfst->parcel_state_media[parcel_index].normal.device_idx != dev_index)
        {
            continue;
        }
        if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_USABLE &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPENING &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
        {
            continue;
        }
        uint_fast32_t num_segs = nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
        for (uint_fast32_t i = 0; i < num_segs; i++)
        {
            uint_fast32_t seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset + i;
            if (!NUVO_SEGMENT_IN_USE(mfst, seg_idx))
            {
                nuvo_mfst_fill_nuvo_segment(mfst,
                                            parcel_index,
                                            (nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE) * i,
                                            seg,
                                            false);
                return;
            }
        }
    }
    NUVO_PANIC("Could not find a free segment.");   // We looked at the free counts up above.
}

// Documented in header.
nuvo_return_t nuvo_mfst_segment_for_log_replay(struct nuvo_mfst    *mfst,
                                               uint32_t             parcel_index,
                                               uint32_t             block_offset,
                                               struct nuvo_segment *segment)
{
    nuvo_mfst_in_core_lock(mfst);
    nuvo_mfst_fill_nuvo_segment(mfst, parcel_index, block_offset, segment, false);
    nuvo_mfst_in_core_unlock(mfst);
    nuvo_return_t rc = open_segment_parcel(mfst, segment);
    NUVO_ASSERT(rc >= 0);
    return (rc);
}

/**
 * Below we define a percentage full of a segment to be considered "full" for purposes
 * of gc scoring.  Basically, want to think of segments that will basically be
 * neutral to clean as "full".  If this was 100, then in the calculation below
 * a segment that was 90% full and twice as old would basically be as good as one that
 * was 80% full.  That would cause us to waste effort.  So, for puposes of scoring,
 * we count the "fullest we can get" as 100% full.  We still return the real utilization.
 */
#define NUVO_MFST_PERCENT_CONSIDERED_FULL    90

inline void nuvo_mfst_segment_gc_grade(struct nuvo_mfst *mfst,
                                       uint_fast32_t     seg_index,
                                       uint_fast32_t     parcel_index,
                                       uint_fast8_t     *utilization,
                                       uint_fast64_t    *grade)
{
    // benefit/cost = (1 - utilization) * age / (1 + utilization)
    // For now use the age to be max_age - seg_age.
    // utilization is 0 to 1, so lets multiply by 100, and make u = 100 * utilization
    NUVO_ASSERT(mfst->max_segment_age >= mfst->segment_state_media[seg_index].seg_age);
    uint64_t age = mfst->max_segment_age - mfst->segment_state_media[seg_index].seg_age + 1;
    uint64_t bytes_used = NUVO_BLOCK_SIZE * (uint_fast64_t)mfst->segment_state_media[seg_index].seg_blks_used;
    uint64_t bytes_really_full = nuvo_mfst_parcel_segment_size_get(mfst, parcel_index);

    // The next 3 lines calculate utilization counting a 0.90 full segment as
    // "100%" full.
    uint64_t bytes_considered_full = NUVO_MFST_PERCENT_CONSIDERED_FULL * bytes_really_full / 100;
    uint64_t u = (100 * bytes_used) / bytes_considered_full;
    u = NUVO_MIN(u, (uint64_t)100);

    *utilization = (100 * bytes_used) / bytes_really_full; // Caculate the real utilization.
    *grade = (100 - u) * age / (100 + u);
}

// Prototype to allow the inline to compile.
void nuvo_mfst_segment_gc_grade(struct nuvo_mfst *mfst,
                                uint_fast32_t     seg_index,
                                uint_fast32_t     parcel_index,
                                uint_fast8_t     *utilization,
                                uint_fast64_t    *grade);

// Documented in header.
nuvo_return_t nuvo_mfst_segments_gc_device(struct nuvo_mfst  *mfst,
                                           uint_fast16_t      dev_index,
                                           int_fast16_t       num_requested,
                                           uint_fast8_t       cutoff,
                                           struct nuvo_dlist *chosen_segs)
{
    int_fast16_t num_found = 0;

    nuvo_mfst_in_core_lock(mfst);
    for (uint_fast32_t parcel_index = 0; parcel_index < mfst->num_parcel_indices; parcel_index++)
    {
        if (dev_index != mfst->parcel_state_media[parcel_index].normal.device_idx)
        {
            continue;
        }
        if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_USABLE &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPENING &&
            mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
        {
            continue;
        }
        uint_fast32_t num_segs = nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
        for (uint_fast32_t i = 0; i < num_segs; i++)
        {
            uint_fast32_t seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset + i;
            if (mfst->segment_state_media[seg_idx].seg_reserved ||
                mfst->segment_state_mem[seg_idx].seg_space_used)
            {
                // Don't try to clean reserved segments or segments in use by logger/gc.
                continue;
            }
            if (mfst->segment_state_media[seg_idx].seg_age == 0 &&
                mfst->segment_state_media[seg_idx].seg_blks_used == 0)
            {
                // Don't try to clean already clean segments
                continue;
            }
            uint_fast8_t  u;
            uint_fast64_t grade;
            nuvo_mfst_segment_gc_grade(mfst, seg_idx, parcel_index, &u, &grade);
            if (u > cutoff)
            {
                // Don't return a segment above the cutoff utilization
                continue;
            }

            // Get an unused segment
            struct nuvo_segment *segment = NULL;
            if (num_found < num_requested)
            {
                segment = nuvo_segment_alloc(&nuvo_global_segment_free_list);
                num_found++;
            }
            if (segment == NULL && grade > nuvo_dlist_get_tail_object(chosen_segs, struct nuvo_segment, list_node)->gc_grade)
            {
                segment = nuvo_dlist_remove_tail_object(chosen_segs, struct nuvo_segment, list_node);
            }
            if (segment != NULL)
            {
                segment->parcel_index = parcel_index;
                segment->block_offset = (nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE) * i;
                segment->gc_utilization = u;
                segment->gc_grade = grade;

                struct nuvo_segment *chosen = nuvo_dlist_get_head_object(chosen_segs, struct nuvo_segment, list_node);
                while (chosen != NULL && chosen->gc_grade > segment->gc_grade)
                {
                    chosen = nuvo_dlist_get_next_object(chosen_segs, chosen, struct nuvo_segment, list_node);
                }
                if (chosen != NULL)
                {
                    nuvo_dlist_insert_before(&chosen->list_node, &segment->list_node);
                }
                else
                {
                    nuvo_dlist_insert_tail(chosen_segs, &segment->list_node);
                }
            }
        }
    }
    struct nuvo_segment *chosen = nuvo_dlist_get_head_object(chosen_segs, struct nuvo_segment, list_node);
    while (chosen != NULL)
    {
        nuvo_mfst_fill_nuvo_segment(mfst, chosen->parcel_index, chosen->block_offset, chosen, true);
        chosen = nuvo_dlist_get_next_object(chosen_segs, chosen, struct nuvo_segment, list_node);
    }
    // TODO - make sure we are not racing with multiple callers getting list
    nuvo_mfst_in_core_unlock(mfst);

    chosen = nuvo_dlist_get_head_object(chosen_segs, struct nuvo_segment, list_node);

    nuvo_return_t rc = 0;
    while (chosen != NULL)
    {
        struct nuvo_segment *next_chosen = nuvo_dlist_get_next_object(chosen_segs, chosen, struct nuvo_segment, list_node);
        nuvo_return_t        open_rc = open_segment_parcel(mfst, chosen);
        if (open_rc < 0)
        {
            rc = open_rc;
            nuvo_dlist_remove(&chosen->list_node);
            nuvo_mfst_segment_done(mfst, chosen, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
            nuvo_segment_free(&nuvo_global_segment_free_list, chosen);
        }
        chosen = next_chosen;
    }
    return ((rc != 0) ? rc : num_found);
}

static inline int_fast32_t device_free_segments(struct nuvo_mfst *mfst, int32_t device_index)
{
    return (mfst->device_state_mem[device_index].free_segments +
            mfst->device_state_mem[device_index].gc_free_current_cp +
            mfst->device_state_mem[device_index].gc_free_next_cp +
            mfst->device_state_mem[device_index].segments_in_gc);
}

nuvo_return_t mfst_find_device_for_gc(struct nuvo_mfst *mfst,
                                      uint8_t           data_class)
{
    int32_t dev_index = mfst->data_class[data_class].device_most_free_segs;

    if (dev_index == -1)
    {
        return (-NUVO_E_DEVICE_CLASS_BAD);
    }
    int32_t      best_dev_index = dev_index;
    int_fast32_t best_free_segments = device_free_segments(mfst, dev_index);

    while (mfst->device_state_mem[dev_index].down_index != (uint16_t)dev_index)
    {
        dev_index = mfst->device_state_mem[dev_index].down_index;
        int_fast32_t free_segments = device_free_segments(mfst, dev_index);
        if (free_segments < best_free_segments)
        {
            best_free_segments = free_segments;
            best_dev_index = dev_index;
        }
    }

    return (best_dev_index);
}

void nuvo_mfst_segment_done_int(struct nuvo_mfst *mfst, struct nuvo_segment *seg, enum nuvo_mfst_segment_reason_t reason);

void nuvo_mfst_return_gc_segments(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);
    for (uint_fast16_t dev_index = 0; dev_index < NUVO_MFST_DEVICE_LIMIT; dev_index++)
    {
        struct nuvo_segment *segment;
        while (NULL != (segment = nuvo_dlist_remove_head_object(&mfst->device_state_mem[dev_index].segs_for_gc, struct nuvo_segment, list_node)))
        {
            nuvo_mfst_segment_done_int(mfst, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
            nuvo_segment_free(&nuvo_global_segment_free_list, segment);
        }
    }
    nuvo_mfst_in_core_unlock(mfst);
}

/**
 * How many segments to pre-search for on a device.
 */
#define NUVO_MFST_GC_SEGMENT_BUFFER    5

/**
 * Don't cache items over this percent full. If all of the segments are at least
 * this full then we will do a full search each time we call, making a tradeoff
 * of CPU cost for disk efficiency.
 */
#define NUVO_MFST_SUSPICIOUSLY_FULL    80

// Documented in header
nuvo_return_t nuvo_mfst_segment_for_gc(struct nuvo_mfst     *mfst,
                                       uint8_t               data_class,
                                       struct nuvo_segment **seg)
{
    nuvo_mfst_in_core_lock(mfst);

    nuvo_return_t device_index = mfst_find_device_for_gc(mfst, data_class);
    if (device_index < 0)
    {
        nuvo_mfst_in_core_unlock(mfst);
        return (device_index);
    }

    nuvo_return_t rc;
    *seg = NULL;

    // Fill the segment free list if it is empty.
    if (NULL == nuvo_dlist_get_head(&mfst->device_state_mem[device_index].segs_for_gc))
    {
        nuvo_mfst_in_core_unlock(mfst);
        rc = nuvo_mfst_segments_gc_device(mfst, device_index, NUVO_MFST_GC_SEGMENT_BUFFER, NUVO_MFST_SUSPICIOUSLY_FULL, &mfst->device_state_mem[device_index].segs_for_gc);
        NUVO_ASSERT(rc >= 0); // TODO handle error opening parcels.
        if (rc == 0)
        {
            // Didn't get any no SUSPICIOUSLY_FULL - try again.
            NUVO_ASSERT(NULL == nuvo_dlist_get_head(&mfst->device_state_mem[device_index].segs_for_gc));
            rc = nuvo_mfst_segments_gc_device(mfst, device_index, 1, 100, &mfst->device_state_mem[device_index].segs_for_gc);
            NUVO_ASSERT(rc >= 0); // TODO handle error opening parcels.
        }
        nuvo_mfst_in_core_lock(mfst);
    }
    struct nuvo_segment *segment = nuvo_dlist_remove_head_object(&mfst->device_state_mem[device_index].segs_for_gc,
                                                                 struct nuvo_segment, list_node);
    nuvo_mfst_in_core_unlock(mfst);

    if (segment == NULL)
    {
        return (-NUVO_E_NO_CLEANABLE_SEGMENT);
    }

    // After time we put on list utilization may have dropped, could recompute.
    *seg = segment;
    return (segment->gc_utilization);
}

/*
 * Pick a segment for gc.
 *
 * This picks a segment of the requested data class for garbage collection.
 * It fills in the details in the supplied struct nuvo_segment.
 *
 * \retval negative for error.
 */
nuvo_return_t nuvo_mfst_segment_for_gc_debug(struct nuvo_mfst     *mfst,
                                             uint_fast32_t         parcel_index,
                                             uint_fast16_t         seg_idx,
                                             struct nuvo_segment **segment)
{
    nuvo_return_t rc;

    *segment = NULL;

    nuvo_mfst_in_core_lock(mfst);

    // MOre info on failures would be nice, but this is debug/test code...
    if (parcel_index >= mfst->num_parcel_indices)
    {
        rc = -1;
        goto failed;
    }
    if (mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_USABLE &&
        mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPENING &&
        mfst->parcel_state_mem[parcel_index].state != NUVO_MFST_PARCEL_OPEN)
    {
        rc = -1;
        goto failed;
    }
    if (seg_idx >= nuvo_mfst_parcel_segment_number_get(mfst, parcel_index))
    {
        rc = -1;
        goto failed;
    }
    uint_fast32_t segment_table_idx = mfst->parcel_state_mem[parcel_index].segment_offset + seg_idx;
    if (mfst->segment_state_media[segment_table_idx].seg_reserved ||
        mfst->segment_state_mem[segment_table_idx].seg_space_used)
    {
        rc = -1;
        goto failed;
    }
    if (mfst->segment_state_media[segment_table_idx].seg_age == 0)
    {
        // Not cleanable, possibly never used.
        rc = -1;
        goto failed;
    }

    *segment = nuvo_segment_alloc(&nuvo_global_segment_free_list);
    if (*segment == NULL)
    {
        rc = -1;
        goto failed;
    }

    nuvo_mfst_fill_nuvo_segment(mfst, parcel_index,
                                (nuvo_mfst_parcel_segment_size_get(mfst, parcel_index) / NUVO_BLOCK_SIZE) * seg_idx, *segment, true);
    nuvo_mfst_in_core_unlock(mfst);
    rc = open_segment_parcel(mfst, *segment);
    NUVO_ERROR_PRINT("Debug trigger for gc " NUVO_LOG_UUID_FMT ", (%d, %d) started.",
                     NUVO_LOG_UUID(nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst)->vs_uuid),
                     parcel_index, seg_idx);
    if (rc != 0)
    {
        nuvo_segment_free(&nuvo_global_segment_free_list, *segment);
        *segment = NULL;
    }
    return (rc);

failed:
    NUVO_ERROR_PRINT("Debug trigger for gc " NUVO_LOG_UUID_FMT ", (%d, %d) failed.",
                     NUVO_LOG_UUID(nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst)->vs_uuid),
                     parcel_index, seg_idx);
    nuvo_mfst_in_core_unlock(mfst);
    return (rc);
}

void nuvo_mfst_log_starts_set(struct nuvo_mfst    *mfst,
                              uint64_t             log_start_seq_no,
                              struct nuvo_segment *segments,
                              unsigned             num)
{
    NUVO_ASSERT(num <= NUVO_MFST_NUM_LOG_STARTS);

    /*
     * Set the in-core lock even though this will be called
     * during CP, because this is what sets the state that
     * gets written out and which is only read on start-up.
     */
    nuvo_mfst_in_core_lock(mfst);
    for (unsigned i = 0; i < num; i++)
    {
        mfst->header.log_segments[i].parcel_index = segments[i].parcel_index;
        mfst->header.log_segments[i].segment_index =
            segments[i].block_offset / (nuvo_mfst_parcel_segment_size_get(mfst, segments[i].parcel_index) / NUVO_BLOCK_SIZE);
        mfst->header.log_segments[i].subclass = segments[i].subclass;
    }
    mfst->header.log_start_seq_no = log_start_seq_no;
    mfst->header.num_used_log_starts = num;
    nuvo_mfst_in_core_unlock(mfst);
}

void nuvo_mfst_log_starts_get(struct nuvo_mfst    *mfst,
                              uint64_t            *sequence_no,
                              uint64_t            *segment_cnt_sequence_no,
                              unsigned            *num,
                              struct nuvo_segment *segments)
{
    NUVO_ASSERT(*num <= NUVO_MFST_NUM_LOG_STARTS);

    /*
     * Set the in-core lock even though this will be called
     * during CP, because this is what sets the state that
     * gets written out and which is only read on start-up.
     */
    nuvo_mfst_in_core_lock(mfst);
    for (unsigned i = 0; i < mfst->header.num_used_log_starts; i++)
    {
        segments[i].parcel_index = mfst->header.log_segments[i].parcel_index;
        segments[i].block_offset = mfst->header.log_segments[i].segment_index *
                                   (nuvo_mfst_parcel_segment_size_get(mfst, segments[i].parcel_index) / NUVO_BLOCK_SIZE);
        segments[i].subclass = mfst->header.log_segments[i].subclass;
    }
    *num = mfst->header.num_used_log_starts;
    *sequence_no = mfst->header.log_start_seq_no;
    *segment_cnt_sequence_no = mfst->header.log_segment_count_seq_no;
    nuvo_mfst_in_core_unlock(mfst);
}

static bool device_in_list(uint_fast32_t  device_index,
                           uint_fast32_t  num,
                           uint_fast32_t *avoid_dev)
{
    for (unsigned i = 0; i < num; i++)
    {
        if (device_index == avoid_dev[i])
        {
            return (true);
        }
    }
    return (false);
}

/**
 * \brief Fill out the basics of space info.
 *
 * Get info on segment usage.
 * Fills in the class_total_segments, class_free_segments, available_parcels
 * and segmentless_devices.
 *
 * \param mfst The manifest to fill in.
 * \param data_class Which data class we are interested in.
 * \param space_info The space_info to fill in.
 */
static void nuvo_mfst_segments_avail_int(struct nuvo_mfst            *mfst,
                                         uint8_t                      data_class,
                                         struct nuvo_mfst_space_info *space_info)
{
    NUVO_ASSERT_MUTEX_HELD(&mfst->mfst_mutex);
    space_info->class_total_segments = mfst->data_class[data_class].total_segments;
    space_info->class_free_segments = mfst->data_class[data_class].free_segments;
    space_info->class_free_this_cp = mfst->data_class[data_class].gc_free_current_cp;
    space_info->class_free_next_cp = mfst->data_class[data_class].gc_free_next_cp;
    space_info->available_parcels = mfst->data_class[data_class].available_parcels;
    space_info->device_free_segments = 0;
    space_info->devices_skipped = 0;
    space_info->segmentless_devices = 0;

    uint16_t device_index = mfst->data_class[data_class].device_most_free_segs;
    while (1)
    {
        if (mfst->device_state_mem[device_index].free_segments == 0)
        {
            space_info->segmentless_devices++;
        }
        if (device_index == mfst->device_state_mem[device_index].down_index)
        {
            break;
        }
        device_index = mfst->device_state_mem[device_index].down_index;
    }
}

void nuvo_mfst_segments_avail(struct nuvo_mfst            *mfst,
                              uint8_t                      data_class,
                              struct nuvo_mfst_space_info *space_info)
{
    nuvo_mfst_in_core_lock(mfst);
    nuvo_mfst_segments_avail_int(mfst, data_class, space_info);
    nuvo_mfst_in_core_unlock(mfst);
}

nuvo_return_t nuvo_mfst_segment_get(struct nuvo_mfst            *mfst,
                                    uint8_t                      data_class,
                                    unsigned                     num,
                                    uint_fast16_t               *avoid_dev,
                                    struct nuvo_segment         *segment,
                                    struct nuvo_mfst_space_info *space_info)
{
    nuvo_return_t rc;

    nuvo_mfst_in_core_lock(mfst);

    nuvo_mfst_segments_avail_int(mfst, data_class, space_info);

    if (mfst->data_class[data_class].device_most_free_segs == NUVO_NO_DEVICE_IN_CLASS)
    {
        NUVO_ASSERT(space_info->class_free_segments == 0);
        goto no_segment;
    }

    uint16_t device_index = mfst->data_class[data_class].device_most_free_segs;
    while (1)
    {
        if (mfst->device_state_mem[device_index].free_segments != 0)
        {
            if (!device_in_list(device_index, num, avoid_dev))
            {
                // Got one!
                // TODO - free segments?
                nuvo_mfst_find_segment(mfst, device_index, segment);
                space_info->device_free_segments = mfst->device_state_mem[device_index].free_segments;
                nuvo_mfst_in_core_unlock(mfst);
                rc = open_segment_parcel(mfst, segment);
                NUVO_ASSERT(rc == 0);  // TODO - handle failure to OPEN
                return (0);
            }
            else
            {
                space_info->devices_skipped++;
            }
        }

        if (device_index == mfst->device_state_mem[device_index].down_index)
        {
            break;
        }
        device_index = mfst->device_state_mem[device_index].down_index;
    }

no_segment:
    rc = -NUVO_E_NO_FREE_SEGMENTS;
    nuvo_mfst_in_core_unlock(mfst);
    return (rc);
}

// Documented in header
void nuvo_mfst_segment_done_int(struct nuvo_mfst *mfst, struct nuvo_segment *seg, enum nuvo_mfst_segment_reason_t reason)
{
    NUVO_ASSERT_MUTEX_HELD(&mfst->mfst_mutex);
    nuvo_segment_io_pin_count_dec(mfst, seg->parcel_index, seg->block_offset); // We currently pin an io as side effect of opening.
    switch (reason)
    {
    case NUVO_MFST_SEGMENT_REASON_UNCHANGED:
        nuvo_segment_space_pinned_clear(mfst, seg->parcel_index, seg->block_offset);
        break;

    case NUVO_MFST_SEGMENT_REASON_CLEAR_AGE:
        nuvo_mfst_slog_change_age(mfst, seg->parcel_index, seg->block_offset, false); // Condition variable wait inside.
        break;

    case NUVO_MFST_SEGMENT_REASON_SET_AGE:
        nuvo_mfst_slog_change_age(mfst, seg->parcel_index, seg->block_offset, true); // Condition variable wait inside.
        break;
    }
    if (seg->user == NUVO_SEGMENT_USER_GC)
    {
        NUVO_ASSERT(mfst->device_state_mem[seg->device_index].segments_in_gc >= 1);
        mfst->device_state_mem[seg->device_index].segments_in_gc--;
    }
}

void nuvo_mfst_segment_done(struct nuvo_mfst *mfst, struct nuvo_segment *seg, enum nuvo_mfst_segment_reason_t reason)
{
    nuvo_mfst_in_core_lock(mfst);
    nuvo_mfst_segment_done_int(mfst, seg, reason);
    nuvo_mfst_in_core_unlock(mfst);
}

// Documented in header
void nuvo_mfst_slog_init(struct nuvo_mfst_slog *slog, uint_fast32_t num)
{
    slog->entries_used = 0;
    NUVO_ASSERT(num <= NUVO_MFST_SLOG_MAX_ENTRIES);
    slog->max_entries = num;
    slog->num_waits = 0;
}

/**
 * Is the slog filling up?  Used to push back on mfl.
 */
bool nuvo_mfst_slog_filling(struct nuvo_vol *vol)
{
    struct nuvo_mfst *mfst = &vol->log_volume.mfst;

    nuvo_mfst_in_core_lock(mfst);
    // Strictly speaking the frozen test is redundant, !frozen implies entries_used is 0.
    bool filling = mfst->frozen && (mfst->slog.entries_used * 2 >= mfst->slog.max_entries);
    nuvo_mfst_in_core_unlock(mfst);
    return (filling);
}

/**
 * \brief Internal function to change usage of blocks.
 *
 * In the case that the manifest is not frozen, life is good.  Everything is simple.
 * Run the list, find the media entries, increment or decrement the values.
 *
 * If it is frozen, then we are putting counts into the slog. Look and see if the
 * entry you are working on is the same as the last.  If so change that entry. If not
 * create a new entry.  At some point in the middle we may find out we have run out
 * of entries.  I really don't want to pause in the middle of list of map entries,
 * with some in the slog and some not.  It offends my sensibilities.  So I want to
 * roll back.  For newly created entries, there is no big deal. Just discard the new entries.
 * But we may have changed a preexisting entry.  We need to set it back.  So remember it at the
 * beginning so we can roll back.
 *
 * \param mfst The manifest.
 * \param num The number of entries.
 * \param map_entry The array of map entries.
 * \param adding True for incrementing values, false for decrementing.
 * \param cow_write If this is a cow write, don't actually free blocks
 *        if they will move to snapshot.
 * \retval 0 Success.
 * \retval -NUVO_ENOSPC Frozen and could not fit it into the slog.
 */
nuvo_return_t nuvo_mfst_slog_blocks_int(struct nuvo_mfst            *mfst,
                                        uint_fast32_t                num,
                                        const struct nuvo_map_entry *map_entry,
                                        bool                         adding,
                                        bool                         cow_write)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t rollback_used;
    int_fast32_t  rollback_value;
    if (mfst->frozen)
    {
        /**
         * Might advance the entries used and might piggyback on last
         * entry.  If so, need to rollback both those
         * values if we run out of log space. this happens if there were old
         * entries and the last entry matches the current map entry.
         */
        rollback_used = mfst->slog.entries_used;
        if (rollback_used > 0 &&
            mfst->slog.log[rollback_used - 1].type == NUVO_MFST_SLOG_BLKS)
        {
            rollback_value = mfst->slog.log[rollback_used - 1].change;
        }
    }

    for (unsigned int i = 0; i < num; i++)
    {
        //process only if map says so
        if (!NUVO_ME_DO_SPACE_ACCOUNT(&(map_entry[i]), cow_write))
        {
            continue;
        }
        uint_fast32_t seg_idx = nuvo_mfst_seg_idx(mfst, map_entry[i].media_addr.parcel_index, map_entry[i].media_addr.block_offset);
        NUVO_LOG(mfst, 50, "Volume " NUVO_LOG_UUID_FMT ", %s parcel index %d block %d (seg_idx %u was %d)",
                 NUVO_LOG_UUID(nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst)->vs_uuid), adding ? "allocating" : "freeing", map_entry[i].media_addr.parcel_index, map_entry[i].media_addr.block_offset, seg_idx, mfst->segment_state_media[seg_idx].seg_blks_used)
        NUVO_PANIC_COND(mfst->segment_state_media[seg_idx].seg_reserved, "Setting blocks used for reserved block!");
        if (!mfst->frozen)
        {
            if (adding)
            {
                if (NUVO_MFST_SEGMENT_BLKS_USED_MAX >= mfst->segment_state_media[seg_idx].seg_blks_used)
                {
                    NUVO_PANIC_COND(NUVO_MFST_SEGMENT_BLKS_USED_MAX == mfst->segment_state_media[seg_idx].seg_blks_used, "Overflowing blocks used in segment.");
                    NUVO_ASSERT(NUVO_SEGMENT_IN_USE(mfst, seg_idx));  // should be pinned
                    mfst->segment_state_media[seg_idx].seg_blks_used++;
                }
                else
                {
                    NUVO_ERROR_PRINT("Overflowing blocks used in segment.");
                }
                // TODO Change device and class total.
            }
            else
            {
                if (mfst->segment_state_media[seg_idx].seg_blks_used > 0)
                {
                    NUVO_PANIC_COND(mfst->segment_state_media[seg_idx].seg_blks_used == 0, "Freeing block from empty segment.");
                    mfst->segment_state_media[seg_idx].seg_blks_used--;
                    NUVO_ASSERT(NUVO_SEGMENT_IN_USE(mfst, seg_idx));  // age is not 0 or logger flag is set.
                }
                else
                {
                    NUVO_ERROR_PRINT("Freeing block from empty segment.");
                }
                // CUM-1199 - consider giving a heads up to the garbage collector when blks_used gets low.
                // TODO Change device and class total.
            }
        }
        else
        {
            if (mfst->slog.entries_used > 0 &&
                mfst->slog.log[mfst->slog.entries_used - 1].type == NUVO_MFST_SLOG_BLKS &&
                mfst->slog.log[mfst->slog.entries_used - 1].segment_index == seg_idx)
            {
                // Piggyback on current last entry.
                mfst->slog.log[mfst->slog.entries_used - 1].change += adding ? 1 : -1;
            }
            else if (mfst->slog.entries_used < mfst->slog.max_entries)
            {
                // start a new entry
                mfst->slog.log[mfst->slog.entries_used].type = NUVO_MFST_SLOG_BLKS;
                mfst->slog.log[mfst->slog.entries_used].segment_index = seg_idx;
                mfst->slog.log[mfst->slog.entries_used].change = adding ? 1 : -1;
                mfst->slog.entries_used++;
            }
            else
            {
                /*
                 * No space. rollback
                 * Instead of rolling back we could put the condition wait here, but then
                 * we'd have to be careful about mfsts state changing in this function.
                 * Not clear that would be simpler.
                 */
                mfst->slog.entries_used = rollback_used;
                if (mfst->slog.entries_used > 0 &&
                    mfst->slog.log[mfst->slog.entries_used - 1].type == NUVO_MFST_SLOG_BLKS)
                {
                    mfst->slog.log[mfst->slog.entries_used - 1].change = rollback_value;
                }
                return (-NUVO_ENOSPC);
            }
        }
    }
    return (0);
}

// TODO - nuvo_mfst_segment_change_blks and nuvo_mfst_slog_change_age are inviting a deadlock.
// Need to avoid waiting on the cond variable here.
// Documented in header
void nuvo_mfst_segment_change_blks(struct nuvo_mfst            *mfst,
                                   uint_fast32_t                num,
                                   const struct nuvo_map_entry *map_entry,
                                   bool                         adding,
                                   bool                         cow_write)
{
    nuvo_return_t rc;

    nuvo_mfst_in_core_lock(mfst);
    if (mfst->enable_segment_count_changes)
    {
        while (0 != (rc = nuvo_mfst_slog_blocks_int(mfst, num, map_entry, adding, cow_write)))
        {
            NUVO_ASSERT(mfst->frozen && rc == -NUVO_ENOSPC);
            mfst->slog.num_waits++;
            nuvo_cond_wait(&mfst->cond_frozen, &mfst->mfst_mutex);
        }
    }
    else
    {
        NUVO_LOG(mfst, 30, "Not counting segment changes\n");
    }
    nuvo_mfst_in_core_unlock(mfst);
}

// Documented in header
void nuvo_mfst_slog_change_age(struct nuvo_mfst *mfst,
                               uint_fast32_t     parcel_index,
                               uint_fast32_t     block_offset,
                               bool              set_age)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t seg_idx = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    NUVO_PANIC_COND(mfst->segment_state_media[seg_idx].seg_reserved, "Setting age for reserved block!");
    NUVO_ASSERT(NUVO_SEGMENT_IN_USE(mfst, seg_idx));
    while (mfst->frozen && mfst->slog.entries_used == mfst->slog.max_entries)
    {
        mfst->slog.num_waits++;
        nuvo_cond_wait(&mfst->cond_frozen, &mfst->mfst_mutex);
    }
    uint64_t new_age = 0;
    if (set_age)
    {
        new_age = ++mfst->max_segment_age;
    }
    if (mfst->frozen)
    {
        mfst->slog.log[mfst->slog.entries_used].type = NUVO_MFST_SLOG_AGE;
        mfst->slog.log[mfst->slog.entries_used].segment_index = seg_idx;
        mfst->slog.log[mfst->slog.entries_used].age = new_age;
        mfst->slog.entries_used++;
    }
    else
    {
        mfst->segment_state_media[seg_idx].seg_age = new_age;
        // must disable this as part of CUM-1197
        // not disabled yet, because i do see the assert sometimes without it.
        // Debugging is TODO
        if ((new_age == 0) &&
            (mfst->segment_state_media[seg_idx].seg_blks_used != 0))
        {
            // CUM-1197 - Don't do this when PiT deletes works
            NUVO_ERROR_PRINT("CUM-1197 : zeroing blks used in segment %d (was %d)", seg_idx, mfst->segment_state_media[seg_idx].seg_blks_used);
            mfst->segment_state_media[seg_idx].seg_blks_used = 0;
        }
        NUVO_ASSERT(new_age != 0 || mfst->segment_state_media[seg_idx].seg_blks_used == 0);
        nuvo_segment_space_pinned_clear(mfst, parcel_index, block_offset);
    }
}

// Documented in header
void nuvo_mfst_slog_replay(struct nuvo_mfst *mfst)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    for (uint_fast32_t i = 0; i < mfst->slog.entries_used; i++)
    {
        int32_t blocks_used;
        bool    was_in_use = NUVO_SEGMENT_IN_USE(mfst, mfst->slog.log[i].segment_index);
        switch (mfst->slog.log[i].type)
        {
        case NUVO_MFST_SLOG_BLKS:
            blocks_used = mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_blks_used + mfst->slog.log[i].change;
            if (NUVO_MFST_SEGMENT_BLKS_USED_MAX < blocks_used)
            {
                NUVO_ERROR_PRINT("Overflowing blocks used in segment.");
                blocks_used = NUVO_MFST_SEGMENT_BLKS_USED_MAX;
            }
            if (0 > blocks_used)
            {
                NUVO_ERROR_PRINT("Underflowing blocks used in segment.");
                blocks_used = 0;
            }
            NUVO_PANIC_COND(NUVO_MFST_SEGMENT_BLKS_USED_MAX < blocks_used, "Overflowing blocks used in segment.");
            NUVO_PANIC_COND(0 > blocks_used, "Underflowing blocks used in segment.");
            mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_blks_used = blocks_used;
            break;

        case NUVO_MFST_SLOG_AGE:
            if ((mfst->slog.log[i].age == 0) &&
                (mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_blks_used != 0))
            {
                // CUM-1197 - Don't do this when PiT deletes works
                NUVO_ERROR_PRINT("CUM-1197 : zeroing blks used in segment %d (was %d)", mfst->slog.log[i].segment_index, mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_blks_used);
                mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_blks_used = 0;
            }
            NUVO_ASSERT(mfst->slog.log[i].age != 0 || mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_blks_used == 0);
            mfst->segment_state_media[mfst->slog.log[i].segment_index].seg_age = mfst->slog.log[i].age;
            mfst->segment_state_mem[mfst->slog.log[i].segment_index].seg_space_used = 0;
            break;

        default:
            NUVO_PANIC("Unexpected type value in log.");
        }
        bool in_use = NUVO_SEGMENT_IN_USE(mfst, mfst->slog.log[i].segment_index);
        NUVO_ASSERT(was_in_use == in_use);
    }
    mfst->slog.entries_used = 0;
}

void nuvo_mfst_print_space_pipeline(struct nuvo_mfst *mfst)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    // TODO - more stats.
    for (uint8_t dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        if (mfst->data_class[dc].gc_free_current_cp != 0 || mfst->data_class[dc].gc_free_next_cp != 0)
        {
            NUVO_LOG(space, 30, "vol gc pipeline: dc: %u, segments current cp: %u, segments next cp: %u",
                     dc,
                     mfst->data_class[dc].gc_free_current_cp,
                     mfst->data_class[dc].gc_free_next_cp);
        }
    }
}

uint_fast16_t nuvo_mfst_gc_pipeline_total(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);
    uint_fast16_t total = 0;
    for (uint8_t dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        total += mfst->data_class[dc].gc_free_current_cp + mfst->data_class[dc].gc_free_next_cp;
    }
    nuvo_mfst_in_core_unlock(mfst);
    return (total);
}

static inline uint_fast16_t nuvo_mfst_free_segments_pending(struct nuvo_mfst *mfst)
{
    uint_fast16_t max_pending = 0;

    for (uint8_t dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        if (max_pending < mfst->data_class[dc].gc_free_next_cp) // TODO - include pending parcel adds?
        {
            max_pending = mfst->data_class[dc].gc_free_next_cp;
        }
    }
    return (max_pending);
}

uint_fast16_t nuvo_mfst_cp_done_for_gc(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);
    struct nuvo_segment *segment;
    while (NULL != (segment = nuvo_dlist_remove_head_object(&mfst->segments_free_in_current_cp, struct nuvo_segment, list_node)))
    {
        NUVO_ASSERT(mfst->data_class[segment->data_class].gc_free_current_cp > 0);
        mfst->data_class[segment->data_class].gc_free_current_cp--;
        NUVO_ASSERT(mfst->device_state_mem[segment->device_index].gc_free_current_cp > 0);
        mfst->device_state_mem[segment->device_index].gc_free_current_cp--;

        struct nuvo_vol *vol = nuvo_containing_object(mfst, struct nuvo_vol, log_volume.mfst);
        NUVO_LOG(mfst, 40, "Done with segment (%d, %d) for " NUVO_LOG_UUID_FMT " setting age 0",
                 segment->parcel_index, segment->block_offset, vol->vs_uuid);
        nuvo_mfst_segment_done_int(mfst, segment, NUVO_MFST_SEGMENT_REASON_CLEAR_AGE);
        nuvo_segment_free(&nuvo_global_segment_free_list, segment);
    }
    for (uint8_t dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        mfst->data_class[dc].gc_free_current_cp = 0;
    }
    uint_fast16_t max_pending = nuvo_mfst_free_segments_pending(mfst);
    nuvo_mfst_print_space_pipeline(mfst);
    nuvo_mfst_in_core_unlock(mfst);
    return (max_pending);
}

uint_fast16_t nuvo_mfst_gc_free_next_cp(struct nuvo_mfst *mfst, struct nuvo_segment *segment)
{
    nuvo_mfst_in_core_lock(mfst);
    nuvo_dlist_insert_tail(&mfst->segments_free_in_next_cp, &segment->list_node);
    uint_fast16_t pending = ++mfst->data_class[segment->data_class].gc_free_next_cp;
    mfst->device_state_mem[segment->device_index].gc_free_next_cp++;
    nuvo_mfst_in_core_unlock(mfst);
    return (pending);
}

void nuvo_mfst_gc_starting_cp(struct nuvo_mfst *mfst)
{
    nuvo_mfst_in_core_lock(mfst);

    struct nuvo_segment *segment;
    for (uint8_t dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        NUVO_ASSERT(mfst->data_class[dc].gc_free_current_cp == 0);
    }
    while (NULL != (segment = nuvo_dlist_remove_head_object(&mfst->segments_free_in_next_cp, struct nuvo_segment, list_node)))
    {
        uint8_t dc = segment->data_class;
        NUVO_ASSERT(mfst->data_class[dc].gc_free_next_cp > 0);
        mfst->data_class[dc].gc_free_next_cp--;
        mfst->data_class[dc].gc_free_current_cp++;
        uint16_t device_index = segment->device_index;
        NUVO_ASSERT(mfst->device_state_mem[device_index].gc_free_next_cp > 0);
        mfst->device_state_mem[device_index].gc_free_next_cp--;
        mfst->device_state_mem[device_index].gc_free_current_cp++;
        nuvo_dlist_insert_tail(&mfst->segments_free_in_current_cp, &segment->list_node);
    }
    for (uint8_t dc = 0; dc < NUVO_MAX_DATA_CLASSES; dc++)
    {
        NUVO_ASSERT(mfst->data_class[dc].gc_free_next_cp == 0);
    }
    nuvo_mfst_print_space_pipeline(mfst);
    nuvo_mfst_in_core_unlock(mfst);
}

// Old cruft
uint64_t pm_total_size(struct nuvo_simple_parcel_manifest *pm)
{
    unsigned int i = 0;
    uint64_t     total_blocks = 0;

    while (i < pm->num_parcels)
    {
        total_blocks += pm->manifest[i].size_in_blocks;
        i++;
    }
    return (NUVO_BLOCK_SIZE * total_blocks);
}
