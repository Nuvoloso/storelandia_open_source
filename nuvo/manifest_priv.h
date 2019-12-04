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
 * @file manifest_priv.h
 * @brief Routines around the manifest.
 *
 * We have multiple tables, which we treat as one entity for disk purposes.
 *
 * The device table includes which devices are used by the volume.
 *
 * The parcel table includes descriptions of the parcels, and which
 * device they are located on.
 *
 * The segment table includes age information for the segments in parcels.
 *
 * The device table is smaller than the parcel manfiest and the manifest is much
 * smaller than the segment table.
 *
 * We are writing them all out together.
 */
#pragma once
#include <stdint.h>
#include <uuid/uuid.h>

#include "map_entry.h"
#include "nuvo_hash.h"
#include "nuvo_list.h"
#include "nuvo_pr.h"
#include "status.h"
#include "superblock.h"

/**********************************************************/
/* On Disk format                                         */
/**********************************************************/

/** \brief The Magic number for manifest headers. */
#define NUFO_MFST_MAGIC    0x6407b72dadd92ded

/*
 * The device table.
 */

/**
 * \brief The per-device entry into the device table.
 *
 * The \c device_class and \c parcel_size_in_blocks are redundant,
 * but I don't want to have a chat storm on every boot.
 *
 * The \c parcel_ration is not yet used, but we have discussed dreams for it,
 * so reserving space now.
 *
 * \c alloced_parcels is how many parcels we are using on the device. \c target
 * parcels is intended to be the target for how many we can use.  The command to
 * allow more parcels bump this number and then space management will decide when
 * to get parcels. Conversely, setting the target lower will drive the cleaner
 * to evacuate the device.  That is not yet implemented.
 *
 * Could go on a diet here or move some fields to in-memory at expense of device
 * info chattiness. There are are so few of these entries, it is
 * not worth the effort.
 */
struct __attribute__((packed)) nuvo_mfst_device_entry {
    uuid_t   device_uuid;                       /** The uuid of the device */
    uint64_t device_class;                      /** Class of device. Bloated. Doesn't matter, Saves space. */
    uint16_t target_parcels;                    /** How many we are "allowed" to have. */
    uint16_t alloced_parcels;                   /** Number of parcels allocated on this device. */
    uint32_t parcel_size_in_blocks;             /** How big are the parcels on this device. */
};
static_assert(sizeof(struct nuvo_mfst_device_entry) == 32, "Changed size of device entries!");

/**
 * \brief Types of parcel entries.
 */
enum nuvo_mfst_parcel_entry_type
{
    NUVO_MFST_PARCEL_ENTRY_UNUSED = 0,  /** Unused parcel entry. */
    NUVO_MFST_PARCEL_ENTRY_PARCEL = 1,  /** Parcel entry used for parcels. */
};

/**
 * \brief Entry into the parcel table.
 *
 * \c type determines which part of the union to use. At present
 * we only have normal parcels and unused slots.
 */
struct __attribute__((packed)) nuvo_mfst_parcel_entry {
    uint8_t type;                               /** Type of parcel. */
    union
    {
        struct __attribute__((packed)) {
            uuid_t   parcel_uuid;               /** Parcel uuid. */
            uint16_t device_idx;                /** Index into the device table. */
            uint8_t  segment_size_minus_1;      /** Compactly encode segment size. */
            uint8_t  number_segments_minus_1;   /** Compactly encode the number of segments. */
        } normal;                               /** Entry for normal segments. */
    };
};
static_assert(sizeof(struct nuvo_mfst_parcel_entry) == 21, "Changed size of parcel entries!");

struct __attribute__((packed)) nuvo_mfst_segment_entry {
    uint64_t seg_age: NUVO_MFST_AGE_BITS; /** TODO - what exactly is this value? */
    uint64_t seg_blks_used : 15;          /** Blocks in use in segment. Limits segments to 128ish MB. */
    uint64_t seg_reserved : 1;            /** This segment reserved for other use (such as table data) */
};
static_assert(sizeof(struct nuvo_mfst_segment_entry) == 8, "Changed size of segment entries!");

#define NUVO_MFST_SEGMENT_BLKS_USED_MAX    0x7FFF

/**********************************************************/
/* In core state                                          */
/**********************************************************/

/**
 * \brief Run-time states of parcels.
 */
enum nuvo_mfst_parcel_entry_state
{
    NUVO_MFST_PARCEL_NONE = 0,      /** There is no parcel. */
    NUVO_MFST_PARCEL_ADDING,        /** Manifest not written out yet, don't put data on this. */
    NUVO_MFST_PARCEL_USABLE,        /** There is a parcel, but not using it. */
    NUVO_MFST_PARCEL_OPENING,       /** Opening the parcel. */
    NUVO_MFST_PARCEL_OPEN           /** The parcel is open and has a parcel descriptor.*/
};

/**
 * \brief Run-time information for a parcel.
 */
struct nuvo_mfst_parcel_state_mem {
    uint32_t                          parcel_desc;    /** Parcel descriptor, if the parcel is open. */
    uint32_t                          segment_offset; /** Where are segment entries for this parcel
                                                       * This is implicit, computed at load.
                                                       */
    enum nuvo_mfst_parcel_entry_state state;          /** What configuration state the parcel is in. */
    enum nuvo_pr_parcel_status        health_status;  /** The health status for the parcel. */
    struct nuvo_dlnode                list_node;      /** For tracking unhealthy parcels. */
};

/** \brief How many operations are keeping this in memory.
 *
 * The primary (only?) intended user of this is to be able to count in-progress
 * I/Os so we won't re-use a segment from underneath in-progess IO's.
 * This counts per block.  That means that we can only have 64K blocks of IO in progress
 * for a segment at a time.  Since there are only 16K blocks in a maximum sized segment, and since
 * IO's are at most 256 blocks, this is probably a safe bet.
 */
struct nuvo_segment_pin_cnts {
    uint16_t seg_io         : 15;   /** Number of in progress IOs.  Segment logger/gc counts as 1. */
    uint16_t seg_space_used : 1;    /** Segment is delegated to logger or gc. */
};

/**
 * \brief Is the segment in use.
 *
 * Note that this uses the "on-disk" segment info data, and does not look at the log, so
 * it is unreliable if called while writing.
 *
 * THINK - change this macro to also look and ASSERT the mfst is not frozen?   I don't think we need to.
 */
#define NUVO_SEGMENT_IN_USE(mfst, seg_idx)    (               \
        (mfst)->segment_state_media[seg_idx].seg_age ||       \
        (mfst)->segment_state_mem[seg_idx].seg_io ||          \
        (mfst)->segment_state_mem[seg_idx].seg_space_used ||  \
        (mfst)->segment_state_media[seg_idx].seg_blks_used || \
        (mfst)->segment_state_media[seg_idx].seg_reserved)

/** This is just MAX_UINT15 */
#define NUVO_SEGMENT_PIN_IO_MAX    0x7FFF

/** Number of blocks need to hold a given number of device entries. */
#define NUVO_MFST_DEVICES_TO_BLKS(N)     (NUVO_BLOCK_ROUND_UP((N)*sizeof(struct nuvo_mfst_device_entry)) / NUVO_BLOCK_SIZE)

/** Number of device entries a given number of blocks can hold. */
#define NUVO_MFST_BLKS_TO_DEVICES(N)     (((N)*NUVO_BLOCK_SIZE) / sizeof(struct nuvo_mfst_device_entry))

/** Number of blocks need to hold a given number of parcel entries. */
#define NUVO_MFST_PARCELS_TO_BLKS(N)     (NUVO_BLOCK_ROUND_UP((N)*sizeof(struct nuvo_mfst_parcel_entry)) / NUVO_BLOCK_SIZE)

/** Number of device entries a given number of blocks can hold. */
#define NUVO_MFST_BLKS_TO_PARCELS(N)     (((N)*NUVO_BLOCK_SIZE) / sizeof(struct nuvo_mfst_parcel_entry))

/** Number of blocks need to hold a given number of segment entries. */
#define NUVO_MFST_SEGMENTS_TO_BLKS(N)    (NUVO_BLOCK_ROUND_UP((N)*sizeof(struct nuvo_mfst_segment_entry)) / NUVO_BLOCK_SIZE)

/** Number of segment entries a given number of blocks can hold. */
#define NUVO_MFST_BLKS_TO_SEGMENTS(N)    (((N)*NUVO_BLOCK_SIZE) / sizeof(struct nuvo_mfst_segment_entry))

/**
 * \brief Allocate a manifest header.
 *
 * Allocate the memory block for the header, but no other blocks.
 * In ordinary load path, we won't know how much to read until after we
 * read the header block, so we'll use the grow path to get more memory.
 *
 * Also inits the mutex and condition variables.
 *
 * \param mfst The manifest to have header resources alloced.
 * \retval -NUVO_ENOMEM or system call returns.
 * \retval -ENOMEM, which euals -NUVO_ENOMEM.
 */
nuvo_return_t nuvo_mfst_alloc_manifest(struct nuvo_mfst *mfst);

/**
 * \brief Allocate basic resources for a manifest header.
 *
 * Free everything from the manifest.  Burn it all down.
 * Free the header, the device table, the parcel table, the
 * segment table, the pin counts the parcel info, the slog,
 * the mutex, the condition varaibles.  Every.  Thing.
 *
 * \param mfst The manifest to have all resources freed.
 *
 */
void nuvo_mfst_free_manifest(struct nuvo_mfst *mfst);

/**
 * \brief Initialize a header.  All zeros. Except the magic.
 *
 * Useful at vol create time.
 * \param mfst Guess... Yep, the manifest.
 */
void nuvo_mfst_init_manifest_header(struct nuvo_mfst *mfst);

/**
 * \brief Init information in the manfiest which comes from the superblock.
 *
 * Useful when you've just read a superblock on volume load.
 * Allows us to avoid passing around pairs of mfst and superblock pointers.
 *
 * \param mfst The manifest.
 * \param sb The superblock.
 */
void nuvo_mfst_set_superblock_info(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb);

/**
 * \brief Ensure there is enough memory in the in-core device table to hold the devices.
 *
 * This will grow the in-core device table if needed. May move to new location.
 * Must be holding the mfst \c mutex.
 *
 * \param mfst The manifest.
 * \param num_devices The target number of devices.
 * \returns 0 or error.
 * \retval 0 There is enough memory.
 * \retval -NUVO_ENOMEM Could not make enough memory available.
 */
nuvo_return_t nuvo_mfst_grow_devices_mem(struct nuvo_mfst *mfst, uint16_t num_devices);

/**
 * \brief Find the device index for a device with a given uuid.
 *
 * Long search down short table.  Don't usually need to do this.
 *
 * \param mfst The manifest.
 * \param device_uuid The parcel_uuid to look for.
 * \param index To return the index.
 * \retval 0 Success
 * \retval -NUVO_ENOENT The is no such device in the device table.
 */
nuvo_return_t nuvo_mfst_find_device_index(struct nuvo_mfst *mfst, const uuid_t device_uuid, uint_fast32_t *index);

/**
 * \brief Set the parcel segment size.
 *
 * Long search down shortish table.  Don't usually need to do this.
 *
 * This is an inline rather than allowing direct access because we store the size
 * encoded as multiples of NUVO_SEGMENT_SIZE_INCREMENT and actually store
 * 1 less than the value, so we can fit the values 1 to 256 in a byte.
 *
 * \param mfst The manifest
 * \param index The segment index.
 * \param size The size of the segment.
 */
inline void nuvo_mfst_parcel_segment_size_set(struct nuvo_mfst *mfst, uint_fast32_t index, uint_fast32_t size)
{
    NUVO_ASSERT(size % NUVO_SEGMENT_SIZE_INCREMENT == 0);
    NUVO_ASSERT(size <= NUVO_SEGMENT_MAX_SIZE_BYTES);
    mfst->parcel_state_media[index].normal.segment_size_minus_1 = size / NUVO_SEGMENT_SIZE_INCREMENT - 1;
}

/**
 * \brief Get the parcel segment size.
 *
 * This is an inline rather than allowing direct access because we store the size
 * encoded as multiples of NUVO_SEGMENT_SIZE_INCREMENT and actually store
 * 1 less than the value, so we can fit the values 1 to 256 in a byte.
 *
 * \param mfst The manifest
 * \param index The segment index.
 * \returns The size of the segment in bytes
 */
inline uint32_t nuvo_mfst_parcel_segment_size_get(struct nuvo_mfst *mfst, uint_fast32_t index)
{
    return ((mfst->parcel_state_media[index].normal.segment_size_minus_1 + 1) * NUVO_SEGMENT_SIZE_INCREMENT);
}

/**
 * \brief Set the number of segments in a parcel.
 *
 * This is an inline rather than allowing direct access because we store the number
 * in a single byte and it ranges from 1 to 256.
 *
 * \param mfst The manifest
 * \param index The segment index.
 * \param number The number of segments.
 */
inline void nuvo_mfst_parcel_segment_number_set(struct nuvo_mfst *mfst, uint_fast32_t index, uint_fast32_t number)
{
    NUVO_ASSERT(number <= NUVO_SEGMENT_CNT_MAX);
    mfst->parcel_state_media[index].normal.number_segments_minus_1 = number - 1;
}

/**
 * \brief Get the number of segments in a parcel.
 *
 * This is an inline rather than allowing direct access because we store the number
 * in a single byte and it ranges from 1 to 256.
 *
 * \param mfst The manifest.
 * \param index The segment index.
 * \returns The number of segments.
 */
inline uint16_t nuvo_mfst_parcel_segment_number_get(struct nuvo_mfst *mfst, uint_fast32_t index)
{
    return (mfst->parcel_state_media[index].normal.number_segments_minus_1 + 1);
}

/**
 * \brief Ensure there is enough memory in the in-core parcel table to hold the parcels.
 *
 * This will grow the in-core parcel table if needed.  May move to new location.
 * Must be holding the mfst \c mutex.
 *
 * \param mfst The manifest.
 * \param num_parcels The target number of parcels.
 * \returns 0 or error.
 * \retval 0 There is enough memory.
 * \retval -NUVO_ENOMEM Could not make enough memory available.
 */
nuvo_return_t nuvo_mfst_grow_parcels_mem(struct nuvo_mfst *mfst, uint32_t num_parcels);

/**
 * \brief Find the parcel index for a parcel with a given uuid.
 *
 * \param mfst The manifest.
 * \param parcel_uuid The parcel_uuid to look for.
 * \param index To return the index.
 * \retval 0 Success
 * \retval -NUVO_ENOENT The is no such parcel in the manifest.
 */
nuvo_return_t nuvo_mfst_find_parcel_index(struct nuvo_mfst *mfst, uuid_t parcel_uuid, uint_fast32_t *index);

/** \brief synchronously opens a parcel and returns the parcel descriptor.
 *
 * This does a subest of nuvo_mfst_pin_open It opens the parcel for the given
 * \c parcel_index and returns the parcel descriptor in \c parcel_desc.
 *
 * Aside from things like theparcel not existing, the likely reason to
 * fail is that the parcel is not usable for some reason, such as the parcel still being in
 * added state.
 *
 * \retval 0 Success
 * \retval -NUVO_ENOMEM The mutex initialization failed.
 * \retval -NUVO_E_PARCEL_UNUSABLE The parcel cannot be opened.
 * \retval negative Other errors, including parcel router open errors.
 */
nuvo_return_t nuvo_mfst_open_parcel_sync(struct nuvo_mfst *mfst, uint_fast32_t parcel_index, uint_fast32_t *parcel_desc);

/**
 * \brief Close a parcel.
 *
 * This closes a parcel.  Forgiving, in that if it is not open it will tell you you are stupid.
 * If it is in active use, this will fail.  Maybe it should burn the village to the ground, but it
 * doesn't.
 *
 * \param mfst The manifest.
 * \param parcel_index Which parcel index are we closing.
 */
nuvo_return_t nuvo_mfst_close_parcel(struct nuvo_mfst *mfst, uint_fast32_t parcel_index);

/*
 * Synchronization strategy.
 *
 * Any caller that is changing either the on-disk state or the
 * in core state should hold the nuvo_mfst mutex while making
 * changes and only release it when the data is in a consistent
 * state.
 *
 * We want to allow some callers in while the writing process
 * is going on, so we do not hold the lock while writing.
 * Instead we set a "_frozen" boolean.  Callers lock using one
 * of two routines for locking.
 *
 * When the on-disk state is being written out it is marked
 * as frozen so we can keep any changes from happening.
 * Internal routines which make changes while the lock
 * is held should assert that they are holding the mutex
 * and that the disk state is not frozen. This is contained
 * within the NUVO_MFST_ASSERT_CHANGING_MEDIA and
 * NUVO_MFST_ASSERT_MUTEX_HELD macros.
 */

/**
 * \brief Lock the mfst to access everything but not change "disk" state.
 *
 * This is for the users that possibly modifying the in-core
 * state (like when adding a parcel descriptor to the table or
 * adjusting pin counts), but only using the on-disk read-only.
 * Users may also be changing the segment informtion via
 * the segment log.  In any case callers are not changing the
 * buffers that are written out, so this is acceptable while
 * writing the tables (dev/parcel/segment).
 *
 * \param mfst The manifest.
 */
void nuvo_mfst_in_core_lock(struct nuvo_mfst *mfst);

void nuvo_mfst_in_core_unlock(struct nuvo_mfst *mfst);

#define NUVO_MFST_ASSERT_MUTEX_HELD(mfst)    NUVO_ASSERT_MUTEX_HELD(&(mfst)->mfst_mutex)

/**
 * \brief Lock to make changes to disk structures for devices and parcels.
 *
 * This excludes everybody else and makes changes to the "disk" structures
 * for parcels and devices, so cannot run while we are writing the those structures out.
 * A caller to this while frozen is set will find themselves waiting on a condition
 * variable, and will not return from this routine until after the manifest is unfrozen.
 *
 * \param mfst The manifest.
 */
void nuvo_mfst_parcels_change_lock(struct nuvo_mfst *mfst);  // TODO - rename this set

/**
 * \brief Done changing device and parcel state.
 *
 * This is quivalent to nuvo_mfst_in_core_unlock with a little
 * addtional error checking code.
 *
 * \param mfst The manifest.
 */
void nuvo_mfst_parcels_change_unlock(struct nuvo_mfst *mfst);

/**
 * \brief Declare that code is changing device/parcel/segment on-media data.
 * Make sure that appropriate locking is being respected.
 */
#define NUVO_MFST_ASSERT_CHANGING_MEDIA(mfst)    { \
        NUVO_MFST_ASSERT_MUTEX_HELD(mfst);         \
        NUVO_ASSERT(!(mfst)->frozen);              \
        NUVO_ASSERT((mfst)->dirtying_media);       \
}

void nuvo_mfst_freeze_at_seqno(struct nuvo_mfst *mfst, uint64_t next_seq_no);

/**
 * \brief Set the manifest as frozen for writing.
 *
 * Set on-disk frozen for writing. At this point any callers to
 * nuvo_mfst_parcels_change_lock will wait on a condition variable.
 * Any calls to routines that change the segment table will be
 * redirected to the slog, or wait on the condition variable if
 * there is no slog space.
 */
void nuvo_mfst_writing_freeze(struct nuvo_mfst *mfst);

/**
 * \brief Adjust number of free segments for the device.
 *
 * This adjusts the number of free segments for the device.
 * Typically this will be -1 for an allocation, 1 for cleaning,
 * and larger numbers only when parcels complete allocating or begin
 * freeing (freeing is in future).
 *
 * \param mfst The manifest.
 * \param device_index The index in the device table of the device.
 * \param num The change in the number of segments.
 * \param total Should the change go into the total (i.e. parcel changes)
 */
void nuvo_mfst_device_free_segment_change(struct nuvo_mfst *mfst, uint16_t device_index, int16_t num, bool total);

/**
 * \brief Turn a parcel index and a block offset into a segment index.
 *
 * Use it while it's fresh, becuase if you drop the lock and the
 * manifest is not frozen, this may change.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index.
 * \param block_offset The block offset.
 * \return segment index.
 */
inline uint_fast32_t nuvo_mfst_seg_idx(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    NUVO_PANIC_COND(parcel_index >= mfst->num_parcel_indices, "parcel out of range");
    NUVO_PANIC_COND(mfst->parcel_state_media[parcel_index].type != NUVO_MFST_PARCEL_ENTRY_PARCEL, "Not a valid parcel");
    uint_fast32_t seg_in_parcel = (block_offset * NUVO_BLOCK_SIZE) / nuvo_mfst_parcel_segment_size_get(mfst, parcel_index);
    NUVO_PANIC_COND(seg_in_parcel >= nuvo_mfst_parcel_segment_number_get(mfst, parcel_index),
                    "block out of range for parcel");
    NUVO_ASSERT(mfst->parcel_state_mem[parcel_index].segment_offset + seg_in_parcel < mfst->num_segment_indices);
    return (mfst->parcel_state_mem[parcel_index].segment_offset + seg_in_parcel);
}

inline uint16_t nuvo_segment_get_blks_used(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    return (mfst->segment_state_media[segment_index].seg_blks_used);
}

/**
 * \brief Get the count of IO pins for the segment
 *
 * Only used for tests?
 */
inline uint16_t nuvo_segment_io_pin_count_get(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    return (mfst->segment_state_mem[segment_index].seg_io);
}

/**
 * \brief Increment the pin count for a given parcel_index and block offset.
 *
 * Increment the pin count but die a horrible death if the pin count overflows.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index.
 * \param block_offset The block offset.
 */
inline void nuvo_segment_io_pin_count_inc(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    NUVO_PANIC_COND(mfst->segment_state_mem[segment_index].seg_io == NUVO_SEGMENT_PIN_IO_MAX, "Overincrementing pin count!");
    NUVO_ASSERT(NUVO_SEGMENT_IN_USE(mfst, segment_index));
    mfst->segment_state_mem[segment_index].seg_io++;
}

/**
 * \brief Decremnent the pin count for a given parcel_index and block offset.
 *
 * Decrement the pin count but die a horrible death if the count underflows.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index.
 * \param block_offset The block offset.
 */
inline void nuvo_segment_io_pin_count_dec(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    NUVO_PANIC_COND(mfst->segment_state_mem[segment_index].seg_io == 0, "Unpinning with pin count 0");
    mfst->segment_state_mem[segment_index].seg_io--;
    if (!NUVO_SEGMENT_IN_USE(mfst, segment_index))
    {
        nuvo_mfst_device_free_segment_change(mfst, mfst->parcel_state_media[parcel_index].normal.device_idx, 1, false);
    }
}

/**
 * \brief Get whether the segment is handed off to the logger.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index.
 * \param block_offset The block offset.
 */
inline uint16_t nuvo_segment_space_pinned_get(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    return (mfst->segment_state_mem[segment_index].seg_space_used);
}

/**
 * \brief Set that segment is no longer handed off to the logger.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index.
 * \param block_offset The block offset.
 */
inline void nuvo_segment_space_pinned_clear(struct nuvo_mfst *mfst, uint64_t parcel_index, uint64_t block_offset)
{
    NUVO_MFST_ASSERT_MUTEX_HELD(mfst);
    uint_fast32_t segment_index = nuvo_mfst_seg_idx(mfst, parcel_index, block_offset);
    NUVO_ASSERT(mfst->segment_state_mem[segment_index].seg_space_used == 1);
    NUVO_ASSERT(mfst->segment_state_media[segment_index].seg_reserved == 0);
    mfst->segment_state_mem[segment_index].seg_space_used = 0;
    if (!NUVO_SEGMENT_IN_USE(mfst, segment_index))
    {
        nuvo_mfst_device_free_segment_change(mfst, mfst->parcel_state_media[parcel_index].normal.device_idx, 1, false);
    }
}

/**
 * \brief Internal function that records that blocks counts are changing for entries in a map.
 *
 * This records that map entries are being used or are no longer used, which
 * increments or decrements the blocks used for corresponding segments.
 *
 * Internally this either directly changes the counters or records that the
 * counters need to be changed depending on whether or not the manifest is frozen for
 * writing.
 *
 * This should be called holding the manifest mutex. this may sleep on a condition variable
 * if the manifest is being written and the in-memory log for such changes is full.
 *
 * \param mfst The manifest.
 * \param num number of map entries.
 * \param map_entry Array of map entries.
 * \param adding True for incrementing counts, false for decrementing.
 * \param cow_write Set True by COW(divergent) writes. If set, the cow blocks in the map_entries will not be freed
 * \sa nuvo_mfst_segment_free_blks, nuvo_mfst_segment_use_blks, nuvo_mfst_segment_free_blocks_for_cow
 */
void nuvo_mfst_segment_change_blks(struct nuvo_mfst            *mfst,
                                   uint_fast32_t                num,
                                   const struct nuvo_map_entry *map_entry,
                                   bool                         adding,
                                   bool                         cow_write);

/**
 * \brief Internal function that changes the age of a segment.
 *
 * This is an internal function that changes the age of a segment. Will wait
 * on the condition variable if the manifest is frozen and the slog is full.
 * Assumes that the segment being changed is pinned by the logger
 * and unpins it, immediately or when the manifest is unfrozen.
 *
 * \param mfst The manifest.
 * \param parcel_index The parcel index the segment lies within.
 * \param block_offset A block offset within the segment (use the first one).
 * \param set_age to set (vs. clear) the age for the segment.
 */
void nuvo_mfst_slog_change_age(struct nuvo_mfst *mfst,
                               uint_fast32_t     parcel_index,
                               uint_fast32_t     block_offset,
                               bool              set_age);

/**
 * \brief Initialize the in-memory log of changes to the segment table.
 *
 * Allocates memory for \c num changes in the log.  Note that consecutive
 * changes to the block counters of the same segment will be coalesced into
 * one change.  So we probably need fewer of these than would otherwise be true.
 *
 * \param slog The segment change log to initialize.
 * \param num How many entries to have in the log.
 */
void nuvo_mfst_slog_init(struct nuvo_mfst_slog *slog, uint_fast32_t num);

/**
 * \brief Replay the in-memory segment log.
 *
 * This plays changes from the in-memory log so segment changes to the segment table.
 * As a side effect clears the log.
 *
 * \param mfst The manifest.
 */
void nuvo_mfst_slog_replay(struct nuvo_mfst *mfst);

/**
 * \brief Start processing a nuvo_mfst_open_parcel.
 *
 * Finds the current state of the parcel.  If it is opened, this finishes quickly, if it is
 * not openable this also finishes quickly.  If it is NUVO_MFST_PARCEL_USABLE, then
 * the state moves to NUVO_MFST_PARCEL_OPENING and the process of sending a request to the
 * parcel router begins. If the request finds that another request has already started opening
 * then this request goes on the pending_opens list and waits for the open to complete.
 *
 * \param op the nuvo_mfst_open_parcel request structure.
 * \sa struct nuvo_mfst_open_parcel
 */
void nuvo_mfst_open_parcel_start(struct nuvo_mfst_open_parcel *op);

/**
 * \brief Callback for nuvo_mfst_open_parcel_sync.
 * \param open The open structure.
 * \sa nuvo_mfst_open_parcel_sync
 */
void nuvo_mfst_open_parcel_sync_cb(struct nuvo_mfst_open_parcel *open);

/**
 * \ brief Validate that the number of free segments for the device is correct.
 *
 * \param mfst The manifest.
 * \param dev_index The index of the device to check.
 */
void mfst_validate_free_segments(struct nuvo_mfst *mfst,
                                 uint32_t          dev_index);

#define NUVO_NO_DEVICE_IN_CLASS    -1
void insert_device_in_free_segment_list(struct nuvo_mfst *mfst, uint16_t dev_index);
