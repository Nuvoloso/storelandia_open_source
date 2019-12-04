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
 * @file manifest.h
 * @brief Routines around the manifest.
 *
 * We have multiple tables.
 *
 * Lun table includes the luns (active+snapshots) of the volume.
 * Device table includes which devices are used by the volume.
 * Parcel table includes descriptions of the parcels, each on a device.
 * Segment table includes age information for the segments in parcels.
 *
 * The device table is smaller than the parcel table and the parcel table is much
 * smaller than the segment table.
 * We are writing them all out together.
 */
#pragma once
#include <stdint.h>
#include <assert.h>
#include <uuid/uuid.h>

#include <nuvo.pb-c.h>

#include "lun.h"
#include "map_entry.h"
#include "nuvo_hash.h"
#include "nuvo_list.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "nuvo_pr_parallel.h"
#include "segment.h"
#include "status.h"
#include "superblock.h"
#include "device_type.h"

struct nuvo_mfst;

/** Limit on the number of usable devices.
 * This is really just a limit on a stupid array in a stupid function that
 * puts segments into the free list for the segment logger.  Doesn't
 * actually limit device table, because the right thing to do is not to
 * limit the device table.
 */
#define NUVO_MFST_DEVICE_LIMIT    512

/** By agreement with the parcel router, this value will never be used as a parcel descriptor. */
#define NUVO_VOL_PD_UNUSED        UINT32_MAX

/** \brief Defines the data classes used for grouping segments */
enum nuvo_data_class
{
    NUVO_DATA_CLASS_A     = 0,
    NUVO_DATA_CLASS_B     = 1,
    NUVO_DATA_CLASS_C     = 2,
    NUVO_MAX_DATA_CLASSES = 3
};

/**
 * Segments are intended to be between 4MB and 64MB, with sizes a multiple
 * of 256KB.
 */
#define NUVO_SEGMENT_CNT_MIN                1
#define NUVO_SEGMENT_CNT_MAX                256

/** Segments are sized as multiples of NUVO_SEGMENT_SIZE_INCREMENT */
#define NUVO_SEGMENT_SIZE_INCREMENT         (256 * 1024)
#define NUVO_SEGMENT_MIN_SIZE_INCREMENTS    16
#define NUVO_SEGMENT_MAX_SIZE_INCREMENTS    256

/** Minimum segment size. 4MB */
#define NUVO_SEGMENT_MIN_SIZE_BLOCKS        1024
#define NUVO_SEGMENT_MIN_SIZE_BYTES         (NUVO_SEGMENT_MIN_SIZE_BLOCKS * NUVO_BLOCK_SIZE)
static_assert(NUVO_SEGMENT_MIN_SIZE_BYTES % NUVO_SEGMENT_SIZE_INCREMENT == 0, "Min segment size is whack!");
static_assert(NUVO_SEGMENT_MIN_SIZE_BYTES == NUVO_SEGMENT_SIZE_INCREMENT * NUVO_SEGMENT_MIN_SIZE_INCREMENTS, "Min segment size is whack!");

// Maximum segment size.  64MB. */
#define NUVO_SEGMENT_MAX_SIZE_BLOCKS    (16 * 1024)
#define NUVO_SEGMENT_MAX_SIZE_BYTES     (NUVO_SEGMENT_MAX_SIZE_BLOCKS * NUVO_BLOCK_SIZE)
static_assert(NUVO_SEGMENT_MAX_SIZE_BYTES % NUVO_SEGMENT_SIZE_INCREMENT == 0, "Max segment size is whack!");
static_assert(NUVO_SEGMENT_MAX_SIZE_BYTES == NUVO_SEGMENT_SIZE_INCREMENT * NUVO_SEGMENT_MAX_SIZE_INCREMENTS, "Max segment size is whack!");

/** Default to the minimum segment size. TODO - Change to use this in the code, then stop only ever using default*/
#define NUVO_DEFAULT_SEGMENT_SIZE    (NUVO_SEGMENT_MIN_SIZE_BLOCKS * NUVO_BLOCK_SIZE)

struct __attribute__((packed)) nuvo_mfst_log_entry {
    uint32_t parcel_index : 24;     /** The parcel index for a segment. */
    uint8_t  segment_index;         /** Which segment within the parcel. */
    uint8_t  subclass;              /** The subclass assigned by the logger */
};
static_assert(sizeof(struct nuvo_mfst_log_entry) == 5, "Changed size of log start entries!");
#define NUVO_MFST_NUM_LOG_STARTS      256

/**
 * The number of blocks in the lun table. Changing this changes the on-disk format.  Which destorys existing volumes.
 */
#define NUVO_MFST_LUN_TABLE_BLOCKS    2
static_assert(NUVO_MFST_LUN_TABLE_BLOCKS == 2, "Somebody changed number of blocks in lun table, changing on-disk format!");

/**
 * \brief The header for a manfiest. - On disk 4KB structure.
 */
struct __attribute__((packed)) nuvo_mfst_header {
    union
    {
        struct __attribute__((packed)) {
            uint64_t    magic;                 /** Magic number.  Same for every mfst of this format. */
            uint64_t    generation;            /** Generation number. Strictly increasing. */
            nuvo_hash_t hash;                  /** Hash of the header and contents of the three tables. */

            uint64_t log_start_seq_no;         /** Only replay log entries with this sequence number or higher. */
            uint64_t log_segment_count_seq_no; /** Only do segment counts with this sequence number or higher */

            uint16_t num_used_luns;
            uint16_t num_used_log_starts;
            uint16_t num_used_devices;                                         /** Number of devices in use. */
            uint32_t num_used_parcels;                                         /** Number of parcels in use. */

            uint16_t num_lun_blocks;                                           /** Always 2 unless we change the code. */
            uint16_t num_device_blocks;                                        /** Number of blocks used for devices. */
            uint32_t num_parcel_blocks;                                        /** Number of blocks used for parcels. */
            uint32_t num_segment_blocks;                                       /** Number of blocks used for segments. */
            uint32_t unused;                                                   /** Was used, don't want to move stuff. */
            struct nuvo_mfst_log_entry log_segments[NUVO_MFST_NUM_LOG_STARTS]; /** log start segments */
        };
        uint8_t data[NUVO_BLOCK_SIZE];                                         /** Reserve 4KB for normal header */
    };
};
static_assert(sizeof(struct nuvo_mfst_header) == NUVO_BLOCK_SIZE, "Changed size of header!");

/*
 * The LUN table.
 * For each LUN we need to know the root map, the size, the UUID and the
 * snapid.
 */
struct __attribute__((packed)) nuvo_mfst_lun_entry {
    union
    {
        struct __attribute__((packed)) {
            uuid_t   lun_uuid;
            uint64_t size;
            struct nuvo_map_entry root_map_entry;
            uint8_t  map_height;
            uint32_t snap_id;
            uint8_t  lun_state;
        };
        unsigned char data[128];
    };
};
static_assert(sizeof(struct nuvo_mfst_lun_entry) == 128, "Changed size of lun entries!");

/**
 * The number of blocks in the lun table. Changing this changes the on-disk format.  Which destroys existing volumes.
 */
#define NUVO_MFST_LUN_TABLE_BLOCKS    2
static_assert(NUVO_MFST_LUN_TABLE_BLOCKS == 2, "Somebody changed number of blocks in lun table, changing on-disk format!");

#define NUVO_MFST_MAX_LUNS            (NUVO_MFST_LUN_TABLE_BLOCKS * NUVO_BLOCK_SIZE / sizeof(struct nuvo_mfst_lun_entry))
static_assert(NUVO_MFST_MAX_LUNS == 64, "Wrong number of luns in table");

// Since snapids go up over time, make active lun "infinity"
#define NUVO_MFST_ACTIVE_LUN_SNAPID    UINT32_MAX
#define NUVO_MFST_ACTIVE_LUN_INDEX     (0)

/**
 * Logging of segment changes while the tables are frozen for writes.
 *
 * While the tables that are written to disk are being written, we do not want to change them.
 * this is not a big problem for parcels or devices, but segment information gets changed
 * regularly during the course of operation.  Segment limits the impact of the writing by
 * storing segment changes in memory and applying them after the write is done.
 *
 * This means that the segment table information is unreliable while writing is occurring.
 * The segment table is used to guide decisions about which parcels to write to or clean based on the
 * age and blks used of a segment.
 *
 * The worst possible consequence of having the wrong information would be to choose a segment that
 * was in fact in use for writing.  To prevent this we do not allow choosing for segment logging
 * while writing is in progress.
 *
 * Entries in the log are indexed by segment.  Since the segment log is only ever used when the
 * manifest is frozen and the segment indices only ever change when it is not frozen, this is safe.
 *
 * Entries for block changes are numbers, not bits, to handle the common case that requests will
 * repeatedly change blocks for the same segment.  As currently implemented, this is only used
 * for immediate repeats (i.e. changing the same segment block count as the last entry in the log.)
 * This could be extended or changed.
 */

/**
 * \brief enum to identify types of log entries.
 */
enum nuvo_mfst_slog_type
{
    NUVO_MFST_SLOG_BLKS,    /** A SLOG entry changing blocks for a segment. */
    NUVO_MFST_SLOG_AGE      /** A SLOG entry changing the age of a segment. */
};

#define NUVO_MFST_AGE_BITS    48

/**
 * \brief An individual entry into a SLOG.
 */
struct nuvo_mfst_slog_entry {
    enum nuvo_mfst_slog_type type;              /** Type of entry. */
    uint32_t                 segment_index;     /** The segment index. */
    union
    {
        uint64_t     age : NUVO_MFST_AGE_BITS;  /** The age to set. */
        int_fast32_t change;                    /** Change to the block count. */
    };
};

/*
 * Really want to replace this.
 * Make it store updates to segment table, in a hash table.
 * That way we don't get duplicate entries, even if entries are larger.
 * For now, making this bigger alongside changes to avoid filling this and dealing with
 * fullness better.
 */
#define NUVO_MFST_SLOG_MAX_ENTRIES    (20000)

/**
 * \brief A log of segment changes for a manifest.
 */
struct nuvo_mfst_slog {
    uint_fast32_t               entries_used;                    /** How many entries are used. */
    uint_fast32_t               max_entries;                     /** Maximum number of entries (can be smaller than MAX for test) */
    struct nuvo_mfst_slog_entry log[NUVO_MFST_SLOG_MAX_ENTRIES]; /** The entries. */
    uint64_t                    num_waits;                       /** Number of times a client has waited because the log was full. */
};

/**
 * \brief The manifest for devices, parcels and segments.
 */
struct nuvo_mfst {
    struct nuvo_mutex                  mfst_mutex;     /** Mutex for changing the manifest. */
    bool                               dirtying_media; /** Are dirtying the blocks that go to media. */
    bool                               frozen;         /** Have frozen the on-disk to prevent changes while writing. */
    pthread_cond_t                     cond_frozen;    /** Place for threads that need to change on-media wait. */

    // In core state (i.e. never go to media)
    uint32_t                           max_segment_age;
    struct {
        int32_t  device_most_free_segs;    /** Device index that has most free segments, or -1 if no devices. */
        uint32_t available_parcels;        /** How many parcels can we go get. */
        int32_t  total_segments;           /** Total number of segments on this device. */
        int32_t  free_segments;            /** How many free segments are available in this class. */
        uint16_t gc_free_current_cp;       /** Number of gc segments free in current cp. */
        uint16_t gc_free_next_cp;          /** Number of gc segments free in next cp. */
                                           /** CUM-1213- count of used/free blocks? */
        uint64_t used_blocks;              /** Blocks used. */
        uint64_t total_mfst_blocks;        /** Blocks currently in volume. */
        uint64_t total_parcel_blocks;      /** Including parcels available to us. */
    }                                  data_class[NUVO_MAX_DATA_CLASSES];

    struct {
        int_fast32_t       free_segments;                             /** Number of free segments on this device */
        uint_fast16_t      up_index;                                  /** device with more free segments */
        uint_fast16_t      down_index;                                /** device with fewer free segments */
                                                                      /** CUM-1213 - count of used/free blocks? */
                                                                      /** CUM-1199 - cache hints about known free segments. */
        uint8_t            gc_free_current_cp;                        /** Number of gc segments free in current cp. */  /* TODO - overflow */
        uint8_t            gc_free_next_cp;                           /** Number of gc segments free in next cp. */ /* TODO - overflow */
        uint_fast16_t      segments_in_gc;                            /** How many segments are in gc processing. */
        struct nuvo_dlist  segs_for_gc;                               /** List of segments cached for future gc. */
        enum nuvo_dev_type device_type;                               /** The type of device */
    }                                  device_state_mem[NUVO_MFST_DEVICE_LIMIT];

    uint32_t                           num_parcel_indices;            /** The number of parcel indices */
    struct nuvo_mfst_parcel_state_mem *parcel_state_mem;              /** In core state for parcels */

    bool                               enable_segment_count_changes;  /** Allow or disallow segment coutn changes */
    uint32_t                           num_segment_allocated_indices; /** Num we have memory array for */
    uint32_t                           num_segment_indices;           /** Num in use. */
    struct nuvo_segment_pin_cnts      *segment_state_mem;             /** In core data for segments (pin counts, etc.)*/
    struct nuvo_mfst_slog              slog;                          /** Log of changes to on-media segment state. */

    struct nuvo_dlist                  pending_opens;                 /** List of structs for async open parcels */
    struct nuvo_dlist                  unhealthy_parcels;             /** List of parcels that are not reachable or degraded. */

    struct nuvo_dlist                  segments_free_in_current_cp;   /** List of segments free in current CP. */
    struct nuvo_dlist                  segments_free_in_next_cp;      /** List of segments free in next CP. */

    // From superblock.
    uuid_t                             vs_uuid;                     /** The volume UUID.  TODO - need here? */
    uint32_t                           num_device_parcel_blocks;    /** How many blocks we have in memory for non-segment table. */
    uint32_t                           num_segment_table_blocks;    /** How many blocks we have in memory for segment table. */

    // On media structures
    struct nuvo_mfst_header            header __attribute__ ((aligned(NUVO_BLOCK_SIZE)));
    struct nuvo_mfst_lun_entry         lun_table[NUVO_MFST_MAX_LUNS] __attribute__ ((aligned(NUVO_BLOCK_SIZE)));

    uint16_t                           alloced_device_blocks;   /** Number of in-core blocks for devices */
    struct nuvo_mfst_device_entry     *device_state_media;      /** The on-media device state. */

    uint32_t                           alloced_parcel_blocks;   /** Number of in-core blocks for parcels */
    struct nuvo_mfst_parcel_entry     *parcel_state_media;      /** The on-media parcel state. */

    uint32_t                           alloced_segment_blocks;  /** Number of in-core blocks for segments */
    struct nuvo_mfst_segment_entry    *segment_state_media;     /** The on-media segment state. */
};


/**
 * \brief Initialize a new volume
 *
 * Assumes that the root parcel has been created.  This sets up the super block,
 * Choosing locations within the parcel for both copies of the tables.  Marks the segment(s)
 * used for the superblock, header and table as reserved.
 * This will insert the root_parcel_desc into the table and mark the parcel open.   This will make you
 * happier if you want to write out your shiny new superblock and manifest later.
 *
 * This initializes the active lun.
 * It allocates the first segment as the intial log location.
 *
 * This does not write out the superblock/manifest.
 *
 * \param sb The superblock to fill in.
 * \param mfst The manifest to fill in.
 * \param vol_uuid The uuid of the volume.
 * \param root_device_uuid The uuid of the root device.
 * \param root_parcel_uuid The uuid of the root parcel.
 * \param root_parcel_desc Descriptor of parcel if open, otherwise NUVO_MFST_PARCEL_USABLE.
 * \param parcel_size_blocks Size of the parcel.  You know because you just created it.
 * \param device_class The data class of the device.
 * \param device_class The type of device.
 * \param segment_size Size of segments.
 * \param blks_for_parcels How many blks to reserve for each copy of the header/dev/parcel table.
 * \param blks_for_segments How many blks to reserve for each copy of the segment table.
 * \param lun_size Size of active lun.
 * \returns 0 on success.  Negative on failure.
 * \retval -NUVO_EINVAL. Segment size was bad.
 * \retval -NUVO_ENOSPC. No space for initial tables, or no space in the tables for the one parcel.  Loser.
 */
nuvo_return_t nuvo_mfst_sb_init(struct nuvo_sb_superblock *sb,
                                struct nuvo_mfst          *mfst,
                                const uuid_t               vol_uuid,
                                const uuid_t               root_device_uuid,
                                uuid_t                     root_parcel_uuid,
                                uint_fast32_t              root_parcel_desc,
                                uint32_t                   parcel_size_blocks,
                                uint8_t                    device_class,
                                uint8_t                    device_type,
                                uint32_t                   segment_size,
                                uint32_t                   blks_for_parcels,
                                uint32_t                   blks_for_segments,
                                uint64_t                   lun_size);

/**
 * \brief Write the whole manifest.  This routine is only used at init
 * and during tests.
 */
nuvo_return_t nuvo_mfst_sync_write(struct nuvo_mfst          *mfst,
                                   struct nuvo_sb_superblock *sb,
                                   uint64_t                   log_seq_no,
                                   uint64_t                   seg_seq_no);

/**
 * \brief Iterates and sends the device table, the parcel table and the segment table.
 *
 * The writes are async.  \p par_io and \p sync_signal should have been
 * initialized before calling.
 *
 * \param mfst The manifest,
 * \param sb The superblock.
 * \param par_io The nuvo_parallel_io struct.
 * \param sync_signal The mutex to use with nuvo_pr_sync_client_req_alloc.
 * \param freeze_seq_no The sequence number at which we froze segment counts.
 */
void nuvo_mfst_write_start(struct nuvo_mfst          *mfst,
                           struct nuvo_sb_superblock *sb,
                           struct nuvo_parallel_io   *par_io,
                           nuvo_mutex_t              *sync_signal,
                           uint64_t                   freeze_seq_no);

/**
 * \brief Computes manifest hash, sends header and lun table, starts finishing writing manifest.
 *
 * The writes are async.  \p par_io and \p sync_signal should have been
 * initialized before calling.
 *
 * \param mfst The manifest,
 * \param sb The superblock.
 * \param par_io The nuvo_parallel_io struct.
 * \param sync_signal The mutex to use with nuvo_pr_sync_client_req_alloc.
 */
void nuvo_mfst_write_final_writes(struct nuvo_mfst          *mfst,
                                  struct nuvo_sb_superblock *sb,
                                  struct nuvo_parallel_io   *par_io,
                                  nuvo_mutex_t              *sync_signal);

/**
 * \brief Set the manifest as no longer frozen for writing.
 *
 * This does a few other things.
 *
 * It moves any parcels that are in NUVO_MFST_PARCEL_ADDING
 * state to the NUVO_MFST_PARCEL_USABLE state. Parcels are only added
 * while not frozen and since these just made it out to "disk" and we can
 * start using them, this adds free segments for the device/data_class.
 *
 * It plays the slog onto the segment table.
 *
 * It broadcasts to the condition variable.
 *
 * Done writing out disk state. Allow modifiers in now.
 */
void nuvo_mfst_writing_thaw(struct nuvo_mfst *mfst);

bool nuvo_mfst_slog_filling(struct nuvo_vol *vol);

/**
 * \brief Read in manifest.
 *
 * We already have a superblock.  This will read both manifest headers, choose the valid-ish
 * one that is most recent, read in those tables, check the hash and make sure it is all good.
 * If the hash fails, try the other one on the theory that we died while writing.
 * Init everything.  And by everything, I mean everthiung, but mostly the parcel info, which
 * maps parcels indices to segment indices.
 *
 * Assumes you already opened the root parcel, since you read the superblock.
 *
 * \param mfst The manifest to be set up from the on-media information.
 * \param sb The superblock we read in previously.
 * \param root_parcel_desc The parcel descriptor for the root parcel.
 * \param open_parcels Whether to open all of the non-root parcels.
 */
nuvo_return_t nuvo_mfst_sync_read(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb, uint_fast32_t root_parcel_desc, bool open_parcels);

/**
 * \brief Pick some segments to clean on a given device.
 *
 * \param mfst The manifest.
 * \param dev_index The index of the device to get segments from.
 * \param num_requested How many to put on the list.
 * \param cutoff Don't return segments more than cutoff percent full.
 * \param chosen_segs The list to fill with segments.
 * \retval non-negative The number returned.
 * \retval negative Error in opening parcels.
 */
nuvo_return_t nuvo_mfst_segments_gc_device(struct nuvo_mfst  *mfst,
                                           uint_fast16_t      dev_index,
                                           int_fast16_t       num_requested,
                                           uint_fast8_t       cutoff,
                                           struct nuvo_dlist *chosen_segs);

/**
 * \brief Get a segment for garbage collectiom.
 *
 * This wrapper exists to make a one-call interface for gc.
 * A successful call will include all relevant information on
 * the segment including opening it and returning the parcel descriptor.
 *
 * \param mfst The manifest.
 * \param data_class The data class of segment we want.
 * \param segment The pointer to return a segment
 * \returns 0 or error
 * \retval -NUVO_E_NO_CLEANABLE_SEGMENT No segment could be found to clean.
 * \retval negative if parcel could not be opened.
 */
nuvo_return_t nuvo_mfst_segment_for_gc(struct nuvo_mfst     *mfst,
                                       uint8_t               data_class,
                                       struct nuvo_segment **segment);

/**
 * \brief Start garbage collection on a particular segment, if possible.
 *
 * This is called (indirectly) by debug trigger to clean a particular segment in tests.
 *
 * \param mfst The manifest.
 * \param parcel_index The index into the parcel table.
 * \param seg_idx Which of that parcels segemnts to gc (Starts at 0).
 * \param segment A pointer to return a nuvo_segment.
 * \returns negative if not cleanable, for any reason.
 */
nuvo_return_t nuvo_mfst_segment_for_gc_debug(struct nuvo_mfst     *mfst,
                                             uint_fast32_t         parcel_index,
                                             uint_fast16_t         seg_idx,
                                             struct nuvo_segment **segment);

/**
 * \brief Get a nuvo_segment for logger/replay.
 *
 * This wrapper exists to make a one-call interface for the replay/logger.
 * Call this with a parcel_index and the block_offset of the parcel and a
 * nuvo_segment to fill out.  This will include all relevant information on
 * the segment including opening it and returning the parcel descriptor.
 *
 * \param mfst The manifest.
 * \param parcel_index Which parcel is needed.
 * \param block_offset A block within the parcel.
 * \param segment The segment structure to fill.
 * \retval 0 on success.
 * \retval negative A problem occurred, probably could not open segment.
 */
nuvo_return_t nuvo_mfst_segment_for_log_replay(struct nuvo_mfst    *mfst,
                                               uint32_t             parcel_index,
                                               uint32_t             block_offset,
                                               struct nuvo_segment *segment);

/**
 * \brief Set the addresses of the start of the log in the manifest.
 *
 * Pass in the number of starting segments and parcel_index/block_offset addresses.
 * This gets the manifest lock in-core style even though it is obviously changing
 * on disk state, because it needs to be called during CP, and it assumes you know
 * what you are doing. Don't disappoint me, JohnE.
 *
 * \param mfst The manifest.
 * \param log_start_seq_no What sequence number to start replay at.
 * \param num How many segments are at the start of the log.
 * \param segments The segment addresses and subclass.
 */
void nuvo_mfst_log_starts_set(struct nuvo_mfst    *mfst,
                              uint64_t             log_start_seq_no,
                              struct nuvo_segment *segments,
                              unsigned             num);

/**
 * \brief Get the addresses of the start of the log in the manifest.
 *
 * Pass in the number of starting segments and parcel_index/block_offset addresses.
 * this only gets called at open time (init or start).
 *
 * \param mfst The manifest.
 * \param sequence_no The sequence number to start replaying ops at.
 * \param segment_cnt_sequence_no The sequence number to start replaying segment counts at.
 * \param num How many segments are at the start of the log.
 * \param segments The segment addresses and subclass.
 */
void nuvo_mfst_log_starts_get(struct nuvo_mfst    *mfst,
                              uint64_t            *sequence_no,
                              uint64_t            *segment_cnt_sequence_no,
                              unsigned            *num,
                              struct nuvo_segment *segments);

/**
 * \brief Get the active lun.
 *
 * Copy the root entry, size and height into the lun.
 *
 * \param mfst The manifest
 * \param active_lun The lun to fill in.
 */
nuvo_return_t nuvo_mfst_get_active_lun(struct nuvo_mfst *mfst,
                                       struct nuvo_lun  *active_lun);

/**
 * \brief Get the luns (active and pits).
 *
 * Copy the root entry, size and height for each  lun.
 *
 * \param vol The volume to get the luns from.
 * \param luns the array of luns
 * \param lun_count the size of the array
 */
nuvo_return_t nuvo_mfst_get_luns(struct nuvo_vol *vol,
                                 struct nuvo_lun *luns,
                                 int              lun_count);

/**
 * \brief set the luns to be written out at next checkpoint.
 *
 * \param mfst The manifest
 * \param num_luns How many luns there are.
 * \param entries The entry for each lun.
 */
void nuvo_mfst_set_luns(struct nuvo_mfst           *mfst,
                        uint_fast16_t               num_luns,
                        struct nuvo_mfst_lun_entry *entries);

nuvo_return_t nuvo_mfst_close_all_parcels(struct nuvo_mfst *mfst);
nuvo_return_t nuvo_mfst_close(struct nuvo_mfst *mfst);

/**
 * \brief Allocate basic resources for a manifest header.
 *
 * Free everything from the manifest.  Burn it all down.
 * Free the header, the device table, the parcel table, the
 * segment table, the pin counts the parcel info, the slog,
 * the mutex, the condition variables.  Every.  Thing.
 *
 * \param mfst The manifest to have all resources freed.
 */
void nuvo_mfst_free_manifest(struct nuvo_mfst *mfst);

/** \brief free blocks referenced to by the map entries.
 *
 * For every media entry in the list, this finds the corresponding segment
 * and decrements the use counts. In agregate this will decrease segement
 * table counts by no more than \c num, fewer if some of the map entries
 * do no refer to media blocks.
 *
 * Does internal locking, the caller doesn't need to worry about it.
 *
 * \param mfst The parcel manifest.
 * \param num The number of map entries.
 * \param map_entry Array of map entries.
 * \sa nuvo_mfst_segment_use_blks
 */
void nuvo_mfst_segment_free_blks(struct nuvo_mfst            *mfst,
                                 uint_fast32_t                num,
                                 const struct nuvo_map_entry *map_entry);

/** \brief increment blocks referenced to by the map entries.
 *
 * For every media entry in the list, this finds the corresponding segment
 * and increments the use counts. In agregate this will decrease segement
 * table counts by no more than \c num, fewer if some of the map entries
 * do not refer to media blocks.
 *
 * Does internal locking, the caller doesn't need to worry about it.
 *
 * \param mfst The parcel manifest.
 * \param num The number of map entries.
 * \param map_entry Array of map entries.
 * \sa nuvo_mfst_segment_free_blks
 */
void nuvo_mfst_segment_use_blks(struct nuvo_mfst            *mfst,
                                uint_fast32_t                num,
                                const struct nuvo_map_entry *map_entry);

/** \brief same as nuvo_mfst_segment_free_blks but for the COW aka write divergence path.
 * \sa nuvo_mfst_segment_free_blks
 * free blocks for the COW(divergence) code path which could involve cow blocks.
 * We dont want to free COW blocks in the divergent code path since
 * these blocks will be used by the snap lun
 * \param mfst The parcel manifest.
 * \param num The number of map entries.
 * \param map_entry Array of map entries.
 */

void nuvo_mfst_segment_free_blks_for_cow(struct nuvo_mfst            *mfst,
                                         uint_fast32_t                num,
                                         const struct nuvo_map_entry *map_entry);

/**
 * \brief Struct to aynchronously handle opening a parcel.
 *
 * This is only in teh public header because we need it in the pin request.
 *
 * The user wants to get the manifest to open a parcel.
 * This reuqires IO to the parcel router, possible
 * sleeps, and managing state.  The caller sets up the op mfst,
 * the index (\c idx) they want opened, callback info (\c caller
 * and \c tag) and calls nuvo_mfst_open_parcel_start.
 *
 * How it all works:
 *
 * Clients have parcel indexes and want to somehow turn them into parcel descriptors
 * so they can do IO. The nuvo_mfst_open_* routines manage this.
 *
 * Parcels that are really usable are in one the states:
 *
 *      NUVO_MFST_PARCEL_USABLE - The parcel is usable, but not open.
 *      NUVO_MFST_PARCEL_OPENING - The system is currently opening the parcel.
 *      NUVO_MFST_PARCEL_OPEN - The parcel is open and the parcel_state_mem in the mfst has a descriptor.
 *
 * To get the parcel descriptor, the caller builds a struct nuvo_mfst_open_parcel with the manifest
 * (\c mfst), the parcel index (\c idx) and callback information (\c callback and \c tag).
 *
 * This calls nuvo_mfst_open_parcel_start which will:
 *     - Return an error through the callback if the parcel is unopenable.
 *     - If parcel is NUVO_MFST_PARCEL_OPEN, returns the pd through the callback.
 *.    - If the parcel is NUVO_MFST_PARCEL_OPENING, wait on the pending_opens list.
 *     - If the parcel is NUVO_MFST_PARCEL_USABLE, do a little more setup and get a request by calling
 *       nuvo_pr_client_req_alloc_cb.
 *
 * nuvo_mfst_open_parcel_alloc_cb runs when the pr io_req is alloced.  It setups up the io request to do the open.
 * and sends it to the pr.
 *
 * nuvo_mfst_open_parcel_io_cb is called when the open completes.
 * On failure this moves the parcel state to NUVO_MFST_PARCEL_USABLE. Might be better to have a
 * state like NUVO_MFST_PARCEL_BROKEN_WE_ARE_ALL_DOOMED.
 *
 * On success nuvo_mfst_open_parcel_io_cb moves moves the parcel state to NUVO_MFST_PARCEL_OPEN, records
 * the parcel descriptor in the parcel table.
 *
 * For the nuvo_mfst_open_parcel request and any matching requests on the pending_opens list,
 * nuvo_mfst_open_parcel_io_cb sets the parcel_desc and status fields from the parcel router IO
 * request and does their callback.
 *
 * \sa nuvo_mfst_open_parcel_start, nuvo_mfst_open_parcel_alloc_cb, nuvo_mfst_open_parcel_io_cb,
 *     nuvo_mfst_open_parcel_sync_cb, nuvo_mfst_open_parcel_sync
 */
struct nuvo_mfst_open_parcel {
    struct nuvo_dlnode       node;           /** List for putting this on pending list. */

    // inputs
    struct nuvo_mfst        *mfst;                                        /** The manifest. */
    uint32_t                 idx;                                         /** The index of the parcel to open. */
    void                     (*callback)(struct nuvo_mfst_open_parcel *); /** Callback for when op is done. */
    union nuvo_tag           tag;                                         /** Whatever the caller wants. */

    // results
    nuvo_return_t            status;         /** For returning status */
    uint32_t                 parcel_desc;    /** The parcel descriptor when open succeeds. */

    // Internals : UUIDS copied from manifest so we can drop the mutex during IO.
    uuid_t                   vs_uuid;        /** vs_uuid from manifest. */
    uuid_t                   device_uuid;    /** device_uuid from manifest. */
    uuid_t                   parcel_uuid;    /** parcel_uuid from manifest. */

    struct nuvo_pr_req_alloc req_alloc;      /** To ask nuvo_pr for an io_req. */
    struct nuvo_io_request  *io_req;         /** The io_req to send to nuvo_pr. */
};

/**
 * \brief Structure for getting parcel descriptors.
 *
 * nuvo_mfst_open_async and it's synchronous sibling nuvo_mfst_pin_open
 * use this structure.
 *
 * The caller supplies the manifest pointer \c mfst, the \c num_map_entries and \c map_entry array.
 * The caller sets the \c callback function and \c tag and \c pds to return the descriptors.
 * The two routines return the descriptors on success.  The async routine returns the
 * status through \c status.
 *
 * \sa nuvo_mfst_open_async, nuvo_mfst_pin_open
 */
struct nuvo_mfst_map_open {
    // inputs
    struct nuvo_mfst            *mfst;                                     /** The manifest. */
    unsigned int                 num_map_entries;                          /** Number of map entries to return descriptors of*/
    const struct nuvo_map_entry *map_entry;                                /** The map entries */

    void                         (*callback)(struct nuvo_mfst_map_open *); /** The callback. */
    union nuvo_tag               tag;                                      /** Tag for callback use. */

    // returns
    uint_fast32_t               *pds;               /** The parcel descriptors returned. */
    nuvo_return_t                status;            /** The status. */

    // internals
    struct nuvo_mfst_open_parcel open;              /** Internal open parcel structure. */
    unsigned int                 working_on;        /** Pointer to which entry working on. */
};

/**
 * \brief Async call to get parcel descriptors.
 *
 * The caller sets up the map_open_req with mfst, num_map_entries, map_entry array , callback function,
 * tag, and pds array.
 *
 * Also makes sure the parcels have been opened and returns the parcel descriptors in \c pds.
 * This does not guarantee that the parcel descriptors remain valid, since it cannot do so.
 * Since this may do parcel opens it may take time.
 *
 * In the typical case this that parcels are already open, this will execute the callback before
 * returning.
 *
 * This does not guarantee that the parcel descriptors remain valid, since it cannot do so.
 *
 * On call back the status will be 0 on success, -NUVO_ENOMEM on mutex initialization failure or
 * other negative if the parcel router opens failed.
 *
 * \param map_open_req The request.
 * \sa nuvo_mfst_map_open, nuvo_mfst_pin_open
 */
void nuvo_mfst_open_async(struct nuvo_mfst_map_open *map_open_req);

/** \brief pin the segments reference by the map entries and return parcel descriptors for each.
 *
 * Sync interface to nuvo_mfst_open_async
 *
 * \param mfst The parcel manifest.
 * \param num The number of map entries.
 * \param map_entry Array of map entries.
 * \param pds Array to return parcel descriptors.
 * \retval 0 Success
 * \retval -NUVO_ENOMEM Mutex initiation failed.  "Won't happen."
 * \returns 0 on success, negative on failure, including failure returns from parcel router.
 * \sa nuvo_mfst_map_open, nuvo_mfst_open_async
 */
nuvo_return_t nuvo_mfst_pin_open(struct nuvo_mfst            *mfst,
                                 uint_fast32_t                num,
                                 const struct nuvo_map_entry *map_entry,
                                 uint_fast32_t               *pds);

/** \brief pin segments.
 *
 * For every media entry in \c map_entry, find the appropriate segment and pin it. Pinning marks the
 * segments as having in-progress IO, which prevents the segment cleaner from pulling the segment
 * out from under in-progress IO.
 *
 * Does internal locking, the caller doesn't need to worry about it.
 *
 * \param mfst The parcel manifest.
 * \param num The number of map entries.
 * \param map_entry Array of map entries.
 */
void nuvo_mfst_pin(struct nuvo_mfst            *mfst,
                   uint_fast32_t                num,
                   const struct nuvo_map_entry *map_entry);

/** \brief Unpin segments.
 *
 * Unpins segments to indicate IO's have been completed.
 *
 * Does internal locking, the caller doesn't need to worry about it.
 *
 * \param mfst The parcel manifest.
 * \param num The number of map entries.
 * \param map_entry Array of map entries.
 */
void nuvo_mfst_unpin(struct nuvo_mfst            *mfst,
                     uint_fast32_t                num,
                     const struct nuvo_map_entry *map_entry);

/**
 * \brief Information to add a device as used by a volume.
 */
struct nuvo_mfst_insert_device_info {
    uuid_t             device_uuid;           /** The UUID of the device */
    uint8_t            device_class;          /** The storage class of the device. */
    uint32_t           parcel_size_in_blocks; /** Size of parcels in blocks. */
    enum nuvo_dev_type device_type;           /** The type of device. */
};

/**
 * \brief Add a list of devices to the manifest.
 *
 * If a device is already in the manifest, an addition is ignored.
 * Similarly, only the first entry in the list is applied.  Will
 * add all devices or fail.  Does not write out the manifest.
 *
 * \param mfst Manifest to which to add.
 * \param num Number of devices on the list.
 * \param devices List of devices.
 * \retval 0 Success
 * \retval -NUVO_ENOSPC Cannot make space to add device.
 * \retval -NUVO_ENOMEM Cannot grow tables.
 */
nuvo_return_t nuvo_mfst_insert_devices(struct nuvo_mfst                    *mfst,
                                       unsigned int                         num,
                                       struct nuvo_mfst_insert_device_info *devices);

/**
 * \brief Add a single device.  Convenience wrapper for nuvo_mfst_insert_devices.
 *
 * Adds a single device to the manifest.
 *
 * \param mfst Manifest to which to add.
 * \param device_uuid UUID of the device.
 * \param device_class Data class of the device.
 * \param parcel_size_blocks Size of parcels in blocks.
 * \param device_type The type of device.
 * \retval 0 Success
 * \retval -NUVO_ENOSPC Cannot make space to add device.
 * \retval -NUVO_ENOMEM Cannot grow tables.
 */
nuvo_return_t nuvo_mfst_insert_device(struct nuvo_mfst        *mfst,
                                      const uuid_t             device_uuid,
                                      const uint8_t            device_class,
                                      const enum nuvo_dev_type device_type,
                                      const uint32_t           parcel_size_blocks);

/**
 * \brief Tell the manifest it is "allowed" \c num parcels on \c device_uuid
 * \param mfst The manifest.
 * \param device_uuid The uuid of the device.
 * \param num the number of parcels allowed.
 */
nuvo_return_t nuvo_mfst_device_parcel_target(struct nuvo_mfst *mfst,
                                             const uuid_t      device_uuid,
                                             uint16_t          num);

/**
 * \brief Information to add a parcel.
 */
struct nuvo_mfst_parcel_insert_info {
    uuid_t               device_uuid;        /** UUID of the device. */
    uuid_t               parcel_uuid;        /** UUID of the parcel. */
    uint32_t             segment_size_bytes; /** Segment size in bytes.  Why not blocks? */
    uint16_t             number_segments;    /** Number of segments to put in device.
                                              * 0 means put as many as will fit. */
    enum nuvo_data_class device_class;       /** The class of the device the parcel was added on. */
    uint_fast32_t        pd;                 /** parcel descriptor for the parcel. */
};

/**
 * \brief Add a list of parcels to the manifest.
 *
 * Each parcel should reference devices which have been previously
 * added. All succeed or fail together. Repeat adds will fail.
 * Also grows the segment table.  Does not write out the manifest.
 * No segments in the added parcels will be available until the
 * manifest has been written to disk.
 *
 * \param mfst Manifest to which to add.
 * \param num Number of parcels on the list.
 * \param parcels List of parcels.
 * \retval 0 Success
 * \retval -NUVO_ENOSPC Cannot make space to add parcels.
 * \retval -NUVO_EINVAL Problem with number of segments or size.
 * \retval -NUVO_EEXIST One of the parcels is already there!
 * \retval -NUVO_ENOMEM Could not grow tables.
 */
nuvo_return_t nuvo_mfst_insert_parcels(struct nuvo_mfst                    *mfst,
                                       unsigned int                         num,
                                       struct nuvo_mfst_parcel_insert_info *parcels);

/**
 * \brief Add a single parcel. Convenience wrapper for nuvo_mfst_insert_parcels.
 *
 * Adds a single parcel to the manifest.
 *
 * \param mfst Manifest to which to add.
 * \param device_uuid UUID of the device.
 * \param parcel_uuid UUID of the parcel.
 * \param segment_size_bytes Size of segments in bytes (why!)
 * \param number_segments How many segments. (0 - means calculate)
 * \param device_class Returns the device class so space can be sensible.
 * \retval 0 Success
 * \retval -NUVO_ENOSPC Cannot make space to add parcel.
 * \retval -NUVO_ENOMEM Cannot grow tables.
 * \retval -NUVO_EEXIST One of the parcels is already there!
 * \retval -NUVO_ENOMEM Could not grow tables.
 */
nuvo_return_t nuvo_mfst_insert_parcel(struct nuvo_mfst *mfst,
                                      const uuid_t      device_uuid,
                                      const uuid_t      parcel_uuid,
                                      const uint32_t    segment_size_bytes,
                                      uint16_t         *number_segments,
                                      uint8_t          *device_class,
                                      uint_fast32_t     pd);

/**
 * \ brief Find the highest used parcel index.
 *
 * This is used for deletion.
 *
 * \param mfst The manifest.
 * \param parcel_uuid To return the uuid of the parcel.
 * \param device_uuid To return the uuid of the device the parcel is on.
 * \returns index or error.
 * \retval non-negative is index of the parcel.
 * \retval negative is error code.
 */
nuvo_return_t nuvo_mfst_find_highest_parcel_index(struct nuvo_mfst *mfst,
                                                  uuid_t            parcel_uuid,
                                                  uuid_t            device_uuid);

/**
 * \brief Remove parcels from the parcel table.
 *
 * This will be handy to destroy volumes and some day to remove individual parcels.
 *
 * \param mfst The manifest.
 * \param num The number.
 * \param uuid The list of uuids to remove.
 * \param destroying Whether we are removing for destroying the volume.
 */
nuvo_return_t nuvo_mfst_remove_parcels(struct nuvo_mfst *mfst,
                                       unsigned int      num,
                                       uuid_t           *uuid,
                                       bool              destroying);

nuvo_return_t nuvo_mfst_set_parcel_health(struct nuvo_vol           *vol,
                                          uuid_t                     parcel_uuid,
                                          enum nuvo_pr_parcel_status status);

bool nuvo_mfst_are_all_parcels_healthy(struct nuvo_mfst *mfst);


struct nuvo_segment;

/*
 * FREE SEGMENT HANDLING
 *
 * This code defines a free segment to be a segment that segments not in use by IO (the io_cnt) or by the
 * logger or garbage collector (the logger bit), and which has both block count and age of zero in the
 * on_media parcel manifest.
 *
 * Every transition of a segment between used and free is counted in the device and data class free_segments
 * count.  We only count segments as free if the age is zero, because if we used the segment age less than
 * log start, we would not know which segments might change state when that boundary ended.  Since the segments
 * that we have very recently used are not likely to be completely free, that transition case would be rare.
 *
 * This does imply that the cleaner will have to search for segments to move to the clean state.  But it had
 * to do that anyway.  This does not preclude the cleaner or manifest from caching hints about which segments
 * are known to be free, so this does not impose additional scanning.
 *
 * When new parcels are allocated, the segments become available when the parcel moves from ADDING state to
 * USABLE state.  At that time free segments are added to the free segment counters in the volume and the device.
 *
 * LOG PINNING
 *
 * When segments are handed to the space management system (either for use by the logger or the garbage collector)
 * the segment is marked with the "logger" flag.  This prevents us from allowing the same segment to be worked on
 * twice.  When segments are returned to the manifest, this flag is cleared.  To be more precise, this flag is
 * immediately cleared if the age is not changed.  If the age is set, the flag is cleared when the age setting
 * reaches the on_media state of the segment table.  this allows us to rely on the on_media version of the
 * table when looking for free segments even if we are in CP.
 */

/**
 * \brief Struct to return information about free space.
 */
struct nuvo_mfst_space_info {
    uint_fast32_t class_total_segments;     /** How many total segments are still in this class. */
    uint_fast32_t class_free_segments;      /** How many segments are free in this class. */
    uint_fast32_t class_free_this_cp;       /** How many segments will be freed this cp. */
    uint_fast32_t class_free_next_cp;       /** How many segments wiil be free next cp. */
    uint_fast32_t available_parcels;        /** How many more parcels are we allowed to allocate in this class. */
    uint_fast32_t segmentless_devices;      /** If we fail, how many devices have no segments? */

    /* Only make sense to nuvo_mfst_segment_get */
    uint_fast32_t devices_skipped;          /** How many devices did we skip because they were in exclude list. */
    uint_fast32_t device_free_segments;     /** How many segments are free on the returned device. */
};

/**
 * \brief Get the free segments usage within the mfst.
 * Gets the number of total segments, clean segments, available parcels and
 * how many devices have all segmments used.
 *
 * \param mfst The manifest
 * \param data_class Which data class we are interested in.
 * \param space_info The structure to fill with data.
 */
void nuvo_mfst_segments_avail(struct nuvo_mfst            *mfst,
                              uint8_t                      data_class,
                              struct nuvo_mfst_space_info *space_info);

/**
 * \brief Call to get a free segment from the manifest.
 *
 * This attempts to return a free segment of the requested data class from the
 * manifest, while not returning a segment in the list of \p avoid_dev.
 * Information about the segment is returned in \p segment.  Information about
 * how many segments are available in this class and on this device are returned via
 * space_info.
 *
 * \param mfst The manifest.
 * \param data_class The class of data segments being requested.
 * \param num The number of devices to avoid allocating from.
 * \param avoid_dev The array of device indices to ignore.
 * \param segment Pointer to the segment structure to fill.
 * \param space_info To return information about how many free segments are available.
 * \returns 0 or an error return.
 * \retval -NUVO_E_NO_FREE_SEGMENTS There are no free segments on devices no in avoid_dev.
 */
nuvo_return_t nuvo_mfst_segment_get(struct nuvo_mfst            *mfst,
                                    uint8_t                      data_class,
                                    unsigned                     num,
                                    uint_fast16_t               *avoid_dev,
                                    struct nuvo_segment         *segment,
                                    struct nuvo_mfst_space_info *space_info);

enum nuvo_mfst_segment_reason_t
{
    NUVO_MFST_SEGMENT_REASON_UNCHANGED = 0,
    NUVO_MFST_SEGMENT_REASON_CLEAR_AGE,
    NUVO_MFST_SEGMENT_REASON_SET_AGE,
};

/**
 * \brief Done with a segment.
 *
 * This returns the segment and sets the age.
 * Ordinarily this grabs the \c mfst mutex, clears some bits and gets out.
 * This may indirectly suspend for IO in the event that the system is writing out the
 * manifest and the in-memory segment log is full.
 *
 * \param mfst The parcel manifest.
 * \param seg The segment being returned.
 * \param reason Set, clear, or do nothing with the age.
 */
void nuvo_mfst_segment_done(struct nuvo_mfst               *mfst,
                            struct nuvo_segment            *seg,
                            enum nuvo_mfst_segment_reason_t reason);

/**
 * \brief Build a message out of a manifest.
 *
 * \brief The manifest.
 * \brief msg The message to fill.
 * \brief short_reply Whether to just send device info.
 */
nuvo_return_t nuvo_mfst_get_manifest(struct nuvo_mfst *mfst,
                                     Nuvo__Manifest   *msg,
                                     bool              short_reply);


/**
 * \brief Choose a device for a new parcel.
 *
 * This picks a device that we could get a new parcel on, based on  free space within the parcel.
 * For convenience of allocation decisions, this also passes back how many free segments are on the
 * device.  That allows the space management to decide not to allocate.
 *
 * The device is passed back in the device_uuid, since the pr wants a device_uuid.  null uuid, means none.
 *
 * \param mfst The manifest
 * \param data_class The data class of device we want a segment from.
 * \param device_uuid To return the device to allocate a parcel from.  null uuid, means none.
 * \param free_segments To return the number of free segments.
 */
void nuvo_mfst_choose_device_for_new_parcel(struct nuvo_mfst *mfst,
                                            uint8_t           data_class,
                                            uuid_t            device_uuid,
                                            int_fast32_t     *free_segments);

/**
 * \brief Start recording segments counts for each operation.
 *
 * Prior to calling this segment count updates for a volume will be ignored.
 * Once it is called we count the changes until we reopen the volume.
 *
 * \param mfst The mfst of the volume.
 */
void nuvo_mfst_seg_counts_start(struct nuvo_mfst *mfst);

/**
 * \brief Freeze the mfst and record the given sequence number.
 *
 * \param mfst The mfst of the volume.
 * \param next_seq_no The mfst includes every op up to this point.
 */
void nuvo_mfst_freeze_at_seqno(struct nuvo_mfst *mfst, uint64_t next_seq_no);

/**
 * \brief Fill in a VolStatus protobuf for a volume.
 *
 * \param mfst The mfst of the volume.
 * \param status The status to fill in.
 * \retval 0 Success.
 * \retval -NUVO_ENOMEM Memory allocation error.
 */
nuvo_return_t nuvo_mfst_get_vol_status(struct nuvo_mfst *mfst, Nuvo__VolStatus *status);

enum nuvo_sb_update_op_t
{
    NUVO_SB_REPLAY_COUNT_ZERO,
    NUVO_SB_REPLAY_COUNT_INCR
};
#define NUVO_MAX_REPLAY_ATTEMPTS    (3)

/**
 * \brief Records the volume replay count in the manifest
 *
 * Each time a volume starts replay the replay count is incremented and
 * written to the superblock along with the git commit hash of the nuvo software.
 * If replay is successful the replay count is reset to zero and the superblock
 * is updated.
 *
 * A replay count > 0 means the volume replay failed.
 *
 * NUVO_SB_REPLAY_COUNT_ZERO resets the replay_count in the superblock to zero
 * NUVO_SB_REPLAY_COUNT_INCR increments the current replay_count by one.
 *
 * \param mfst Pointer to the volume manifest
 * \param sb Pointer to the volume superblock
 * \param op How to update the replay_count
 * \returns 0 if successful, otherwise the error
 */
nuvo_return_t nuvo_mfst_sb_update_replay_count(struct nuvo_mfst *mfst, struct nuvo_sb_superblock *sb, enum nuvo_sb_update_op_t op);

/**
 * \brief Print out information about the pipeline.
 * \param mfst The manifest.
 */
void nuvo_mfst_print_space_pipeline(struct nuvo_mfst *mfst);

/**
 * \brief Return the number of segments being freed.
 * \param mfst The manifest.
 * \returns Number of segments to be freed.
 */
uint_fast16_t nuvo_mfst_gc_pipeline_total(struct nuvo_mfst *mfst);

/**
 * \brief Mark that a CP is done, move gc segments along.
 *
 * \param mfst The manifest.
 * \returns Max number of segments free in next CP of any class.
 */
uint_fast16_t nuvo_mfst_cp_done_for_gc(struct nuvo_mfst *mfst);

/**
 * \brief The segment will be freed in next CP.
 * \param mfst The manifest.
 * \param segment The segment to be freed in the next CP.
 * \returns Number of segments in this class free at next CP.
 */
uint_fast16_t nuvo_mfst_gc_free_next_cp(struct nuvo_mfst *mfst, struct nuvo_segment *segment);

/**
 * \brief Starting a CP.
 *
 * Moves segments that are on list for freed in the next CP to
 * free in the CP we are starting.
 * \param The manifest.
 */
void nuvo_mfst_gc_starting_cp(struct nuvo_mfst *mfst);

/**
 * \brief Return any cached segments waiting for gc.
 *
 * If the manifest has segments that have been selected for future
 * gc, unpin them and return the segment structures to the
 * free list.   Used when shutting down.
 * \param mfst The manifest.
 */
void nuvo_mfst_return_gc_segments(struct nuvo_mfst *mfst);

/*************************************************************************************************************
 *
 * KEEP REAL VOLUME STUFF ABOVE HERE!  PARCEL VOLUME STUFF BELOW!
 *
 * Below here is the parcel manager for the "parcel volumes". May eventually purge this.
 * For now this is pretty lame. Making the parcel manifest a table and writing the whole
 * thing out at once, and only keeping one copy of it.
 */
struct nuvo_parcel_manifest_entry {
    uuid_t   parcel_id;
    uuid_t   device_id;
    uint32_t size_in_blocks;
};

#define MAX_PARCELS_IN_PARCEL_VOL    1000
struct nuvo_simple_parcel_manifest {
    uint32_t                          num_parcels;
    struct nuvo_parcel_manifest_entry manifest[MAX_PARCELS_IN_PARCEL_VOL];
    nuvo_hash_t                       hash;
};

#define NUVO_SIMPLE_PARCEL_MANIFEST_OFFSET    0
#define NUVO_SIMPLE_PARCEL_MANIFEST_SIZE      NUVO_BLOCK_ROUND_UP(sizeof(struct nuvo_simple_parcel_manifest))
#define NUVO_SIMPLE_PARCEL_MANIFEST_BLKS      (NUVO_SIMPLE_PARCEL_MANIFEST_SIZE / NUVO_BLOCK_SIZE)
uint64_t pm_total_size(struct nuvo_simple_parcel_manifest *pm);
