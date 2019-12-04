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

#pragma once

/**
 * @file gc.h
 * @brief data structures for garbage collecting segments.
 */
#include "map.h"
#include "parallel.h"
#include "segment.h"

/** How many garbage collections can be going on in parallel. */
#define NUVO_SPACE_GC_NUM               4
/** How many garbage collections sub-operations can go on in parallel. */
#define NUVO_SPACE_GC_BATCHES           (NUVO_SPACE_GC_NUM)
/** How many map reqs can be used in on parallel op. */
#define NUVO_GC_MAP_REQS_PARALLEL       128
/** How many data blocks can be moved in on parallel op. */
#define NUVO_GC_DATA_BLOCK_NUM_MAX      128

#define NUVO_GC_DATA_BLOCKS_READ_MAX    512

#define NUVO_GC_SEGMENTS_PER_CP         3
struct nuvo_gc;

/**
 * When we read data we need to know what the identity of the data is.  Otherwise we
 * won't know what map entry it represents.  We also need the old location, but of
 * of course that is implicit in the io.
 */
struct nuvo_gc_data_read {
    struct      nuvo_gc *gc;
    unsigned             boffset;
};

// TODO - make sure these are cleaned up.
enum nuvo_gc_block_action
{
    NUVO_GC_BLOCK_UNKNOWN = 0,  /** Don't know about this block yet. */
    NUVO_GC_BLOCK_UNUSED,       /** This block is unused, leave it behind. */
    NUVO_GC_BLOCK_MOVE_DATA,    /** Moving a data block. */
    NUVO_GC_BLOCK_MOVE_MAP      /** Moving a map block. */
};

/**
 * Whether to use the gc_decision log or not.
 * Want to minimize the number of #if in the code,
 * so just have the one here.
 */
#define NUVO_GC_MOVING_LOG         0
#if NUVO_GC_MOVING_LOG
#define GC_DECISION_LOG_SIZE       10000
#define GC_DECISION_LOG_ENABLED    true
#else
#define GC_DECISION_LOG_SIZE       1
#define GC_DECISION_LOG_ENABLED    false
#endif

/*
 * Debug - Track decisions for data blocks.
 */
enum nuvo_gc_move_decision_e
{
    NUVO_GC_DECISION_MOVING   = 1,
    NUVO_GC_DECISION_NOT_USED = 2
};

/*
 * Whether a data block being moved by gc is cached or not.
 * Also used as array index.
 */
enum nuvo_gc_block_type
{
    NUVO_GC_BLOCK_HOT  = 0,
    NUVO_GC_BLOCK_COLD = 1
};

/*
 * Number of block types defined in nuvo_gc_block_type
 * */
#define NUVO_GC_NUM_BLOCK_TYPE    2

struct nuvo_gc_data_move_decision {
    uint32_t                      boffset;
    uint32_t                      snap_id;
    enum  nuvo_gc_move_decision_e decision;
};

/**
 * When we send a request to the map it is related to a certain range of
 * indices in the digest. We need to know what range it is. The map_req
 * has a range in it, so we don't need to keep the number.  We do need to
 * keep the first entry's corresponding index in the summary table
 */
struct nuvo_gc_map_info {
    struct nuvo_map_request map_req;   /** The map request. */
    struct nuvo_gc_batch   *gc_batch;  /** The gc_batch this is part of. */
    uint_fast16_t           map_index; /** The location of the data used in the summary table. */
};

struct nuvo_gc_batch {
    struct nuvo_dlnode list_node;           /** For maintaining a free list. */
    struct nuvo_gc    *gc;                  /** The gc this is associated with. */
    nuvo_mutex_t       sync_signal;

    union
    {
        struct {
            uint32_t                log_pit_id;                                    /** Which pit are we working on. */
            struct nuvo_parallel_op par_ops;                                       /** The parallel ops for map lookups. */
            uint_fast16_t           maps_used;                                     /** Count of how many maps have been used. */
            struct nuvo_gc_map_info map_info[NUVO_GC_MAP_REQS_PARALLEL];           /** The map ops being sent in parallel. */
        } elide;                                                                   /** For use when planning the gc op. */
        struct {
            uint_fast16_t           first_boffset;                                 /** First relative offset within segment. */
            uint_fast16_t           boffsets_used;                                 /** How many contiguous blocks in this move, including unused padding. */
            uint_fast16_t           blocks_moving;                                 /** How many blocks are being moved. */
            uint_fast16_t           maps_used;                                     /** How many map ios are used. */
            struct nuvo_parallel_io par_io;                                        /** The parallel ios for reading data. */
            struct nuvo_parallel_op hot_par_ops;                                   /** The parallel map ops for faulting in hot. */
            struct nuvo_parallel_op cold_par_ops;                                  /** The parallel map ops for faulting in cold. */
            uint_fast16_t           boffset_moved[NUVO_GC_DATA_BLOCK_NUM_MAX];     /** Location in summary map each block was moved from. */
            void                   *data_bufs[NUVO_GC_DATA_BLOCKS_READ_MAX];       /** The data buffers for moving. */
            uint_fast16_t           blocks_used;
            bool                    cached[NUVO_GC_DATA_BLOCKS_READ_MAX];          /** Whether the block read by GC was cached. */
            struct {
                uint_fast16_t           blocks_moving;                             /** How many blocks are being moved. */
                uint_fast16_t           maps_used;                                 /** How many map ios are used. */
                struct nuvo_log_request log_req;                                   /** The log request to send if using for a move. */
                struct nuvo_gc_map_info map_info[NUVO_GC_MAP_REQS_PARALLEL];       /** Map_reqs used for the fault-ins and updates. */
                uint_fast16_t           boffset_moved[NUVO_GC_DATA_BLOCK_NUM_MAX]; /** Location in summary map each block was moved from. */
                uint_fast16_t           blocks_used;                               /** blocks used in one bunch. */
                bool                    done;                                      /** Are the reads and map fault in done. */
            }                       bunch[NUVO_GC_NUM_BLOCK_TYPE];
        } move_data;                                                               /** For use when moving data. */
        struct {
            struct nuvo_parallel_op par_ops;                                       /** Parallel ops for map requests. */
            uint_fast16_t           maps_used;                                     /** How many maps have we used. */
            struct nuvo_gc_map_info map_info[NUVO_GC_MAP_REQS_PARALLEL];           /** The maps. */
            struct nuvo_map_entry   old_map_entries[NUVO_GC_MAP_REQS_PARALLEL];    /** Locations of old map blocks. */
        } move_maps;                                                               /** For use when moving maps. */
    };
};

enum nuvo_gc_state
{
    NUVO_SPACE_GC_UNUSED = 0,       /** The gc is unused. */
    NUVO_SPACE_GC_DIGEST_READING,   /** Reading the digest. */
    NUVO_SPACE_GC_DIGEST_ELIDING,   /** Figuring out which blocks to move. */
    NUVO_SPACE_GC_MOVING_DATA,      /** Moving data */
    NUVO_SPACE_GC_MOVE_MAPS,        /** Dirtying the maps that need to move. */
    NUVO_SPACE_GC_MOVING_DONE,      /** Done - just need to wait for the CPs so we can return the segment.*/
    NUVO_SPACE_GC_MOVE_FAILED       /** Moving data failed due to an active write - go back to READING */
};

struct nuvo_gc {
    struct nuvo_dlnode         list_node;                            /** List to keep gc's on work lists. */
    nuvo_mutex_t               gc_mutex;                             /** Mutex protecting this gc. */

    enum nuvo_gc_state         state;                                /** Overall state of this gc op. */
    struct nuvo_vol           *vol;                                  /** the volume the segment is part of. */
    struct nuvo_segment       *segment;                              /** Which segment is being moved. */

    struct nuvo_segment_digest digest;                               /** Digest has per block info. */
    struct nuvo_segment_digest digest2;                              /** For debugging */
    enum nuvo_gc_block_action  block_state[NUVO_MAX_SEGMENT_BLOCKS]; /** Per-block state tracking. */

    void                       (*phase_callback)(struct nuvo_gc *);  /** For testing state transitions. */
    void                       (*moving_callback)(struct nuvo_gc *); /** For gc trigger. */
    bool                       no_cp;
    union nuvo_tag             tag;

    /** internal state */
    uint32_t                   boffset;                     /** Location in the segment in the current scan. */
    struct nuvo_lun           *pinned_lun;                  /** At beginning pin the oldest lun VALID or DELETING lun.
                                                             *   This prevents any luns being deleted out from under us. */
    uint32_t                   lun_id;                      /** Which of active/pit are we currently working on. */
    uint32_t                   starting_next_create_pit_id; /** Allows us to track if a pit was created while running. */
    uint32_t                   lowest_data_pit_id;          /** Lowest pit a data block could fall to. */
    uint32_t                   lowest_map_pit_id;           /** Lowest map pit we'll try to move. */
    uint32_t                   actives_failed;              /** How many actives moved out from under gc into snaps on this iteration */

    uint_fast16_t              gc_batches_outstanding;      /** How many sets of parallel ops are in flight for current phase. */
    struct {
        uint_fast16_t data_reads;
        uint_fast16_t data_blocks_read;
        uint_fast16_t data_writes;
        uint_fast16_t data_blocks_written;
        uint_fast16_t data_block_moves;
        uint_fast16_t reinits;
        uint_fast16_t actives_failed;
    }                          stats;

    struct {
        unsigned                               num_used;
        struct      nuvo_gc_data_move_decision record[GC_DECISION_LOG_SIZE];
    }                          moving_log;
};

/**
 *  gc allocation and frees.  These are actually in the space.c file.
 * They are there for test linkage reasons.
 */

/**
 *  \brief Allocate a gc tracking structure
 * \returns An allocated tracking structure.
 * \retval NULL There aren't any available.  You lose.
 */
struct nuvo_gc *nuvo_gc_alloc();

/**
 * \brief Init a gc for a volume and a segment.
 * This takes the gc, volume and segment (which identifies a segment marked in-use so no one else will
 * mess with it.) and initializes the gc.
 * \param gc The gc to init.
 * \param vol The volume this will be working on.
 * \param segment The segment to clean.
 */
void nuvo_gc_init(struct nuvo_gc *gc, struct nuvo_vol *vol, struct nuvo_segment *segment);

void nuvo_gc_re_init(struct nuvo_gc *gc);

/**
 * \brief Free a gc.
 * \param gc The gc to free.
 */
void nuvo_gc_free(struct nuvo_gc *gc);


/**
 * Allocation and freeing of nuvo_gc_batch requests.
 * These are the map/io requests for use by gc.
 * Located in space.c for test linking reasons.
 */

/**
 * \brief Init the pool of nuvo_gc_batch.
 * \retval 0 Success.
 * \retval -NUVO_ENOMEM Not able to allocate these.
 */
nuvo_return_t nuvo_gc_batchs_init();

/**
 * \brief Destroy the nuvo_gc_batch pool.
 */
void nuvo_gc_batchs_destroy();

/**
 * \brief Allocate a nuvo_gc_batch
 * \retval A nuvo_gc_batch.
 * \retval NULL No nuvo_gc_batch available.
 */
struct nuvo_gc_batch *nuvo_gc_batch_alloc();

/**
 * \brief Free a nuvo_gc_batch
 * \param gc_batch The nuvo_gc_batch to free.
 */
void nuvo_gc_batch_free(struct nuvo_gc_batch *gc_batch);

/**
 * \brief Put a gc on list as needing work.
 * \param gc The gc that needs work.
 */
void nuvo_gc_needs_work(struct nuvo_gc *gc);

/**
 * \brief Get a gc that needs work.
 * \retval The nuvo_gc to work on.
 * \retval NULL None need work.
 */
struct nuvo_gc *nuvo_gc_needs_work_get();

/**
 * \brief Record a nuvo_gc as needing a nuvo_gc_batch to proceed.
 * \param gc The nuvo_gc that needs a nuvo_gc_batch.
 * This puts the worker on a separate list than the work list, so we don't spin
 * waiting for a batch to finish.  There is no real harm in being on the
 * work list instead of the batch list since the space code will immediately
 * move this to the batch list.
 */
void nuvo_gc_needs_batch(struct nuvo_gc *gc);

/**
 * \brief Get a nuvo_gc that needs a nuvo_gc_batch.
 * \retval The nuvo_gc that was waiting.
 * \retval NULL No nuvo_gc was waiting.
 */
struct nuvo_gc *nuvo_gc_needs_batch_get();

/**
 * \brief This takes a volume and a segment structure and starts the async read of the digest.
 *
 * The \p gc has an attached nuvo_segment that describes the segment to be garbage collected.
 * this segment has been pinned for use by the space management system and so we can
 * rely on it not changing and use the parcel descriptor the manifest has supplied.  The
 * callback will continue the garbage collecting by moving the state of the gc.
 *
 * \param gc The nuvo_gc structure controlling the garbage collection.
 * \returns 0 or an error.
 * \retval 0 success in dispatching the read.
 * \retval -NUVO_ENOMEM Unable to initialize a mutex.
 */
nuvo_return_t nuvo_gc_read_digest(struct nuvo_gc *gc);

/**
 * \brief Start doing a batch of planning for gc.
 *
 * This dispatches a batch of planning, checking with the map to see which blocks
 * need to be moved.  This finishes asynchronously and another batch may be dispatched
 * immediately.
 *
 *  We send off as many map requests as we can at a time.  First time we call this for
 * a gc segment the boffset will be zero.  After the first batch is complete, we will come back
 * and do another starting at the boffset where the first left off.  Continue.
 *
 * First time through we are looking for blocks that were written for the active lun and checking the active lun.
 * Later times through we are looking for any block that might be in a particular PiT.  Those would include blocks
 * written for that PiT and possibly blocks written for the active at or after that snapshot.
 * When looking for blocks we try to chain them together for efficiency, so once we find a block to check we look
 * to see if the next unknown block is the next bno and also one we need to check.
 *
 * \param gc The gc being worked on.
 * \param gc_batch The structure to track this batch.
 * \returns Number of map ops this batch will (or did) use.
 * \retval 0 Planning is done.
 */
nuvo_return_t nuvo_gc_elide_unused_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch);

/**
 * \brief Start a batch of moving data blocks.
 *
 * This dispatches a set of reads and a set of map op fault-ins and then in
 * callbacks will send log requests to write out the data and then update the map.
 * This call finishes asynchronously and another batch may be started.
 *
 * \param gc The gc being worked on.
 * \param gc_batch The structure to track this batch.
 * \returns Number of blocks that will be moved in this batch.
 * \retval 0 No more moves need to be started.
 */
nuvo_return_t nuvo_gc_move_data_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch);

/**
 * \brief Start a batch of moving map blocks.
 *
 * This dispatches a set of map fault-ins that will then allow
 * conditional dirtying of map blocks which will write them to new locations
 * in next cp.
 *
 * When moving data we scan the gc digest finding ranges of
 * blocks we are going to move.  The last block that we have started moving is
 * contained in gc->boffset. As we find a contiguous set of blocks to read and rewrite
 * we issue the read for those blocks.
 *
 * \param gc The gc being worked on.
 * \param gc_batch The structure to track this batch.
 * \returns Number of maps that will be (attempted) moved in this batch.
 * \retval 0 No more moves need to be started.
 */
nuvo_return_t nuvo_gc_move_maps_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch);

/**
 * \brief Complete gc on a segment.
 *
 * This marks the end of the active cleaning and puts the segment on the list of cleanings that will be done in
 * next cp.
 * \param gc The gc.
 */
void nuvo_gc_done(struct nuvo_gc *gc);
