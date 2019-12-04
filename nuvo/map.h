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
#include <stdint.h>
#include <stdbool.h>
#include "nuvo.h"
#include "nuvo_hash.h"
#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "status.h"

#include "map_entry.h"
#include "map_request.h"
#include "logger.h"
#include "map_diff.h"

/**
 * @file map.h
 * @brief Definition of the interface to the map.
 */

#define NUVO_MAP_RADIX_BITS          (8)
#define NUVO_MAP_RADIX               (1ull << NUVO_MAP_RADIX_BITS)
#define NUVO_MAP_MEMORY_SIZE         (64ull * 1024 * 1024)

#define NUVO_MAP_WRITE_BATCH_SIZE    (128)
#define NUVO_MAP_WRITE_BATCHES       (8)
#define NUVO_MAP_BALANCE_MAPS_MAX    (NUVO_MAP_WRITE_BATCHES * NUVO_MAP_WRITE_BATCH_SIZE)

#define NUVO_MAP_CP_ALLOC_BATCH      (8)

struct nuvo_vol;
struct nuvo_lun;

/** An enumeration of the states of a struct nuvo_map_writer_batch. */
enum nuvo_map_batch_state
{
    NUVO_MAP_BATCH_FREE    = 0,
    NUVO_MAP_BATCH_WRITING = 1
};

enum nuvo_map_writer_flush_mode
{
    NUVO_MW_FLUSH_AUTO  = 0,
    NUVO_MW_FLUSH_NONE  = 1,
    NUVO_MW_FLUSH_FORCE = 2
};

/** A structure for describing map writer batches. */
struct nuvo_map_writer_batch {
    enum nuvo_map_batch_state state;
    struct nuvo_dlist         map_list;
    struct nuvo_vol          *vol;
    struct nuvo_log_request   log_req;
};

/** A structure for describing the state of a map writer. */
struct nuvo_map_writer {
    uint_fast32_t                free_batch_count;
    struct nuvo_dlist            batch_comp_list;
    uint_fast64_t                batches_completed;
    struct nuvo_map_writer_batch batches[NUVO_MAP_WRITE_BATCHES];
    uint_fast32_t                write_count;
    nuvo_mutex_t                 writer_flush_mutex;
    struct nuvo_dlist            write_queue;
};


/** A structure for keeping track of per-volume map state. */
struct nuvo_map_vol_state {
    struct nuvo_map_writer writer;
    uint64_t               checkpoint_gen;
    uint32_t               flush_replay_count;
};

struct nuvo_lun_cp_map_entry {
    uint64_t              snap_id;
    struct nuvo_map_entry root_map_entry;
};


struct nuvo_map_checkpoint_req {
    union nuvo_tag               tag;
    void                         (*callback)(struct nuvo_map_checkpoint_req *);
    nuvo_return_t                status;
    struct nuvo_lun_cp_map_entry lun_cp_map_entry[NUVO_MFST_MAX_LUNS]; //array of root map entries for each lun
    uint32_t                     lun_cnt;                              // number of luns that were cped.
    bool                         cp_begin;                             // Set to false in the beginning. used by the cp begin code to decide
                                                                       // to shadow the root map and increase the cp_gen as cp begin function is reentered few times
                                                                       // during cp. Read the comments where cp_begin is used for details

    struct nuvo_vol             *vol;
    struct nuvo_lun             *lun;        // the current CP lun, in case of multi lun CP ( or CP when pit luns are present)

    uint_fast64_t                cp_gen;
    uint_fast64_t                prev_gen;
    union
    {
        struct nuvo_map_alloc_req       map_alloc_req;
        struct nuvo_map_writer_wait_req writer_wait_req;
    };
    struct nuvo_dlist            map_list;
};

/**
 * \brief Initialize the map layer and allocate memory for map tables.
 *
 * This function is equivalent to calling nuvo_map_init_mem with \p mem_size
 * set to NUVO_MAP_MEMORY_SIZE (64MB).
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_EINVAL The map size specified is too small.
 * \retval -NUVO_ENOMEM Unable to allocate memory for the map.
 */
nuvo_return_t nuvo_map_init();

/**
 * \brief Initialize the map layer and allocate memory for map tables.
 *
 * This is an initialization function for the map layer.  It allocates and
 * initializes the in-memory map tables and associated tracking structures
 * that will be used by the map code.  The parameter \p mem_size is used as
 * a target for the amount of memory to allocate for the in-memory map tables.
 * Total allocation size will usually be slightly larger than this as
 * additional space for tracking structures will also be allocated.
 * The size must be at least 2 * NUVO_MAP_WRITE_BATCH_SIZE *
 * NUVO_MAP_WRITE_BATCHES * NUVO_BLOCK_SIZE (1MB).
 *
 * This operation must be performed before any other nuvo_map* functions are
 * invoked.
 *
 * \param map_size The number of bytes that the map should try to allocate for
 *      in-memory map table usage.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_EINVAL The map size specified is too small.
 * \retval -NUVO_ENOMEM Unable to allocate memory for the map.
 */
nuvo_return_t nuvo_map_init_mem(uint64_t map_size);

/**
 * \brief Shuts-down the map layer and frees memory for map tables.
 *
 * This is a shutdown function for the map layer.  It performs any necessary
 * clean-up and frees any allocated memory used by the map layer.  When this
 * function is invoked, the map must not be used by any open luns.  I.E. any
 * previous calls to nuvo_map_lun_open must have had a corresponding
 * nuvo_map_lun_close call.
 *
 * Once this operation is performed, no other calls to nuvo_map* functions
 * should be made unless nuvo_map_init is invoked again.
 */
void nuvo_map_shutdown();

/**
 * \brief Initialize a nuvo_map_vol_state struct for use.
 *
 * This function will initialize a struct nuvo_map_vol_state struct for future
 * map use.  This initializes the nuvo_map_writer and checkpoint tracking
 * state.
 *
 * \param vol_state The struct nuvo_map_vol_state to initialize.
 * \param vol The struct nuvo_vol that vol_state is for.
 */
void nuvo_map_vol_state_init(struct nuvo_map_vol_state *vol_state, struct nuvo_vol *vol);

/**
 * \brief Destroy a nuvo_map_vol_state struct and release any resources used.
 *
 * \param vol_state The struct nuvo_map_vol_state to destroy.
 */
void nuvo_map_vol_state_destroy(struct nuvo_map_vol_state *vol_state);

/**
 * \brief Initialize a map request for use.
 *
 * This function intializes a struct nuvo_map_request with the specified
 * logical block range for a future map read or write operation.  Note that
 * the user must fill in the tag and callback member if this request is to
 * be used with asynchronous map functions.
 *
 * \param req A pointer to the struct nuvo_map_request to initialize.
 * \param lun A pointer the struct nuvo_lun of the LUN that the operation
 * will be performed.
 * \param block_start The block number of the first block in the range.
 * \param block_count The number of blocks in the range.
 */
void nuvo_map_request_init(struct nuvo_map_request *req,
                           struct nuvo_lun         *lun,
                           uint_fast64_t            block_start,
                           uint_fast32_t            block_count);

/**
 * \brief Reserve the necessary map resources to perform a future map
 * operation.
 *
 * This function will reserve the necessary map resources needed to
 * perform a future nuvo_map_fault_in_sync or nuvo_map_read_and_pin call.
 * The \p req parameter must have previously been initialized via the
 * nuvo_map_request_init function.  After this function has been invoked
 * on a struct nuvo_map_request object, the object must be used with a
 * nuvo_map_read_and_pin or a nuvo_map_fault_in_sync call to release the reserved
 * resources.  This function must be called prior to a call to
 * nuvo_map_read_and_pin or nuvo_map_fault_in_sync.
 *
 * \param req A pointer to a struct nuvo_map_request that has been
 * initialized with the logical block range for the future map operation.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 */
void nuvo_map_reserve(struct nuvo_map_request *req);

/**
 * \brief A synchronous version of nuvo_map_reserve().
 *
 * \param req A pointer to a struct nuvo_map_request that has been
 * initialized with the logical block range for the future map operation.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Unable to initialize mutex.
 */
void nuvo_map_reserve_sync(struct nuvo_map_request *req);

/**
 * \brief Fault-in the map for a write in the logical range specified.
 *
 * This function will fault-in any part of the map that is needed for a future
 * nuvo_map_commit_write in the logical range in \p req, but is not in memory.
 * This function uses resources in \p req that were previously allocated by
 * nuvo_map_reserve.
 *
 * \param req A pointer to a struct nuvo_map_request containing the map
 * resources and logical range.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOENT Unable to pin/open parcels in manifest.
 * \retval -NUVO_EIO An error occurred while try to read a map block.
 * \retval -NUVO_E_BAD_HASH Read map block failed hash verification.
 */
void nuvo_map_fault_in(struct nuvo_map_request *req);

/**nuvo_map_request_init
 * \brief A synchronous version of nuvo_map_fault_in().
 *
 * \param req A pointer to a struct nuvo_map_request containing the map
 * resources and logical range.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Unable to initialize mutex.
 * \retval -NUVO_ENOENT Unable to pin/open parcels in manifest.
 * \retval -NUVO_EIO An error occurred while try to read a map block.
 * \retval -NUVO_E_BAD_HASH Read map block failed hash verification.
 */
void nuvo_map_fault_in_sync(struct nuvo_map_request *req);


/**
 * \brief Update a range of the map with new entries.
 *
 * This function will update a range of the map with new map entries.  The
 * \p req parameter contains the range of the map that will be updated.
 * This range must have previously been faulted-in via nuvo_map_fault_in and
 * the struct nuvo_map_reservation \p req must be the same.  While updating
 * the map, this function will also inform the segment table of the new
 * blocks that are in use and the old blocks that are no longer in use.
 *
 * Note:Only to be used when the caller is sure that only the active alone
 * needs udpating
 *
 * \param req A pointer to a struct nuvo_map_request containing the
 * logical range of the map to update.
 * \param new_entries A pointer to an array of struct nuvo_map_entries that
 * will be written into the map.
 */
void nuvo_map_commit_write(struct nuvo_map_request *req,
                           struct nuvo_map_entry   *new_entries);

/**
 * \brief Update a range of the map with new entries if old_media_addrs are correct.
 *
 * This function will update a range of the map with new map entries.  The
 * \p req parameter contains the range of the map that will be updated.
 * This range must have previously been faulted-in via nuvo_map_fault_in and
 * the struct nuvo_map_reservation \p req must be the same.  While updating
 * the map, this function will also inform the segment table of the new
 * blocks that are in use and the old blocks that are no longer in use.
 *
 * \param req A pointer to a struct nuvo_map_request containing the
 * logical range of the map to update.
 * \param new_entries A pointer to an array of struct nuvo_map_entries that
 * will be written into the map.
 * \param old_media_addrs Old media addresses
 * \param succeeded Pointer to integer to count number of updates applied to map
 * \param failed Pointer to integer to count number of updates NOT applied to map
 */
void nuvo_map_commit_gc_write(struct nuvo_map_request *req,
                              struct nuvo_map_entry   *new_entries,
                              struct nuvo_media_addr  *old_media_addrs,
                              uint_fast32_t           *succeeded,
                              uint_fast32_t           *failed);

/**
 * \brief   do an atomic commit write on the active and the youngest snap lun
 *  This does path locks on paths of the both the luns
 *  Dirty and update the L0 map table(s) for entries in the active lun, save the old
 *  entries to apply to the snap
 *
 * In detail, do the following
 * --lock the L0 maps of both the snap and active lun
 * --Dirty the L0 maps in the active lun from COW->NONE and save the old entries
 * --Dirty the L0 snap map tables with the old entries above
 * --update the above L0 maps in the snap lun from SHARED->COW.
 * --release the locks on the L0 maps of both active and snap luns
 *  \param map_req request for the active lun
 *  \param map_req_snap request for the snap lun
 *  \param new_entries the log entries from the logger for the data blocks in the active.
 */
void
nuvo_map_multi_lun_commit_write(struct nuvo_map_request *map_req,
                                struct nuvo_map_request *map_req_snap,
                                struct nuvo_map_entry   *new_entries);

/**
 * \brief A synchronous/single lun version "read and pin" map entries
 *
 * \brief Read a logical range of map entries from the map and pin the media
 * blocks referenced by the map entries, and get parcel descriptors for the
 * underly parcels.
 *
 * This function will read a logical range of the map contained in \p req.
 * This range must have previously been faulted-in via nuvo_map_fault_in and
 * the struct nuvo_map_request \p req must be the same.
 * While reading the map, this function will also pin the media that the map
 * entries reference so that it will not be erased by the garbage collector.
 * This function will also return the parcel descriptors for the underlying
 * parcel for each media map entry in the returned list.  The length of the
 * arrays pointed to by \p entries and \p parcel_descs should be the same.
 * Parcel descriptors for map entries will be put in matching index locations
 * between the two arrays.
 * Once the caller is finished using the map entries read, they must be
 * released via the nuvo_map_read_release function.
 *
 * \param req A pointer to a struct nuvo_map_request containing the
 * logical range of the map to read.
 * \param entries A pointer to an array of struct nuvo_map_entries where the
 * function will put the read map entries.
 * \param parcel_descs A pointer to an array of uint_fast32_t's where the
 * function will return parcel descriptors for the map entries.
 * \param pin Whether to actually pin or not.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Unable to initialize mutex.
 * \retval -NUVO_ENOENT Unable to pin/open parcels in manifest.
 * \retval -NUVO_EIO An error occurred while try to read a map block.
 * \retval -NUVO_E_BAD_HASH Read map block failed hash verification.
 */
void nuvo_map_read_and_pin_sync(struct nuvo_map_request *req,
                                bool                     pin,
                                struct nuvo_map_entry   *entries,
                                uint_fast32_t           *parcel_descs);

/**
 * \brief Release map entries that were previously read and pinned.
 *
 * This function will release a list of map entries that were previously
 * pinned by a call to nuvo_map_read_and_pin.
 *
 * \param lun A pointer to the struct nuvo_lun of the LUN whose map to read.
 * \param block_count How many entries are in the array of entries.
 * \param entries A pointer to an array of struct nuvo_map_entries where the
 * function will put the read map entries.
 */
void nuvo_map_read_release(struct nuvo_lun       *lun,
                           uint_fast32_t          block_count,
                           struct nuvo_map_entry *entries);

/**
 * \brief Get the map entries of the final locations
 *
 * This will traverse snapshots to find the actual
 * map entries that reflect the data.  (No Shared)
 *
 * \param lun the lun
 * \param block_offset the block offset of interest
 * \param block_count the number of blocks
 * \param final_entries the result array of entries
 * \param abort_on_non_zero if we find a non-zero abort early
 */
int nuvo_map_final_map_entries(struct nuvo_lun *lun, uint64_t block_offset, uint32_t block_count,
                               struct nuvo_map_entry *final_entries, bool abort_on_non_zero);

/**
 * \brief create snap/pits root map
 * obfuscated, used by UT only
 *
 * marks the root map of the snapshot as SHARED
 * and mark the corresponding entries in active root map as COW
 *
 * \param active_lun active lun
 * \param snap_lun snap lun
 */


void __nuvo_map_create_snap(struct nuvo_lun *active_lun,
                            struct nuvo_lun *snap_lun);


/**
 * \brief Checkpoint a volume's map.
 *
 * This function will initiate a checkpoint on the requested volume.  When the
 * checkpoint is complete, and all checkpoint related map tables have been
 * written to media, the callback will be invoked and the resulting new root
 * map entry will be stored in the request structure.
 *
 * \param req A pointer to a checkpoint request structure.
 */
void nuvo_map_checkpoint(struct nuvo_map_checkpoint_req *req);

void nuvo_map_replay(struct nuvo_log_request *log_req);

/**
 * \brief Checkpoint a volume's map synchronously (blocking call).
 *
 * This is a synchronous version of the nuvo_map_checkpoint call.  Calls to
 * this function will block until the requested checkpoint is complete.
 *
 * \param vol A pointer to the volume to checkpoint.
 * \param map_entry A pointer to where to sture the resulting checkpoint
 *      root map entry.
 */
nuvo_return_t nuvo_map_checkpoint_sync(struct nuvo_vol *vol, struct nuvo_map_entry *map_entry);

/* is the lun map-opened ? */
#define NUVO_MAP_IS_LUN_OPEN(lun)    ((lun)->root_map)

/**
 * \brief Load the top level map table for a lun.
 *
 * This function loads the top level map table for a lun.  This function must
 * be used on a lun prior to any other map operations being performed for this
 * lun.
 *
 * \param lun A pointer to the struct nuvo_lun for the LUN whose map to load.
 * \param map_entry A pointer to the root map entry for the LUN.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Unable to initialize mutex.
 * \retval -NUVO_ENOENT Unable to pin/open parcels in manifest.
 * \retval -NUVO_EIO An error occurred while try to read a map block.
 * \retval -NUVO_E_BAD_HASH Read map block failed hash verification.
 */
nuvo_return_t nuvo_map_lun_open(struct nuvo_lun *lun, const struct nuvo_map_entry *map_entry);

/**
 * \brief Close the map for a LUN.
 *
 * This function will unload all of the map tables associated with a LUN from
 * the map.  If map tables in the LUN's tree are dirty, they will first be
 * written out/cleaned.  The function will return a new struct nuvo_map_entry
 * that describes the LUN's current root map.
 *
 * \param lun A pointer to the struct nuvo_lun for the LUN whose map to close.
 * \param map_entry A pointer to a struct nuvo_map_entry where to store the
 * LUN's root map entry.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 */
nuvo_return_t nuvo_map_lun_close(struct nuvo_lun *lun, struct nuvo_map_entry *map_entry);

/**
 * \brief init a map request to rewrite a single map block within a lun.
 *
 * \param map_req The map request to fill in.
 * \param lun The lun in which the map block to be written appears.
 * \param bno The block number of the block to be rewritten.
 * \param level The level to be rewritten.
 */
void nuvo_map_rewrite_init(struct nuvo_map_request *map_req,
                           struct nuvo_lun         *lun,
                           uint64_t                 bno,
                           uint_fast16_t            level);

/**
 * \brief Ensure map block is rewritten in next CP.
 *
 * This dirties a map block ensuring it will be written in the next CP.
 *
 * \param map_req The map request describing the lun, level and offset of the block.
 */
void nuvo_map_rewrite(struct nuvo_map_request *map_req);

/**
 * \brief open the maps of all the LUNS of a given volume
 *
 * \param vol:  the vol series whose LUNS are to be opened
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 */
nuvo_return_t nuvo_map_multi_luns_open(struct nuvo_vol *vol);

/**
 * \brief close the maps of all the LUNS of a given volume
 *
 * \param vol : the vol series whose LUNS are to be closed
 * \returns : void
 */

nuvo_return_t nuvo_map_luns_close(struct nuvo_vol *vol);

/**
 * \brief The function checks whether the faulted L0 maps in the request
 * has any COW blocks
 * if true the writer could fault in the snapshot
 * and use the atomic multi lun write interface
 *
 * \param req: the map request on the active,
 *  assumes the caller has faulted in the path for the request
 */

bool nuvo_map_is_cow_reqd(struct nuvo_map_request *req);

/**
 * \brief The function checks whether the fauled in L0 maps of this request
 * has any shared entries. This can be used to check whether a read would
 * cause any ROR(redirect on read) requests to the active.
 * If true, the reader must use the atomic mutli lun read interface
 * which would lock both the snap and the active lun during read
 * \param req: the map request on the snap,
 * assumes the caller has faulted in the path for the request
 */
bool nuvo_map_is_ror_reqd(struct nuvo_map_request *req);

/**
 * \brief  the atomic multilun version of read and pin sync
 * The required that maps of both the active and snaps, be faulted in priori.
 * This would lock out both the active and snap map entries before a read
 * Hence this would be atomic with respect to writers on the active.
 *
 * \param map_req ( map req on the snap, path must be fauted in )
 * \param map_req_active ( map req on the active, path must be fauted in )
 * \param entries output map entries
 * \param parcel_descs array for parcel descriptors
 */

void nuvo_map_multi_lun_read_sync(struct nuvo_map_request *map_req,
                                  bool                     pin,
                                  struct nuvo_map_request *map_req_active,
                                  struct nuvo_map_entry   *entries,
                                  uint_fast32_t           *parcel_descs);


bool map_entries_are_cow_or_shared(struct nuvo_map_request *req, nuvo_map_entry_snap_type entry_type);

/**
 * \brief: create snap function from map
 * This allocates a root map mem, allocates a new snap lun,   sets up the new snap lun
 * and the active lun root map so that a pit is created
 * \param vol vol
 * \param lun_uuid lun uuid
 * \returns the pointer to the new snap lun
 */
struct nuvo_lun *nuvo_map_create_snap(struct nuvo_vol *vol, const uuid_t lun_uuid);

/**
 *\brief: flush the dirty maps, intermittently
 * map write consumers may accumulate a load of dirty maps and may not be able to flush if we are out of flush batches.
 * So we also cant wait for flush batches if the we are out of batches in the logger completion thread
 * This is to be called from a non logger completion thread so that flush batches are available in the logger callback
 * gc is a consumer and this is done after a batch of map updates
 * \param vol vol
 */
void nuvo_map_try_flush(struct nuvo_vol *vol);

// space account media addrs only
//also ignore the entries that are cowed from active to snap
#define  NUVO_ME_DO_SPACE_ACCOUNT(map_entry, cow_write)    (((map_entry)->type == NUVO_ME_MEDIA) && \
                                                            (!cow_write || (map_entry)->cow != NUVO_MAP_ENTRY_COW))

#define NUVO_MAP_IS_SHARED(map)                            (map->map_entry.cow == NUVO_MAP_ENTRY_SHARED)
#define NUVO_MAP_IS_COW(map)                               (map->map_entry.cow == NUVO_MAP_ENTRY_COW)
#define NUVO_MAP_IS_NONE(map)                              (map->map_entry.cow == NUVO_MAP_ENTRY_NONE)

#define NUVO_MAP_SET_COW(map)                              do { \
        map->map_entry.cow = NUVO_MAP_ENTRY_COW;                \
} while (0)

#define NUVO_MAP_SET_SHARED(map)                           do { \
        map->map_entry.cow = NUVO_MAP_ENTRY_SHARED;             \
        map->map_entry.type = NUVO_ME_NULL;                     \
} while (0)

#define NUVO_MAP_SET_NONE(map)                             do { \
        map->map_entry.cow = NUVO_MAP_ENTRY_NONE;               \
} while (0)

/*
 *\brief fault inject allocator for map module
 *\ret fi
 */
struct test_fi_info *nuvo_map_get_test_fi();
