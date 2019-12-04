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
#include "map.h"

/**
 * @file map_priv.h
 * @brief Definition of the private interface to the map.
 *
 * Useful for unit tests.
 */

struct nuvo_lun;

#define NUVO_MAP_MAX_LEVELS    (5)

/** An enumeration of the possible states of a struct nuvo_map_track. */
enum nuvo_map_state
{
    NUVO_MAP_MIXED_LIST = 0,
    NUVO_MAP_CLEAN_LIST,
    NUVO_MAP_PINNED,
    NUVO_MAP_CLEANING,
    NUVO_MAP_SHADOW
};

/** A tracking structure for map tables.  This structure is used to track
 * in-memory map table properties, states, and relationships. */
struct nuvo_map_track {
    nuvo_mutex_t           mutex;
    struct nuvo_dlist      wait_list;

    enum nuvo_map_state    state                   : 7;
    uint32_t               cleaning_shadow         : 1; // distinguish this from the CP shadow
                                                        // cp shadows only have one pinned count

    uint_fast8_t           level;
    uint64_t               base_offset;
    struct nuvo_lun       *lun;
    struct nuvo_vol       *vol;
    struct nuvo_map_track *parent;
    struct nuvo_map_track *shadow_link;
    struct nuvo_map_entry  map_entry;

    uint64_t               cp_gen;

    uint32_t               is_dirty                : 1;
    uint32_t               is_new_entry            : 1;
    uint32_t               is_in_replay_stash_list : 1;  // per volume mixed list during replay
    uint32_t               mfl                     : 1;  //this map has been freed
    uint32_t               map_line_no             : 12; //TODO debug info for cp, enums instead of line no

    uint32_t               child_count             : 16;
    int                    pinned;
    uint32_t               snap_gen;

    struct nuvo_map_entry *entries;

    struct nuvo_dlnode     list_node;
};

/** A structure for interpreting map tables.  It is used for both in-memory and on-disk representations. */
struct __attribute__((aligned(NUVO_BLOCK_SIZE))) nuvo_map_table {
    struct nuvo_map_entry entries[NUVO_MAP_RADIX];
};

static_assert(sizeof(struct nuvo_map_table) == NUVO_BLOCK_SIZE, "Map tables must be block sized.");

/** A structure containing the top-level runtime state of the map. */
struct nuvo_map {
    // list_mutex covers alloc, lru, and pinned lists and counters
    nuvo_mutex_t           list_mutex;

    struct nuvo_dlist      alloc_list;
    int_fast32_t           alloc_remaining;

    int_fast32_t           mixed_count;
    int_fast32_t           clean_count;
    int_fast32_t           pinned_count;

    struct nuvo_dlist      mixed_lru_list;
    struct nuvo_dlist      clean_lru_list;
    struct nuvo_dlist      pinned_list;

    uint_fast32_t          map_table_count;
    struct nuvo_map_track *map_tracking;
    struct nuvo_map_table *map_tables;
};

extern struct nuvo_map *nuvo_map;

/* note map_line_no is for debugging where we set the cp_gen.
 * We need to make sure that all the maps with the current cp_gen
 * are included in the CP and none of them are already in the current CP
 * (map->cp_gen == req->prev_gen assert)
 * We have only 12 bits of free space in nuvo_map_track and i didnt want to reduce
 * the number of maps for a debugging field.
 * so subtracting 1530 which is the first occurence of MAP_SET_CP.
 */

#define MAP_SET_CP(tmap, checkpoint_gen)    do {                            \
        (tmap)->cp_gen = (checkpoint_gen);                                  \
        (tmap)->map_line_no = (__LINE__ - 1530);                            \
        NUVO_LOG(map, 200, "map set cp %p %llu", (tmap), (checkpoint_gen)); \
} while (0)

/**
 * \brief Remove a struct nuvo_map_track from the mixed lru list.
 *
 * This function removes a struct nuvo_map_track from the map's mixed lru
 * list.  The struct nuvo_map_track must have previously been put on the
 * map's mixed lru list via the nuvo_map_mixed_insert function.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * \param map A pointer to the struct nuvo_map_track to remove.
 */
void nuvo_map_mixed_remove(struct nuvo_map_track *map);

/**
 * \brief Remove a struct nuvo_map_track from the clean lru list.
 *
 * This function removes a struct nuvo_map_track from the map's clean lru
 * list.  The struct nuvo_map_track must have previously been put on the
 * map's clean lru list via the nuvo_map_clean_insert* functions.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * \param map A pointer to the struct nuvo_map_track to remove.
 */
void nuvo_map_clean_remove(struct nuvo_map_track *map);

/**
 * \brief Remove a struct nuvo_map_track from the pinned list.
 *
 * This function removes a struct nuvo_map_track from the map's pinned
 * list.  The struct nuvo_map_track must have previously been put on the
 * map's pinned list via the nuvo_map_pinned_insert function.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * \param map A pointer to the struct nuvo_map_track to remove.
 */
void nuvo_map_pinned_remove(struct nuvo_map_track *map);

/**
 * \brief Insert a struct nuvo_map_track onto the head of the mixed lru list.
 *
 * This function inserts a struct nuvo_map_track onto the head of the map's
 * mixed lru list.  Normally,
 * the map table allocator would need to be invoked after a call to this
 * function as the newly inserted mixed table might be able to service an
 * outstanding map allocation request.  It is the caller's responsibility to
 * invoke/run the allocator (nuvo_map_run_alloc/nuvo_map_run_alloc_locked)
 * after inserting mixed map tables.
 * The struct nuvo_map_track must not be on any other lists
 * before invoking this function.  The struct nuvo_map_track must be in the
 * NUVO_MAP_MIXED_LIST state prior to being inserted onto the mixed lru list.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * Also note that the replay could cause a storm of dirty maps which are not flushable
 * causing huge walks in balance lists.
 * So mixed list entries during replay for a volume are stashed in a per
 * volume replay list.
 * These are added to mixed lru list on reply completion of the volume.
 *
 * \param map A pointer to the struct nuvo_map_track to insert.
 * \returns true if the map made it to the mixed lru list
 *          false if the map was stashed in the per volume replay list
 * The caller may not chose to do an alloc if the return is false
 * See the note above for the callers responsibility for map allocations.
 * since no candidates for map allocation would have been available.
 */
bool nuvo_map_mixed_insert_noalloc(struct nuvo_map_track *map);
void nuvo_map_mixed_insert(struct nuvo_map_track *map, struct nuvo_dlist *comp_list);

/**
 * \brief helper method for removing a map out of the per volume replay stash list
 * \param map A pointer to the struct nuvo_map_track to remove.
 * \sa nuvo_map_mixed_insert_noalloc nuvo_map_mixed_insert
 */

void nuvo_map_replay_stash_list_remove(struct nuvo_map_track *map);

/**
 * \brief helper method for removing a map out of the per volume replay stash list
 * \param map A pointer to the struct nuvo_map_track to remove.
 * \sa nuvo_map_mixed_insert_noalloc nuvo_map_mixed_insert
 */

void nuvo_map_replay_stash_list_insert(struct nuvo_map_track *map);

/**
 * \brief Initialize a volume map writer for use.
 *
 * This is an initialization function for volume map writers.  This
 * function must be invoked on a struct nuvo_map_writer before any
 * nuvo_map_writer* functions are invoked on said struct nuvo_map_writer.
 *
 * \param writer A pointer to the struct nuvo_map_writer to initialize.
 * \param vol A pointer to the struct nuvo_vol for which the struct
 *      nuvo_map_writer will be used for.
 *
 */
void nuvo_map_writer_init(struct nuvo_map_writer *writer,
                          struct nuvo_vol        *vol);

/**
 * \brief Destroy a previously initialized volume map writer.
 *
 * This function releases all resources which were allocated for a struct
 * nuvo_map_writer by a previous invocation of nuvo_map_writer_init.
 *
 * \param writer A pointer to the struct nuvo_map_writer whose resources
 *      to free.
 */
void nuvo_map_writer_destroy(struct nuvo_map_writer *writer);

/**
 * \brief Insert a struct nuvo_map_track onto the head of the clean lru list
 * without invoking the map table allocator.
 *
 * This function inserts a struct nuvo_map_track onto the head of the map's
 * clean lru list without invoking the map table allocator.  Normally,
 * inserting a map table onto the clean lru list would invoke the allocator
 * to check if the newly available table could be used to complete any
 * outstanding map table allocation requests.
 * The struct nuvo_map_track must not be on any other lists before
 * invoking this function.  The struct nuvo_map_track must be in the
 * NUVO_MAP_CLEAN_LIST state prior to being inserted onto the clean lru list.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * \param map A pointer to the struct nuvo_map_track to insert.
 */
void nuvo_map_clean_insert_noalloc(struct nuvo_map_track *map);

/**
 * \brief Insert a struct nuvo_map_track onto the tail of the clean lru list
 * without invoking the map table allocator.
 *
 * This function inserts a struct nuvo_map_track onto the tail of the map's
 * clean lru list without invoking the map table allocator.  Normally,
 * the map table allocator would need to be invoked after a call to this
 * function as the newly inserted clean table might be able to service an
 * outstanding map allocation request.  It is the caller's responsibility to
 * invoke/run the allocator (nuvo_map_run_alloc/nuvo_map_run_alloc_locked)
 * after inserting clean map tables.
 * The struct nuvo_map_track must not be on any other lists before
 * invoking this function.  The struct nuvo_map_track must be in the
 * NUVO_MAP_CLEAN_LIST state prior to being inserted onto the clean lru list.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * \param map A pointer to the struct nuvo_map_track to insert.
 */
void nuvo_map_clean_insert_tail_noalloc(struct nuvo_map_track *map);

/**
 * \brief Insert a struct nuvo_map_track onto the head of the pinned list.
 *
 * This function inserts a struct nuvo_map_track onto the head of the map's
 * pinned list.  The struct nuvo_map_track must not be on any other lists
 * before invoking this function.  The struct nuvo_map_track must be in the
 * NUVO_MAP_PINNED state prior to being inserted onto the pinned list.
 * The caller must be holding both the nuvo_map->list_mutex and the
 * map->mutex.
 *
 * \param map A pointer to the struct nuvo_map_track to insert.
 */
void nuvo_map_pinned_insert(struct nuvo_map_track *map);

/**
 * \brief Initialize a struct nuvo_map_track.
 *
 * This function initializes a struct nuvo_map_track for use by the map.
 * The \p map parameter must but a pointer to a struct nuvo_map_track from
 * the nuvo_map->map_tracking array.  This function performs all necessary
 * allocations and setup for a struct nuvo_map_track, as well as filling in
 * it's entries member to point to the corresponding table in
 * nuvo_map->map_tables.
 *
 * \param map A pointer to the struct nuvo_map_track to initialize.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Unable to initialize mutex or condition variable.
 */
nuvo_return_t nuvo_map_track_init(struct nuvo_map_track *map);

/**
 * \brief Release all resources used by a struct nuvo_map_track.
 *
 * This function releases all resources allocated by a previous call to
 * nuvo_map_track_init for a given struct nuvo_map_track.
 *
 * \param map A pointer to the struct nuvo_map_track to destroy.
 */
void nuvo_map_track_destroy(struct nuvo_map_track *map);

/**
 * \brief Callback for logger requests by the map writer.
 *
 * This function is invoked as a callback for the completion of write
 * requests submitted to the segment logger by the nuvo_map_writer_flush
 * function.  This function will update the map tables being written with
 * the new media addresses provided by the segment logger, and then unpin
 * the underlying map tables and put them on their corresponding clean or
 * pinned lists.  It will also free any shadowed duplicate tables.
 *
 * \param log_req A pointer to the completed logger request.
 */
void nuvo_map_writer_flush_cb(struct nuvo_log_request *log_req);

/**
 * \brief Flush any pending dirty pages in a volume map writer.
 *
 * This function flushes any previous dirty pages that were queued for
 * cleaning by calls to nuvo_map_writer_add_map for this map writer, and
 * have not yet had write requests issued to the logger.
 * The caller must be holding the vol->mutex, and must not be holding any
 * other locks.  Upon returning from this function, the vol->mutex will have
 * be released.
 *
 * \param vol A pointer to the volume whose map writer to flush.
 */
void nuvo_map_writer_flush(struct nuvo_vol *vol);

/**
 * \brief Enqueue a map table to a map writer for cleaning.
 *
 * This function enqueues a dirty map table onto a volume's map writer for
 * writing out.  The map writer will try to fill a batch of
 * NUVO_MAP_CLEAN_BATCH_SIZE maps before sending the batch for writing to the
 * segment logger via the nuvo_map_clean_flush function.  If a caller needs
 * to know that map tables previously submitted to nuvo_map_writer_add_map
 * have begun to be written out to the segment logger, the caller should
 * set \p flush to NUVO_MW_FLUSH_FORCE.  If \p is set to NUVO_MW_FLUSH_AUTO,
 * the map willl only be flushed immediately if the batch is full.
 *
 * \param map A pointer to the struct nuvo_map_track to enqueue.
 * \param flush The flush policy.
 */
void nuvo_map_writer_add_map(struct nuvo_map_track          *map,
                             enum nuvo_map_writer_flush_mode flush);


/**
 * \brief Get the map table entry index for a given logical block number.
 *
 * This function computes the map table entry index for a given block number
 * and a map level.  The returned value is what should be used to index the
 * entries member of struct nuvo_map_track objects.  The map level starts at
 * zero at the leaves, and increases for each level in the map tree as you
 * approach the root.  The level here should match the level field of struct
 * nuvo_map_track objects.
 *
 * \param block_num The logical block number of the block whose table index
 * will be generated.
 * \param level The level of the map for which to generate the table index.
 *
 * \returns The map table entries index for the given block number and map
 * level.
 */
uint_fast32_t nuvo_map_get_table_index(uint_fast64_t block_num, uint_fast8_t level);

/**
 * \brief Get the base block number for a map table.
 *
 * This function computes the first block number for the map table at the
 * specified level which would contain the logical block \p block_num.
 *
 * \param block_num The logical block number of the block in question.
 * \param level The level of the map for which to generate the base offset.
 *
 * \returns The base offset of the map table.
 */
uint_fast64_t nuvo_map_get_base_offset(uint_fast64_t block_num, uint_fast8_t level);

/**
 * \brief Get the logical block number of a given entry in a map
 * \param base_offset base_offset of this map
 * \param index entry index
 * \param level The level of this map
 * \returns block_num The logical block number of the block in question.
 *
 */
inline uint64_t nuvo_map_get_block_at_index(uint_fast64_t base_offset, uint_fast32_t index, uint_fast8_t level)
{
    uint64_t block = base_offset | (index >> (level * NUVO_MAP_RADIX_BITS));

    return (block);
}

/**
 * \brief Balance the map's internal clean and mixed lru lists.
 *
 * This function attempts to balance the map's internal clean and mixed lru
 * lists.  The goal of this function is to maintain the lengths of the two
 * lists such that the length of the mixed lru list is lower or equal to the
 * length of the clean lru list.  Whenever map tables are inserted onto
 * the mixed lru list or are removed from the clean lru list, this function
 * should be invoked to make sure the balance is maintained.
 *
 * If this function finds that the mixed lru list is longer than the clean
 * lru list, it will begin taking maps off of the mixed lru list and trying
 * to put them onto the clean lru list.  If the maps taken from the tail of
 * the mixed lru list are dirty, they are enqueued for cleaning by invoking
 * the nuvo_map_writer_add_map function and flushed before this function
 * returns.
 */
void nuvo_map_balance_lists();

/**
 * \brief Pin a map table.
 *
 * This function pins a map table so that it will not be evicted.  If the
 * map table is in the NUVO_MAP_CLEAN_LIST or the NUVO_MAP_MIXED_LIST states
 * the its state will be changed to NUVO_MAP_PINNED and it will be removed
 * from its corresponding list and added to the pinned list.  Each pinned
 * map maintains a count of the number of times it has been pinned (I.E a
 * ref count).  This function will increment this pinned count.
 * The caller must be holding the table->mutex.
 *
 * \param table A pointer to the struct nuvo_map_track to pin.
 */
void nuvo_map_pin_table(struct nuvo_map_track *table);

/**
 * \brief Unpin a map table.
 *
 * This function will unpin a map table that has previously been pinned by
 * decrementing it's pinned count.  If the map table's pinned count reaches
 * zero, it will be put at the head of the /p comp_list and its state set
 * to NUVO_MAP_MIXED_LIST.  This will allow it to eventually be evicted.
 * The caller must be holding the table->mutex.
 *
 * \param table A pointer to the struct nuvo_map_track to unpin.
 * \param comp_list The list to place the an unpinned table.
 */
void nuvo_map_unpin_table(struct nuvo_map_track *table, struct nuvo_dlist *comp_list);

/**
 * \brief Unpin a map table while holding the nuvo_map->list_mutex.
 *
 * This function will unpin a map table that has previously been pinned by
 * decrementing it's pinned count.  If the map table's pinned count reaches
 * zero, it will be put at the head of the mixed lru list and its state set
 * to NUVO_MAP_MIXED_LIST.  This will allow it to eventually be evicted.
 * The caller must be holding the nuvo_map->list_mutex and the table->mutex.
 *
 * \param table A pointer to the struct nuvo_map_track to unpin.
 */
void nuvo_map_unpin_table_locked(struct nuvo_map_track *table);

/**
 * \brief unpin for map table that are shadows.
 *
 * This function will unpin a map table and a shadow that has previously been pinned
 * If the map table's pinned count reaches zero,
 * the relationship with the live map will be removed by setting the live map's shadow link to NULL.
 * Also, a pincount would be removed from the live map for the above case
 * the shadow map will be moved to the head of the clean LRU
 *
 * The caller must be holding the table->mutex.
 * The caller must be holding the live map mutex
 * The table must be a shadow
 *
 * \param table
 * \param comp_list optional list if an alloc fill is required
 *
 */
void nuvo_map_shadow_unpin_table(struct nuvo_map_track *table, struct nuvo_dlist *comp_list);

/**
 * \brief unpin for map table that are shadows. The pincount to deduct is supplied by the caller
 *  This calls nuvo_map_shadow_unpin_table unpin_count times
 * \sa  nuvo_map_shadow_unpin_table
 * \param map
 * \param unpin_count number of pins to deduct
 * \param comp_list optional list if an alloc fill is required
 *
 */
void nuvo_map_shadow_unpin_multiple(struct nuvo_map_track *map, uint_fast16_t unpin_count, struct nuvo_dlist *comp_list);

/**
 * \brief Evict a map table from the map.
 *
 * This function will evict a map table from the map, unlinking it from it's
 * parent map.
 * If a parent shadow exists, the map is unlinked from the parent shadow as well
 * The map must be in either the NUVO_MAP_CLEAN_LIST state or
 * the NUVO_MAP_MIXED_LIST state and must not be dirty.  After unlinking the
 * map table, this function will put it at the tail of the clean list and set
 * the map table's state to NUVO_MAP_CLEAN_LIST.
 * The caller must be holding the nuvo_map->list_mutex, table->mutex, and
 * table->parent->mutex and table->parent->shadow->mutex if the parent shadow exists.
 *
 * \param table A pointer to the struct nuvo_map_track to evict.
 * \retval false if the parent shadow mutex was lost. True otherwise
 *
 */
bool nuvo_map_evict_table(struct nuvo_map_track *table);

/**
 * \brief Run the map table allocator.
 *
 * This function will run the map table allocator, which will attempt to
 * fulfill any pending map table allocation requests by evicting map tables
 * from the lru lists.
 */
void nuvo_map_alloc_run();

/**
 * \brief Run the map table allocator while holding the nuvo_map->list_mutex.
 *
 * This function is the same as nuvo_map_alloc_run, except it assumes that
 * the caller is already holding the nuvo_map->list_mutex.
 */
void nuvo_map_alloc_run_locked(struct nuvo_dlist *comp_list);

/**
 * \brief Allocate map tables.
 *
 * This function allocates tables from the lru lists and places
 * them onto the map_list within the \p req provided.  If there are not enough map tables
 * available on the lru lists (and \p pinned is false, more on this later),
 * the function will block until there are enough map tables on the lru lists
 * to satisfy the allocation requested.  The \p pinned parameter is set to
 * true to inform the function if the caller is currently holding map tables
 * pinned.  If the caller has map tables pinned, the function will only try
 * to allocate the map tables requested if there are no other allocation
 * requests pending, as otherwise it would open the potential for a deadlock.
 * If the \p pinned parameter is true, and there are pending allocation
 * requests, the function will return an error.
 *
 * \param req A pointer to the request holding the map_lists.
 * \param pinned A boolean indicating if the caller is holding pinned map
 * tables.
 *
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 * \retval -NUVO_ENOMEM Unable to initialize mutex.
 * \retval -NUVO_EAGAIN Allocation cannot proceed without blocking, but the
 *      caller has specified pinned as true.
 */
nuvo_return_t nuvo_map_alloc_tables(struct nuvo_map_alloc_req *req, bool pinned);

void nuvo_map_fault_in_int(struct nuvo_map_request *req);

void nuvo_map_shadow_path(struct nuvo_map_request *req, struct nuvo_map_track *map, uint64_t new_cp_gen, struct nuvo_dlist *comp_list);
nuvo_return_t nuvo_map_shadow_reg(struct nuvo_dlist *map_list, struct nuvo_map_track *map);

/*
 * \brief get to the L0 map(s) and lock it
 * This could involve switching over from a shadow to a live map
 * shaodwing a map put of a cleaning map
 * triggering path shadowing etc
 * Guaranteed to get locked mutex, the caller can apply the changes
 * The locked maps are stashed in first_map and last_map fields
 * of the request.
 *
 * \param : the map request
 */
void nuvo_map_commit_lock(struct nuvo_map_request *req);

/**
 * \brief unlock of the above locked map(s) in previous call to lock
 * \param req The map request
 */
void nuvo_map_commit_unlock(struct nuvo_map_request *req);

/**
 * \brief interface for gc to lock a map before dirtying it for rewrite
 * GCs exepectation is that the map would be written to a new location after it is being dirtied.
 * GC only needs to dirty the map and can use the cp_gen at hand because it would do an explicit
 * cp after rewrite.
 * and doesnt need to worry about the shadow and cleaning maps
 * TODO more documentation
 * \param req: map request
 */

void nuvo_map_rewrite_lock(struct nuvo_map_request *req);

/**
 * \brief the unlock interface correspoding to nuvo_map_rewrite_lock
 * Note that the map pins are released in unlock, so this can be called only per every fault in
 * similar to nuvo_map_commit_lock
 * \sa nuvo_map_rewrite_lock nuvo_map_commit_lock
 * \param req: map request
 */
void nuvo_map_rewrite_unlock(struct nuvo_map_request *req);

/**
 * \brief
 * commit the changes onto the map obtained with nuvo_map_commit_lock
 * update replace the existing entries with entries.
 * For multi lun, also additionally get the old entries in the snap entries field.
 *
 * \param req: map request
 * \param new_entries : new entries to be applied . For the active, this is typically the logger supplied entries
 *                     For the snap cow LUN, this is the old snap entries obtained with a previous call to the active.
 *                     (read the snap entries field on how to obtain these
 * \param snap_entries : old entries that need COW. (only meaningful on the active LUN)
 * \param old_media_addrs : the current media addrs read by GC.
 * \param multi_lun : If this is to set to true, the snap entries would contain the COW entries
 * \param failed_gc : Count of how many changes were not applied, becuase old_media_addr was wrong
 * returns the number of COW blocks that need to be written to the peer COW lun of active.
 */
uint_fast32_t nuvo_map_update_entries(struct nuvo_map_request *req,
                                      struct nuvo_map_entry   *new_entries,
                                      struct nuvo_map_entry   *snap_entries,
                                      struct nuvo_media_addr  *old_media_addrs,
                                      bool                     multi_lun,
                                      uint_fast32_t           *succeeded_gc,
                                      uint_fast32_t           *failed_gc);

uint_fast32_t  nuvo_map_read_entries(struct nuvo_map_request *req,
                                     struct nuvo_map_entry   *entries,
                                     bool                     pin,
                                     bool                     multi_lun);

/**
 * \brief update the live map entry from shadow map
 * \param shadow_link : shadow_map
 * \param live_map: live map
 */
void map_entry_update(struct nuvo_map_track *shadow_link, struct nuvo_map_track *live_map);
struct nuvo_map_track *map_get_live_map(struct nuvo_map_request *req,
                                        struct nuvo_map_track   *map,
                                        struct nuvo_dlist       *comp_list);

void nuvo_map_read_and_pin_sync_impl(struct nuvo_map_request *map_req,
                                     struct nuvo_map_request *map_req_active,
                                     bool                     pin,
                                     struct nuvo_map_entry   *entries,
                                     uint_fast32_t           *parcel_descs,
                                     bool                     multi_lun);
void nuvo_map_multi_lun_read(struct nuvo_map_request *map_req_lun,
                             struct nuvo_map_request *map_req_active,
                             struct nuvo_map_entry   *entries,
                             bool                     pin);
void nuvo_map_single_lun_read(struct nuvo_map_request *req,
                              struct nuvo_map_entry   *entries,
                              bool                     pin);
void nuvo_map_read_get_parcel_desc_async(struct nuvo_map_request *req,
                                         struct nuvo_map_entry   *entries,
                                         uint_fast32_t           *parcel_descs);

void map_release_maps(struct nuvo_dlist *map_list, struct nuvo_dlist *comp_list);
void map_request_free(struct nuvo_map_request *req, struct nuvo_dlist *comp_list);
void nuvo_map_lun_checkpoint(struct nuvo_map_checkpoint_req *req);

void map_percolate_cow_on_fault_in(struct nuvo_map_track *map, const struct nuvo_map_entry *map_entry);
bool map_percolate_cow_for_inmem_intermediate(struct nuvo_map_request *req, struct nuvo_map_track *map,
                                              bool reserve_phase, struct nuvo_dlist *comp_list);
void map_percolate_cow_for_inmem_L0(struct nuvo_map_request *req, struct nuvo_map_track *map);

bool map_read_entry(struct nuvo_map_request *req,
                    struct nuvo_map_track   *map,
                    struct nuvo_map_entry   *map_entry,
                    struct nuvo_map_entry   *entry, /*output entry*/
                    bool                     multi_lun,
                    bool                     pin);

/* Some TLC for the map differ module */

void nuvo_map_reserve_differ(struct nuvo_map_diff_request *mdr, struct nuvo_map_track *fault_map);
void nuvo_map_fault_in_differ(struct nuvo_map_diff_request *mdr, struct nuvo_map_track *map);
nuvo_return_t  nuvo_map_wait_fault_in_differ(struct nuvo_map_diff_request *mdr);

inline void nuvo_map_writer_lock(struct nuvo_vol *vol)
{
    struct nuvo_map_writer *writer = &vol->log_volume.map_state.writer;

    nuvo_mutex_lock(&writer->writer_flush_mutex);
}

inline void  nuvo_map_writer_unlock(struct nuvo_vol *vol)
{
    struct nuvo_map_writer *writer = &vol->log_volume.map_state.writer;

    nuvo_mutex_unlock(&writer->writer_flush_mutex);
}

int  map_parent_entry_update_nl(struct nuvo_map_track *map, struct nuvo_map_track *parent);

// functions needed during snap create
struct nuvo_map_track *nuvo_map_alloc_map_sync();
struct nuvo_lun       *nuvo_map_lun_alloc_and_open_nl(struct nuvo_vol *vol, const uuid_t lun_uuid, struct nuvo_map_track *root_map);
void nuvo_map_snap_update_active_nl(struct nuvo_lun *active_lun, struct nuvo_lun *snap_lun);


/**
 *\brief free an L0 map
 * free the data blocks and mark the map dirty
 *\param req Map request that reserved/faulted in the map at hand
 *\ret if the map was dirtied or not
 */
void map_free_lun_L0(struct nuvo_map_request *req);

void nuvo_map_shadow_cleaning(struct nuvo_map_request *req, struct nuvo_map_track **map, struct nuvo_dlist *comp_list);

void nuvo_map_read_lock(struct nuvo_map_request *req);
void nuvo_map_read_unlock(struct nuvo_map_request *req);
bool map_mfl_free_entries(struct nuvo_map_track *map);

#define NUVO_MAP_LUN_DELETING_DONE(lun)    (lun->mfl_state == NUVO_LUN_MFL_CP_DONE)
