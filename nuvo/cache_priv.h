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
#include <uuid/uuid.h>
#include <stdint.h>
#include <stdbool.h>
#include <search.h>
#include "status.h"
#include "map_entry.h"  // for nuvo_media_addr
#include "nuvo_lock.h"
#include "nuvo_pr.h"
#include "parcel_manager.h"
#include "cache.h"

#define NUVO_CACHE_MAX_DEVICES                   (8)
#define NUVO_CACHE_LINE_SIZE_BITS                (4)
#define NUVO_CACHE_LINE_SIZE_BLOCKS              (1ull << NUVO_CACHE_LINE_SIZE_BITS)

/* Incremental cache allocation unit in sets */
#define NUVO_CACHE_TB_NUM_SETS_PER_ALLOCATION    (4)

#define cache_size_bytes_to_cl(size)    ((size / NUVO_BLOCK_SIZE) / NUVO_CACHE_LINE_SIZE_BLOCKS)
#define cache_size_cl_to_bytes(cl)      (cl * NUVO_BLOCK_SIZE * NUVO_CACHE_LINE_SIZE_BLOCKS)

/* the global cache tracking struct */
extern struct nuvo_cache cache;

#define NUVO_CACHE_KEY_OFFSET_BITS    (24)
#define NUVO_CACHE_KEY_PARCEL_BITS    (32)
#define NUVO_CACHE_BLOCK_KEY_BITS     (NUVO_CACHE_KEY_OFFSET_BITS + NUVO_CACHE_KEY_PARCEL_BITS);

#define NUVO_CACHE_IN_USE_BITS        (1)

/**
 * \brief Search key for the hash table
 *
 * The key is 64 bits. Keys are unique across volumes and are composed of the
 * volume, parcel, offset of the io.
 *
 */
union nuvo_cache_key
{
    uint64_t block_key : NUVO_CACHE_BLOCK_KEY_BITS;
    struct {
        uint64_t block_offset : NUVO_CACHE_KEY_OFFSET_BITS;
        uint64_t parcel_desc  : NUVO_CACHE_KEY_PARCEL_BITS;
    };
};

/**
 * \brief Cache device tracking information
 */
struct nuvo_cache_device {
    uuid_t             device_uuid;                     /**< The device uuid of the cache */
    uuid_t             parcel_uuid;                     /**< The parcel uuid, a cache only has one parcel */
    uint_fast32_t      parcel_desc;                     /**< The parcel descriptor */
    uint64_t           cache_size_bytes;                /**< The total usable cache capacity on the device */
    struct device_info device_info;                     /**< cache device geometry info */
};

/**
 * \brief Tracking structure for a cache fragment
 */
struct nuvo_cache_fragment {
    struct nuvo_dlnode list_node;           /**< For tracking this fragment on free and allocated lists */
    uint32_t           size_cl;             /**< The size of the fragment in NUVO_CACHE_LINE_SIZE_BLOCKS units */
    uint32_t           block_offset;        /**< The starting offset of the fragment */
};


/**
 * \brief A tracking structure for a cache line
 *  Each cache line represents a NUVO_CACHE_LINE_SIZE_BLOCKS allocation on a cache device.
 *
 *
 */
struct nuvo_cache_line {
    uint64_t block_key : NUVO_CACHE_BLOCK_KEY_BITS;   /**< The key associated with the the cache line, if mapped */
    uint8_t  in_use    : NUVO_CACHE_IN_USE_BITS;      /**< Set to 1 if this cache line has a valid key */
    uint8_t  lpos      : NUVO_CACHE_TB_MAX_WAYS_BITS; /**< Position of cache line on logical LRU list within a set */
    uint32_t num_set;                                 /**< Number of sets in the cache the last time written */
    uint8_t  wr_count;                                /**< The number of writes pending against this cache line */
    uint8_t  rd_count;                                /**< The number of reads pending against this cache line */
    uint8_t  first_block;                             /**< The index of the first block written in this cache line */
    uint8_t  last_block;                              /**< The index of the last block written in the cache line */
};
static_assert(sizeof(struct nuvo_cache_line) == 16, "struct nuvo_cache_line must be 16 bytes.");


/**
 * \brief cache io operations
 */
enum cio_op
{
    NUVO_OP_CACHE_READ_AROUND          = 0,
    NUVO_OP_CACHE_READ_HIT             = 1,
    NUVO_OP_CACHE_READ_MISS            = 2,
    NUVO_OP_CACHE_WRITE_CACHE          = 3,
    NUVO_OP_CACHE_WRITE_CACHE_ASYNC    = 4,
    NUVO_OP_CACHE_WRITE_AROUND         = 5,
    NUVO_OP_CACHE_WRITE_MISS           = 6,
    NUVO_OP_CACHE_READ_AROUND_BAD_HASH = 7
};

/**
 * \brief A structure for tracking cache io requests
 *
 * Every original io submitted to the cache has one or more cache io requests
 * associated with it. An io will have multiple cache io requests associated with it
 * when the io spans cache lines, or has data partially in cache and partially on
 * the primary backing device.
 *
 * When there are multiple cache io requests, their completion is collectively tracked
 * using a parallel operation. The original io is completed when all cache io requests
 * complete.
 *
 */
struct cio_request {
    struct nuvo_dlnode       list_node;
    uint8_t                  operation;    /**< one of cio_op */
    void                     (*callback) (struct nuvo_io_request *req);
    nuvo_return_t            status;       /**< completion status of the operation */
    bool                     verify_flag;  /**< true if the read hashes should be verified */

    uint32_t                 parcel_desc;  /**< the parcel descriptor of the parcel. */
    uint32_t                 block_offset; /**< the block offset within the parcel. */
    uint32_t                 block_count;  /**< the io size */
    uint32_t                 par_io_count; /**< the number of parallel io for the original io request */
    uint32_t                 iov_offset;   /**< iov buffer offset where to place data on cache hits */

    struct nuvo_cache_line  *cl;           /**< pointer to the cache line for this io */
    struct nuvo_pr_req_alloc req_alloc;    /**< structure for allocating io reqs from the parcel router */
    struct nuvo_pr_buf_alloc buf_alloc;    /**< structure for allocating buffers from the parcel router */
    struct nuvo_parallel_op *par_op;       /**< a pointer to the parallel op this io is part of */
    struct nuvo_io_request  *io_req;       /**< a pointer to the original io request being serviced */
    struct nuvo_cache_vol   *cache_vol;    /**< a pointer to the volume cache tracking structure */
};


#define NUVO_CACHE_CIO_REQ_POOL_SIZE    (1024) // The size of the cio_request pool

/**
 * \brief A structure for maintaining a pool of cache io request structures
 */
struct cio_req_pool {
    nuvo_mutex_t       mutex;                               /**< Mutex protecting structure access */
    struct nuvo_dlist  alloc_list;                          /**< List of cio_request allocated */
    uint_fast32_t      used;                                /**< Number of cio_request currently in use */
    struct nuvo_dlist  free_list;                           /**< List of free cio_requests */
    struct cio_request table[NUVO_CACHE_CIO_REQ_POOL_SIZE]; /**< Static array of cio_requests */
};

/**
 * The cache cycles through the following three states.
 *
 * NUVO_CACHE_STATE_SHUTDOWN
 * The global cache struct has not been initialized. The cache must be intialized before
 * any other cache api calls may be called.
 * NUVO_CACHE_STATE_INITIALIZED
 * The global cache struct has been initialized. Devices may be added to the cache while in this state.
 * NUVO_CACHE_STATE_IN_USE.
 * Cache capacity has been allocated to at least one volume. No more devices may be added to the cache
 * while it's in this state.
 *
 */
enum cache_state
{
    NUVO_CACHE_STATE_SHUTDOWN    = 0,  /**< cache is shutdown, not initialized */
    NUVO_CACHE_STATE_INITIALIZED = 1,  /**< cache is initialized */
    NUVO_CACHE_STATE_IN_USE      = 2   /**< cache has been allocated to at least one volume */
};

/**
 * \brief Cache state variables
 */
struct nuvo_cache {
    nuvo_mutex_t             mutex;                           /**< Mutex protecting the cache state and mapping table */
    uint8_t                  cache_state;                     /**< Set to true when the cache is initialized */
    uuid_t                   cache_uuid;                      /**< The cache uuid */
    uint64_t                 required_device_size_bytes;      /**< The required size of all cache devices */
    uint64_t                 cache_size_bytes;                /**< The total unaligned size of the cache in bytes */
    uint32_t                 cache_avail_cl_count;            /**< The total unallocated number of cache lines */
    uint32_t                 cl_count;                        /**< The total number of cache lines */
    uint32_t                 tb_min_ways;                     /**< The minimum numbers of columns (ways) in the cache table */
    struct cio_req_pool      cio_req_pool;                    /**< pool of cache io requests */
    uint32_t                 device_count;                    /**< The number of devices that make up the cache */
    uint32_t                 num_fragments;                   /**< The number of fragments on the free list */
    struct nuvo_dlist        free_fragments;                  /**< A list of free cache space fragments */
    struct nuvo_cache_device devices[NUVO_CACHE_MAX_DEVICES]; /**< Array of individual cache devices */
};

/**
 * \brief Get the device index corresponding to a position within a set
 *
 * \return The device index.
 */
inline uint16_t cache_tb_set_idx_to_device_idx(uint16_t set_idx)
{
    NUVO_ASSERT(cache.device_count != 0);
    uint16_t idx;

    if (cache.device_count == 1)
    {
        idx = 0;
    }
    else if (cache.device_count <= 3)
    {
        idx = set_idx % cache.device_count;
    }
    else
    {
        idx = set_idx;
    }
    return (idx);
}

/**
 * \brief Get the number of cache lines (ways) in a the set
 *
 * For a given number of devices, calculates the minumum stripe width that uses
 * all devices an equal number of times and meets the minimum way count.
 *
 * The number of ways the N-way cache is derived from the number of devices being
 * used for the cache and subject to the following constraints.
 * Their is a minimum number of cache lines contained in a set.
 * Each set in the table is striped across all devices.
 * A set may contain only full stripes.
 * Within a set, devices are allocated an equal number of times.
 *
 * \return The number of ways
 */
inline uint16_t cache_tb_num_ways()
{
    NUVO_ASSERT(cache.tb_min_ways != 0);
    uint16_t ways;

    if (cache.device_count == 0)
    {
        ways = 0;
    }
    else if (cache.device_count >= cache.tb_min_ways)
    {
        ways = cache.device_count;
    }
    else if (cache.tb_min_ways % cache.device_count)
    {
        ways = ((cache.tb_min_ways / cache.device_count) + 1) * cache.device_count;
    }
    else
    {
        ways = cache.tb_min_ways;
    }
    return (ways);
}

/**
 * \brief Get the table set size
 *
 * \return The set size in bytes
 */
inline uint64_t cache_tb_get_set_size()
{
    return (cache_tb_num_ways() * NUVO_CACHE_LINE_SIZE_BLOCKS * NUVO_BLOCK_SIZE);
}

/**
 * \brief Get the incremental cache allocation unit size
 *
 * The cache allocation unit size is the number sets * size of set
 * that must be used when allocating cache capacity to a volume.
 *
 * The minimum allocation unit size could the size of a single set,
 * however, a larger number of sets is chosen to reduce the amount
 * memory required to track free cache space.
 *
 */
inline uint64_t cache_tb_get_alloc_unit_size()
{
    return (NUVO_CACHE_TB_NUM_SETS_PER_ALLOCATION * cache_tb_get_set_size());
}

/**
 * \brief Get the blocks needed per device for a cache allocation
 *
 * Calculates how many blocks are needed per device for the given
 * cache size allocation.
 *
 */
inline uint64_t cache_size_cl_to_blocks_per_device(uint32_t num_cl)
{
    return ((num_cl / cache.device_count) * NUVO_CACHE_LINE_SIZE_BLOCKS);
}

/**
 * \brief Get a cache line to insert a new entry
 *
 * \return The cache line to insert the key or NULL if none available
 */
struct nuvo_cache_line *cache_tb_insert(struct nuvo_cache_vol *cache_vol, union nuvo_cache_key key);

/**
 * \brief Find the set
 *
 * \return The cache line at the beginning of the set
 */
struct nuvo_cache_line *cache_tb_get_set(struct nuvo_cache_vol *cache_vol, uint64_t block_key, uint32_t num_sets);

/**
 * \brief Find a cache line
 *
 * \return The cache line or NULL if not found
 */
struct nuvo_cache_line *cache_tb_get(struct nuvo_cache_vol *cache_vol, union nuvo_cache_key key);

/**
 * \brief Move a cache line to the head of the logical LRU list
 */
void cache_tb_move_to_head(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl);

/**
 * \brief Invalidate a cache line
 */
void cache_tb_invalidate(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl);
