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
#include "status.h"
#include "nuvo_list.h"
#include "nuvo_pr.h"
#include "parcel_manager.h"

/**
 * \brief Cache statistics
 */
struct nuvo_cache_stats {
    uint64_t cio_read_hit_count;            /**< IO's serviced from cache */
    uint64_t cio_read_miss_count;           /**< IO's serviced from primary backing device */
    uint64_t cio_read_around_count;         /**< IO's that couldn't be serviced from cache line because it was pending an update */
    uint64_t cio_read_miss_no_update_count; /**< IO's serviced from primary but unable to be subsequently written to cache */
    uint64_t cio_write_new_count;           /**< IO's that allocated a new cache line on write */
    uint64_t cio_write_evict_count;         /**< IO's that evicted a cache line on write */
    uint64_t cio_write_update_count;        /**< IO's that updated an existing cache line (sequentially) */
    uint64_t cio_read_count;                /**< Total number of disaggregated reads */
    uint64_t cio_write_count;               /**< Total number of disaggregated writes */
    uint64_t cio_read_from_primary_count;   /**< Total number of reads from primary backing device */
    uint64_t ioreq_read_count;              /**< Total number of originating read IO's */
    uint64_t ioreq_write_count;             /**< Total number of originating write IO's */
    uint64_t ioreq_read_with_miss_count;    /**< Number of originating read that can't be serviced from cache completely */
    uint64_t cl_allocated_count;            /**< Total number of cache lines allocated */
    uint64_t cl_unavail_read_count;         /**< Number of times a read request cannot get a cache line */
    uint64_t cl_unavail_write_count;        /**< Number of times a write request cannot get a cache line */
};

/**
 * \brief Cache statistics related to GC data block move
 */
struct nuvo_cache_gc_stats {
    uint64_t read_block_count;              /**< Number of data blocks read by GC */
    uint64_t read_hit_block_count;          /**< Number of data blocks read by GC that's a cache hit */
    uint64_t read_miss_block_count;         /**< Number of data blocks read by GC that's a cache miss */
    uint64_t write_block_count;             /**< Number of data blocks written by GC */
    uint64_t write_cache_block_count;       /**< Number of data blocks written by GC with cache hint */
    uint64_t write_no_cache_block_count;    /**< Number of data blocks written by GC without cache hint */
};

/**
 * The cache can be resized any number of times.
 * Each time the cache is resized the hash function changes.
 * This caps the maximum number of hash functions that'll be evaluated to locate data in cache.
 * Data in cache that was last accessed more than NUVO_CACHE_MAX_HASHES ago will age out.
 */
#define NUVO_CACHE_MAX_HASHES_BITS    (3)
#define NUVO_CACHE_MAX_HASHES         (3)
static_assert((NUVO_CACHE_MAX_HASHES <= (1ull << NUVO_CACHE_MAX_HASHES_BITS) - 1ull), "NUVO_CACHE_MAX_RESIZES is too large");

/* The minimum number of columns (ways) in N-way set associative cache. */
/* min ways could be set at runtime in the future */
#define NUVO_CACHE_TB_MIN_WAYS         (4)
#define NUVO_CACHE_TB_MAX_WAYS_BITS    (4)
#define NUVO_CACHE_TB_MAX_WAYS         ((1ull << NUVO_CACHE_TB_MAX_WAYS_BITS) - 1ull)
static_assert((NUVO_CACHE_TB_MIN_WAYS <= NUVO_CACHE_TB_MAX_WAYS), "NUVO_CACHE_TB_MIN_WAYS is too large");

/**
 * \brief For tracking per volume cache limits and allocations
 */
struct nuvo_cache_vol {
    struct nuvo_cache_line    *tb;                              /**< Pointer to the start of the cache line mapping table */
    uint32_t                   tb_size;                         /**< Total size of the cache line mapping table */
    struct nuvo_dlist          fragments;                       /**< A list of the cache space fragments being used */
    uint32_t                   num_fragments;                   /**< Total number of fragments */
    uint32_t                   num_sets[NUVO_CACHE_MAX_HASHES]; /**< The number of sets in the set associative cache */
    uint16_t                   num_ways;                        /**< Number of cache lines in a set */
    uint32_t                   num_cl;                          /**< Total number of cache lines allocated to the volume */
    nuvo_mutex_t               io_pending_count_mutex;          /**< Mutex protecting io_pending_count */
    nuvo_cond_t                io_pending_count_zero_cond;      /**< Signaled when io_pending_count == 0 */
    uint32_t                   io_pending_count;                /**< The total number of IO's outstanding */
    struct nuvo_cache_stats    io_stats;                        /**< Cache stats for all IO to this volume */
    struct nuvo_cache_stats    user_io_stats;                   /**< Cache stats for user generated IO to this volume */
    struct nuvo_cache_gc_stats gc_io_stats;                     /**< Cache stats for GC generated IO to this volume */
    uint8_t                    num_hashes;                      /**< Number of hash functions to evaluate */
    bool                       is_enabled;                      /**< Set to true when the cache is able to handle IO */
};

#define NUVO_VOL_HAS_CACHE(vol)                                ((vol->log_volume.cache_vol.is_enabled) && (vol->log_volume.cache_vol.num_cl > 0))

#define NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, member)    { \
        (cache_vol)->io_stats.member++;                          \
        if (is_user) {                                           \
            (cache_vol)->user_io_stats.member++;                 \
        }                                                        \
}

#define NUVO_UPDATE_CACHE_GC_STATS(cache_vol, member, val)     { \
        (cache_vol)->gc_io_stats.member += val;                  \
}

/**
 *
 * \brief Initialize the cache state
 *
 * Initializes the global state struct used for the cache.
 *
 * \return 0 if successfully initialized.
 */
nuvo_return_t nuvo_cache_init();

/**
 * \brief Close the cache parcel and deallocate cache resources
 *
 * Destroying the cache closes the cache device releases any resources associated with the cache.
 *
 * \return None
 */
void nuvo_cache_destroy();

/**
 * \brief initialize the per volume cache tracking structure
 *
 * Intializes a structure to track the state of volumes cache.
 * After initialization cache capacity must be allocated to the volume
 * before the cache can be used.
 *
 * \param vol  A pointer to the volume
 * \return 0 if successfully initialized.
 */
nuvo_return_t nuvo_cache_vol_init(struct nuvo_vol *vol);

/**
 * \brief Destroys the per volume cache tracking structure
 *
 * Disable the per volume cache and free associated resources.
 * Waits for IO currently in progress to complete.
 * New IO will be sent to the primary backing device.
 *
 * \param vol  A pointer to the volume
 * \return None
 */
void nuvo_cache_vol_destroy(struct nuvo_vol *vol);

/**
 * \brief Add a new device to the cache.
 *
 * Takes a device path and uuid and formats the device with a single parcel and adds the
 * additional capacity to the existing cache.
 *
 * The cache size is the maximum block aligned parcel that can be allocated from the device,
 * after accounting for formatting overhead.
 *
 * After the device is formatted and the parcel allocated, the cache device will be addressable
 * using the same parcel_desc:block_offset that's used to rw to volume devices.
 *
 * The additional cache size is returned to the caller on create.
 * The devices size may also be queried after creation through nuvo_pm_device_info() or
 * a NUVO_OP_DEV_INFO request.
 *
 * \param device_path The device to be used as a cache
 * \param device_uuid The uuid to be used for the cache device
 * \param size_bytes A pointer to return the formatted devices cache capacity.
 * \param alloc_unit_size_bytes A pointer to return the cache allocation unit size.
 * \return 0 if successful, otherwise the error code.
 */
nuvo_return_t nuvo_cache_device_open(const char *device_path, const uuid_t device_uuid, uint64_t *size_bytes, uint64_t *alloc_unit_size_bytes);

/**
 * \brief Submit a cache read or write request
 *
 * If cache is enabled, all read and write operations are handled through this function,
 * which submits io requests to the cache and/or the primary as required.
 *
 * This routine should only be called via the resiliency layer, and only for
 * NUVO_OP_WRITE, NUVO_OP_READ, NUVO_OP_READ_VERIFY operations.
 *
 * If this routine is called and the volume has no cache enabled, nuvo_cache_submit_req()
 * will fail with NUVO_E_NO_CACHE. The io_req may be resubmitted directly to the backend
 * device.
 *
 * The cache is allocated in NUVO_CACHE_LINE_SIZE_BLOCKS size cache lines, which are
 * mapped into a table.
 * A cache key is an identifier made up from the volume,parcel,offset of the cache line.
 * The volume,parcel,offset provided on the io request is mapped to a corresponding cache
 * line tracking structure in the mapping table.
 *
 * The mapping table is organized into sets, with N cache lines per set for N-way set
 * associative cache. For cache lookup, a key is first hashed (modulo) to a set, and then
 * compared with the key of each valid cache line in the set to find a cache hit.
 * For allocating new cache line, the first unused cache line in the set is used, or if the
 * set is full, the least recently used cache line in the set will be evicted and reassigned.
 * The mapping from in-memory cache line tracking structure to on-device cache line offset
 * is static.
 * It's possible that an io request spans cache lines, so multiple keys may be required for lookup.
 *
 * If a read request spans cache lines, it's necessary to issue multiple io's to service the read.
 * It's possible that part of the data for the request is read partly from cache and partly from
 * the primary backing store.
 *
 * On a read request, the key is used to locate the corresponding cache lines. If the cache line is
 * found in the mapping table, and it's not currently being written, the data is read from cache with
 * a NUVO_OP_CACHE_HIT operation.
 * If the cache line is currently being updated, data will be read from the primary backing store
 * with NUVO_OP_CACHE_READ_AROUND operation.
 * On a cache miss, a cache line is allocated from the cache device and populated from the primary
 * backing store with a NUVO_OP_CACHE_MISS operation.
 * Because a cache miss reads an entire cache line, it may read data in excess of what's needed for
 * the immediate io request.
 *
 * On a write request, the key is used to locate the corresponding cache line. If the cache line is
 * found in the mapping table it's entry is deleted. This will cause a cache miss for the next read that
 * lands in the cache line.
 *
 * On a read miss, the full cache line is read from primary, which populates the cache line.
 * Because the primary backing store is written sequentially, new writes into the cache line
 * are similarly sequential. A write update to a cache line which has negative offset to the
 * last block written will cause the block cache line to be evicted.
 *
 * \param io_req A read or write io request.
 * \return 0 if successfully submitted, otherwise NUVO_E_NO_CACHE.
 */
nuvo_return_t nuvo_cache_submit_req(struct nuvo_io_request *io_req);

/**
 * \brief Allocates cache to a volume
 *
 * The cache space consumed by a volume is controlled by its cache
 * allocation. nuvo_cache_allocate() assigns cache space to a volume
 * for its dedicated use.
 *
 * The size_bytes must be a multiple of the allocation unit size returned
 * from the last call to nuvo_cache_device_open().
 *
 * If the allocation fails, an error is returned.
 * NUVO_EINVAL If the requested size is not a multiple of the cache allocation size.
 * NUVO_ENOMEM If memory couldn't be allocated to the table.
 *
 * \param vol  A pointer to the volume.
 * \param size_bytes  The amount of cache to allocate to the volume.
 * \return 0 if allocation was successful, otherwise error.
 */
nuvo_return_t nuvo_cache_vol_allocate(struct nuvo_vol *vol, uint64_t size_bytes);

/**
 * \brief Copy stats in a snapshotted struct for API.
 *
 * Returns a snapshot of the stats.
 *
 * \param cache_vol A pointer to the volumes cache tracking struct.
 * \param data A pointer to the cache stats struct for data counters.
 * \param metadata A pointer to the cache stats struct for metadata counters.
 * \param clear Resets counters if set to true.
 */
void nuvo_cache_stats_snap(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_stats *data, struct nuvo_cache_stats *metadata, bool clear);

/**
 * \brief Drop cache for a volume
 *
 * Used for testing only
 *
 * \param vol The volume whose cache to drop
 * \return none
 */
void nuvo_drop_cache(struct nuvo_vol *vol);
