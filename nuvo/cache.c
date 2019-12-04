/**
 * @file cache.c
 * @brief Implements a write through cache
 */

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
#include <uuid/uuid.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "nuvo.h"
#include "nuvo_vol_series.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "parcel_manager.h"
#include "cache_priv.h"
#include "parallel.h"
#include "gc.h"

struct nuvo_parallel_op *cache_par_op_alloc();
void cache_par_op_alloc_cb();
void cache_par_op_free(struct nuvo_parallel_op *ptr);
void cache_cio_submit(struct cio_request *cio_req, struct nuvo_io_request *io_req);

extern inline uint16_t cache_tb_set_idx_to_device_idx(uint16_t set_idx);
extern inline uint16_t cache_tb_num_ways();
extern inline uint64_t cache_tb_get_set_size();
extern inline uint64_t cache_tb_get_alloc_unit_size();
extern inline uint64_t cache_size_cl_to_blocks_per_device(uint32_t num_cl);

struct nuvo_cache cache;

/**
 * \brief Get the number of blocks to read from or write to the given cache line
 *
 * \param block_offset The offset of the cache line
 * \param io_req A pointer to the io_req being serviced
 *
 * \return The number of blocks
 */
uint32_t get_cache_line_io_len(uint32_t block_offset, struct nuvo_io_request *io_req)
{
    int32_t start, end;
    int32_t last_block = io_req->rw.block_offset + io_req->rw.block_count;

    if ((start = (io_req->rw.block_offset - block_offset)) < 0)
    {
        start = block_offset;
    }
    else
    {
        start += block_offset;
    }

    end = block_offset + NUVO_CACHE_LINE_SIZE_BLOCKS;
    if (end > last_block)
    {
        end = block_offset + (last_block % NUVO_CACHE_LINE_SIZE_BLOCKS);
    }

    return (end - start);
}

/**
 * \brief Return the parcel descriptor for the given cache line.
 * Given a pointer to an in-memory cache line tracking structure, return
 * the parcel descriptor for that cache line on caching device.
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param cl Pointer to cache line tracking structure
 * \return Parcel descriptor for the cache line
 */
uint32_t cl_parcel_desc(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl)
{
    NUVO_ASSERT(cl != NULL);
    return (cache.devices[cache_tb_set_idx_to_device_idx((cl - cache_vol->tb) % cache_vol->num_ways)].parcel_desc);
}

/**
 * \brief Map a cache device address to a cache line pointer
 *
 * Maps a cache device and block address back to a cache line pointer.
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param device_index the cache device.
 * \param block_offset block offset on the cache device.
 * \return Pointer to the cache line.
 */
struct nuvo_cache_line *device_offset_to_cl(struct nuvo_cache_vol *cache_vol, uint32_t device_index, uint32_t block_offset)
{
    struct nuvo_cache_line *cl = NULL;
    uint32_t cl_count = 0;
    struct nuvo_cache_fragment *curr_fragment;

    curr_fragment = nuvo_dlist_get_head_object(&cache_vol->fragments, struct nuvo_cache_fragment, list_node);
    while (1)
    {
        NUVO_ASSERT(curr_fragment);
        if ((block_offset < curr_fragment->block_offset) ||
            (block_offset >= curr_fragment->block_offset + ((curr_fragment->size_cl / cache.device_count) * NUVO_CACHE_LINE_SIZE_BLOCKS)))
        {
            // address is not in this fragment
            cl_count += curr_fragment->size_cl;
            curr_fragment = nuvo_dlist_get_next_object(&cache_vol->fragments, curr_fragment, struct nuvo_cache_fragment, list_node);
        }
        else
        {
            uint32_t cl_pos;
            cl_pos = cl_count + (((block_offset - curr_fragment->block_offset) * cache.device_count) / NUVO_CACHE_LINE_SIZE_BLOCKS) + device_index;
            cl = cache_vol->tb + cl_pos;
            break;
        }
    }
    return (cl);
}

/**
 * \brief Map cache line tracking structure to offset on cache device
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param cl Pointer to cache line tracking structure
 * \return Block offset on cache device
 */
uint32_t cl_block_offset(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl)
{
    NUVO_ASSERT(cl != NULL);
    struct nuvo_cache_fragment *curr_fragment;
    uint32_t cl_offset, cl_count = 0;
    uint32_t cl_pos = (cl - cache_vol->tb);

    curr_fragment = nuvo_dlist_get_head_object(&cache_vol->fragments, struct nuvo_cache_fragment, list_node);
    while (1)
    {
        NUVO_ASSERT(curr_fragment);
        if ((cl_count + curr_fragment->size_cl) < cl_pos + 1)
        {
            // cl is not in this fragment
            cl_count += curr_fragment->size_cl;
            NUVO_ASSERT(cl_count != 0);
            curr_fragment = nuvo_dlist_get_next_object(&cache_vol->fragments, curr_fragment, struct nuvo_cache_fragment, list_node);
        }
        else
        {
            // cl is in this fragment
            // the table row is striped across all devices at least once. To get the device relative address of the cache line,
            // divide the cl table position by the number of devices and multiply by the cache line size.
            cl_offset = curr_fragment->block_offset + (((cl_pos - cl_count) / cache.device_count) * NUVO_CACHE_LINE_SIZE_BLOCKS);

            NUVO_LOG(cache, 90, "cl %p is in fragment starting at block_offset %lu, size %lu. cl_offset: %lu", cl, curr_fragment->block_offset, curr_fragment->size_cl, cl_offset);
            break;
        }
    }
    return (cl_offset);
}

/**
 * \brief Find mapping table index for a block key
 *
 * \param block_key The key to look up.
 * \param num_sets The number of sets in the table.
 * \return The mapping table index.
 */
static inline uint64_t cache_tb_hash(uint64_t block_key, uint32_t num_sets)
{
    return ((block_key >> NUVO_CACHE_LINE_SIZE_BITS) % num_sets);
}

/**
 * \brief Map a key to a set
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param cl Pointer to a cache line object.
 * \return A pointer to the first cache line in the set.
 */
struct nuvo_cache_line *cache_tb_get_cl_set(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl)
{
    NUVO_ASSERT(cache_vol != NULL);
    NUVO_ASSERT(cl != NULL);

    uint64_t index = (cl - cache_vol->tb) / cache_vol->num_ways;
    struct nuvo_cache_line *set_cl = cache_vol->tb + (index * cache_vol->num_ways);

    NUVO_ASSERT(index < cache_vol->num_sets[cache_vol->num_hashes]);

    NUVO_LOG(cache, 90, "set %p. %p - %p = %lu. index = %lu index * num_ways = %lu. set offset %lu", set_cl, cl, cache_vol->tb, (cl - cache_vol->tb), index, (index * cache_vol->num_ways), cl - set_cl);

    return (set_cl);
}

/**
 * \brief Map a key to a set
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param block_key The key to a cache line.
 * \param num_sets The number of sets in the table.
 * \return A pointer to the first cache line in the set.
 */
struct nuvo_cache_line *cache_tb_get_set(struct nuvo_cache_vol *cache_vol, uint64_t block_key, uint32_t num_sets)
{
    NUVO_ASSERT(num_sets != 0);
    struct nuvo_cache_line *set_cl = NULL;

    // If the cache has been reduced in size, it's possible that this key
    // maps into a set that no longer exists. If it does return NULL.
    uint64_t index = cache_tb_hash(block_key, num_sets);
    if (index < cache_vol->num_sets[cache_vol->num_hashes])
    {
        set_cl = cache_vol->tb + (index * cache_vol->num_ways);
    }
    return (set_cl);
}

/**
 * \brief Check whether a key exists in the mapping table
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param key The key to a cache line
 * \return A pointer to the cache line or NULL if key does not exist
 */
struct nuvo_cache_line *cache_tb_get(struct nuvo_cache_vol *cache_vol, union nuvo_cache_key key)
{
    uint8_t num_hashes = 0;

    do
    {
        struct nuvo_cache_line *set_cl = cache_tb_get_set(cache_vol, key.block_key, cache_vol->num_sets[num_hashes]);
        if (set_cl != NULL)
        {
            // Find match within the set
            // TODO: starting with the most recent hash may be more efficient
            for (struct nuvo_cache_line *iter_cl = set_cl;
                 iter_cl < set_cl + cache_vol->num_ways;
                 iter_cl++)
            {
                if (iter_cl->in_use != 0 && (iter_cl->block_key == key.block_key))
                {
                    NUVO_LOG(cache, 90, "cl: %p in set %p at row index: %u cl->num_set: %u block_key: %lu", iter_cl, set_cl, iter_cl - set_cl, iter_cl->num_set, iter_cl->block_key);
                    return (iter_cl);
                }
            }
        }
        num_hashes++;
    } while (num_hashes <= cache_vol->num_hashes);

    return (NULL);
}

/**
 * \brief Move a cache line to the head of the per-set logical LRU list
 *
 * The cache line to be moved can be currently in use (on the logical LRU list),
 * or not currently in use (not on the logical LRU list). If the cache line is
 * not in use, its lpos must be set to an invalid value (>= cache_vol.num_ways)
 * by the caller before calling.
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param cl The cache line to move
 * \return none
 */
void cache_tb_move_to_head(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl)
{
    struct nuvo_cache_line *set_cl = cache_tb_get_cl_set(cache_vol, cl);


    for (struct nuvo_cache_line *iter_cl = set_cl;
         iter_cl < set_cl + cache_vol->num_ways;
         iter_cl++)
    {
        // Bump the lpos of in-use cache line that's lower than the lpos of
        // the cache line being moved to head
        if (iter_cl->in_use != 0 && iter_cl->lpos < cl->lpos)
        {
            iter_cl->lpos++;
            NUVO_ASSERT(iter_cl->lpos < cache_vol->num_ways);
        }
    }

    // Set the lpos of cache line being moved to 0 (head)
    cl->lpos = 0;
}

/**
 * \brief Get a cache line to insert a new entry (new allocation)
 *
 * Given a key which must not already exist in the mapping table, return
 * a cache line for use by this key. Cache line with pending I/O will not
 * be considered. Unused cache line in the set will be selected first.
 * If all cache lines in the set are in use, the most LRU cache line without
 * pending I/O will be selected (evicted for reuse). The selected cache
 * line's position will be moved to the head of the logical LRU list.
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param key The key of a cache line
 * \return Cache line to use or NULL if none available
 */
struct nuvo_cache_line *cache_tb_insert(struct nuvo_cache_vol *cache_vol, union nuvo_cache_key key)
{
    struct nuvo_cache_line *set_cl = cache_tb_get_set(cache_vol, key.block_key, cache_vol->num_sets[cache_vol->num_hashes]);
    struct nuvo_cache_line *ret_cl = NULL;

    NUVO_ASSERT(set_cl != NULL);

    // Iterate over each cache line in the set
    for (struct nuvo_cache_line *iter = set_cl;
         iter < set_cl + cache_vol->num_ways;
         iter++)
    {
        // Don't consider a cache line with pending I/O
        if (iter->rd_count != 0 || iter->wr_count != 0)
        {
            continue;
        }

        // If cache line is unused
        if (iter->in_use == 0)
        {
            // Select this cache line if we don't already have a candidate,
            // or if current candidate is a cache line in used (always prefer
            // unused cache line over used cache line)
            if (ret_cl == NULL || ret_cl->in_use != 0)
            {
                ret_cl = iter;
            }
        }
        else
        {
            // Cache line in use
            // The key must not already exist in the set
            NUVO_ASSERT(iter->block_key != key.block_key);
            NUVO_ASSERT(iter->lpos < cache_vol->num_ways);

            // Select this cache line as candidate if no current candidate exists, or
            // if current candidate is also a cache line in use but more recently used
            if (ret_cl == NULL || (ret_cl->in_use != 0 && ret_cl->lpos < iter->lpos))
            {
                ret_cl = iter;
            }
        }
    }

    if (ret_cl != NULL)
    {
        NUVO_ASSERT(ret_cl->wr_count == 0);
        NUVO_ASSERT(ret_cl->rd_count == 0);

        // If selected cache line is an unused cache line, set its
        // logical position to NUVO_CACHE_NUM_WAY (to indicate it
        // as such) before calling tb_move_to_head()
        if (ret_cl->in_use == 0)
        {
            ret_cl->lpos = cache_vol->num_ways;
        }
        else
        {
            NUVO_LOG(cache, 80, "evicting cache line [%lu:%05lu] for new key [%u:%04u]",
                     cl_parcel_desc(cache_vol, ret_cl), cl_block_offset(cache_vol, ret_cl), key.parcel_desc, key.block_offset);
        }
        // Set the key field and mark the cache line in use before calling tb_move_to_head()
        ret_cl->block_key = key.block_key;
        ret_cl->in_use = 1;
        ret_cl->first_block = ret_cl->last_block = 0;
        ret_cl->num_set = cache_vol->num_sets[cache_vol->num_hashes];
        cache_tb_move_to_head(cache_vol, ret_cl);
    }

    return (ret_cl);
}

/**
 * \brief Invalidate an in-use cache line
 *
 * Set the key of a valid (in-use) cache line to 0 and remove it from the
 * per-set logical LRU list
 *
 * \param cache_vol Pointer to the volumes cache tracking struct.
 * \param cl The cache line to invalidate
 * \return none
 */
void cache_tb_invalidate(struct nuvo_cache_vol *cache_vol, struct nuvo_cache_line *cl)
{
    struct nuvo_cache_line *set_cl = cache_tb_get_cl_set(cache_vol, cl);

    for (struct nuvo_cache_line *iter = set_cl;
         iter < set_cl + cache_vol->num_ways;
         iter++)
    {
        // Shift position of affected cache lines one place toward the head
        // of the logical LRU list
        if (iter->in_use != 0 && iter->lpos > cl->lpos)
        {
            iter->lpos--;
            // Valid value between 0 and (num_ways - 1) inclusive
            NUVO_ASSERT(iter->lpos < cache_vol->num_ways);
        }
    }

    // Invalidate this cache line by setting in_use to 0
    cl->in_use = 0;
}

/**
 * \brief Drop cache for a volume
 *
 * Used by debug trigger for testing only.
 *
 * \param vol The volume whose cache to drop
 * \return none
 */
void nuvo_drop_cache(struct nuvo_vol *vol)
{
    struct nuvo_cache_vol *cache_vol = &vol->log_volume.cache_vol;

    nuvo_mutex_lock(&cache.mutex);
    if (cache_vol == NULL)
    {
        nuvo_mutex_unlock(&cache.mutex);
        NUVO_LOG(cache, 0, "dropping cache for vol " NUVO_LOG_UUID_FMT " : volume does not have cache", NUVO_LOG_UUID(vol->vs_uuid));
        return;
    }

    NUVO_LOG(cache, 0, "dropping cache for vol " NUVO_LOG_UUID_FMT " ", NUVO_LOG_UUID(vol->vs_uuid));

    // Disable cache temporarily to prevent further cache I/O
    cache_vol->is_enabled = false;
    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
    nuvo_mutex_unlock(&cache.mutex);

    // Wait for pending I/O to complete
    while (cache_vol->io_pending_count != 0)
    {
        nuvo_cond_wait(&cache_vol->io_pending_count_zero_cond, &cache_vol->io_pending_count_mutex);
    }
    nuvo_mutex_lock(&cache.mutex);
    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

    // Clear entire cache
    struct nuvo_cache_line *iter = cache_vol->tb;
    for (uint32_t index = 0; index < cache_vol->num_cl; index++)
    {
        if (iter->in_use != 0)
        {
            cache_tb_invalidate(cache_vol, iter);
        }
        iter++;
    }

    cache_vol->is_enabled = true;
    nuvo_mutex_unlock(&cache.mutex);
    NUVO_LOG(cache, 0, "dropped cache for vol " NUVO_LOG_UUID_FMT " ", NUVO_LOG_UUID(vol->vs_uuid));
}

/**
 * \brief Initialize the pool of cache io (CIO) requests
 *
 * \param req_pool Pointer the CIO req pool.
 * \return 0 if successful, otherwise NUVO_ENOMEM.
 */
nuvo_return_t cache_cio_req_pool_init(struct cio_req_pool *req_pool)
{
    req_pool->used = 0;
    nuvo_dlist_init(&req_pool->free_list);
    nuvo_dlist_init(&req_pool->alloc_list);
    int ret = nuvo_mutex_init(&req_pool->mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
    }
    return (ret);
}

/**
 * \brief Uninitialize the pool of cache io requests
 *
 * the CIO request pool is statically allocated, so just destroy the mutex
 * \return None
 */
void cache_cio_req_pool_destroy(struct cio_req_pool *req_pool)
{
    nuvo_mutex_destroy(&req_pool->mutex);
}

/**
 * \brief allocate a cio_request for the pool of cache io requests
 *
 * \return a pointer to cio_request
 */
struct cio_request *cache_cio_req_alloc()
{
    struct cio_req_pool *req_pool = &cache.cio_req_pool;

    nuvo_mutex_lock(&req_pool->mutex);
    struct cio_request *req = nuvo_dlist_remove_head_object(&req_pool->free_list, struct cio_request, list_node);
    if (req == NULL)
    {
        if (req_pool->used < NUVO_ARRAY_LENGTH(req_pool->table))
        {
            req = &req_pool->table[req_pool->used++];
            nuvo_dlnode_init(&req->list_node);
        }
    }
    nuvo_mutex_unlock(&req_pool->mutex);
    return (req);
}

/**
 * \brief Free a cio_request
 *
 * \param req The request to be freed
 * \return None
 */
void cache_cio_req_free(struct cio_request *req)
{
    struct cio_req_pool *req_pool = &cache.cio_req_pool;

    NUVO_ASSERT(req != NULL);
    NUVO_ASSERT(req - req_pool->table >= 0);
    NUVO_ASSERT(req - req_pool->table < (intptr_t)NUVO_ARRAY_LENGTH(req_pool->table));

    nuvo_mutex_lock(&req_pool->mutex);
    nuvo_dlist_insert_head(&req_pool->free_list, &req->list_node);
    nuvo_mutex_unlock(&req_pool->mutex);
}

/**
 * \brief Completion callback for parallel io
 *
 * Called when all requested parallel io has completed
 *
 * \param par_op The parallel request op
 * \return None
 */
void cache_par_io_complete(struct nuvo_parallel_op *par_op)
{
    struct nuvo_io_request *io_req = (struct nuvo_io_request *)par_op->tag.ptr;

    nuvo_parallel_op_destroy(par_op);
    io_req->callback(io_req);
}

/**
 * \brief Allocate a cache line from the mapping table
 *
 * Allocates a tracking structure associated with a NUVO_CACHE_LINE_SIZE_BLOCKS size region in cache.
 * The allocation will fail if all cache lines in the set have pending I/O.
 *
 * \param cache_vol The volume
 * \param key Key to the cache line
 * \return A pointer to free cache line or NULL if none available
 */
struct nuvo_cache_line *cache_cio_cache_line_alloc(struct nuvo_cache_vol *cache_vol, union nuvo_cache_key key)
{
    struct nuvo_cache_line *cl;

    NUVO_ASSERT_MUTEX_HELD(&cache.mutex);

    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
    cl = cache_tb_insert(cache_vol, key);
    if (cl != NULL)
    {
        NUVO_LOG(cache, 80, "allocating cache line [%lu:%lu] for key [%u:%04u]",
                 cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), key.parcel_desc, key.block_offset);
    }
    else
    {
        NUVO_LOG(cache, 80, "unable to allocate cache line for key [%u:%04u]", key.parcel_desc, key.block_offset);
    }
    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

    return (cl);
}

/**
 * \brief get the index of the volume
 *
 * The volume index is part of the hash key, along with the parcel_desc and block_offset.
 * The index returned is offset by one when used as a hash key since 0 is not intended to be a valid key.
 *
 * \param vol The volume to get the index.
 * \return The index of the volume offset by one.
 */
uint16_t cache_vol_index_lookup(struct nuvo_vol *vol)
{
    NUVO_ASSERT(vol != NULL);
    uint16_t idx = nuvo_vol_index_lookup(vol) + 1;
    NUVO_ASSERT(idx < NUVO_MAX_VOL_SERIES_OPEN + 1);
    return (idx);
}

/*
 * Documented in header
 */
nuvo_return_t nuvo_cache_init()
{
    nuvo_return_t ret = 0;

    memset(&cache, 0, sizeof(struct nuvo_cache));

    if ((ret = nuvo_mutex_init(&cache.mutex)) != 0)
    {
        goto err_out;
    }
    if ((ret = cache_cio_req_pool_init(&cache.cio_req_pool)) != 0)
    {
        goto err_out_1;
    }

    nuvo_dlist_init(&cache.free_fragments);
    struct nuvo_cache_fragment *first_fragment = malloc(sizeof(struct nuvo_cache_fragment));
    nuvo_dlnode_init(&first_fragment->list_node);
    first_fragment->size_cl = 0;
    first_fragment->block_offset = 0;
    nuvo_dlist_insert_head(&cache.free_fragments, &first_fragment->list_node);
    cache.num_fragments = 1;

    cache.tb_min_ways = NUVO_CACHE_TB_MIN_WAYS;
    cache.cache_state = NUVO_CACHE_STATE_INITIALIZED;
    return (ret);

err_out_1:
    nuvo_mutex_destroy(&cache.mutex);
err_out:
    return (ret);
}

/*
 * Documented in header
 */
void nuvo_cache_destroy()
{
    NUVO_ASSERT(cache.cache_state != NUVO_CACHE_STATE_SHUTDOWN);

    // Assumes that all the individual volumes cache have been closed.

    nuvo_mutex_lock(&cache.mutex);
    cache.cache_state = NUVO_CACHE_STATE_SHUTDOWN;
    nuvo_mutex_unlock(&cache.mutex);

    for (unsigned i = 0; i < cache.device_count; i++)
    {
        nuvo_return_t             ret;
        struct nuvo_cache_device *device = &cache.devices[i];
        if ((ret = nuvo_pr_sync_parcel_close(device->parcel_desc)) != 0)
        {
            NUVO_ERROR_PRINT("Closing cache parcel failed: %d", ret);
            continue;
        }

        if ((ret = nuvo_pr_device_remove(device->device_uuid)) != 0)
        {
            NUVO_ERROR_PRINT("Removing cache device failed: %d", ret);
            continue;
        }

        if ((ret = nuvo_pm_device_close(device->device_uuid)) != 0)
        {
            NUVO_ERROR_PRINT("Closing cache device failed: %d", ret);
            continue;
        }
    }

    struct nuvo_cache_fragment *cache_fragment = nuvo_dlist_remove_head_object(&cache.free_fragments, struct nuvo_cache_fragment, list_node);
    if (cache_fragment)
    {
        NUVO_LOG(cache, 10, "Freeing cache allocation. block_offset: %lu size_cl: %lu", cache_fragment->block_offset, cache_fragment->size_cl);
        cache.num_fragments--;
        free(cache_fragment);
    }
    NUVO_ASSERT(cache.num_fragments == 0);
    NUVO_ASSERT(nuvo_dlist_remove_head_object(&cache.free_fragments, struct nuvo_cache_fragment, list_node) == NULL);

    cache_cio_req_pool_destroy(&cache.cio_req_pool);

    return;
}

/**
 * /brief Get the device index associated with the parcel descriptor.
 *
 * /param parcel_desc The parcel_desc of the cache device.
 * /return device index, otherwise -1.
 */
int32_t cache_get_device_idx_by_parcel_desc(uint32_t parcel_desc)
{
    NUVO_ASSERT_MUTEX_HELD(&cache.mutex);

    for (unsigned i = 0; i < cache.device_count; i++)
    {
        if (cache.devices[i].parcel_desc == parcel_desc)
        {
            return (i);
        }
    }
    return (-1);
}

/**
 * /brief Returns a pointer to the nuvo_cache_device struct associated with the given UUID is open.
 *
 * If a cache device with the given UUID has already been opened,
 * the function returns a pointer the nuvo_cache_device struct containing
 * information about the device, otherwise NULL.
 *
 * /param uuid The uuid of the cache device.
 * /return A pointer to a struct nuvo_cache_device, otherwise NULL.
 */
struct nuvo_cache_device *cache_get_device_by_uuid(const uuid_t device_uuid)
{
    NUVO_ASSERT(!uuid_is_null(device_uuid));
    NUVO_ASSERT_MUTEX_HELD(&cache.mutex);

    for (unsigned i = 0; i < cache.device_count; i++)
    {
        if (uuid_compare(cache.devices[i].device_uuid, device_uuid) == 0)
        {
            return (&cache.devices[i]);
        }
    }
    return (NULL);
}

/*
 * Documented in header
 *
 */
nuvo_return_t nuvo_cache_device_open(const char *device_path, const uuid_t device_uuid, uint64_t *size_bytes, uint64_t *alloc_unit_size_bytes)
{
    NUVO_ASSERT(device_path != NULL);
    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);
    NUVO_ASSERT(cache.cache_state != NUVO_CACHE_STATE_SHUTDOWN);
    nuvo_return_t ret, ret2;

    nuvo_mutex_lock(&cache.mutex);

    // set the return values so they're sane even if an error is encountered.
    *size_bytes = 0;
    *alloc_unit_size_bytes = cache_tb_get_alloc_unit_size();

    struct nuvo_cache_device *cache_device;
    cache_device = cache_get_device_by_uuid(device_uuid);
    if (cache_device)
    {
        nuvo_mutex_unlock(&cache.mutex);
        NUVO_ERROR_PRINT("A cache device with UUID: "NUVO_LOG_UUID_FMT " is already open.", NUVO_LOG_UUID(device_uuid));

        // return the correct return values since the caller may choose to ignore this error.
        *size_bytes = cache_device->cache_size_bytes;
        *alloc_unit_size_bytes = cache_tb_get_alloc_unit_size();
        return (-NUVO_E_DEVICE_ALREADY_OPEN);
    }
    else if (cache.device_count == NUVO_CACHE_MAX_DEVICES)
    {
        nuvo_mutex_unlock(&cache.mutex);
        NUVO_ERROR_PRINT("The cache is already configured with the maximum of %u devices.", NUVO_CACHE_MAX_DEVICES);
        return (-NUVO_E_DEVICE_NOT_USABLE);
    }
    else if (cache.cache_state == NUVO_CACHE_STATE_IN_USE)
    {
        nuvo_mutex_unlock(&cache.mutex);
        NUVO_ERROR_PRINT("The cache is in use. Unable to add additional cache devices.");
        return (-NUVO_E_DEVICE_NOT_USABLE);
    }
    else
    {
        cache_device = &cache.devices[cache.device_count];
    }

    // store the device_uuid
    uuid_copy(cache_device->device_uuid, device_uuid);

    // format device
    // pass zero on call to create one large parcel based on device size.
    ret = nuvo_pm_device_format(device_path, device_uuid, 0);
    if (ret != 0)
    {
        nuvo_mutex_unlock(&cache.mutex);
        return (ret);
    }

    // open "use" the device
    ret = nuvo_pm_device_open(device_path, device_uuid, NUVO_DEV_TYPE_EPH);
    if (ret != 0)
    {
        nuvo_mutex_unlock(&cache.mutex);
        return (ret);
    }

    // get the parcel size, the device is formatted as a single parcel.
    ret = nuvo_pm_device_info(device_uuid, &cache_device->device_info);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Get cache device info failed.");
        goto out_close;
    }

    // all cache devices added must have the same parcel size.
    if (cache.required_device_size_bytes == 0)
    {
        cache.required_device_size_bytes = cache_device->device_info.parcel_size;
    }
    else if (cache.required_device_size_bytes != cache_device->device_info.parcel_size)
    {
        NUVO_ERROR_PRINT("Cache devices must all have same size of %lu bytes. New device is %lu bytes",
                         cache.required_device_size_bytes, cache_device->device_info.parcel_size);
        ret = -NUVO_E_DEVICE_NOT_USABLE;
        goto out_close;
    }

    // need to inform the pr about the cache device in order to perform io to it.
    // accessing the device directly via the parcel_manager isn't practical because the it calls the pr on io completion.
    // in order to insert into the device table the local node uuid is required.
    uuid_t node_uuid;
    ret = nuvo_pr_get_node_uuid(node_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Unable to get the local node UUID.");
        goto out_close;
    }

    // tell the pr about the device
    ret = nuvo_pr_device_insert(device_uuid, node_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Unable to set the device location.");
        goto out_close;
    }

    // allocate the parcel
    // parcels must be associated with volume uuid, since we don't have a volume generate a cache uuid.
    ret = nuvo_pr_sync_parcel_alloc(cache_device->parcel_uuid, device_uuid, cache.cache_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Allocating cache parcel failed.");
        goto out_remove;
    }

    // open the parcel
    ret = nuvo_pr_sync_parcel_open(&cache_device->parcel_desc, cache_device->parcel_uuid, device_uuid, cache.cache_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Opening cache parcel failed.");
        goto out_remove;
    }

    // The cache allocation unit is minimum cache size allocation increment.
    // It is a pre-defined multiple of the set size.
    // As devices are added, the number of ways may change, changing the size of the set.
    // The cache size is a cache allocation unit aligned value, which is <= cache formatted size.
    cache.device_count++;
    *alloc_unit_size_bytes = cache_tb_get_alloc_unit_size();
    *size_bytes = cache_device->cache_size_bytes = cache_device->device_info.parcel_size;
    cache.cache_size_bytes += cache_device->cache_size_bytes;
    cache.cl_count = cache.cache_avail_cl_count = cache_size_bytes_to_cl(cache.cache_size_bytes);

    // Before the first volume is allocated cache, their is a single cache fragment representing the total cache capacity.
    // As devices are added the size of the cache fragment is increased.
    // After the first volume is allocated cache capacity, no new devices can be added to the cache.
    struct nuvo_cache_fragment *cache_fragment;
    cache_fragment = nuvo_dlist_get_head_object(&cache.free_fragments, struct nuvo_cache_fragment, list_node);
    NUVO_ASSERT(cache_fragment != NULL);
    cache_fragment->size_cl = cache.cache_avail_cl_count;
    cache_fragment->block_offset = 0;

    NUVO_LOG(cache, 0, "Added %lu bytes cache capacity from device "NUVO_LOG_UUID_FMT "", *size_bytes, NUVO_LOG_UUID(device_uuid));
    NUVO_LOG(cache, 0, "Total cache size: %lu bytes on %u devices", cache.cache_size_bytes, cache.device_count);

    nuvo_mutex_unlock(&cache.mutex);
    return (0);

out_remove:
    ret2 = nuvo_pr_device_remove(device_uuid);
    if (ret2 != 0)
    {
        NUVO_ERROR_PRINT("Unable to remove device after error: %d", ret2);
    }
out_close:
    ret2 = nuvo_pm_device_close(device_uuid);
    if (ret2 != 0)
    {
        NUVO_ERROR_PRINT("Unable to close device after error: %d", ret2);
    }
    memset(cache_device, 0, sizeof(struct nuvo_cache_device));
    nuvo_mutex_unlock(&cache.mutex);
    return (ret);
}

/**
 * \brief Handle io completion
 *
 * Processes completions for io submitted through the cache layer
 *
 * \b NUVO_OP_CACHE_READ_MISS
 * Completion of a NUVO_OP_CACHE_READ_MISS returns a full cache line. The original io request
 * may need one, some, or all of the blocks read. These blocks are copied to buffers provided
 * on the original io request. The data read is then written to cache, provided that the cache
 * line hasn't subsequently been invalidated.
 *
 * \b NUVO_OP_CACHE_READ_HIT and NUVO_OP_CACHE_READ_AROUND
 * Completion of these operations returns only the blocks requested using buffers
 * provided on the original io request, either from cache or from the primary device.
 *
 * \b NUVO_OP_CACHE_WRITE_AROUND
 * Completion of a write around request wrote data only to the primary device with no
 * corresponding cache update.
 *
 * \b NUVO_OP_CACHE_WRITE_CACHE
 * Completion of a cache write operation wrote a full cache line to the cache device, using
 * the buffers from the previous completion of a NUVO_OP_CACHE_READ_MISS operation.
 *
 *
 * \param completed_io_req Pointer to the completed io request
 * \return None
 */
void cache_cio_complete(struct nuvo_io_request *completed_io_req)
{
    NUVO_ASSERT(completed_io_req != NULL);

    struct cio_request    *cio_req = (struct cio_request *)completed_io_req->tag.ptr;
    struct nuvo_cache_vol *cache_vol = cio_req->cache_vol;
    struct nuvo_vol       *vol = nuvo_containing_object(cache_vol, struct nuvo_vol, log_volume.cache_vol);

    // check if this was a read from the cache device that returned bad data.
    // if it was, then re-submit this read to the primary device.
    if ((completed_io_req->status == -NUVO_E_BAD_HASH) && (cio_req->operation == NUVO_OP_CACHE_READ_HIT) && (completed_io_req->operation == NUVO_OP_READ_VERIFY))
    {
        NUVO_ASSERT(cio_req->io_req != NULL);
        NUVO_ASSERT(completed_io_req->rw.block_count == cio_req->block_count);

        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        NUVO_ASSERT(cache_vol->io_pending_count > 0);
        NUVO_ASSERT(cio_req->cl->rd_count > 0);
        cio_req->cl->rd_count--;
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

        cio_req->operation = NUVO_OP_CACHE_READ_AROUND_BAD_HASH;
        cio_req->parcel_desc = cio_req->io_req->rw.parcel_desc;
        cio_req->block_offset = cio_req->io_req->rw.block_offset + cio_req->iov_offset;
        cio_req->status = 0;

        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Cache read hash mismatch: parcel:offset: %lu:%lu length: %lu status: %ld. Reading data from primary: parcel offset %lu:%lu length %lu",
                         NUVO_LOG_UUID(vol->vs_uuid),
                         completed_io_req->rw.parcel_desc, completed_io_req->rw.block_offset, completed_io_req->rw.block_count, completed_io_req->status,
                         cio_req->parcel_desc, cio_req->block_offset, cio_req->block_count);

        completed_io_req->rw.parcel_desc = cio_req->parcel_desc;
        completed_io_req->rw.block_offset = cio_req->block_offset;
        completed_io_req->status = 0;

        NUVO_ASSERT(completed_io_req->callback == cache_cio_complete);

        struct nuvo_dlist submit_list;
        nuvo_dlist_init(&submit_list);
        nuvo_dlist_insert_tail(&submit_list, &completed_io_req->list_node);
        nuvo_pr_submit(&submit_list);

        return;
    }
    else if (cio_req->operation == NUVO_OP_CACHE_READ_AROUND_BAD_HASH)
    {
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Primary read completed: op: %u parcel offset [%lu:%lu] length %lu status: %ld",
                         NUVO_LOG_UUID(vol->vs_uuid),
                         completed_io_req->operation,
                         completed_io_req->rw.parcel_desc,
                         completed_io_req->rw.block_offset,
                         completed_io_req->rw.block_count,
                         completed_io_req->status);

        if (completed_io_req->status == 0)
        {
            NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". Invalid data detected in cache. Verified data on primary is correct", NUVO_LOG_UUID(vol->vs_uuid));
        }
        else
        {
            NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". Hash mismatch detected in both cache and on primary", NUVO_LOG_UUID(vol->vs_uuid));
        }
    }
    else if (completed_io_req->status < 0)
    {
        // TODO: handle errors. However, the parcel manager panics on i/o failure, fix this when it doesn't.
        NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". IO error: op: %u parcel offset [%lu:%lu] length %lu status: %ld",
                   NUVO_LOG_UUID(vol->vs_uuid),
                   completed_io_req->operation,
                   completed_io_req->rw.parcel_desc,
                   completed_io_req->rw.block_offset,
                   completed_io_req->rw.block_count,
                   completed_io_req->status);
    }
    else if (cio_req->operation != NUVO_OP_CACHE_WRITE_CACHE_ASYNC)
    {
        // The original io_req is not valid when the cache is being updated async
        NUVO_ASSERT(cio_req->io_req != NULL);
        cio_req->io_req->status = 0;
    }

    if (cio_req->operation == NUVO_OP_CACHE_READ_MISS)
    {
        NUVO_ASSERT(cio_req->io_req != NULL);
        struct nuvo_io_request *io_req = cio_req->io_req; // Pointer to the original io_req being serviced.
        uint32_t block_count = get_cache_line_io_len(cio_req->block_offset, io_req);
        uint32_t iov_offset = cio_req->iov_offset;
        int32_t  req_offset = io_req->rw.block_offset - cio_req->block_offset;
        bool     is_user = NUVO_IS_USER_IO(io_req);

        // A read miss always reads in a full cache line from the device.
        // Copy only the blocks needed for the original io_req.
        for (uint32_t i = iov_offset; i < iov_offset + block_count; i++)
        {
            memcpy(io_req->rw.iovecs[i].iov_base, completed_io_req->rw.iovecs[req_offset + i].iov_base, io_req->rw.iovecs[i].iov_len);
            if (cio_req->verify_flag)
            {
                NUVO_ASSERT(io_req->rw.block_hashes[i] == completed_io_req->rw.block_hashes[req_offset + i]);
            }
            else
            {
                io_req->rw.block_hashes[i] = completed_io_req->rw.block_hashes[req_offset + i];
            }
        }

        // Indicate that this portion of the read is complete
        // The update of the cache is performed asynchronously, since the read isn't dependant on
        // the subsequent completion of the cache write.
        // If all data needed for the request has been read this call will do completion to the caller.
        nuvo_parallel_op_done(cio_req->par_op, io_req->status);
        // After calling done the io_req passed in on the cio_req can no longer be referenced.
        cio_req->io_req = io_req = NULL;

        // Now update the cache with the data just read from the primary device.
        // Can re-use the completed io_req since the cache layer allocated the read buffers.
        nuvo_mutex_lock(&cache.mutex);
        if (cio_req->cl->in_use == 0)
        {
            nuvo_mutex_unlock(&cache.mutex);
            struct nuvo_cache_line *cl = cio_req->cl;
            NUVO_ASSERT(cl != NULL);

            nuvo_pr_client_buf_free_req(completed_io_req);
            nuvo_pr_client_req_free(completed_io_req);
            cache_cio_req_free(cio_req);

            // A new write has since invalidated this cache line, so skip updating the cache
            nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
            NUVO_ASSERT(cl->wr_count > 0);
            NUVO_ASSERT(cache_vol->io_pending_count > 0);
            NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_miss_no_update_count);
            cl->wr_count--;
            if (--cache_vol->io_pending_count == 0)
            {
                nuvo_cond_signal(&cache_vol->io_pending_count_zero_cond);
            }
            nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
        }
        else
        {
            // since this is a full cache line write there shouldn't be any other writes going on.
            nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
            NUVO_ASSERT(cio_req->cl->wr_count == 1);
            NUVO_ASSERT(cache_vol->io_pending_count > 0);
            nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

            // Reuse the cio_req and the completed_io_req from the read to write to cache.
            cio_req->operation = NUVO_OP_CACHE_WRITE_CACHE_ASYNC;
            completed_io_req->operation = NUVO_OP_WRITE;
            completed_io_req->tag.ptr = cio_req;
            completed_io_req->callback = cache_cio_complete;
            completed_io_req->rw.parcel_desc = cl_parcel_desc(cache_vol, cio_req->cl);
            completed_io_req->rw.block_offset = cl_block_offset(cache_vol, cio_req->cl);
            nuvo_mutex_unlock(&cache.mutex);

            struct nuvo_dlist submit_list;
            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_tail(&submit_list, &completed_io_req->list_node);
            nuvo_pr_submit(&submit_list);
        }
    }
    else if (cio_req->operation == NUVO_OP_CACHE_WRITE_CACHE)
    {
        struct nuvo_cache_line *cl = cio_req->cl;
        NUVO_ASSERT(cl != NULL);

        nuvo_parallel_op_done(cio_req->par_op, completed_io_req->status);

        nuvo_pr_client_req_free(completed_io_req);
        cache_cio_req_free(cio_req);

        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        NUVO_ASSERT(cl->wr_count > 0);
        NUVO_ASSERT(cache_vol->io_pending_count > 0);
        cl->wr_count--;
        if (--cache_vol->io_pending_count == 0)
        {
            nuvo_cond_signal(&cache_vol->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
    }
    else if (cio_req->operation == NUVO_OP_CACHE_READ_HIT)
    {
        struct nuvo_cache_line *cl = cio_req->cl;
        NUVO_ASSERT(cl != NULL);

        // Copy the block hashes for the buffers from the completed io_req to the original io_req and send completion.
        NUVO_ASSERT(cio_req->io_req != NULL);
        NUVO_ASSERT(completed_io_req->rw.block_count == cio_req->block_count);
        for (uint32_t i = 0; i < completed_io_req->rw.block_count; i++)
        {
            NUVO_ASSERT(cio_req->io_req->rw.iovecs[i + cio_req->iov_offset].iov_base == completed_io_req->rw.iovecs[i].iov_base);
            NUVO_ASSERT(cio_req->io_req->rw.iovecs[i + cio_req->iov_offset].iov_len == completed_io_req->rw.iovecs[i].iov_len);
            cio_req->io_req->rw.block_hashes[i + cio_req->iov_offset] = completed_io_req->rw.block_hashes[i];
        }
        // After calling done the io_req pointer on the cio_req should no longer be referenced.
        nuvo_parallel_op_done(cio_req->par_op, cio_req->io_req->status);
        cio_req->io_req = NULL;

        completed_io_req->rw.block_count = 0;
        nuvo_pr_client_req_free(completed_io_req);
        cache_cio_req_free(cio_req);

        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        NUVO_ASSERT(cache_vol->io_pending_count > 0);
        NUVO_ASSERT(cl->rd_count > 0);
        cl->rd_count--;
        if (--cache_vol->io_pending_count == 0)
        {
            nuvo_cond_signal(&cache_vol->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
    }
    else if (cio_req->operation == NUVO_OP_CACHE_READ_AROUND)
    {
        // Copy the block hashes for the buffers read in and send completion.
        NUVO_ASSERT(cio_req->io_req != NULL);
        NUVO_ASSERT(completed_io_req->rw.block_count == cio_req->block_count);
        for (uint32_t i = 0; i < completed_io_req->rw.block_count; i++)
        {
            NUVO_ASSERT(cio_req->io_req->rw.iovecs[i + cio_req->iov_offset].iov_base == completed_io_req->rw.iovecs[i].iov_base);
            NUVO_ASSERT(cio_req->io_req->rw.iovecs[i + cio_req->iov_offset].iov_len == completed_io_req->rw.iovecs[i].iov_len);
            cio_req->io_req->rw.block_hashes[i + cio_req->iov_offset] = completed_io_req->rw.block_hashes[i];
        }
        // After calling done the io_req pointer on the cio_req should no longer be referenced.
        nuvo_parallel_op_done(cio_req->par_op, cio_req->io_req->status);
        cio_req->io_req = NULL;

        completed_io_req->rw.block_count = 0;
        nuvo_pr_client_req_free(completed_io_req);
        cache_cio_req_free(cio_req);

        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        NUVO_ASSERT(cache_vol->io_pending_count > 0);
        if (--cache_vol->io_pending_count == 0)
        {
            nuvo_cond_signal(&cache_vol->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
    }
    else if (cio_req->operation == NUVO_OP_CACHE_WRITE_AROUND)
    {
        // The buffers on the completed io_req are shared with the original io_req
        // This loop is debug only. It asserts that we're working the correct buffers, and cleans up the io_req.
#ifndef NDEBUG
        for (uint32_t i = 0; i < completed_io_req->rw.block_count; i++)
        {
            NUVO_ASSERT(cio_req->io_req->rw.iovecs[cio_req->block_offset + i].iov_base == completed_io_req->rw.iovecs[i].iov_base);
            completed_io_req->rw.iovecs[i].iov_base = NULL;
            completed_io_req->rw.iovecs[i].iov_len = 0;
        }
#endif
        NUVO_ASSERT(cio_req->io_req != NULL);
        nuvo_parallel_op_done(cio_req->par_op, cio_req->io_req->status);

        completed_io_req->rw.block_count = 0;
        nuvo_pr_client_req_free(completed_io_req);
        cache_cio_req_free(cio_req);

        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        NUVO_ASSERT(cache_vol->io_pending_count > 0);
        if (--cache_vol->io_pending_count == 0)
        {
            nuvo_cond_signal(&cache_vol->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
    }
    else if (cio_req->operation == NUVO_OP_CACHE_WRITE_CACHE_ASYNC)
    {
        struct nuvo_cache_line *cl = cio_req->cl;
        NUVO_ASSERT(cl != NULL);

        nuvo_pr_client_buf_free_req(completed_io_req);
        nuvo_pr_client_req_free(completed_io_req);
        cache_cio_req_free(cio_req);

        // Finished update of the cache line.
        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        NUVO_ASSERT(cl->wr_count > 0);
        NUVO_ASSERT(cache_vol->io_pending_count > 0);
        cl->wr_count--;
        if (--cache_vol->io_pending_count == 0)
        {
            nuvo_cond_signal(&cache_vol->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
    }
}

/**
 * \brief Prepares read and write requests and submits for i/o.
 *
 * \b NUVO_OP_CACHE_WRITE_AROUND:
 * Submits a write io request to the primary backing store.
 * \b NUVO_OP_CACHE_READ_MISS:
 * Submits a read io request to the primary backing store.
 * Read misses read in the entire cache line, which will be written to cache
 * on completion.
 * \b NUVO_OP_CACHE_READ_AROUND:
 * Submits a read io request to the primary backing store.
 * \b NUVO_OP_CACHE_READ_HIT:
 * Submits a read io request to the cache device.
 *
 * \param cio_req A pointer to a cache i/o request struct containing i/o parameters.
 * \param io_req A pointer to an i/o request struct allocated from the parcel router.
 * \return None.
 */
void cache_cio_submit(struct cio_request *cio_req, struct nuvo_io_request *io_req)
{
    NUVO_ASSERT(cio_req != NULL);
    NUVO_ASSERT(io_req != NULL);

    struct nuvo_dlist submit_list;

    if (cio_req->operation == NUVO_OP_CACHE_READ_MISS)
    {
        io_req->operation = NUVO_OP_READ;
        io_req->tag.ptr = cio_req;
        io_req->callback = cache_cio_complete;
        io_req->rw.block_offset = cio_req->block_offset;
        io_req->rw.parcel_desc = cio_req->parcel_desc;
        NUVO_ASSERT(io_req->rw.block_count = cio_req->block_count);
    }
    else if ((cio_req->operation == NUVO_OP_CACHE_WRITE_AROUND) ||
             (cio_req->operation == NUVO_OP_CACHE_WRITE_CACHE))
    {
        io_req->operation = NUVO_OP_WRITE;
        io_req->tag.ptr = cio_req;
        io_req->callback = cache_cio_complete;
    }
    else if ((cio_req->operation == NUVO_OP_CACHE_READ_HIT) ||
             (cio_req->operation == NUVO_OP_CACHE_READ_AROUND))
    {
        io_req->operation = (cio_req->verify_flag) ? NUVO_OP_READ_VERIFY : NUVO_OP_READ;
        io_req->tag.ptr = cio_req;
        io_req->callback = cache_cio_complete;
    }
    else
    {
        NUVO_PANIC("invalid cache io operation");
    }
    nuvo_parallel_op_submitting(cio_req->par_op);
    nuvo_mutex_lock(&cio_req->par_op->mutex);
    bool done = (cio_req->par_io_count == cio_req->par_op->ops_submitted) ? true : false;
    nuvo_mutex_unlock(&cio_req->par_op->mutex);

    if (done)
    {
        // Need to call before submitting otherwise can deadlock
        nuvo_parallel_op_finalize(cio_req->par_op);
    }

    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
    nuvo_pr_submit(&submit_list);
}

/** \brief Callback routine after allocating buffers
 *
 * Wrapper routine to call cache_io_submit() with the appropriate parameters.
 *
 * \param buf_alloc A request pointer
 * \return None.
 */
void cache_cio_rw_submit(struct nuvo_pr_buf_alloc *buf_alloc)
{
    struct cio_request     *cio_req = (struct cio_request *)buf_alloc->tag.ptr;
    struct nuvo_io_request *io_req = (struct nuvo_io_request *)buf_alloc->req;

    cache_cio_submit(cio_req, io_req);
}

/** \brief Callback routine for allocating buffers.
 *
 * When this callback is invoked req_alloc will have a nuvo_io_request allocated.
 * For NUVO_OP_CACHE_READ_MISS this function sets up the next call into the PR again to get buffers for the io request.
 * For all other operations the buffers used for the io are provided by the original io request.
 *
 * \param req_alloc A request pointer
 * \return None.
 */
void cache_cio_buf_alloc_cb(struct nuvo_pr_req_alloc *req_alloc)
{
    NUVO_ASSERT(req_alloc != NULL);
    NUVO_ASSERT(req_alloc->req != NULL);

    struct cio_request *cio_req = (struct cio_request *)req_alloc->tag.ptr;
    NUVO_ASSERT(cio_req != NULL);

    if (cio_req->operation == NUVO_OP_CACHE_WRITE_AROUND)
    {
        req_alloc->req->rw.parcel_desc = cio_req->parcel_desc;
        req_alloc->req->rw.block_offset = cio_req->io_req->rw.block_offset + cio_req->block_offset;
        req_alloc->req->rw.block_count = cio_req->block_count;
        for (uint32_t i = 0; i < cio_req->block_count; i++)
        {
            req_alloc->req->rw.iovecs[i].iov_base = cio_req->io_req->rw.iovecs[i + cio_req->block_offset].iov_base;
            req_alloc->req->rw.iovecs[i].iov_len = cio_req->io_req->rw.iovecs[i + cio_req->block_offset].iov_len;
            req_alloc->req->rw.block_hashes[i] = cio_req->io_req->rw.block_hashes[i + cio_req->block_offset];
            NUVO_ASSERT((req_alloc->req->rw.iovecs[i].iov_base != NULL) && (req_alloc->req->rw.iovecs[i].iov_len > 0));
        }
        cache_cio_submit(cio_req, req_alloc->req);
    }
    else if ((cio_req->operation == NUVO_OP_CACHE_READ_HIT) ||
             (cio_req->operation == NUVO_OP_CACHE_READ_AROUND) ||
             (cio_req->operation == NUVO_OP_CACHE_WRITE_CACHE))
    {
        req_alloc->req->rw.parcel_desc = cio_req->parcel_desc;
        req_alloc->req->rw.block_offset = cio_req->block_offset;
        req_alloc->req->rw.block_count = cio_req->block_count;
        for (uint32_t i = 0; i < cio_req->block_count; i++)
        {
            req_alloc->req->rw.iovecs[i].iov_base = cio_req->io_req->rw.iovecs[i + cio_req->iov_offset].iov_base;
            req_alloc->req->rw.iovecs[i].iov_len = cio_req->io_req->rw.iovecs[i + cio_req->iov_offset].iov_len;
            if ((cio_req->operation == NUVO_OP_CACHE_WRITE_CACHE) || cio_req->verify_flag)
            {
                req_alloc->req->rw.block_hashes[i] = cio_req->io_req->rw.block_hashes[i + cio_req->iov_offset];
            }
            NUVO_ASSERT((req_alloc->req->rw.iovecs[i].iov_base != NULL) && (req_alloc->req->rw.iovecs[i].iov_len > 0));
        }
        cache_cio_submit(cio_req, req_alloc->req);
    }
    else
    {
        struct nuvo_pr_buf_alloc *buf_alloc = &cio_req->buf_alloc;

        nuvo_pr_buf_alloc_init_req(buf_alloc,
                                   req_alloc->req,
                                   (union nuvo_tag)(void *)cio_req,
                                   cache_cio_rw_submit);
        buf_alloc->req->rw.block_count = cio_req->block_count;

        nuvo_pr_client_buf_alloc_batch(buf_alloc);
    }
}

/*
 * Documented in header
 */
nuvo_return_t nuvo_cache_submit_req(struct nuvo_io_request *io_req)
{
    NUVO_ASSERT(io_req != NULL);
    NUVO_ASSERT(io_req->operation == NUVO_OP_READ || io_req->operation == NUVO_OP_READ_VERIFY || io_req->operation == NUVO_OP_WRITE);
    struct nuvo_cache_vol *cache_vol = &io_req->rw.vol->log_volume.cache_vol;

    // Lock the entire cache object when working with table
    nuvo_mutex_lock(&cache.mutex);

    // Ensure this volume has its cache enabled.
    if (!NUVO_VOL_HAS_CACHE(io_req->rw.vol))
    {
        nuvo_mutex_unlock(&cache.mutex);
        return (-NUVO_E_NO_CACHE);
    }
    NUVO_ASSERT(cache_vol->num_cl != 0);

    NUVO_LOG(cache, 40, "Vol: "NUVO_LOG_UUID_FMT ". Device io [%05lu:%05lu] length %u. %s",
             NUVO_LOG_UUID(io_req->rw.vol->vs_uuid),
             io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_count,
             (io_req->operation == NUVO_OP_WRITE) ? "write" : "read");

    struct nuvo_parallel_op *par_op = &io_req->rw.par_op;
    bool          is_user = NUVO_IS_USER_IO(io_req);
    nuvo_return_t ret;
    if ((ret = nuvo_parallel_op_init(par_op)) != 0)
    {
        // Something is very wrong if we can't init.
        // Return an error back to the resiliency layer without doing anything.
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Failed to initialize parallel op.", NUVO_LOG_UUID(io_req->rw.vol->vs_uuid));
        nuvo_mutex_unlock(&cache.mutex);
        return (ret);
    }
    par_op->callback = cache_par_io_complete;
    par_op->tag.ptr = (void *)io_req;   // Stash the original io request

    // The list of cio_request to submit
    struct nuvo_dlist local_submit_list;
    int num_cio_req = 0;
    int num_skip = 0;
    nuvo_dlist_init(&local_submit_list);

    if (io_req->operation == NUVO_OP_WRITE)
    {
        // Submit the original write to the primary back end device
        struct cio_request *cio_req = cache_cio_req_alloc();
        if (cio_req == NULL)
        {
            // It would better to do this alloc async, but i need a req to get a req which i don't have.
            NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". Out of cio requests.", NUVO_LOG_UUID(io_req->rw.vol->vs_uuid));
        }

        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, ioreq_write_count);
        if (NUVO_IS_GC_DATA(io_req))
        {
            NUVO_UPDATE_CACHE_GC_STATS(cache_vol, write_block_count, io_req->rw.block_count);
            if (io_req->rw.cache_hint == NUVO_CACHE_DEFAULT)
            {
                NUVO_UPDATE_CACHE_GC_STATS(cache_vol, write_cache_block_count, io_req->rw.block_count);
            }
            if (io_req->rw.cache_hint == NUVO_CACHE_NONE)
            {
                NUVO_UPDATE_CACHE_GC_STATS(cache_vol, write_no_cache_block_count, io_req->rw.block_count);
            }
        }

        cio_req->operation = NUVO_OP_CACHE_WRITE_AROUND;
        cio_req->parcel_desc = io_req->rw.parcel_desc;
        cio_req->block_count = io_req->rw.block_count;
        cio_req->block_offset = 0;
        cio_req->par_op = par_op;
        cio_req->io_req = io_req;
        cio_req->cache_vol = cache_vol;
        cio_req->cl = NULL;

        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
        cache_vol->io_pending_count++;
        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

        nuvo_dlist_insert_tail(&local_submit_list, &cio_req->list_node);
        num_cio_req++;
    }
    else
    {
        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, ioreq_read_count);
        if (NUVO_IS_GC_DATA(io_req))
        {
            NUVO_UPDATE_CACHE_GC_STATS(cache_vol, read_block_count, io_req->rw.block_count);
        }
    }

    uint32_t b_offset = io_req->rw.block_offset;
    int32_t  b_remaining = io_req->rw.block_count;
    uint32_t iov_offset = 0;
    uint32_t cl_count = 0;
    uint32_t read_from_primary_count = 0; // Number of read from primary device needed for this io_req
    while (b_remaining > 0)
    {
        union nuvo_cache_key key;
        uint32_t             cb_offset = b_offset - (b_offset % NUVO_CACHE_LINE_SIZE_BLOCKS);
        uint32_t             first_block = b_offset - cb_offset;
        uint32_t             b_count = get_cache_line_io_len(cb_offset, io_req);

        key.parcel_desc = io_req->rw.parcel_desc;
        key.block_offset = cb_offset;
        NUVO_LOG(cache, 80, "key %d: [%u:%04u]  b_offset: %u b_remaining: %u iov_offset: %u b_count: %u cb_offset: %u first_block: %u",
                 cl_count++, key.parcel_desc, key.block_offset, b_offset, b_remaining, iov_offset, b_count, cb_offset, first_block);

        struct nuvo_cache_line *cl = cache_tb_get(cache_vol, key);
        struct cio_request     *cio_req = cache_cio_req_alloc();
        if (cio_req == NULL)
        {
            // It would better to do this alloc async, but i need a req to get a req which i don't have.
            NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". Out of cio requests.", NUVO_LOG_UUID(io_req->rw.vol->vs_uuid));
        }

        if (io_req->operation == NUVO_OP_WRITE)
        {
            NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_write_count);
            if (cl == NULL)
            {
                if (io_req->rw.cache_hint == NUVO_CACHE_NONE)
                {
                    num_skip++;
                    cache_cio_req_free(cio_req);
                    NUVO_LOG(cache, 80, "write miss. key [%u:%04u] write will not update cache. Skip cache on hint", key.parcel_desc, key.block_offset);
                }
                else if ((cl = cache_cio_cache_line_alloc(cache_vol, key)) == NULL)
                {
                    // Can't get a cache line
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_unavail_write_count);
                    num_skip++;
                    cache_cio_req_free(cio_req);
                    NUVO_LOG(cache, 80, "write miss. key [%u:%04u] write will not update cache. no cache line available", key.parcel_desc, key.block_offset);
                }
                else
                {
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_allocated_count);
                    NUVO_ASSERT(cl->in_use == 1);
                    NUVO_ASSERT(cl->block_key == key.block_key);
                    cl->first_block = first_block;
                    cl->last_block = cl->first_block + b_count;

                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_write_new_count);
                    cio_req->operation = NUVO_OP_CACHE_WRITE_CACHE;
                    cio_req->parcel_desc = cl_parcel_desc(cache_vol, cl);
                    cio_req->block_offset = cl_block_offset(cache_vol, cl) + cl->first_block;
                    cio_req->block_count = b_count;
                    cio_req->iov_offset = iov_offset;
                    cio_req->par_op = par_op;
                    cio_req->io_req = io_req;
                    cio_req->cache_vol = cache_vol;
                    cio_req->cl = cl;

                    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                    cl->wr_count = 1;
                    cache_vol->io_pending_count++;
                    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

                    NUVO_LOG(cache, 80, "cache write: new cl: device io [%lu:%05lu] -> cache [%lu:%lu] write to %lu length %u for iov_start %u. first: %u last: %u. req: %d",
                             io_req->rw.parcel_desc, io_req->rw.block_offset + iov_offset,
                             cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl),
                             cio_req->block_offset, cio_req->block_count, cio_req->iov_offset,
                             cl->first_block, cl->last_block, num_cio_req + 1);

                    nuvo_dlist_insert_tail(&local_submit_list, &cio_req->list_node);
                    num_cio_req++;
                }
            }
            else
            {
                if (io_req->rw.cache_hint == NUVO_CACHE_NONE)
                {
                    // Just invalidate the cache line
                    cache_tb_invalidate(cache_vol, cl);
                    num_skip++;
                    cache_cio_req_free(cio_req);
                    NUVO_LOG(cache, 80, "write hit. invalidating cache line [%lu:%lu] with key [%u:%04u] on hint",
                             cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), key.parcel_desc, key.block_offset);
                }
                else if (first_block != cl->last_block)
                {
                    // Updating the cache line non-sequentially.
                    NUVO_LOG(cache, 80, "cache write: invalidating cache line [%lu:%lu] with key [%u:%04u]. update at offset %lu != %lu with pending io (writes: %d, reads: %d)",
                             cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), key.parcel_desc, key.block_offset,
                             first_block, cl->last_block, cl->wr_count, cl->rd_count);

                    // TODO: if this is a range error and there are no reads or writes outstanding,
                    // you could just re-use the existing key,value and reset the counters on the cl.

                    // This io is updating a cache line non-sequentially while there's io outstanding.
                    // if there's reads outstanding the cache line also needs to be dropped since
                    // there's not enough info to know if this write would overlap.
                    // The current cache line is evicted and we get a new cache line to write to.

                    // The key is valid, but this is an overwrite or non-sequential update
                    // Mark the existing cache line as unused, and get new one to write our update.
                    NUVO_ASSERT(cl->in_use == 1);
                    cache_tb_invalidate(cache_vol, cl);
                    cl = cache_cio_cache_line_alloc(cache_vol, key);
                    if (!cl)
                    {
                        // Can't get a cache line
                        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_unavail_write_count);
                        num_skip++;
                        cache_cio_req_free(cio_req);
                        NUVO_LOG(cache, 80, "write hit. key: [%u:%04u] write will not update cache. no cache line available", key.parcel_desc, key.block_offset);
                    }
                    else
                    {
                        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_allocated_count);
                        NUVO_ASSERT(cl->in_use == 1);
                        NUVO_ASSERT(cl->block_key == key.block_key);
                        cl->first_block = first_block;
                        cl->last_block = cl->first_block + b_count;

                        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_write_evict_count);
                        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_write_new_count);
                        cio_req->operation = NUVO_OP_CACHE_WRITE_CACHE;
                        cio_req->parcel_desc = cl_parcel_desc(cache_vol, cl);
                        cio_req->block_offset = cl_block_offset(cache_vol, cl) + cl->first_block;
                        cio_req->block_count = b_count;
                        cio_req->iov_offset = iov_offset;
                        cio_req->par_op = par_op;
                        cio_req->io_req = io_req;
                        cio_req->cache_vol = cache_vol;
                        cio_req->cl = cl;

                        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                        cl->wr_count = 1;
                        cache_vol->io_pending_count++;
                        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

                        NUVO_LOG(cache, 80, "cache write: new cl: device io [%lu:%05lu] -> cache [%lu:%lu] write to %lu length %u for iov_start %u. first: %u last: %u. req: %d",
                                 io_req->rw.parcel_desc, io_req->rw.block_offset + iov_offset,
                                 cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl),
                                 cio_req->block_offset, cio_req->block_count, cio_req->iov_offset,
                                 cl->first_block, cl->last_block, num_cio_req + 1);

                        nuvo_dlist_insert_tail(&local_submit_list, &cio_req->list_node);
                        num_cio_req++;
                    }
                }
                else
                {
                    NUVO_ASSERT(cl->in_use == 1);

                    // This write is updating new blocks in the cache line.
                    cl->last_block = cl->last_block + b_count;
                    cl->num_set = cache_vol->num_sets[cache_vol->num_hashes];

                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_write_update_count);
                    cio_req->operation = NUVO_OP_CACHE_WRITE_CACHE;
                    cio_req->parcel_desc = cl_parcel_desc(cache_vol, cl);
                    cio_req->block_offset = cl_block_offset(cache_vol, cl) + first_block;
                    cio_req->block_count = b_count;
                    cio_req->iov_offset = iov_offset;
                    cio_req->par_op = par_op;
                    cio_req->io_req = io_req;
                    cio_req->cache_vol = cache_vol;
                    cio_req->cl = cl;

                    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                    cl->wr_count++;
                    cache_vol->io_pending_count++;
                    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

                    NUVO_LOG(cache, 80, "cache write: update: device io [%lu:%05lu] -> cache [%lu:%lu] write to %lu length %u for iov_start %u. first: %u last: %u. req: %d",
                             io_req->rw.parcel_desc, io_req->rw.block_offset + iov_offset,
                             cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl),
                             cio_req->block_offset, cio_req->block_count, cio_req->iov_offset,
                             cl->first_block, cl->last_block, num_cio_req + 1);

                    // Move to the head of the LRU
                    cache_tb_move_to_head(cache_vol, cl);

                    nuvo_dlist_insert_tail(&local_submit_list, &cio_req->list_node);
                    num_cio_req++;
                }
            }
        }
        else
        {
            NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_count);
            if (cl == NULL)
            {
                NUVO_ASSERT(io_req->operation == NUVO_OP_READ || io_req->operation == NUVO_OP_READ_VERIFY);

                // Cache miss
                if (io_req->rw.cache_hint == NUVO_CACHE_NONE)
                {
                    // Currently reads from non-active LUNs are the only ones with no-cache hint,
                    // and they are also tagged as non-user I/O for use by the stats.
                    NUVO_ASSERT(!is_user);
                    // No caching indicated, change to a read around.
                    cio_req->operation = NUVO_OP_CACHE_READ_AROUND;
                    cio_req->block_offset = io_req->rw.block_offset + iov_offset;
                    cio_req->block_count = b_count;
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_around_count);
                    NUVO_LOG(cache, 80, "read miss. key: [%u:%04u] read will not updated cache. no cache indicated", key.parcel_desc, key.block_offset);
                }
                else if ((cl = cache_cio_cache_line_alloc(cache_vol, key)) == NULL)
                {
                    // Can't get a cache line, just do a read around.
                    cio_req->operation = NUVO_OP_CACHE_READ_AROUND;
                    cio_req->block_offset = io_req->rw.block_offset + iov_offset;
                    cio_req->block_count = b_count;
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_around_count);
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_unavail_read_count);
                    num_skip++;
                    NUVO_LOG(cache, 80, "read miss. key: [%u:%04u] read will not updated cache. no cache line available", key.parcel_desc, key.block_offset);
                }
                else
                {
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_allocated_count);
                    NUVO_ASSERT(cl->in_use == 1);
                    NUVO_ASSERT(cl->block_key == key.block_key);
                    cl->first_block = 0;
                    cl->last_block = NUVO_CACHE_LINE_SIZE_BLOCKS;

                    cio_req->operation = NUVO_OP_CACHE_READ_MISS;
                    cio_req->block_offset = key.block_offset;
                    cio_req->block_count = NUVO_CACHE_LINE_SIZE_BLOCKS; // First read populates the cache line

                    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                    cl->wr_count = 1;
                    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

                    NUVO_LOG(cache, 80, "cache read:   miss: device io [%05lu:%05lu] -> cache [%lu:%lu] length %u. req: %d",
                             cio_req->parcel_desc, cio_req->block_offset,
                             cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), cio_req->block_count, num_cio_req + 1);
                }

                NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_miss_count);
                NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_from_primary_count);
                if (NUVO_IS_GC_DATA(io_req))
                {
                    NUVO_UPDATE_CACHE_GC_STATS(cache_vol, read_miss_block_count, b_count);
                }

                read_from_primary_count++;
                cio_req->verify_flag = (io_req->operation == NUVO_OP_READ_VERIFY) ? true : false;
                cio_req->parcel_desc = key.parcel_desc;
                cio_req->iov_offset = iov_offset;
                cio_req->par_op = par_op;
                cio_req->io_req = io_req;
                cio_req->cache_vol = cache_vol;
                cio_req->cl = cl;

                nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                cache_vol->io_pending_count++;
                nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

                nuvo_dlist_insert_tail(&local_submit_list, &cio_req->list_node);
                num_cio_req++;
            }
            else
            {
                NUVO_ASSERT(cl->in_use == 1);
                nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                if (((first_block >= cl->first_block) && ((first_block + b_count) <= cl->last_block)) &&
                    (cl->wr_count == 0))
                {
                    // Cache hit
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_hit_count);
                    cio_req->operation = NUVO_OP_CACHE_READ_HIT;
                    cio_req->verify_flag = (io_req->operation == NUVO_OP_READ_VERIFY) ? true : false;
                    cio_req->parcel_desc = cl_parcel_desc(cache_vol, cl);
                    cio_req->block_offset = cl_block_offset(cache_vol, cl) + first_block;
                    cio_req->block_count = b_count;
                    cio_req->iov_offset = iov_offset;
                    cio_req->par_op = par_op;
                    cio_req->io_req = io_req;
                    cio_req->cache_vol = cache_vol;
                    cio_req->cl = cl;
                    cl->rd_count++;

                    // Record cache hit for GC read
                    if (NUVO_IS_GC_DATA(io_req))
                    {
                        bool *cache_result = io_req->rw.cache_result + (io_req->rw.block_count - b_remaining);

                        // Get a reference to the gc_batch, for debug/assert use
                        struct nuvo_parallel_io *par_io = io_req->tag.ptr;
                        struct nuvo_gc_batch    *gc_batch = par_io->tag.ptr;
                        NUVO_ASSERT(gc_batch != NULL);

                        for (uint32_t bi = 0; bi < b_count; bi++)
                        {
                            NUVO_ASSERT((uint64_t)cache_result >= (uint64_t)gc_batch->move_data.cached);
                            NUVO_ASSERT((uint64_t)cache_result <= (uint64_t)&gc_batch->move_data.cached[NUVO_GC_DATA_BLOCKS_READ_MAX]);
                            *cache_result = true;
                            cache_result++;
                        }

                        NUVO_UPDATE_CACHE_GC_STATS(cache_vol, read_hit_block_count, b_count);
                    }

                    NUVO_LOG(cache, 80, "   cache read hit:  data for [%05lu:%05lu] <- cache [%lu:%lu] reading from %lu length %u. first: %u last %u req: %d",
                             io_req->rw.parcel_desc, io_req->rw.block_offset + cio_req->iov_offset,
                             cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl),
                             cio_req->block_offset, cio_req->block_count,
                             cl->first_block, cl->last_block, num_cio_req + 1);
                }
                else
                {
                    if (NUVO_IS_GC_DATA(io_req))
                    {
                        NUVO_UPDATE_CACHE_GC_STATS(cache_vol, read_miss_block_count, b_count);
                    }
                    NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_from_primary_count);
                    read_from_primary_count++;

                    // This cache line doesn't have the blocks needed.
                    // The IO will be sent to the primary backing device and then the cache line will be updated when it's completed.
                    // The cache line returned on lookup can only be reused if it's in the correct set and it has no writes pending.
                    if (cl->num_set != cache_vol->num_sets[cache_vol->num_hashes])
                    {
                        cache_tb_invalidate(cache_vol, cl);
                        nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
                        cl = cache_cio_cache_line_alloc(cache_vol, key);
                        if (cl == NULL)
                        {
                            // Can't get a cache line
                            NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cl_unavail_write_count);
                            NUVO_LOG(cache, 80, "cache line read miss. key: [%u:%04u] read will not update cache. no cache line available", key.parcel_desc, key.block_offset);
                        }
                        nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
                    }

                    if (cl == NULL || cl->wr_count > 0)
                    {
                        // There's either no cache line available, or a write is updating the cache line.
                        // Read from disk, but set operation to read-around so the cache isn't updated on completion.
                        // TODO: only trigger this case when reads and writes overlap.
                        NUVO_LOG(cache, 80, "cache line read while updating: [%04lu:%04lu]. first: %u last: %u  wanted %u len %u. rd_count: %u wr_count: %u",
                                 cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), cl->first_block, cl->last_block, first_block, b_count,
                                 cl->rd_count, cl->wr_count);

                        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_around_count);
                        cio_req->operation = NUVO_OP_CACHE_READ_AROUND;
                        cio_req->verify_flag = (io_req->operation == NUVO_OP_READ_VERIFY) ? true : false;
                        cio_req->parcel_desc = key.parcel_desc;
                        cio_req->block_offset = io_req->rw.block_offset + iov_offset;;
                        cio_req->block_count = b_count;
                        cio_req->iov_offset = iov_offset;
                        cio_req->par_op = par_op;
                        cio_req->io_req = io_req;
                        cio_req->cache_vol = cache_vol;
                        cio_req->cl = cl;

                        NUVO_LOG(cache, 80, "cache read around:  data for [%05lu:%05lu] length %u from primary. req: %d\n",
                                 cio_req->parcel_desc, cio_req->block_offset, cio_req->block_count, num_cio_req + 1);
                    }
                    else
                    {
                        // Got a read request but the cache line didn't have the block
                        // Read in the entire cache line

                        // if the num_set != cache_vol->num_sets then the cache line needs to be invalidated.
                        // the cache will read data from its existing set location, but will only write new
                        // data to the current set.
                        NUVO_LOG(cache, 80, "cache line read miss: [%04lu:%04lu]. first: %u last: %u  wanted %u len %u. rd_count: %u wr_count: %u",
                                 cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), cl->first_block, cl->last_block, first_block, b_count,
                                 cl->rd_count, cl->wr_count);

                        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, cio_read_miss_count);
                        cio_req->operation = NUVO_OP_CACHE_READ_MISS;
                        cio_req->verify_flag = (io_req->operation == NUVO_OP_READ_VERIFY) ? true : false;
                        cio_req->parcel_desc = key.parcel_desc;
                        cio_req->block_offset = key.block_offset;
                        cio_req->block_count = NUVO_CACHE_LINE_SIZE_BLOCKS;
                        cio_req->iov_offset = iov_offset;
                        cio_req->par_op = par_op;
                        cio_req->io_req = io_req;
                        cio_req->cache_vol = cache_vol;
                        cio_req->cl = cl;

                        cl->first_block = 0;
                        cl->last_block = NUVO_CACHE_LINE_SIZE_BLOCKS;
                        cl->wr_count++;

                        NUVO_LOG(cache, 80, "cache line read miss: device io [%05lu:%05lu] -> cache [%lu:%lu] length %u req: %d iov_offset: %u",
                                 cio_req->parcel_desc, cio_req->block_offset,
                                 cl_parcel_desc(cache_vol, cl), cl_block_offset(cache_vol, cl), cio_req->block_count, num_cio_req + 1, iov_offset);
                    }
                }
                cache_vol->io_pending_count++;
                nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

                // Move this cache line to the head of the LRU
                cache_tb_move_to_head(cache_vol, cl);

                nuvo_dlist_insert_tail(&local_submit_list, &cio_req->list_node);
                num_cio_req++;
            }
        }

        iov_offset += b_count;
        b_offset = b_offset + (NUVO_CACHE_LINE_SIZE_BLOCKS - (b_offset - cb_offset));
        b_remaining -= b_count;
    }

    if (io_req->operation != NUVO_OP_WRITE && read_from_primary_count != 0)
    {
        NUVO_UPDATE_CACHE_STATS(cache_vol, is_user, ioreq_read_with_miss_count);
    }

    // Submit the cio_request
    for (int i = 0; i < num_cio_req; i++)
    {
        struct cio_request       *cio_req = nuvo_dlist_remove_head_object(&local_submit_list, struct cio_request, list_node);
        struct nuvo_pr_req_alloc *req_alloc = &cio_req->req_alloc;
        NUVO_ASSERT(cio_req != NULL);

        cio_req->par_io_count = num_cio_req;
        nuvo_dlnode_init(&req_alloc->list_node);
        req_alloc->tag.ptr = cio_req;
        req_alloc->callback = cache_cio_buf_alloc_cb;
        nuvo_pr_client_req_alloc_cb(req_alloc);
    }
    NUVO_LOG(cache, 80, "Number of requests submitted: %d, skipped: %d", num_cio_req, num_skip);

    nuvo_mutex_unlock(&cache.mutex);
    return (0);
}

/**
 *
 * \brief Frees capacity previously allocated to a volume
 *
 * Removes the given number of cache lines from the cache.
 * The minimum number of cl that may be removed is cache_tb_get_alloc_unit_size().
 * When the cache is reduced in size, the assigned fragments are returned to the free list.
 * Fragments returned that are contiguous with fragments on the free list are merged.
 *
 * \param cache_vol A pointer to the cache tracking struct for the volume.
 * \param remove_cl The number of cache lines to remove from the cache.
 * \return None.
 */
nuvo_return_t cache_capacity_free(struct nuvo_cache_vol *cache_vol, uint32_t remove_cl)
{
    NUVO_ASSERT(cache_vol != NULL);
    struct nuvo_vol            *vol = nuvo_containing_object(cache_vol, struct nuvo_vol, log_volume.cache_vol);
    struct nuvo_cache_fragment *cache_fragment;
    struct nuvo_cache_fragment *freelist_fragment;

    NUVO_ASSERT_MUTEX_HELD(&cache.mutex);
    NUVO_ASSERT(remove_cl <= cache_vol->num_cl);
    NUVO_ASSERT(remove_cl >= cache_size_bytes_to_cl(cache_tb_get_alloc_unit_size()));

    // The cache lines represented in the set associative cache table maps 1:1 to the
    // cache capacity represented by the cache fragments. Because the cache
    // table is truncated on shrink the cache capacity must be freed in the reverse
    // order that it was added. The fragments allocated to the volume can be in any order
    //
    // for each fragment being freed find it's insertion point on the free list.
    // fragments returned to the free list are consolidated with adjacent fragments.

    // It's possible when shrinking the cache that the fragment currently allocated
    // needs to be reduced in size and the remainder put back on the freelist as a
    // new fragment. This requires allocating memory for a new fragment. This is
    // done provisionally up front to avoid having to deal with an aborted resize
    // after previous fragments have already been returned to the freelist.
    struct nuvo_cache_fragment *new_fragment;
    if ((new_fragment = malloc(sizeof(struct nuvo_cache_fragment))) == NULL)
    {
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Failed to allocate new cache fragment", NUVO_LOG_UUID(vol->vs_uuid));
        return (-NUVO_ENOMEM);
    }
    nuvo_dlnode_init(&new_fragment->list_node);

    uint32_t orig_cl = cache_vol->num_cl;
    uint32_t remaining_cl = remove_cl;

    while (remaining_cl != 0)
    {
        cache_fragment = nuvo_dlist_get_tail_object(&cache_vol->fragments, struct nuvo_cache_fragment, list_node);

        // Check if only part of the fragment needs to be freed.
        if ((int32_t)(remaining_cl - cache_fragment->size_cl) < 0)
        {
            // Split this fragment, and put the remainder on the free list
            NUVO_LOG(cache, 10, "Vol: "NUVO_LOG_UUID_FMT ". split fragment: %u size: %u to new size: %u\n",
                     NUVO_LOG_UUID(vol->vs_uuid),
                     cache_fragment->block_offset, cache_fragment->size_cl, cache_fragment->size_cl - remaining_cl);
            new_fragment->size_cl = remaining_cl;
            cache_fragment->size_cl = cache_fragment->size_cl - new_fragment->size_cl;
            new_fragment->block_offset = cache_fragment->block_offset + cache_size_cl_to_blocks_per_device(cache_fragment->size_cl);
            remaining_cl = 0;
            cache_fragment = new_fragment;
            new_fragment = NULL;
            NUVO_LOG(cache, 10, "Vol: "NUVO_LOG_UUID_FMT ". freeing fragment: %u size: %u\n",
                     NUVO_LOG_UUID(vol->vs_uuid),
                     cache_fragment->block_offset, cache_fragment->size_cl);
        }
        else
        {
            // The entire fragment is being freed.
            nuvo_dlist_remove(&cache_fragment->list_node);
            cache_vol->num_fragments--;
            remaining_cl -= cache_fragment->size_cl;
        }
        cache_vol->num_cl -= cache_fragment->size_cl;

        // Find where to insert or merge cache_fragment back on the free list.
        freelist_fragment = nuvo_dlist_get_head_object(&cache.free_fragments, struct nuvo_cache_fragment, list_node);
        while (cache_fragment != NULL)
        {
            if (!freelist_fragment)
            {
                // The fragment is either being inserted on the free list either as the first or the last fragment.
                nuvo_dlist_insert_tail(&cache.free_fragments, &cache_fragment->list_node);
                cache.num_fragments++;
                cache.cache_avail_cl_count += cache_fragment->size_cl;
                cache_fragment = NULL;
            }
            else if (cache_fragment->block_offset + cache_size_cl_to_blocks_per_device(cache_fragment->size_cl) == freelist_fragment->block_offset)
            {
                // The end of the fragment being freed is contiguous with the start of the freelist fragment
                // Adjust the size and offset of the freelist fragment to include the fragment being freed.
                freelist_fragment->size_cl += cache_fragment->size_cl;
                freelist_fragment->block_offset = cache_fragment->block_offset;
                cache.cache_avail_cl_count += cache_fragment->size_cl;
                free(cache_fragment);
                cache_fragment = NULL;
            }
            else if (freelist_fragment->block_offset + cache_size_cl_to_blocks_per_device(freelist_fragment->size_cl) == cache_fragment->block_offset)
            {
                // The end of the freelist fragment is contiguous with the start of the fragment that's being freed.
                // Adjust the size of the freelist fragment to include the fragment being freed.
                freelist_fragment->size_cl += cache_fragment->size_cl;
                cache.cache_avail_cl_count += cache_fragment->size_cl;
                free(cache_fragment);
                cache_fragment = NULL;

                // Check if this fragment filled a gap between two fragments on the free list.
                // If the new end of freelist fragment is now contiguous with the start of the next fragment and consolidate
                struct nuvo_cache_fragment *next_fragment = nuvo_dlist_get_next_object(&cache.free_fragments, freelist_fragment, struct nuvo_cache_fragment, list_node);
                if (next_fragment && (freelist_fragment->block_offset + cache_size_cl_to_blocks_per_device(freelist_fragment->size_cl) == next_fragment->block_offset))
                {
                    freelist_fragment->size_cl += next_fragment->size_cl;
                    nuvo_dlist_remove(&next_fragment->list_node);
                    cache.num_fragments--;
                    free(next_fragment);
                }
            }
            else if (cache_fragment->block_offset < freelist_fragment->block_offset)
            {
                // The fragment being freed couldn't be consolidated with an existing fragment.
                nuvo_dlist_insert_before(&freelist_fragment->list_node, &cache_fragment->list_node);
                cache.num_fragments++;
                cache.cache_avail_cl_count += cache_fragment->size_cl;
                cache_fragment = NULL;
            }
            else
            {
                // Get the next fragment on the free list.
                freelist_fragment = nuvo_dlist_get_next_object(&cache.free_fragments, freelist_fragment, struct nuvo_cache_fragment, list_node);
            }
        }
    }

    if (new_fragment)
    {
        free(new_fragment);
    }

    if (cache_vol->num_cl != orig_cl - remove_cl)
    {
        NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". Unable to free cache. Tried to free %u of %u cache lines. Remaining cache lines: %u",
                   NUVO_LOG_UUID(vol->vs_uuid), remove_cl, orig_cl, cache_vol->num_cl);
    }
    else if (orig_cl - remove_cl == 0)
    {
        NUVO_ASSERT(cache_vol->num_cl == 0);
        NUVO_ASSERT(cache_vol->num_fragments == 0);
        NUVO_ASSERT(nuvo_dlist_get_head_object(&cache_vol->fragments, struct nuvo_cache_fragment, list_node) == NULL);
    }

    return (0);
}

/**
 *
 * \brief Allocates cache capacity to a volume
 *
 * A fragment is contiguous region of cache capacity, stored a starting offset and length.
 * A cache allocation is made up of one or more fragments. After all devices are added, the cache
 * has a single fragment representing the full cache capacity. As volumes are allocated cache
 * they are assigned a new fragment representing the region of cache dedicated to the volume.
 *
 * When volumes are closed the assigned fragment is returned to the free list. Contiguous fragments
 * returned to the free list are merged. The cache may become fragmented when a volume is closed and
 * the fragment freed is not contiguous with any fragments on the current free list.
 *
 * \param cache_vol A pointer to the cache tracking struct for the volume.
 * \param num_cl The number cache lines to allocate.
 * \return 0 if successful, otherwise NUVO_ENOMEM.
 */
nuvo_return_t cache_capacity_alloc(struct nuvo_cache_vol *cache_vol, uint32_t num_cl)
{
    NUVO_ASSERT(cache_vol != NULL);
    struct nuvo_vol *vol = nuvo_containing_object(cache_vol, struct nuvo_vol, log_volume.cache_vol);
    NUVO_ASSERT_MUTEX_HELD(&cache.mutex);
    NUVO_ASSERT(cache.cache_avail_cl_count + cache_vol->num_cl >= num_cl);

    if (cache_vol->num_cl == 0)
    {
        NUVO_ASSERT(nuvo_dlist_get_head_object(&cache_vol->fragments, struct nuvo_cache_fragment, list_node) == NULL);
        NUVO_ASSERT(cache_vol->num_fragments == 0);
    }

    struct nuvo_cache_fragment *new_fragment;
    if ((new_fragment = malloc(sizeof(struct nuvo_cache_fragment))) == NULL)
    {
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Failed to allocate new cache fragment.", NUVO_LOG_UUID(vol->vs_uuid));
        return (-NUVO_ENOMEM);
    }
    nuvo_dlnode_init(&new_fragment->list_node);

    NUVO_LOG(cache, 10, "Vol: "NUVO_LOG_UUID_FMT ". allocating cache. num_cl: %lu", NUVO_LOG_UUID(vol->vs_uuid), num_cl);
    uint32_t remaining_cl = num_cl - cache_vol->num_cl;
    while (remaining_cl)
    {
        struct nuvo_cache_fragment *freelist_fragment = nuvo_dlist_remove_head_object(&cache.free_fragments, struct nuvo_cache_fragment, list_node);
        if (!freelist_fragment)
        {
            // Capacity allocation accounting must be wrong.
            NUVO_PANIC("Vol: "NUVO_LOG_UUID_FMT ". Unable to allocate cache. Available cl: %u requested: %u remaining needed: %u",
                       NUVO_LOG_UUID(vol->vs_uuid), cache.cache_avail_cl_count, num_cl, remaining_cl);
        }
        if (remaining_cl >= freelist_fragment->size_cl)
        {
            // Allocate the entire fragment
            remaining_cl -= freelist_fragment->size_cl;
            cache_vol->num_cl += freelist_fragment->size_cl;
            cache.cache_avail_cl_count -= freelist_fragment->size_cl;
            cache.num_fragments--;
        }
        else
        {
            // Split this fragment, and allocate the portion needed to the cache.
            new_fragment->size_cl = freelist_fragment->size_cl - remaining_cl;
            new_fragment->block_offset = freelist_fragment->block_offset + cache_size_cl_to_blocks_per_device(remaining_cl);
            nuvo_dlist_insert_head(&cache.free_fragments, &new_fragment->list_node);
            freelist_fragment->size_cl = remaining_cl;
            cache_vol->num_cl += freelist_fragment->size_cl;
            cache.cache_avail_cl_count -= freelist_fragment->size_cl;
            remaining_cl = 0;
            new_fragment = NULL;
            NUVO_ASSERT(cache_vol->num_cl = num_cl);
        }
        nuvo_dlist_insert_tail(&cache_vol->fragments, &freelist_fragment->list_node);
        NUVO_LOG(cache, 10, "Vol: "NUVO_LOG_UUID_FMT ". allocated cache fragment. starting offset: %lu ending at offset: %lu. size_cl: %lu",
                 NUVO_LOG_UUID(vol->vs_uuid),
                 freelist_fragment->block_offset,
                 freelist_fragment->block_offset + (freelist_fragment->size_cl * NUVO_CACHE_LINE_SIZE_BLOCKS),
                 freelist_fragment->size_cl);
        cache_vol->num_fragments++;
    }
    NUVO_ASSERT(cache_vol->num_fragments > 0);
    NUVO_ASSERT(nuvo_dlist_get_head_object(&cache_vol->fragments, struct nuvo_cache_fragment, list_node) != NULL);

    if (new_fragment)
    {
        free(new_fragment);
    }
    return (0);
}

/**
 * \brief Allocate memory for the set-associative cache
 *
 * Changes the size of the memory pointed to by cache_vol->tb to the specified
 * number of 16 byte cache line entries.
 *
 * If the new size is larger than the old size, the added memory will be also be initialized.
 *
 * \param cache_vol A pointer to the cache tracking struct for the volume.
 * \param num_cl Size of the cache allocation in bytes
 * \return 0 if successful, otherwise error.
 */
nuvo_return_t cache_vol_tb_realloc(struct nuvo_cache_vol *cache_vol, uint64_t num_cl)
{
    NUVO_ASSERT(cache_vol != NULL);
    NUVO_ASSERT(num_cl != 0);
    struct nuvo_vol *vol = nuvo_containing_object(cache_vol, struct nuvo_vol, log_volume.cache_vol);

    nuvo_return_t           ret = 0;
    struct nuvo_cache_line *tbp;
    uint32_t old_tb_size = cache_vol->tb_size;
    uint32_t old_num_cl = cache_vol->tb_size / sizeof(struct nuvo_cache_line);
    uint32_t new_tb_size = num_cl * sizeof(struct nuvo_cache_line);

    if ((tbp = (struct nuvo_cache_line *)realloc(cache_vol->tb, new_tb_size)) == NULL)
    {
        // No memory for the table.
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Error initializing %lu byte %u-way mapping table for a %lu byte cache.",
                         NUVO_LOG_UUID(vol->vs_uuid),
                         new_tb_size, cache_tb_num_ways());
        ret = -NUVO_ENOMEM;
    }
    else
    {
        cache_vol->tb = tbp;
        cache_vol->tb_size = new_tb_size;
        if (old_tb_size < cache_vol->tb_size)
        {
            memset(cache_vol->tb + old_num_cl, 0, cache_vol->tb_size - old_tb_size);
        }
        NUVO_LOG(cache, 0, "Vol: "NUVO_LOG_UUID_FMT ". Resized cache table from %lu to %lu bytes",
                 NUVO_LOG_UUID(vol->vs_uuid),
                 old_tb_size, cache_vol->tb_size);
    }
    return (ret);
}

/**
 * \brief Create the cache for a volume
 *
 * Creates the set associative cache mapping table and allocates space
 * from the available cache devices.
 *
 * The first successful call to cache_vol_alloc() changes the cache state to
 * NUVO_CACHE_STATE_IN_USE. Once in this state cache devices may no longer
 * be added to the pool of cache devices.
 *
 * \param cache_vol A pointer to the cache tracking struct for the volume.
 * \param size_bytes Size of the cache allocation in bytes
 * \return 0 if successful, otherwise error.
 */
nuvo_return_t cache_vol_alloc(struct nuvo_cache_vol *cache_vol, uint64_t size_bytes)
{
    NUVO_ASSERT(cache_vol != NULL);
    struct nuvo_vol *vol = nuvo_containing_object(cache_vol, struct nuvo_vol, log_volume.cache_vol);
    nuvo_return_t    ret = 0;
    uint32_t         old_tb_size = cache_vol->tb_size;
    uint32_t         num_cl = cache_size_bytes_to_cl(size_bytes);


    nuvo_mutex_lock(&cache.mutex);

    NUVO_ASSERT(cache_vol != NULL);
    NUVO_ASSERT(cache_vol->tb_size ? cache_vol->is_enabled : !cache_vol->is_enabled);
    NUVO_ASSERT(cache_vol->tb_size != num_cl * sizeof(struct nuvo_cache_line));

    if (size_bytes % cache_tb_get_alloc_unit_size())
    {
        // Invalid cache allocation size provided.
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Invalid cache allocation size %lu bytes. Allocation size must a multiple of %lu bytes",
                         NUVO_LOG_UUID(vol->vs_uuid),
                         size_bytes, cache_tb_get_alloc_unit_size());
        ret = -NUVO_EINVAL;
    }
    else if (cache_vol->num_cl > num_cl)
    {
        // Shrink
        if ((ret = cache_vol_tb_realloc(cache_vol, num_cl)) >= 0)
        {
            uint32_t num_rm_cl = cache_vol->num_cl - num_cl;
            cache_capacity_free(cache_vol, num_rm_cl);
        }
    }
    else
    {
        // Grow
        if (num_cl > cache_vol->num_cl + cache.cache_avail_cl_count)
        {
            // Invalid cache allocation size provided.
            NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Invalid cache allocation size %lu bytes. Only %lu bytes free",
                             NUVO_LOG_UUID(vol->vs_uuid),
                             size_bytes, cache_size_cl_to_bytes(cache.cache_avail_cl_count));
            ret = -NUVO_EINVAL;
        }
        else if ((ret = cache_vol_tb_realloc(cache_vol, num_cl)) >= 0)
        {
            if ((ret = cache_capacity_alloc(cache_vol, num_cl)) != 0)
            {
                NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Unable to allocate additional cache capacity: %d", NUVO_LOG_UUID(vol->vs_uuid));
                ret = -NUVO_ENOSPC;
            }
        }
    }

    if (!ret)
    {
        if (old_tb_size == 0)
        {
            cache_vol->num_ways = cache_tb_num_ways();
            cache_vol->num_hashes = 0;
            cache_vol->num_sets[cache_vol->num_hashes] = num_cl / cache_vol->num_ways;
            cache_vol->is_enabled = true;

            // Set the global cache state to NUVO_CACHE_STATE_IN_USE, this prevents new cache devices from being added.
            cache.cache_state = NUVO_CACHE_STATE_IN_USE;
        }
        else
        {
            uint32_t new_num_sets = num_cl / cache_vol->num_ways;
            uint8_t  num_hashes = 0;
            // The num_sets array has the previous NUVO_CACHE_MAX_HASHES set sizes.
            // 1. If the cache is being resized back to a previous size, shift the array forward into the position of the
            //    previous matching size and add new size at end of array.
            // 2. If setting a new size and there are less than NUVO_CACHE_MAX_HASHES entries, add new size to end of array.
            // 3. If there are already NUVO_CACHE_MAX_HASHES entries, remove oldest by shifting entire array forward,
            //    and add new size to end of array.
            while (num_hashes < cache_vol->num_hashes)
            {
                if (cache_vol->num_sets[num_hashes] == new_num_sets)
                {
                    while (num_hashes < cache_vol->num_hashes)
                    {
                        cache_vol->num_sets[num_hashes] = cache_vol->num_sets[num_hashes + 1];
                        num_hashes++;
                    }
                    cache_vol->num_sets[num_hashes] = new_num_sets;
                    break;
                }
                num_hashes++;
            }

            if (cache_vol->num_sets[cache_vol->num_hashes] != new_num_sets)
            {
                if (cache_vol->num_hashes != NUVO_CACHE_MAX_HASHES - 1)
                {
                    // haven't reached NUVO_CACHE_MAX_HASHES
                    cache_vol->num_hashes++;
                    cache_vol->num_sets[cache_vol->num_hashes] = new_num_sets;
                }
                else
                {
                    // drop the oldest entry.
                    num_hashes = 0;
                    while (num_hashes < cache_vol->num_hashes)
                    {
                        cache_vol->num_sets[num_hashes] = cache_vol->num_sets[num_hashes + 1];
                        num_hashes++;
                    }
                    cache_vol->num_sets[num_hashes] = new_num_sets;
                }
            }
        }
        NUVO_LOG(cache, 0, "Vol: "NUVO_LOG_UUID_FMT ". Initialized %lu byte %u * %u-way mapping table for a %lu byte cache.",
                 NUVO_LOG_UUID(vol->vs_uuid),
                 cache_vol->tb_size, cache_vol->num_sets[cache_vol->num_hashes], cache_vol->num_ways, size_bytes);
    }
    nuvo_mutex_unlock(&cache.mutex);
    return (ret);
}

/**
 * \brief Deallocate the cache for the given volume
 *
 * Holds the global cache mutex while re-configuring
 * 1. Stop sending new IO to the cache.
 * 2. Wait for all outstanding IO to the cache to complete.
 * 3. Free the cache resources.
 *
 * \param cache_vol A pointer to the cache tracking struct for the volume.
 * \return None
 */
void cache_vol_free(struct nuvo_cache_vol *cache_vol)
{
    NUVO_ASSERT(cache_vol != NULL);
    struct nuvo_vol *vol = nuvo_containing_object(cache_vol, struct nuvo_vol, log_volume.cache_vol);

    nuvo_mutex_lock(&cache.mutex);
    if (!cache_vol->is_enabled)
    {
        nuvo_mutex_unlock(&cache.mutex);
        return;
    }
    cache_vol->is_enabled = false;

    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
    nuvo_mutex_unlock(&cache.mutex);

    // Let any outstanding IO to the volumes cache complete.
    while (cache_vol->io_pending_count != 0)
    {
        nuvo_cond_wait(&cache_vol->io_pending_count_zero_cond, &cache_vol->io_pending_count_mutex);
    }
    nuvo_mutex_lock(&cache.mutex);
    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);

    // Free the mapping table.
    free(cache_vol->tb);

    // Free the on disk cache capacity.
    cache_capacity_free(cache_vol, cache_vol->num_cl);
    nuvo_mutex_unlock(&cache.mutex);

    NUVO_LOG(cache, 0, "Vol: "NUVO_LOG_UUID_FMT ". Disabled cache and released allocation.", NUVO_LOG_UUID(vol->vs_uuid));
}

/*
 * Documented in header
 */
nuvo_return_t nuvo_cache_vol_allocate(struct nuvo_vol *vol, uint64_t size_bytes)
{
    NUVO_ASSERT(vol != NULL);
    nuvo_return_t          ret;
    struct nuvo_cache_vol *cache_vol = &vol->log_volume.cache_vol;
    uint64_t prev_size_bytes = cache_size_cl_to_bytes(cache_vol->num_cl);

    if (prev_size_bytes == size_bytes)
    {
        // Idempotent
        ret = 0;
    }
    else if (size_bytes == 0)
    {
        // Free the current allocation
        cache_vol_free(cache_vol);
        ret = 0;
    }
    else
    {
        ret = cache_vol_alloc(cache_vol, size_bytes);
    }

    if (ret == 0)
    {
        NUVO_LOG(cache, 0, "Vol: "NUVO_LOG_UUID_FMT ". Changed cache allocation from %lu to %lu bytes.", NUVO_LOG_UUID(vol->vs_uuid), prev_size_bytes, size_bytes);
    }
    return (ret);
}

/*
 * Documented in header
 */
nuvo_return_t nuvo_cache_vol_init(struct nuvo_vol *vol)
{
    NUVO_ASSERT(vol != NULL);
    nuvo_return_t          ret;
    struct nuvo_cache_vol *cache_vol = &vol->log_volume.cache_vol;

    memset(cache_vol, 0, sizeof(struct nuvo_cache_vol));

    if ((ret = nuvo_mutex_init(&cache_vol->io_pending_count_mutex)) != 0)
    {
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Error initializing mutex.", NUVO_LOG_UUID(vol->vs_uuid));
        goto err_out;
    }
    if ((ret = nuvo_cond_init(&cache_vol->io_pending_count_zero_cond)) != 0)
    {
        NUVO_ERROR_PRINT("Vol: "NUVO_LOG_UUID_FMT ". Error initializing condition.", NUVO_LOG_UUID(vol->vs_uuid));
        goto err_out_1;
    }

    nuvo_dlist_init(&cache_vol->fragments);
    return (0);

err_out_1:
    nuvo_mutex_destroy(&cache_vol->io_pending_count_mutex);
err_out:
    return (ret);
}

/*
 * \brief Debug routine for printing cache statistics
 *
 * \param vol_uuid The volume uuid.
 * \param nuvo_cache_stats A pointer to the cache statistics tracking struct.
 * \return None
 */
void nuvo_cache_print_stats_debug(uuid_t vol_uuid, struct nuvo_cache_stats *stats)
{
    NUVO_LOG(cache, 0, "Vol: "NUVO_LOG_UUID_FMT ". Cache stats. orig_r: %8lu orig_w: %8lu orig_rm: %8lu r: %8lu w: %8lu rp: %8lu rh: %8lu rm: %8lu ra: %8lu rmnu: %8lu wn: %8lu we: %8lu wu: %8lu ur: %8lu uw: %8lu alloc: %8lu",
             NUVO_LOG_UUID(vol_uuid), stats->ioreq_read_count, stats->ioreq_write_count, stats->ioreq_read_with_miss_count,
             stats->cio_read_count, stats->cio_write_count, stats->cio_read_from_primary_count,
             stats->cio_read_hit_count, stats->cio_read_miss_count, stats->cio_read_around_count, stats->cio_read_miss_no_update_count,
             stats->cio_write_new_count, stats->cio_write_evict_count, stats->cio_write_update_count,
             stats->cl_unavail_read_count, stats->cl_unavail_write_count,
             stats->cl_allocated_count)
}

/*
 * \brief Debug routine for printing cache statistics related to GC data move
 *
 * \param vol_uuid The volume uuid.
 * \param nuvo_cache_stats A pointer to the cache gc statistics tracking struct.
 * \return None
 */
void nuvo_cache_print_gc_stats_debug(uuid_t vol_uuid, struct nuvo_cache_gc_stats *stats)
{
    NUVO_LOG(cache, 0, "Vol: "NUVO_LOG_UUID_FMT ". Cache GC stats. gc_r: %8lu gc_rh: %8lu gc_rm: %8lu gc_w: %8lu gc_wc: %8lu gc_wn: %8lu",
             NUVO_LOG_UUID(vol_uuid), stats->read_block_count, stats->read_hit_block_count, stats->read_miss_block_count,
             stats->write_block_count, stats->write_cache_block_count, stats->write_no_cache_block_count);
}

/*
 * Documented in header
 */
void nuvo_cache_vol_destroy(struct nuvo_vol *vol)
{
    struct nuvo_cache_vol *cache_vol = &vol->log_volume.cache_vol;

    nuvo_cache_print_stats_debug(vol->vs_uuid, &cache_vol->io_stats);
    nuvo_cache_print_stats_debug(vol->vs_uuid, &cache_vol->user_io_stats);
    nuvo_cache_print_gc_stats_debug(vol->vs_uuid, &cache_vol->gc_io_stats);
    cache_vol_free(cache_vol);
    nuvo_cond_destroy(&cache_vol->io_pending_count_zero_cond);
    nuvo_mutex_destroy(&cache_vol->io_pending_count_mutex);
}

/*
 * Documented in header
 */
void nuvo_cache_stats_snap(struct nuvo_cache_vol   *cache_vol,
                           struct nuvo_cache_stats *data,
                           struct nuvo_cache_stats *metadata,
                           bool                     clear)
{
    struct nuvo_cache_stats all_data;

    memset(data, 0, sizeof(*data));
    memset(metadata, 0, sizeof(*metadata));

    nuvo_mutex_lock(&cache_vol->io_pending_count_mutex);
    if (cache_vol->is_enabled)
    {
        memcpy(data, &cache_vol->user_io_stats, sizeof(cache_vol->user_io_stats));
        memcpy(&all_data, &cache_vol->io_stats, sizeof(all_data));

        metadata->cio_read_hit_count = all_data.cio_read_hit_count - data->cio_read_hit_count;
        metadata->cio_read_miss_count = all_data.cio_read_miss_count - data->cio_read_miss_count;
        metadata->cio_read_around_count = all_data.cio_read_around_count - data->cio_read_around_count;
        metadata->cio_read_miss_no_update_count = all_data.cio_read_miss_no_update_count - data->cio_read_miss_no_update_count;
        metadata->cio_write_new_count = all_data.cio_write_new_count - data->cio_write_new_count;
        metadata->cio_write_evict_count = all_data.cio_write_evict_count - data->cio_write_evict_count;
        metadata->cio_write_update_count = all_data.cio_write_update_count - data->cio_write_update_count;
        metadata->ioreq_read_count = all_data.ioreq_read_count - data->ioreq_read_count;
        metadata->ioreq_write_count = all_data.ioreq_write_count - data->ioreq_write_count;
        metadata->cl_allocated_count = all_data.cl_allocated_count - data->cl_allocated_count;
        metadata->cl_unavail_read_count = all_data.cl_unavail_read_count - data->cl_unavail_read_count;
        metadata->cl_unavail_write_count = all_data.cl_unavail_write_count - data->cl_unavail_write_count;
    }
    if (clear)
    {
        memset(&cache_vol->user_io_stats, 0, sizeof(cache_vol->user_io_stats));
        memset(&cache_vol->io_stats, 0, sizeof(cache_vol->io_stats));
    }
    nuvo_mutex_unlock(&cache_vol->io_pending_count_mutex);
}
