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

#include "nuvo_pr_sync.h"
#include "manifest.h"
#include "nuvo_vol_series.h"
#include "nuvo_range_lock.h"
#include "map_priv.h"
#include "nuvo_pr.h"
#include "lun.h"
#include "map_diff.h"
#include "device_type.h"

#include <stdlib.h>


// add the map entry to the req if possible
//   ENOMEM if request has no memory to hold the entry
//  0 if the entry got coalesced
//  1 if a new entry was added

nuvo_return_t map_de_add(struct nuvo_map_diff_request *req, uint64_t start_offset, uint64_t len)
{
    struct map_de *map_de = &req->map_de_batch[req->batch_size];

    if (req->batch_size && ((map_de - 1)->start_offset + len == start_offset))
    {
        (map_de - 1)->length += len;
        return (0);
    }

    if (req->batch_size == MAP_DIFF_ENTRY_THRESHOLD)
    {
        return (-NUVO_ENOMEM);
    }

    req->batch_size++;
    map_de->start_offset = start_offset;
    map_de->length = len;
    map_de++;
    return (1);
}

void map_diff_request_init(struct nuvo_map_diff_request *mdr, struct nuvo_vol *vol, struct map_de *map_de_array)
{
    mdr->vol = vol;
    mdr->batch_size = 0;
    mdr->status = 0;
    mdr->fault_in_cnt = 0;
    // we only go down upto level 1 for diff, this gives us 1MB grandulaity diffs
    //TODO dont use the magic number 1
    mdr->target_level = 1;

    mdr->map_de_batch = map_de_array;
    memset(mdr->map_de_batch, 0, sizeof(struct map_de));

    nuvo_dlist_init(&mdr->map_list);

    nuvo_return_t ret = nuvo_mutex_init(&mdr->fault_in_mutex);
    NUVO_ASSERT(!(ret < 0));
    nuvo_cond_init(&mdr->fault_in_done_cond);

    mdr->init_state = true;
}

// map_right is unused as we are only using the left map
// as we support adjacent luns only
// caller must lock the map
// Assumptions:
// --only adjacent luns
// --only the oldest pit is deleted
nuvo_return_t map_diff(struct nuvo_map_diff_request *mdr, struct nuvo_map_track *map, struct nuvo_map_track *map_right,
                       uint64_t offset_begin, uint64_t *offset_end)
{
    uint32_t      cnt_entries = 0;
    nuvo_return_t ret = 0;
    int           fault_in_cnt = 0;

    NUVO_ASSERT_MUTEX_HELD(&map->mutex);

    if (map_right)
    {
        NUVO_ASSERT_MUTEX_HELD(&map_right->mutex);
    }


    NUVO_ASSERT(offset_begin >= map->base_offset);

    uint_fast32_t begin_index = nuvo_map_get_table_index(offset_begin, map->level);

    NUVO_ASSERT(begin_index <= NUVO_MAP_RADIX);


    for (uint_fast32_t i = begin_index; i < NUVO_MAP_RADIX; i++)
    {
        enum nuvo_map_entry_type type = map->entries[i].type;
        nuvo_map_entry_snap_type cow = map->entries[i].cow;
        uint64_t block_start = nuvo_map_get_block_at_index(map->base_offset, i, map->level);

        /* Skip the clean ones, gotta love those! */
        /* ondisk shared are clean */
        if ((type != NUVO_ME_IN_MEM) && (cow == NUVO_MAP_ENTRY_SHARED))
        {
            continue;
        }
        else
        {
            if (map->level == mdr->target_level)
            {
                // condition for diff
                // if in mem inmem child L0 must be COW
                // or ondisk COW
                if ((type != NUVO_ME_IN_MEM) || (NUVO_MAP_IS_COW(map->entries[i].ptr)))
                {
                    uint64_t block_len = (1ull << (NUVO_MAP_RADIX_BITS * map->level));
                    ret = map_de_add(mdr, block_start, block_len);

                    if (ret == -NUVO_ENOMEM)
                    {
                        break;
                    }

                    cnt_entries += ret;
                    *offset_end = block_start + block_len - 1;
                }
                continue;
            }
            if (type == NUVO_ME_IN_MEM)
            {
                mdr->map = (struct nuvo_map_track *)map->entries[i].ptr;
                nuvo_mutex_lock(&mdr->map->mutex);
                nuvo_map_pin_table(mdr->map);
            }
            else
            {
                NUVO_ASSERT(map->level > mdr->target_level);
                // no multi fault in at the moment primarily because multi fault in
                // needs then maps to be sorted before you call diff on them
                // since you want them to be sorted.
                int fault_in_max_cnt = 1;

                //TODO optional -> write an optimized lockless version of fault in

                nuvo_map_request_init(&mdr->map_req, map->lun, block_start, 1);
                nuvo_map_reserve_differ(mdr, map);
                nuvo_map_fault_in_differ(mdr, map);

                fault_in_cnt++;

                if (fault_in_cnt == fault_in_max_cnt)
                {
                    nuvo_return_t status = nuvo_map_wait_fault_in_differ(mdr);
                    fault_in_cnt = 0;

                    // fault in fail, lets return with whatever we got till now */
                    if (status < 0)
                    {
                        break;
                    }
                }
                // get back the locks after fault in
                nuvo_mutex_lock(&map->mutex);
                nuvo_mutex_lock(&mdr->map->mutex);
            }

            NUVO_ASSERT(mdr->map->pinned > 0);

            ret = map_diff(mdr, mdr->map, NULL, mdr->map->base_offset, offset_end);
            nuvo_mutex_unlock(&mdr->map->mutex);
            if (ret == -NUVO_ENOMEM)
            {
                break;
            }


            cnt_entries += ret;
        }
    }

    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_unpin_table_locked(map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    // if ret is ENOMEM, we already have 256 entries.
    // so we retun the count we got irrspective of what we have.


    return (ret);
}

static void nuvo_map_diff_mem_sync_cb(struct nuvo_map_alloc_req *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t *)req->tag.ptr;

    nuvo_mutex_unlock(sync_signal);
}

void map_diff_alloc_mem_sync(struct nuvo_map_diff_request *mdr)
{
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);
    nuvo_mutex_lock(&sync_signal);

    mdr->alloc_req.count = NUVO_MAP_DIFFER_ALLOC_BATCH_SIZE;  // alloc 32 at a time
    mdr->alloc_req.map_list = &mdr->map_list;
    mdr->alloc_req.callback = nuvo_map_diff_mem_sync_cb;
    mdr->alloc_req.tag.ptr = &sync_signal;
    //TODO yes, we are holding pinned tables , but we are lying here tempoarily
    // must fix this by handling the error.
    nuvo_return_t ret = nuvo_map_alloc_tables(&mdr->alloc_req, false);
    NUVO_ASSERT(ret >= 0); // non-pinned version should never fail
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);
}

void map_diff_release_mem_unused(struct nuvo_map_diff_request *mdr)
{
    struct nuvo_dlist comp_list;

    nuvo_dlist_init(&comp_list);

    map_release_maps(&mdr->map_list, &comp_list);

    struct nuvo_map_alloc_req *comp_req;
    while ((comp_req = nuvo_dlist_remove_head_object(&comp_list, struct nuvo_map_alloc_req, list_node)) != NULL)
    {
        comp_req->callback(comp_req);
    }
}

nuvo_return_t nuvo_map_diff(struct nuvo_map_diff_request *mdr, struct nuvo_lun *lun_left,
                            struct nuvo_lun *lun_right, uint64_t offset_begin, uint64_t *offset_end)
{
    nuvo_return_t ret;

    nuvo_mutex_lock(&lun_left->mutex);

    if (lun_right) // if null, diff with the immediate next lun, mainly for testing
    {
        nuvo_mutex_lock(&lun_right->mutex);

        if ((lun_right->snap_id - lun_left->snap_id) != 1)
        {
            nuvo_mutex_unlock(&lun_right->mutex);
            nuvo_mutex_unlock(&lun_right->mutex);
            return (-NUVO_EINVAL);
        }
    }

    struct nuvo_map_track *root_map_left = lun_left->root_map;
    nuvo_mutex_unlock(&lun_left->mutex);

    if (lun_right)
    {
        nuvo_mutex_unlock(&lun_right->mutex);
    }

    //*alloc mem
    map_diff_alloc_mem_sync(mdr);
    nuvo_mutex_lock(&root_map_left->mutex);
    ret = map_diff(mdr, root_map_left, NULL, offset_begin, offset_end);
    nuvo_mutex_unlock(&root_map_left->mutex);

    /* freee unused memory here */
    map_diff_release_mem_unused(mdr);

    return (ret);
}

nuvo_return_t nuvo_map_diff_api_helper(struct nuvo_lun *lun_left, struct nuvo_lun *lun_right, uint64_t offset_begin, struct map_de *map_de_array, uint32_t *batch_size, uint64_t *offset_end)
{
    struct nuvo_map_diff_request mdr;

    map_diff_request_init(&mdr, lun_left->vol, map_de_array);
    nuvo_return_t ret;
    ret = nuvo_map_diff(&mdr, lun_left, lun_right, offset_begin, offset_end);
    *batch_size = mdr.batch_size;
    return (ret);
}
