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

#include "log_volume.h"

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
#include "map.h"
#include "nuvo_range_lock.h"
#include "lun.h"
#include "resilience.h"

void nuvo_log_vol_log_cb(struct nuvo_log_request *log_req)
{
    nuvo_mutex_t *mutex = (nuvo_mutex_t *)log_req->tag.ptr;

    nuvo_mutex_unlock(mutex);
}

int nuvo_log_vol_write(struct nuvo_vol *vol, uint64_t block_offset, uint32_t block_count, void **buf_list)
{
    struct nuvo_map_request map_req;
    struct nuvo_map_request map_req_snap;
    struct nuvo_log_request log_req;
    bool multi_lun = false;

    NUVO_ASSERT(block_count <= NUVO_MAX_IO_BLOCKS);
    nuvo_mutex_t  sync_signal;
    nuvo_return_t ret = nuvo_mutex_init(&sync_signal);
    if (ret != 0)
    {
        // TODO ERROR CODE
        return (ENOMEM);
    }

    nuvo_space_write_permission(&vol->log_volume.space);
    nuvo_rwlock_rdlock(&vol->rw_lock);

    // do map request
    nuvo_map_request_init(&map_req, &vol->log_volume.lun, block_offset, block_count);
    nuvo_map_reserve_sync(&map_req);
    if (map_req.status < 0)
    {
        nuvo_rwlock_unlock(&vol->rw_lock);
        nuvo_mutex_destroy(&sync_signal);
        // TODO: need error codes
        return (ENOMEM);
    }
    //Check if cow is needed, if yes we need to take the long route
    //of updating both the snap lun and the active lun
    // atomically using the multi lun commit interface

#if 0
    struct nuvo_lun *snap_lun = nuvo_get_peer_cow_lun(vol);
    if (snap_lun && nuvo_map_is_cow_reqd(&map_req))
    {
        multi_lun = true;
        nuvo_map_request_init(&map_req_snap, snap_lun, block_offset, block_count);
        nuvo_map_reserve_sync(&map_req_snap);
    }
#endif
    struct nuvo_lun *snap_lun = nuvo_get_peer_cow_lun(vol, false);
    if (snap_lun)
    {
        multi_lun = true;
        nuvo_map_request_init(&map_req_snap, snap_lun, block_offset, block_count);
        nuvo_map_reserve_sync(&map_req_snap);
    }

    // start logger
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &sync_signal;
    log_req.vs_ptr = vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = block_count;
    for (unsigned i = 0; i < block_count; i++)
    {
        log_req.log_io_blocks[i].data = buf_list[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;

        LOG_PIT_INFO_SET_DATA(log_req.log_io_blocks[i].pit_info, 1, 0); // TODO - change 0 to next pit_id
    }
    nuvo_mutex_lock(&sync_signal);
    log_req.callback = nuvo_log_vol_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    if (map_req.status < 0)
    {
        // map fault-in failed, panic
        NUVO_PANIC("Map fault-in failed!");
    }

    if (multi_lun)
    {
        nuvo_map_fault_in_sync(&map_req_snap);
        NUVO_ASSERT(!(map_req_snap.status < 0));
    }
    // wait for completion
    nuvo_mutex_lock(&sync_signal);

    NUVO_ASSERT(!log_req.status);


    // Check if cow is needed, if yes we need to take the long route
    // of updating both the snap lun and the active lun
    // atomically using the multi lun commit interface

    if (multi_lun)
    {
        // commit map on both the luns atomically
        nuvo_map_multi_lun_commit_write(&map_req, &map_req_snap, log_req.nuvo_map_entries);
    }
    else
    {
        nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);
    }

    // do reserve + fault in on the snap lun


    nuvo_log_ack_sno(&log_req);

    nuvo_rwlock_unlock(&vol->rw_lock);
    nuvo_mutex_destroy(&sync_signal);

    return (0);
}

struct nuvo_log_vol_read_state {
    nuvo_mutex_t  mutex;
    nuvo_cond_t   completed_cond;
    uint_fast32_t remaining_count;
    uint_fast32_t failed_count;
    int_fast64_t  status;
};

void nuvo_log_vol_read_cb(struct nuvo_io_request *req)
{
    struct nuvo_log_vol_read_state *read_state = (struct nuvo_log_vol_read_state *)req->tag.ptr;
    nuvo_return_t status = req->status;

    if (status < 0)
    {
        NUVO_ERROR_PRINT("Read error at parcel %d, block offset %d, block count %d", req->rw.parcel_desc, req->rw.block_offset, req->rw.block_count);
    }
    nuvo_pr_client_req_free(req);

    nuvo_mutex_lock(&read_state->mutex);
    if (status < 0)
    {
        read_state->failed_count++;
        read_state->status = status;
    }
    read_state->remaining_count--;
    if (read_state->remaining_count == 0)
    {
        nuvo_cond_broadcast(&read_state->completed_cond);
    }
    nuvo_mutex_unlock(&read_state->mutex);
}

int nuvo_log_vol_lun_read(struct nuvo_lun *lun, uint64_t block_offset, uint32_t block_count, void **buf_list,
                          struct nuvo_io_request *req_cb)
{
    struct nuvo_map_request        map_req;
    struct nuvo_map_entry          map_entries[NUVO_MAX_IO_BLOCKS];
    uint_fast32_t                  parcel_descs[NUVO_MAX_IO_BLOCKS];
    struct nuvo_log_vol_read_state read_state;
    bool rw_locked = false;

    read_state.failed_count = 0;
    read_state.remaining_count = 0;
    read_state.status = 0;

    int_fast64_t ret;
    NUVO_ASSERT(block_count <= NUVO_MAX_IO_BLOCKS);
    nuvo_mutex_t sync_signal;
    ret = nuvo_mutex_init(&sync_signal);
    if (ret != 0)
    {
        // TODO ERROR CODE
        return (ENOMEM);
    }

    ret = nuvo_mutex_init(&read_state.mutex);
    if (ret < 0)
    {
        nuvo_mutex_destroy(&sync_signal);
        // TODO: need error codes
        return (ENOMEM);
    }

    ret = nuvo_cond_init(&read_state.completed_cond);
    if (ret < 0)
    {
        nuvo_mutex_destroy(&read_state.mutex);
        nuvo_mutex_destroy(&sync_signal);
        // TODO: need error codes
        return (ENOMEM);
    }

    if (NUVO_LUN_IS_ACTIVE(lun))
    {
        nuvo_rwlock_rdlock(&lun->vol->rw_lock);
        rw_locked = true;
    }

    nuvo_map_request_init(&map_req, lun, block_offset, block_count);
    nuvo_map_reserve_sync(&map_req);
    if (map_req.status < 0)
    {
        ret = ENOMEM;
        goto _out;
    }
    nuvo_map_fault_in_sync(&map_req);
    if (map_req.status < 0)
    {
        ret = ENOMEM;
        goto _out;
    }

    //am I the peer cow lun(the youngest snapshot of the series)
    // and will at least one block of this read could be redirected ?
    // In other words, will this read go to the active?
    // If yes, we must use the mulit locking read.

    //if (nuvo_is_peer_cow_lun(map_req.lun) && nuvo_map_is_ror_reqd(&map_req))
    if (nuvo_is_peer_cow_lun(map_req.lun))
    {
        struct nuvo_map_request map_req_active;
        nuvo_map_request_init(&map_req_active, &(lun->vol->log_volume.lun), block_offset, block_count);
        nuvo_map_reserve_sync(&map_req_active);

        if (map_req_active.status < 0)
        {
            ret = ENOMEM;
            goto _out;
        }
        nuvo_map_fault_in_sync(&map_req_active);
        if (map_req_active.status < 0)
        {
            ret = ENOMEM;
            goto _out;
        }
        nuvo_map_multi_lun_read_sync(&map_req, true, &map_req_active, map_entries, parcel_descs);
    }
    else
    {
        nuvo_map_read_and_pin_sync(&map_req, true, map_entries, parcel_descs);
    }

    if (map_req.status < 0)
    {
        // TODO: need error codes
        ret = ENOMEM;
        goto _out;
    }

//read data begins here.

    // issue read requests for contiguous segments of map entries
    for (uint_fast32_t i = 0; i < block_count;)
    {
        // get a request
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
        req->rw.block_count = 0;
        uint_fast32_t            first_map_entry = 0;
        void                    *buf;
        enum nuvo_map_entry_type first_map_type;

        uint_fast32_t n = i;
        for (; n < block_count; n++)
        {
            // check each block
            if ((map_entries[n].type == NUVO_ME_MEDIA) ||
                (map_entries[n].type == NUVO_ME_NULL))
            {
                // map entry has on-media data or shared entries
                // check if we have any entries already in this request

                // assert that shared entries are consistent on type and cow bit
                if (map_entries[n].type == NUVO_ME_NULL)
                {
                    NUVO_ASSERT(map_entries[n].cow == NUVO_MAP_ENTRY_SHARED);
                }
                if (req->rw.block_count == 0)
                {
                    // no previous entries, put ourselves as the first
                    if (map_entries[n].type == NUVO_ME_MEDIA)
                    {
                        // if this is active lun  and this is a redirected
                        // read (req_cb != NULL), check that the entry is COW
                        // assert since this must not happen in the mulit lock approach
                        // if entry is NONE and this is redirected read, we must read
                        // back from the peer cow lun(youngest lun)
                        // again ( and add checks for infinite cycles)

                        if (req_cb && NUVO_LUN_IS_ACTIVE(lun) && map_entries[n].cow == NUVO_MAP_ENTRY_NONE)
                        {
                            NUVO_DEBUG_ASSERT(NUVO_LUN_IS_ACTIVE(lun),
                                              "redirected read on active must return cow, going back to read from peer cow lun");

                            req->rw.block_offset = block_offset + n;
                            buf = &buf_list[n];
                            map_entries[n].type = NUVO_ME_NULL;
                        }
                        else
                        {
                            req->rw.parcel_desc = parcel_descs[n];
                            req->rw.block_offset = map_entries[n].media_addr.block_offset;
                            req->rw.iovecs[req->rw.block_count].iov_base = buf_list[n];
                            req->rw.iovecs[req->rw.block_count].iov_len = NUVO_BLOCK_SIZE;
                            req->rw.block_hashes[req->rw.block_count] = map_entries[n].hash;
                        }
                    }
                    else // shared snapshot read
                    {
                        // no shared reads on active on the active please
                        NUVO_ASSERT(!NUVO_LUN_IS_ACTIVE(lun));
                        req->rw.block_offset = block_offset + n;
                        buf = &buf_list[n];
                    }

                    first_map_entry = n;
                    req->rw.block_count = 1;
                    first_map_type = map_entries[n].type;
                }
                else
                {
                    // TODO rewrite as more readable
                    // are we media contigous  OR
                    // are we shared contigous

                    if ((((map_entries[first_map_entry].media_addr.parcel_index ==
                           map_entries[n].media_addr.parcel_index) &&
                          (map_entries[first_map_entry].media_addr.block_offset +
                           req->rw.block_count ==
                           map_entries[n].media_addr.block_offset)) &&
                         ((map_entries[n].type == NUVO_ME_MEDIA) &&
                          (first_map_type == NUVO_ME_MEDIA))) ||
                        ((map_entries[n].type == NUVO_ME_NULL) &&
                         (first_map_type == NUVO_ME_NULL)))

                    {
                        // the map entries are contiguous
                        req->rw.iovecs[req->rw.block_count].iov_base = buf_list[n];
                        req->rw.iovecs[req->rw.block_count].iov_len = NUVO_BLOCK_SIZE;
                        req->rw.block_hashes[req->rw.block_count] = map_entries[n].hash;
                        req->rw.block_count++;
                    }
                    else
                    {
                        // the map entries are not contiguous, break out
                        // and submit the io req
                        break;
                    }
                }
            }

            else if (map_entries[n].type == NUVO_ME_CONST)
            {
                // map entry has const value data
                static_assert((NUVO_BLOCK_SIZE % (sizeof(uint64_t) * 8)) == 0, "NUVO_BLOCK_SIZE is not a multiple of the const fill loop.");
                uint64_t pattern = map_entries[n].pattern;
                for (uint64_t *cur = (uint64_t *)buf_list[n],
                     *end = (uint64_t *)((uintptr_t)buf_list[n] + NUVO_BLOCK_SIZE);
                     cur < end;
                     cur += 8)
                {
                    cur[0] = pattern;
                    cur[1] = pattern;
                    cur[2] = pattern;
                    cur[3] = pattern;
                    cur[4] = pattern;
                    cur[5] = pattern;
                    cur[6] = pattern;
                    cur[7] = pattern;
                }
                n++;
                break; //break as we might have to issue some i/os
            }
            else
            {
                NUVO_PANIC("Unsupported map entry type in read.");
            }
        }

        // was anything put on the req
        if ((req->rw.block_count != 0) && (first_map_type == NUVO_ME_MEDIA))
        {
            // Only IO on the active lun is considered user IO.
            NUVO_SET_IO_TYPE(req, NUVO_OP_READ_VERIFY, (NUVO_LUN_IS_ACTIVE(lun)) ? NUVO_IO_ORIGIN_USER : NUVO_IO_ORIGIN_INTERNAL);
            NUVO_SET_CACHE_HINT(req, NUVO_LUN_IS_ACTIVE(lun) ? NUVO_CACHE_DEFAULT : NUVO_CACHE_NONE);
            req->tag.ptr = &read_state;
            req->callback = nuvo_log_vol_read_cb;
            req->rw.vol = lun->vol;
            // fillout req, update the read state, and submit
            nuvo_mutex_lock(&read_state.mutex);
            read_state.remaining_count++;
            nuvo_mutex_unlock(&read_state.mutex);

            struct nuvo_dlist submit_list;
            nuvo_dlist_init(&submit_list);
            nuvo_dlist_insert_head(&submit_list, &req->list_node);
            nuvo_rl_submit(&submit_list);
        }
        else if ((req->rw.block_count != 0) && (first_map_type == NUVO_ME_NULL))
        {
            // Only IO on the active lun is considered user IO.
            NUVO_SET_IO_TYPE(req, NUVO_OP_READ, (NUVO_LUN_IS_ACTIVE(lun)) ? NUVO_IO_ORIGIN_USER : NUVO_IO_ORIGIN_INTERNAL);
            NUVO_SET_CACHE_HINT(req, NUVO_LUN_IS_ACTIVE(lun) ? NUVO_CACHE_DEFAULT : NUVO_CACHE_NONE);
            req->tag.ptr = &read_state;
            req->callback = nuvo_log_vol_read_cb;
            req->rw.vol = lun->vol;
            // fillout req, update the read state, and submit
            nuvo_mutex_lock(&read_state.mutex);
            read_state.remaining_count++;
            nuvo_mutex_unlock(&read_state.mutex);

            //redirected active reads only happen
            // when active returns NONE on redirected read.
            // this means a snap write came in the way

            struct nuvo_lun *lun_next;

            if (NUVO_LUN_IS_ACTIVE(lun))
            {
                lun_next = nuvo_get_peer_cow_lun(lun->vol, false);
            }
            else
            {
                lun_next = nuvo_get_next_younger_lun(lun, false);
            }
            nuvo_log_vol_lun_read(lun_next, req->rw.block_offset, req->rw.block_count, buf, req);
        }
        else
        {
            nuvo_pr_client_req_free(req);
        }

        i = n;
    }



    // wait for everything to complete
    nuvo_mutex_lock(&read_state.mutex);
    while (read_state.remaining_count != 0)
    {
        nuvo_cond_wait(&read_state.completed_cond, &read_state.mutex);
    }
    ret = read_state.status;
    nuvo_mutex_unlock(&read_state.mutex);

    nuvo_map_read_release(lun, block_count, map_entries);

_out:

    if (rw_locked)
    {
        nuvo_rwlock_unlock(&lun->vol->rw_lock);
    }

    nuvo_cond_destroy(&read_state.completed_cond);
    nuvo_mutex_destroy(&read_state.mutex);
    nuvo_mutex_destroy(&sync_signal);

    if (req_cb)
    {
        req_cb->status = -ret;
        req_cb->callback(req_cb);
    }

    if (ret < 0)
    {
        NUVO_ERROR_PRINT("Read error on lun %d, offset %d, len %d", lun->snap_id, block_offset, block_count);
    }
    return (ret);
}
