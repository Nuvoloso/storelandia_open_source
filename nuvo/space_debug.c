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
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "gc.h"
#include "logger.h"
#include "map.h"
#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "nuvo_pr_sync.h"
#include "nuvo_vol_series.h"
#include "parallel.h"
#include "replay.h"
#include "segment.h"
#include "space.h"
#include "resilience.h"

/**
 * @file space_debug.c
 * @brief Debug for the space management code.
 */

static void space_gc_call_done_cb(struct nuvo_gc *gc)
{
    nuvo_mutex_unlock(gc->tag.ptr);
}

// Documented in header.
nuvo_return_t nuvo_space_vol_gc_seg_debug(struct nuvo_space_vol *space,
                                          uint32_t               parcel_index,
                                          uint32_t               segment_index,
                                          bool                   no_cp)
{
    struct nuvo_vol     *vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);
    struct nuvo_segment *segment;

    nuvo_return_t rc = nuvo_mfst_segment_for_gc_debug(
        &vol->log_volume.mfst, parcel_index, segment_index, &segment);

    if (rc < 0)
    {
        return (rc);
    }

    nuvo_mutex_lock(&space->space_vol_mutex);

    struct nuvo_gc *gc = nuvo_gc_alloc();
    if (gc == NULL)
    {
        nuvo_mutex_unlock(&space->space_vol_mutex);
        nuvo_mfst_segment_done(&vol->log_volume.mfst, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
        nuvo_segment_free(&nuvo_global_segment_free_list, segment);
        return (-1);
    }

    NUVO_ERROR_PRINT("Cleaning segment (%d, %d)", parcel_index, segment_index);
    space->gc_data_class[segment->data_class].gc_in_progress++;
    nuvo_mutex_unlock(&space->space_vol_mutex);
    nuvo_gc_init(gc, vol, segment);
    gc->moving_callback = space_gc_call_done_cb;
    gc->no_cp = no_cp;

    nuvo_mutex_t sync_signal;
    nuvo_mutex_init(&sync_signal);
    gc->tag.ptr = &sync_signal;
    nuvo_mutex_lock(gc->tag.ptr);
    nuvo_gc_needs_work(gc);
    nuvo_mutex_lock(gc->tag.ptr);
    nuvo_mutex_unlock(gc->tag.ptr);
    nuvo_mutex_destroy(&sync_signal);
    rc = 0;

    return (0);
}

nuvo_return_t nuvo_space_read_digest_debug(struct nuvo_space_vol      *space,
                                           uint32_t                    parcel_index,
                                           uint32_t                    segment_index,
                                           struct nuvo_segment_digest *digest)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t rc;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        rc = -NUVO_ENOMEM;
        goto mutex_failed;
    }

    struct nuvo_vol     *vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);
    struct nuvo_segment *segment;

    struct nuvo_io_request *io_req = nuvo_pr_sync_client_req_alloc(&sync_signal);

    rc = nuvo_mfst_segment_for_gc_debug(
        &vol->log_volume.mfst, parcel_index, segment_index, &segment);
    if (rc < 0)
    {
        goto mfst_segment_failed;
    }
    NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
    io_req->rw.parcel_desc = segment->parcel_desc;
    io_req->rw.block_offset = get_segment_digest_offset(segment);
    io_req->rw.block_count = get_segment_digest_len(segment);
    NUVO_LOG(space, 40, "nuvo_space_read_digest_debug " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(vol->vs_uuid), segment->parcel_index, segment->block_offset);
    NUVO_ASSERT(io_req->rw.block_count <= NUVO_MAX_IO_BLOCKS);
    for (unsigned i = 0; i < io_req->rw.block_count; i++)
    {
        io_req->rw.iovecs[i].iov_base = ((void *)digest) + i * NUVO_BLOCK_SIZE;
        io_req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
    }
    nuvo_rl_sync_submit(io_req, &sync_signal);
    if (io_req->status < 0)
    {
        NUVO_ERROR_PRINT("nuvo_space_read_digest_debug: Read of digest failed.");
        rc = io_req->status;
        goto io_failed;
    }
    bool valid = segment_digest_verify(io_req->rw.iovecs[0].iov_base, io_req->rw.block_hashes, io_req->rw.block_count);
    if (valid)
    {
        rc = 0;
    }
    else
    {
        NUVO_ERROR_PRINT("nuvo_space_read_digest_debug: Digest not valid.");
        rc = -1;
    }

io_failed:
    nuvo_mfst_segment_done(&vol->log_volume.mfst, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
mfst_segment_failed:
    nuvo_pr_client_req_free(io_req);
    nuvo_segment_free(&nuvo_global_segment_free_list, segment);
    nuvo_mutex_destroy(&sync_signal);
mutex_failed:
    return (rc);
}
