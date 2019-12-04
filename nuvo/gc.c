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
 * @file gc.c
 * @brief data structures for garbage collecting segments.
 */

static void nuvo_gc_elide_prepare(struct nuvo_gc *gc);
static void prep_types(struct nuvo_gc_batch *gc_batch);
static void map_faulting(struct nuvo_gc_batch *gc_batch, enum nuvo_gc_block_type type);

#define MIN(A, B)    (((A) < (B)) ? (A) : (B))

static inline void nuvo_gc_decision_record(struct nuvo_gc *gc, uint32_t boffset, uint32_t snap_id, enum  nuvo_gc_move_decision_e decision)
{
    if (GC_DECISION_LOG_ENABLED)
    {
        if (gc->moving_log.num_used >= GC_DECISION_LOG_SIZE)
        {
            NUVO_ERROR_PRINT("gc decision log overflowed.");
        }
        else
        {
            gc->moving_log.record[gc->moving_log.num_used].boffset = boffset;
            gc->moving_log.record[gc->moving_log.num_used].snap_id = snap_id;
            gc->moving_log.record[gc->moving_log.num_used].decision = decision;
            gc->moving_log.num_used++;
        }
    }
}

static void nuvo_gc_decision_print(struct nuvo_gc *gc, uint32_t boffset)
{
    for (unsigned i = 0; i < gc->moving_log.num_used; i++)
    {
        if (boffset != gc->moving_log.record[i].boffset)
        {
            continue;
        }
        NUVO_ERROR_PRINT("GC did not move %u, %u reason: %d", gc->moving_log.record[i].boffset, gc->moving_log.record[i].snap_id, gc->moving_log.record[i].decision);
    }
}

/**
 * \brief Handle the callback from a read of the digest.
 *
 * The io_req from reading a digest for gc has returned.
 *
 * When the read of a segment digest has returned from the pr
 * check that the read succeeded and that the digest is valid.
 * Assuming that it is, move the nuvo_gc to the next state in the
 * gc state machine (eliding) and queue the gc as needing work.
 *
 * For testing purposes, will also call a callback on the gc.
 *
 * \param io_req The io request reading the digest.
 */
void nuvo_gc_read_digest_cb(struct nuvo_io_request *io_req)
{
    struct nuvo_gc *gc = (struct nuvo_gc *)io_req->tag.ptr;

    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_DIGEST_READING);
    if (io_req->status < 0)
    {
        NUVO_PANIC("Read of digest failed.");
    }
    NUVO_LOG(space, 50, "nuvo_gc_read_digest_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
    bool valid = segment_digest_verify(io_req->rw.iovecs[0].iov_base, io_req->rw.block_hashes, io_req->rw.block_count);
    NUVO_PANIC_COND(!valid, "Invalid segment digest");  // TODO - handle error gracefully.
    memcpy(&gc->digest2, &gc->digest, io_req->rw.block_count * NUVO_BLOCK_SIZE);
    nuvo_pr_client_req_free(io_req);
    nuvo_gc_elide_prepare(gc);
    nuvo_mutex_unlock(&gc->gc_mutex);
    if (gc->phase_callback != NULL)
    {
        gc->phase_callback(gc);
    }
}

/* Documented in header */
nuvo_return_t nuvo_gc_read_digest(struct nuvo_gc *gc)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (-NUVO_ENOMEM);
    }
    struct nuvo_io_request *io_req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
    io_req->rw.vol = gc->vol;
    io_req->rw.parcel_desc = gc->segment->parcel_desc;
    io_req->rw.block_offset = get_segment_digest_offset(gc->segment);
    io_req->rw.block_count = get_segment_digest_len(gc->segment);
    NUVO_LOG(space, 40, "nuvo_gc_read_digest " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
    NUVO_ASSERT(io_req->rw.block_count <= NUVO_MAX_IO_BLOCKS);
    for (unsigned i = 0; i < io_req->rw.block_count; i++)
    {
        io_req->rw.iovecs[i].iov_base = ((void *)&gc->digest) + i * NUVO_BLOCK_SIZE;
        io_req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
    }
    io_req->tag.ptr = gc;
    io_req->callback = nuvo_gc_read_digest_cb;
    nuvo_mutex_unlock(&gc->gc_mutex);
    nuvo_rl_submit_req(io_req);

    return (0);
}

// TODO - better place.
#define NUVO_MAX_PIT    0x7FFFFFFF

/**
 * Go through looking for actives first. For each active look in the map checking to see if it is still in-use.
 * If so move that block to NUVO_GC_BLOCK_MOVE_DATA state.
 *
 * Then go through for the newest snapshot.  Look in it's map to see if it is using any blocks that the summary
 * says are owned by that snapshot or that are owned by the active, where written no later than that snap and are
 * still NUVO_GC_BLOCK_UNKNOWN. Any block that is in use there will be rewritten there.  Do surgery on the summary
 * too include the lun.
 *
 * Go through each snapshot in turn.
 *
 * Once done pick up and conditionally rewrite the blocks.
 */

/**
 * \brief Prepare to elide the summary (i.e. figure out which blocks to move)
 *
 * Finds which blocks may have data we need to move and set up to scan starting at the active id.
 *
 * \param gc The gc.
 */
static void nuvo_gc_elide_prepare(struct nuvo_gc *gc)
{
    gc->state = NUVO_SPACE_GC_DIGEST_ELIDING;
    gc->boffset = 0;
    gc->lun_id = NUVO_MFST_ACTIVE_LUN_SNAPID;
    uint32_t lowest_data_pit_id = NUVO_MAX_PIT;
    uint32_t lowest_map_pit_id = NUVO_MAX_PIT;
    NUVO_LOG(space, 40, "nuvo_gc_elide_prepare " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
    for (unsigned i = 0; i < gc->digest.footer.used_block_count; i++)
    {
        if (NUVO_LE_MAP(gc->digest.table[i].log_entry_type))
        {
            lowest_map_pit_id = MIN(lowest_map_pit_id, gc->digest.table[i].data.pit_info.pit_id);
            gc->block_state[i] = NUVO_GC_BLOCK_MOVE_MAP;
        }
        else if (gc->digest.table[i].log_entry_type == NUVO_LE_DATA)
        {
            gc->block_state[i] = NUVO_GC_BLOCK_UNKNOWN;
            lowest_data_pit_id = MIN(lowest_data_pit_id, gc->digest.table[i].data.pit_info.pit_id);
        }
        else
        {
            gc->block_state[i] = NUVO_GC_BLOCK_UNUSED;  // Definitely not moving.
        }
    }

    /*
     * Any block belonging to a PiT older than pinned is in a deleted snapshot.   Don't waste our time.
     * Only set these if pinned_lun is set, since if it is NULL we do not move snaps.
     */
    if (gc->pinned_lun != NULL)
    {
        gc->lowest_data_pit_id = NUVO_MAX(lowest_data_pit_id, gc->pinned_lun->snap_id);
        gc->lowest_map_pit_id = NUVO_MAX(lowest_map_pit_id, gc->pinned_lun->snap_id);
    }
    else
    {
        gc->lowest_data_pit_id = NUVO_MFST_ACTIVE_LUN_SNAPID;
        gc->lowest_map_pit_id = NUVO_MFST_ACTIVE_LUN_SNAPID;
    }


    nuvo_gc_needs_work(gc);
}

/**
 * \brief A map fault-in has completed, do the read and eliding.
 *
 * The \p map_req is a single map request fault in that has just returned.  Since the fault in
 * has just returned, the nuvo_map_read will be non-blocking. Compare the entry that has been
 * returned with the block from the nuvo_segment_digest. If they are different, this block
 * is no longer in use and we don't need to move it.  After done, let the parallel op know that one of
 * the requests are completed so it can do its thing when the batch is done.
 *
 * \param map_req The fault-in map req.
 */
void nuvo_gc_elide_faultin_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_gc_map_info *map_info = map_req->tag.ptr;

    NUVO_ASSERT(&map_info->map_req == map_req);
    if (map_req->status >= 0)
    {
        struct nuvo_map_entry entries[NUVO_MAX_IO_BLOCKS];
        uint_fast16_t         num = map_req->block_last - map_req->block_start + 1;
        NUVO_ASSERT(num <= NUVO_MAX_IO_BLOCKS);
        struct nuvo_gc *gc = map_info->gc_batch->gc;
        uint_fast32_t   log_pit_id = map_info->gc_batch->elide.log_pit_id;
        nuvo_mutex_lock(&gc->gc_mutex);
        NUVO_LOG(space, 50, "nuvo_gc_elide_faultin_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                 NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

        NUVO_ASSERT(map_req->lun != NULL);
        NUVO_ASSERT(map_req->lun->snap_id == log_pit_id);
        uint_fast32_t pds[NUVO_MAX_IO_BLOCKS];
        nuvo_map_read_and_pin_sync(map_req, false, entries, pds);  // TODO - make map deal with pds == NULL

        // Now compare the entries returned to the entries in the digest.
        // If they are different we definitely don't need to move the block.
        for (unsigned i = 0; i < num; i++)
        {
            uint_fast32_t boffset = map_info->map_index + i;
            if (entries[i].type == NUVO_ME_MEDIA &&
                entries[i].media_addr.parcel_index == gc->segment->parcel_index &&
                entries[i].media_addr.block_offset == gc->segment->block_offset + boffset)
            {
                nuvo_gc_decision_record(gc, boffset, log_pit_id, NUVO_GC_DECISION_MOVING);
                gc->block_state[boffset] = NUVO_GC_BLOCK_MOVE_DATA;
                if (log_pit_id != NUVO_MFST_ACTIVE_LUN_SNAPID)
                {
                    NUVO_ASSERT(log_pit_id >= gc->lowest_data_pit_id);
                    NUVO_ASSERT(log_pit_id <= gc->vol->snap_generation);
                    LOG_PIT_INFO_SET_DATA(gc->digest.table[boffset].data.pit_info, 0, log_pit_id);
                }
            }
            else
            {
                nuvo_gc_decision_record(gc, boffset, log_pit_id, NUVO_GC_DECISION_NOT_USED);
                // Not here.  Actives can be overwritten.  Both active and
                // PiTs may be moved.  So we could be here in any case.
                // As optimization could move set table to NUVO_LE_EMPTY if block cannot be used in
                // any more snapshots.
                // Don't do that yet.
            }
        }
        nuvo_mutex_unlock(&gc->gc_mutex);
    }
    else
    {
        NUVO_ERROR_PRINT_ERRNO(map_req->status, "Map request failed");
    }
    nuvo_parallel_op_done(&map_info->gc_batch->elide.par_ops, map_req->status);
}

static inline void nuvo_gc_set_state_moving(struct nuvo_gc *gc)
{
    gc->state = NUVO_SPACE_GC_MOVING_DATA;
    gc->actives_failed = 0;
    gc->boffset = 0;
}

void nuvo_gc_elide_lun_done(struct nuvo_gc *gc)
{
    NUVO_ASSERT_MUTEX_HELD(&gc->gc_mutex);
    // All reqs are done and there are no more to issue.
    NUVO_LOG(space, 40, "nuvo_gc_elide_lun_done " NUVO_LOG_UUID_FMT ", segment (%d, %d), lun_id %d",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset, gc->lun_id);
    if (gc->pinned_lun != NULL)
    {
        // Move to next newest snap.
        gc->lun_id = (gc->lun_id == NUVO_MFST_ACTIVE_LUN_SNAPID) ? gc->starting_next_create_pit_id - 1 : gc->lun_id - 1;
    }
    if (gc->pinned_lun != NULL && gc->lun_id >= gc->lowest_data_pit_id)
    {
        NUVO_LOG(space, 40, "nuvo_gc_elide_lun_done " NUVO_LOG_UUID_FMT ", segment (%d, %d), starting with lun_id %d",
                 NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset, gc->lun_id);
    }
    else
    {
        NUVO_LOG(space, 40, "nuvo_gc_elide_lun_done " NUVO_LOG_UUID_FMT ", segment (%d, %d), done",
                 NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
        for (unsigned i = 0; i < gc->digest.footer.used_block_count; i++)
        {
            if (gc->block_state[i] == NUVO_GC_BLOCK_UNKNOWN)
            {
                // Never found.  So don't move.
                gc->block_state[i] = NUVO_GC_BLOCK_UNUSED;
            }
        }
        nuvo_gc_set_state_moving(gc);
    }
    gc->boffset = 0;
    nuvo_gc_needs_work(gc);
}

/**
 * \brief A batch of eliding is done.
 *
 * A batch of map calls and the consequent eliding has completed.  Free the gc_batch.  If this was the
 * last outstanding batch and all needed batches have been dispatched, then eliding is done so move
 * the gc on to the next state and schedule it for work.
 *
 * For testing purposes only this may execute a callback on the gc.
 *
 * \param par_ops The set of parallel operations in an eliding batch.
 */
void nuvo_gc_elide_batch_done(struct nuvo_parallel_op *par_ops)
{
    NUVO_ASSERT(par_ops->status == 0);  // TODO Don't handle errors yet.
    struct nuvo_gc_batch *gc_batch = nuvo_containing_object(par_ops, struct nuvo_gc_batch, elide.par_ops);
    struct nuvo_gc       *gc = gc_batch->gc;
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_DIGEST_ELIDING);
    NUVO_ASSERT(gc->gc_batches_outstanding > 0);
    nuvo_mutex_lock(&gc->gc_mutex);
    nuvo_parallel_op_destroy(par_ops);
    nuvo_gc_batch_free(gc_batch);
    NUVO_LOG(space, 40, "nuvo_gc_elide_batch_done " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
    gc->gc_batches_outstanding--;
    if (gc->gc_batches_outstanding == 0 && gc->boffset == gc->digest.footer.used_block_count)
    {
        nuvo_gc_elide_lun_done(gc);
    }

    nuvo_mutex_unlock(&gc->gc_mutex);
    if (gc->phase_callback != NULL)
    {
        // callback is for testing purposes.
        gc->phase_callback(gc);
    }
}

/**
 * \brief find the next block to move.
 *
 * \param gc The gc to search.
 * \param map_pit_id The pit we are looking for blocks of.
 * \returns The block offset in the digest that contains next interesting block.
 * \retval gc->digest.footer.used_block_count Have reached end of digest on this pass.
 */
static inline uint_fast32_t find_next_elide_range(struct nuvo_gc *gc,
                                                  uint_fast32_t   map_pit_id)
{
    uint_fast32_t boffset = gc->boffset;

    while (boffset < gc->digest.footer.used_block_count)
    {
        if (gc->block_state[boffset] == NUVO_GC_BLOCK_UNKNOWN)
        {
            if ((map_pit_id == NUVO_MFST_ACTIVE_LUN_SNAPID) && gc->digest.table[boffset].data.pit_info.active)
            {
                break;
            }
            if ((map_pit_id != NUVO_MFST_ACTIVE_LUN_SNAPID) && NUVO_LOG_PIT_COULD_BE_IN_PIT(map_pit_id, gc->digest.table[boffset].data.pit_info))
            {
                break;
            }
        }
        boffset++;
    }
    return (boffset);
}

/**
 * \brief Find how many blocks in the next range.
 *
 * \param gc The gc to search.
 * \param map_pit_id The pit we are looking for blocks of.
 * \returns How many blocks in a row can be batched in a map request.
 */
static inline uint_fast32_t find_elide_number(struct nuvo_gc *gc,
                                              uint_fast32_t   map_pit_id)
{
    uint_fast32_t n = 0;
    uint_fast32_t boffset = gc->boffset;
    uint_fast64_t target_bno = gc->digest.table[gc->boffset].data.bno;

    while (n < NUVO_MAX_IO_BLOCKS &&
           boffset < gc->digest.footer.used_block_count &&
           gc->block_state[boffset] == NUVO_GC_BLOCK_UNKNOWN &&
           target_bno == gc->digest.table[boffset].data.bno &&
           NUVO_LOG_PIT_COULD_BE_IN_PIT(map_pit_id, gc->digest.table[boffset].data.pit_info))
    {
        n++;
        boffset++;
        target_bno++;
    }
    return (n);
}

/* Documented in header */
nuvo_return_t nuvo_gc_elide_unused_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    gc_batch->gc = gc;
    struct nuvo_parallel_op *par_ops = &gc_batch->elide.par_ops;
    nuvo_return_t            rc = nuvo_parallel_op_init(par_ops);
    NUVO_ASSERT(rc == 0);  // TODO - handle init failure
    par_ops->callback = nuvo_gc_elide_batch_done;
    nuvo_mutex_lock(&gc->gc_mutex);
    gc_batch->elide.maps_used = 0;
    NUVO_LOG(space, 40, "nuvo_gc_elide_unused_batch " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    // The lun cannot go away because we pinned oldest snapshot.
    gc_batch->elide.log_pit_id = gc->lun_id;
    struct nuvo_lun *lun = nuvo_get_lun_by_snapid(gc->vol, gc->lun_id, false);
    NUVO_ASSERT(lun != NULL);
    NUVO_ASSERT(lun->snap_id == gc->lun_id);

    gc->gc_batches_outstanding++;

    while (gc->boffset < gc->digest.footer.used_block_count &&
           gc_batch->elide.maps_used < NUVO_GC_MAP_REQS_PARALLEL)
    {
        unsigned n = 0;
        gc->boffset = find_next_elide_range(gc, gc_batch->elide.log_pit_id);
        if (gc->boffset == gc->digest.footer.used_block_count)
        {
            break;
        }
        uint_fast64_t base_bno = gc->digest.table[gc->boffset].data.bno;
        n = find_elide_number(gc, gc_batch->elide.log_pit_id);
        if (n == 0)
        {
            break;
        }

        struct nuvo_gc_map_info *gc_map_info = &gc_batch->elide.map_info[gc_batch->elide.maps_used];
        gc_map_info->gc_batch = gc_batch;
        gc_map_info->map_index = gc->boffset;

        // We want to do n blocks.
        nuvo_map_request_init(&gc_map_info->map_req, lun, base_bno, n);
        gc_map_info->map_req.op = NUVO_MAP_REQUEST_OP_GC;
        nuvo_map_reserve_sync(&gc_map_info->map_req);
        gc_map_info->map_req.callback = nuvo_gc_elide_faultin_cb;
        gc_map_info->map_req.tag.ptr = gc_map_info;
        gc->boffset += n;
        nuvo_parallel_op_submitting(par_ops);
        nuvo_mutex_unlock(&gc->gc_mutex);
        nuvo_map_fault_in(&gc_map_info->map_req);
        nuvo_mutex_lock(&gc->gc_mutex);
        gc_batch->elide.maps_used++;
    }

    rc = gc_batch->elide.maps_used;
    if (gc_batch->elide.maps_used != 0)
    {
        // Did some work, so finalize this batch.
        if (gc->boffset < gc->digest.footer.used_block_count)
        {
            // We didn't get to end, so do more work.
            nuvo_gc_needs_work(gc);
        }
        nuvo_mutex_unlock(&gc->gc_mutex);
        nuvo_parallel_op_finalize(par_ops);
    }
    else
    {
        // We didn't find any work to do.
        gc->gc_batches_outstanding--;
        NUVO_ASSERT(gc->boffset == gc->digest.footer.used_block_count);
        if (gc->gc_batches_outstanding == 0)
        {
            nuvo_gc_elide_lun_done(gc);
        }
        nuvo_mutex_unlock(&gc->gc_mutex);
        // Didn't do any work, so don't finalize, just destroy.
        // TODO Think about whether we should just use the case above and let the finalize do the callback and be done.
        nuvo_parallel_op_destroy(par_ops);
        nuvo_gc_batch_free(gc_batch);
    }
    return (rc);
}

/*
 * Rewriting a batch
 * When we figure out which blocks we are going to read.  Then we can read those and
 * make sure that the relevant blocks in the map are loaded.   That means that we build the map request
 * and send in then we send the fault in call. Once we've done that we can send the request to the logger
 * and finally when the logger returns call the map with all of the map updates.
 * We do it in this order because the step with all of the map updates stalls the reply
 * queue while it is running.  So we do not want to force IOs while that is happening.
 */

void nuvo_gc_data_possibly_done(struct nuvo_gc *gc)
{
    nuvo_mutex_lock(&gc->vol->mutex);
    uint32_t starting_next_create_pit_id = gc->vol->snap_generation + 1;
    nuvo_mutex_unlock(&gc->vol->mutex);
    if (gc->actives_failed || starting_next_create_pit_id != gc->starting_next_create_pit_id)   // TODO means TODO asshole! repro with a NUVO_ERROR predicting doom, then fix - or a snap create snuck in.
    {
        NUVO_LOG(space, 30, "retrying gc again: " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
                 NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);
        gc->state = NUVO_SPACE_GC_MOVE_FAILED;
        nuvo_gc_needs_work(gc);
        // TODO - keep track of failures to assert not spinning forever.
        // Could maybe assert about sgc->stats.reinit, but multiple snap creates COULD cause us to loop again and again.
        // If I was more clever I could limit us to one snapshot induced pass, since the worry is that blocks will move from active into
        // and untracked snapshot, but that seems to be too clever.
    }
    else
    {
        gc->state = NUVO_SPACE_GC_MOVE_MAPS;
        gc->boffset = 0;
        nuvo_gc_needs_work(gc);
    }
}

/**
 * \brief log_req The log request that just finished.
 *
 * This gets called when the logger has completed the write.  Store away the old media addresses we just got.
 * The map was already faulted in, so we can send (effectively) non-blocking nuvo_map_commit_gc_write requests
 * to update the map requests.
 *
 * \param log_req
 */
void nuvo_gc_log_req_cb(struct nuvo_log_request *log_req)
{
    struct nuvo_gc_batch *gc_batch = (struct nuvo_gc_batch *)log_req->tag.ptr;

    NUVO_ASSERT(log_req->status >= 0);  // TODO - handle errors

    struct nuvo_media_addr  old_media_addrs[NUVO_GC_DATA_BLOCK_NUM_MAX];
    struct nuvo_gc         *gc = gc_batch->gc;
    enum nuvo_gc_block_type type = (log_req->cache_hint == NUVO_CACHE_DEFAULT ? NUVO_GC_BLOCK_HOT : NUVO_GC_BLOCK_COLD);

    NUVO_LOG(space, 50, "nuvo_gc_log_req_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    nuvo_mutex_lock(&gc->gc_mutex);
    for (uint_fast16_t i = 0; i < gc_batch->move_data.bunch[type].blocks_moving; i++)
    {
        // Assert to make sure media_addrs have not changed.
        NUVO_ASSERT(gc->segment->parcel_index == log_req->log_io_blocks[i].gc_media_addr.parcel_index);
        NUVO_ASSERT(gc_batch->move_data.bunch[type].boffset_moved[i] + gc->segment->block_offset == log_req->log_io_blocks[i].gc_media_addr.block_offset);

        old_media_addrs[i] = log_req->log_io_blocks[i].gc_media_addr;
    }

    // Finished a write.  Need to send these off to the map.
    uint_fast16_t entries_done = 0;
    for (uint_fast16_t i = 0; i < gc_batch->move_data.bunch[type].maps_used; i++)
    {
        struct nuvo_map_request *map_req = &gc_batch->move_data.bunch[type].map_info[i].map_req;
        // Returns whether number of failed commits (because the active moved on)
        uint_fast32_t succeeded = 0;
        uint_fast32_t failed = 0;
        NUVO_ASSERT(gc->vol->log_volume.mfst.enable_segment_count_changes);
        nuvo_map_commit_gc_write(map_req, log_req->nuvo_map_entries + entries_done, old_media_addrs + entries_done, &succeeded, &failed);
        NUVO_ASSERT(failed + succeeded == map_req->block_last - map_req->block_start + 1);
        gc->actives_failed += failed;
        gc->stats.actives_failed += failed;
        if (failed > 0)
        {
            NUVO_LOG(space, 40, "nuvo_gc_log_req_cb " NUVO_LOG_UUID_FMT ", type %u segment (%d, %d), failed %d rewrites",
                     NUVO_LOG_UUID(gc->vol->vs_uuid), type, gc->segment->parcel_index, gc->segment->block_offset, gc->actives_failed);
        }
        entries_done += (map_req->block_last - map_req->block_start) + 1;
    }
    gc->stats.data_block_moves += entries_done;
    NUVO_ASSERT(entries_done == gc_batch->move_data.bunch[type].blocks_moving);

    gc_batch->move_data.bunch[type].done = true;
    bool other_done = (gc_batch->move_data.bunch[type == NUVO_GC_BLOCK_HOT ? NUVO_GC_BLOCK_COLD : NUVO_GC_BLOCK_HOT].done);

    if (other_done)
    {
        gc->gc_batches_outstanding--;
        if (0 == gc->gc_batches_outstanding && gc->boffset == gc->digest.footer.used_block_count)
        {
            nuvo_gc_data_possibly_done(gc);
        }
    }

    nuvo_mutex_unlock(&gc->gc_mutex);

    nuvo_log_ack_sno(log_req);

    if (other_done)
    {
        if (gc->phase_callback != NULL)
        {
            gc->phase_callback(gc);
        }
        nuvo_pr_client_buf_free_list(gc_batch->move_data.data_bufs, gc_batch->move_data.boffsets_used);
        nuvo_gc_batch_free(gc_batch);
    }
}

/**
 * \brief Send a log request for the batch of data moves.
 *
 * Both of the data reads and the map fault-ins are done, so now we can send
 * the log request.
 *
 * \param gc_batch The control structure for the batch.
 */
void nuvo_gc_send_log_req(struct nuvo_gc_batch *gc_batch, enum nuvo_gc_block_type type)
{
    struct nuvo_log_request *log_req = &gc_batch->move_data.bunch[type].log_req;
    struct nuvo_gc          *gc = gc_batch->gc;

    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_LOG(space, 40, "nuvo_gc_send_log_req " NUVO_LOG_UUID_FMT ", type %d segment (%d, %d) %p",
             NUVO_LOG_UUID(gc->vol->vs_uuid), type, gc->segment->parcel_index, gc->segment->block_offset, gc_batch);
    log_req->operation = NUVO_LOG_OP_GC;
    log_req->atomic = true;
    log_req->tag.ptr = gc_batch;
    log_req->vs_ptr = gc->vol;
    log_req->data_class = gc->segment->data_class;   // For now move to same class.
    log_req->block_count = gc_batch->move_data.bunch[type].blocks_moving;
    log_req->callback = nuvo_gc_log_req_cb;
    log_req->cache_hint = (type == NUVO_GC_BLOCK_HOT ? NUVO_CACHE_DEFAULT : NUVO_CACHE_NONE);

    for (uint_fast16_t i = 0; i < gc_batch->move_data.bunch[type].blocks_moving; i++)
    {
        struct nuvo_segment_summary_entry *summary_entry = &gc->digest.table[gc_batch->move_data.bunch[type].boffset_moved[i]];
        log_req->log_io_blocks[i].data = gc_batch->move_data.data_bufs[gc_batch->move_data.bunch[type].boffset_moved[i] - gc_batch->move_data.first_boffset];
        log_req->log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req->log_io_blocks[i].pit_info = summary_entry->data.pit_info;
        log_req->log_io_blocks[i].bno = summary_entry->data.bno;
        log_req->log_io_blocks[i].gc_block_hash = summary_entry->block_hash;
        log_req->log_io_blocks[i].gc_media_addr.parcel_index = gc->segment->parcel_index;
        log_req->log_io_blocks[i].gc_media_addr.block_offset = gc->segment->block_offset + gc_batch->move_data.bunch[type].boffset_moved[i];
    }
    gc->stats.data_writes++;
    gc->stats.data_blocks_written += gc_batch->move_data.bunch[type].blocks_moving;
    nuvo_mutex_unlock(&gc->gc_mutex);
    NUVO_LOG(space, 20, "nuvo_gc_send_log_req batch %p type %d count: %u", gc_batch, type, log_req->block_count);
    nuvo_log_submit(log_req);
}

/*
 * \brief All of the data reads for the batch are done.
 *
 * \param par_io The batch of parallel reads.
 */
void nuvo_gc_move_data_par_cb(struct nuvo_parallel_io *par_io)
{
    NUVO_ASSERT(par_io->status == 0);  // TODO Don't handle errors yet.
    struct nuvo_gc_batch *gc_batch = nuvo_containing_object(par_io, struct nuvo_gc_batch, move_data.par_io);
    struct nuvo_gc       *gc = gc_batch->gc;
    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_LOG(space, 50, "nuvo_gc_move_data_par_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    nuvo_pr_parallel_destroy(par_io);
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_MOVING_DATA);

    // Copy boffset_moved into separate arrays for hot and cold blocks
    prep_types(gc_batch);
    gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].done = gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].blocks_moving > 0 ? false : true;
    gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].done = gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].blocks_moving > 0 ? false : true;
    nuvo_mutex_unlock(&gc->gc_mutex);

    // Start the map faulting
    if (gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].blocks_moving > 0)
    {
        map_faulting(gc_batch, NUVO_GC_BLOCK_HOT);
    }
    if (gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].blocks_moving > 0)
    {
        map_faulting(gc_batch, NUVO_GC_BLOCK_COLD);
    }

    nuvo_mutex_lock(&gc->gc_mutex);
    if (gc->boffset < gc->digest.footer.used_block_count)
    {
        // Need to issue more moving.
        nuvo_gc_needs_work(gc);
    }
    nuvo_mutex_unlock(&gc->gc_mutex);
}

/**
 * \brief A single map fault in for hot data moving has returned.
 *
 * Not really anything to do since we have to wait for all the maps and all the reads.
 *
 * \param map_req The map request.
 */
void nuvo_gc_move_data_map_par_hot_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_gc_map_info *map_info = map_req->tag.ptr;
    struct nuvo_gc          *gc = map_info->gc_batch->gc;

    NUVO_LOG(space, 50, "nuvo_gc_move_data_par_hot_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    NUVO_ASSERT(&map_info->map_req == map_req);
    if (map_req->status < 0)
    {
        NUVO_ERROR_PRINT_ERRNO(map_req->status, "Map request failed");
    }
    nuvo_parallel_op_done(&map_info->gc_batch->move_data.hot_par_ops, map_req->status);
}

/**
 * \brief A single map fault in for cold data moving has returned.
 *
 * Not really anything to do since we have to wait for all the maps and all the reads.
 *
 * \param map_req The map request.
 */
void nuvo_gc_move_data_map_par_cold_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_gc_map_info *map_info = map_req->tag.ptr;
    struct nuvo_gc          *gc = map_info->gc_batch->gc;

    NUVO_LOG(space, 50, "nuvo_gc_move_data_par_cold_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    NUVO_ASSERT(&map_info->map_req == map_req);
    if (map_req->status < 0)
    {
        NUVO_ERROR_PRINT_ERRNO(map_req->status, "Map request failed");
    }
    nuvo_parallel_op_done(&map_info->gc_batch->move_data.cold_par_ops, map_req->status);
}

/**
 * \brief The batch of map fault ins for rewriting hot data is done.
 *
 * Send the write to the log.
 *
 * \param par_ops The parallel map ops doing the fault-in.
 */
void nuvo_gc_move_data_map_par_batch_done_hot(struct nuvo_parallel_op *par_ops)
{
    NUVO_ASSERT(par_ops->status == 0);  // TODO Don't handle errors yet.
    struct nuvo_gc_batch *gc_batch = nuvo_containing_object(par_ops, struct nuvo_gc_batch, move_data.hot_par_ops);
    struct nuvo_gc       *gc = gc_batch->gc;
    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_LOG(space, 50, "nuvo_gc_move_data_map_par_batch_done_hot " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    nuvo_parallel_op_destroy(par_ops);
    nuvo_mutex_unlock(&gc->gc_mutex);
    nuvo_gc_send_log_req(gc_batch, NUVO_GC_BLOCK_HOT);
}

void nuvo_gc_move_data_map_par_batch_done_cold(struct nuvo_parallel_op *par_ops)
{
    NUVO_ASSERT(par_ops->status == 0);  // TODO Don't handle errors yet.
    struct nuvo_gc_batch *gc_batch = nuvo_containing_object(par_ops, struct nuvo_gc_batch, move_data.cold_par_ops);
    struct nuvo_gc       *gc = gc_batch->gc;
    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_LOG(space, 50, "nuvo_gc_move_data_map_par_batch_done_cold " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    nuvo_parallel_op_destroy(par_ops);
    nuvo_mutex_unlock(&gc->gc_mutex);
    nuvo_gc_send_log_req(gc_batch, NUVO_GC_BLOCK_COLD);
}

/* Documented in header */
nuvo_return_t nuvo_gc_move_data_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_MOVING_DATA);

    gc_batch->gc = gc;
    for (int i = 0; i < NUVO_GC_DATA_BLOCKS_READ_MAX; i++)
    {
        gc_batch->move_data.cached[i] = false;
    }

    NUVO_LOG(space, 20, "nuvo_gc_move_data_batch " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    gc->gc_batches_outstanding++;

    uint_fast16_t boffset = gc->boffset;  // Store new value back into gc->boffset before we release gc lock.

    // Advance to first block to move.
    while (boffset < gc->digest.footer.used_block_count && gc->block_state[boffset] != NUVO_GC_BLOCK_MOVE_DATA)
    {
        boffset++;
    }
    if (boffset == gc->digest.footer.used_block_count)
    {
        NUVO_ASSERT(boffset == gc->digest.footer.used_block_count);
        gc->boffset = boffset;
        gc->gc_batches_outstanding--;
        nuvo_gc_batch_free(gc_batch);
        if (gc->gc_batches_outstanding == 0)
        {
            nuvo_gc_data_possibly_done(gc);
        }
        nuvo_mutex_unlock(&gc->gc_mutex);
        return (0);
    }

    /**
     * Before we init the pr below, we figure out which blocks we are moving.
     * gc_batch->move_data.first_boffset will be the first block we read.
     * gc_batch->move_data.boffsets_used will be the number we read.
     * gc_batch->move_data.blocks_moving will be the number of blocks we are moving.
     *
     * boffset moves forward to at least first_boffset + boffsets_used and possibly further
     * since there may be blocks at the end we know we don't need to move.
     *
     * blocks_moving may be less than boffsets_used minus first_boffset + 1 since
     * there may be blocks in the middle we don't want to move.
     */
    gc_batch->move_data.first_boffset = boffset;
    uint_fast16_t last_boffset_moved = boffset;
    gc_batch->move_data.blocks_moving = 0;
    gc_batch->move_data.maps_used = 0;
    while (boffset < gc->digest.footer.used_block_count &&
           gc_batch->move_data.blocks_moving < NUVO_GC_DATA_BLOCK_NUM_MAX &&
           gc_batch->move_data.maps_used < NUVO_GC_MAP_REQS_PARALLEL &&
           boffset - gc_batch->move_data.first_boffset < NUVO_GC_DATA_BLOCKS_READ_MAX)
    {
        if (gc->block_state[boffset] == NUVO_GC_BLOCK_MOVE_DATA)
        {
            // Want to move this block.
            NUVO_ASSERT(gc->digest.table[boffset].log_entry_type == NUVO_LE_DATA);
            gc_batch->move_data.boffset_moved[gc_batch->move_data.blocks_moving] = boffset;
            gc_batch->move_data.blocks_moving++;

            // We'll coalesce sequential blocks within a pit into one map request.
            if (gc_batch->move_data.blocks_moving == 1)
            {
                NUVO_ASSERT(gc_batch->move_data.maps_used == 0);
                gc_batch->move_data.maps_used = 1;
            }
            else
            {
                if (gc->digest.table[boffset].data.pit_info.active != gc->digest.table[last_boffset_moved].data.pit_info.active ||
                    gc->digest.table[boffset].data.pit_info.pit_id != gc->digest.table[last_boffset_moved].data.pit_info.pit_id ||
                    gc->digest.table[boffset].data.bno != gc->digest.table[last_boffset_moved].data.bno + 1)
                {
                    gc_batch->move_data.maps_used++;
                }
            }
            last_boffset_moved = boffset;
        }
        boffset++;
    }
    gc_batch->move_data.boffsets_used = last_boffset_moved - gc_batch->move_data.first_boffset + 1;
    NUVO_ASSERT(gc_batch->move_data.blocks_moving > 0);
    NUVO_ASSERT(gc_batch->move_data.maps_used > 0);
    NUVO_ASSERT(gc_batch->move_data.blocks_moving <= gc_batch->move_data.boffsets_used);
    NUVO_ASSERT(gc_batch->move_data.first_boffset + gc_batch->move_data.boffsets_used <= boffset);
    gc->boffset = boffset;

    // We know how many blocks we are going to read, how many read ios and how many map requests.
    // TODO we could do a reservation call here is such things existed.  It doesn't.  Let's roll.
    gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].done = false;
    gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].done = false;

    nuvo_return_t rc = nuvo_pr_parallel_init(&gc_batch->move_data.par_io);
    if (rc != 0)
    {
        NUVO_PANIC("Initializing par_io failed.");
    }
    gc_batch->move_data.par_io.callback = nuvo_gc_move_data_par_cb;
    gc_batch->move_data.par_io.tag.ptr = gc_batch;

    nuvo_pr_sync_buf_alloc_list(gc_batch->move_data.data_bufs, gc_batch->move_data.boffsets_used, &gc_batch->sync_signal);

    // Now we are going to do a batch of reads.  Keep adding to the
    // batch until we have filled the batch.
    uint_fast16_t blocks_read = 0;
    int           read_count = 0;
    while (blocks_read < gc_batch->move_data.boffsets_used)
    {
        unsigned n = gc_batch->move_data.boffsets_used - blocks_read;
        n = MIN(n, NUVO_MAX_IO_BLOCKS);

        // Setup the read.
        struct nuvo_io_request *io_req = nuvo_pr_sync_client_req_alloc(&gc_batch->sync_signal);
        // Need n buffers
        NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ_VERIFY, NUVO_IO_ORIGIN_GC_DATA);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_NONE); // Don't cache read from old location
        io_req->rw.vol = gc->vol;
        io_req->rw.parcel_desc = gc->segment->parcel_desc;
        io_req->rw.block_offset = gc->segment->block_offset + gc_batch->move_data.first_boffset + blocks_read;
        io_req->rw.block_count = n;
        io_req->rw.cache_result = &gc_batch->move_data.cached[blocks_read]; // Location to store whether read is a cache hit
        for (uint_fast32_t i = 0; i < n; i++)
        {
            io_req->rw.iovecs[i].iov_base = gc_batch->move_data.data_bufs[blocks_read + i];
            io_req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            io_req->rw.block_hashes[i] = gc->digest.table[gc_batch->move_data.first_boffset + blocks_read + i].block_hash;
        }

        // Send the read.
        gc->stats.data_reads++;
        gc->stats.data_blocks_read += n;
        nuvo_mutex_unlock(&gc->gc_mutex);
        nuvo_pr_parallel_submit(&gc_batch->move_data.par_io, io_req);
        read_count++;
        nuvo_mutex_lock(&gc->gc_mutex);
        blocks_read += n;
    }

    nuvo_mutex_unlock(&gc->gc_mutex);
    nuvo_pr_parallel_finalize(&gc_batch->move_data.par_io);
    return (gc_batch->move_data.blocks_moving);
}

/**
 * \brief A single fault-in call to prepare to move a map has completed.
 *
 * Since the fault-in is done we can do the simple call telling the map to write out the map
 * block in the next CP.
 *
 * \param map_req The map fault-in request.
 */
void nuvo_gc_move_maps_cb(struct nuvo_map_request *map_req)
{
    struct nuvo_gc_map_info *map_info = map_req->tag.ptr;
    struct nuvo_gc          *gc = map_info->gc_batch->gc;

    NUVO_LOG(space, 50, "nuvo_gc_move_maps_cb " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    NUVO_ASSERT(&map_info->map_req == map_req);
    if (map_req->status >= 0)
    {
        nuvo_map_rewrite(map_req);
    }
    else
    {
        NUVO_ERROR_PRINT_ERRNO(map_req->status, "Map request failed");
    }

    nuvo_parallel_op_done(&map_info->gc_batch->move_maps.par_ops, map_req->status);
}

/**
 * \brief A batch of map moves is done.
 *
 * If all of the batches are done move to the next state.
 *
 * The callback is for unit testing purposes only.
 * \param par_ops The parallel map ops.
 */
void nuvo_gc_move_maps_batch_done(struct nuvo_parallel_op *par_ops)
{
    NUVO_ASSERT(par_ops->status == 0);  // TODO Don't handle errors yet.
    struct nuvo_gc_batch *gc_batch = nuvo_containing_object(par_ops, struct nuvo_gc_batch, move_maps.par_ops);
    struct nuvo_gc       *gc = gc_batch->gc;
    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_LOG(space, 40, "nuvo_gc_move_maps_batch_done " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    nuvo_parallel_op_destroy(par_ops);
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_MOVE_MAPS);
    gc->gc_batches_outstanding--;
    if (0 == gc->gc_batches_outstanding && gc->boffset == gc->digest.footer.used_block_count)
    {
        gc->state = NUVO_SPACE_GC_MOVING_DONE;
        gc->boffset = 0;
        nuvo_gc_needs_work(gc);
    }
    nuvo_gc_batch_free(gc_batch);
    nuvo_mutex_unlock(&gc->gc_mutex);
    if (gc->phase_callback != NULL)
    {
        gc->phase_callback(gc);
    }
}

/* Commented in header */
nuvo_return_t nuvo_gc_move_maps_batch(struct nuvo_gc *gc, struct nuvo_gc_batch *gc_batch)
{
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_MOVE_MAPS);
    struct nuvo_parallel_op *par_ops = &gc_batch->move_maps.par_ops;
    nuvo_return_t            rc = nuvo_parallel_op_init(par_ops);
    NUVO_ASSERT(rc >= 0); // TODO handle errors
    par_ops->callback = nuvo_gc_move_maps_batch_done;
    gc_batch->gc = gc;
    nuvo_mutex_lock(&gc->gc_mutex);
    NUVO_LOG(space, 40, "nuvo_gc_move_maps_batch " NUVO_LOG_UUID_FMT ", segment (%d, %d)",
             NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset);

    gc_batch->move_maps.maps_used = 0;
    unsigned maps_moved = 0;
    gc->gc_batches_outstanding++;
    while (gc->boffset < gc->digest.footer.used_block_count && gc_batch->move_maps.maps_used < NUVO_GC_MAP_REQS_PARALLEL)
    {
        if (NUVO_LE_MAP(gc->digest.table[gc->boffset].log_entry_type) && gc->digest.table[gc->boffset].log_entry_type < NUVO_LE_MAP_L3)  // TODO - HANDLE THE TOP LEVEL CASE
        {
            uint32_t lun_id = gc->digest.table[gc->boffset].data.pit_info.active ? NUVO_MFST_ACTIVE_LUN_SNAPID : gc->digest.table[gc->boffset].data.pit_info.pit_id;
            if (lun_id >= gc->lowest_map_pit_id)
            {
                struct nuvo_lun *lun = nuvo_get_lun_by_snapid(gc->vol, lun_id, false);
                NUVO_ASSERT(lun != NULL);  // Our current pinning strategy relies on completing deletions from oldest to youngest.
                struct nuvo_gc_map_info *gc_map_info = &gc_batch->move_maps.map_info[gc_batch->move_maps.maps_used];
                gc_map_info->gc_batch = gc_batch;
                gc_map_info->map_index = gc->boffset;
                struct nuvo_map_request *map_req = &gc_map_info->map_req;
                nuvo_map_rewrite_init(map_req, lun, gc->digest.table[gc->boffset].data.bno, gc->digest.table[gc->boffset].log_entry_type - NUVO_LE_MAP_L0);
                nuvo_map_reserve_sync(map_req);

                map_req->map_entries = &gc_batch->move_maps.old_map_entries[gc_batch->move_maps.maps_used];
                map_req->map_entries[0].type = NUVO_ME_MEDIA;
                map_req->map_entries[0].media_addr.parcel_index = gc->segment->parcel_index;
                map_req->map_entries[0].media_addr.block_offset = gc->segment->block_offset + gc->boffset;
                map_req->map_entries[0].hash = gc->digest.table[gc->boffset].block_hash;

                map_req->callback = nuvo_gc_move_maps_cb;
                map_req->tag.ptr = gc_map_info;
                nuvo_parallel_op_submitting(par_ops);
                nuvo_map_fault_in(map_req);
                gc_batch->move_maps.maps_used++;
                maps_moved++;
            }
        }
        gc->boffset++;
    }
    if (maps_moved == 0)
    {
        NUVO_ASSERT(gc->boffset == gc->digest.footer.used_block_count);
        nuvo_parallel_op_destroy(par_ops);
        // Actually ended up with nothing to do.
        gc->gc_batches_outstanding--;
        nuvo_gc_batch_free(gc_batch);
        if (gc->gc_batches_outstanding == 0)
        {
            gc->boffset = 0;
            gc->state = NUVO_SPACE_GC_MOVING_DONE;
            nuvo_gc_needs_work(gc);
        }
        nuvo_mutex_unlock(&gc->gc_mutex);
        return (0);
    }
    else
    {
        if (gc->boffset < gc->digest.footer.used_block_count)
        {
            nuvo_gc_needs_work(gc);
        }
        nuvo_mutex_unlock(&gc->gc_mutex);
        nuvo_parallel_op_finalize(par_ops);
        return (maps_moved);
    }
}

void nuvo_gc_verify_data_moved_lun_fault_cb(struct nuvo_map_request *map_req)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)map_req->tag.ptr);
}

/*
 * Make sure every block has been moved.
 */
void nuvo_gc_verify_data_moved_lun(struct nuvo_gc *gc, struct nuvo_lun *lun)
{
    // Assert lun is pinned.
    nuvo_mutex_t sync_signal;

    nuvo_mutex_init(&sync_signal);

    for (unsigned boffset = 0; boffset < gc->digest2.footer.used_block_count; boffset++)
    {
        if (gc->digest2.table[boffset].log_entry_type != NUVO_LE_DATA)
        {
            continue;
        }
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, lun, gc->digest2.table[boffset].data.bno, 1);
        nuvo_map_reserve_sync(&map_req);
        nuvo_mutex_lock(&sync_signal);
        map_req.callback = nuvo_gc_verify_data_moved_lun_fault_cb;
        map_req.tag.ptr = &sync_signal;
        nuvo_map_fault_in(&map_req);
        nuvo_mutex_lock(&sync_signal);
        nuvo_mutex_unlock(&sync_signal);

        struct nuvo_map_entry entry;
        uint_fast32_t         pds[NUVO_MAX_IO_BLOCKS];
        nuvo_map_read_and_pin_sync(&map_req, false, &entry, pds);
        if (entry.type == NUVO_ME_MEDIA &&
            entry.media_addr.parcel_index == gc->segment->parcel_index &&
            entry.media_addr.block_offset == gc->segment->block_offset + boffset)
        {
            nuvo_gc_decision_print(gc, boffset);
            NUVO_PANIC("Block still in use!");
        }
    }
}

void nuvo_gc_verify_data_moved(struct nuvo_gc *gc)
{
    uint_fast32_t lun_count = NUVO_ARRAY_LENGTH(gc->vol->log_volume.lun_list);

    for (uint_fast32_t i = 1; i < lun_count; i++)
    {
        struct  nuvo_lun *lun = &gc->vol->log_volume.lun_list[i];

        if (lun->lun_state != NUVO_LUN_STATE_VALID && lun->lun_state != NUVO_LUN_STATE_DELETING)
        {
            continue;
        }
        nuvo_gc_verify_data_moved_lun(gc, lun);
    }
}

/* Commented in header */
void nuvo_gc_done(struct nuvo_gc *gc)
{
    NUVO_ASSERT(gc->state == NUVO_SPACE_GC_MOVING_DONE);
    struct nuvo_vol       *vol = gc->vol;
    struct nuvo_space_vol *space_vol = &vol->log_volume.space;

    nuvo_gc_verify_data_moved(gc);
    if (gc->moving_callback)
    {
        gc->moving_callback(gc);
    }

    if (gc->pinned_lun != NULL)
    {
        nuvo_mutex_lock(&gc->pinned_lun->mutex);
        nuvo_lun_unpin(gc->pinned_lun);
        nuvo_mutex_unlock(&gc->pinned_lun->mutex);
        gc->pinned_lun = NULL;
    }

    nuvo_mutex_lock(&space_vol->space_vol_mutex);
    space_vol->gc_data_class[gc->segment->data_class].gc_in_progress--;

    if (!gc->no_cp)
    {
        NUVO_ASSERT(gc->actives_failed == 0);
        NUVO_LOG(space, 20, "nuvo_gc_done " NUVO_LOG_UUID_FMT ", segment (%d, %d), read %u blocks in %u IOs and wrote %d blocks in %d IOs, %d block moves sent (%u reinits, %u actives failed)",
                 NUVO_LOG_UUID(gc->vol->vs_uuid), gc->segment->parcel_index, gc->segment->block_offset,
                 gc->stats.data_blocks_read, gc->stats.data_reads,
                 gc->stats.data_blocks_written, gc->stats.data_writes,
                 gc->stats.data_block_moves,
                 gc->stats.reinits, gc->stats.actives_failed);

        uint16_t pending = nuvo_mfst_gc_free_next_cp(&vol->log_volume.mfst, gc->segment);
        gc->segment = NULL;
        gc->state = NUVO_SPACE_GC_UNUSED;
        nuvo_gc_free(gc);
        nuvo_mutex_unlock(&space_vol->space_vol_mutex);
        if (pending >= NUVO_GC_SEGMENTS_PER_CP)
        {
            nuvo_space_trigger_cp(space_vol);  // Would be nice if we could do this inside the lock.
        }
    }
    else
    {
        NUVO_LOG(space, 0, "Returning gc segment without triggering CP.");
        nuvo_space_vol_segment_done(space_vol, gc->segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);   // Don't clear the age.
        gc->segment = NULL;
        nuvo_gc_free(gc);
        nuvo_mutex_unlock(&space_vol->space_vol_mutex);
    }
}

/**
 * When this is called, the data reads are done and the cached array is filled in
 */
void map_faulting(struct nuvo_gc_batch *gc_batch, enum nuvo_gc_block_type type)
{
    struct nuvo_gc *gc = gc_batch->gc;

    nuvo_mutex_lock(&gc->gc_mutex);

    NUVO_LOG(space, 20, "map_faulting gc_batch: %p type: %d", gc_batch, type);
    // Now start the map faulting.
    struct nuvo_parallel_op *par_ops = (type == NUVO_GC_BLOCK_HOT) ? &gc_batch->move_data.hot_par_ops : &gc_batch->move_data.cold_par_ops;
    nuvo_parallel_op_init(par_ops);
    par_ops->callback = (type == NUVO_GC_BLOCK_HOT ? nuvo_gc_move_data_map_par_batch_done_hot : nuvo_gc_move_data_map_par_batch_done_cold);
    par_ops->tag.ptr = gc_batch;
    uint_fast16_t blocks_used = 0;
    uint_fast16_t maps_used = 0;
    gc_batch->move_data.bunch[type].maps_used = 0;
    NUVO_ASSERT(gc_batch->move_data.bunch[type].blocks_moving <= NUVO_GC_DATA_BLOCK_NUM_MAX);
    while (blocks_used < gc_batch->move_data.bunch[type].blocks_moving)
    {
        unsigned            n = 1;
        struct log_pit_info base_pit_info = gc->digest.table[gc_batch->move_data.bunch[type].boffset_moved[blocks_used]].data.pit_info;
        uint64_t            base_bno = gc->digest.table[gc_batch->move_data.bunch[type].boffset_moved[blocks_used]].data.bno;

        while (blocks_used + n < gc_batch->move_data.bunch[type].blocks_moving &&
               gc->digest.table[gc_batch->move_data.bunch[type].boffset_moved[blocks_used + n]].data.pit_info.active == base_pit_info.active &&
               gc->digest.table[gc_batch->move_data.bunch[type].boffset_moved[blocks_used + n]].data.pit_info.pit_id == base_pit_info.pit_id &&
               gc->digest.table[gc_batch->move_data.bunch[type].boffset_moved[blocks_used + n]].data.bno == base_bno + n)
        {
            n++;
        }
        struct nuvo_gc_map_info *gc_map_info = &gc_batch->move_data.bunch[type].map_info[maps_used];
        gc_map_info->gc_batch = gc_batch;
        gc_map_info->map_index = gc->boffset;
        struct nuvo_map_request *map_req = &gc_map_info->map_req;

        uint32_t         base_lun_id = base_pit_info.active ? NUVO_MFST_ACTIVE_LUN_SNAPID : base_pit_info.pit_id;
        struct nuvo_lun *lun = nuvo_get_lun_by_snapid(gc->vol, base_lun_id, false);
        NUVO_ASSERT(lun != 0);
        nuvo_map_request_init(map_req, lun, base_bno, n);
        map_req->op = NUVO_MAP_REQUEST_OP_GC;
        // TODO Doing reserve like this invites deadlocks.
        nuvo_map_reserve_sync(map_req);
        nuvo_parallel_op_submitting(par_ops);
        map_req->callback = (type == NUVO_GC_BLOCK_HOT) ? nuvo_gc_move_data_map_par_hot_cb : nuvo_gc_move_data_map_par_cold_cb;
        map_req->tag.ptr = gc_map_info;

        nuvo_mutex_unlock(&gc->gc_mutex);
        nuvo_map_fault_in(map_req);
        nuvo_mutex_lock(&gc->gc_mutex);

        blocks_used += n;
        maps_used++;
    }

    gc_batch->move_data.bunch[type].maps_used = maps_used;
    gc_batch->move_data.bunch[type].blocks_used = blocks_used;

    nuvo_mutex_unlock(&gc->gc_mutex);

    nuvo_parallel_op_finalize(par_ops);
}

/**
 * Go through the cached array, and separate boffset into hot and cold bunches
 */
void prep_types(struct nuvo_gc_batch *gc_batch)
{
    NUVO_ASSERT(gc_batch->move_data.blocks_moving <= NUVO_GC_DATA_BLOCK_NUM_MAX);
    uint_fast16_t blocks_moving_hot = 0;
    uint_fast16_t blocks_moving_cold = 0;

    for (uint_fast16_t i = 0; i < gc_batch->move_data.blocks_moving; i++)
    {
        uint_fast16_t rd_offset = gc_batch->move_data.boffset_moved[i] - gc_batch->move_data.first_boffset;
        // For each block that we want to move, see if it is currently cached
        if (gc_batch->move_data.cached[rd_offset])
        {
            gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].boffset_moved[blocks_moving_hot] = gc_batch->move_data.boffset_moved[i];
            blocks_moving_hot++;
        }
        else
        {
            gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].boffset_moved[blocks_moving_cold] = gc_batch->move_data.boffset_moved[i];
            blocks_moving_cold++;
        }
    }

    gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].blocks_moving = blocks_moving_hot;
    gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].blocks_moving = blocks_moving_cold;

    NUVO_LOG(space, 40, "prep_types gc_batch %p first_boffset %u blocks_moving %u hot %u, cold %u", gc_batch,
             gc_batch->move_data.first_boffset, gc_batch->move_data.blocks_moving,
             gc_batch->move_data.bunch[NUVO_GC_BLOCK_HOT].blocks_moving,
             gc_batch->move_data.bunch[NUVO_GC_BLOCK_COLD].blocks_moving);
}
