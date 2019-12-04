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

/**
 * @file replay.c
 * @brief Implements log replay
 */


#include <stdio.h>
#include <stdlib.h>
#include "nuvo_pr.h"
#include "logger.h"
#include "replay.h"
#include "space.h"
#include "nuvo_vol_series.h"
#include "log_volume.h"
#include "map_replay.h"
#include "fault_inject.h"

bool find_next_log_operation(struct nuvo_logger *logger, struct logger_segment *log_segment);
void rebuild_segment_digest(struct nuvo_logger *logger, struct logger_segment *log_segment, struct iovec *iovecs, nuvo_hash_t *block_hashes, uint32_t block_count, uint32_t segment_block_index);
void nuvo_map_replay(struct nuvo_log_request *log_req);

extern inline uint32_t segment_offset_to_index(struct nuvo_segment *segment, uint32_t block_offset);
extern inline uint32_t segment_index_to_offset(struct nuvo_segment *segment, uint32_t block_index);

#define NUVO_IS_DATA_OR_MAP_ENTRY(e)           ((e >= NUVO_LE_DATA && e <= NUVO_LE_MAP_L4) ? 1 : 0)
#define NUVO_IS_MAP_ENTRY(e)                   ((e >= NUVO_LE_MAP_L0 && e <= NUVO_LE_MAP_L4) ? 1 : 0)
#define NUVO_ROUND_DOWN_TO_MAX_IO_BLOCKS(x)    ((x <= NUVO_MAX_IO_BLOCKS) ? x : NUVO_MAX_IO_BLOCKS)

/**
 *@brief Verify the internal hash of a segment block
 *
 *@param block A segment header, log descriptor, or fork block
 *@return True if the hash is valid, otherwise False.
 */
static inline bool internal_hash_compare(struct nuvo_segment_header *block)
{
    nuvo_hash_t orig_block_hash = block->block_hash;

    block->block_hash = 0;
    nuvo_hash_t block_hash = nuvo_hash(block, NUVO_BLOCK_SIZE);
    block->block_hash = orig_block_hash;

    return (block_hash == orig_block_hash);
}

/**
 *@brief Check if segment is in the list of log starts given to start replay
 *
 * @param logger The logger state.
 * @param segment The segment to search for.
 * @return True if the segment was replay log start, otherwise false.
 */
static inline bool is_replay_log_start_segment(struct nuvo_logger *logger, struct nuvo_segment *segment)
{
    bool log_start_flag = false;

    for (uint32_t i = 0; i < logger->replay_req->segment_count; i++)
    {
        if ((segment->parcel_index == logger->replay_req->replay_segments[i].parcel_index) &&
            (segment->block_offset == logger->replay_req->replay_segments[i].block_offset))
        {
            log_start_flag = true;
            break;
        }
    }
    return (log_start_flag);
}

/**
 * @brief Free the given log request
 *
 * Puts the given log request back on the free list.
 *
 * @param logger The logger state.
 * @param log_req The log request to be freed.
 * @return None.
 */
void nuvo_log_request_free(struct nuvo_logger *logger, struct nuvo_log_request *log_req)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_req != NULL);

    nuvo_mutex_lock(&logger->replay_log_request_structs_mutex);
    nuvo_dlist_insert_tail(&logger->replay_log_request_structs.free_log_reqs, &log_req->list_node);
    nuvo_mutex_unlock(&logger->replay_log_request_structs_mutex);
}

/**
 * @brief Allocate a log request for replay
 *
 * Allocates a nuvo_log_request struct from the free list if one is available.
 *
 * @param logger The logger state.
 * @return A pointer to a nuvo_log_request struct, otherwise NULL if no free log requests are available.
 */
struct nuvo_log_request *nuvo_log_request_alloc(struct nuvo_logger *logger)
{
    NUVO_ASSERT(logger != NULL);

    nuvo_mutex_lock(&logger->replay_log_request_structs_mutex);
    struct nuvo_log_request *log_req;
    log_req = nuvo_dlist_remove_head_object(&logger->replay_log_request_structs.free_log_reqs, struct nuvo_log_request, list_node);
    nuvo_mutex_unlock(&logger->replay_log_request_structs_mutex);

    return (log_req);
}

/**
 * @brief Find log operations requiring replay.
 *
 * This is the main loop which drives replay.
 * do_replay() looks at each segment in replay state and calls find_next_log_operation() to find the
 * log operation with the next sequence number required for replay.
 * The loop will continue for as long there are log operations found that can be replayed, and log request resources are available
 * for them to be enqueued, or there are no more log operations which can be replayed pending io.
 *
 * After a new segment digest is read, do_replay() is called to continue the replay operations.
 *
 * @param logger The logger state.
 * @return None.
 */
void do_replay(struct nuvo_logger *logger)
{
    bool replay_flag;

    NUVO_ASSERT_MUTEX_HELD(&logger->open_data_segments_mutex);
    do
    {
        replay_flag = false;
        for (uint32_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
        {
            if ((logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_DATA].open_count == 0) &&
                (logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_GC].open_count == 0))
            {
                // Skip this data class if nothing is currently open
                continue;
            }
            for (uint32_t i = 0; i < logger->open_data_segments[data_class].max_open_count; i++)
            {
                struct logger_segment *log_segment = &logger->open_data_segments[data_class].segments[i];
                if (log_segment && (log_segment->state == NUVO_SEGMENT_REPLAYING))
                {
                    if (find_next_log_operation(logger, log_segment))
                    {
                        replay_flag = true;
                    }
                }
            }
        }
    } while (replay_flag);
}

/**
 * @brief Set the segment index to the first transaction needed for replay.
 *
 * Examines the segment digest and finds the first transaction >= to the sequence number specified as
 * where to start replay. All log operations with sequence numbers that are not required for replay are
 * skipped, while advancing the current offset, last sequence no, and free block count in the segment
 * so that they reflect the offset and free block count in the segment as it was when the data was
 * originally written to the log.
 *
 * segment_replay_head_set() sets the lowest sequence number known to be in the segment that
 * is needed for replay, and updates the current_offset within the segment the offset of that
 * operation in the log.
 *
 * @param log_segment A segment with a valid digest.
 * @param replay_sequence_no The sequence number of the first operation needed for replay.
 * @return None.
 */
void segment_replay_head_set(struct logger_segment *log_segment, uint64_t replay_sequence_no)
{
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT(log_segment->digest->footer.sequence_no >= replay_sequence_no);
    uint32_t block_count = (get_segment_digest_offset(log_segment->segment) - log_segment->segment->block_offset);

    // Set the highest known sequence number known to be in this segment.
    // This is used during replay to identify the last log transaction present in the segment.
    log_segment->replay.highest_sequence_no = log_segment->digest->footer.sequence_no;

    // Iterate over the summary table and find the offset of the first operation for replay.
    struct nuvo_segment_summary_entry *summary_table = (struct nuvo_segment_summary_entry *)&log_segment->digest->table;
    for (uint32_t i = 0; i < block_count; i++)
    {
        if ((summary_table[i].log_entry_type == NUVO_LE_DESCRIPTOR && summary_table[i].descriptor.sequence_no >= replay_sequence_no) ||
            (summary_table[i].log_entry_type == NUVO_LE_FORK && summary_table[i].fork.sequence_no >= replay_sequence_no) ||
            (summary_table[i].log_entry_type == NUVO_LE_SNAP && summary_table[i].snap.sequence_no >= replay_sequence_no))
        {
            // Found a descriptor or a fork block with a sequence number requiring replay.
            // Adjust segment counters to mark this a starting point for replay in this segment
            switch (summary_table[i].log_entry_type)
            {
            case NUVO_LE_DESCRIPTOR:
                log_segment->replay.sequence_no = summary_table[i].descriptor.sequence_no;
                break;

            case NUVO_LE_FORK:
                log_segment->replay.sequence_no = summary_table[i].fork.sequence_no;
                break;

            case NUVO_LE_SNAP:
                log_segment->replay.sequence_no = summary_table[i].snap.sequence_no;
                break;

            default:
                NUVO_PANIC("invalid log entry type");
                break;
            }
            log_segment->current_offset = log_segment->segment->block_offset + i;         // The offset of the descriptor
            log_segment->free_block_count = (block_count - i) - NUVO_SEGMENT_FORK_BLOCKS; // Adjust the free blocks
            return;
        }
    }
}

/**
 * @brief Verifies that the segment digest is internally consistent
 *
 * Verifies the internal hash of the digest recorded in the footer block
 * and compares the block hashes of each block of the summary table against
 * those recorded in the footer.
 *
 * @param digest A pointer to the segment digest.
 * @param block_hashes Block hashes for each block of the segment digest on media.
 * @param digest_len The number of blocks in the digest.
 * @return True if the digest is valid, otherwise False.
 */
bool segment_digest_verify(struct nuvo_segment_digest *digest, nuvo_hash_t *block_hashes, uint32_t digest_len)
{
    struct nuvo_segment_footer        *footer = (struct nuvo_segment_footer *)&digest->footer;
    struct nuvo_segment_summary_entry *summary_table = (struct nuvo_segment_summary_entry *)&digest->table;

    // Verify the footer block
    if (footer->magic != NUVO_SEGMENT_FOOTER_MAGIC)
    {
        return (false);
    }

    // Verify the block hash
    nuvo_hash_t footer_hash = footer->block_hash;
    footer->block_hash = 0;
    if (footer_hash != nuvo_hash(footer, NUVO_BLOCK_SIZE))
    {
        return (false);
    }
    footer->block_hash = footer_hash;

    // Verify checksums of each block written in the summary table
    for (uint32_t j = 1; j < digest_len; j++)
    {
        if (block_hashes[j] != footer->block_hashes[j - 1])
        {
            return (false);
        }
    }

    // Verify first summary table entry is a segment header
    if (summary_table[0].log_entry_type != NUVO_LE_HEADER)
    {
        return (false);
    }

    return (true);
}

/**
 * @brief Verifies the internal structure of the given log descriptor blocks
 *
 * @param ld_blocks A pointer to block_count log descriptor blocks.
 * @param block_count The number of blocks in the log descriptor.
 * @return True if the log descriptor is valid, otherwise False.
 */
bool log_descriptor_verify(struct nuvo_log_descriptor_block **ld_blocks, uint32_t block_count)
{
    NUVO_ASSERT(block_count <= NUVO_MAX_LOG_DESCRIPTOR_BLOCKS);

    // Cycle through the blocks returned and make sure they're valid
    for (uint32_t i = 0; i < block_count; i++)
    {
        // Verify magic
        if (ld_blocks[i]->header.magic != NUVO_LOG_DESCRIPTOR_MAGIC)
        {
            return (false);
        }

        // Verify hash
        nuvo_hash_t block_hash = ld_blocks[i]->header.block_hash;
        ld_blocks[i]->header.block_hash = 0;
        if (block_hash != nuvo_hash(ld_blocks[i], NUVO_BLOCK_SIZE))
        {
            return (false);
        }
        ld_blocks[i]->header.block_hash = block_hash;

        // Verify the descriptor count
        uint32_t meta_block_count = (ld_blocks[i]->header.entry_count <= NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES) ? 1 : 2;
        if (meta_block_count != block_count)
        {
            return (false);
        }

        // If more than one block, make sure both sequence numbers match
        if ((i > 0) && (ld_blocks[i]->header.sequence_no != ld_blocks[i - 1]->header.sequence_no))
        {
            return (false);
        }

        // TODO verify the number of entries match the count in the header.
    }
    return (true);
}

/**
 * @brief Reads the requested number of blocks from the segment at the given offset.
 *
 * @param logger The logger state
 * @param log_segment The segment being read from.
 * @param segment_block_index The segment relative starting offset of the blocks read.
 * @param block_count The number of blocks to be read.
 * @return None.
 */
void read_segment_data(struct nuvo_logger *logger, struct logger_segment *log_segment, uint32_t segment_block_index, uint32_t block_count)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT(block_count <= NUVO_MAX_IO_BLOCKS);

    struct segment_io_req *seg_req = &log_segment->segment_req;
    memset(seg_req, 0, sizeof(struct segment_io_req));

    seg_req->op = NUVO_SEGMENT_OP_READ_DATA;
    seg_req->sequence_no = 0;
    seg_req->parcel_index = log_segment->segment->parcel_index;
    seg_req->parcel_desc = log_segment->segment->parcel_desc;
    seg_req->block_count = block_count;
    seg_req->block_offset = segment_index_to_offset(log_segment->segment, segment_block_index);
    seg_req->meta_block_count = seg_req->block_count;
    seg_req->logger = logger;
    seg_req->log_segment = log_segment;
    seg_req->log_req = NULL;

    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    logger->pr_io_count++;
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    struct nuvo_pr_req_alloc *req_alloc = &seg_req->req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);
    req_alloc->tag.ptr = seg_req;
    req_alloc->callback = segment_buf_alloc;
    nuvo_pr_client_req_alloc_cb(req_alloc);
}

/** @brief Handle segment i/o completions.
 *
 * This function is called on every read i/o completion and processes the returned
 * data according to the operation type.
 *
 * <br>\b NUVO_SEGMENT_OP_READ_DIGEST. Verifies the digest, and starts replay. Otherwise starts
 * a new read operation to rebuild the digest from the log descriptors in the segment.
 * <br>\b NUVO_SEGMENT_OP_READ_DESCRIPTOR. Verifies the log descriptor, and assembles the map
 * entries required for replaying the associated log operation.
 * <br>\b NUVO_SEGMENT_OP_READ_DATA. Rebuilds the segment digest from the returned data. Starts
 * replay of the segment once rebuild is complete.<br>
 *
 * @param io_req The i/o request which completed.
 * @return None.
 */
void segment_read_complete(struct nuvo_io_request *io_req)
{
    struct segment_io_req *seg_req = io_req->tag.ptr;
    struct nuvo_logger    *logger = seg_req->logger;

    NUVO_ASSERT(seg_req != NULL);
    NUVO_ASSERT(logger != NULL);

    nuvo_mutex_lock(&logger->replay_queue_mutex);
    nuvo_mutex_lock(&logger->replay_callback_count_mutex);
    logger->replay_callback_count++;
    nuvo_mutex_unlock(&logger->replay_callback_count_mutex);
    nuvo_mutex_unlock(&logger->replay_queue_mutex);

    // Copy the status off the io_req
    seg_req->status = io_req->status;

    if (io_req->status < 0)
    {
        // TODO handle io errors, recover, rollback, etc.
        // The parcel manager will panic when an i/o failure is detected. fix this when it doesn't.
        NUVO_PANIC("%s: read failed: operation: %u  parcel offset: %lu:%lu length: %lu status: %ld \n", __func__, seg_req->op, io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_count, io_req->status);
    }
    if (seg_req->op == NUVO_SEGMENT_OP_READ_DIGEST)
    {
        NUVO_ASSERT(seg_req->log_segment != NULL);
        struct logger_segment      *log_segment = seg_req->log_segment;
        struct nuvo_segment_digest *digest = log_segment->digest;
        NUVO_ASSERT(io_req->rw.iovecs[0].iov_base == digest);

        log_segment->replay.has_digest = segment_digest_verify((struct nuvo_segment_digest *)io_req->rw.iovecs[0].iov_base, io_req->rw.block_hashes, io_req->rw.block_count);

        // Free the io_req. first null out the block pointer references in the iovec
        for (uint32_t i = 0; i < io_req->rw.block_count; i++)
        {
            io_req->rw.iovecs[i].iov_base = NULL;
        }
        nuvo_pr_client_req_free(io_req);

        // Replay reads the segment digest first. The segment digest is only written when the segment is closed so
        // it's possible that the segment being read has no digest, the segment has and old digest from an old volume, or
        // the segment has an old digest because it's being reclaimed after garbage collection.
        // The digest is checked for internal consistiency, the volume uuid is correct, and segment contains
        // sequence numbers needed for replay. Otherwise the segment digest is rebuilt from the segment log
        // descriptors.
        if (log_segment->replay.has_digest)
        {
            if (uuid_compare(digest->footer.vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid))
            {
                NUVO_LOG(logger, 20, "replay: segment %lu:%lu digest has unknown volume uuid. cross checking segment header.", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);
                read_segment_data(logger, log_segment, 0, NUVO_MAX_IO_BLOCKS);
            }
            else if (log_segment->digest->footer.sequence_no < logger->replay_req->sequence_no)
            {
                // The digest has lower sequence numbers than are required for replay.
                // This can happen if it's a reclaimed segment or was closed after the last CP without a new write.
                if ((log_segment->digest->footer.closing_sequence_no >= logger->replay_req->sequence_no) && is_replay_log_start_segment(logger, log_segment->segment))
                {
                    // This digest was written after the last CP so the digest must be current. The segment must be closed.
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu has nothing to replay, highest sequence no: %lu. closed at sequence no %lu. closing.", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->digest->footer.sequence_no, log_segment->digest->footer.closing_sequence_no);
                    nuvo_mutex_lock(&logger->open_data_segments_mutex);
                    close_segment(logger, log_segment, false);
                    process_segment_open_queue(logger);
                    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
                }
                else
                {
                    // The digest needs to be cross checked with the segment header sequence number.
                    // When has_digest is true, rebuild will only rebuild the digest if it's older than the segment header.
                    // If after rebuild it's confirmed the segment has nothing to replay it will be opened.
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu digest may not be current, highest sequence no: %lu. cross checking segment header.", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->digest->footer.sequence_no);
                    NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);
                    read_segment_data(logger, log_segment, 0, NUVO_MAX_IO_BLOCKS);
                }
            }
            else
            {
                // segment can be replayed from the existing digest
                NUVO_ASSERT(log_segment->segment->subclass == log_segment->digest->table->header.subclass);
                segment_replay_head_set(log_segment, logger->replay_req->sequence_no);
                NUVO_LOG(logger, 20, "replay: segment %lu:%lu digest verified. replaying sequence range: %lu - %lu", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->replay.sequence_no, log_segment->replay.highest_sequence_no);
                log_segment->state = NUVO_SEGMENT_REPLAYING;
            }
        }
        else
        {
            NUVO_LOG(logger, 20, "replay: segment %lu:%lu digest not found. rebuilding", log_segment->segment->parcel_index, log_segment->segment->block_offset);
            NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);
            read_segment_data(logger, log_segment, 0, NUVO_MAX_IO_BLOCKS);
        }
    }
    else if (seg_req->op == NUVO_SEGMENT_OP_READ_DESCRIPTOR)
    {
        NUVO_ASSERT(seg_req->log_req != NULL);
        struct nuvo_log_request          *replay_log_req = seg_req->log_req;
        struct nuvo_log_descriptor_block *ld_blocks[NUVO_MAX_LOG_DESCRIPTOR_BLOCKS];

        uint32_t parcel_index = seg_req->parcel_index;
        uint32_t block_count = seg_req->block_count;
        uint32_t data_block_offset = seg_req->block_offset + block_count;
        for (uint32_t i = 0; i < block_count; i++)
        {
            if (io_req->rw.block_hashes[i] != seg_req->read.block_hashes[i])
            {
                // hash of data read from media doesn't match the hash recorded in the summary table
                NUVO_PANIC("replay failed: invalid descriptor block at offset: %lu:%lu media hash %lu expected %lu",
                           io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_hashes[i], seg_req->read.block_hashes[i]);
            }
            ld_blocks[i] = io_req->rw.iovecs[i].iov_base;
        }
        // Create the map entries for replay from the log descriptor block(s) that were just read
        // first verifies the blocks read are valid log descriptor blocks
        // verifies that the sequence number in the log descriptor matches the summary table
        // creates map entries from the log descriptor block.
        // If the logger needs to read a log descriptor from media to get constant values
        // and the descriptor returned can't be used then panic.
        if (!log_descriptor_verify(ld_blocks, block_count))
        {
            // the log descriptor is invalid
            NUVO_PANIC("replay failed: invalid log descriptor at offset: %lu:%lu length: %lu",
                       io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_count);
        }

        // verify the sequence number matches the one requested on the read
        if (ld_blocks[0]->header.sequence_no != replay_log_req->sequence_tag.uint)
        {
            NUVO_PANIC("replay failed: invalid sequence no: %lu expected: %lu  offset: %lu:%lu length: %lu",
                       ld_blocks[0]->header.sequence_no, replay_log_req->sequence_tag.uint,
                       io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_count);
        }

        // build the map entries needed to complete the log request for replay
        uint32_t entry_idx = 0;
        for (uint32_t i = 0; i < block_count; i++)
        {
            for (uint32_t j = 0; j < NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES; j++)
            {
                struct nuvo_log_descriptor_entry *ld_entry = &ld_blocks[i]->entries[j];
                struct nuvo_map_entry            *map_entry = &replay_log_req->nuvo_map_entries[entry_idx];
                struct nuvo_log_io_block         *block_meta = &replay_log_req->log_io_blocks[entry_idx];
                if (ld_entry->log_entry_type == NUVO_LE_EMPTY)
                {
                    break;
                }

                if (NUVO_IS_DATA_OR_MAP_ENTRY(ld_entry->log_entry_type))
                {
                    block_meta->data = NULL;
                    block_meta->log_entry_type = ld_entry->log_entry_type;
                    block_meta->pit_info = ld_entry->pit_info;
                    block_meta->bno = ld_entry->bno;
                    block_meta->gc_media_addr.parcel_index = ld_entry->gc_media_addr.parcel_index;
                    block_meta->gc_media_addr.block_offset = ld_entry->gc_media_addr.block_offset;

                    if (ld_entry->is_cv)
                    {
                        map_entry->type = NUVO_ME_CONST;
                        map_entry->pattern = ld_entry->pattern;
                        map_entry->media_addr.parcel_index = 0;
                        map_entry->media_addr.block_offset = 0;
                    }
                    else
                    {
                        map_entry->type = NUVO_ME_MEDIA;
                        map_entry->hash = ld_entry->block_hash;
                        map_entry->media_addr.parcel_index = parcel_index;
                        map_entry->media_addr.block_offset = data_block_offset;
                        data_block_offset++;
                    }
                }
                else
                {
                    NUVO_PANIC("replay failed: invalid entry type: %u index: %lu  offset: %lu:%lu length: %lu",
                               ld_blocks[i]->entries[j].log_entry_type, entry_idx,
                               io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_count);
                }
                entry_idx++;
            }
        }
        NUVO_ASSERT(entry_idx == ld_blocks[0]->header.entry_count);
        replay_log_req->replay_ready = true;

        nuvo_pr_client_buf_free_req(io_req);
        nuvo_pr_client_req_free(io_req);
    }
    else if (seg_req->op == NUVO_SEGMENT_OP_READ_SNAP)
    {
        NUVO_ASSERT(seg_req->log_req != NULL);
        struct nuvo_log_request  *replay_log_req = seg_req->log_req;
        struct nuvo_segment_snap *snap_block = io_req->rw.iovecs[0].iov_base;

        NUVO_ASSERT(replay_log_req->sequence_tag.uint == snap_block->sequence_no);

        if (io_req->rw.block_hashes[0] != seg_req->read.block_hashes[0])
        {
            // hash of data read from media doesn't match the hash recorded in the summary table
            NUVO_PANIC("replay failed: invalid snap block at offset: %lu:%lu media hash %lu expected %lu",
                       io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_hashes[0], seg_req->read.block_hashes[0]);
        }
        else if (!internal_hash_compare((struct nuvo_segment_header *)snap_block))
        {
            // block has an internal inconsistency
            NUVO_PANIC("replay failed: invalid snap block at offset: %lu:%lu internal hash mismatch", io_req->rw.parcel_desc, io_req->rw.block_offset);
        }
        else if (snap_block->magic != NUVO_SNAP_DESCRIPTOR_MAGIC)
        {
            // the block that was read is not a snapshot block
            NUVO_PANIC("replay failed: block at offset: %lu:%lu type %u expected snap block", io_req->rw.parcel_desc, io_req->rw.block_offset, snap_block->magic);
        }

        replay_log_req->operation = snap_block->operation;
        replay_log_req->pit_id = snap_block->pit_id;
        uuid_copy(replay_log_req->pit_uuid, snap_block->pit_uuid);
        replay_log_req->replay_ready = true;

        nuvo_pr_client_buf_free_req(io_req);
        nuvo_pr_client_req_free(io_req);
    }
    else if (seg_req->op == NUVO_SEGMENT_OP_READ_DATA)
    {
        NUVO_ASSERT(seg_req->log_segment != NULL);

        uint32_t segment_block_index = segment_offset_to_index(seg_req->log_segment->segment, io_req->rw.block_offset);
        rebuild_segment_digest(logger, seg_req->log_segment, io_req->rw.iovecs, io_req->rw.block_hashes, io_req->rw.block_count, segment_block_index);

        nuvo_pr_client_buf_free_req(io_req);
        nuvo_pr_client_req_free(io_req);
    }
    else
    {
        NUVO_PANIC("invalid read operation: %u", seg_req->op);
    }

    nuvo_mutex_lock(&logger->replay_queue_mutex);
    nuvo_cond_signal(&logger->replay_queue_cond);
    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    logger->pr_io_count--;
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    nuvo_mutex_lock(&logger->replay_callback_count_mutex);
    nuvo_mutex_unlock(&logger->replay_queue_mutex);
    if (--logger->replay_callback_count == 0)
    {
        nuvo_cond_signal(&logger->replay_callback_count_zero_cond);
    }
    nuvo_mutex_unlock(&logger->replay_callback_count_mutex);
}

/**
 * @brief Rebuilds the segment digest from log descriptors
 *
 * Rebuilding the segment requires using information in the log descriptors
 * to re-create the summary table entries. As each log descriptor is read,
 * the block_count is used to locate the next non-data block in the segment.
 * Since data blocks are opaque, their content cannot be used to identify the type of block.
 *
 * Rebuilding the summary table starts by locating each successive log descriptor in the
 * segment. When a log descriptor is found, the entries are made in the summary table
 * for the log descriptor block(s), followed entries for the number of data blocks
 * that are indicated in the header. If the expected number of data blocks is not
 * found or cannot be verified using the hashes in the log descriptor, a summary table entry
 * is not made. Rebuild of the digest stops at the first incomplete or invalid operation
 * found in the log.
 *
 * @param logger The logger state
 * @param log_segment The segment being rebuilt.
 * @param iovecs An array of block_count data blocks read from media.
 * @param block_hashes An array of block_hashes for the corresponding data blocks.
 * @param block_count The number of blocks read.
 * @param segment_block_index The segment relative offset of the blocks read.
 * @return None.
 */
void rebuild_segment_digest(struct nuvo_logger *logger, struct logger_segment *log_segment, struct iovec *iovecs, nuvo_hash_t *block_hashes, uint32_t block_count, uint32_t segment_block_index)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT(iovecs != NULL);
    NUVO_ASSERT(block_hashes != NULL);
    NUVO_ASSERT(block_count != 0);

    NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);
    struct nuvo_segment_digest *digest = log_segment->digest;
    NUVO_ASSERT(digest != NULL);

    // current_offset is the location of the next expected sequenced transaction in the log
    // the end_block_offset is the segment offset of the last block in the iovec.
    uint32_t end_block_offset = log_segment->current_offset + block_count;
    uint32_t st_entry_index = segment_block_index;
    uint32_t io_block_index = 0;
    uuid_t   vs_uuid;
    uuid_copy(vs_uuid, nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger)->vs_uuid);

    while (st_entry_index < segment_block_index + block_count)
    {
        struct nuvo_segment_header        *block = (iovecs + io_block_index)->iov_base;
        struct nuvo_segment_summary_entry *st_entry = &digest->table[st_entry_index];
        if (st_entry_index == 0)
        {
            NUVO_ASSERT(log_segment->current_offset == log_segment->segment->block_offset);
            NUVO_ASSERT(log_segment->last_sequence_no == 0);
            NUVO_ASSERT((uint32_t)log_segment->free_block_count == (get_segment_digest_offset(log_segment->segment) - log_segment->segment->block_offset - NUVO_SEGMENT_FORK_BLOCKS));

            uint64_t header_sequence_no = 0;
            uint64_t closing_sequence_no = 0;
            uint64_t highest_sequence_no = 0;
            bool     had_digest = log_segment->replay.has_digest;
            if (had_digest)
            {
                // A digest was read in but all sequence numbers were less than needed for replay.
                // Need to cross-check the digest sequence numbers with the segment header
                log_segment->replay.has_digest = false;
                header_sequence_no = st_entry->header.sequence_no;
                closing_sequence_no = log_segment->digest->footer.closing_sequence_no;
                highest_sequence_no = log_segment->digest->footer.sequence_no;
            }
            memset(digest, 0, sizeof(struct nuvo_segment_digest));

            digest->footer.sequence_no = 0;
            log_segment->current_offset = log_segment->segment->block_offset;
            log_segment->free_block_count = get_segment_digest_offset(log_segment->segment) - log_segment->segment->block_offset - NUVO_SEGMENT_FORK_BLOCKS;
            log_segment->last_sequence_no = 0;

            if (block->magic != NUVO_SEGMENT_HEADER_MAGIC)
            {
                // Segment was most likely never written before.
                // This is a common case when opening a new volume and logger attempts to replay the starting segment.
                NUVO_LOG(logger, 20, "replay: segment %lu:%lu does not have a header block. nothing to replay. opening.", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                log_segment->state = NUVO_SEGMENT_OPEN;
                return;
            }
            else if (!internal_hash_compare(block))
            {
                // Segment most likely had a header that was partially written or was corrupted.
                // Panic since this should not be a common case.
                NUVO_PANIC("replay: segment %lu:%lu has a corrupted header block. nothing can be replayed.", log_segment->segment->parcel_index, log_segment->segment->block_offset);
            }
            else if (uuid_compare(block->vs_uuid, vs_uuid))
            {
                // Segment header is from an old volume
                // This is a common case when reusing devices or parcels.
                NUVO_LOG(logger, 20, "replay: segment %lu:%lu header has an unkown volume uuid. nothing to replay. opening.", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                log_segment->state = NUVO_SEGMENT_OPEN;
                return;
            }
            else if (had_digest && (block->sequence_no == header_sequence_no))
            {
                // Segment has a valid digest, but all sequence numbers were lower than what was needed for replay.
                // The segment header agrees with the digest confirming there's nothing to replay.
                // Should only be here if this segment was closed before the sequence no at last CP.
                //
                // If this segment was arrived at via fork then it means this was a GC'd segment that was opened
                // but never written to before the last shutdown. Otherwise if this segment was given to the logger
                // to start replay, then it must be closed since it may have live data.
                if (closing_sequence_no > logger->replay_req->sequence_no)
                {
                    NUVO_ERROR_PRINT("segment %lu:%lu has nothing to replay. header: %lu highest: %lu closing: %lu replay start: %lu",
                                     log_segment->segment->parcel_index, log_segment->segment->block_offset,
                                     header_sequence_no, highest_sequence_no, closing_sequence_no, logger->replay_req->sequence_no);

                    // TODO: This assert will always fire. should be changed to to return a replay failure.
                    NUVO_ASSERT(closing_sequence_no <= logger->replay_req->sequence_no);
                }

                if (is_replay_log_start_segment(logger, log_segment->segment))
                {
                    NUVO_LOG(logger, 20, "replay: starting segment %lu:%lu has nothing to replay, highest sequence no: %lu. last closed at sequence no %lu. closing.",
                             log_segment->segment->parcel_index, log_segment->segment->block_offset, highest_sequence_no, closing_sequence_no);
                    nuvo_mutex_lock(&logger->open_data_segments_mutex);
                    close_segment(logger, log_segment, false);
                    process_segment_open_queue(logger);
                    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
                }
                else
                {
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu has nothing to replay, highest sequence no: %lu. opening.",
                             log_segment->segment->parcel_index, log_segment->segment->block_offset, highest_sequence_no);
                    log_segment->state = NUVO_SEGMENT_OPEN;
                }
                return;
            }
            else
            {
                // Segment digest is obsolete, so rebuild.
                NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);
                if (had_digest)
                {
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu digest is obsolete. rebuilding digest.", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                }
                else
                {
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu rebuilding digest.", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                }

                // Segment has a good header, create a summary table entry
                st_entry->log_entry_type = NUVO_LE_HEADER;
                st_entry->block_hash = block_hashes[io_block_index];
                st_entry->header.sequence_no = block->sequence_no;
                st_entry->header.subclass = block->subclass;

                st_entry_index++;
                io_block_index++;
                log_segment->current_offset += NUVO_SEGMENT_HEADER_BLOCKS;
                log_segment->free_block_count -= NUVO_SEGMENT_HEADER_BLOCKS;
                log_segment->last_sequence_no = 0;
            }
        }
        else
        {
            // The current_offset must always point the location of a block that could be log descriptor or a fork.
            // The summary table is rebuilt by transaction. This requires all data from that transaction to be read
            // If rebuild requires additional blocks not read they need to be read in first.
            // The read offset is set to read the entire transaction, this may lead to some blocks being read twice.
            // This was approach was chosen to avoid holding buffers dependent on the next read completing.
            bool rebuild_done = false;
            switch (block->magic)
            {
            case NUVO_LOG_DESCRIPTOR_MAGIC:
            {
                // re-cast this block to a log descriptor
                struct nuvo_log_descriptor_block *logd_block = (struct nuvo_log_descriptor_block *)block;

                // verify the header using the internal block hash */
                if (!internal_hash_compare(block))
                {
                    // even though this block had a descriptor block signature it's otherwise corrupted, most likely due a bug.
                    // for now panic because corruption.
                    NUVO_PANIC("digest rebuild failed: invalid log descriptor: block offset: %lu:%lu", log_segment->segment->parcel_index, log_segment->current_offset);
                }

                // verify that this log record is from the correct volume and in sequence
                if (uuid_compare(logd_block->header.vs_uuid, vs_uuid) || (logd_block->header.sequence_no <= log_segment->last_sequence_no))
                {
                    rebuild_done = true;
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu found out of sequence log descriptor. %lu <= %lu at offset %lu", log_segment->segment->parcel_index, log_segment->segment->block_offset,
                             logd_block->header.sequence_no, log_segment->last_sequence_no, log_segment->current_offset);
                    break;
                }

                uint32_t entry_count = logd_block->header.entry_count;
                uint32_t meta_block_count = (entry_count <= NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES) ? 1 : 2;
                uint32_t data_block_count = logd_block->header.data_block_count;
                uint64_t sequence_no = logd_block->header.sequence_no;

                // Check if everything required for rebuilding this transaction has been read in.
                if (log_segment->current_offset + meta_block_count + data_block_count >= end_block_offset)
                {
                    // Need to read in the full log operation first
                    read_segment_data(logger, log_segment, st_entry_index, NUVO_ROUND_DOWN_TO_MAX_IO_BLOCKS(get_segment_digest_offset(log_segment->segment) - log_segment->current_offset));
                    return;
                }

                if (meta_block_count == NUVO_MAX_LOG_DESCRIPTOR_BLOCKS)
                {
                    if (!internal_hash_compare(block))
                    {
                        // The second block of a two block descriptor is corrupted.
                        // This descriptor cannot be used. This is the end of the digest rebuild.
                        // panic since this would almost certainly be corruption caused by a bug.
                        NUVO_PANIC("digest rebuild failed: inconsistent log descriptor: block offset: %lu:%lu", log_segment->segment->parcel_index, log_segment->current_offset);
                    }
                }

                // All required blocks are available to rebuild the summary table for this log
                // operation and the log descriptor has passed validation.
                // First rebuild the entries for the log descriptors
                struct nuvo_log_descriptor_block *ld_blocks[NUVO_MAX_LOG_DESCRIPTOR_BLOCKS];
                for (uint32_t i = 0; i < meta_block_count; i++)
                {
                    // Keep pointers to the descriptor blocks for this transaction
                    // These are referenced during rebuild of the summary table entries for the data blocks
                    ld_blocks[i] = (iovecs + io_block_index)->iov_base;

                    // Rebuild the summary table entries for the descriptor
                    st_entry = &digest->table[st_entry_index];
                    st_entry->log_entry_type = NUVO_LE_DESCRIPTOR;
                    st_entry->block_hash = block_hashes[io_block_index];
                    st_entry->descriptor.sequence_no = logd_block->header.sequence_no;
                    st_entry->descriptor.entry_count = logd_block->header.entry_count;
                    st_entry->descriptor.data_block_count = logd_block->header.data_block_count;
                    st_entry->descriptor.cv_flag = (logd_block->header.entry_count == logd_block->header.data_block_count) ? 0 : 1;
                    st_entry->descriptor.operation = logd_block->header.operation;

                    st_entry_index++;
                    io_block_index++;
                }

                // The summary table is assembled from the log descriptor entries
                // For data block entry in the log descriptor, the summary table entry is re-built.
                // The block_hash of the data block returned on the read is used to validate the
                // data blocks read in are the ones expected. If any of the blocks have incorrect checksums
                // then the entire transaction is removed from the table, and rebuild ends.
                uint32_t ld_entry_index;
                uint32_t ld_block_index;
                bool     st_error_flag = false;
                for (uint32_t i = 0; i < entry_count; i++)
                {
                    if (i == 0 || i == NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES)
                    {
                        ld_entry_index = 0;
                        ld_block_index = (i == 0) ? 0 : 1;
                    }

                    struct nuvo_log_descriptor_entry *ld_entry = &ld_blocks[ld_block_index]->entries[ld_entry_index];
                    if (ld_entry->is_cv != 1)
                    {
                        if (NUVO_IS_DATA_OR_MAP_ENTRY(ld_entry->log_entry_type))
                        {
                            // Compare the block hash recorded in the log descriptor with the hash calculated on read.
                            // If the hash doesn't match it means this transaction wasn't fully written out, or the block was corrupted.
                            // Since we need the full transaction history on replay, if there were other log descriptors in this segment
                            // they cannot be used.
                            if (ld_entry->block_hash != block_hashes[io_block_index])
                            {
                                st_error_flag = true;
                                break;
                            }
                            st_entry = &digest->table[st_entry_index];
                            st_entry->log_entry_type = ld_entry->log_entry_type;
                            st_entry->block_hash = ld_entry->block_hash;
                            st_entry->data.pit_info = ld_entry->pit_info;
                            st_entry->data.bno = ld_entry->bno;
                            st_entry->data.gc_media_addr.parcel_index = ld_entry->gc_media_addr.parcel_index;
                            st_entry->data.gc_media_addr.block_offset = ld_entry->gc_media_addr.block_offset;
                        }
                        else
                        {
                            // The log descriptor entry is invalid
                            // given the hash was valid, this problem was introduced when the original write was staged
                            NUVO_PANIC("digest rebuild failed: invalid entry type in log descriptor: %u descriptor entry: %u:%u block offset: %lu:%lu",
                                       ld_entry->log_entry_type, ld_block_index, ld_entry_index, log_segment->segment->parcel_index, log_segment->current_offset);
                        }
                        st_entry_index++;
                        io_block_index++;
                    }
                    ld_entry_index++;
                }

                if (st_error_flag)
                {
                    // Found inconsistency in the log descriptor and associated data.
                    // This can happen if there was a crash midway through writing a log descriptor.
                    // Since the full log transaction isn't available it can't be replayed, so it needs to be backed out of the rebuilt summary table.
                    // Rewind the summary table index and wipe the summary table entries that were being assembled for this operation.
                    if (log_segment->digest->footer.sequence_no == 0)
                    {
                        // the footer sequence number is 0, it means the first log operation wasn't completed, so the header is backed out as well.
                        NUVO_LOG(logger, 20, "replay: segment %lu:%lu incomplete descriptor at block index %u. nothing to replay. end of rebuild\n", log_segment->segment->parcel_index, log_segment->segment->block_offset, st_entry_index);
                        st_entry = &digest->table[0];
                        memset(st_entry, 0, sizeof(struct nuvo_segment_summary_entry) * (meta_block_count + data_block_count + NUVO_SEGMENT_HEADER_BLOCKS));

                        log_segment->current_offset = log_segment->segment->block_offset;
                        log_segment->free_block_count = get_segment_digest_offset(log_segment->segment) - log_segment->segment->block_offset - NUVO_SEGMENT_FORK_BLOCKS;
                        log_segment->last_sequence_no = 0;
                        rebuild_done = true;
                    }
                    else if (log_segment->digest->footer.sequence_no >= logger->replay_req->sequence_no)
                    {
                        st_entry = &digest->table[segment_offset_to_index(log_segment->segment, log_segment->current_offset)];
                        memset(st_entry, 0, sizeof(struct nuvo_segment_summary_entry) * (meta_block_count + data_block_count));

                        NUVO_LOG(logger, 20, "replay: segment %lu:%lu incomplete descriptor at block index %u. end of rebuild\n", log_segment->segment->parcel_index, log_segment->segment->block_offset, st_entry_index);
                        rebuild_done = true;
                    }
                    else
                    {
                        // Found segment inconsistency before finding a sequence number needed for replay
                        NUVO_PANIC("digest rebuild failed: log entry starting at block offset %lu:%lu is incomplete. footer sequence number: %lu\n", log_segment->segment->parcel_index, log_segment->current_offset, log_segment->digest->footer.sequence_no);
                    }
                }
                else
                {
                    log_segment->current_offset += (meta_block_count + data_block_count);
                    log_segment->free_block_count -= (meta_block_count + data_block_count);
                    digest->footer.sequence_no = log_segment->last_sequence_no = sequence_no;
                    NUVO_ASSERT(log_segment->current_offset == segment_index_to_offset(log_segment->segment, st_entry_index));
                }
            }
            break;

            case NUVO_FORK_DESCRIPTOR_MAGIC:
            {
                // re-cast this block to a fork descriptor
                struct nuvo_segment_fork *fork_block = (struct nuvo_segment_fork *)block;

                // verify that this fork record is from the correct volume and in sequence
                if (uuid_compare(fork_block->vs_uuid, vs_uuid) || (fork_block->sequence_no <= log_segment->last_sequence_no))
                {
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu found out of sequence fork descriptor at offset %lu", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->current_offset);
                    rebuild_done = true;
                    break;
                }

                st_entry->log_entry_type = NUVO_LE_FORK;
                st_entry->block_hash = block_hashes[io_block_index];
                st_entry->fork.segment_addr.parcel_index = fork_block->parcel_index;
                st_entry->fork.segment_addr.block_offset = fork_block->block_offset;
                st_entry->fork.sequence_no = fork_block->sequence_no;
                st_entry->fork.subclass = fork_block->subclass;

                st_entry_index++;
                io_block_index++;

                log_segment->current_offset += 1;
                log_segment->free_block_count -= 1;
                digest->footer.sequence_no = log_segment->last_sequence_no = fork_block->sequence_no;
            }
            break;

            case NUVO_SNAP_DESCRIPTOR_MAGIC:
            {
                // re-cast this block to a snapshot descriptor
                struct nuvo_segment_snap *snap_block = (struct nuvo_segment_snap *)block;

                // verify that this snap record is from the correct volume and in sequence
                if (uuid_compare(snap_block->vs_uuid, vs_uuid) || (snap_block->sequence_no <= log_segment->last_sequence_no))
                {
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu found out of sequence snap descriptor at offset %lu", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->current_offset);
                    rebuild_done = true;
                    break;
                }

                // for snapshot blocks record create or delete and the sequence number
                // note that the lun_id and lun_uuid don't fit in the summary table
                st_entry->log_entry_type = NUVO_LE_SNAP;
                st_entry->block_hash = block_hashes[io_block_index];
                st_entry->snap.sequence_no = snap_block->sequence_no;
                st_entry->snap.operation = snap_block->operation;

                st_entry_index++;
                io_block_index++;

                log_segment->current_offset += 1;
                log_segment->free_block_count -= 1;
                digest->footer.sequence_no = log_segment->last_sequence_no = snap_block->sequence_no;
            }
            break;

            default:
            {
                // There was supposed to be either a fork, snap, or a log descriptor at this address,
                // since there wasn't we're at the end of the segment and the digest rebuild is complete.
                NUVO_LOG(logger, 20, "replay: segment %lu:%lu descriptor not found at block index %u", log_segment->segment->parcel_index, log_segment->segment->block_offset, st_entry_index);
                rebuild_done = true;
            }
            }

            if (rebuild_done || (log_segment->current_offset == get_segment_digest_offset(log_segment->segment)))
            {
                NUVO_ASSERT(digest->footer.sequence_no == log_segment->last_sequence_no);
                if (digest->footer.sequence_no >= logger->replay_req->sequence_no)
                {
                    segment_replay_head_set(log_segment, logger->replay_req->sequence_no);
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu rebuild completed. replaying sequence range: %lu - %lu", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->replay.sequence_no, log_segment->replay.highest_sequence_no);
                    log_segment->state = NUVO_SEGMENT_REPLAYING;
                }
                else
                {
                    // Reached the end of rebuild, but there's nothing in the segment needed for replay.
                    // Put into open state, the rebuilt digest will be written on close.
                    // Close will happen when there's an io that requires more free space than it has available.
                    NUVO_LOG(logger, 20, "replay: segment %lu:%lu rebuild completed. nothing to replay", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                    log_segment->state = NUVO_SEGMENT_OPEN;
                }
                return;
            }
        }
    }


    // rebuild requires more segment data to be read in
    NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);
    read_segment_data(logger, log_segment, st_entry_index, NUVO_ROUND_DOWN_TO_MAX_IO_BLOCKS(get_segment_digest_offset(log_segment->segment) - log_segment->current_offset));
}

/** @brief Queues a log request for replay.
 *
 * Adds the given log request to the tail of the replay queue.
 * Log requests must be added to the replay queue in sequential order according to their sequence number.
 *
 * @param logger Pointer to the logger state variables.
 * @param replay_log_req Pointer to the log request to be replayed.
 * @return None.
 */
void replay_log_operation(struct nuvo_logger *logger, struct nuvo_log_request *replay_log_req)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(replay_log_req != NULL);

    nuvo_mutex_lock(&logger->replay_queue_mutex);
    struct nuvo_log_request *last_req;
    last_req = nuvo_dlist_get_tail_object(&logger->replay_queue, struct nuvo_log_request, list_node);
    if (last_req)
    {
        NUVO_ASSERT(last_req->sequence_tag.uint + 1 == replay_log_req->sequence_tag.uint);
    }

    nuvo_dlist_insert_tail(&logger->replay_queue, &replay_log_req->list_node);
    logger->replay_queue_len++;

    nuvo_mutex_lock(&logger->log_io_count_mutex);
    logger->log_io_count++;
    nuvo_mutex_unlock(&logger->log_io_count_mutex);
    nuvo_mutex_unlock(&logger->replay_queue_mutex);
}

/**
 * @brief Reads the log entry at the given segment offset.
 *
 * This starts a read of a block_count size log descriptor at the specified block_offset.
 * Final completion of the read is handled in segment_read_complete().
 *
 * This function is used for reading snap and constant value log descriptors.
 * The block_hashes used for verification are from the summary table and are used to verify
 * block read is the one recorded in the summary table.
 *
 * @param logger The logger state.
 * @param op The type of descriptor to read
 * @param log_segment The segment to read from.
 * @param block_offset The offset to read at.
 * @param block_count The number of blocks to read.
 * @param block_hashes Block hashes to verify blocks read from media.
 * @param replay_log_req The log request associated with this log descriptor.
 * @return None.
 */
void read_segment_log_entry(struct nuvo_logger *logger, uint8_t op, struct logger_segment *log_segment, uint32_t block_offset, uint32_t block_count, nuvo_hash_t *block_hashes, struct nuvo_log_request *replay_log_req)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);

    // For a segment read the segment_io_request struct is part of the tracking structure.
    struct segment_io_req *seg_req = &replay_log_req->segment_req;
    memset(seg_req, 0, sizeof(struct segment_io_req));
    nuvo_dlnode_init(&seg_req->list_node);

    seg_req->op = op;
    seg_req->parcel_index = log_segment->segment->parcel_index;
    seg_req->parcel_desc = log_segment->segment->parcel_desc;
    seg_req->block_offset = block_offset;
    seg_req->meta_block_count = block_count;
    seg_req->block_count = seg_req->meta_block_count;
    seg_req->log_segment = log_segment;
    seg_req->logger = logger;
    seg_req->log_req = replay_log_req;

    // Copy block hashes, they'll be used to verify the read on completion
    for (uint32_t i = 0; i <= block_count; i++)
    {
        seg_req->read.block_hashes[i] = block_hashes[i];
    }

    struct nuvo_pr_req_alloc *req_alloc = &seg_req->req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);

    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    logger->pr_io_count++;
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    req_alloc->tag.ptr = seg_req;
    req_alloc->callback = segment_buf_alloc;
    nuvo_pr_client_req_alloc_cb(req_alloc);
}

/**
 * @brief Callback routine after allocating a req.
 *
 * A wrapper routine to call segment_io_submit().
 *
 * @param req_alloc A request pointer.
 * @return None.
 */
void segment_read_digest_submit(struct nuvo_pr_req_alloc *req_alloc)
{
    struct segment_io_req  *seg_req = (struct segment_io_req *)req_alloc->tag.ptr;
    struct nuvo_io_request *io_req = (struct nuvo_io_request *)req_alloc->req;

    segment_io_submit(seg_req, io_req);
}

/**
 * @brief Reads in the segment digest of the given segment.
 *
 * This starts a read of the segment digest, which includes the segment footer block
 * followed by a variable number of summary table blocks proportional to the segment size.
 * Final completion of the read is handled in segment_read_complete().
 *
 * @param logger The logger state.
 * @param log_segment The segment to read from.
 */
void read_segment_digest(struct nuvo_logger *logger, struct logger_segment *log_segment)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);

    // The segment must be be opened in replay read pending state.
    NUVO_ASSERT(log_segment->state == NUVO_SEGMENT_REPLAY_PENDING);

    // For a segment read the segment_io_request struct is part of the tracking structure.
    struct segment_io_req *seg_req = &log_segment->segment_req;
    memset(seg_req, 0, sizeof(struct segment_io_req));
    nuvo_dlnode_init(&seg_req->list_node);

    seg_req->op = NUVO_SEGMENT_OP_READ_DIGEST;
    seg_req->parcel_index = log_segment->segment->parcel_index;
    seg_req->parcel_desc = log_segment->segment->parcel_desc;
    seg_req->block_offset = get_segment_digest_offset(log_segment->segment);
    seg_req->meta_block_count = get_segment_digest_len(log_segment->segment);
    seg_req->block_count = seg_req->meta_block_count;
    seg_req->log_segment = log_segment;
    seg_req->logger = logger;

    struct nuvo_pr_req_alloc *req_alloc = &seg_req->req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);

    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    logger->pr_io_count++;
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    req_alloc->tag.ptr = seg_req;
    req_alloc->callback = segment_read_digest_submit;
    nuvo_pr_client_req_alloc_cb(req_alloc);
}

/**
 * @brief Checks if there's any segments haven't been checked for replayable operations
 *
 * @param logger The logger state.
 * @return True if at least one segment requires replay, otherwise False.
 */
bool segments_need_replay(struct nuvo_logger *logger)
{
    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    for (uint32_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        if ((logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_DATA].open_count == 0) &&
            (logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_GC].open_count == 0))
        {
            continue;
        }
        uint32_t max_open_count = logger->open_data_segments[data_class].max_open_count;
        for (uint32_t i = 0; i <= max_open_count; i++)
        {
            struct logger_segment *log_segment = &logger->open_data_segments[data_class].segments[i];
            if (log_segment->state == NUVO_SEGMENT_REPLAYING)
            {
                // Make sure replay has been attempted on the segment
                if (!log_segment->replay.is_processed)
                {
                    NUVO_LOG(logger, 20, "segment %lu:%lu needs replay", log_segment->segment->parcel_index, log_segment->segment->block_offset);
                    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
                    return (true);
                }
            }
        }
    }
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
    return (false);
}

/**
 * @brief Checks if any segments are in replay state.
 *
 * @param logger The logger state.
 * @return True if at least one segment is in replay state, otherwise False.
 */
bool segments_in_replay_state(struct nuvo_logger *logger)
{
    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    for (uint32_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        if ((logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_DATA].open_count == 0) &&
            (logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_GC].open_count == 0))
        {
            continue;
        }
        uint32_t max_open_count = logger->open_data_segments[data_class].max_open_count;
        for (uint32_t i = 0; i <= max_open_count; i++)
        {
            struct logger_segment *log_segment = &logger->open_data_segments[data_class].segments[i];
            if ((log_segment->state == NUVO_SEGMENT_REPLAYING) ||
                (log_segment->state == NUVO_SEGMENT_REPLAY_PENDING))
            {
                nuvo_mutex_unlock(&logger->open_data_segments_mutex);
                return (true);
            }
        }
    }
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
    return (false);
}

/**
 * @brief Puts any segments that are in replay state into open state.
 *
 * This function is called to move segments that are currently in replay state into open state.
 * This action is needed when there's a missing or incomplete log operation and further replay
 * of operations with higher sequence numbers is not possible.
 *
 * @param logger The logger state.
 * @return None.
 */
void open_segments_in_replay(struct nuvo_logger *logger)
{
    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    for (uint32_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        if ((logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_DATA].open_count == 0) &&
            (logger->open_data_segments[data_class].subclass[NUVO_SEGMENT_TYPE_GC].open_count == 0))
        {
            continue;
        }
        uint32_t max_open_count = logger->open_data_segments[data_class].max_open_count;
        for (uint32_t i = 0; i <= max_open_count; i++)
        {
            struct logger_segment *log_segment = &logger->open_data_segments[data_class].segments[i];
            if (log_segment->state == NUVO_SEGMENT_REPLAYING)
            {
                NUVO_ERROR_PRINT("replay: segment %lu:%lu unable to recover sequence range: %lu - %lu.", log_segment->segment->parcel_index, log_segment->segment->block_offset, log_segment->replay.sequence_no, log_segment->replay.highest_sequence_no);
                log_segment->state = NUVO_SEGMENT_OPEN;
            }
        }
    }
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
}

/**
 * @brief Replay the next log operation in the segment that's required for replay.
 *
 * Replays the next transactions in the segment if the sequence number up for replay.
 * A single call will attempt to replay as many sequential sequence numbers as it finds in the
 * segment. The function returns when the lowest sequence number in the segment is greater than
 * than the current replay sequence number, everything logged to the segment has been replayed,
 * '* or there are no log_reqs available.
 *
 * If the segment had a digest on media, it will be closed after the last log operation has
 * been replayed. Otherwise the segment is put in the open state.
 *
 * There is no dependency on information in the summary table once the log operation is queued
 * for replay.
 *
 * @param logger The logger state.
 * @param log_segment A segment with log operations requiring replay.
 * @return True if a log operation from the segment was queued for replay, otherwise False.
 */
bool find_next_log_operation(struct nuvo_logger *logger, struct logger_segment *log_segment)
{
    NUVO_ASSERT_MUTEX_HELD(&logger->open_data_segments_mutex);
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);

    nuvo_return_t ret;
    bool          replay_flag = false;
    struct nuvo_segment_digest *digest = log_segment->digest;
    NUVO_ASSERT(digest != NULL);
    struct nuvo_segment_summary_entry *summary_table = (struct nuvo_segment_summary_entry *)&digest->table;

    uint32_t st_entry_index = segment_offset_to_index(log_segment->segment, log_segment->current_offset);
    struct nuvo_segment_summary_entry *st_entry = &summary_table[st_entry_index];
    nuvo_mutex_lock(&logger->sequence_no_mutex);

    log_segment->replay.is_processed = true;
    while (log_segment->replay.sequence_no == logger->sequence_no)
    {
        // This loop will enqueue replay log requests for many consecutive sequence numbers as it can find in the summary table.
        // The expected location of the next descriptor in the segment is calculated using the entry count of the previous descriptor.
        struct nuvo_log_request *replay_log_req;
        if ((replay_log_req = nuvo_log_request_alloc(logger)) == NULL)
        {
            // The replay queue is full
            nuvo_mutex_unlock(&logger->sequence_no_mutex);
            return (false);
        }
        replay_log_req->vs_ptr = nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger);

        switch (st_entry->log_entry_type)
        {
        case NUVO_LE_DESCRIPTOR:
        {
            NUVO_ASSERT(logger->sequence_no == st_entry->descriptor.sequence_no);
            enum  nuvo_log_op_type operation = st_entry->descriptor.operation;
            uint32_t entry_count = st_entry->descriptor.entry_count;
            uint32_t data_block_count = st_entry->descriptor.data_block_count;
            uint32_t descriptor_count = (entry_count <= NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES) ? 1 : 2;

            NUVO_ASSERT((operation == NUVO_LOG_OP_DATA) || (operation == NUVO_LOG_OP_MAP) || (operation == NUVO_LOG_OP_GC));

            if (st_entry->descriptor.cv_flag)
            {
                // Put this request on the replay queue, however it will require descriptors to be read before
                // the media addresses can be reconstructed.
                replay_log_req->operation = operation;
                replay_log_req->replay_ready = false;
                replay_log_req->block_count = entry_count;
                replay_log_req->sequence_tag.uint = logger->sequence_no;
                replay_log_req->data_block_count = data_block_count;
                replay_log_req->meta_block_count = descriptor_count;
                replay_log_req->io_block_count = data_block_count + descriptor_count;

                replay_log_operation(logger, replay_log_req);

                // As on writes, mark this segment as the segment used.
                logger->active_segment = logger->open_data_segments[log_segment->segment->data_class].subclass[log_segment->segment->subclass].active_segment = log_segment;

                // Read in the log descriptor to get the cv info
                nuvo_hash_t block_hashes[NUVO_MAX_LOG_DESCRIPTOR_BLOCKS];
                for (uint32_t i = 0; i < descriptor_count; i++)
                {
                    block_hashes[i] = 0;
                    block_hashes[i] = st_entry->block_hash;
                    st_entry = &summary_table[++st_entry_index];
                }
                read_segment_log_entry(logger, NUVO_SEGMENT_OP_READ_DESCRIPTOR, log_segment, log_segment->current_offset, descriptor_count, block_hashes, replay_log_req);

                // Adjust segment info
                // Last sequence number replayed in this segment
                log_segment->last_sequence_no = logger->sequence_no;
                log_segment->current_offset += (descriptor_count + data_block_count);
                log_segment->free_block_count -= (descriptor_count + data_block_count);

                // Start read of the log descriptor block
                replay_flag = true;
            }
            else
            {
                // Reassemble the media addresses from the summary table entry
                // Put the request on the replay queue for replay.
                st_entry_index += descriptor_count;
                for (uint32_t i = 0; i < entry_count; i++)
                {
                    st_entry = &summary_table[st_entry_index];
                    struct nuvo_map_entry    *map_entry = &replay_log_req->nuvo_map_entries[i];
                    struct nuvo_log_io_block *block_meta = &replay_log_req->log_io_blocks[i];

                    if (NUVO_IS_DATA_OR_MAP_ENTRY(st_entry->log_entry_type))
                    {
                        map_entry->type = NUVO_ME_MEDIA;
                        map_entry->hash = st_entry->block_hash;
                        map_entry->media_addr.parcel_index = log_segment->segment->parcel_index;
                        map_entry->media_addr.block_offset = segment_index_to_offset(log_segment->segment, st_entry_index);
                        block_meta->log_entry_type = st_entry->log_entry_type;
                        block_meta->pit_info = st_entry->data.pit_info;
                        block_meta->bno = st_entry->data.bno;
                        block_meta->gc_media_addr.parcel_index = st_entry->data.gc_media_addr.parcel_index;
                        block_meta->gc_media_addr.block_offset = st_entry->data.gc_media_addr.block_offset;
                        st_entry_index++;
                    }
                    else
                    {
                        NUVO_PANIC("replay failed: invalid summary table entry type: %u  st index: %lu  segment offset: %lu:%lu",
                                   st_entry->log_entry_type, st_entry_index, log_segment->segment->parcel_index, log_segment->segment->block_offset);
                    }
                }

                replay_log_req->operation = operation;
                replay_log_req->replay_ready = true;
                replay_log_req->block_count = entry_count;
                replay_log_req->sequence_tag.uint = logger->sequence_no;
                replay_log_req->data_block_count = data_block_count;
                replay_log_req->meta_block_count = descriptor_count;
                replay_log_req->io_block_count = data_block_count + descriptor_count;

                replay_log_operation(logger, replay_log_req);

                // As on writes, mark this segment as the segment used.
                logger->active_segment = logger->open_data_segments[log_segment->segment->data_class].subclass[log_segment->segment->subclass].active_segment = log_segment;

                // Adjust segment info
                log_segment->last_sequence_no = logger->sequence_no;
                log_segment->current_offset += (descriptor_count + entry_count);
                log_segment->free_block_count -= (descriptor_count + entry_count);

                replay_flag = true;
            }
            // The next sequence number to be located for replay
            logger->sequence_no++;
            break;
        }

        case NUVO_LE_SNAP:
        {
            NUVO_ASSERT(logger->sequence_no == st_entry->snap.sequence_no);
            NUVO_ASSERT(NUVO_SEGMENT_SNAP_BLOCKS == 1);

            // Put this request on the replay queue,
            // however it will require the snapshot block to be read to get the lun_id and lun_uuid.
            replay_log_req->operation = st_entry->snap.operation;
            replay_log_req->replay_ready = false;
            replay_log_req->block_count = NUVO_SEGMENT_SNAP_BLOCKS;
            replay_log_req->sequence_tag.uint = logger->sequence_no;
            replay_log_req->data_block_count = 0;
            replay_log_req->meta_block_count = NUVO_SEGMENT_SNAP_BLOCKS;
            replay_log_req->io_block_count = NUVO_SEGMENT_SNAP_BLOCKS;
            replay_log_operation(logger, replay_log_req);

            // As on writes, mark this segment as the segment used.
            logger->active_segment = logger->open_data_segments[log_segment->segment->data_class].subclass[log_segment->segment->subclass].active_segment = log_segment;

            // Read in the snapshot block to get the lun info
            nuvo_hash_t block_hashes[NUVO_SEGMENT_SNAP_BLOCKS];
            block_hashes[0] = st_entry->block_hash;
            read_segment_log_entry(logger, NUVO_SEGMENT_OP_READ_SNAP, log_segment, log_segment->current_offset, NUVO_SEGMENT_SNAP_BLOCKS, block_hashes, replay_log_req);

            // Adjust the current offset to expected location of the next descriptor or fork
            log_segment->last_sequence_no = logger->sequence_no;
            log_segment->current_offset += NUVO_SEGMENT_SNAP_BLOCKS;
            log_segment->free_block_count -= NUVO_SEGMENT_SNAP_BLOCKS;

            replay_flag = true;

            // The next sequence number to be located for replay
            logger->sequence_no++;
            break;
        }

        case NUVO_LE_FORK:
        {
            NUVO_ASSERT(logger->sequence_no == st_entry->fork.sequence_no);

            // A fork entry contains the address of segment and a sequence number.
            // writes into the new segment referenced by the fork are not completed until the fork write completes.
            // Although a fork isn't replayed with map a log request is created to maintain the sequential order of log_reqs added to the replay queue.
            replay_log_req->sequence_tag.uint = logger->sequence_no;
            replay_log_req->operation = NUVO_LOG_OP_FORK;
            replay_log_req->replay_ready = false;
            replay_log_req->block_count = 0;
            replay_log_req->data_block_count = 0;
            replay_log_req->meta_block_count = NUVO_SEGMENT_FORK_BLOCKS;
            replay_log_req->io_block_count = NUVO_SEGMENT_FORK_BLOCKS;
            replay_log_operation(logger, replay_log_req);

            // As on writes, mark this segment as the segment used.
            logger->active_segment = logger->open_data_segments[log_segment->segment->data_class].subclass[log_segment->segment->subclass].active_segment = log_segment;

            replay_flag = true;

            // Check that this fork wasn't already in the set of segments originally provided for replay.
            // If was, skip the open since it will be opened by log_replay_start
            struct nuvo_segment fork_segment;
            fork_segment.parcel_index = st_entry->fork.segment_addr.parcel_index;
            fork_segment.block_offset = st_entry->fork.segment_addr.block_offset;
            fork_segment.subclass = st_entry->fork.subclass;
            if (!is_replay_log_start_segment(logger, &fork_segment))
            {
                // Space allocates a new segment based on the information found in the fork.
                struct nuvo_vol     *vol = nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger);
                struct nuvo_segment *new_segment;
                if ((ret = nuvo_space_vol_segment_log_replay_get(&vol->log_volume.space, fork_segment.parcel_index, fork_segment.block_offset, &new_segment)) != 0)
                {
                    // Panic since this is unexpected behaviour during replay
                    NUVO_PANIC("replay failed: unable to get segment details: %ld  st index: %lu  segment offset: %lu:%lu",
                               ret, st_entry->log_entry_type, st_entry_index, fork_segment.parcel_index, fork_segment.block_offset);
                }
                NUVO_ASSERT(new_segment != NULL);

                // Queue the open of this fork.
                // Since replay is queuing opens in sequence number order, they are guaranteed to be opened in the same order
                // as they were when originally written.
                new_segment->subclass = fork_segment.subclass;
                open_segment(logger, new_segment);
            }

            // Adjust the current offset to expected location of the next descriptor or fork
            log_segment->current_offset += NUVO_SEGMENT_FORK_BLOCKS;
            log_segment->free_block_count -= NUVO_SEGMENT_FORK_BLOCKS;
            log_segment->last_sequence_no = logger->sequence_no;

            // Increment the next sequence number to be found
            logger->sequence_no++;
            break;
        }

        default:
            NUVO_PANIC("replay failed: unexpected entry type: %u  summary table index: %u  segment offset: %lu:%lu\n",
                       st_entry->log_entry_type, st_entry_index, log_segment->segment->parcel_index, log_segment->current_offset);
            break;
        }

        // Check if this was the last transaction in this segment that needed replay.
        // The current offset has been advanced to the expected location of the next descriptor,
        // or where it would be written.
        if (log_segment->replay.sequence_no == log_segment->replay.highest_sequence_no)
        {
            NUVO_ASSERT(log_segment->current_offset <= get_segment_digest_offset(log_segment->segment));
            // Everything has been replayed in this segment
            if (log_segment->replay.has_digest)
            {
                close_segment(logger, log_segment, false);
            }
            else
            {
                // Segments that were open at time of shutdown will not have a digest (i.e. footer and summary table).
                // When the summary table is rebuilt from log entries it's expected that the segment will remain open when replay completes.
                // When the volume opens and a new write occurs, if the segment has no space, the segment will be closed and the digest will be written then.
                // However, a segment may have needed to have a summary table rebuilt because the original summary table was corrupted at some time after the write completed.
                // Unfortunately, there's currently no simple way to know that this occurred. As a result, replay doesn't know the segment really needed to be closed
                // with a new digest.
                log_segment->state = NUVO_SEGMENT_OPEN;
            }
            process_segment_open_queue(logger);
            break;
        }
        else
        {
            // Set the next sequence number in this segment ready for replay
            st_entry_index = segment_offset_to_index(log_segment->segment, log_segment->current_offset);
            st_entry = &summary_table[st_entry_index];
            if (st_entry->log_entry_type == NUVO_LE_DESCRIPTOR)
            {
                log_segment->replay.sequence_no = st_entry->descriptor.sequence_no;
            }
            else if (st_entry->log_entry_type == NUVO_LE_FORK)
            {
                log_segment->replay.sequence_no = st_entry->fork.sequence_no;
            }
            else if (st_entry->log_entry_type == NUVO_LE_SNAP)
            {
                log_segment->replay.sequence_no = st_entry->snap.sequence_no;
            }
            else
            {
                // There was supposed to be a log descriptor or a fork entry here according to the summary table.
                NUVO_PANIC("replay failed: unexpected entry type: %u  summary table index: %u  segment offset: %lu:%lu\n",
                           st_entry->log_entry_type, st_entry_index, log_segment->segment->parcel_index, log_segment->current_offset);
            }
        }
    }
    nuvo_mutex_unlock(&logger->sequence_no_mutex);

    return (replay_flag);
}

/**
 * @brief Checks if there are operations being replayed.
 *
 * Checks if there are any outstanding io requests or log operations queued.
 * Checks if there are any additional segments queued to be open for replay.
 * Checks the replay queue to ensure all transactions have been replayed with map.
 * Checks if there are any segments are in replay or pending replay.
 *
 * If everything has completed this routine will run the callback on the replay request.
 * @param logger The logger state.
 * @return None.
 */
bool log_replay_complete(struct nuvo_logger *logger)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT_MUTEX_HELD(&logger->replay_queue_mutex);

    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    if (logger->pr_io_count != 0)
    {
        nuvo_mutex_unlock(&logger->pr_io_count_mutex);
        return (false);
    }
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    nuvo_mutex_lock(&logger->log_io_count_mutex);
    if (logger->log_io_count != 0)
    {
        nuvo_mutex_unlock(&logger->log_io_count_mutex);
        return (false);
    }
    nuvo_mutex_unlock(&logger->log_io_count_mutex);

    nuvo_mutex_lock(&logger->segment_open_queue_mutex);
    if (nuvo_dlist_get_head_object(&logger->segment_open_queue, struct nuvo_segment, list_node))
    {
        nuvo_mutex_unlock(&logger->segment_open_queue_mutex);
        return (false);
    }
    nuvo_mutex_unlock(&logger->segment_open_queue_mutex);

    if (logger->state == NUVO_LOG_STATE_REPLAY)
    {
        if (segments_in_replay_state(logger))
        {
            if (segments_need_replay(logger))
            {
                // There's at least one segment that hasn't
                // been looked at yet for replayable operations.
                return (false);
            }
            nuvo_mutex_lock(&logger->replay_callback_count_mutex);
            if (logger->replay_queue_len == 0 && logger->replay_callback_count != 0)
            {
                nuvo_mutex_unlock(&logger->replay_callback_count_mutex);
                nuvo_cond_signal(&logger->replay_queue_len_zero_cond);
                return (false);
            }
            nuvo_mutex_unlock(&logger->replay_callback_count_mutex);

            // If there are still segments in replay mode at this point, it means the log operation with the
            // next sequence number needed for replay could not be found.
            // This can happen if there was crash and the log descriptor wasn't fully written; but due to
            // how the log is written async, there are segments with higher sequence numbers in them.
            // Since the log operations with higher sequence numbers could not have been ack'd when originally written,
            // the segments in replay mode are moved to open state.
            NUVO_ERROR_PRINT("replay expected sequence number %lu but was unable to locate it in the log.\n", logger->sequence_no);
            open_segments_in_replay(logger);

            NUVO_PANIC("replay failed. replay expected sequence number %lu but was unable to locate it in the log.\n", logger->sequence_no);
        }
        // After replay completes, the active segment must be in open state.
        if ((!logger->active_segment) || (logger->active_segment->state != NUVO_SEGMENT_OPEN))
        {
            NUVO_PANIC("active segment is not open following replay: %p", logger->active_segment);
        }

        // call the volume handler for replay done.

        struct nuvo_vol *vol = nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger);
        nuvo_map_replay_vol_done(vol);

        logger->state = NUVO_LOG_STATE_RUNNING;
        nuvo_cond_signal(&logger->replay_queue_len_zero_cond);

        nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
        nuvo_mfst_seg_counts_start(&logger->replay_req->vol->log_volume.mfst);
        logger->lowest_sequence_no_seg_cnts = UINT64_MAX;
        nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);

        NUVO_LOG(logger, 0, "replay complete: "NUVO_LOG_UUID_FMT " replayed sequence number range: %lu - %lu",
                 NUVO_LOG_UUID(vol->vs_uuid), logger->replay_req->sequence_no, logger->sequence_no);
        NUVO_LOG(logger, 10, "replay complete: "NUVO_LOG_UUID_FMT " map flush_replay_count:%d map_replay_stash_list_count:%d",
                 NUVO_LOG_UUID(vol->vs_uuid),
                 vol->log_volume.map_state.flush_replay_count, vol->map_replay_stash_list_count);
        logger->replay_req->callback(logger->replay_req);
    }
    else
    {
        NUVO_PANIC("logger is not in replay state");
    }
    return (true);
}

/**
 * @brief Start log replay by opening each of the segments given for replay.
 *
 * Log replay is kicked off by opening each of the segments that were given to start replay
 * as each segment is opened, the segments digest is read from media.
 *
 * A pointer to the original nuvo_log_replay_request is on the logger state.
 *
 * @param logger The logger state.
 * @return None.
 */
void log_replay_start(struct nuvo_logger *logger)
{
    nuvo_return_t ret;

    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    for (uint32_t i = 0; i < logger->replay_req->segment_count; i++)
    {
        struct nuvo_vol     *vol = nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger);
        struct nuvo_segment *segment;
        if ((ret = nuvo_space_vol_segment_log_replay_get(&vol->log_volume.space, logger->replay_req->replay_segments[i].parcel_index, logger->replay_req->replay_segments[i].block_offset, &segment)) != 0)
        {
            // Panic since this is unexpected during replay
            NUVO_PANIC("replay failed: unable to get segment at offset: %lu:%lu ret: %ld",
                       logger->replay_req->replay_segments[i].parcel_index, logger->replay_req->replay_segments[i].block_offset, ret);
        }
        NUVO_ASSERT(segment != NULL);

        // Copy the subclass it was when in use at CP.
        segment->subclass = logger->replay_req->replay_segments[i].subclass;;
        open_segment(logger, segment);
    }
    logger->replay_segments_opened = true;
    NUVO_LOG(logger, 10, "opened all starting segments for replay");
    nuvo_cond_signal(&logger->replay_segments_opened_cond);
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
}

/**
 * @brief Starts log replay
 *
 * Called to start a log replay.
 * The caller provides a nuvo_log_replay_request struct which provides
 * an array of segments addresses which may require replay, and a sequence number
 * from were replay should start.
 *
 * When the log is initialized it's put into \b NUVO_LOG_STATE_REPLAY state.
 * Replay will open each segment and locate each log operation requiring replay.
 * As each log operation is replayed, the logger state will reflect the state as
 * it was when the log operation was originally performed.
 * Replay completes when there are no more log operations to be replayed, and there
 * are no more segments to be opened, or forks in the log to follow.
 *
 * Replay is also called on a new volume with a single segment and sequence number.
 * In this usage replay will open the segment and upon finding nothing to replay, and
 * no forks to follow, will transition the logger into \b NUVO_LOG_STATE_RUNNING state.
 *
 * @param replay_req The log replay request.
 * @return None.
 */
void nuvo_log_replay(struct nuvo_log_replay_request *replay_req)
{
    NUVO_ASSERT(replay_req != NULL);
    NUVO_ASSERT(replay_req->vol != NULL);

    struct nuvo_logger *logger = &replay_req->vol->log_volume.logger;

    // Set the logger state to indicate that a replay is in progress
    logger->state = NUVO_LOG_STATE_REPLAY;

    // Set the current to indicate where replay is starting
    NUVO_ERROR_PRINT("Starting replay at seq_no %d, segment count seq_no %d\n", replay_req->sequence_no, replay_req->segment_cnt_sequence_no);
    logger->sequence_no = replay_req->sequence_no;
    logger->lowest_sequence_no = logger->sequence_no;
    logger->lowest_sequence_no_seg_cnts = replay_req->segment_cnt_sequence_no;

    // Keep a pointer to the replay request
    logger->replay_req = replay_req;

    // Clear the return status
    replay_req->status = 0;

    if (test_fi_inject_vol_rc(TEST_FI_GENERAL_USE_FAIL_VOL_REPLAY,
                              test_fi_general_use_fi_get(),
                              replay_req->vol->vs_uuid,
                              &replay_req->status))
    {
        NUVO_ERROR_PRINT("Debug: TEST_FI_GENERAL_USE_FAIL_VOL_REPLAY. Failing replay with error code: %lu", replay_req->status);
        logger->state = NUVO_LOG_STATE_SHUTDOWN;
        replay_req->callback(replay_req);
        return;
    }

    log_replay_start(logger);
}

/**
 * @brief Callback for the synchronous return on completion of replay.
 * @param replay_req The log replay request
 * @return None.
 */
void nuvo_log_sync_replay_done(struct nuvo_log_replay_request *replay_req)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)replay_req->tag.ptr);
}

/**
 * @brief Starts log replay and waits for completion.
 *
 * This is a sync wrapper to the async log replay routine.
 *
 * @param replay_req The log replay request
 * @return 0 if successful, otherwise the error set on the log replay request.
 */
nuvo_return_t nuvo_log_sync_replay(struct nuvo_log_replay_request *replay_req)
{
    NUVO_ASSERT(replay_req != NULL);

    nuvo_mutex_t sync_signal;
    if (nuvo_mutex_init(&sync_signal) != 0)
    {
        return (NUVO_ENOMEM);
    }
    nuvo_mutex_lock(&sync_signal);
    replay_req->tag.ptr = &sync_signal;
    replay_req->callback = nuvo_log_sync_replay_done;
    replay_req->status = 0;

    // Start log replay and wait
    nuvo_log_replay(replay_req);

    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    return (replay_req->status);
}
