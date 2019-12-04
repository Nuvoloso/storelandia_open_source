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
 * @file logger.c
 * @brief Implements the segment logging
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "nuvo_pr.h"
#include "logger.h"
#include "replay.h"
#include "space.h"
#include "resilience.h"
#include "nuvo_vol_series.h"
#include "log_volume.h"
#include "device_type.h"

bool process_segment_open_queue(struct nuvo_logger *logger);
void process_segment_close_queue(struct nuvo_logger *logger);
void nuvo_process_segment_io_queue(struct nuvo_logger *logger);
bool open_segment(struct nuvo_logger *logger, struct nuvo_segment *segment);
void close_segment(struct nuvo_logger *logger, struct logger_segment *log_segment, bool write_digest);
void fork_segment(struct nuvo_logger *logger, struct logger_segment *seg, struct nuvo_segment *segment, struct segment_io_req *seg_req);
void write_segment(struct nuvo_logger *logger, struct nuvo_log_request *log_req, struct logger_segment *seg);
void segment_io_submit(struct segment_io_req *seg_req, struct nuvo_io_request *io_req);
void free_logger_segment(struct nuvo_logger *logger, struct logger_segment *log_segment);
void nuvo_log_request_free(struct nuvo_logger *logger, struct nuvo_log_request *log_req);
bool log_replay_complete(struct nuvo_logger *logger);
void *do_completion_callbacks(void *arg);

extern inline uint32_t get_segment_digest_len(struct nuvo_segment *segment);
extern inline uint32_t get_segment_digest_offset(struct nuvo_segment *segment);
extern inline bool nuvo_logger_is_running(struct nuvo_logger *logger);

extern inline const char *logger_op_to_str(uint8_t op);

const char *const nuvo_log_op_str[NUVO_LOG_OP_INVALID + 1] =
{
    [0] = "None",
    [NUVO_LOG_OP_DATA] = "Data",
    [NUVO_LOG_OP_MAP] = "Map",
    [NUVO_LOG_OP_GC] = "GC",
    [NUVO_LOG_OP_CREATE_SNAP] = "Snap Create",
    [NUVO_LOG_OP_DELETE_SNAP] = "Snap Delete",
    [NUVO_LOG_OP_FORK] = "Fork",
    [NUVO_LOG_OP_INVALID] = "Invalid"
};

/**
 * @brief Initialize logger mutex objects
 * @param logger Pointer to the logger state.
 * @return 0 if successful, otherwise the error returned by nuvo_mutex_init.
 */
nuvo_return_t logger_init_mutexes(struct nuvo_logger *logger)
{
    nuvo_return_t ret = 0;

    if ((ret = nuvo_mutex_init(&logger->sequence_no_mutex)) != 0)
    {
        goto out;
    }
    if ((ret = nuvo_mutex_init(&logger->lowest_sequence_no_mutex)) != 0)
    {
        goto err_mutex_1;
    }
    if ((ret = nuvo_mutex_init(&logger->completion_list_mutex)) != 0)
    {
        goto err_mutex_2;
    }
    if ((ret = nuvo_mutex_init(&logger->segment_close_queue_mutex)) != 0)
    {
        goto err_mutex_3;
    }
    if ((ret = nuvo_mutex_init(&logger->segment_open_queue_mutex)) != 0)
    {
        goto err_mutex_4;
    }
    if ((ret = nuvo_mutex_init(&logger->segment_io_queue_mutex)) != 0)
    {
        goto err_mutex_5;
    }
    if ((ret = nuvo_mutex_init(&logger->open_data_segments_mutex)) != 0)
    {
        goto err_mutex_6;
    }
    if ((ret = nuvo_mutex_init(&logger->tracking_structs_mutex)) != 0)
    {
        goto err_mutex_7;
    }
    if ((ret = nuvo_mutex_init(&logger->segment_io_req_structs_mutex)) != 0)
    {
        goto err_mutex_8;
    }
    if ((ret = nuvo_mutex_init(&logger->log_io_count_mutex)) != 0)
    {
        goto err_mutex_9;
    }
    if ((ret = nuvo_mutex_init(&logger->cp_trigger_mutex)) != 0)
    {
        goto err_mutex_10;
    }
    if ((ret = nuvo_mutex_init(&logger->pr_io_count_mutex)) != 0)
    {
        goto err_mutex_11;
    }
    if ((ret = nuvo_cond_init(&logger->log_io_count_zero_cond)) != 0)
    {
        goto err_mutex_12;
    }
    if ((ret = nuvo_cond_init(&logger->pr_io_count_zero_cond)) != 0)
    {
        goto err_mutex_13;
    }
    if ((ret = nuvo_cond_init(&logger->segment_io_queue_len_zero_cond)) != 0)
    {
        goto err_mutex_14;
    }
    if ((ret = nuvo_cond_init(&logger->close_queue_len_zero_cond)) != 0)
    {
        goto err_mutex_15;
    }
    if ((ret = nuvo_mutex_init(&logger->replay_queue_mutex)) != 0)
    {
        goto err_mutex_16;
    }
    if ((ret = nuvo_cond_init(&logger->replay_queue_len_zero_cond)) != 0)
    {
        goto err_mutex_17;
    }
    if ((ret = nuvo_mutex_init(&logger->replay_log_request_structs_mutex)) != 0)
    {
        goto err_mutex_18;
    }
    if ((ret = nuvo_mutex_init(&logger->replay_callback_count_mutex)) != 0)
    {
        goto err_mutex_19;
    }
    if ((ret = nuvo_cond_init(&logger->replay_callback_count_zero_cond)) != 0)
    {
        goto err_mutex_20;
    }
    if ((ret = nuvo_cond_init(&logger->acking_sequence_no_zero_cond)) != 0)
    {
        goto err_mutex_21;
    }
    if ((ret = nuvo_cond_init(&logger->completion_list_cond)) != 0)
    {
        goto err_mutex_22;
    }
    if ((ret = nuvo_cond_init(&logger->replay_queue_cond)) != 0)
    {
        goto err_mutex_23;
    }
    if ((ret = nuvo_cond_init(&logger->replay_segments_opened_cond)) != 0)
    {
        goto err_mutex_24;
    }
    goto out;

err_mutex_24:
    nuvo_cond_destroy(&logger->replay_queue_cond);
err_mutex_23:
    nuvo_cond_destroy(&logger->completion_list_cond);
err_mutex_22:
    nuvo_cond_destroy(&logger->acking_sequence_no_zero_cond);
err_mutex_21:
    nuvo_cond_destroy(&logger->replay_callback_count_zero_cond);
err_mutex_20:
    nuvo_mutex_destroy(&logger->replay_callback_count_mutex);
err_mutex_19:
    nuvo_mutex_destroy(&logger->replay_log_request_structs_mutex);
err_mutex_18:
    nuvo_cond_destroy(&logger->replay_queue_len_zero_cond);
err_mutex_17:
    nuvo_mutex_destroy(&logger->replay_queue_mutex);
err_mutex_16:
    nuvo_cond_destroy(&logger->close_queue_len_zero_cond);
err_mutex_15:
    nuvo_cond_destroy(&logger->segment_io_queue_len_zero_cond);
err_mutex_14:
    nuvo_cond_destroy(&logger->pr_io_count_zero_cond);
err_mutex_13:
    nuvo_cond_destroy(&logger->log_io_count_zero_cond);
err_mutex_12:
    nuvo_mutex_destroy(&logger->pr_io_count_mutex);
err_mutex_11:
    nuvo_mutex_destroy(&logger->cp_trigger_mutex);
err_mutex_10:
    nuvo_mutex_destroy(&logger->log_io_count_mutex);
err_mutex_9:
    nuvo_mutex_destroy(&logger->segment_io_req_structs_mutex);
err_mutex_8:
    nuvo_mutex_destroy(&logger->tracking_structs_mutex);
err_mutex_7:
    nuvo_mutex_destroy(&logger->open_data_segments_mutex);
err_mutex_6:
    nuvo_mutex_destroy(&logger->segment_io_queue_mutex);
err_mutex_5:
    nuvo_mutex_destroy(&logger->segment_open_queue_mutex);
err_mutex_4:
    nuvo_mutex_destroy(&logger->segment_close_queue_mutex);
err_mutex_3:
    nuvo_mutex_destroy(&logger->completion_list_mutex);
err_mutex_2:
    nuvo_mutex_destroy(&logger->lowest_sequence_no_mutex);
err_mutex_1:
    nuvo_mutex_destroy(&logger->sequence_no_mutex);
out:
    return (ret);
}

/**
 * @brief Destroy logger mutex objects
 * @param logger Pointer to the logger The logger state structure.
 * @return None.
 */
void logger_destroy_mutexes(struct nuvo_logger *logger)
{
    nuvo_mutex_destroy(&logger->sequence_no_mutex);
    nuvo_mutex_destroy(&logger->lowest_sequence_no_mutex);
    nuvo_mutex_destroy(&logger->completion_list_mutex);
    nuvo_mutex_destroy(&logger->segment_close_queue_mutex);
    nuvo_mutex_destroy(&logger->segment_open_queue_mutex);
    nuvo_mutex_destroy(&logger->segment_io_queue_mutex);
    nuvo_mutex_destroy(&logger->open_data_segments_mutex);
    nuvo_mutex_destroy(&logger->tracking_structs_mutex);
    nuvo_mutex_destroy(&logger->segment_io_req_structs_mutex);
    nuvo_mutex_destroy(&logger->log_io_count_mutex);
    nuvo_mutex_destroy(&logger->cp_trigger_mutex);
    nuvo_mutex_destroy(&logger->pr_io_count_mutex);
    nuvo_cond_destroy(&logger->log_io_count_zero_cond);
    nuvo_cond_destroy(&logger->pr_io_count_zero_cond);
    nuvo_cond_destroy(&logger->segment_io_queue_len_zero_cond);
    nuvo_cond_destroy(&logger->close_queue_len_zero_cond);
    nuvo_mutex_destroy(&logger->replay_queue_mutex);
    nuvo_cond_destroy(&logger->replay_queue_len_zero_cond);
    nuvo_mutex_destroy(&logger->replay_log_request_structs_mutex);
    nuvo_mutex_destroy(&logger->replay_callback_count_mutex);
    nuvo_cond_destroy(&logger->replay_callback_count_zero_cond);
    nuvo_cond_destroy(&logger->acking_sequence_no_zero_cond);
    nuvo_cond_destroy(&logger->completion_list_cond);
    nuvo_cond_destroy(&logger->replay_queue_cond);
    nuvo_cond_destroy(&logger->replay_segments_opened_cond);
}

nuvo_return_t logger_init_concatenators(struct nuvo_logger *logger)
{
    uint32_t i, j;

    for (i = 0; i < NUVO_MAX_DATA_CLASSES; i++)
    {
        for (j = 0; j < logger->open_data_segments[i].max_open_count; j++)
        {
            nuvo_return_t rc;
            rc = nuvo_io_concat_init(&logger->open_data_segments[i].segments[j].concatenator, nuvo_rl_submit);
            if (rc < 0)
            {
                goto destroy_mutexes;
            }
        }
    }
    return (0);

destroy_mutexes:
    for (uint32_t di = 0; di < NUVO_MAX_DATA_CLASSES; di++)
    {
        for (uint32_t dj = 0; dj < logger->open_data_segments[di].max_open_count; dj++)
        {
            if (i == di && j == dj)
            {
                return (-NUVO_ENOMEM);
            }
            nuvo_io_concat_destroy(&logger->open_data_segments[di].segments[dj].concatenator);
        }
    }
    return (-NUVO_ENOMEM);
}

void logger_destroy_concatenators(struct nuvo_logger *logger)
{
    for (uint32_t i = 0; i < NUVO_MAX_DATA_CLASSES; i++)
    {
        for (uint32_t j = 0; j < logger->open_data_segments[i].max_open_count; j++)
        {
            nuvo_io_concat_destroy(&logger->open_data_segments[i].segments[j].concatenator);
        }
    }
}

/** @brief Initialize the logger state for the given volume series
 *
 * Initializes the tracking structures used by the logger
 * these tracking structures are kept per volume series.
 *
 * The starting sequence number is passed in on initialization.
 * The logger will use sequence numbers greater than this number.
 *
 * @param vol A pointer to the volume series.
 * @return 0 if successfully initialized.
 */
nuvo_return_t nuvo_log_init(struct nuvo_vol *vol)
{
    struct nuvo_logger *logger = &vol->log_volume.logger;

    memset(&logger->open_data_segments, 0, sizeof(logger->open_data_segments));
    memset(&logger->tracking_structs, 0, sizeof(logger->tracking_structs));
    memset(&logger->segment_io_req_structs, 0, sizeof(logger->segment_io_req_structs));
    memset(&logger->replay_log_request_structs, 0, sizeof(logger->replay_log_request_structs));

    nuvo_dlist_init(&logger->completion_list);
    nuvo_dlist_init(&logger->segment_close_queue);
    nuvo_dlist_init(&logger->segment_open_queue);
    nuvo_dlist_init(&logger->segment_io_queue);
    nuvo_dlist_init(&logger->replay_queue);

    logger->sequence_no = 0;
    logger->lowest_sequence_no = 0;
    logger->close_queue_len = 0;
    logger->segment_io_queue_len = 0;
    logger->log_io_count = 0;
    logger->pr_io_count = 0;
    logger->replay_queue_len = 0;
    logger->replay_callback_count = 0;
    logger->active_segment = NULL;
    logger->replay_req = NULL;
    logger->acking_sequence_no = 0;
    logger->completions_frozen = false;
    logger->replay_segments_opened = false;

    // Set the default checkpoint trigger type and default values.
    // In the future these could be changed runtime.
    logger->cp_trigger_type = NUVO_CP_TRIGGER_DEFAULT;
    logger->cp_trigger_log_io_count_limit = NUVO_CP_TRIGGER_LOG_IO_COUNT_LIMIT;
    logger->cp_trigger_segments_used_count_limit = NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT_LIMIT;
    logger->cp_trigger_log_io_count = 0;
    logger->cp_trigger_segments_used_count = 0;

    for (uint32_t i = 0; i < NUVO_MAX_DATA_CLASSES; i++)
    {
        /*
         * Memory for the segment digests is pre-allocated as part of the logger
         * populates a list of free tracking structures used for the segment digest
         */
        nuvo_dlist_init(&logger->tracking_structs[i].free_tracking_structs);
        union digest_tracking_structs *tracking_digests = logger->tracking_structs[i].tracking_digests;
        for (uint32_t j = 0; j < NUVO_MAX_OPEN_SEGMENTS; j++)
        {
            nuvo_dlnode_init(&tracking_digests[j].list_node);
            nuvo_dlist_insert_tail(&logger->tracking_structs[i].free_tracking_structs, &tracking_digests[j].list_node);
        }

        logger->open_data_segments[i].max_open_count = NUVO_MAX_OPEN_SEGMENTS;
        for (uint8_t type = 0; type < NUVO_MAX_SEGMENT_SUBCLASSES; type++)
        {
            logger->open_data_segments[i].subclass[type].max_open_count = NUVO_MAX_OPEN_SUBCLASS_SEGMENTS;
            logger->open_data_segments[i].subclass[type].open_count = 0;
            logger->open_data_segments[i].subclass[type].open_queue_len = 0;
            logger->open_data_segments[i].subclass[type].active_segment = NULL;
        }

        for (uint32_t j = 0; j < logger->open_data_segments[i].max_open_count; j++)
        {
            logger->open_data_segments[i].segments[j].state = NUVO_SEGMENT_CLOSED;
        }

        /* Populates a list of segment_io_reqs to be used when writing fork blocks */
        nuvo_dlist_init(&logger->segment_io_req_structs[i].free_segment_io_reqs);
        struct segment_io_req *sr = logger->segment_io_req_structs[i].seg_reqs;
        for (uint32_t j = 0; j < NUVO_MAX_OPEN_SEGMENTS; j++)
        {
            nuvo_dlist_insert_tail(&logger->segment_io_req_structs[i].free_segment_io_reqs, &sr[j].list_node);
        }
    }

    /* Populates a list of log_reqs to be used when replaying log transactions */
    nuvo_dlist_init(&logger->replay_log_request_structs.free_log_reqs);
    for (uint32_t i = 0; i < NUVO_MAX_REPLAY_TRANSACTIONS; i++)
    {
        nuvo_dlnode_init(&logger->replay_log_request_structs.log_reqs[i].list_node);
        nuvo_dlist_insert_tail(&logger->replay_log_request_structs.free_log_reqs, &logger->replay_log_request_structs.log_reqs[i].list_node);
    }

    nuvo_return_t ret;

    if ((ret = logger_init_concatenators(logger)) != 0)
    {
        return (ret);
    }

    if ((ret = logger_init_mutexes(logger)) != 0)
    {
        logger_destroy_concatenators(logger);
        return (ret);
    }

    logger->state = NUVO_LOG_STATE_REPLAY;
    logger->ack_th_running = true;
    (void)pthread_create(&logger->ack_tid, NULL, do_completion_callbacks, (void *)logger);

    return (0);
}

/**
 * @brief Release logger resources.
 * @param vol A pointer to the volume series.
 * @return None.
 */
void nuvo_log_destroy(struct nuvo_vol *vol)
{
    struct nuvo_logger *logger = &vol->log_volume.logger;

    NUVO_ASSERT(logger->state == NUVO_LOG_STATE_SHUTDOWN);

    logger->ack_th_running = false;
    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    nuvo_cond_signal(&logger->replay_segments_opened_cond);
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);
    nuvo_mutex_lock(&logger->replay_queue_mutex);
    nuvo_cond_signal(&logger->replay_queue_cond);
    nuvo_mutex_unlock(&logger->replay_queue_mutex);
    nuvo_mutex_lock(&logger->completion_list_mutex);
    nuvo_cond_signal(&logger->completion_list_cond);
    nuvo_mutex_unlock(&logger->completion_list_mutex);
    pthread_join(logger->ack_tid, NULL);

    logger_destroy_concatenators(&vol->log_volume.logger);
    logger_destroy_mutexes(&vol->log_volume.logger);
}

/** @brief Sets the hashes and or CVs in the nuvo_map_entries array
 *
 * The nuvo_map_entires array is returned upon completion of the log request.
 * This routine sets the hashes and or CVs as needed.
 *
 * If the IO destination is a HDD and the operation is a data write NUVO_LOG_OP_DATA,
 * constant value detection is disabled and the hashes of the blocks are recorded in the
 * nuvo_map_entries array.
 *
 * @param log_req Pointer to the log request.
 * @param device_type The type of device being written too
 * @return None.
 */
void logger_set_map_entry_hashes(struct nuvo_log_request *log_req, enum nuvo_dev_type device_type)
{
    for (uint32_t i = 0; i < log_req->block_count; i++)
    {
        switch (log_req->operation)
        {
        case NUVO_LOG_OP_DATA:
            if (device_type == NUVO_DEV_TYPE_HDD)
            {
                // Use only the hash and ignore any constant values since the block is going to be written.
                log_req->nuvo_map_entries[i].type = NUVO_ME_MEDIA;
                log_req->nuvo_map_entries[i].hash = log_req->log_io_block_hashes[i].hash;
                log_req->nuvo_map_entries[i].cow = NUVO_MAP_ENTRY_NONE;
                log_req->nuvo_map_entries[i].unused = 0;
            }
            else if (log_req->log_io_block_hashes[i].type == NUVO_ME_CONST)
            {
                log_req->nuvo_map_entries[i].type = log_req->log_io_block_hashes[i].type;
                log_req->nuvo_map_entries[i].pattern = log_req->log_io_block_hashes[i].pattern;
                log_req->nuvo_map_entries[i].media_addr.parcel_index = 0;
                log_req->nuvo_map_entries[i].media_addr.block_offset = 0;
                log_req->nuvo_map_entries[i].cow = NUVO_MAP_ENTRY_NONE;
                log_req->nuvo_map_entries[i].unused = 0;
            }
            else
            {
                NUVO_ASSERT(log_req->log_io_block_hashes[i].type == NUVO_ME_MEDIA);
                log_req->nuvo_map_entries[i].type = log_req->log_io_block_hashes[i].type;
                log_req->nuvo_map_entries[i].hash = log_req->log_io_block_hashes[i].hash;
                log_req->nuvo_map_entries[i].cow = NUVO_MAP_ENTRY_NONE;
                log_req->nuvo_map_entries[i].unused = 0;
            }
            break;

        case NUVO_LOG_OP_MAP:
            // TODO: NUVO_LOG_OP_MAP zero map writes on HDD should be supported too.
            // NUVO_LOG_OP_MAP currently sets a flag indicating that the map is zero.
            // The logger can't override this flag in the case of an HDD write since it
            // the map is expecting map zero blocks will only have the 0 CV logged in the
            // descriptor and won't have media entries returned.
            if (log_req->log_io_blocks[i].map_is_zero)
            {
                log_req->nuvo_map_entries[i].type = NUVO_ME_CONST;
                log_req->nuvo_map_entries[i].pattern = NUVO_MAP_IS_ZERO_PATTERN;
                log_req->nuvo_map_entries[i].media_addr.parcel_index = 0;
                log_req->nuvo_map_entries[i].media_addr.block_offset = 0;
                log_req->nuvo_map_entries[i].cow = NUVO_MAP_ENTRY_NONE;
                log_req->nuvo_map_entries[i].unused = 0;
            }
            else
            {
                log_req->nuvo_map_entries[i].type = log_req->log_io_block_hashes[i].type;
                log_req->nuvo_map_entries[i].hash = log_req->log_io_block_hashes[i].hash;
                log_req->nuvo_map_entries[i].cow = NUVO_MAP_ENTRY_NONE;
                log_req->nuvo_map_entries[i].unused = 0;
            }
            break;

        case NUVO_LOG_OP_GC:
            log_req->nuvo_map_entries[i].type = log_req->log_io_block_hashes[i].type;
            log_req->nuvo_map_entries[i].hash = log_req->log_io_block_hashes[i].hash;
            log_req->nuvo_map_entries[i].cow = NUVO_MAP_ENTRY_NONE;
            log_req->nuvo_map_entries[i].unused = 0;
            break;

        case NUVO_LOG_OP_CREATE_SNAP:
        case NUVO_LOG_OP_DELETE_SNAP:
            // Snapshot records a 4K op descriptor only.
            break;

        default:
            NUVO_PANIC("invalid operation: %u", log_req->operation);
            break;
        }
    }
}

/** @brief Check if a CP should be triggered.
 *
 * Function returns true if the active CP trigger criteria has been met.
 * The logger can use different CP trigger criteria.
 *
 * @param logger Pointer to the logger state.
 * @return True if a CP should be triggered, otherwise False.
 */
bool logger_cp_trigger(struct nuvo_logger *logger)
{
    bool cp_trigger = false;

    NUVO_ASSERT_MUTEX_HELD(&logger->cp_trigger_mutex);
    switch (logger->cp_trigger_type)
    {
    case NUVO_CP_TRIGGER_DISABLED:
        break;

    case NUVO_CP_TRIGGER_LOG_IO_COUNT:
        if (logger->cp_trigger_log_io_count >= logger->cp_trigger_log_io_count_limit)
        {
            cp_trigger = true;
        }
        break;

    case NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT:
        if (logger->cp_trigger_segments_used_count >= logger->cp_trigger_segments_used_count_limit)
        {
            cp_trigger = true;
        }
        break;

    default:
        NUVO_PANIC("invalid trigger type: %u", logger->cp_trigger_type);
        break;
    }
    return (cp_trigger);
}

/** @brief Check if there any outstanding log requests.
 *
 * Function returns true if there are outstanding sequence numbers that either haven't reached i/o complete
 * or haven't been acknowledged.
 *
 * When the sequence number is the same as the lowest outstanding sequence number it means
 * all outstanding requests have completed and been acknowledged.
 *
 * @param logger Pointer to the logger state.
 * @return True if there are outstanding i/o requests, otherwise False.
 */
bool log_requests_outstanding(struct nuvo_logger *logger)
{
    nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
    nuvo_mutex_lock(&logger->sequence_no_mutex);

    bool reqs_outstanding_flag = (logger->lowest_sequence_no == logger->sequence_no) ? false : true;

    nuvo_mutex_unlock(&logger->sequence_no_mutex);
    nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);

    return (reqs_outstanding_flag);
}

/** @brief Gets the next sequence number
 *
 * @param logger Pointer to the logger state.
 * @return The next sequence number.
 */
uint64_t get_next_sequence_no(struct nuvo_logger *logger)
{
    uint64_t sequence_no;

    NUVO_ASSERT(logger != NULL);

    nuvo_mutex_lock(&logger->sequence_no_mutex);
    sequence_no = logger->sequence_no++;
    nuvo_mutex_unlock(&logger->sequence_no_mutex);

    return (sequence_no);
}

/** @brief Perform log request callbacks according to sequence number.
 *
 * Handles the ordered calling of completion callbacks based on the sequence number.
 * Processes the list of completed requests, checking the sequence number of each request
 * against the lowest unacknowledged sequence number.
 *
 * The completion list is a sorted list ordered by increasing sequence number.
 * If the sequence number of the request at the head of the list is equal to the lowest
 * unacknowledged sequence number the callback for the log request is called.
 *
 * The callback must be acknowledged by calling nuvo_log_ack_sno(), which increments the
 * lowest unacknowledged sequence number.
 *
 * A log write request may trigger additional write operations for fork blocks, which
 * are also given sequence numbers since subsequent writes depend on their completion.
 * The fork blocks are internal to the logger, so sequence numbers associated with fork
 * blocks are handled without calling a callback.
 *
 * @param arg Pointer to the logger state.
 * @return None.
 */
void *do_completion_callbacks(void *arg)
{
    struct nuvo_logger *logger = arg;

    NUVO_ASSERT(logger != NULL);

    while (logger->ack_th_running)
    {
        if (logger->state == NUVO_LOG_STATE_REPLAY)
        {
            nuvo_mutex_lock(&logger->open_data_segments_mutex);
            if (!logger->replay_segments_opened)
            {
                // Wait until all the segments that were given to start replay are opened.
                NUVO_LOG(logger, 20, "waiting for initial segments to be opened");
                nuvo_cond_wait(&logger->replay_segments_opened_cond, &logger->open_data_segments_mutex);
                nuvo_mutex_unlock(&logger->open_data_segments_mutex);
                continue;
            }

            // Try to do some replay work
            do_replay(logger);
            nuvo_mutex_lock(&logger->replay_queue_mutex);
            nuvo_mutex_unlock(&logger->open_data_segments_mutex);

            if (log_replay_complete(logger))
            {
                NUVO_LOG(logger, 20, "replay completed");
                nuvo_mutex_unlock(&logger->replay_queue_mutex);
                continue;
            }

            nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
            struct nuvo_log_request *replay_log_req = nuvo_dlist_get_head_object(&logger->replay_queue, struct nuvo_log_request, list_node);
            if ((replay_log_req == NULL) || (replay_log_req->sequence_tag.uint != logger->lowest_sequence_no))
            {
                NUVO_LOG(logger, 90, "replay: waiting for sequence no %lu", logger->lowest_sequence_no);
                nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
                NUVO_ASSERT_MUTEX_HELD(&logger->replay_queue_mutex);

                // Before waiting make sure that we've looked at all segments.
                // Checking the thread state avoids a UT shutdown race condition.
                if (!segments_need_replay(logger) && logger->ack_th_running)
                {
                    nuvo_cond_wait(&logger->replay_queue_cond, &logger->replay_queue_mutex);
                }
                nuvo_mutex_unlock(&logger->replay_queue_mutex);
                continue;
            }

            while ((replay_log_req) && (replay_log_req->sequence_tag.uint == logger->lowest_sequence_no))
            {
                NUVO_ASSERT_MUTEX_HELD(&logger->replay_queue_mutex);
                NUVO_ASSERT_MUTEX_HELD(&logger->lowest_sequence_no_mutex);
                if (logger->lowest_sequence_no >= logger->lowest_sequence_no_seg_cnts)
                {
                    // We've reached the point on replay that the next segment count is the first one that we replay.
                    nuvo_mfst_seg_counts_start(&replay_log_req->vs_ptr->log_volume.mfst);
                    logger->lowest_sequence_no_seg_cnts = UINT64_MAX;
                }
                if (replay_log_req->operation == NUVO_LOG_OP_FORK)
                {
                    NUVO_LOG(logger, 100, "replay: op: %s sequence no: %lu", logger_op_to_str(replay_log_req->operation), replay_log_req->sequence_tag.uint);
                    nuvo_dlist_remove(&replay_log_req->list_node);
                    nuvo_log_request_free(logger, replay_log_req);

                    nuvo_mutex_lock(&logger->log_io_count_mutex);
                    logger->log_io_count--;
                    nuvo_mutex_unlock(&logger->log_io_count_mutex);

                    logger->replay_queue_len--;

                    logger->lowest_sequence_no++;
                    replay_log_req = nuvo_dlist_get_head_object(&logger->replay_queue, struct nuvo_log_request, list_node);
                }
                else if (replay_log_req->replay_ready)
                {
                    nuvo_dlist_remove(&replay_log_req->list_node);
                    if ((replay_log_req->operation == NUVO_LOG_OP_DATA) ||
                        (replay_log_req->operation == NUVO_LOG_OP_MAP) ||
                        (replay_log_req->operation == NUVO_LOG_OP_GC))
                    {
                        NUVO_LOG(logger, 100, "replay: op: %s sequence no: %lu descriptors: %u, entries: %u, blocks: %u, constants: %u, total log entry size: %u",
                                 logger_op_to_str(replay_log_req->operation), replay_log_req->sequence_tag.uint, replay_log_req->meta_block_count,
                                 replay_log_req->block_count, replay_log_req->data_block_count, replay_log_req->block_count - replay_log_req->data_block_count, replay_log_req->io_block_count);
                        nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
                        nuvo_mutex_unlock(&logger->replay_queue_mutex);

                        // The map interface is async, however it's possible this thread updates the map and calls nuvo_log_ack_sno.
                        replay_log_req->ack_submit_time = nuvo_get_timestamp();
                        nuvo_map_replay(replay_log_req);

                        nuvo_mutex_lock(&logger->replay_queue_mutex);
                        nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
                    }
                    else if ((replay_log_req->operation == NUVO_LOG_OP_CREATE_SNAP) ||
                             (replay_log_req->operation == NUVO_LOG_OP_DELETE_SNAP))
                    {
                        NUVO_LOG(logger, 100, "replay: op: %s sequence no: %lu", logger_op_to_str(replay_log_req->operation), replay_log_req->sequence_tag.uint);
                        struct nuvo_vol *vol = replay_log_req->vs_ptr;
                        uuid_t          *pit_uuid = &replay_log_req->pit_uuid;
                        uint32_t         pit_id = replay_log_req->pit_id;

                        if (replay_log_req->operation == NUVO_LOG_OP_CREATE_SNAP)
                        {
                            struct nuvo_lun *lun = nuvo_map_create_snap(vol, *pit_uuid);
                            NUVO_ASSERT(lun);
                            NUVO_ASSERT(lun->snap_id == pit_id);
                        }
                        else
                        {
                            nuvo_mutex_lock(&vol->mutex);
                            struct nuvo_lun *lun =
                                nuvo_get_lun_by_snapid_locked(vol, pit_id, false);
                            nuvo_mutex_unlock(&vol->mutex);
                            nuvo_return_t ret = nuvo_log_vol_delete_lun_int(lun);
                            NUVO_ASSERT(!ret);
                        }
                        nuvo_log_request_free(logger, replay_log_req);
                        nuvo_mutex_lock(&logger->log_io_count_mutex);
                        logger->log_io_count--;
                        nuvo_mutex_unlock(&logger->log_io_count_mutex);

                        logger->replay_queue_len--;

                        logger->lowest_sequence_no++;
                    }
                    else
                    {
                        NUVO_PANIC("unexpected log operation type: %u (%s)", replay_log_req->operation, logger_op_to_str(replay_log_req->operation));
                    }
                    replay_log_req = nuvo_dlist_get_head_object(&logger->replay_queue, struct nuvo_log_request, list_node);
                }
                else
                {
                    // Need to wait for log descriptors to be read before before replaying with the map.
                    // Before waiting, the lowest_sequence_no_mutex must be unlocked to allow the replay
                    // queue to make progress. On wakeup, the replay_queue_mutex is already locked, and the
                    // lock needs to be taken again.
                    NUVO_LOG(logger, 90, "replay: waiting for log descriptors for sequence no %lu", logger->lowest_sequence_no);
                    nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
                    NUVO_ASSERT_MUTEX_HELD(&logger->replay_queue_mutex);
                    nuvo_cond_wait(&logger->replay_queue_cond, &logger->replay_queue_mutex);
                    nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
                }
            }
            nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
            nuvo_mutex_unlock(&logger->replay_queue_mutex);
        }
        else
        {
            // After nuvo_log_destroy sets logger->ack_th_running = false, if the do_completion_callbacks()
            // thread has already checked ack_th_running and it suspends execution before grabbing the
            // completion_list_mutex, then it's possible when the thread resumes it will go to sleep waiting
            // on the completion_list condition and will never wake up. Grabbing the completion_list_mutex
            // and checking the logger state prevents this.
            nuvo_mutex_lock(&logger->completion_list_mutex);
            if (logger->state == NUVO_LOG_STATE_SHUTDOWN)
            {
                nuvo_mutex_unlock(&logger->completion_list_mutex);
                continue;
            }
            if (logger->completions_frozen)
            {
                // If completions are frozen wait
                nuvo_cond_wait(&logger->completion_list_cond, &logger->completion_list_mutex);
                nuvo_mutex_unlock(&logger->completion_list_mutex);
                continue;
            }
            nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
            struct segment_io_req *seg_req;
            seg_req = nuvo_dlist_get_head_object(&logger->completion_list, struct segment_io_req, list_node);
            if ((seg_req == NULL) || (seg_req->sequence_no != logger->lowest_sequence_no))
            {
                // No more log_req completion notifications can be sent
                nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);

                nuvo_cond_wait(&logger->completion_list_cond, &logger->completion_list_mutex);
                nuvo_mutex_unlock(&logger->completion_list_mutex);
                continue;
            }

            nuvo_dlist_remove(&seg_req->list_node);

            if (seg_req->op == NUVO_SEGMENT_OP_FORK)
            {
                uint8_t data_class = seg_req->log_segment->segment->data_class;

                // This is fork block i/o request, the lowest sequence number can be incremented without an ack
                logger->lowest_sequence_no++;
                nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
                nuvo_mutex_unlock(&logger->completion_list_mutex);

                nuvo_mutex_lock(&logger->log_io_count_mutex);
                logger->log_io_count--;
                nuvo_mutex_unlock(&logger->log_io_count_mutex);

                nuvo_mutex_lock(&logger->segment_io_req_structs_mutex);
                nuvo_dlist_insert_tail(&logger->segment_io_req_structs[data_class].free_segment_io_reqs, &seg_req->list_node);
                nuvo_mutex_unlock(&logger->segment_io_req_structs_mutex);
            }
            else
            {
                // Run the log_req callback.
                // The next completion will be sent after the completion is ack'd via nuvo_log_ack_sno()
                logger->acking_sequence_no = seg_req->log_req->sequence_tag.uint;

                nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
                nuvo_mutex_unlock(&logger->completion_list_mutex);
                seg_req->log_req->ack_submit_time = nuvo_get_timestamp();

                // Must get the volume pointer for this request before running the callback.
                // The seg_req may not be valid after the callback returns.
                struct nuvo_vol *vs_ptr = seg_req->log_req->vs_ptr;
                NUVO_ASSERT(vs_ptr != NULL);

                seg_req->log_req->callback(seg_req->log_req);

                // Trigger a CP if there's been enough IO.
                nuvo_mutex_lock(&logger->cp_trigger_mutex);
                logger->cp_trigger_log_io_count++;
                if (logger_cp_trigger(logger))
                {
                    nuvo_mutex_unlock(&logger->cp_trigger_mutex);
                    nuvo_space_trigger_cp(&vs_ptr->log_volume.space);
                }
                else
                {
                    nuvo_mutex_unlock(&logger->cp_trigger_mutex);
                }
            }

            // Handles closing segments where the close operation was dependent on completion of previous i/o
            process_segment_close_queue(logger);

            // If there are no outstanding requests then we run the i/o queue since there could be requests waiting in queue.
            // This may happen when a queued log request depends on previous i/o completing before it can proceed.
            if (!log_requests_outstanding(logger))
            {
                nuvo_process_segment_io_queue(logger);
            }

            // Signal there are no more log requests waiting for an ack
            nuvo_mutex_lock(&logger->log_io_count_mutex);
            if (logger->log_io_count == 0)
            {
                nuvo_cond_signal(&logger->log_io_count_zero_cond);
            }
            nuvo_mutex_unlock(&logger->log_io_count_mutex);
        }
    }
    return (NULL);
}

/** @brief Acknowledge log request has been processed.
 *
 * Completions notifications are sent and acknowledged in sequence number order.
 * There's only one outstanding completion notification outstanding at a time.
 * The next completion notification will not be processed until the previous completion has been acknowledged.
 *
 * @param log_req The log request which was completed.
 * @return None.
 */
void nuvo_log_ack_sno(struct nuvo_log_request *log_req)
{
    struct nuvo_logger *logger = &log_req->vs_ptr->log_volume.logger;

    nuvo_mutex_lock(&logger->completion_list_mutex);
    nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
    nuvo_mutex_lock(&logger->log_io_count_mutex);
    if (logger->lowest_sequence_no == log_req->sequence_tag.uint)
    {
        uint_fast64_t ack_complete_time = nuvo_get_timestamp();
        NUVO_LOG(logger, 100, "received ack for sequence number: %lu %s ack time: %lu ns", log_req->sequence_tag.uint, (logger->state == NUVO_LOG_STATE_REPLAY) ? "map replay" : "map", (ack_complete_time - log_req->ack_submit_time));
        logger->lowest_sequence_no++;
        logger->log_io_count--;
        logger->acking_sequence_no = 0;
    }
    else
    {
        NUVO_PANIC("ack sequence number: %lu, expected: %lu", logger->lowest_sequence_no, log_req->sequence_tag.uint);
    }
    nuvo_mutex_unlock(&logger->log_io_count_mutex);
    nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
    nuvo_cond_signal(&logger->acking_sequence_no_zero_cond);
    nuvo_mutex_unlock(&logger->completion_list_mutex);

    /* There may be more completions notifications that can be sent now */
    if (logger->state == NUVO_LOG_STATE_REPLAY)
    {
        nuvo_log_request_free(logger, log_req);
        nuvo_mutex_lock(&logger->replay_queue_mutex);
        logger->replay_queue_len--;
        nuvo_cond_signal(&logger->replay_queue_cond);
        nuvo_mutex_unlock(&logger->replay_queue_mutex);

        // prevents shutdown from destroying logger until done.
        nuvo_mutex_lock(&logger->replay_callback_count_mutex);
        logger->replay_callback_count++;
        nuvo_mutex_unlock(&logger->replay_callback_count_mutex);
        nuvo_mutex_lock(&logger->replay_callback_count_mutex);
        if (--logger->replay_callback_count == 0)
        {
            nuvo_cond_signal(&logger->replay_callback_count_zero_cond);
        }
        nuvo_mutex_unlock(&logger->replay_callback_count_mutex);
    }
    else
    {
        nuvo_mutex_lock(&logger->completion_list_mutex);
        nuvo_cond_signal(&logger->completion_list_cond);
        nuvo_mutex_unlock(&logger->completion_list_mutex);
    }
}

/** @brief Handle segment i/o completions
 *
 * This function is called on every i/o completion.
 *
 * Write operation for data and fork blocks are handled similarly since both have sequence numbers assigned. These
 * operations are added to the completion queue by inserting the request in the queue in order sorted by sequence
 * number. The completion queue is then processed.
 *
 * Close operations write the segment digest. The digest is written asynchronously and doesn't have a sequence number.
 * When a segment's digest write operation has completed, the memory used for tracking the summary table is released
 * back onto a free list, allowing new segments to be opened in it's place.
 *
 * @param io_req The i/o request which completed.
 * @return None.
 */
void segment_io_complete(struct nuvo_io_request *io_req)
{
    struct segment_io_req *seg_req = io_req->tag.ptr;
    struct nuvo_logger    *logger = seg_req->logger;

    NUVO_ASSERT(seg_req != NULL);
    NUVO_ASSERT(logger != NULL);

    /* Copy the status off the io_req */
    seg_req->status = io_req->status;

    if (io_req->status < 0)
    {
        /*
         * TODO handle io errors, recover, rollback, etc.
         * The parcel manager will panic when an i/o failure is detected. fix this when it doesn't.
         */
        NUVO_PANIC("%s: write failed: operation: %u  parcel offset: %lu:%lu length: %lu status: %ld \n", __func__, seg_req->op, io_req->rw.parcel_desc, io_req->rw.block_offset, io_req->rw.block_count, io_req->status);
    }

    if (seg_req->op == NUVO_SEGMENT_OP_CLOSE)
    {
        /* Close completions don't need to be handled in sequence */
        nuvo_mutex_lock(&logger->open_data_segments_mutex);

        uint8_t data_class = seg_req->log_segment->segment->data_class;
        uint8_t type = seg_req->log_segment->segment->subclass;

        /* informs the manifest the logger is done with the segment and frees the tracking resources */
        free_logger_segment(logger, seg_req->log_segment);

        /* Free the io_req. first null out the block pointer references in the iovec */
        for (uint32_t i = 0; i < io_req->rw.block_count; i++)
        {
            io_req->rw.iovecs[i].iov_base = NULL;
        }
        nuvo_pr_client_req_free(io_req);

        bool run_queue_flag = false;
        if ((logger->open_data_segments[data_class].subclass[type].open_count == 0) || !log_requests_outstanding(logger))
        {
            /*
             * If there are no open segments, or there are no outstanding requests then run the io queue
             * since there could be requests in queue waiting for a previous completion.
             */
            run_queue_flag = true;
        }

        /* Opens may be waiting for closes to complete to get tracking structures */
        process_segment_open_queue(logger);
        nuvo_mutex_unlock(&logger->open_data_segments_mutex);

        if (run_queue_flag)
        {
            /* i/o requests may  be waiting for segments to be opened */
            nuvo_process_segment_io_queue(logger);
        }
    }
    else
    {
        /* Add the request to the completion list to be handled in sequence */
        nuvo_mutex_lock(&logger->completion_list_mutex);
        struct segment_io_req *curr_req;
        curr_req = nuvo_dlist_get_head_object(&logger->completion_list, struct segment_io_req, list_node);
        while (curr_req != NULL)
        {
            if (seg_req->sequence_no < curr_req->sequence_no)
            {
                nuvo_dlist_insert_before(&curr_req->list_node, &seg_req->list_node);
                break;
            }
            curr_req = nuvo_dlist_get_next_object(&logger->completion_list, curr_req, struct segment_io_req, list_node);
        }
        if (curr_req == NULL)
        {
            /* either the first or the last */
            nuvo_dlist_insert_tail(&logger->completion_list, &seg_req->list_node);
        }

        /* Set log_req status and free all the resources associated with write  */
        if ((seg_req->op == NUVO_SEGMENT_OP_WRITE) || (seg_req->op == NUVO_SEGMENT_OP_SNAP))
        {
            NUVO_ASSERT(seg_req->log_req != NULL);
            seg_req->log_req->status = seg_req->status;

            /* Remove the data block pointer references in the iovec */
            for (uint32_t i = seg_req->meta_block_count; i < io_req->rw.block_count; i++)
            {
                io_req->rw.iovecs[i].iov_base = NULL;
            }
            /* Reset the block count so PR knows what blocks to free on the req */
            io_req->rw.block_count = seg_req->meta_block_count;
        }
        nuvo_pr_client_buf_free_req(io_req);
        nuvo_pr_client_req_free(io_req);

        nuvo_cond_signal(&logger->completion_list_cond);
        nuvo_mutex_unlock(&logger->completion_list_mutex);
    }
    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    if (--logger->pr_io_count == 0)
    {
        nuvo_cond_signal(&logger->pr_io_count_zero_cond);
    }
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);
}

/** @brief Callback routine after allocating buffers
 *
 * Wrapper routine to call segment_io_submit() with the appropriate parameters.
 *
 * @param buf_alloc A request pointer
 * @return None.
 */
void segment_rw_submit(struct nuvo_pr_buf_alloc *buf_alloc)
{
    struct segment_io_req  *seg_req = (struct segment_io_req *)buf_alloc->tag.ptr;
    struct nuvo_io_request *io_req = (struct nuvo_io_request *)buf_alloc->req;

    segment_io_submit(seg_req, io_req);
}

/**
 * @brief Callback routine after allocating a req
 *
 * Wrapper routine to call segment_io_submit() with the appropriate parameters.
 *
 * @param req_alloc A request pointer
 * @return None.
 */
void segment_write_summarytable_submit(struct nuvo_pr_req_alloc *req_alloc)
{
    struct segment_io_req  *seg_req = (struct segment_io_req *)req_alloc->tag.ptr;
    struct nuvo_io_request *io_req = (struct nuvo_io_request *)req_alloc->req;

    segment_io_submit(seg_req, io_req);
}

/**
 * @brief Prepares write requests and submits for i/o.
 *
 * \b NUVO_SEGMENT_OP_WRITE:
 * Writes new data to the log. Writes are one to three metadata blocks, followed by between 0 to 253 data blocks.
 * 253 = NUVO_MAX_IO_BLOCKS - NUVO_MAX_LOG_DESCRIPTOR_BLOCKS - NUVO_SEGMENT_HEADER_BLOCKS
 * Minimally a write may be a single log descriptor block.
 * The first write into a segment is minimally two blocks as it must also include a segment header block.
 * Log writes have a sequence number, and must have completions sent and acknowledged in sequence number order.
 * The buffers for metadata blocks are allocated from the PR and must be freed on completion.
 *
 * \b NUVO_SEGMENT_OP_FORK:
 * Writes a fork block. Forks are a single meta data block. The fork operation records the address of
 * a new segment, where sequence numbers > than the recorded number may be found.
 * Fork blocks have a sequence number assigned to the write operation, which is also recorded in the fork block.
 * The buffer for the fork block is allocated from the PR and must be freed on completion.
 *
 * \b NUVO_SEGMENT_OP_CLOSE:
 * Writes out the segment footer and summary table. Closes operations write multiple metadata blocks.
 * It has one footer block followed by a multi-block summary table, which is proportional to the size of the segment.
 * The close operation is not issued until all outstanding writes to the segment complete.
 * The write operation does not have sequence number assigned to it.
 * All memory for the summary table is pre-allocated when the segment is opened.
 * No buffers need to be allocated from the PR for a close operation.
 *
 * @param seg_req A pointer to a segment i/o request struct containing i/o parameters.
 * @param io_req A pointer to an i/o request struct allocated from the parcel router.
 * @return None.
 */
void segment_io_submit(struct segment_io_req *seg_req, struct nuvo_io_request *io_req)
{
    struct nuvo_dlist submit_list;

    NUVO_ASSERT(seg_req != NULL);
    NUVO_ASSERT(io_req != NULL);

    switch (seg_req->op)
    {
    case NUVO_SEGMENT_OP_SNAP:
    case NUVO_SEGMENT_OP_FORK:
    {
        struct nuvo_log_request *log_req = NULL;
        bool write_header_flag;

        if (seg_req->op == NUVO_SEGMENT_OP_SNAP)
        {
            NUVO_ASSERT(seg_req->log_req != NULL);
            log_req = seg_req->log_req;
            write_header_flag = log_req->write_header_flag;
        }
        else
        {
            write_header_flag = seg_req->fork.write_header_flag;
        }

        uint32_t iovec_idx = 0;
        if (write_header_flag)
        {
            NUVO_ASSERT(seg_req->meta_block_count == 1 + NUVO_SEGMENT_HEADER_BLOCKS);
            NUVO_ASSERT(io_req->rw.iovecs[0].iov_base != NULL);

            /* Prepare the header block */
            struct nuvo_segment_header *header_block = (struct nuvo_segment_header *)io_req->rw.iovecs[0].iov_base;
            memset(header_block, 0, NUVO_BLOCK_SIZE);
            header_block->magic = NUVO_SEGMENT_HEADER_MAGIC;
            header_block->sequence_no = seg_req->sequence_no;
            header_block->subclass = seg_req->log_segment->segment->subclass;
            uuid_copy(header_block->vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid);

            header_block->block_hash = 0;
            header_block->block_hash = nuvo_hash(header_block, NUVO_BLOCK_SIZE);
            io_req->rw.block_hashes[0] = nuvo_hash(header_block, NUVO_BLOCK_SIZE);

            /* Update the summary table entry for segment header */
            /* If writing a header, the block offset must be at index 0 */
            NUVO_ASSERT(segment_offset_to_index(seg_req->log_segment->segment, seg_req->block_offset) == 0);
            struct nuvo_segment_summary_entry *st = &seg_req->log_segment->digest->table[0];
            st->log_entry_type = NUVO_LE_HEADER;
            st->block_hash = io_req->rw.block_hashes[0];
            st->header.sequence_no = header_block->sequence_no;
            st->header.subclass = header_block->subclass;

            /* Index of the first log descriptor block in the iovec array */
            iovec_idx = NUVO_SEGMENT_HEADER_BLOCKS;
        }

        /*
         * Fork and snap blocks have two hashes computed.
         * First the internal hash of the block is computed and stored the in the block. Then
         * the hash of the block as written to media is calculated and the value recorded
         * the summary table. The fork and snap block have an internal hash since
         * the summary table may be rebuilt on replay and the media block hashes recomputed.
         */
        if (seg_req->op == NUVO_SEGMENT_OP_FORK)
        {
            struct nuvo_segment_fork *fork_block = (struct nuvo_segment_fork *)io_req->rw.iovecs[iovec_idx].iov_base;
            NUVO_ASSERT(fork_block != NULL);
            NUVO_ASSERT(io_req->rw.block_count == seg_req->meta_block_count);

            /* Prepare the fork block with address information for new segment */
            memset(fork_block, 0, NUVO_BLOCK_SIZE);
            fork_block->magic = NUVO_FORK_DESCRIPTOR_MAGIC;
            fork_block->sequence_no = seg_req->sequence_no;
            fork_block->parcel_index = seg_req->fork.segment->parcel_index;
            fork_block->block_offset = seg_req->fork.segment->block_offset;
            fork_block->subclass = seg_req->fork.segment->subclass;
            uuid_copy(fork_block->vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid);

            fork_block->block_hash = 0;
            fork_block->block_hash = nuvo_hash(fork_block, NUVO_BLOCK_SIZE);
            io_req->rw.block_hashes[iovec_idx] = nuvo_hash(fork_block, NUVO_BLOCK_SIZE);

            /* Update the log summary table */
            /* The summary table records the hash of the block written to media, not it's internal hash */
            uint32_t block_index = segment_offset_to_index(seg_req->log_segment->segment, seg_req->block_offset);
            struct nuvo_segment_summary_entry *st = &seg_req->log_segment->digest->table[block_index + iovec_idx];
            st->log_entry_type = NUVO_LE_FORK;
            st->block_hash = io_req->rw.block_hashes[iovec_idx];
            st->fork.segment_addr.parcel_index = fork_block->parcel_index;
            st->fork.segment_addr.block_offset = fork_block->block_offset;
            st->fork.sequence_no = fork_block->sequence_no;
            st->fork.subclass = fork_block->subclass;
        }
        else
        {
            NUVO_ASSERT(seg_req->op == NUVO_SEGMENT_OP_SNAP);

            /* write a create or delete snapshot block */
            struct nuvo_segment_snap *snap_block = (struct nuvo_segment_snap *)io_req->rw.iovecs[iovec_idx].iov_base;
            NUVO_ASSERT(snap_block != NULL);
            NUVO_ASSERT(io_req->rw.block_count == seg_req->meta_block_count);

            /* Prepare the snap block. Use the information passed in on the log_req */
            memset(snap_block, 0, NUVO_BLOCK_SIZE);
            snap_block->magic = NUVO_SNAP_DESCRIPTOR_MAGIC;
            snap_block->sequence_no = log_req->sequence_tag.uint;
            snap_block->pit_id = log_req->pit_id;
            uuid_copy(snap_block->pit_uuid, log_req->pit_uuid);
            snap_block->operation = log_req->operation;
            uuid_copy(snap_block->vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid);

            snap_block->block_hash = 0;
            snap_block->block_hash = nuvo_hash(snap_block, NUVO_BLOCK_SIZE);
            io_req->rw.block_hashes[iovec_idx] = nuvo_hash(snap_block, NUVO_BLOCK_SIZE);

            /*
             * A summary table entry doesn't have enough bytes to record the pit_id and pit_uuid
             * on replay the snap block will need to be read from the log
             */
            uint32_t block_index = segment_offset_to_index(seg_req->log_segment->segment, seg_req->block_offset);
            struct nuvo_segment_summary_entry *st = &seg_req->log_segment->digest->table[block_index + iovec_idx];
            st->log_entry_type = NUVO_LE_SNAP;
            st->snap.operation = log_req->operation;
            st->block_hash = io_req->rw.block_hashes[iovec_idx];
            st->snap.sequence_no = snap_block->sequence_no;
        }

        /* Prepare the write */
        NUVO_SET_IO_TYPE(io_req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->tag.ptr = seg_req;
        io_req->callback = segment_io_complete;
        io_req->rw.block_offset = seg_req->block_offset;
        io_req->rw.block_count = seg_req->meta_block_count;
        io_req->rw.parcel_desc = seg_req->parcel_desc;
        io_req->rw.vol = nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger);

        nuvo_io_concat_submit_req(&seg_req->log_segment->concatenator, io_req);
        break;
    }

    case NUVO_SEGMENT_OP_CLOSE:
    {
        /* Write the segment digest (i.e. footer and summary table) */
        uint8_t *digest_block_ptr = (uint8_t *)seg_req->log_segment->digest;
        uint8_t *table_block_ptr = (uint8_t *)seg_req->log_segment->digest->table;
        struct nuvo_segment_footer *footer_block = (struct nuvo_segment_footer *)&seg_req->log_segment->digest->footer;

        footer_block->magic = NUVO_SEGMENT_FOOTER_MAGIC;
        footer_block->sequence_no = seg_req->log_segment->last_sequence_no;
        footer_block->used_block_count = seg_req->log_segment->current_offset - seg_req->log_segment->segment->block_offset;
        footer_block->closing_sequence_no = seg_req->close.closing_sequence_no;
        uuid_copy(footer_block->vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid);

        /*
         * Calculate the block hashes of each block written as part of the summary table
         * and store the hashes in the footer block. These hashes are also used for the
         * hashes submitted on the io_req.
         */
        for (uint32_t i = 0; i < (seg_req->block_count - NUVO_SEGMENT_FOOTER_BLOCKS); i++)
        {
            footer_block->block_hashes[i] = nuvo_hash(table_block_ptr, NUVO_BLOCK_SIZE);
            io_req->rw.block_hashes[i + 1] = footer_block->block_hashes[i];
            table_block_ptr += NUVO_BLOCK_SIZE;
        }

        /*
         * Calculate the hash of the block and store the value in the block. Then
         * re-calculate the hash of the modified block to be included with on the io request.
         */
        footer_block->block_hash = 0;
        footer_block->block_hash = nuvo_hash(footer_block, NUVO_BLOCK_SIZE);
        io_req->rw.block_hashes[0] = nuvo_hash(footer_block, NUVO_BLOCK_SIZE);

        NUVO_SET_IO_TYPE(io_req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->tag.ptr = seg_req;
        io_req->callback = segment_io_complete;
        io_req->rw.parcel_desc = seg_req->parcel_desc;
        io_req->rw.block_offset = seg_req->block_offset;
        io_req->rw.block_count = seg_req->block_count;
        io_req->rw.vol = nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger);

        for (uint32_t i = 0; i < io_req->rw.block_count; i++)
        {
            io_req->rw.iovecs[i].iov_base = digest_block_ptr;
            io_req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            digest_block_ptr += NUVO_BLOCK_SIZE;
        }

        nuvo_io_concat_submit_req(&seg_req->log_segment->concatenator, io_req);
        break;
    }

    case NUVO_SEGMENT_OP_WRITE:
    {
        struct nuvo_log_request *log_req = seg_req->log_req;
        uint32_t meta_block_count = io_req->rw.block_count;
        uint32_t ld_iovec_idx;
        uint32_t block_index;

        NUVO_ASSERT(meta_block_count == seg_req->meta_block_count);

        /* Check if we're writing a new segment header with this request */
        if (log_req->write_header_flag)
        {
            NUVO_ASSERT((meta_block_count > NUVO_SEGMENT_HEADER_BLOCKS) && (meta_block_count <= (NUVO_SEGMENT_HEADER_BLOCKS + NUVO_MAX_LOG_DESCRIPTOR_BLOCKS)));
            NUVO_ASSERT(io_req->rw.iovecs[0].iov_base != NULL);

            /* Prepare the header block */
            struct nuvo_segment_header *header_block = (struct nuvo_segment_header *)io_req->rw.iovecs[0].iov_base;
            memset(header_block, 0, NUVO_BLOCK_SIZE);
            header_block->magic = NUVO_SEGMENT_HEADER_MAGIC;
            header_block->sequence_no = log_req->sequence_tag.uint;
            header_block->subclass = seg_req->log_segment->segment->subclass;
            uuid_copy(header_block->vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid);

            /*
             * Calculate the internal hash of the block and store the value in the block. Then
             * re-calculate the hash of the modified block to be included on the io request,
             * and in the summary table. The block has an internal hash since the summary
             * table is not guaranteed to be present on replay.
             */
            header_block->block_hash = 0;
            header_block->block_hash = nuvo_hash(header_block, NUVO_BLOCK_SIZE);
            io_req->rw.block_hashes[0] = nuvo_hash(header_block, NUVO_BLOCK_SIZE);

            /* If writing a header, the block offset must be at index 0 */
            block_index = segment_offset_to_index(seg_req->log_segment->segment, seg_req->block_offset);
            NUVO_ASSERT(block_index == 0);
            struct nuvo_segment_summary_entry *st = &seg_req->log_segment->digest->table[block_index];
            st->log_entry_type = NUVO_LE_HEADER;
            st->block_hash = io_req->rw.block_hashes[0];
            st->header.sequence_no = header_block->sequence_no;
            st->header.subclass = header_block->subclass;

            /* Index of the first log descriptor block in the iovec array */
            ld_iovec_idx = NUVO_SEGMENT_HEADER_BLOCKS;
        }
        else
        {
            /* No segment header */
            block_index = segment_offset_to_index(seg_req->log_segment->segment, seg_req->block_offset);
            ld_iovec_idx = 0;
        }

        struct nuvo_log_descriptor_block *log_descriptor_block;
        uint32_t ld_entry_idx = 0;                              /* the index of the entry in the log descriptor block */
        uint32_t ld_block_idx = 0;                              /* the index of the log descriptor block */
        uint32_t io_iovec_idx = meta_block_count;               /* index into iovec array */
        uint32_t st_entry_idx = block_index + meta_block_count; /* index into the summary table */
        uint8_t  cv_flag = 0;

        /* Cycle through each data block sent on the request and prepare descriptors entries */
        for (uint32_t i = 0; i < log_req->block_count; i++)
        {
            NUVO_ASSERT(log_req->log_io_blocks[i].log_entry_type >= NUVO_LE_DATA && log_req->log_io_blocks[i].log_entry_type <= NUVO_LE_MAP_L4)

            /*
             * Get pointer to the log descriptor block allocated on the io_req.
             * There may be one or two log descriptor blocks depending on the number of data blocks being written.
             * A log writes with > 128 data blocks requires two log descriptor blocks.
             */
            if (i == 0 || i == NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES)
            {
                log_descriptor_block = (struct nuvo_log_descriptor_block *)io_req->rw.iovecs[ld_iovec_idx + ld_block_idx].iov_base;
                NUVO_ASSERT(log_descriptor_block != NULL);
                memset(log_descriptor_block, 0, NUVO_BLOCK_SIZE);
                ld_entry_idx = 0;
                ld_block_idx++;
            }

            /* Create the log descriptor entry for this data block */
            struct nuvo_log_descriptor_entry *log_entry;
            log_entry = (struct nuvo_log_descriptor_entry *)&log_descriptor_block->entries[ld_entry_idx];
            if (log_req->nuvo_map_entries[i].type == NUVO_ME_MEDIA)
            {
                /* Log descriptor information passed in as part of the log_req */
                log_entry->is_cv = 0;
                log_entry->log_entry_type = log_req->log_io_blocks[i].log_entry_type;
                log_entry->pit_info = log_req->log_io_blocks[i].pit_info;
                log_entry->bno = log_req->log_io_blocks[i].bno;

                /*
                 * The hash in the map entry was updated during pre-processing of this log request.
                 * The hash is also included the block_hashes on the io request.
                 */
                log_entry->block_hash = log_req->nuvo_map_entries[i].hash;
                io_req->rw.block_hashes[io_iovec_idx] = log_entry->block_hash;

                /* These are the map entries indicating where this block can be found on media */
                log_req->nuvo_map_entries[i].media_addr.parcel_index = seg_req->parcel_index;
                log_req->nuvo_map_entries[i].media_addr.block_offset = seg_req->block_offset + io_iovec_idx;
                (log_req->operation == NUVO_LOG_OP_GC) ? log_entry->gc_media_addr.parcel_index = log_req->log_io_blocks[i].gc_media_addr.parcel_index : 0;
                (log_req->operation == NUVO_LOG_OP_GC) ? log_entry->gc_media_addr.block_offset = log_req->log_io_blocks[i].gc_media_addr.block_offset : 0;

                /* Add the data buffer to the io_req */
                io_req->rw.iovecs[io_iovec_idx].iov_base = log_req->log_io_blocks[i].data;
                io_req->rw.iovecs[io_iovec_idx].iov_len = NUVO_BLOCK_SIZE;
                io_iovec_idx++;

                /* Update the summary table entry */
                struct nuvo_segment_summary_entry *st = &seg_req->log_segment->digest->table[st_entry_idx];
                st->log_entry_type = log_entry->log_entry_type;
                st->block_hash = log_entry->block_hash;
                st->data.pit_info = log_entry->pit_info;
                st->data.bno = log_entry->bno;
                st->data.gc_media_addr.parcel_index = log_entry->gc_media_addr.parcel_index;
                st->data.gc_media_addr.block_offset = log_entry->gc_media_addr.block_offset;
                st_entry_idx++;
            }
            else
            {
                /* The map entry was updated during pre-processing of this log request */
                NUVO_ASSERT(log_req->nuvo_map_entries[i].type == NUVO_ME_CONST);

                log_entry->is_cv = 1;
                log_entry->log_entry_type = log_req->log_io_blocks[i].log_entry_type;
                log_entry->pattern = log_req->nuvo_map_entries[i].pattern;
                log_entry->pit_info = log_req->log_io_blocks[i].pit_info;
                log_entry->bno = log_req->log_io_blocks[i].bno;
                log_entry->gc_media_addr.parcel_index = 0;
                log_entry->gc_media_addr.block_offset = 0;

                /* Flag to indicate in summary table that this log descriptor contains constant values */
                cv_flag = 1;
            }
            ld_entry_idx++;
        }
        NUVO_ASSERT(io_iovec_idx == log_req->io_block_count);

        /* Update information in the log descriptor block headers */
        for (uint32_t i = ld_iovec_idx; i < meta_block_count; i++)
        {
            struct nuvo_log_descriptor_header *log_header;
            log_header = (struct nuvo_log_descriptor_header *)io_req->rw.iovecs[i].iov_base;
            memset(log_header, 0, sizeof(struct nuvo_log_descriptor_header));
            log_header->magic = NUVO_LOG_DESCRIPTOR_MAGIC;
            log_header->sequence_no = log_req->sequence_tag.uint;
            log_header->entry_count = log_req->block_count;
            log_header->data_block_count = log_req->data_block_count;
            uuid_copy(log_header->vs_uuid, nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger)->vs_uuid);
            log_header->operation = log_req->operation;

            /*
             * Calculate the hash of the block and store the value in the block. Then
             * re-calculate the hash of the modified block to be included with on the io request
             * and in the summary table. The block has an internal hash since the summary
             * table is not guaranteed to be present on replay.
             */
            log_header->block_hash = 0;
            log_header->block_hash = nuvo_hash(log_header, NUVO_BLOCK_SIZE);
            io_req->rw.block_hashes[i] = nuvo_hash(log_header, NUVO_BLOCK_SIZE);

            /* Update the summary table entries for the log descriptor blocks */
            /* The summary table records the hash of the block written to media, not it's internal hash */
            struct nuvo_segment_summary_entry *st = &seg_req->log_segment->digest->table[block_index + i];
            st->log_entry_type = NUVO_LE_DESCRIPTOR;
            st->block_hash = io_req->rw.block_hashes[i];
            st->descriptor.cv_flag = cv_flag;
            st->descriptor.entry_count = log_header->entry_count;
            st->descriptor.data_block_count = log_header->data_block_count;
            st->descriptor.sequence_no = log_header->sequence_no;
            st->descriptor.operation = log_header->operation;
        }

        /* Prepare the write request */
        enum nuvo_io_origin io_origin;
        if (log_req->operation == NUVO_LOG_OP_DATA)
        {
            io_origin = NUVO_IO_ORIGIN_USER;
        }
        else if (log_req->operation == NUVO_LOG_OP_GC)
        {
            io_origin = NUVO_IO_ORIGIN_GC_DATA;
        }
        else
        {
            io_origin = NUVO_IO_ORIGIN_INTERNAL;
        }

        NUVO_SET_IO_TYPE(io_req, NUVO_OP_WRITE, io_origin);
        // For now only GC passes down cache hint through the logger
        NUVO_SET_CACHE_HINT(io_req, io_origin == NUVO_IO_ORIGIN_GC_DATA ? log_req->cache_hint : NUVO_CACHE_DEFAULT);

        io_req->tag.ptr = seg_req;
        io_req->callback = segment_io_complete;
        io_req->rw.block_count = log_req->io_block_count;
        io_req->rw.block_offset = seg_req->block_offset;
        io_req->rw.parcel_desc = seg_req->parcel_desc;
        io_req->rw.vol = nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger);

        nuvo_io_concat_submit_req(&seg_req->log_segment->concatenator, io_req);
        break;
    }

    case NUVO_SEGMENT_OP_READ_DIGEST:
    {
        /* Read the segment digest (i.e. footer and summary table) */
        uint8_t *digest_block_ptr = (uint8_t *)seg_req->log_segment->digest;

        NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->tag.ptr = seg_req;
        io_req->callback = segment_read_complete;
        io_req->rw.parcel_desc = seg_req->parcel_desc;
        io_req->rw.block_offset = seg_req->block_offset;
        io_req->rw.block_count = seg_req->block_count;
        io_req->rw.vol = nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger);

        for (uint32_t i = 0; i < io_req->rw.block_count; i++)
        {
            io_req->rw.iovecs[i].iov_base = digest_block_ptr;
            io_req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            digest_block_ptr += NUVO_BLOCK_SIZE;
        }
        nuvo_dlist_init(&submit_list);
        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        nuvo_rl_submit(&submit_list);
        break;
    }

    case NUVO_SEGMENT_OP_READ_DESCRIPTOR:
    case NUVO_SEGMENT_OP_READ_SNAP:
    {
        NUVO_ASSERT(io_req->rw.block_count == seg_req->meta_block_count);

        /* Prepare the read */
        NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->tag.ptr = seg_req;
        io_req->callback = segment_read_complete;
        io_req->rw.block_count = seg_req->meta_block_count;
        io_req->rw.block_offset = seg_req->block_offset;
        io_req->rw.parcel_desc = seg_req->parcel_desc;
        io_req->rw.vol = nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger);

        nuvo_dlist_init(&submit_list);
        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        nuvo_rl_submit(&submit_list);
        break;
    }

    case NUVO_SEGMENT_OP_READ_DATA:
    {
        NUVO_ASSERT(io_req->rw.block_count == seg_req->block_count);

        /* Prepare the read */
        NUVO_SET_IO_TYPE(io_req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(io_req, NUVO_CACHE_DEFAULT);
        io_req->tag.ptr = seg_req;
        io_req->callback = segment_read_complete;
        io_req->rw.block_count = seg_req->block_count;
        io_req->rw.block_offset = seg_req->block_offset;
        io_req->rw.parcel_desc = seg_req->parcel_desc;
        io_req->rw.vol = nuvo_containing_object(seg_req->logger, struct nuvo_vol, log_volume.logger);

        nuvo_dlist_init(&submit_list);
        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        nuvo_rl_submit(&submit_list);
        break;
    }

    default:
        NUVO_PANIC("operation not implemented: %d", seg_req->op);
        break;
    }
}

/** @brief Callback routine for allocating buffers.
 *
 * When this callback is invoked req_alloc will have a nuvo_io_request allocated.
 * This sets up the next call into pr again to get buffers for the io request
 *
 * @param req_alloc A request pointer
 * @return None.
 */
void segment_buf_alloc(struct nuvo_pr_req_alloc *req_alloc)
{
    NUVO_ASSERT(req_alloc != NULL);
    NUVO_ASSERT(req_alloc->req != NULL);

    struct segment_io_req *seg_req = (struct segment_io_req *)req_alloc->tag.ptr;
    NUVO_ASSERT(seg_req != NULL);

    struct nuvo_pr_buf_alloc *buf_alloc = &seg_req->buf_alloc;
    nuvo_pr_buf_alloc_init_req(buf_alloc,
                               req_alloc->req,
                               (union nuvo_tag)(void *)seg_req,
                               segment_rw_submit);
    buf_alloc->req->rw.block_count = seg_req->meta_block_count;

    nuvo_pr_client_buf_alloc_batch(buf_alloc);
}

/** @brief Get a segment off the free list.
 *
 * Checks the devices associated with the currently open segments, and if there's already a segment open on that device
 * will skip it in favor of finding one that's not on the same device. This keeps the set of open segments all on
 * different devices.
 *
 * If no segments meet criteria the routine returns NULL, unless the return_any_flag is set.
 * When the return_any_flag is set the first available segment is returned if none better are available.
 * This flag will be set in case the system has only one open segment and needs another to continue.
 *
 * @param logger Pointer to the logger state
 * @param data_class The data class the new segment must be in.
 * @param subclass Currently unused, but intended for type of data (e.g. GC, map, something)
 * @param return_any_flag A flag to indicate that a segment on a currently open device may be returned if necessary.
 * @return pointer to the new segment, otherwise NULL.
 */
struct nuvo_segment *get_free_segment(struct nuvo_logger *logger, uint8_t data_class, uint8_t subclass, bool return_any_flag)
{
    struct nuvo_segment *seg;
    uint_fast32_t        dev[NUVO_MAX_OPEN_SEGMENTS];
    unsigned             num_avoid = 0;

    for (uint32_t idx = 0; idx < logger->open_data_segments[data_class].max_open_count; idx++)
    {
        if (logger->open_data_segments[data_class].segments[idx].state == NUVO_SEGMENT_OPEN &&
            logger->open_data_segments[data_class].segments[idx].segment->subclass == subclass)
        {
            dev[num_avoid++] = logger->open_data_segments[data_class].segments[idx].segment->device_index;
        }
    }

    /* also avoid segments on devices that've previously been queued for open */
    struct nuvo_segment *segment;
    nuvo_mutex_lock(&logger->segment_open_queue_mutex);
    segment = nuvo_dlist_get_head_object(&logger->segment_open_queue, struct nuvo_segment, list_node);
    while (segment)
    {
        if ((segment->data_class == data_class) && (segment->subclass == subclass))
        {
            dev[num_avoid++] = segment->device_index;
        }
        segment = nuvo_dlist_get_next_object(&logger->segment_open_queue, segment, struct nuvo_segment, list_node);
    }
    nuvo_mutex_unlock(&logger->segment_open_queue_mutex);

    struct nuvo_space_vol *space = &nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger)->log_volume.space;
    /* TODO - confirm how the logger asks for GC segments */
    seg = nuvo_space_vol_segment_get(space, data_class, subclass, num_avoid, dev,
                                     return_any_flag ? NUVO_SPACE_SEGMENT_TRY_AVOID : NUVO_SPACE_SEGMENT_DEFINITELY_AVOID);
    return (seg);
}

/** @brief Get a new segment and a structure to write a fork block.
 *
 * This is a wrapper function to get both a new segment and a segment io request structure to write a fork block.
 *
 * A fork block recording the address of a new segment must be written to an existing open segment.
 * Writing a fork block requires allocating a segment_io_req in order to pass parameters for this io through a series
 * of callbacks.
 *
 * The segment_io_reqs used for fork operations are allocated from a pool.
 * If one is available, then it proceeds to get a new segment off the free list.
 *
 * A pointer to the segment_io_req is returned in fork_req pointer.
 * A pointer to the new segment is returned in the segment pointer.
 *
 * If the routine was able to allocate a segment pointer, and segment_io_request for writing the fork block
 * (if required), It returns true.
 * Otherwise if the requested resources are unavailable it returns false.
 *
 * @param logger Pointer to the logger state
 * @param data_class The data class the new segment must be in.
 * @param subclass The subclass type of segment (for GC or DATA).
 * @param return_any_flag A flag to indicate that a segment on a currently open device may be returned if necessary.
 * @param segment Used to return a pointer to the new segment.
 * @param fork_req  Used to return a pointer to structure for passing parameters to write a fork block.
 * @return True if a segment was allocated, otherwise False.
 */
bool new_segment(struct nuvo_logger *logger, uint8_t data_class, uint8_t subclass, bool return_any_flag, struct nuvo_segment **segment, struct segment_io_req **fork_req)
{
    nuvo_mutex_lock(&logger->segment_io_req_structs_mutex);
    *fork_req = nuvo_dlist_remove_head_object(&logger->segment_io_req_structs[data_class].free_segment_io_reqs, struct segment_io_req, list_node);
    nuvo_mutex_unlock(&logger->segment_io_req_structs_mutex);

    if (*fork_req != NULL)
    {
        if ((*segment = get_free_segment(logger, data_class, subclass, return_any_flag)) != NULL)
        {
            (*segment)->subclass = subclass;
            return (true);
        }

        /* no segment. put the fork_req back on the list */
        nuvo_mutex_lock(&logger->segment_io_req_structs_mutex);
        nuvo_dlist_insert_tail(&logger->segment_io_req_structs[data_class].free_segment_io_reqs, &(*fork_req)->list_node);
        nuvo_mutex_unlock(&logger->segment_io_req_structs_mutex);
    }
    return (false);
}

/**
 * @brief Shuts down the logger for a volume
 *
 * Stops the logger from processing new log write requests.
 * Waits for any log write requests that've previously been enqueued to complete.
 * Waits for all io to complete.
 * Calls nuvo_log_destroy() to release resources.
 *
 * @param vol The volume being shutdown.
 * @return 0 if successful.
 */
nuvo_return_t nuvo_log_shutdown(struct nuvo_vol *vol)
{
    NUVO_ASSERT(vol != NULL);
    struct nuvo_logger *logger = &vol->log_volume.logger;

    /* lock all the queues and change the state of the logger to indicate it's shutting down */
    nuvo_mutex_lock(&logger->segment_io_queue_mutex);
    nuvo_mutex_lock(&logger->segment_close_queue_mutex);
    nuvo_mutex_lock(&logger->segment_open_queue_mutex);

    /* unlock the queues and wait for everything to complete */
    nuvo_mutex_unlock(&logger->segment_io_queue_mutex);
    nuvo_mutex_unlock(&logger->segment_close_queue_mutex);
    nuvo_mutex_unlock(&logger->segment_open_queue_mutex);

    /* Wait for all previously submitted log write requests to be issued */
    nuvo_mutex_lock(&logger->segment_io_queue_mutex);
    while (logger->segment_io_queue_len != 0)
    {
        nuvo_cond_wait(&logger->segment_io_queue_len_zero_cond, &logger->segment_io_queue_mutex);
    }
    nuvo_mutex_unlock(&logger->segment_io_queue_mutex);

    /* Wait for the close queue to reach zero */
    nuvo_mutex_lock(&logger->segment_close_queue_mutex);
    while (logger->close_queue_len != 0)
    {
        nuvo_cond_wait(&logger->close_queue_len_zero_cond, &logger->segment_close_queue_mutex);
    }
    nuvo_mutex_unlock(&logger->segment_close_queue_mutex);

    /* Wait for in flight io requests to complete */
    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    while (logger->pr_io_count != 0)
    {
        nuvo_cond_wait(&logger->pr_io_count_zero_cond, &logger->pr_io_count_mutex);
    }
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    /* Wait for completed io requests to be acknowledged */
    nuvo_mutex_lock(&logger->log_io_count_mutex);
    while (logger->log_io_count != 0)
    {
        nuvo_cond_wait(&logger->log_io_count_zero_cond, &logger->log_io_count_mutex);
    }
    nuvo_mutex_unlock(&logger->log_io_count_mutex);

    nuvo_mutex_lock(&logger->replay_queue_mutex);
    while (logger->replay_queue_len != 0)
    {
        nuvo_cond_wait(&logger->replay_queue_len_zero_cond, &logger->replay_queue_mutex);
    }
    nuvo_mutex_unlock(&logger->replay_queue_mutex);

    nuvo_mutex_lock(&logger->replay_callback_count_mutex);
    while (logger->replay_callback_count != 0)
    {
        nuvo_cond_wait(&logger->replay_callback_count_zero_cond, &logger->replay_callback_count_mutex);
    }
    nuvo_mutex_unlock(&logger->replay_callback_count_mutex);

    /*
     * All queues are empty and all i/o operations are completed.
     * At this point, If there are pending requests to open more segments they can be cancelled.
     * These are segments that were taken off the free list but were never written to.
     */
    struct nuvo_segment *segment;
    while ((segment = nuvo_dlist_remove_head_object(&logger->segment_open_queue, struct nuvo_segment, list_node)) != NULL)
    {
        nuvo_space_vol_segment_done(&vol->log_volume.space, segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);
        logger->open_data_segments[segment->data_class].subclass[segment->subclass].open_queue_len--;
    }

    /* Return in use segments to the manifest */
    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    for (uint32_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        for (uint32_t idx = 0; idx < logger->open_data_segments[data_class].max_open_count; idx++)
        {
            struct logger_segment *seg = &logger->open_data_segments[data_class].segments[idx];
            if ((seg != NULL) && seg->state != NUVO_SEGMENT_CLOSED)
            {
                seg->state = NUVO_SEGMENT_CLOSED;
                logger->open_data_segments[data_class].subclass[seg->segment->subclass].open_count--;
                nuvo_space_vol_segment_done(&vol->log_volume.space, seg->segment, NUVO_MFST_SEGMENT_REASON_UNCHANGED);

                /* put the tracking structure for the summary table back on the free list */
                union digest_tracking_structs *tracking_digest = (union digest_tracking_structs *)seg->digest;
                nuvo_dlnode_init(&tracking_digest->list_node);
                nuvo_mutex_lock(&logger->tracking_structs_mutex);
                nuvo_dlist_insert_tail(&logger->tracking_structs[data_class].free_tracking_structs, &tracking_digest->list_node);
                nuvo_mutex_unlock(&logger->tracking_structs_mutex);
            }
        }
        for (uint8_t type = 0; type < NUVO_MAX_SEGMENT_SUBCLASSES; type++)
        {
            logger->open_data_segments[data_class].subclass[type].active_segment = NULL;
        }
    }
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);

    // Grab the completion list mutex before setting the state to shutdown.
    // This prevents a shutdown race condition where the completion thread
    // could go to sleep while in shutdown state and never wake up.
    nuvo_mutex_lock(&logger->completion_list_mutex);
    logger->state = NUVO_LOG_STATE_SHUTDOWN;
    nuvo_mutex_unlock(&logger->completion_list_mutex);

    nuvo_log_destroy(vol);
    return (0);
}

/** @brief Submit a log request
 *
 * This routine is called to enqueue a log request.
 *
 * \b NUVO_LOG_OP_DATA
 * Pre-processes data log requests to determine how many log descriptors the request
 * will require and if there any data blocks containing constant values and don't
 * require writing to the log.
 *
 * \b NUVO_LOG_OP_MAP
 * Handled the same as NUVO_LOG_OP_DATA, but constant value detection is not performed.
 *
 * \b NUVO_LOG_OP_GC
 * This indicates that the request contain data blocks cleaned from older segments.
 * Data blocks written by the cleaner are written to segment dedicated for garbage collection.
 *
 * @param log_req The log request to be enqueued.
 * @return None.
 */
void nuvo_log_submit(struct nuvo_log_request *log_req)
{
    NUVO_ASSERT(log_req != NULL);
    struct nuvo_logger *logger = &log_req->vs_ptr->log_volume.logger;
    uint32_t            meta_block_count = 0;
    uint32_t            data_block_count = 0;

    NUVO_ASSERT(logger->state == NUVO_LOG_STATE_RUNNING);

    switch (log_req->operation)
    {
    case NUVO_LOG_OP_DATA:
    case NUVO_LOG_OP_MAP:
    case NUVO_LOG_OP_GC:

        /*
         * Each log io request is limited to NUVO_MAX_IO_BLOCKS total size.
         * There can be up to 3 additional blocks of meta data written as part of log write.
         */
        NUVO_ASSERT(log_req->block_count <= NUVO_MAX_IO_BLOCKS - NUVO_MAX_LOG_DESCRIPTOR_BLOCKS - NUVO_SEGMENT_HEADER_BLOCKS);

        /* Calculate the number of log descriptor blocks needed. Each  block can have up to 128 entries */
        meta_block_count = (log_req->block_count <= NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES) ? 1 : 2;

        /*
         * Process the input data blocks, checking for constant value entries, and marking blocks that are.
         * Data blocks which are constant value only require a log descriptor entry, and don't need to be written
         *
         * The log entry type must be set by the caller to indicate the type of log entry being made.
         * This value may be overridden by the logger when a constant value is detected and the destination device
         * is not a HDD, otherwise it's used as is.
         */
        for (uint32_t i = 0; i < log_req->block_count; i++)
        {
            nuvo_hash_t hash;
            uint64_t    cv;
            int         is_cv;

            switch (log_req->operation)
            {
            case NUVO_LOG_OP_DATA:
                hash = nuvo_hash_cv(log_req->log_io_blocks[i].data, NUVO_BLOCK_SIZE, &cv, &is_cv);
                if (is_cv)
                {
                    // When the type is NUVO_ME_CONST store both the pattern and the hash.
                    // The hash will be needed if this log_req gets written to an HDD.
                    log_req->log_io_block_hashes[i].type = NUVO_ME_CONST;
                    log_req->log_io_block_hashes[i].hash = hash;
                    log_req->log_io_block_hashes[i].pattern = cv;
                }
                else
                {
                    // when the type is NUVO_ME_MEDIA only the hash will be used.
                    log_req->log_io_block_hashes[i].type = NUVO_ME_MEDIA;
                    log_req->log_io_block_hashes[i].hash = hash;
                    data_block_count++;
                }
                break;

            case NUVO_LOG_OP_MAP:
                // The map tells the logger if a map block is zero or not.
                if (log_req->log_io_blocks[i].map_is_zero)
                {
                    log_req->log_io_block_hashes[i].type = NUVO_ME_CONST;
                    log_req->log_io_block_hashes[i].pattern = NUVO_MAP_IS_ZERO_PATTERN;
                }
                else
                {
                    hash = nuvo_hash(log_req->log_io_blocks[i].data, NUVO_BLOCK_SIZE);
                    log_req->log_io_block_hashes[i].type = NUVO_ME_MEDIA;
                    log_req->log_io_block_hashes[i].hash = hash;
                    data_block_count++;
                }
                break;

            case NUVO_LOG_OP_GC:

                /*
                 * GC passes in a data blocks, with their old media address and block hash
                 * the block hashes given on the request are used instead of recalculating.
                 */
                log_req->log_io_block_hashes[i].type = NUVO_ME_MEDIA;
                log_req->log_io_block_hashes[i].hash = log_req->log_io_blocks[i].gc_block_hash;
                data_block_count++;
                break;

            default:
                NUVO_PANIC("invalid operation: %u", log_req->operation);
                break;
            }
        }

        // For convenience, store calculated values in the log request.
        // nocv_io_block_count is used to store the size of the operation with CV detection disabled.
        log_req->data_block_count = data_block_count;
        log_req->meta_block_count = meta_block_count;
        log_req->io_block_count = data_block_count + meta_block_count;
        log_req->nocv_io_block_count = log_req->block_count + meta_block_count;

        break;

    case NUVO_LOG_OP_CREATE_SNAP:
    case NUVO_LOG_OP_DELETE_SNAP:
        /* A snap operation writes a single log descriptor with the lun ID and lun UUID of the snapshot */
        log_req->data_block_count = 0;
        log_req->meta_block_count = NUVO_SEGMENT_SNAP_BLOCKS;
        log_req->io_block_count = NUVO_SEGMENT_SNAP_BLOCKS;
        log_req->nocv_io_block_count = NUVO_SEGMENT_SNAP_BLOCKS;
        break;

    default:
        NUVO_PANIC("operation not implemented: %d", log_req->operation);
    }

    /*
     * Puts this log request in the io processing queue.
     * If the logger is in shutdown then cancel the request.
     */
    nuvo_mutex_lock(&logger->segment_io_queue_mutex);
    if (logger->state != NUVO_LOG_STATE_RUNNING)
    {
        nuvo_mutex_unlock(&logger->segment_io_queue_mutex);
        log_req->status = NUVO_ECANCELED;
        log_req->callback(log_req);
        return;
    }
    nuvo_dlnode_init(&log_req->list_node);
    nuvo_dlist_insert_tail(&logger->segment_io_queue, &log_req->list_node);
    logger->segment_io_queue_len++;
    nuvo_mutex_unlock(&logger->segment_io_queue_mutex);
    nuvo_process_segment_io_queue(logger);
}

/** @brief Process queued log write requests
 *
 * Looks at each log request and attempts to find a segment meeting the free space and data class criteria
 * The logger aims to write to segments in a round robin manner. If a segment does not have enough space for
 * the write it is closed, this continues until a suitable segment is found, or all segments are closing.
 *
 * If a suitable segment could not be found, a new segment will be opened. If that open operation
 * could not be completed synchronously, the log write request will remain queued and be completed
 * once a new segment is available.
 *
 * If segments were closed, new segments will be allocated off the free list and additional open operations
 * will be queued. If there are no more free segments, log requests may still be queued, but will remain
 * queued until free segments are available.
 *
 * @param logger Pointer to the logger state.
 * @return None.
 */
void nuvo_process_segment_io_queue(struct nuvo_logger *logger)
{
    bool rerun_queue_flag;

    if (logger->state == NUVO_LOG_STATE_SHUTDOWN)
    {
        /*
         * nuvo_process_segment_io_queue is called after manifest writing is done for a CP.
         * It's possible the volume could be closed and destroyed after the CP completes
         * but before this function is called.
         * If the logger is shutdown then there's no work to do.
         */
        return;
    }

    do
    {
        struct nuvo_log_request *log_req;

        nuvo_mutex_lock(&logger->segment_io_queue_mutex);
        nuvo_mutex_lock(&logger->open_data_segments_mutex);
        rerun_queue_flag = false;

        log_req = nuvo_dlist_get_head_object(&logger->segment_io_queue, struct nuvo_log_request, list_node);
        while (log_req)
        {
            int32_t active_segment_idx;
            bool    write_flag = false;
            uint8_t data_class = log_req->data_class;
            uint8_t type = (log_req->operation == NUVO_LOG_OP_GC) ? NUVO_SEGMENT_TYPE_GC : NUVO_SEGMENT_TYPE_DATA;

            /*
             * The active segment is the last segment that was written into.
             * If a write to this data class has never happened, active segment will be NULL.
             * This will be the case when there's a new volume.
             */
            struct logger_segment *active_segment = logger->open_data_segments[data_class].subclass[type].active_segment;
            if (!active_segment || active_segment->state == NUVO_SEGMENT_CLOSED)
            {
                active_segment_idx = -1;
            }
            else
            {
                active_segment_idx = active_segment - logger->open_data_segments[data_class].segments;
            }

            uint32_t max_open_count = logger->open_data_segments[data_class].max_open_count;
            for (uint32_t i = active_segment_idx + 1; i <= (max_open_count + active_segment_idx); i++)
            {
                int32_t idx = i % max_open_count;
                struct logger_segment *seg = &logger->open_data_segments[data_class].segments[idx];

                if (seg && seg->state == NUVO_SEGMENT_OPEN && seg->segment->subclass == type)
                {
                    int32_t io_block_count;
                    bool    nocv_hdd = false;
                    if ((log_req->operation == NUVO_LOG_OP_DATA) && (seg->segment->device_type == NUVO_DEV_TYPE_HDD))
                    {
                        // TODO: CV detection for HDDs is only disabled on data writes, it should support map writes as well.
                        io_block_count = log_req->nocv_io_block_count;
                        nocv_hdd = true;
                    }
                    else
                    {
                        // Map and gc operations don't have special handling for HDDs.
                        io_block_count = log_req->io_block_count;
                    }

                    if (seg->free_block_count >= io_block_count)
                    {
                        // Found a suitable segment
                        // Since the device type for the write is now known,
                        // set the log_req io_block_count and data_block_count to the correct values for what we intend to write.
                        if (nocv_hdd)
                        {
                            // Set the io_block_count now that we know the write destination is an HDD.
                            // Although we could allow for mixed CV and data writes to HDD if the total io size >= 8 blocks,
                            // we completely turn off CV detection for HDDs since it also impacts replay performance as
                            // replay would require a 4K io to recover the CV from the log descriptor.
                            log_req->io_block_count = log_req->nocv_io_block_count;
                            log_req->data_block_count = log_req->block_count;
                            NUVO_ASSERT(log_req->io_block_count == (log_req->data_block_count + log_req->meta_block_count))
                        }
                        // Sets the hashes and or CVs as needed in the nuvo_map_entries return array
                        logger_set_map_entry_hashes(log_req, seg->segment->device_type);

                        write_segment(logger, log_req, seg);
                        active_segment = logger->active_segment = logger->open_data_segments[data_class].subclass[type].active_segment = seg;
                        active_segment_idx = active_segment - logger->open_data_segments[data_class].segments;
                        write_flag = true;
                        break;
                    }
                    else
                    {
                        /*
                         * Close any open segments that don't have enough free blocks for this request.
                         * The exception is the active segment which is left open to later have a fork block written.
                         */
                        if (idx != active_segment_idx)
                        {
                            close_segment(logger, seg, true);
                        }
                    }
                }
            }

            if (!write_flag)
            {
                /*
                 * All segments are being closed except for the active segment.
                 * Request a new segment, setting a flag to indicate any segment will do.
                 * In the case where there is only one device this will concatenate the log into the next segment.
                 * Always re-run to prevent the queue from hanging when all segments are in a closing state.
                 */
                if (!active_segment)
                {
                    /* forking into a new data class that's never been open before */
                    /* use the last segment written to to write the fork block */
                    struct nuvo_segment   *segment;
                    struct segment_io_req *fork_req;
                    if (new_segment(logger, data_class, type, true, &segment, &fork_req))
                    {
                        /* Write fork block into active segment */
                        fork_segment(logger, logger->active_segment, segment, fork_req);
                        /* Open a new segment */
                        rerun_queue_flag = open_segment(logger, segment);
                    }
                }
                else if (active_segment->state == NUVO_SEGMENT_OPEN)
                {
                    /* Closing the active (last) segment */
                    struct nuvo_segment   *segment;
                    struct segment_io_req *fork_req;
                    if (new_segment(logger, data_class, type, true, &segment, &fork_req))
                    {
                        /* Write fork block into active segment */
                        fork_segment(logger, active_segment, segment, fork_req);
                        /* Close the active segment */
                        close_segment(logger, active_segment, true);
                        /* Open a new segment */
                        rerun_queue_flag = open_segment(logger, segment);
                    }
                }
            }

            /* Try to open additional segments if required and available */
            if ((logger->open_data_segments[data_class].subclass[type].open_count +
                 logger->open_data_segments[data_class].subclass[type].open_queue_len) <
                logger->open_data_segments[data_class].subclass[type].max_open_count)
            {
                uint32_t max_open_count = logger->open_data_segments[data_class].max_open_count;
                for (uint32_t i = active_segment_idx + 1; i <= (max_open_count + active_segment_idx); i++)
                {
                    int32_t idx = i % max_open_count;
                    struct logger_segment *seg = &logger->open_data_segments[data_class].segments[idx];

                    /* Only write a fork into open segments that have a header and at least one free block (don't allow use the reserved fork block here) */
                    if (seg && ((seg->state == NUVO_SEGMENT_OPEN) &&
                                (seg->free_block_count >= NUVO_SEGMENT_FOOTER_BLOCKS) &&
                                (seg->current_offset != seg->segment->block_offset)))
                    {
                        struct nuvo_segment   *segment = NULL;
                        struct segment_io_req *fork_req;
                        if (new_segment(logger, data_class, type, false, &segment, &fork_req))
                        {
                            fork_segment(logger, seg, segment, fork_req);
                            if (open_segment(logger, segment))
                            {
                                rerun_queue_flag = true;
                            }
                            if ((logger->open_data_segments[data_class].subclass[type].open_count + logger->open_data_segments[data_class].subclass[type].open_queue_len) >= logger->open_data_segments[data_class].subclass[type].max_open_count)
                            {
                                break;
                            }
                        }
                        else
                        {
                            /* No free segments, so stop asking */
                            break;
                        }
                    }
                }
            }

            if (write_flag)
            {
                struct nuvo_log_request *next_log_req;
                next_log_req = nuvo_dlist_get_next_object(&logger->segment_io_queue, log_req, struct nuvo_log_request, list_node);
                nuvo_dlist_remove(&log_req->list_node);
                if (--logger->segment_io_queue_len == 0)
                {
                    nuvo_cond_signal(&logger->segment_io_queue_len_zero_cond);
                }
                log_req = next_log_req;
            }
            else
            {
                log_req = nuvo_dlist_get_next_object(&logger->segment_io_queue, log_req, struct nuvo_log_request, list_node);
            }
        }
        nuvo_mutex_unlock(&logger->open_data_segments_mutex);
        nuvo_mutex_unlock(&logger->segment_io_queue_mutex);
    } while (rerun_queue_flag);
}

/**
 * @brief Queue an i/o request to write log data to a segment
 *
 * Prepares a segment_io_req to write log data to a segment.
 * All data writes are assigned a sequence number, which determines this log_reqs order
 * in the log.
 *
 * Before calling write_segment() the caller must pre-process the data blocks on the log_req
 * to determine if a block contains a constant value, or otherwise calculate the blocks checksum.
 * The pre-processing of the log request also determines how many log descriptor blocks
 * are required.
 *
 * write_segment() is also used to write snapshot blocks in the log. Snapshot blocks record the
 * creation or deletion of a snapshot. A snapshot block is a single a metadata block that
 * records the pit_id and pit_uuid from the snapshot log_req.
 *
 * If this is the first write to the segment a flag is set on the nuvo_log_req indicating that
 * a nuvo_segment_header segment header must be written, and requests allocation of an additional block on the io_req
 * to write the header.
 *
 * The segment_io_req used for the write operation is statically allocated as part of the log_req.
 *
 * @param logger Pointer to the logger state.
 * @param log_req Pointer to originating log_req.
 * @param log_segment Pointer to the segment where the data will be written
 * @return None.
 */
void write_segment(struct nuvo_logger *logger, struct nuvo_log_request *log_req, struct logger_segment *log_segment)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_req != NULL);
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT(log_segment->free_block_count >= (int32_t)log_req->io_block_count);

    struct segment_io_req *seg_req = &log_req->segment_req;
    memset(seg_req, 0, sizeof(struct segment_io_req));

    /* Check if segments ever been written to and write a segment header if needed  */
    if (log_segment->current_offset == log_segment->segment->block_offset)
    {
        log_req->io_block_count += NUVO_SEGMENT_HEADER_BLOCKS;
        log_req->meta_block_count += NUVO_SEGMENT_HEADER_BLOCKS;
        log_req->write_header_flag = true;
    }
    else
    {
        log_req->write_header_flag = false;
    }

    if ((log_req->operation == NUVO_LOG_OP_CREATE_SNAP) ||
        (log_req->operation == NUVO_LOG_OP_DELETE_SNAP))
    {
        seg_req->op = NUVO_SEGMENT_OP_SNAP;
    }
    else
    {
        seg_req->op = NUVO_SEGMENT_OP_WRITE;
    }
    seg_req->sequence_no = log_req->sequence_tag.uint = get_next_sequence_no(logger);
    seg_req->parcel_desc = log_segment->segment->parcel_desc;
    seg_req->parcel_index = log_segment->segment->parcel_index;
    seg_req->block_offset = log_segment->current_offset;
    seg_req->block_count = log_req->io_block_count;
    seg_req->meta_block_count = log_req->meta_block_count;
    seg_req->logger = logger;
    seg_req->log_req = log_req;
    seg_req->log_segment = log_segment;

    /* Adjust the segment tracking data */
    log_segment->current_offset += log_req->io_block_count;
    log_segment->free_block_count -= log_req->io_block_count;
    log_segment->last_sequence_no = log_req->sequence_tag.uint;
    NUVO_ASSERT(log_segment->free_block_count >= 0);

    nuvo_mutex_lock(&logger->log_io_count_mutex);
    logger->log_io_count++;
    nuvo_mutex_unlock(&logger->log_io_count_mutex);

    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    logger->pr_io_count++;
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    struct nuvo_pr_req_alloc *req_alloc = &seg_req->req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);
    req_alloc->tag.ptr = seg_req;
    req_alloc->callback = segment_buf_alloc;

    NUVO_LOG(logger, 100, "write (op: %u). sequence no: %lu segment: %lu:%lu offset: %lu descriptors: %u, entries: %u, total log entry size: %u",
             seg_req->op, seg_req->sequence_no, seg_req->parcel_index, log_segment->segment->block_offset, seg_req->block_offset,
             seg_req->meta_block_count, seg_req->block_count - seg_req->meta_block_count, seg_req->block_count);

    nuvo_pr_client_req_alloc_cb(req_alloc);
}

/** @brief Queue an i/o request to write a fork block
 *
 * Prepares a segment_io_req to write a fork block to a segment
 * The segment_io_req that was allocated when the new segment was allocated is used
 * to  pass parameters for the fork operation through the callback series.
 *
 * If this is the first write to the segment a flag is set on the nuvo_log_req indicating that
 * a nuvo_segment_header segment header must be written, and requests allocation of an additional block on the io_req
 * to write the header.
 *
 * @param logger Pointer to the logger state variables.
 * @param log_segment Pointer to the segment where the fork block will be written
 * @param segment Pointer to the new segment address being written into the fork
 * @param seg_req Pointer to structure for passing i/o parameters on the callbacks.
 * @return None..
 */
void fork_segment(struct nuvo_logger *logger, struct logger_segment *log_segment, struct nuvo_segment *segment, struct segment_io_req *seg_req)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT(segment != NULL);
    NUVO_ASSERT(seg_req != NULL);

    memset(seg_req, 0, sizeof(struct segment_io_req));
    nuvo_dlnode_init(&seg_req->list_node);

    NUVO_ASSERT(log_segment->free_block_count >= 0);

    /*
     * The fork can be safely written at the current offset even with no free blocks
     * because there's a block reserved for a fork as the last block before the segment footer.
     */
    seg_req->op = NUVO_SEGMENT_OP_FORK;
    seg_req->sequence_no = get_next_sequence_no(logger);
    seg_req->parcel_desc = log_segment->segment->parcel_desc;
    seg_req->parcel_index = log_segment->segment->parcel_index;
    seg_req->block_offset = log_segment->current_offset;
    seg_req->meta_block_count = 1;
    seg_req->block_count = seg_req->meta_block_count;
    seg_req->log_segment = log_segment;
    seg_req->logger = logger;

    /* if a volume has multiple data classes it's possible the first log request write requires a fork */
    /* this requires a segment header to be written with the fork */
    if (seg_req->block_offset == log_segment->segment->block_offset)
    {
        seg_req->meta_block_count += NUVO_SEGMENT_HEADER_BLOCKS;
        seg_req->fork.write_header_flag = true;
    }
    else
    {
        seg_req->fork.write_header_flag = false;
    }

    /* Pointer to the segment information to be written to the fork block */
    seg_req->fork.segment = segment;

    /* Adjust the current offset and free blocks if the reserved fork block wasn't used */
    NUVO_ASSERT(log_segment->free_block_count >= 0);
    log_segment->current_offset += seg_req->meta_block_count;
    log_segment->free_block_count -= seg_req->meta_block_count;
    log_segment->last_sequence_no = seg_req->sequence_no;

    nuvo_mutex_lock(&logger->log_io_count_mutex);
    logger->log_io_count++;
    nuvo_mutex_unlock(&logger->log_io_count_mutex);

    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    logger->pr_io_count++;
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    struct nuvo_pr_req_alloc *req_alloc = &seg_req->req_alloc;
    nuvo_dlnode_init(&req_alloc->list_node);
    req_alloc->tag.ptr = seg_req;
    req_alloc->callback = segment_buf_alloc;

    NUVO_LOG(logger, 100, "fork. sequence no: %lu. segment: %lu:%lu. write offset: %lu. fork to segment %lu:%lu.",
             seg_req->sequence_no, seg_req->parcel_index, log_segment->segment->block_offset, seg_req->block_offset,
             seg_req->fork.segment->parcel_index, seg_req->fork.segment->block_offset);

    nuvo_pr_client_req_alloc_cb(req_alloc);
}

/** @brief Queue a request to close a segment
 *
 * This is an async routine to close a segment by writing the segment digest and free it's tracking structures.
 *
 * The caller must hold the lock on list of open data segments.
 *
 * @param logger Pointer to the logger state variables.
 * @param log_segment Pointer to the new segment to be opened.
 * @param write_digest When set to true the segment digest will be written to media.
 * @return None..
 */
void close_segment(struct nuvo_logger *logger, struct logger_segment *log_segment, bool write_digest)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT_MUTEX_HELD(&logger->open_data_segments_mutex);

    uint8_t data_class = log_segment->segment->data_class;
    uint8_t type = log_segment->segment->subclass;

    /* For a segment close the segment_io_request struct is part of the tracking structure */
    struct segment_io_req *seg_req = &log_segment->segment_req;
    memset(seg_req, 0, sizeof(struct segment_io_req));
    nuvo_dlnode_init(&seg_req->list_node);

    if (write_digest)
    {
        seg_req->op = NUVO_SEGMENT_OP_CLOSE;
        seg_req->parcel_index = log_segment->segment->parcel_index;
        seg_req->parcel_desc = log_segment->segment->parcel_desc;
        seg_req->block_offset = get_segment_digest_offset(log_segment->segment);
        seg_req->meta_block_count = get_segment_digest_len(log_segment->segment);
        seg_req->block_count = seg_req->meta_block_count;
        seg_req->log_segment = log_segment;
        seg_req->logger = logger;

        nuvo_mutex_lock(&logger->cp_trigger_mutex);
        logger->cp_trigger_segments_used_count++;
        nuvo_mutex_unlock(&logger->cp_trigger_mutex);
    }
    else
    {
        /* fast close is only used during replay since the digest is already on media */
        seg_req->op = NUVO_SEGMENT_OP_FAST_CLOSE;
        seg_req->log_segment = log_segment;
        seg_req->logger = logger;
    }

    /* stop any new writes to this segment */
    log_segment->state = NUVO_SEGMENT_CLOSING;

    nuvo_mutex_lock(&logger->segment_close_queue_mutex);
    nuvo_dlist_insert_tail(&logger->segment_close_queue, &seg_req->list_node);
    logger->open_data_segments[data_class].subclass[type].open_count--;
    logger->close_queue_len++;
    nuvo_mutex_unlock(&logger->segment_close_queue_mutex);

    process_segment_close_queue(logger);
}

/** @brief Process queued requests to close segments
 *
 * The close segment is queue is a list of segments which need to be closed.
 *
 * Closing a segment requires all previous i/o to the segment to have
 * completed and be acknowledged. After all i/o to the segment has
 * completed a segment digest is written which includes a segment
 * footer block and multi-block summary table which represents a
 * block map of the segment.
 *
 * @param logger Pointer to the logger state variables.
 * @return None.
 */
void process_segment_close_queue(struct nuvo_logger *logger)
{
    nuvo_mutex_lock(&logger->segment_close_queue_mutex);
    nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);

    struct segment_io_req *seg_req;
    seg_req = nuvo_dlist_get_head_object(&logger->segment_close_queue, struct segment_io_req, list_node);
    while (seg_req)
    {
        struct logger_segment *seg = seg_req->log_segment;
        if (seg_req->op == NUVO_SEGMENT_OP_FAST_CLOSE)
        {
            NUVO_LOG(logger, 100, "fast close. segment: %lu:%lu.", seg->segment->parcel_index, seg->segment->block_offset);

            /* Closing a segment during replay does not require writing the summary table */
            struct segment_io_req *next_seg_req;
            next_seg_req = nuvo_dlist_get_next_object(&logger->segment_close_queue, seg_req, struct segment_io_req, list_node);
            nuvo_dlist_remove(&seg_req->list_node);

            free_logger_segment(logger, seg);

            if (--logger->close_queue_len == 0)
            {
                nuvo_cond_signal(&logger->close_queue_len_zero_cond);
            }
            seg_req = next_seg_req;
        }
        else if (seg->last_sequence_no < logger->lowest_sequence_no)
        {
            /* All log writes to this segment have been completed and acknowledged */
            struct segment_io_req *next_seg_req;
            next_seg_req = nuvo_dlist_get_next_object(&logger->segment_close_queue, seg_req, struct segment_io_req, list_node);
            nuvo_dlist_remove(&seg_req->list_node);
            struct nuvo_pr_req_alloc *req_alloc = &seg_req->req_alloc;
            nuvo_dlnode_init(&req_alloc->list_node);

            /*
             * Record the current lowest sequence number.
             * This is used during recovery to determine if the digest was written before or after the
             * last CP (i.e. sequence number to start replay).
             */
            seg_req->close.closing_sequence_no = logger->lowest_sequence_no;

            nuvo_mutex_lock(&logger->pr_io_count_mutex);
            logger->pr_io_count++;
            nuvo_mutex_unlock(&logger->pr_io_count_mutex);

            req_alloc->tag.ptr = seg_req;
            req_alloc->callback = segment_write_summarytable_submit;

            NUVO_LOG(logger, 100, "close. segment: %lu:%lu. closing sequence no: %lu. last sequence no: %lu.",
                     seg->segment->parcel_index, seg->segment->block_offset, seg_req->close.closing_sequence_no, seg->last_sequence_no);

            nuvo_pr_client_req_alloc_cb(req_alloc);
            if (--logger->close_queue_len == 0)
            {
                nuvo_cond_signal(&logger->close_queue_len_zero_cond);
            }
            seg_req = next_seg_req;
        }
        else
        {
            /* This close operation is waiting for outstanding io to this segment to completed and be acknowledged */
            seg_req = nuvo_dlist_get_next_object(&logger->segment_close_queue, seg_req, struct segment_io_req, list_node);
        }
    }
    nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);
    nuvo_mutex_unlock(&logger->segment_close_queue_mutex);
}

/** @brief Queue a request to open a new segment
 *
 * This is an async routine to get a tracking structure for an open segment.
 * If a tracking structure is available this function may complete the allocation to the open segment
 * synchronously. When this happens the function returns true.
 *
 * There isn't a dedicated thread that can process requests waiting for an open segment.
 * If a tracking structure is available, this routine may complete the allocation synchronously.
 * If this happens, the caller is alerted so it can retry the write operation.
 * This is necessary to prevent the write from waiting indefinitely.
 *
 * The caller must hold the lock on list of open data segments.
 *
 * @param logger Pointer to the logger state variables.
 * @param segment Pointer to the new segment to be opened.
 * @return True if a segment was opened synchronously, otherwise False.
 */
bool open_segment(struct nuvo_logger *logger, struct nuvo_segment *segment)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(segment != NULL);
    NUVO_ASSERT_MUTEX_HELD(&logger->open_data_segments_mutex);

    nuvo_dlnode_init(&segment->list_node);
    nuvo_mutex_lock(&logger->segment_open_queue_mutex);
    nuvo_dlist_insert_tail(&logger->segment_open_queue, &segment->list_node);
    logger->open_data_segments[segment->data_class].subclass[segment->subclass].open_queue_len++;
    nuvo_mutex_unlock(&logger->segment_open_queue_mutex);

    return (process_segment_open_queue(logger));
}

/** @brief Process queued requests to open new segments
 *
 * The open segment is queue is a list of segments which need to be allocated
 * a tracking structure for the segment and the segment digest.
 *
 * Opening a segment does not require i/o, but may depend on previous i/o to
 * closing segments to complete in order to have free tracking structures
 * available.
 *
 * In the case where an open request is completed, the routine returns
 * true, to indicate a new segment was opened. This is used as flag to
 * tell the caller it may try again to write to a segment.
 *
 * The caller must hold the lock on list of open data segments.
 *
 * @param logger Pointer to the logger state variables.
 * @return True if a segment was opened, otherwise False.
 */
bool process_segment_open_queue(struct nuvo_logger *logger)
{
    struct nuvo_segment *segment;
    bool retry_flag = false;

    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT_MUTEX_HELD(&logger->open_data_segments_mutex);

    nuvo_mutex_lock(&logger->segment_open_queue_mutex);
    segment = nuvo_dlist_get_head_object(&logger->segment_open_queue, struct nuvo_segment, list_node);
    while (segment)
    {
        bool    open_flag = false;
        uint8_t data_class = segment->data_class;
        uint8_t type = segment->subclass;

        /* Find a closed out segment and get a tracking structure for the summary table and footer */
        uint32_t max_open_count = logger->open_data_segments[data_class].max_open_count;
        for (uint32_t i = 0; i < max_open_count; i++)
        {
            struct logger_segment *seg = &logger->open_data_segments[data_class].segments[i];
            if (seg->state == NUVO_SEGMENT_CLOSED)
            {
                nuvo_mutex_lock(&logger->tracking_structs_mutex);
                struct nuvo_segment_digest *digest = (struct nuvo_segment_digest *)nuvo_dlist_remove_head_object(&logger->tracking_structs[data_class].free_tracking_structs, union digest_tracking_structs, list_node);
                nuvo_mutex_unlock(&logger->tracking_structs_mutex);
                if (digest)
                {
                    memset(digest, 0, sizeof(struct nuvo_segment_digest));
                    seg->digest = digest;
                    seg->segment = segment;
                    seg->current_offset = segment->block_offset;
                    seg->last_sequence_no = 0;
                    seg->free_block_count = get_segment_digest_offset(segment) - segment->block_offset - NUVO_SEGMENT_FORK_BLOCKS;
                    if (logger->state == NUVO_LOG_STATE_REPLAY)
                    {
                        /* if the logger is in replay then we need to read the segment digest */
                        seg->state = NUVO_SEGMENT_REPLAY_PENDING;
                        seg->replay.is_processed = false;
                        read_segment_digest(logger, seg);
                        open_flag = true;
                    }
                    else
                    {
                        seg->state = NUVO_SEGMENT_OPEN;
                        retry_flag = open_flag = true;
                    }

                    /* if this is the first segment opened in this class it becomes the active segment */
                    if (logger->open_data_segments[data_class].subclass[type].active_segment == NULL)
                    {
                        logger->open_data_segments[data_class].subclass[type].active_segment = seg;
                        if (logger->state == NUVO_LOG_STATE_REPLAY && logger->active_segment == NULL)
                        {
                            /* if this is the first segment opened on replay set it as the last segment written */
                            logger->active_segment = logger->open_data_segments[data_class].subclass[type].active_segment;
                        }
                    }
                    logger->open_data_segments[data_class].subclass[type].open_count++;
                    NUVO_LOG(logger, 100, "open. segment: %lu:%lu.", segment->parcel_index, segment->block_offset);
                }
                /* No tracking structure available */
                break;
            }
        }

        if (open_flag)
        {
            struct nuvo_segment *next_segment;
            next_segment = nuvo_dlist_get_next_object(&logger->segment_open_queue, segment, struct nuvo_segment, list_node);
            nuvo_dlist_remove(&segment->list_node);
            logger->open_data_segments[data_class].subclass[type].open_queue_len--;
            segment = next_segment;
        }
        else
        {
            /* No segments of this class in closed state */
            segment = nuvo_dlist_get_next_object(&logger->segment_open_queue, segment, struct nuvo_segment, list_node);
        }
    }
    nuvo_mutex_unlock(&logger->segment_open_queue_mutex);
    return (retry_flag);
}

/**@brief Free logger resources associate with an open segment
 *
 * This function returns the segment to manifest and frees associated tracking structures
 * That were allocated when the segment was open.
 *
 *@param logger The logger state.
 *@param log_segment The logger segment to free.
 *@return None.
 */
void free_logger_segment(struct nuvo_logger *logger, struct logger_segment *log_segment)
{
    NUVO_ASSERT(logger != NULL);
    NUVO_ASSERT(log_segment != NULL);
    NUVO_ASSERT(log_segment->state != NUVO_SEGMENT_CLOSED);

    /* Inform the manifest the logger is finished with the segment */
    struct nuvo_vol *vol = nuvo_containing_object(logger, struct nuvo_vol, log_volume.logger);
    nuvo_space_vol_segment_done(&vol->log_volume.space, log_segment->segment, NUVO_MFST_SEGMENT_REASON_SET_AGE);

    /* Put the tracking structure for the summary table back on the free list */
    uint8_t data_class = log_segment->segment->data_class;
    union digest_tracking_structs *tracking_digest = (union digest_tracking_structs *)log_segment->digest;
    nuvo_dlnode_init(&tracking_digest->list_node);
    nuvo_mutex_lock(&logger->tracking_structs_mutex);
    nuvo_dlist_insert_tail(&logger->tracking_structs[data_class].free_tracking_structs, &tracking_digest->list_node);
    nuvo_mutex_unlock(&logger->tracking_structs_mutex);

    log_segment->state = NUVO_SEGMENT_CLOSED;
    log_segment->digest = NULL;
    log_segment->segment = NULL;
}

/**@brief Freeze performing io completions with the map and return sequence number
 *
 * The logger performs io completions synchronously and in order by running the callback on the log request and
 * waiting for nuvo_log_ack_sno() to be called when the map update has completed.
 * When the logger is frozen it will not run completion callbacks, however new log writes will be accepted and issued.
 * The resulting completions will be queued but not run until io completions are resumed.
 *
 * Freeze first takes the completion_list_mutex. At the time the completion queue is locked there may be a completion
 * in progress with the map. nuvo_log_freeze_map_updates() will synchronously wait for this io completion to the
 * acknowledged before getting the sequence number. This ensures that the lowest unacknowledged sequence number
 * doesn't change while updates are frozen. To account for an io completion that's in progress with map, the logger
 * sets acking_sequence_no before running the callback, and unset when the map update is acknowledged.
 *
 * The completions_frozen flag is set, which stops completion callbacks from running while frozen.
 *
 * Note that holding the completion_list_mutex and the lowest_sequence_no_mutex for the duration of the freeze would
 * stop new io from being serviced as a side effect. Locking the completion list would block any io completion threads,
 * and locking the lowest_sequence_no would potentially block segments from being closed (and new segments from being
 * opened).
 *
 * The sequence_no returned is the lowest_sequence_no number that the logger hasn't acknowledged. This is the sequence
 * number where replay should start as it's the lowest sequence number not completed with the map.
 *
 * Calling nuvo_log_unfreeze_map_updates() releases the lock and sets the state.
 *
 * @param vol A pointer the volume series.
 * @return The sequence number, representing the lowest sequence number that the logger has NOT acknowledged.
 */
uint64_t nuvo_log_freeze_map_updates(struct nuvo_vol *vol)
{
    NUVO_ASSERT(vol != NULL);
    struct nuvo_logger *logger = &vol->log_volume.logger;

    /* get the completion list lock, this will stop further completions from being sent. */
    nuvo_mutex_lock(&logger->completion_list_mutex);

    NUVO_ASSERT(logger->completions_frozen == false);

    /* check if there's any outstanding acknowledgment */
    while (logger->acking_sequence_no != 0)
    {
        nuvo_cond_wait(&logger->acking_sequence_no_zero_cond, &logger->completion_list_mutex);
    }

    nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
    uint64_t sequence_no = logger->lowest_sequence_no;
    nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);

    /*
     * Setting the completions_frozen flag prevents the completion callback queue from running.
     * This flag is protected by the completion_list_mutex.
     */
    logger->completions_frozen = true;

    /* Since we're starting a CP reset the cp_trigger counters */
    nuvo_mutex_lock(&logger->cp_trigger_mutex);
    logger->cp_trigger_log_io_count = 0;
    logger->cp_trigger_segments_used_count = 0;
    nuvo_mutex_unlock(&logger->cp_trigger_mutex);

    /*
     * Unlock the completion list. This allows in-flight io to be added to completion list.
     */
    nuvo_mutex_unlock(&logger->completion_list_mutex);

    NUVO_LOG(logger, 20, "log checkpoint: freezing map updates at sequence no: %lu.", sequence_no);
    return (sequence_no);
}

/**@brief Resume performing io completions with the map
 *
 * Indicate the freeze is over and signal the completion list
 * to kick the completion thread to start running completion
 * callbacks again.
 *
 * @param vol A pointer the volume series.
 * @return None.
 */
void nuvo_log_unfreeze_map_updates(struct nuvo_vol *vol)
{
    NUVO_ASSERT(vol != NULL);
    struct nuvo_logger *logger = &vol->log_volume.logger;

    NUVO_LOG(logger, 20, "log checkpoint: resuming map updates.");
    nuvo_mutex_lock(&logger->completion_list_mutex);
    logger->completions_frozen = false;
    nuvo_cond_signal(&logger->completion_list_cond);
    nuvo_mutex_unlock(&logger->completion_list_mutex);
}

/**@brief Get the loggers current set of open segments
 *
 * Gets the media addresses and count of the current set of open segments
 *
 * Before calling nuvo_log_get_open_segments() it's necessary to call nuvo_log_freeze_map_updates() to stop the logger
 * from performing io completions with the map. Freezing io completions ensures the set of open segments
 * and sequence number are consistent and the sequence number (if it exists) is guaranteed to be found
 * in the set of open segments returned.
 *
 * @param vol A pointer the volume series.
 * @param sequence_no The expected sequence number for the set of open segments, used for validation.
 * @param segments A pointer to an array of  NUVO_MFST_NUM_LOG_STARTS where segments will be returned.
 * @param segment_count The address in which the segment count will be returned.
 * @return None.
 */
void nuvo_log_get_open_segments(struct nuvo_vol *vol, uint64_t sequence_no, struct nuvo_segment *segments, uint32_t *segment_count)
{
    NUVO_ASSERT(vol != NULL);
    NUVO_ASSERT(segments != NULL);
    NUVO_ASSERT(segment_count != NULL);

    struct nuvo_logger *logger = &vol->log_volume.logger;

    /* io completions should be frozen */
    NUVO_ASSERT(logger->completions_frozen == true);

    /* the sequence number is used to verify that the set of open segments is indeed correct */
    nuvo_mutex_lock(&logger->lowest_sequence_no_mutex);
    if (sequence_no != logger->lowest_sequence_no)
    {
        NUVO_PANIC("invalid sequence number: %lu expected: %lu\n", sequence_no, logger->lowest_sequence_no);
    }
    nuvo_mutex_unlock(&logger->lowest_sequence_no_mutex);

    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    nuvo_mutex_lock(&logger->segment_open_queue_mutex);

    *segment_count = 0;
    for (uint32_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        for (uint32_t i = 0; i < NUVO_MAX_OPEN_SEGMENTS; i++)
        {
            if (logger->open_data_segments[data_class].segments[i].segment)
            {
                segments[*segment_count].parcel_index = logger->open_data_segments[data_class].segments[i].segment->parcel_index;
                segments[*segment_count].block_offset = logger->open_data_segments[data_class].segments[i].segment->block_offset;
                segments[*segment_count].subclass = logger->open_data_segments[data_class].segments[i].segment->subclass;
                NUVO_LOG(logger, 20, "log checkpoint: segment %lu:%lu class %u. open", segments[*segment_count].parcel_index, segments[*segment_count].block_offset, segments[*segment_count].subclass);
                *segment_count = *segment_count + 1;
            }
        }
    }
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);

    /*
     * Also need to get the segments on the open queue because the forks to these segments are not guaranteed to be
     * in the current set of open segments.
     */
    struct nuvo_segment *segment = nuvo_dlist_get_head_object(&logger->segment_open_queue, struct nuvo_segment, list_node);
    while (segment)
    {
        segments[*segment_count].parcel_index = segment->parcel_index;
        segments[*segment_count].block_offset = segment->block_offset;
        segments[*segment_count].subclass = segment->subclass;
        *segment_count = *segment_count + 1;
        NUVO_LOG(logger, 20, "log checkpoint: segment %lu:%lu class %u. queued", segments[*segment_count].parcel_index, segments[*segment_count].block_offset, segments[*segment_count].subclass);
        segment = nuvo_dlist_get_next_object(&logger->segment_open_queue, segment, struct nuvo_segment, list_node);
    }
    nuvo_mutex_unlock(&logger->segment_open_queue_mutex);
}

/**@brief Close an open segment
 *
 * Closes the specified segment and optionally writes a digest.
 *
 * The segment information is passed via a pointer to a nuvo_segment struct.
 * However only the parcel_desc, block_offset, and data_class are used to locate the segment for closing.
 * The segment close operation will complete asynchronously.
 * When the close has completed nuvo_space_vol_segment_done() will be called.
 *
 * @param vol A pointer the volume series.
 * @param segment A pointer to nuvo_segment struct with the parcel_desc, block_offset, and data_class specified.
 * @param write_digest Set to true to write a digest, this should be the default.
 * @return None.
 */
void nuvo_log_close_segment(struct nuvo_vol *vol, struct nuvo_segment *segment, bool write_digest)
{
    NUVO_ASSERT(vol != NULL);
    NUVO_ASSERT(segment != NULL);

    struct nuvo_logger    *logger = &vol->log_volume.logger;
    struct logger_segment *log_segment = NULL;

    nuvo_mutex_lock(&logger->open_data_segments_mutex);
    for (uint32_t i = 0; i < NUVO_MAX_OPEN_SEGMENTS; i++)
    {
        log_segment = &logger->open_data_segments[segment->data_class].segments[i];
        if (!log_segment->segment || (log_segment->segment->parcel_index != segment->parcel_index) || (log_segment->segment->block_offset != segment->block_offset))
        {
            log_segment = NULL;
            continue;
        }

        // Found it, make sure it's open
        if (log_segment->state != NUVO_SEGMENT_OPEN)
        {
            // This segment is already closed or closing
            NUVO_PANIC("segment %lu:%lu data class %u already closed or closing", segment->parcel_desc, segment->block_offset, segment->data_class);
        }

        // If this is the current active segment and the only segment currently open in the data class
        // a new segment fork needs to be written into the segment first, otherwise replay won't be able
        // to locate the next segment in the log.
        nuvo_mutex_lock(&logger->segment_open_queue_mutex);
        if ((log_segment == logger->active_segment) &&
            (logger->open_data_segments[segment->data_class].subclass[log_segment->segment->subclass].open_count +
             logger->open_data_segments[segment->data_class].subclass[log_segment->segment->subclass].open_queue_len) == 1)
        {
            nuvo_mutex_unlock(&logger->segment_open_queue_mutex);
            struct nuvo_segment   *next_segment;
            struct segment_io_req *fork_req;
            if (new_segment(logger, segment->data_class, log_segment->segment->subclass, true, &next_segment, &fork_req))
            {
                fork_segment(logger, logger->active_segment, next_segment, fork_req);
                close_segment(logger, logger->active_segment, write_digest);
                open_segment(logger, next_segment);
            }
            else
            {
                // Panic since allowing this could cause replay to fail
                NUVO_PANIC("request to close last open segment but no free segments are available");
            }
        }
        else
        {
            nuvo_mutex_unlock(&logger->segment_open_queue_mutex);
            // Since other segments are open or opening, this segment can just be closed.
            close_segment(logger, log_segment, write_digest);
        }
        break;
    }
    nuvo_mutex_unlock(&logger->open_data_segments_mutex);

    if (!log_segment)
    {
        NUVO_PANIC("segment %lu:%lu data class %u could not be found", segment->parcel_desc, segment->block_offset, segment->data_class);
    }
}
