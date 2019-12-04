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
 * @file logger_debug.c
 * @brief Implements the logging protobufs
 */

#include "logger.h"
#include <nuvo.pb-c.h>

nuvo_return_t nuvo_logger_fill_log_summary(Nuvo__LogSummary           *log_summary,
                                           struct nuvo_segment_digest *digest)
{
    log_summary->magic = digest->footer.magic;
    log_summary->has_magic = 1;
    log_summary->sequence_no = digest->footer.sequence_no;
    log_summary->has_sequence_no = 1;
    log_summary->closing_sequence_no = digest->footer.closing_sequence_no;
    log_summary->has_closing_sequence_no = 1;
    log_summary->vs_uuid = malloc(UUID_UNPARSED_LEN);
    if (log_summary->vs_uuid == NULL)
    {
        return (-NUVO_ENOMEM);
    }
    uuid_unparse(digest->footer.vs_uuid, log_summary->vs_uuid);
    log_summary->entries = calloc(digest->footer.used_block_count, sizeof(*log_summary->entries));
    if (log_summary->entries == NULL)
    {
        return (-NUVO_ENOMEM);
    }

    for (unsigned i = 0; i < digest->footer.used_block_count; i++)
    {
        Nuvo__LogSummaryEntry *log_entry = malloc(sizeof(*log_entry));
        log_entry = malloc(sizeof(*log_entry));
        if (log_entry == NULL)
        {
            return (-NUVO_ENOMEM);
        }
        nuvo__log_summary_entry__init(log_entry);
        log_summary->entries[i] = log_entry;
        log_summary->n_entries = i + 1;
        log_entry->block_hash = digest->table[i].block_hash;
        log_entry->log_entry_type = digest->table[i].log_entry_type;
        switch (digest->table[i].log_entry_type)
        {
        case NUVO_LE_DATA:
        case NUVO_LE_MAP_L0:
        case NUVO_LE_MAP_L1:
        case NUVO_LE_MAP_L2:
        case NUVO_LE_MAP_L3:
        case NUVO_LE_MAP_L4:
            log_entry->data = malloc(sizeof(*log_entry->data));
            if (log_entry->data == NULL)
            {
                return (-NUVO_ENOMEM);
            }
            nuvo__log_summary_entry__data__init(log_entry->data);
            log_entry->data->pit_info_active = digest->table[i].data.pit_info.active;
            log_entry->data->pit_info_id = digest->table[i].data.pit_info.pit_id;
            log_entry->data->bno = digest->table[i].data.bno;
            log_entry->data->gc_parcel_index = digest->table[i].data.gc_media_addr.parcel_index;
            log_entry->data->gc_block_offset = digest->table[i].data.gc_media_addr.block_offset;
            break;

        case NUVO_LE_HEADER:
            log_entry->header = malloc(sizeof(*log_entry->header));
            if (log_entry->header == NULL)
            {
                return (-NUVO_ENOMEM);
            }
            nuvo__log_summary_entry__header__init(log_entry->header);
            log_entry->header->sequence_no = digest->table[i].header.sequence_no;
            log_entry->header->subclass = digest->table[i].header.subclass;
            break;

        case NUVO_LE_FORK:
            log_entry->fork = malloc(sizeof(*log_entry->fork));
            if (log_entry->fork == NULL)
            {
                return (-NUVO_ENOMEM);
            }
            nuvo__log_summary_entry__fork__init(log_entry->fork);
            log_entry->fork->seg_parcel_index = digest->table[i].fork.segment_addr.parcel_index;
            log_entry->fork->seg_block_offset = digest->table[i].fork.segment_addr.block_offset;
            log_entry->fork->sequence_no = digest->table[i].fork.sequence_no;
            log_entry->fork->seg_subclass = digest->table[i].fork.subclass;
            break;

        case NUVO_LE_DESCRIPTOR:
            log_entry->descriptor = malloc(sizeof(*log_entry->descriptor));
            if (log_entry->descriptor == NULL)
            {
                return (-NUVO_ENOMEM);
            }
            nuvo__log_summary_entry__descriptor__init(log_entry->descriptor);
            log_entry->descriptor->cv_flag = digest->table[i].descriptor.cv_flag;
            log_entry->descriptor->entry_count = digest->table[i].descriptor.entry_count;
            log_entry->descriptor->data_block_count = digest->table[i].descriptor.data_block_count;
            log_entry->descriptor->sequence_no = digest->table[i].descriptor.sequence_no;
            break;

        case NUVO_LE_SNAP:
            log_entry->snap = malloc(sizeof(*log_entry->snap));
            if (log_entry->snap == NULL)
            {
                return (-NUVO_ENOMEM);
            }
            nuvo__log_summary_entry__snap__init(log_entry->snap);
            log_entry->snap->operation = digest->table[i].snap.operation;
            log_entry->snap->sequence_no = digest->table[i].snap.sequence_no;
            break;

        default:
            break;
        }
    }
    return (0);
}
