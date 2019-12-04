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

static void print_map_entry(char *title, int index, struct nuvo_map_entry *entry)
{
#ifdef DEBUG_FINAL_MAP
    char *type[] = { "CONST", "MEDIA", "INMEM", "LODNG", "??4??", "??5??", "??6??", "NULL " };
    char *cow[] = { "NONE", "SHRD", "COW " };

    if (entry->type == NUVO_ME_CONST)
    {
        NUVO_ERROR_PRINT("%s[%02x] %s %s pattern: %08x",
                         title, index, cow[entry->cow], type[entry->type], entry->pattern);
    }
    else
    {
        NUVO_ERROR_PRINT("%s[%02x] %s %s MAddr: %04lx:%04lx",
                         title, index, cow[entry->cow], type[entry->type],
                         entry->media_addr.parcel_index, entry->media_addr.block_offset);
    }
#else
    (void)title;
    (void)index;
    (void)entry;
#endif // DEBUG_FINAL_MAP
}

// nuvo_log_vol_pit_diff_block tells if the set of blocks at offset is different between
// the two specified snapshots.
int nuvo_log_vol_pit_diff_block(struct nuvo_lun *base_lun, struct nuvo_lun *incr_lun,
                                uint64_t offset, bool *diff)
{
    bool done = false;
    int  i;

    *diff = false;

    if (base_lun == incr_lun)
    {
        // We have hit the end of the looking through PiTs
        // we are clean;
        return (0);
    }

    if (base_lun == NULL)
    {
        // This is a level 0 (initial) back-up.
        // Start with the incremental PiT map entries and traverse out
        // toward the active PiT looking for CONST zero, if const zero,
        // no diff, otherwise is dirty.
        struct nuvo_map_entry incr_map_entries[NUVO_MAX_IO_BLOCKS];

        NUVO_DEBUG_ASSERT(DIFF_ENTRY_BLOCKS == NUVO_MAX_IO_BLOCKS, "Sizes Don't match");
        int ret;

        for (i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
        {
            incr_map_entries[i].cow = NUVO_MAP_ENTRY_SHARED;  // means unresolved
        }

        ret = nuvo_map_final_map_entries(incr_lun, offset / NUVO_BLOCK_SIZE, DIFF_ENTRY_BLOCKS,
                                         incr_map_entries, true /* for now */);

        if (ret < 0)
        {
            NUVO_ERROR_PRINT("nuvo_log_vol_final_map_entries failed: offst: %04lx",
                             offset);
            return (ret);
        }

        for (i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
        {
            print_map_entry("Final", i + offset / NUVO_BLOCK_SIZE, &incr_map_entries[i]);
            if ((incr_map_entries[i].type != NUVO_ME_CONST) ||
                (incr_map_entries[i].pattern != 0))
            {
                *diff = true;
                break;
            }
        }
    }
    else
    {
        // This is an incremental backup which starts with a
        // base snapshot and may span a few PiTs on its way
        // to the incremental PiT.
        struct nuvo_map_entry base_map_entries[NUVO_MAX_IO_BLOCKS];

        struct nuvo_map_request base_map_req;
        uint_fast32_t           base_parcel_descs[NUVO_MAX_IO_BLOCKS];

        nuvo_map_request_init(&base_map_req, base_lun, offset / NUVO_BLOCK_SIZE, DIFF_ENTRY_BLOCKS);
        base_map_req.op = NUVO_MAP_REQUEST_OP_DIFF;
        nuvo_map_reserve_sync(&base_map_req);
        if (base_map_req.status < 0)
        {
            return (ENOMEM);
        }
        nuvo_map_fault_in_sync(&base_map_req);
        if (base_map_req.status < 0)
        {
            return (ENOMEM);
        }
        nuvo_map_read_and_pin_sync(&base_map_req, false, base_map_entries, base_parcel_descs);

        int i;
        for (i = 0; i < DIFF_ENTRY_BLOCKS; i++)
        {
            if (base_map_entries[i].cow == NUVO_MAP_ENTRY_COW)
            {
                *diff = true;
                done = true;
                break;
            }
        }

        if (done == false)
        {
            base_lun = nuvo_get_next_younger_lun(base_lun, false);
            return (nuvo_log_vol_pit_diff_block(base_lun, incr_lun, offset, diff));
        }
    }

    return (0);
}
