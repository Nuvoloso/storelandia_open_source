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
#include <stdint.h>
#include <assert.h>
#include "nuvo_hash.h"

/**
 * @file map_entry.h
 * @brief Definition of the format of the map_entry.
 */

/* TODO: since these are stored on media, bit fields should be done manually
 *      and have accessor functions
 */


struct __attribute__((packed)) nuvo_media_addr {
    uint64_t parcel_index : 24;
    uint64_t block_offset : 24;
};

enum nuvo_map_entry_type
{
    NUVO_ME_CONST   = 0x0,
    NUVO_ME_MEDIA   = 0x1,
    NUVO_ME_IN_MEM  = 0x2,
    NUVO_ME_LOADING = 0x3,
    NUVO_ME_NULL    = 0x7
};

typedef enum nuvo_map_entry_snap_type_t
{
    NUVO_MAP_ENTRY_NONE   = 0,
    NUVO_MAP_ENTRY_SHARED = 1,
    NUVO_MAP_ENTRY_COW    = 2,
} nuvo_map_entry_snap_type;


struct __attribute__((packed)) nuvo_map_entry {
    uint16_t cow : 2;
    uint16_t type : 3;
    uint16_t unused : 11;
    struct nuvo_media_addr media_addr;
    union
    {
        nuvo_hash_t            hash;
        uint64_t               pattern;
        struct nuvo_map_track *ptr;
    };
};

//TODO rethink the values?
#define NUVO_LOG_MEDIA_ADDR_FREE      0
#define NUVO_LOG_BLOCK_OFFSET_FREE    0

#define NUVO_MEDIA_ADDR_EQUAL(m1, m2)       (((m1)->parcel_index == (m2)->parcel_index) && \
                                             ((m1)->block_offset == (m2)->block_offset))

#define NUVO_MEDIA_ADDR_FREE(media_addr)    (((media_addr)->parcel_index == NUVO_LOG_MEDIA_ADDR_FREE) && \
                                             ((media_addr)->block_offset == NUVO_LOG_BLOCK_OFFSET_FREE))

#define NUVO_MAP_IS_ZERO_PATTERN    (0xBAD0BAD0BAD0BAD0)

#define NUVO_ME_SET_MFL_DONE(me)    do  {                           \
        (me)->media_addr.parcel_index = NUVO_LOG_MEDIA_ADDR_FREE;   \
        (me)->media_addr.block_offset = NUVO_LOG_BLOCK_OFFSET_FREE; \
        (me)->type = NUVO_ME_CONST;                                 \
} while (0);

#define NUVO_ME_IS_MFL_DONE(me)     (NUVO_MEDIA_ADDR_FREE(&((me)->media_addr)) && \
                                     (me)->type == NUVO_ME_CONST)

static_assert(sizeof(struct nuvo_map_entry) == 16, "Map entries must be 16 bytes in size.");
