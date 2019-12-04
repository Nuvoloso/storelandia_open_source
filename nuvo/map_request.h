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

struct nuvo_lun;
#include <stdint.h>
#include <stdbool.h>
#include "nuvo.h"
#include "nuvo_list.h"
#include "manifest.h"

enum nuvo_map_path
{
    NUVO_MAP_PATH_FIRST = 0,
    NUVO_MAP_PATH_LAST  = 1
};

/** A structure for describing a map table allocation request. */
struct nuvo_map_alloc_req {
    void               (*callback)(struct nuvo_map_alloc_req *);
    uint_fast32_t      count;
    struct nuvo_dlist *map_list;
    struct nuvo_dlnode list_node;
    union nuvo_tag     tag;
};

/** A structure for describing a writer wait request. */
struct nuvo_map_writer_wait_req {
    void               (*callback)(struct nuvo_map_writer_wait_req *);
    struct nuvo_dlnode list_node;
    union nuvo_tag     tag;
};

enum nuvo_map_request_op_t
{
    NUVO_MAP_REQUEST_OP_DEFAULT,
    NUVO_MAP_REQUEST_OP_IO,
    NUVO_MAP_REQUEST_OP_GC,
    NUVO_MAP_REQUEST_OP_DIFF
};

/** A structure for describing a map resource request. */
struct nuvo_map_request {
    union nuvo_tag             tag;
    void                       (*callback)(struct nuvo_map_request *);
    nuvo_return_t              status;
    struct nuvo_lun           *lun;
    struct nuvo_map_entry     *map_entries;
    enum nuvo_map_request_op_t op;

    union
    {
        struct nuvo_map_alloc_req map_alloc_req;
        struct nuvo_mfst_map_open pin_req;
        struct nuvo_pr_req_alloc  pr_req_alloc;
    };

    uint_fast64_t              cp_commit_gen;
    struct nuvo_dlnode         list_node;
    struct nuvo_dlist          map_list;
    uint_fast64_t              block_start;
    uint_fast64_t              block_last;
    uint_fast64_t              fault_block_num;
    uint_fast32_t              fault_parcel_desc;
    enum nuvo_map_path         fault_path;
    struct nuvo_map_track     *fault_map;
    uint_fast8_t               target_level;
    uint64_t                   snap_gen;

    struct nuvo_map_track     *first_map;
    struct nuvo_map_track     *last_map;
};
