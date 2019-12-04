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
#define MAP_DIFF_ENTRY_COUNT_MAX    (256)
#define MAP_DIFF_ENTRY_THRESHOLD    (10)

struct map_de {
    uint64_t start_offset;
    uint64_t length;
    //bool     dirty;
};

struct nuvo_map_diff_request {
    //struct nuvo_diff_entry entries[NUVO_DIFF_ENTRY_COUNT];
    bool                      init_state;
    struct nuvo_vol          *vol;
    uint32_t                  batch_size;
    //struct map_de map_de_batch[MAP_DIFF_ENTRY_COUNT_MAX];
    struct map_de            *map_de_batch;
    // map request for fault in should be an array eventually for multi fault in */
    struct nuvo_map_request   map_req;
    struct nuvo_map_track    *map;          /*current map faulted in */
    int                       target_level; /*target level to compute the diff entry, currently we do till L1 */

#define NUVO_MAP_DIFFER_ALLOC_BATCH_SIZE    32

    struct nuvo_map_alloc_req alloc_req; /*bulk map alloc request*/
    struct nuvo_dlist         map_list;

    nuvo_return_t             status;
    uint32_t                  fault_in_cnt;
    nuvo_mutex_t              fault_in_mutex;
    nuvo_cond_t               fault_in_done_cond;
};

/* set up the de mem allocation */
struct nuvo_map_vol_state;


void map_diff_request_init(struct nuvo_map_diff_request *mdr, struct nuvo_vol *vol, struct map_de *map_de_array);


/* add a DE to the diff request */
nuvo_return_t map_de_add(struct nuvo_map_diff_request *req, uint64_t start_off, uint64_t len);

/*
 * the core map diff function*/


nuvo_return_t map_diff(struct nuvo_map_diff_request *mdr, struct nuvo_map_track *map, struct nuvo_map_track *map_right,
                       uint64_t offset_begin, uint64_t *offset_end);


//alloc mem in bulk for mdr ops */
void map_diff_alloc_mem_sync(struct nuvo_map_diff_request *mdr);

//release mem at the end of mdr*/
void map_diff_release_mem_unused(struct nuvo_map_diff_request *mdr);

nuvo_return_t nuvo_map_diff_api_helper(struct nuvo_lun *lun_left, struct nuvo_lun *lun_right, uint64_t offset_begin, struct map_de *map_de_array, uint32_t *batch_size, uint64_t *offset_end);

// print functions
void mdr_print(struct nuvo_map_diff_request *mdr);
void map_de_batch_print(struct map_de *map_de_batch, uint32_t batch_size);
