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

/* map ut functions used by unit_test_nuvo_map.c */
/* implemented in map_ut.c */

void __nuvo_map_create_snap(struct nuvo_lun * active_lun, struct nuvo_lun *snap_lun);
struct nuvo_lun * map_ut_create_snap(struct nuvo_vol *vol);
void map_ut_vol_init(struct nuvo_vol *vol);
void map_ut_init_active(struct nuvo_vol *vol);
void map_ut_multi_write(struct nuvo_lun *active_lun, struct nuvo_lun *snap_lun, int max_iter,
                        uint32_t num_blocks, bool seq, int *seed);
void map_ut_set_map_cleaning(struct nuvo_map_track *map);
void map_ut_reserve_fault_in(struct nuvo_map_request *map_req, struct nuvo_lun * lun,  uint64_t block);
void map_ut_reserve_fault_in_intermediate(struct nuvo_map_request *map_req, struct nuvo_lun * lun,  uint64_t block, int level);
void map_ut_evict(struct nuvo_map_track *map);

void map_ut_log_create_snap(struct nuvo_vol *vol, struct nuvo_lun *lun);
void map_ut_log_delete_lun(struct nuvo_vol *vol, struct nuvo_lun *lun);

nuvo_return_t map_ut_delete_lun_int(struct nuvo_lun *lun);

void map_ut_force_clean(struct nuvo_map_track *map, bool flush);
void map_ut_wait_clean(struct nuvo_map_track *map);
void map_ut_reserve_and_fault_in(struct nuvo_map_request *req, struct nuvo_lun *lun, int bno, int num_blocks);

// reserve, fault in and read the map into req->first_map
// pins are released
void map_ut_read_map(struct nuvo_map_request *map_req, struct nuvo_lun * lun,  uint64_t bno);
