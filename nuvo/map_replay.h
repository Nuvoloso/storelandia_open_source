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

void nuvo_map_replay_rsv_cb(struct nuvo_map_request *map_req);
void nuvo_map_data_replay_snap_fault_cb(struct nuvo_map_request *map_req);
void nuvo_map_data_replay_snap_rsv_cb(struct nuvo_map_request *map_req_snap);
void nuvo_map_replay_fault_cb(struct nuvo_map_request *map_req);

/**
 * \brief replay volume done callback for map, called by replay code after replay is done
 * \param vol vol on which the replay is done
 *
 * heavy storm of dirty maps could cause perf issues in balance lists
 * as the dirty maps are not flushable during replay.
 * So during replay these are stashed in the volume.
 * When replay is done, this list is added to the global lru list
 * This funciton does the job
 */

void nuvo_map_replay_vol_done(struct nuvo_vol *vol);

void nuvo_map_replay_cmp_read_map(struct nuvo_map_request *req, struct nuvo_map_entry *map_entry);

void nuvo_map_replay_evict(struct nuvo_map_request *map_req, bool unpin);
void nuvo_map_replay_next(struct nuvo_log_request *log_req);
