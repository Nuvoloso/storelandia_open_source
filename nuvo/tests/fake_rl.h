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
 * @file fake_rl.h
 * @brief fake resilience layer
 *
 * test wrapper calls either real or fake pr
 */
#pragma once

void nuvo_rl_submit(struct nuvo_dlist *sl)
{
    nuvo_pr_submit(sl);
}

void nuvo_rl_submit_req(struct nuvo_io_request *req)
{
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_rl_submit(&submit_list);
}

void nuvo_rl_sync_submit(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal)
{
    nuvo_pr_sync_submit(req, sync_signal);
}
