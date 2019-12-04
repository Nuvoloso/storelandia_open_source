
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

#include <check.h>
#include <unistd.h>
#include <stdio.h>

#include "../gc.h"
#include "../logger.h"
#include "../log_volume.h"
#include "../manifest_priv.h"
#include "../nuvo_pr.h"
#include "../nuvo_pr_sync.h"
#include "../nuvo_vol_series.h"
#include "../parcel_manager.h"
#include "../space.h"

#include "fake_pr.h"
#include "nuvo_ck_assert.h"

void nuvo_map_mfl_req_init(struct nuvo_map_free_lun_request *mfl_req, struct nuvo_lun *lun)
{
    (void)mfl_req;
    (void)lun;
    NUVO_ASSERT(0);
}
void nuvo_map_mfl_init(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
}
void nuvo_map_mfl_start(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
}
void nuvo_map_mfl_work(struct nuvo_map_free_lun_request *req)
{
    (void)req;
}
void nuvo_map_mfl_kick(struct nuvo_map_free_lun_request *req)
{
    (void)req;
}
bool nuvo_map_mfl_is_paused(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
    return true;
}
void nuvo_map_mfl_halt(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
}
void nuvo_map_mfl_wait_for_halt(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
}
bool nuvo_map_mfl_is_halting(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
    return false;
}
bool nuvo_map_mfl_is_halted(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
    return false;
}
void nuvo_map_mfl_trigger_halting(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
}
void nuvo_map_mfl_stop(struct nuvo_map_free_lun_request *mfl_req)
{
    (void)mfl_req;
}
