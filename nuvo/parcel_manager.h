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
#include <uuid/uuid.h>
#include <stdint.h>
#include <limits.h>
#include "nuvo_list.h"
#include "nuvo_stats.h"
#include "device_type.h"

struct device_info {
    char               device_path[PATH_MAX];
    uuid_t             device_uuid;
    uint64_t           parcel_size;
    uint64_t           device_size;
    uint64_t           header_size;
    uint64_t           even_header_start_offset;
    uint64_t           even_header_end_offset;
    uint64_t           odd_header_start_offset;
    uint64_t           odd_header_end_offset;
    uint64_t           formatted_start_offset;
    uint64_t           formatted_end_offset;
    uint64_t           formatted_size;
    uint64_t           formatted_aligned_size;
    uint64_t           formatted_aligned_end_offset;
    uint32_t           max_parcels;
    uint32_t           parcels_allocated;
    uint32_t           parceltable_full;
    enum nuvo_dev_type device_type;
};

void    nuvo_pm_submit(struct nuvo_dlist *submit_list);
int64_t nuvo_pm_device_format(const char *device_path, const uuid_t device_uuid, uint64_t parcel_size);
int64_t nuvo_pm_device_open(const char *device_path, const uuid_t device_uuid, const enum nuvo_dev_type device_type);
bool    nuvo_pm_is_device_in_use(const uuid_t dev_uuid);
int64_t nuvo_pm_device_close(const uuid_t device_uuid);
int64_t nuvo_pm_device_delay(const uuid_t device_uuid, uint64_t delay);
int64_t nuvo_pm_device_info(const uuid_t device_uuid, struct device_info *device_info);
int64_t nuvo_pm_device_stats(const uuid_t device_uuid, const int type, const bool clear, struct nuvo_io_stats_snap *stats_snapshot);
int64_t nuvo_pm_device_reset_stats(const uuid_t device_uuid);
int64_t nuvo_pm_init();
int64_t nuvo_pm_destroy();
