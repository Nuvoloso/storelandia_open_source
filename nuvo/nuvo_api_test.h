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
 * @file nuvo_api_test.h
 * @brief Exposes internal api functions to the test framework.
 *
 * These definitions are all really internal to nuvo_api.c, but we
 * need to let the unit tests at them.
 */
#pragma once
#include <stdbool.h>

#include "nuvo_api.h"
#include "nuvo_fuse.h"
#include "device_type.h"

/**
 * \brief Worker function protoype for recording using devices.
 */
typedef nuvo_return_t use_device_work_t (const char *, const uuid_t, const enum nuvo_dev_type);

/**
 * \brief Worker function protoype for recording using cache devices.
 */
typedef nuvo_return_t use_device_cache_work_t (const char *, const uuid_t, uint64_t *, uint64_t *);
Nuvo__Cmd *nuvo_api_use_device(struct nuvo_api_req    *req,
                               use_device_work_t       do_device_work,
                               use_device_cache_work_t do_cache_work);

/**
 * \brief Worker function protoype for closing a device.
 */
typedef nuvo_return_t close_device_work_t (const uuid_t);
Nuvo__Cmd *nuvo_api_close_device(struct nuvo_api_req *req, close_device_work_t do_work);

/**
 * \brief Worker function protoype for formatting new devices.
 */
typedef nuvo_return_t format_device_work_t (const char *, const uuid_t, uint64_t);
Nuvo__Cmd *nuvo_api_format_device(struct nuvo_api_req *req, format_device_work_t do_work);

/**
 * \brief Worker function protoype for recording a device is on a node.
 */
typedef nuvo_return_t device_location_work_t (const uuid_t, const uuid_t);
Nuvo__Cmd *nuvo_api_device_location(struct nuvo_api_req *req, device_location_work_t do_work);

/**
 * \brief Worker function protoype for recording where a node is.
 */
typedef nuvo_return_t node_location_work_t (const uuid_t, const char *, uint16_t);
Nuvo__Cmd *nuvo_api_node_location(struct nuvo_api_req *req, node_location_work_t do_work);

/**
 * \brief Worker function protoype for notification that kontroller is done
 * with the initial node configuration.
 */
typedef nuvo_return_t node_init_done_work_t (const uuid_t, bool);
Nuvo__Cmd *nuvo_api_node_init_done(struct nuvo_api_req  *req,
                                   node_init_done_work_t do_work);

/**
 * \brief Worker function protoype for opening a passthrough volume.
 */
typedef nuvo_return_t passthrough_open_vol_work_t (struct nuvo_vol *vol, const char *, size_t);
Nuvo__Cmd *nuvo_api_passthrough_open_volume(struct nuvo_api_req *req, passthrough_open_vol_work_t do_work);

/**
 * \brief Worker function protoype for opening a passthrough volume.
 */
typedef nuvo_return_t export_lun_work_t (struct nuvo_vol *vol, const uuid_t, const char *, int);
Nuvo__Cmd *nuvo_api_export_lun(struct nuvo_api_req *req, export_lun_work_t do_work);

/**
 * \brief Worker function protoype for opening a passthrough volume.
 */
typedef nuvo_return_t unexport_lun_work_t (struct nuvo_vol *vol, const uuid_t, const char *);
Nuvo__Cmd *nuvo_api_unexport_lun(struct nuvo_api_req *req, unexport_lun_work_t do_work);

/**
 * \brief Worker function prototype for creating a parcel volume.
 */
typedef nuvo_return_t create_volume_work_t (struct nuvo_vol *vol, const uuid_t, uuid_t, bool log_vol, uint64_t size);
Nuvo__Cmd *nuvo_api_create_volume(struct nuvo_api_req *req, create_volume_work_t do_work);

/**
 * \brief Worker function prototype for opening a parcel volume.
 */
typedef nuvo_return_t open_volume_work_t (struct nuvo_vol *vol, const uuid_t, const uuid_t, bool log_vol);
Nuvo__Cmd *nuvo_api_open_volume(struct nuvo_api_req *req, open_volume_work_t do_work);

/**
 * \brief Worker function prototype for allocating parcels to a volume.
 */
typedef nuvo_return_t alloc_parcels_work_t (struct nuvo_vol *vol, const uuid_t, uint64_t num);
Nuvo__Cmd *nuvo_api_alloc_parcels(struct nuvo_api_req *req, alloc_parcels_work_t do_work);

/**
 * \brief Worker function prototype for allocating cache to a volume.
 */
typedef nuvo_return_t alloc_cache_work_t (struct nuvo_vol *vol, uint64_t size);
Nuvo__Cmd *nuvo_api_alloc_cache(struct nuvo_api_req *req, alloc_cache_work_t do_work);

/**
 * \brief Worker function prototype for closing a volume.
 */
typedef nuvo_return_t close_vol_work_t (struct nuvo_vol *vol);
Nuvo__Cmd *nuvo_api_close_vol(struct nuvo_api_req *req, close_vol_work_t do_work);

/**
 * \brief Worker function prototype for getting stats.
 */
typedef nuvo_return_t get_stats_work_t (const Nuvo__GetStats__Type,
                                        const Nuvo__GetStats__ReadWrite,
                                        const bool,
                                        const uuid_t,
                                        Nuvo__GetStats__Statistics **stats);
Nuvo__Cmd *nuvo_api_get_stats(struct nuvo_api_req *req, get_stats_work_t do_work);
Nuvo__GetStats__Statistics *nuvo_build_getstats_stats();

/**
 * \brief Worker function prototype for getting volume stats.
 */
typedef nuvo_return_t get_volume_stats_work_t (const bool,
                                               const uuid_t,
                                               Nuvo__GetVolumeStats *vol_stats);
Nuvo__Cmd *nuvo_api_get_volume_stats(struct nuvo_api_req *req, get_volume_stats_work_t do_work);

/**
 * \brief Worker function prototype for destroying volumes.
 *
 * Destroy makes no sense on passthhrough volumes, so this is a
 * parcel volume command.  Hopefully can use same command for
 * our final volumes.
 */
typedef nuvo_return_t destroy_vol_work_t (bool             log_volume,
                                          struct nuvo_vol *vol,
                                          const uuid_t     device_uuid,
                                          const uuid_t     root_parcel_uuid);
Nuvo__Cmd *nuvo_api_destroy_vol(struct nuvo_api_req *req, destroy_vol_work_t do_work);

/**
 * \brief Worker function prototype for setting node uuids.
 */
typedef nuvo_return_t set_node_uuid_work_t (const uuid_t node_uuid);
Nuvo__Cmd *nuvo_api_set_node_uuid(struct nuvo_api_req *req, set_node_uuid_work_t do_work);

/**
 * \brief Worker function prototype for getting a manifest.
 */
typedef nuvo_return_t get_manifest_work_t (struct nuvo_vol *vol, Nuvo__Manifest *msg, bool short_reply);
Nuvo__Cmd *nuvo_api_get_manifest(struct nuvo_api_req *req, get_manifest_work_t do_work);

/**
 * \brief Worker function prototype for getting Pit Differences
 */
typedef nuvo_return_t diff_pits_work_t (struct nuvo_vol   *vol,
                                        const uuid_t       base_pit_uuid,
                                        const uuid_t       incr_pit_uuid,
                                        Nuvo__GetPitDiffs *msg);
Nuvo__Cmd *nuvo_api_diff_pits(struct nuvo_api_req *req, diff_pits_work_t do_work);

/**
 * \brief Worker function prototype for capturing a PiT (Point in Time)
 */
typedef nuvo_return_t create_pit_work_t (struct nuvo_vol *vol, const uuid_t pit_uuid);
Nuvo__Cmd *nuvo_api_create_pit(struct nuvo_api_req *req, create_pit_work_t do_work);

/**
 * \brief Worker function prototype for deleting a PiT (Point in Time)
 */
typedef nuvo_return_t delete_pit_work_t (struct nuvo_vol *vol, const uuid_t pit_uuid);
Nuvo__Cmd *nuvo_api_delete_pit(struct nuvo_api_req *req, delete_pit_work_t do_work);

/**
 * \brief Worker function prototype for retrieving the list of PiTs in a volume.
 */
typedef nuvo_return_t list_pit_work_t (struct nuvo_vol *vol, Nuvo__ListPits *msg);
Nuvo__Cmd *nuvo_api_list_pits(struct nuvo_api_req *req, list_pit_work_t do_work);

/**
 * \brief Worker function prototype for listing vols this node
 */
typedef nuvo_return_t list_vol_work_t (Nuvo__ListVols *msg);
Nuvo__Cmd *nuvo_api_list_vols(struct nuvo_api_req *req, list_vol_work_t do_work);

/**
 * \brief Worker function prototype for pausing I/O on a volume
 */
typedef nuvo_return_t pause_io_work_t (struct nuvo_vol *vol);
Nuvo__Cmd *nuvo_api_pause_io(struct nuvo_api_req *req, pause_io_work_t do_work);

/**
 * \brief Worker function prototype for resuming I/O on a volume
 */
typedef nuvo_return_t resume_io_work_t (struct nuvo_vol *vol);
Nuvo__Cmd *nuvo_api_resume_io(struct nuvo_api_req *req, resume_io_work_t do_work);

/**
 * \brief Worker function prototype for setting log levels.
 */
typedef nuvo_return_t log_level_work_t (const char *module_name, uint32_t level);
Nuvo__Cmd *nuvo_api_log_level(struct nuvo_api_req *req, log_level_work_t do_work);

/**
 * \brief Worker function prototype for getting node (and vol) status
 */
typedef nuvo_return_t node_status_work_t (Nuvo__NodeStatus *msg);
Nuvo__Cmd *nuvo_api_node_status(struct nuvo_api_req *req, node_status_work_t do_work);

/**
 * \brief Whether the command needs to allocate a new volume structure
 */
extern bool cmd_need_alloc_vol(Nuvo__Cmd *cmd);

/**
 * \brief Whether the command is volume-specific
 */
extern bool cmd_is_vol_specific(Nuvo__Cmd *cmd);

/**
 * \brief Get a pointer to volume uuid in command structure
 */
extern char *get_vol_uuid(Nuvo__Cmd *cmd);

/**
 * \brief Setup reply for API dispatcher thread to return error
 */
extern void prep_dispatcher_err_reply(Nuvo__Cmd *cmd, nuvo_return_t err, nuvo_return_t rc);
