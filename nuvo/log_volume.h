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
 * @file log_volume.h
 * @brief Log volume routines.
 */
#pragma once
#include <uuid/uuid.h>

#include "nuvo_lock.h"
#include "manifest.h"
#include "nuvo_vol_series.h"

/*
 * Some Differ related constants.
 */
#define MEG                  (1024 * 1024)
#define DIFF_ENTRY_SPAN      MEG // maybe this should number of map entries * NUVO_BLOCK_SIZE
#define DIFF_ENTRY_BLOCKS    (DIFF_ENTRY_SPAN / NUVO_BLOCK_SIZE)

/**
 * \brief API worker to create a log volume.
 *
 * Allocates a parcel from the device and creates log volume.
 *
 * \param root_parcel_uuid The root parcel uuid to use.
 * \param device_uuid Where to allocate the parcel.
 * \param root_device_class How to treat the device the root parcel is on.
 * \param vol Pointer to the volume structure (allocated by API request dispatcher thread).
 * \param size The size in bytes.
 * \returns Success or error code.
 * \retval 0 Success or... TODO
 */
nuvo_return_t nuvo_log_vol_create_work(struct nuvo_vol *vol, const uuid_t device_uuid, uint8_t root_device_class, uuid_t root_parcel_uuid, uint64_t size);

/**
 * \brief API worker to open a log volume.
 *
 * \param root_parcel_uuid The root parcel.
 * \param device_uuid Where the root parcel is.
 * \param vol The volume structure.
 * \returns Success or error code.
 * \retval 0 Success or... TODO
 */
nuvo_return_t nuvo_log_vol_open_work(struct nuvo_vol *vol, const uuid_t device_uuid, const uuid_t root_parcel_uuid);

/**
 * \brief Alloc parcels to a log volume.
 *
 * \param nvs_p The volume to which to alloc parcels.
 * \param dev_uuid Where the root parcel is.
 * \param device_class How to use this device.
 * \param num How many parcels.
 * \returns Success or error code.
 * \retval 0 Success or... TODO
 */
nuvo_return_t nuvo_log_vol_alloc_parcels(struct nuvo_vol *nvs_p, const uuid_t dev_uuid, uint8_t device_class, uint64_t num);

/**
 * \brief Does the work of closing a volume series.
 *
 * Should succeed unless volume is exported.
 *
 * \param nvs_p The pointer to the open volume series.
 * \returns 0 or - error code.
 */
nuvo_return_t nuvo_log_vol_close(struct nuvo_vol *nvs_p);

/**
 * \brief Destroy a log volume.
 *
 * \param root_parcel_uuid The root parcel.
 * \param device_uuid Where the root parcel is.
 * \param vol The volume structure.
 * \returns Success or error code.
 * \retval 0 Success or... TODO
 */
int nuvo_log_vol_destroy(struct nuvo_vol *vol,
                         const uuid_t     device_uuid,
                         const uuid_t     root_parcel_uuid);

/**
 * \brief Write to a log volume
 *
 * \param vol The volume being written to.
 * \param block_offset The starting block to write.
 * \param block_count The number of blocks to write.
 * \param buf_list The array of buffers of the data blocks.
 */
int nuvo_log_vol_write(struct nuvo_vol *vol, uint64_t block_offset, uint32_t block_count, void **buf_list);


/** \brief lun read
 *  \param lun to read from
 ** \param block_offset offset to read
 *  \param block_count number of blocks to read
 *  \param buf_list list output buffer array
 *  \param req_cb callback req structure for async io, specify NULL for sync i/o
 */
int nuvo_log_vol_lun_read(struct nuvo_lun *lun, uint64_t block_offset, uint32_t block_count, void **buf_list,
                          struct nuvo_io_request *req_cb);

/**
 * \brief Diff two PiTs of a log volume
 *
 * \param base_lun The lun for the base pit.
 * \param incr_lun The lun for the incr pit.
 * \param offset The offset for which to comparte.
 * \param diff The result of the diff.  diff == true means different.
 */
int nuvo_log_vol_pit_diff_block(struct nuvo_lun *base_lun, struct nuvo_lun *incr_lun,
                                uint64_t offset, bool *diff);

/**
 * \brief Fill in a manifest API message.
 *
 * \param vol The volume.
 * \param msg The message to fill in with the manifest info.
 * \param short_reply Whether to just return device info (or also parcels/segments)
 */
nuvo_return_t nuvo_log_vol_get_manifest(struct nuvo_vol *vol, Nuvo__Manifest *msg, bool short_reply);

/**
 * \brief callback for nuvo_log_submit
 *
 * \param log_req the log request
 */
void nuvo_log_vol_log_cb(struct nuvo_log_request *log_req);

/**
 * \brief create a pit(snap)
 *
 * \param vol volume
 * \param lun_uuid pit uuid
 * \return error code
 */

nuvo_return_t nuvo_log_vol_create_pit(struct nuvo_vol *vol, const uuid_t lun_uuid);

/**
 * \brief delete a pit(snap)
 *
 * \param vs_uuid vol uuid.
 * \param lun_uuid pit uuid
 * \return error code
 */

nuvo_return_t nuvo_log_vol_delete_pit(struct nuvo_vol *vol, const uuid_t lun_uuid);


nuvo_return_t nuvo_log_vol_delete_lun(struct nuvo_vol *vol, struct nuvo_lun *lun);


//TODO documentation someday
nuvo_return_t nuvo_log_vol_delete_lun_int(struct nuvo_lun *lun);

nuvo_return_t nuvo_log_vol_create_lun_int(struct nuvo_vol *vol, const uuid_t lun_uuid);

struct test_fi_info *nuvo_vol_ops_test_fi(void);
