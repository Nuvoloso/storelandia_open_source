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
#include <libaio.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sys/uio.h>
#include <stdatomic.h>
#include <stdbool.h>

#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "nuvo_hash.h"
#include "status.h"
#include "device_type.h"

/**
 * \brief Synchronous call to allocate a parcel on a device.
 *
 * This function wraps the NUVO_OP_ALLOC request, doing
 * all of the request setup and turning the async into sync
 * using the passed in mutex.
 *
 * \param parcel_uuid To return the uuid of the parcel
 * \param device_uuid The device to allocate from.
 * \param vs_uuid The volume series to allocate for.
 * returns 0 on success.  Passes up error from request.
 */
int nuvo_pr_sync_parcel_alloc(uuid_t       parcel_uuid,
                              const uuid_t device_uuid,
                              const uuid_t vs_uuid);

/**
 * \brief Synchronous call to open a parcel.
 *
 * This function wraps the NUVO_OP_OPEN request, doing
 * all of the request setup and turning the async into sync
 * using the passed in mutex.
 *
 * \param parcel_desc To return the parcel descriptor.
 * \param parcel_uuid The parcel to open.
 * \param device_uuid The device holding the parcel.
 * \param vs_uuid The volume series owning the parcel.
 * returns 0 on success.  Passes up error from request.
 */
nuvo_return_t nuvo_pr_sync_parcel_open(uint_fast32_t *parcel_desc,
                                       const uuid_t   parcel_uuid,
                                       const uuid_t   device_uuid,
                                       const uuid_t   vs_uuid);

/**
 * \brief Synchronous call to free a parcel.
 *
 * This function wraps the NUVO_OP_FREE request, doing
 * all of the request setup and turning the async into sync
 * using the passed in mutex.
 *
 * \param parcel_uuid The parcel to open.
 * \param device_uuid The device holding the parcel.
 * \param vs_uuid The volume series owning the parcel.
 * returns 0 on success.  Passes up error from request.
 */
int nuvo_pr_sync_parcel_free(const uuid_t parcel_uuid,
                             const uuid_t device_uuid,
                             const uuid_t vs_uuid);

/**
 * \brief Synchronous call to close a parcel.
 *
 * This function wraps the NUVO_OP_CLOSE request, doing
 * all of the request setup and turning the async into sync
 * using the passed in mutex.
 *
 * \param parcel_desc The parcel descriptor to close.
 * returns 0 on success.  Passes up error from request.
 */
nuvo_return_t nuvo_pr_sync_parcel_close(uint_fast32_t parcel_desc);

/**
 * \brief Get device info.
 *
 * This function wraps the  NUVO_OP_DEV_INFO request, doing
 * all of the request setup and turning the async into sync
 * using the passed in mutex.
 *
 * \param device_uuid The device to get info for.
 * \param device_size Pointer to return the device size.
 * \param parcel_size Pointer to return the parcel size.
 * \param device_type Pointer to return the device type.
 */
int nuvo_pr_sync_dev_info(const uuid_t        device_uuid,
                          uint64_t           *device_size,
                          uint64_t           *parcel_size,
                          enum nuvo_dev_type *device_type);

/**
 * \brief Read some number of blocks.
 *
 * This reads blocks from an open parcel. \c num_blocks may be large, resulting
 * in multiple IO's.
 *
 * \param desc Descriptor of the parcel to read from.
 * \param block_offset Offset within the parcel.
 * \param num_blocks How many blocks to read.
 * \param buffer Place to put the data.
 * \returns negative on error.
 */
nuvo_return_t nuvo_pr_sync_read(uint_fast32_t desc, uint_fast32_t block_offset, uint_fast32_t num_blocks, uint8_t *buffer);

/**
 * \brief Synchronously allocate a request.
 *
 * sync_signal is locked and unlocked internally.
 * Just passed in to avoid constant creating and destroying mutexes.
 *
 * \param sync_signal Mutex to make call synchronous.
 */
struct nuvo_io_request *nuvo_pr_sync_client_req_alloc(nuvo_mutex_t *sync_signal);

/**
 * \brief Synchronously allocate buffers for a request.
 *
 * sync_signal is locked and unlocked internally.
 * Just passed in to avoid constant creating and destroying mutexes.
 *
 * \param req The req that needs buffers.
 * \param sync_signal Mutex to make call synchronous.
 */
void nuvo_pr_sync_buf_alloc_req(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal);
void nuvo_pr_sync_buf_alloc_list(void **buf_list, unsigned count, nuvo_mutex_t *sync_signal);

/**
 * \brief Synchronously submit a request.
 *
 * sync_signal is locked and unlocked internally.
 * Just passed in to avoid constant creating and destroying mutexes.
 *
 * \param req The request to submit.
 * \param sync_signal Mutex to make call synchronous.
 */
void nuvo_pr_sync_submit(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal);
