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
 * @file parcel_vol.h
 * @brief Parcel volume routines.
 */
#pragma once
#include <uuid/uuid.h>

#include "nuvo_lock.h"
#include "manifest.h"

/**
 * \brief API worker to create a parcel volume.
 *
 * Allocates a parcel from the device and creates parcel volume.
 *
 * \param root_parcel_uuid The root parcel uuid to use.
 * \param device_uuid Where to allocate the parcel.
 * \param vol The volume structure.
 * \param sync_signal Mutex to make all this seem synchronous for api.
 * \returns Success or error code.
 * \retval 0 Success or... CUM-1258
 */
int nuvo_parcel_vol_create_work(struct nuvo_vol *vol, const uuid_t device_uuid, uuid_t root_parcel_uuid, nuvo_mutex_t *sync_signal);

/**
 * \brief API worker to open a parcel volume.
 *
 * \param root_parcel_uuid The root parcel.
 * \param device_uuid Where the root parcel is.
 * \param vol The volume structure.
 * \param sync_signal Mutex to make all this seem synchronous for api.
 * \returns Success or error code.
 * \retval 0 Success or negative
 */
int nuvo_parcel_vol_open_work(struct nuvo_vol *vol, const uuid_t device_uuid, const uuid_t root_parcel_uuid, nuvo_mutex_t *sync_signal);

/**
 * \brief Alloc parcels to a parcel volume.
 *
 * \param nvs_p The volume series.
 * \param dev_uuid DEvice for parcels
 * \param num How many parcels.
 * \returns Success or error code.
 * \retval 0 Success or negative
 */
nuvo_return_t nuvo_parcel_vol_alloc_parcels(struct nuvo_vol *nvs_p, const uuid_t dev_uuid, uint64_t num);

/**
 * \brief Does the work of closing a volume series.
 *
 * Should succeed unless volume is exported.
 *
 * \param nvs_p The pointer to the open volume series.
 * \returns 0 or - error code.
 */

int nuvo_parcel_vol_close(struct nuvo_vol *nvs_p);

/**
 * \brief Destroy a parcel volume.
 *
 * \param root_parcel_uuid The root parcel.
 * \param device_uuid Where the root parcel is.
 * \param vol The volume structure.
 * \param sync_signal Mutex to make all this seem synchronous for api.
 * \returns Success or error code.
 * \retval 0 Success or negative
 */
int nuvo_parcel_vol_destroy(struct nuvo_vol *vol,
                            const uuid_t     device_uuid,
                            const uuid_t     root_parcel_uuid,
                            nuvo_mutex_t    *sync_signal);

/**
 * \brief Find parcel location of an IO in a parcel volume.
 *
 * Given the \p bno and \p num_blocks within the volume
 * series, find the descriptor of the parcel holding the
 * first block, the offset of the first block and how many of
 * the requested blocks are in this parcel.
 *
 * \param nvs The parcel volume.
 * \param bno The bno within the volume.
 * \param num_blocks The number of blocks in the IO.
 * \param pdesc Pointer to return the pdesc.
 * \param pd_boff Pointer to the block offset with the parcel.
 * \param pd_num Pointer to the number of blocks left in volume.
 * \returns 0 or error
 * \retval ERANGE
 */
int64_t nuvo_parcel_vol_find_location(const struct nuvo_vol *nvs,
                                      uint64_t               bno,
                                      uint64_t               num_blocks,
                                      uint_fast32_t         *pdesc,
                                      uint_fast32_t         *pd_boff,
                                      uint_fast32_t         *pd_num);
