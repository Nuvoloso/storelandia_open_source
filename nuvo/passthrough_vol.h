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
 * @file passthrough_vol.h passthrough volumes.
 */
#pragma once
#include <uuid/uuid.h>
#include "nuvo_vol_series.h"

/**
 * \brief API worker to open a passthrough volume.
 *
 * Opens the block device, and creates an in-core volume series operating on it.
 * \param vol The volume.
 * \param blk_dev The path to the block device.
 * \param size The size of the volume.
 * \returns Success or error code.
 * \retval 0 Success, internal error or the error from OPEN.
 * \retval EEXIST That UUID is already in use.
 * \retval ENOMEM The volume series table is full.
 * \retval EINVAL The size is not a positive multiple of BLOCK_SIZE.
 * \retval ENOENT There was no device at that path.
 */
nuvo_return_t nuvo_passthrough_open_work(struct nuvo_vol *vol, const char *blk_dev, size_t size);

/**
 * \brief API worker to close a passthrough volume.
 *
 * Closes the volume: closes the file and removes the in-core volume entry.
 * Fails if volume is not open or if it is exported.
 *
 * \param nvs_p The open passthrough volume to close.
 * \returns Success or error code.
 * \retval 0 Success, internal error or the error.
 */
nuvo_return_t nuvo_passthrough_close_vol(struct nuvo_vol *nvs_p);
