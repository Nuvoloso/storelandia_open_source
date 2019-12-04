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

/**
 * @file device_type.h
 * @brief Definition of the device types.
 */

/**
 * @brief Defines the type of device
 *
 * These are used to indicate what kind of storage device we're dealing with
 * in order to determine appropriate usage and optimizations.
 */
enum nuvo_dev_type
{
    NUVO_DEV_TYPE_SSD  = 0,       /**< Solid-state storage device. */
    NUVO_DEV_TYPE_HDD  = 1,       /**< Rotating disk. */
    NUVO_DEV_TYPE_EPH  = 2,       /**< Ephemeral device. */
    NUVO_MAX_DEV_TYPES = 3
};

/**
 * @brief Defines strings for the device types
 */
static const char *const nuvo_dev_type_str[NUVO_MAX_DEV_TYPES] =
{
    [NUVO_DEV_TYPE_SSD] = "SSD",
    [NUVO_DEV_TYPE_HDD] = "HDD",
    [NUVO_DEV_TYPE_EPH] = "Cache"
};
