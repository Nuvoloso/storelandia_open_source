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
#include "nuvo_list.h"
#include "nuvo_lock.h"
#include "device_type.h"

/**
 * @file segment.h
 * @brief Structure for handing segments around between manifest and logger via space.
 */

enum nuvo_segment_user_e
{
    NUVO_SEGMENT_USER_LOGGER = 1,
    NUVO_SEGMENT_USER_GC     = 2
};

/**
 * \brief Structure for working segments.
 *
 * This is the structure handed back and forth between the manifest and its clients (logger and gc)
 * via space management code.
 */
struct nuvo_segment {
    struct nuvo_dlnode       list_node;      /** This is the list node */

    enum nuvo_segment_user_e user;           /** Was this allocated for logger or for gc. */

    uint32_t                 parcel_index;   /** Which parcel. */
    uint32_t                 block_offset;   /** First block in the segment. */
    uint32_t                 block_count;    /** How many blocks in the segment. */
    uint32_t                 parcel_desc;    /** Parcel descriptor for IO. */
    uint16_t                 device_index;   /** device index to guide writing policy decisions. */
    uint8_t                  data_class;     /** Data class to guide writing policy decisions. */
    uint8_t                  subclass;       /** Sub-class type of segment, for GC or new data. */
    enum nuvo_dev_type       device_type;    /** The type of device this segment is on. */

    uint_fast8_t             gc_utilization; /** The utiilization if this is for gc. */
    uint_fast64_t            gc_grade;       /** The grade if this is for gc. */
};

/**
 * \brief A free list of nuvo_segments.
 *
 * Keeps the nuvo_segment_list and a pointer to the allocated memory and a
 * count of the number allocated, so we can free it.
 */
struct nuvo_segment_free_list {
    nuvo_mutex_t         mutex;       /** The mutex protecting the list. */
    struct nuvo_dlist    free_list;   /** The actual list. */
    struct nuvo_segment *memory;      /** The memory allocated to hold the segments. */
    uint_fast32_t        allocated;   /** The count of structures that have been handed out. */
};

/**
 * \brief Create a free list of segments.
 *
 * \param free_list The free list to initialize.
 * \param num The number of segments to create on the list.
 * \retval 0 success
 * \retval negative Memory allocation error.
 */
nuvo_return_t nuvo_segment_free_list_create(struct nuvo_segment_free_list *free_list, uint32_t num);

/**
 * \brief Destroy a free list of segments.
 *
 * Asserts all members have been freed.
 *
 * \brief free_list the List allocated in nuvo_segment_free_list_create
 * \sa nuvo_segment_free_list_create
 */
void nuvo_segment_free_list_destroy(struct nuvo_segment_free_list *free_list);

/**
 * \brief Global list of free segment structures.
 */
extern struct nuvo_segment_free_list nuvo_global_segment_free_list;

// TODO Push callers of this as low as possible.

/**
 * \brief Allocate a segment structure from the free list.
 *
 * \param free_list The free list from which to allocate.
 * \returns pointer to the segment structure
 * \retval NULL If the list is empty.
 */
struct nuvo_segment *nuvo_segment_alloc(struct nuvo_segment_free_list *free_list);

/**
 * \brief Return a segment structure to the free list.
 *
 * \param free_list The free list to return to.
 * \paramseg The segment to return.
 */
void nuvo_segment_free(struct nuvo_segment_free_list *free_list, struct nuvo_segment *seg);
