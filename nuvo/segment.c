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
#include "segment.h"

/**
 * @file segment.c
 * @brief The segment code
 */

/** \brief The global free list for segment structures.  Maybe this Should this be per volume. */
struct nuvo_segment_free_list nuvo_global_segment_free_list;

// Documented in header
nuvo_return_t nuvo_segment_free_list_create(struct nuvo_segment_free_list *free_list, uint32_t num)
{
    nuvo_return_t rc = nuvo_mutex_init(&free_list->mutex);

    if (rc != 0)
    {
        return (-NUVO_ENOMEM);
    }
    free_list->memory = calloc(num, sizeof(struct nuvo_segment));
    if (free_list->memory == NULL)
    {
        nuvo_mutex_destroy(&free_list->mutex);
        return (-NUVO_ENOMEM);
    }
    nuvo_dlist_init(&free_list->free_list);
    free_list->allocated = 0;
    for (uint_fast32_t i = 0; i < num; i++)
    {
        nuvo_dlnode_init((struct nuvo_dlnode *)&free_list->memory[i]);
        nuvo_dlist_insert_head(&free_list->free_list, (struct nuvo_dlnode *)&free_list->memory[i]);
    }
    return (0);
}

// Documented in header
void nuvo_segment_free_list_destroy(struct nuvo_segment_free_list *free_list)
{
    nuvo_mutex_destroy(&free_list->mutex);
    NUVO_ASSERT(free_list->allocated == 0);
    free(free_list->memory);
}

// Documented in header
struct nuvo_segment *nuvo_segment_alloc(struct nuvo_segment_free_list *free_list)
{
    nuvo_mutex_lock(&free_list->mutex);
    struct nuvo_segment *seg = nuvo_dlist_remove_head_object(&free_list->free_list, struct nuvo_segment, list_node);
    if (seg != NULL)
    {
        free_list->allocated++;
    }
    nuvo_mutex_unlock(&free_list->mutex);
    return (seg);
}

// Documented in header
void nuvo_segment_free(struct nuvo_segment_free_list *free_list, struct nuvo_segment *seg)
{
    nuvo_mutex_lock(&free_list->mutex);
    NUVO_ASSERT(free_list->allocated > 0);
    free_list->allocated--;
    nuvo_dlist_insert_head(&free_list->free_list, &seg->list_node);
    nuvo_mutex_unlock(&free_list->mutex);
}
