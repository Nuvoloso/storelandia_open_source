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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "nuvo_list.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "cache_priv.h"
#include "cache.h"
#include "resilience.h"
#include "nuvo_vol_series.h"

extern struct nuvo_cache cache;

/**
 * \brief Submit a list of requests to the resiliency layer.
 *
 * only handles read and write operations.
 * parcel operations are not made via the resiliency layer.
 *
 * The resiliency layer will examine the io request and perform the
 * necessary i/o to conform to the caching and redundancy characteristics
 * of the volume.
 *
 * The caller of the resiliancy layer isn't necessarily aware of what the
 * caching and redundancy properties of the volume are. This allows
 * for the resiliancy layer to perform io to multiple devices, including
 * the cache.
 *
 * The request structure used is the same as used for nuvo_pr_submit
 *
 * \param submit_list A pointer to a struct nuvo_dlist containing the requests to submit.
 * \return void
 */
void nuvo_rl_submit(struct nuvo_dlist *submit_list)
{
    NUVO_ASSERT(submit_list != NULL);
    struct nuvo_io_request *io_req;
    struct nuvo_dlist       local_submit_list;
    nuvo_dlist_init(&local_submit_list);

    while ((io_req = nuvo_dlist_remove_head_object(submit_list, struct nuvo_io_request, list_node)) != NULL)
    {
        NUVO_ASSERT(io_req->operation == NUVO_OP_READ || io_req->operation == NUVO_OP_READ_VERIFY || io_req->operation == NUVO_OP_WRITE);
        NUVO_ASSERT(io_req->rw.vol != NULL);

        // TODO add support for tagging io as cache or no cache
        if (NUVO_VOL_HAS_CACHE(io_req->rw.vol))
        {
            // We don't take a lock when checking if the cache is enabled for a volume.
            // nuvo_cache_submit_req() returns NUVO_E_NO_CACHE if the cache for this volume is subsequently disabled.
            nuvo_return_t ret = nuvo_cache_submit_req(io_req);
            if (ret == NUVO_E_NO_CACHE)
            {
                nuvo_dlist_insert_head(&local_submit_list, &io_req->list_node);
            }
            else if (ret != 0)
            {
                // TODO: The IO could be serviced from the primary, however if this was a write
                // the cache will need to be reset since a primary write may result in invalid cache lines.
                // for now panic.
                NUVO_PANIC("nuvo_cache_submit_req() failed. ret = %d", ret);
            }
        }
        else
        {
            nuvo_dlist_insert_head(&local_submit_list, &io_req->list_node);
        }
    }
    if (nuvo_dlist_get_head_object(&local_submit_list, struct nuvo_io_request, list_node) != NULL)
    {
        nuvo_pr_submit(&local_submit_list);
    }
}

void nuvo_rl_sync_submit_callback(struct nuvo_io_request *req)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)req->tag.ptr);
}

/*
 * \brief Submits I/O request to the resilience layer and waits for it to return.
 *
 * \param req The I/O request
 * \param sync_signal The mutex to wait for completion
 */
void nuvo_rl_sync_submit(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal)
{
    nuvo_mutex_lock(sync_signal);
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    req->callback = nuvo_rl_sync_submit_callback;
    req->tag.ptr = sync_signal;
    nuvo_rl_submit(&submit_list);

    // Wait for completion callback
    nuvo_mutex_lock(sync_signal);
    nuvo_mutex_unlock(sync_signal);
    req->tag.ptr = NULL;
}

extern inline void nuvo_rl_submit_req(struct nuvo_io_request *req);
