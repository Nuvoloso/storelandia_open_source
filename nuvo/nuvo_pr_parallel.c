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
#include "nuvo_pr_parallel.h"
#include "resilience.h"

// Documented in header.
nuvo_return_t nuvo_pr_parallel_init(struct nuvo_parallel_io *par_io)
{
    par_io->ios_outstanding = 1;
    par_io->status = 0;
    par_io->callback = NULL;
    par_io->tag.ptr = NULL;

    return (nuvo_mutex_init(&par_io->mutex));
}

// Documented in header.
void nuvo_pr_parallel_destroy(struct nuvo_parallel_io *par_io)
{
    nuvo_mutex_destroy(&par_io->mutex);
}

static void nuvo_pr_parallel_cb(struct nuvo_io_request *io_req)
{
    struct nuvo_parallel_io *par_io = (struct nuvo_parallel_io *)io_req->tag.ptr;

    nuvo_mutex_lock(&par_io->mutex);
    par_io->ios_outstanding--;
    if (io_req->status != 0)
    {
        par_io->status = io_req->status;  // Return one of the calls.
    }
    nuvo_pr_client_req_free(io_req);
    bool done = (par_io->ios_outstanding == 0);
    nuvo_mutex_unlock(&par_io->mutex);

    if (done)
    {
        par_io->callback(par_io);
    }
}

// Documented in header.
void nuvo_pr_parallel_submit(struct nuvo_parallel_io *par_io, struct nuvo_io_request *io_req)
{
    nuvo_mutex_lock(&par_io->mutex);
    io_req->callback = nuvo_pr_parallel_cb;
    io_req->tag.ptr = par_io;
    par_io->ios_outstanding++;

    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
    nuvo_rl_submit(&submit_list);

    nuvo_mutex_unlock(&par_io->mutex);
}

void nuvo_pr_parallel_finalize(struct nuvo_parallel_io *par_io)
{
    nuvo_mutex_lock(&par_io->mutex);
    par_io->ios_outstanding--;
    bool already_done = (par_io->ios_outstanding == 0);
    nuvo_mutex_unlock(&par_io->mutex);
    if (already_done)
    {
        par_io->callback(par_io);
    }
}
