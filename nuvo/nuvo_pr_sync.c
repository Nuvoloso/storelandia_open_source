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

#include <stdlib.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <signal.h>

#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "nuvo.h"
#include "nuvo_util.h"
#include "signal_handler.h"
int nuvo_pr_sync_parcel_alloc(uuid_t       parcel_uuid,
                              const uuid_t device_uuid,
                              const uuid_t vs_uuid)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (NUVO_ENOMEM);
    }

    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    // Have to free req before exiting.
    req->operation = NUVO_OP_ALLOC;
    memset(&req->alloc, 0, sizeof(req->alloc));
    if (!uuid_is_null(parcel_uuid))
    {
        uuid_copy(req->alloc.parcel_uuid, parcel_uuid);
    }
    else
    {
        uuid_clear(req->alloc.parcel_uuid);
    }
    uuid_copy(req->alloc.device_uuid, device_uuid);
    uuid_copy(req->alloc.volume_uuid, vs_uuid);
    int ret;
    nuvo_pr_sync_submit(req, &sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
        goto free_req;
    }
    uuid_copy(parcel_uuid, req->alloc.parcel_uuid);
    ret = 0;

free_req:
    nuvo_mutex_destroy(&sync_signal);
    nuvo_pr_client_req_free(req);
    return (ret);
}

nuvo_return_t nuvo_pr_sync_parcel_open(uint_fast32_t *parcel_desc,
                                       const uuid_t   parcel_uuid,
                                       const uuid_t   device_uuid,
                                       const uuid_t   vs_uuid)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (NUVO_ENOMEM);
    }
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    // Have to free req before exiting.

    // Open root parcel
    req->operation = NUVO_OP_OPEN;
    uuid_copy(req->open.parcel_uuid, parcel_uuid);
    uuid_copy(req->open.device_uuid, device_uuid);
    uuid_copy(req->open.volume_uuid, vs_uuid);
    req->open.reopen_flag = 0;
    nuvo_return_t ret;
    nuvo_pr_sync_submit(req, &sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
        goto free_req;
    }
    *parcel_desc = req->open.parcel_desc;
    ret = 0;

free_req:
    nuvo_mutex_destroy(&sync_signal);
    nuvo_pr_client_req_free(req);
    return (ret);
}

nuvo_return_t nuvo_pr_sync_parcel_close(uint_fast32_t parcel_desc)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (NUVO_ENOMEM);
    }
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    // Have to free req before exiting.

    // close parcel
    req->operation = NUVO_OP_CLOSE;
    req->close.parcel_desc = parcel_desc;
    int ret;
    nuvo_pr_sync_submit(req, &sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
        goto free_req;
    }
    ret = 0;

free_req:
    nuvo_mutex_destroy(&sync_signal);
    nuvo_pr_client_req_free(req);
    return (ret);
}

int nuvo_pr_sync_parcel_free(const uuid_t parcel_uuid,
                             const uuid_t device_uuid,
                             const uuid_t vs_uuid)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (NUVO_ENOMEM);
    }
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    // Have to free req before exiting.

    // Open root parcel
    req->operation = NUVO_OP_FREE;
    uuid_copy(req->free.parcel_uuid, parcel_uuid);
    uuid_copy(req->free.device_uuid, device_uuid);
    uuid_copy(req->free.volume_uuid, vs_uuid);
    int ret;
    nuvo_pr_sync_submit(req, &sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
        goto free_req;
    }
    ret = 0;

free_req:
    nuvo_mutex_destroy(&sync_signal);
    nuvo_pr_client_req_free(req);
    return (ret);
}

int nuvo_pr_sync_dev_info(const uuid_t        device_uuid,
                          uint64_t           *device_size,
                          uint64_t           *parcel_size,
                          enum nuvo_dev_type *device_type)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (NUVO_ENOMEM);
    }
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    // Have to free req before exiting.

    // Open root parcel
    req->operation = NUVO_OP_DEV_INFO;
    uuid_copy(req->dev_info.device_uuid, device_uuid);
    int ret;
    nuvo_pr_sync_submit(req, &sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
        goto free_req;
    }
    *device_size = req->dev_info.device_size;
    *parcel_size = req->dev_info.parcel_size;
    *device_type = req->dev_info.device_type;
    ret = 0;

free_req:
    nuvo_mutex_destroy(&sync_signal);
    nuvo_pr_client_req_free(req);
    return (ret);
}

nuvo_return_t nuvo_pr_sync_read(uint_fast32_t desc, uint_fast32_t block_offset, uint_fast32_t num_blocks, uint8_t *buffer)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t rc = nuvo_mutex_init(&sync_signal);

    if (rc != 0)
    {
        return (-NUVO_ENOMEM);
    }
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    while (rc == 0 && num_blocks > 0)
    {
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = desc;
        req->rw.block_offset = block_offset;
        req->rw.block_count = (num_blocks > NUVO_MAX_IO_BLOCKS) ? NUVO_MAX_IO_BLOCKS : num_blocks;
        for (uint32_t i = 0; i < req->rw.block_count; i++)
        {
            req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            req->rw.iovecs[i].iov_base = buffer;
            buffer += NUVO_BLOCK_SIZE;
        }
        nuvo_pr_sync_submit(req, &sync_signal);
        rc = req->status;
        num_blocks -= req->rw.block_count;
        block_offset += req->rw.block_count;
    }
    nuvo_pr_client_req_free(req);
    nuvo_mutex_destroy(&sync_signal);
    return (rc);
}

void nuvo_pr_sync_client_req_alloc_callback(struct nuvo_pr_req_alloc *alloc)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)alloc->tag.ptr);
}

struct nuvo_io_request *nuvo_pr_sync_client_req_alloc(nuvo_mutex_t *sync_signal)
{
    nuvo_mutex_lock(sync_signal);
    struct nuvo_pr_req_alloc req_alloc;
    nuvo_dlnode_init(&req_alloc.list_node);
    req_alloc.callback = nuvo_pr_sync_client_req_alloc_callback;
    req_alloc.tag.ptr = sync_signal;
    nuvo_pr_client_req_alloc_cb(&req_alloc);

    // wait for completion callback
    nuvo_mutex_lock(sync_signal);
    nuvo_mutex_unlock(sync_signal);
    return (req_alloc.req);
}

void nuvo_pr_sync_buf_alloc_callback(struct nuvo_pr_buf_alloc *req)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)req->tag.ptr);
}

/*
 * This submits the io request list to the parcel router
 * and waits for it to return.
 */
void nuvo_pr_sync_buf_alloc_req(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal)
{
    nuvo_mutex_lock(sync_signal);
    struct nuvo_pr_buf_alloc buf_alloc;

    nuvo_pr_buf_alloc_init_req(&buf_alloc,
                               req,
                               (union nuvo_tag)((void *)sync_signal),
                               nuvo_pr_sync_buf_alloc_callback);

    nuvo_pr_client_buf_alloc_batch(&buf_alloc);

    // wait for completion callback
    nuvo_mutex_lock(sync_signal);
    nuvo_mutex_unlock(sync_signal);
}

void nuvo_pr_sync_buf_alloc_list(void **buf_list, unsigned count, nuvo_mutex_t *sync_signal)
{
    nuvo_mutex_lock(sync_signal);
    struct nuvo_pr_buf_alloc buf_alloc;

    nuvo_pr_buf_alloc_init_list(&buf_alloc,
                                buf_list,
                                count,
                                (union nuvo_tag)((void *)sync_signal),
                                nuvo_pr_sync_buf_alloc_callback);

    nuvo_pr_client_buf_alloc_batch(&buf_alloc);

    // wait for completion callback
    nuvo_mutex_lock(sync_signal);
    nuvo_mutex_unlock(sync_signal);
}

void nuvo_pr_sync_submit_callback(struct nuvo_io_request *req)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)req->tag.ptr);
}

/*
 * This submits the io request list to the parcel router
 * and waits for it to return.
 */
void nuvo_pr_sync_submit(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal)
{
    nuvo_mutex_lock(sync_signal);
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    req->callback = nuvo_pr_sync_submit_callback;
    req->tag.ptr = sync_signal;
    nuvo_pr_submit(&submit_list);

    // wait for completion callback
    nuvo_mutex_lock(sync_signal);
    nuvo_mutex_unlock(sync_signal);
    req->tag.ptr = NULL; // I don't like leaking garbage pointers.
}

nuvo_return_t nuvo_pr_zero(struct nuvo_vol *vol, uint_fast32_t desc, uint_fast32_t block_offset, uint_fast32_t num_blocks)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t rc = nuvo_mutex_init(&sync_signal);

    if (rc != 0)
    {
        return (-NUVO_ENOMEM);
    }
    uint8_t buffer[NUVO_BLOCK_SIZE] __attribute__((aligned(NUVO_BLOCK_SIZE)));
    memset(buffer, 0, NUVO_BLOCK_SIZE);
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    while (rc == 0 && num_blocks > 0)
    {
        NUVO_SET_IO_TYPE(req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_INTERNAL);
        NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
        req->rw.vol = vol;
        req->rw.parcel_desc = desc;
        req->rw.block_offset = block_offset;
        req->rw.block_count = (num_blocks > NUVO_MAX_IO_BLOCKS) ? NUVO_MAX_IO_BLOCKS : num_blocks;
        for (uint32_t i = 0; i < req->rw.block_count; i++)
        {
            req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
            req->rw.iovecs[i].iov_base = buffer;  // keep reusing same buffer
            req->rw.block_hashes[i] = nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
        }
        nuvo_pr_sync_submit(req, &sync_signal);
        rc = req->status;
        num_blocks -= req->rw.block_count;
        block_offset += req->rw.block_count;
    }
    nuvo_pr_client_req_free(req);
    nuvo_mutex_destroy(&sync_signal);
    return (rc);
}
