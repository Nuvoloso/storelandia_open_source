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
#include <check.h>

#include "../nuvo.h"
#include "../nuvo_pr.h"
#include "../nuvo_pr_sync.h"

#include "fake_pr.h"
#include "nuvo_ck_assert.h"

/**
 * This is a parcel and its data. The data
 * field is alloced lazily, to avoid valgrind madness.
 */
struct fake_pr_parcel {
    struct nuvo_dlnode  node;

    uuid_t              parcel_uuid;
    uuid_t              vs_uuid;

    uint64_t            parcel_size;
    uint8_t             *data;
};

/**
 * This is a device. At the pr interface there is
 * no distinction between local and remote devices.
 */
struct fake_pr_device {
    struct nuvo_dlnode  node;

    uuid_t              device_uuid;
    uint64_t            parcel_size;
    uint64_t            device_size;  // Not currently respected.
    enum nuvo_dev_type  device_type;
    bool                opened;

    struct nuvo_dlist   parcels;
};

/**
 * A parcel descriptor
 */
struct fake_pr_desc {
    struct nuvo_dlnode  node;

    uint_fast32_t       desc;
    uuid_t              device_uuid;
    uuid_t              parcel_uuid;
};

struct fake_pr {
    nuvo_mutex_t        mutex;
    nuvo_cond_t         cond;
    pthread_t           thread;

    struct nuvo_dlist   devices;
    struct nuvo_dlist   descriptors;

    struct nuvo_dlist   submitted;
    struct nuvo_dlist   completed;

    bool                suspend_replies;

    uint_fast32_t       fail_after;   // Count down, then fail with below.
    nuvo_return_t       fail_req_return;

    uint_fast32_t       last_descriptor;

    bool                exiting;

    uint64_t            ops_completed;
} fake_pr;

uint64_t fake_pr_ops_completed()
{
    nuvo_mutex_lock(&fake_pr.mutex);
    uint64_t count = fake_pr.ops_completed;
    nuvo_mutex_unlock(&fake_pr.mutex);
    return count;
}

struct fake_pr_device *fake_pr_find_dev(const uuid_t device_uuid)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_device *dev = nuvo_dlist_get_head_object(&fake_pr.devices, struct fake_pr_device, node);
    while (dev != NULL)
    {
        if (0 == uuid_compare(dev->device_uuid, device_uuid))
        {
            return dev;
        }
        dev = nuvo_dlist_get_next_object(&fake_pr.devices, dev, struct fake_pr_device, node);
    }
    return NULL;
}

int64_t nuvo_pm_device_format(const char *path, const uuid_t uuid, uint64_t parcel_size)
{
    (void) path;
    nuvo_mutex_lock(&fake_pr.mutex);
    struct fake_pr_device *dev = malloc(sizeof(*dev));
    nuvo_dlnode_init(&dev->node);
    uuid_copy(dev->device_uuid, uuid);
    dev->parcel_size = parcel_size;
    dev->device_size = 10 * 1024 * 1024 * 1024ull;
    dev->opened = false;
    nuvo_dlist_init(&dev->parcels);
    nuvo_dlist_insert_tail(&fake_pr.devices, &dev->node);
    nuvo_mutex_unlock(&fake_pr.mutex);
    return 0;
}

int64_t nuvo_pm_device_open(const char *path, const uuid_t uuid, const enum nuvo_dev_type device_type)
{
    (void) path;
    int64_t rc;
    nuvo_mutex_lock(&fake_pr.mutex);
    struct fake_pr_device *dev = fake_pr_find_dev(uuid);
    if (dev)
    {
        rc = 0;
        dev->opened = true;
        dev->device_type = device_type;
    }
    else
    {
        rc = -1;
    }
    nuvo_mutex_unlock(&fake_pr.mutex);
    return rc;
}

struct fake_pr_parcel *fake_pr_find_parcel(const uuid_t device_uuid,
                                           const uuid_t parcel_uuid)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_device *dev = fake_pr_find_dev(device_uuid);
    if (dev == NULL)
    {
        return NULL;
    }
    struct fake_pr_parcel *parcel = nuvo_dlist_get_head_object(&dev->parcels, struct fake_pr_parcel, node);
    while (parcel != NULL)
    {
        if (0 == uuid_compare(parcel->parcel_uuid, parcel_uuid))
        {
            return parcel;
        }
        parcel = nuvo_dlist_get_next_object(&dev->parcels, parcel, struct fake_pr_parcel, node);
    }
    return NULL;
}

struct fake_pr_desc *fake_pr_lookup_desc(uint_fast32_t pd)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_desc *desc = nuvo_dlist_get_head_object(&fake_pr.descriptors, struct fake_pr_desc, node);
    while (desc != NULL)
    {
        if (desc->desc == pd)
        {
            return desc;
        }
        desc = nuvo_dlist_get_next_object (&fake_pr.descriptors, desc, struct fake_pr_desc, node);
    }
    return NULL;
}


struct fake_pr_parcel *fake_pr_lookup_parcel(uint_fast32_t pd)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_desc *desc = fake_pr_lookup_desc(pd);
    if (desc != NULL) {
        return fake_pr_find_parcel(desc->device_uuid, desc->parcel_uuid);
    }
    return NULL;
}


bool fake_pr_parcel_descriptor_valid(uint_fast32_t pd)
{
    nuvo_mutex_lock(&fake_pr.mutex);
    struct fake_pr_parcel *parcel = fake_pr_lookup_parcel(pd);
    nuvo_mutex_unlock(&fake_pr.mutex);
    return NULL != parcel;
}

void fake_pr_parcel_populate(struct fake_pr_parcel *parcel)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    if (parcel->data == NULL) {
        parcel->data = malloc(parcel->parcel_size);
        memset(parcel->data, 0xff, parcel->parcel_size);
    }
}

uint8_t *fake_pr_parcel_data(uint_fast32_t pd)
{
    nuvo_mutex_lock(&fake_pr.mutex);
    struct fake_pr_parcel *parcel = fake_pr_lookup_parcel(pd);
    if (parcel == NULL)
    {
        nuvo_mutex_unlock(&fake_pr.mutex);
        return NULL;
    }
    fake_pr_parcel_populate(parcel);
    uint8_t *data = parcel->data;
    nuvo_mutex_unlock(&fake_pr.mutex);
    return data;
}

struct fake_pr_parcel *fake_pr_add_parcel_int(uuid_t device_uuid,
                                              uuid_t parcel_uuid,
                                              uuid_t vs_uuid)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_device *dev = nuvo_dlist_get_head_object(&fake_pr.devices, struct fake_pr_device, node);
    while (dev != NULL)
    {
        if (0 == uuid_compare(dev->device_uuid, device_uuid) && dev->opened)
        {
            struct fake_pr_parcel *parcel = malloc(sizeof(*parcel));
            nuvo_dlnode_init(&parcel->node);
            uuid_copy(parcel->parcel_uuid, parcel_uuid);
            uuid_copy(parcel->vs_uuid, vs_uuid);
            parcel->parcel_size = dev->parcel_size;
            parcel->data = NULL;
            nuvo_dlist_insert_tail(&dev->parcels, &parcel->node);
            return parcel;
        }
        dev = nuvo_dlist_get_next_object(&fake_pr.devices, dev, struct fake_pr_device, node);
    }
    ck_assert(0 == 1);
    return NULL;
}

uint_fast32_t fake_pr_add_desc_int(uuid_t device_uuid, struct fake_pr_parcel *parcel)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_desc *desc = (struct fake_pr_desc*) malloc(sizeof(*desc));
    nuvo_dlnode_init(&desc->node);
    desc->desc = ++fake_pr.last_descriptor;
    uuid_copy(desc->device_uuid, device_uuid);
    uuid_copy(desc->parcel_uuid, parcel->parcel_uuid);
    nuvo_dlist_insert_tail(&fake_pr.descriptors, &desc->node);
    return desc->desc;
}

uint_fast32_t fake_pr_get_last_descriptor()
{
    nuvo_mutex_lock(&fake_pr.mutex);
    uint_fast32_t pd = fake_pr.last_descriptor;
    nuvo_mutex_unlock(&fake_pr.mutex);
    return pd;
}

void fake_pr_destroy_parcel(struct fake_pr_parcel *parcel)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    if (parcel->data)
    {
        free(parcel->data);
    }
    free(parcel);
}

void fake_pr_destroy_device(struct fake_pr_device *device)
{
    NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
    struct fake_pr_parcel *parcel;
    while((parcel = nuvo_dlist_remove_head_object(&device->parcels, struct fake_pr_parcel, node)) != NULL) {
        fake_pr_destroy_parcel(parcel);
    }
    free(device);
}

void fake_pr_do_callbacks()
{
    struct nuvo_dlist completed;
    nuvo_dlist_init(&completed);

    nuvo_mutex_lock(&fake_pr.mutex);
    nuvo_dlist_insert_list_tail(&completed, &fake_pr.completed);
    nuvo_mutex_unlock(&fake_pr.mutex);

    struct nuvo_io_request *req;
    while((req = nuvo_dlist_remove_head_object(&completed, struct nuvo_io_request, list_node)) != NULL) {
        nuvo_mutex_lock(&fake_pr.mutex);
        fake_pr.ops_completed++;
        nuvo_mutex_unlock(&fake_pr.mutex);
        req->callback(req);
    }
}

void fake_pr_suspend_replies()
{
    nuvo_mutex_lock(&fake_pr.mutex);
    fake_pr.suspend_replies = true;
    nuvo_mutex_unlock(&fake_pr.mutex);
}

void fake_pr_unsuspend_replies()
{
    nuvo_mutex_lock(&fake_pr.mutex);
    fake_pr.suspend_replies = false;
    nuvo_mutex_unlock(&fake_pr.mutex);
    fake_pr_do_callbacks();
}

void fake_pr_fail_next_io(nuvo_return_t status, unsigned after)
{
    nuvo_mutex_lock(&fake_pr.mutex);
    fake_pr.fail_req_return = status;
    fake_pr.fail_after = after;
    nuvo_mutex_unlock(&fake_pr.mutex);
}

void *fake_pr_run(void *arg)
{
    (void) arg;
    while (!fake_pr.exiting)
    {
        nuvo_mutex_lock(&fake_pr.mutex);
        struct nuvo_io_request *req;
        if (nuvo_dlist_get_head_object(&fake_pr.submitted, struct nuvo_io_request, list_node) == NULL)
        {
            nuvo_cond_wait(&fake_pr.cond, &fake_pr.mutex);
        }
        while((req = nuvo_dlist_remove_head_object(&fake_pr.submitted, struct nuvo_io_request, list_node)) != NULL)
        {
            NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
            if (fake_pr.fail_after == 0 && fake_pr.fail_req_return != 0)
            {
                req->status = fake_pr.fail_req_return;
                fake_pr.fail_req_return = 0;
                nuvo_dlist_insert_head(&fake_pr.completed, &req->list_node);
                continue;
            }
            if (fake_pr.fail_after > 0)
            {
                fake_pr.fail_after--;
            }
            switch (req->operation)
            {
            case NUVO_OP_READ:
            case NUVO_OP_READ_VERIFY:
            case NUVO_OP_WRITE:
                {
                    struct fake_pr_parcel *parcel = fake_pr_lookup_parcel(req->rw.parcel_desc);
                    if (parcel == NULL)
                    {
                        req->status = -EINVAL;
                    }
                    else
                    {
                        fake_pr_parcel_populate(parcel);
                        for (uint_fast32_t i = 0; i < req->rw.block_count; i++)
                        {
                            assert(req->rw.iovecs[i].iov_len == NUVO_BLOCK_SIZE);
                            uint64_t offset = (req->rw.block_offset + i) * NUVO_BLOCK_SIZE;
                            if (req->operation == NUVO_OP_READ)
                            {
                                memcpy(req->rw.iovecs[i].iov_base, parcel->data + offset, NUVO_BLOCK_SIZE);
                                req->rw.block_hashes[i] = nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
                            }
                            else if (req->operation == NUVO_OP_READ_VERIFY)
                            {
                                memcpy(req->rw.iovecs[i].iov_base, parcel->data + offset, NUVO_BLOCK_SIZE);
                                assert(req->rw.block_hashes[i] == nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE));
                            }
                            else
                            {
                                assert(req->rw.block_hashes[i] == nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE));
                                memcpy(parcel->data + offset, req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
                            }
                        }
                        req->status = 0;
                    }
                }
                break;
            case NUVO_OP_OPEN:
                {
                    struct fake_pr_parcel *parcel = fake_pr_find_parcel(req->open.device_uuid, req->open.parcel_uuid);
                    if (parcel == NULL)
                    {
                        req->status = -ENOENT;
                    }
                    else if (0 != uuid_compare(parcel->vs_uuid, req->open.volume_uuid))
                    {
                        req->status = -EPERM;
                    }
                    else
                    {
                        req->open.parcel_desc = fake_pr_add_desc_int(req->open.device_uuid, parcel);
                        req->status = 0;
                    }
                }
                break;
            case NUVO_OP_CLOSE:
                {
                    struct fake_pr_desc *desc = fake_pr_lookup_desc(req->close.parcel_desc);
                    if (desc == NULL) {
                        req->status = -ENOENT;
                    }
                    else
                    {
                        nuvo_dlist_remove(&desc->node);
                        free(desc);
                        req->status = 0;
                    }
                }
                break;
            case NUVO_OP_ALLOC:
                {
                    struct fake_pr_device *dev = fake_pr_find_dev(req->alloc.device_uuid);
                    if (dev)
                    {
                        uuid_generate_random(req->alloc.parcel_uuid);
                        (void) fake_pr_add_parcel_int(req->alloc.device_uuid, req->alloc.parcel_uuid, req->alloc.volume_uuid);
                        req->status = 0;
                    }
                    else
                    {
                        req->status = -NUVO_ENOENT;
                    }
                }
                break;
            case NUVO_OP_DEV_INFO:
                {
                    struct fake_pr_device *dev = fake_pr_find_dev(req->dev_info.device_uuid);
                    if (dev)
                    {
                        req->dev_info.device_size = dev->device_size;
                        req->dev_info.parcel_size = dev->parcel_size;
                        req->dev_info.device_type = dev->device_type;
                        req->status = 0;
                    }
                    else
                    {
                        req->status = -NUVO_ENOENT;
                    }
                }
                break;
            case NUVO_OP_FREE:
                ck_assert(0 == 1);  // Not implemented
            }
            NUVO_ASSERT_MUTEX_HELD(&fake_pr.mutex);
            nuvo_dlist_insert_tail(&fake_pr.completed, &req->list_node);
            continue;
        }

        bool do_callbacks = !fake_pr.suspend_replies;

        nuvo_mutex_unlock(&fake_pr.mutex);
        if (do_callbacks)
        {
            fake_pr_do_callbacks();
        }
    }
    return NULL;
}

void fake_pr_init()
{
    fake_pr.exiting = false;
    ck_assert_msg(nuvo_mutex_init(&fake_pr.mutex) == 0, "Unable to initialize mutex");
    ck_assert(nuvo_cond_init(&fake_pr.cond) >= 0);
    nuvo_dlist_init(&fake_pr.devices);
    nuvo_dlist_init(&fake_pr.descriptors);
    nuvo_dlist_init(&fake_pr.submitted);
    nuvo_dlist_init(&fake_pr.completed);
    fake_pr.suspend_replies = false;
    fake_pr.fail_req_return = 0;
    fake_pr.fail_after = 0;
    fake_pr.ops_completed = 0;
    ck_assert(pthread_create(&fake_pr.thread, NULL, fake_pr_run, NULL) == 0);
}

void fake_pr_teardown()
{
    nuvo_mutex_lock(&fake_pr.mutex);
    fake_pr.exiting = true;
    nuvo_cond_broadcast(&fake_pr.cond);
    nuvo_mutex_unlock(&fake_pr.mutex);

    ck_assert(0 == pthread_join(fake_pr.thread, NULL));

    nuvo_mutex_lock(&fake_pr.mutex);
    struct fake_pr_device *device;
    while((device =  nuvo_dlist_remove_head_object(&fake_pr.devices, struct fake_pr_device, node)) != NULL) {
        fake_pr_destroy_device(device);
    }
    struct fake_pr_desc *desc;
    while((desc = nuvo_dlist_remove_head_object(&fake_pr.descriptors, struct fake_pr_desc, node)) != NULL) {
        free(desc);
    }
    nuvo_mutex_unlock(&fake_pr.mutex);
    nuvo_mutex_destroy(&fake_pr.mutex);
}

void nuvo_pr_client_req_alloc_cb(struct nuvo_pr_req_alloc *alloc)
{
    alloc->req = malloc(sizeof(struct nuvo_io_request));
    nuvo_dlnode_init(&alloc->req->list_node);
    alloc->callback(alloc);
}

struct nuvo_io_request *nuvo_pr_client_req_alloc()
{
    return (struct nuvo_io_request *)malloc(sizeof(struct nuvo_io_request));
}

void nuvo_pr_client_req_free(struct nuvo_io_request *req)
{
    free(req);
}

extern inline void nuvo_pr_buf_alloc_init_req(struct nuvo_pr_buf_alloc *alloc,
                    struct nuvo_io_request *req,
                    union nuvo_tag tag,
                    void    (*callback)(struct nuvo_pr_buf_alloc *));

extern inline void nuvo_pr_buf_alloc_init_list(struct nuvo_pr_buf_alloc *alloc,
                    void **list,
                    uint_fast32_t count,
                    union nuvo_tag tag,
                    void    (*callback)(struct nuvo_pr_buf_alloc *));

void nuvo_pr_client_buf_alloc_batch(struct nuvo_pr_buf_alloc *alloc)
{
    if (alloc->buf_count == 0)
    {
        for (uint_fast32_t i = 0; i < alloc->req->rw.block_count; i++)
        {
            (void) posix_memalign(&alloc->req->rw.iovecs[i].iov_base,
                                  NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
            alloc->req->rw.iovecs[i].iov_len = NUVO_BLOCK_SIZE;
        }
    }
    else
    {
        for (uint_fast32_t i = 0; i < alloc->buf_count; i++)
        {
            (void) posix_memalign(&alloc->buf_list[i],
                                  NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        }
    }

    alloc->callback(alloc);
}

void nuvo_pr_client_buf_free_req(struct nuvo_io_request *req)
{
    for (uint_fast32_t i = 0; i < req->rw.block_count; i++)
    {
        free(req->rw.iovecs[i].iov_base);
    }
}

void nuvo_pr_client_buf_free_list(void **buf_list, uint_fast32_t count)
{
    for (unsigned i = 0; i < count; i++)
    {
        free(buf_list[i]);
    }
}

void nuvo_pr_submit(struct nuvo_dlist *submit_list)
{
    nuvo_mutex_lock(&fake_pr.mutex);
    nuvo_dlist_insert_list_tail(&fake_pr.submitted, submit_list);
    nuvo_cond_broadcast(&fake_pr.cond);
    nuvo_mutex_unlock(&fake_pr.mutex);
}


extern inline void nuvo_pr_submit_req(struct nuvo_io_request *req);
