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
#include "nuvo_pr_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include "nuvo_lock.h"

static uuid_t local_node_id;

START_TEST(nuvo_pr_test_init)
{

}
END_TEST

START_TEST(nuvo_pr_test_node_alloc_free_cycle)
{
    // here we test for basic leaks by allocating and freeing repeatedly
    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES*2; i++)
    {
        struct nuvo_pr_node_desc *nodes[16];
        for(int j = 0; j < 16; j++)
        {
            nuvo_mutex_lock(&nuvo_pr->node_mutex);
            nodes[j] = nuvo_pr_node_alloc();
            nuvo_mutex_unlock(&nuvo_pr->node_mutex);
            ck_assert_ptr_ne(nodes[j], NULL);
        }
        for(int j = 0; j < 16; j++)
        {
            nuvo_pr_node_free(nodes[j]);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_node_alloc_free_max)
{
    struct nuvo_pr_node_desc *nodes[NUVO_PR_MAX_NODES];
    // one node is consumed on init for the local node
    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES - 1; i++)
    {
        nuvo_mutex_lock(&nuvo_pr->node_mutex);
        nodes[i] = nuvo_pr_node_alloc();
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        ck_assert_ptr_ne(nodes[i], NULL);
    }

    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    ck_assert_ptr_eq(nuvo_pr_node_alloc(), NULL);
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);
    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_pr_node_free(nodes[i]);
    }

    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_mutex_lock(&nuvo_pr->node_mutex);
        nodes[i] = nuvo_pr_node_alloc();
        nuvo_mutex_unlock(&nuvo_pr->node_mutex);
        ck_assert_ptr_ne(nodes[i], NULL);
    }
    nuvo_mutex_lock(&nuvo_pr->node_mutex);
    ck_assert_ptr_eq(nuvo_pr_node_alloc(), NULL);
    nuvo_mutex_unlock(&nuvo_pr->node_mutex);

    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES - 1; i++)
    {
        nuvo_pr_node_free(nodes[i]);
    }
}
END_TEST

START_TEST(nuvo_pr_test_node_insert_addr_long)
{
    // check that we reject addresses that are too long
    char        addr[128];
    uint16_t    port = 1234;
    uuid_t      id;
    uuid_generate(id);

    for(int i = 0; i < NUVO_MAX_ADDR_LEN + 1; i++)
    {
        addr[i] = ' ';
    }
    addr[NUVO_MAX_ADDR_LEN+1] = '\0';

    int_fast64_t ret = nuvo_pr_node_insert(id, addr, port);
    ck_assert_int_lt(ret, 0);

}
END_TEST

START_TEST(nuvo_pr_test_node_insert_get_remove)
{
    struct {
        uuid_t      id;
        char        addr[64];
        uint16_t    port;
    } node_infos[255];

    int_fast64_t ret;

    // populate node infos
    for(int i = 0; i < 255; i++)
    {
        uuid_generate(node_infos[i].id);
        snprintf(node_infos[i].addr, 64, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);
        node_infos[i].port = (uint16_t)rand();
    }

    // insert all the nodes
    for(int i = 0; i < 255; i++)
    {
        ret = nuvo_pr_node_insert(node_infos[i].id, node_infos[i].addr, node_infos[i].port);
        ck_assert_int_ge(ret, 0);
    }

    // get all the nodes
    for(int i = 0; i < 255; i++)
    {
        struct nuvo_pr_node_desc *node = nuvo_pr_node_get_locked(node_infos[i].id);
        ck_assert_ptr_ne(node, NULL);
        nuvo_mutex_unlock(&node->nd_mutex);
    }

    // remove some nodes
    int nn[] = {0, 56, 79, 34, 105, 141, 233, 254};
    for(uint32_t i = 0; i < NUVO_ARRAY_LENGTH(nn); i++)
    {
        ret = nuvo_pr_node_remove(node_infos[nn[i]].id);
        ck_assert_int_ge(ret, 0);
    }

    // get all the nodes
    for(int i = 0; i < 255; i++)
    {
        struct nuvo_pr_node_desc *node = nuvo_pr_node_get_locked(node_infos[i].id);
        bool was_removed = false;
        for(uint32_t j = 0; j < NUVO_ARRAY_LENGTH(nn); j++)
        {
            was_removed |= nn[j] == i;
        }

        if (was_removed)
        {
            ck_assert_ptr_eq(node, NULL);
        }
        else
        {
            ck_assert_ptr_ne(node, NULL);
            nuvo_mutex_unlock(&node->nd_mutex);
        }
    }

    // remove all the nodes
    for(int i = 0; i < 255; i++)
    {
        ret = nuvo_pr_node_remove(node_infos[i].id);

        bool was_removed = false;
        for(uint32_t j = 0; j < NUVO_ARRAY_LENGTH(nn); j++)
        {
            was_removed |= nn[j] == i;
        }

        if (was_removed)
        {
            ck_assert_int_lt(ret, 0);
        }
        else
        {
            ck_assert_int_ge(ret, 0);
        }
    }

    for(int i = 0; i < 255; i++)
    {
        struct nuvo_pr_node_desc *node = nuvo_pr_node_get_locked(node_infos[i].id);
        ck_assert_ptr_eq(node, NULL);
    }

    // lastly, try to remove the local node
    ret = nuvo_pr_node_remove(local_node_id);
    ck_assert_int_lt(ret, 0);

}
END_TEST

START_TEST(nuvo_pr_test_device_insert_remove_cycle)
{
    int_fast64_t ret = 0;
    // cycle inserting and remove devices
    for(uint32_t i = 0; i < NUVO_PR_MAX_DEVS; i++)
    {
        uuid_t dev_ids[8];
        for(int j = 0; j < 8; j++)
        {
            uuid_generate(dev_ids[j]);
            ret = nuvo_pr_device_insert(dev_ids[j], local_node_id);
            ck_assert_int_ge(ret, 0);
        }
        for(int j = 0; j < 8; j++)
        {
            ret = nuvo_pr_device_remove(dev_ids[j]);
            ck_assert_int_ge(ret, 0);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_device_insert_lookup_remove)
{
    int_fast64_t ret;
    // insert a new node
    uuid_t node_id;
    uuid_t ret_id;
    uuid_generate(node_id);
    ret = nuvo_pr_node_insert(node_id, "1.2.3.4", 12345);
    ck_assert_int_ge(ret, 0);

    // add some devices
    uuid_t device_ids[NUVO_PR_MAX_DEVS];
    for(uint32_t i = 0; i < NUVO_ARRAY_LENGTH(device_ids); i++)
    {
        uuid_generate(device_ids[i]);
        ret = nuvo_pr_device_insert(device_ids[i], node_id);
        ck_assert_int_ge(ret, 0);
    }

    uuid_t extra_dev_id;
    uuid_generate(extra_dev_id);
    ret = nuvo_pr_device_insert(extra_dev_id, node_id);
    ck_assert_int_lt(ret, 0);

    // lookup some devices
    for(uint32_t i = 0; i < NUVO_ARRAY_LENGTH(device_ids); i++)
    {
        ret = nuvo_pr_device_lookup(device_ids[i], &ret_id);
        ck_assert_int_ge(ret, 0);

        ck_assert_int_eq(uuid_compare(node_id, ret_id), 0);
    }

    // remove a device
    uint32_t dev_index = 3;
    ret = nuvo_pr_device_remove(device_ids[dev_index]);
    ck_assert_int_ge(ret, 0);

    // lookup some devices
    for(uint32_t i = 0; i < NUVO_ARRAY_LENGTH(device_ids); i++)
    {
        ret = nuvo_pr_device_lookup(device_ids[i], &ret_id);
        if (i != dev_index)
        {
            ck_assert_int_ge(ret, 0);
            ck_assert_int_eq(uuid_compare(node_id, ret_id), 0);
        }
        else
        {
            ck_assert_int_lt(ret, 0);
        }
    }
    // remove all devices
    ret = nuvo_pr_device_remove_all(node_id);

    // lookup some devices
    for(uint32_t i = 0; i < NUVO_ARRAY_LENGTH(device_ids); i++)
    {
        ret = nuvo_pr_device_lookup(device_ids[i], &ret_id);
        ck_assert_int_lt(ret, 0);
    }
}
END_TEST

START_TEST(nuvo_pr_test_device_update)
{
    int_fast64_t ret = 0;
    uuid_t dev_id, node_id, new_node_id, ret_id;
    uuid_generate(dev_id);
    uuid_generate(node_id);
    uuid_generate(new_node_id);

    // insert a node
    ret = nuvo_pr_node_insert(node_id, "1.2.3.4", 12345);
    ck_assert_int_ge(ret, 0);

    // insert device
    ret = nuvo_pr_device_insert(dev_id, local_node_id);
    ck_assert_int_ge(ret, 0);

    // lookup device and verify
    ret = nuvo_pr_device_lookup(dev_id, &ret_id);
    ck_assert_int_ge(ret, 0);
    ck_assert_int_eq(uuid_compare(ret_id, local_node_id), 0);

    // update the device
    ret = nuvo_pr_device_update(dev_id, node_id);
    ck_assert_int_ge(ret, 0);

    // look up device and verify
    ret = nuvo_pr_device_lookup(dev_id, &ret_id);
    ck_assert_int_ge(ret, 0);
    ck_assert_int_eq(uuid_compare(ret_id, node_id), 0);

    ret = nuvo_pr_node_remove(node_id);
    ck_assert_int_ge(ret, 0);

    ret = nuvo_pr_device_lookup(dev_id, &ret_id);
    ck_assert_int_lt(ret, 0);
}
END_TEST

START_TEST(nuvo_pr_test_cconn_alloc_free_cycle)
{
    // here we test for basic leaks by allocating and freeing repeatedly
    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES*2; i++)
    {
        struct nuvo_pr_client_conn *conns[16];
        for(int j = 0; j < 16; j++)
        {
            conns[j] = nuvo_pr_cconn_alloc();
            ck_assert_ptr_ne(conns[j], NULL);
        }
        for(int j = 0; j < 16; j++)
        {
            nuvo_pr_cconn_free(conns[j]);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_cconn_alloc_free_max)
{
    struct nuvo_pr_client_conn *conns[NUVO_PR_MAX_NODES];

    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES; i++)
    {
        conns[i] = nuvo_pr_cconn_alloc();
        ck_assert_ptr_ne(conns[i], NULL);
    }

    ck_assert_ptr_eq(nuvo_pr_cconn_alloc(), NULL);
    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_pr_cconn_free(conns[i]);
    }

    for(uint32_t i = 0; i < 16; i++)
    {
        conns[i] = nuvo_pr_cconn_alloc();
        ck_assert_ptr_ne(conns[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_cconn_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES; i++)
    {
        nuvo_pr_cconn_free(conns[i]);
    }
}
END_TEST

START_TEST(nuvo_pr_test_sconn_alloc_free_cycle)
{
    // here we test for basic leaks by allocating and freeing repeatedly
    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES*2; i++)
    {
        struct nuvo_pr_server_conn *conns[16];
        for(int j = 0; j < 16; j++)
        {
            conns[j] = nuvo_pr_sconn_alloc();
            ck_assert_ptr_ne(conns[j], NULL);
        }
        for(int j = 0; j < 16; j++)
        {
            nuvo_pr_sconn_free(conns[j]);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_sconn_alloc_free_max)
{
    struct nuvo_pr_server_conn *conns[NUVO_PR_MAX_NODES];

    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES; i++)
    {
        conns[i] = nuvo_pr_sconn_alloc();
        ck_assert_ptr_ne(conns[i], NULL);
    }

    ck_assert_ptr_eq(nuvo_pr_sconn_alloc(), NULL);
    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_pr_sconn_free(conns[i]);
    }

    for(uint32_t i = 0; i < 16; i++)
    {
        conns[i] = nuvo_pr_sconn_alloc();
        ck_assert_ptr_ne(conns[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_sconn_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_NODES; i++)
    {
        nuvo_pr_sconn_free(conns[i]);
    }
}
END_TEST

START_TEST(nuvo_pr_test_req_alloc_free_cycle)
{
    // here we test for basic leaks by allocating and freeing repeatedly
    for(uint32_t i = 0; i < NUVO_PR_MAX_REQS*2; i++)
    {
        struct nuvo_pr_server_conn *conns[16];
        for(int j = 0; j < 16; j++)
        {
            conns[j] = nuvo_pr_sconn_alloc();
            ck_assert_ptr_ne(conns[j], NULL);
        }
        for(int j = 0; j < 16; j++)
        {
            nuvo_pr_sconn_free(conns[j]);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_req_alloc_free_max)
{
    struct nuvo_io_request *reqs[NUVO_PR_MAX_REQS];

    for(uint32_t i = 0; i < NUVO_PR_MAX_REQS; i++)
    {
        reqs[i] = nuvo_pr_client_req_alloc();
        ck_assert_ptr_ne(reqs[i], NULL);
    }

    ck_assert_ptr_eq(nuvo_pr_client_req_alloc(), NULL);
    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_pr_client_req_free(reqs[i]);
    }

    for(uint32_t i = 0; i < 16; i++)
    {
        reqs[i] = nuvo_pr_client_req_alloc();
        ck_assert_ptr_ne(reqs[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_client_req_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_REQS; i++)
    {
        nuvo_pr_client_req_free(reqs[i]);
    }
}
END_TEST

uint64_t nuvo_pr_test_req_cb_count = 0;

void nuvo_pr_test_req_alloc_cb(struct nuvo_pr_req_alloc *alloc)
{
    ck_assert_ptr_eq((struct nuvo_pr_req_alloc *)alloc->tag.ptr, alloc);
    nuvo_pr_test_req_cb_count++;
}

START_TEST(nuvo_pr_test_req_alloc_free_cb_max)
{
    struct nuvo_io_request *reqs[NUVO_PR_MAX_REQS];

    // alloc with out deferment first
    struct nuvo_pr_req_alloc req_alloc;
    nuvo_dlnode_init(&req_alloc.list_node);
    req_alloc.callback = nuvo_pr_test_req_alloc_cb;
    req_alloc.tag.ptr = &req_alloc;

    nuvo_pr_test_req_cb_count = 0;
    nuvo_pr_client_req_alloc_cb(&req_alloc);
    ck_assert_int_eq(nuvo_pr_test_req_cb_count, 1);
    nuvo_pr_client_req_free(req_alloc.req);

    // allocate all available requests
    for(uint32_t i = 0; i < NUVO_PR_MAX_REQS; i++)
    {
        reqs[i] = nuvo_pr_client_req_alloc();
        ck_assert_ptr_ne(reqs[i], NULL);
    }

    // verify none are left
    ck_assert_ptr_eq(nuvo_pr_client_req_alloc(), NULL);

    // submit deferred allcation
    nuvo_pr_client_req_alloc_cb(&req_alloc);
    // verify callback was not called
    ck_assert_int_eq(nuvo_pr_test_req_cb_count, 1);
    // free a request
    nuvo_pr_client_req_free(reqs[NUVO_PR_MAX_REQS - 1]);
    // verify that callback was invoked
    ck_assert_int_eq(nuvo_pr_test_req_cb_count, 2);

    // verify none are left still
    ck_assert_ptr_eq(nuvo_pr_client_req_alloc(), NULL);

    // free the rest
    for(uint32_t i = 0; i < NUVO_PR_MAX_REQS - 1; i++)
    {
        nuvo_pr_client_req_free(reqs[i]);
    }
}
END_TEST

START_TEST(nuvo_pr_test_pdef_alloc_free_cycle)
{
    // here we test for basic leaks by allocating and freeing repeatedly
    for(uint32_t i = 0; i < NUVO_PR_MAX_PDS*2; i++)
    {
        _Atomic struct nuvo_pr_pdef *pdefs[16];
        for(int j = 0; j < 4; j++)
        {
            pdefs[j] = nuvo_pr_pdef_alloc();
            if (pdefs[j] == NULL)
            {
                // turns out these asserts are rather cpu intensive
                // putting this outside the if causes significant slow down
                ck_assert_ptr_ne(pdefs[j], NULL);
            }
        }
        for(int j = 0; j < 4; j++)
        {
            nuvo_pr_pdef_free(pdefs[j]);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_pdef_alloc_free_max)
{
    _Atomic struct nuvo_pr_pdef **pdefs = malloc(sizeof(_Atomic struct nuvo_pr_pdef *)*NUVO_PR_MAX_PDS);

    for(uint32_t i = 0; i < NUVO_PR_MAX_PDS; i++)
    {
        pdefs[i] = nuvo_pr_pdef_alloc();
        if (pdefs[i] == NULL)
        {
            ck_assert_ptr_ne(pdefs[i], NULL);
        }
    }

    ck_assert_ptr_eq(nuvo_pr_pdef_alloc(), NULL);
    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_pr_pdef_free(pdefs[i]);
    }

    for(uint32_t i = 0; i < 16; i++)
    {
        pdefs[i] = nuvo_pr_pdef_alloc();
        ck_assert_ptr_ne(pdefs[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_pdef_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_REQS; i++)
    {
        nuvo_pr_pdef_free(pdefs[i]);
    }

    free(pdefs);
}
END_TEST

START_TEST(nuvo_pr_test_pdef_get_to_pdesc)
{
    _Atomic struct nuvo_pr_pdef *pdef = nuvo_pr_pdef_alloc();
    ck_assert_ptr_ne(pdef, NULL);

    struct nuvo_pr_pdef pdef_val = atomic_load(pdef);
    pdef_val.outstanding_io = 0;
    pdef_val.gen = 15;
    atomic_store(pdef, pdef_val);

    union parcel_descriptor pdesc = nuvo_pr_pdef_to_pdesc(pdef);
    ck_assert_int_eq(pdesc.gen, 15);

    struct nuvo_pr_pdef pdef_get;
    int_fast64_t ret = nuvo_pr_pdef_get(pdesc, &pdef_get);
    ck_assert_int_ge(ret, 0);
    ck_assert_int_eq(memcmp(&pdef_get, &pdef_val, sizeof(pdef_get)), 0);

    pdesc.gen++;
    ret = nuvo_pr_pdef_get(pdesc, &pdef_get);
    ck_assert_int_lt(ret, 0);

    nuvo_pr_pdef_free(pdef);
}
END_TEST

START_TEST(nuvo_pr_test_pdef_outstanding)
{
    int_fast64_t ret;
    struct nuvo_pr_pdef pdef_get;
    _Atomic struct nuvo_pr_pdef *pdef = nuvo_pr_pdef_alloc();
    ck_assert_ptr_ne(pdef, NULL);

    struct nuvo_pr_pdef pdef_val = atomic_load(pdef);
    pdef_val.gen = 15;
    pdef_val.outstanding_io = 0;
    atomic_store(pdef, pdef_val);

    union parcel_descriptor pdesc = nuvo_pr_pdef_to_pdesc(pdef);
    ck_assert_int_eq(pdesc.gen, 15);

    ret = nuvo_pr_pdef_add_outstanding(pdesc, 5);
    ck_assert_int_ge(ret, 0);

    ret = nuvo_pr_pdef_get(pdesc, &pdef_get);
    ck_assert_int_ge(ret, 0);
    ck_assert_int_eq(pdef_get.outstanding_io, 5);

    ret = nuvo_pr_pdef_add_outstanding(pdesc, -2);
    ck_assert_int_ge(ret, 0);

    ret = nuvo_pr_pdef_get(pdesc, &pdef_get);
    ck_assert_int_ge(ret, 0);
    ck_assert_int_eq(pdef_get.outstanding_io, 3);

    pdesc.gen = 3;
    ret = nuvo_pr_pdef_get(pdesc, &pdef_get);
    ck_assert_int_lt(ret, 0);

    nuvo_pr_pdef_free(pdef);
}
END_TEST

START_TEST(nuvo_pr_test_buf_alloc_free_cycle)
{
    // here we test for basic leaks by allocating and freeing repeatedly
    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS*2; i++)
    {
        void *bufs[16];
        for(int j = 0; j < 16; j++)
        {
            bufs[j] = nuvo_pr_client_buf_alloc();
            if (bufs[j] == NULL)
            {
                ck_assert_ptr_ne(bufs[j], NULL);
            }
        }
        for(int j = 0; j < 16; j++)
        {
            nuvo_pr_client_buf_free(bufs[j]);
        }
    }
}
END_TEST

START_TEST(nuvo_pr_test_buf_alloc_free_max)
{
    void *bufs[NUVO_PR_MAX_BUFS];

    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS; i++)
    {
        bufs[i] = nuvo_pr_client_buf_alloc();
        if (bufs[i] == NULL)
        {
            ck_assert_ptr_ne(bufs[i], NULL);
        }
    }

    ck_assert_ptr_eq(nuvo_pr_client_buf_alloc(), NULL);
    for(uint32_t i = 0; i < 16; i++)
    {
        nuvo_pr_client_buf_free(bufs[i]);
    }

    for(uint32_t i = 0; i < 16; i++)
    {
        bufs[i] = nuvo_pr_client_buf_alloc();
        ck_assert_ptr_ne(bufs[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_client_buf_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS; i++)
    {
        nuvo_pr_client_buf_free(bufs[i]);
    }
}
END_TEST

uint32_t nuvo_pr_test_buf_alloc_cb_count = 0;

void nuvo_pr_test_buf_alloc_cb(struct nuvo_pr_buf_alloc *alloc)
{
    ck_assert_ptr_eq((struct nuvo_pr_buf_alloc *)alloc->tag.ptr, alloc);
    nuvo_pr_test_buf_alloc_cb_count++;
}

START_TEST(nuvo_pr_test_buf_alloc_free_req_max)
{
    struct nuvo_io_request *req;
    struct nuvo_pr_buf_alloc buf_alloc;
    void *bufs[NUVO_PR_MAX_BUFS];

    // alloc a req
    req = nuvo_pr_client_req_alloc();
    ck_assert_ptr_ne(req, NULL);

    // fill out relevant fields of the req
    req->operation = NUVO_OP_READ;
    req->rw.block_count = NUVO_MAX_IO_BLOCKS;

    // fill out buf alloc struct
    nuvo_pr_buf_alloc_init_req(&buf_alloc,
        req,
        (union nuvo_tag)((void*)&buf_alloc),
        nuvo_pr_test_buf_alloc_cb);

    // do a buf req alloc
    nuvo_pr_test_buf_alloc_cb_count = 0;
    nuvo_pr_client_buf_alloc_batch(&buf_alloc);
    // verify it completed successfully
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);

    // free allocated bufs
    nuvo_pr_client_buf_free_req(req);

    // consume all available bufs
    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS; i++)
    {
        bufs[i] = nuvo_pr_client_buf_alloc();
        if (bufs[i] == NULL)
        {
            ck_assert_ptr_ne(bufs[i], NULL);
        }
    }

    // verify no bufs left
    ck_assert_ptr_eq(nuvo_pr_client_buf_alloc(), NULL);

    // submit buf req alloc
    nuvo_pr_client_buf_alloc_batch(&buf_alloc);
    // verify it didn't succeed yet
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);

    // free some bufs
    for(uint32_t i = 0; i < NUVO_MAX_IO_BLOCKS - 1; i++)
    {
        nuvo_pr_client_buf_free(bufs[i]);
    }
    // verify buf req alloc didn't succeed yet
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);
    nuvo_pr_client_buf_free(bufs[NUVO_PR_MAX_BUFS - 1]);
    // verify buf req alloc did succeed
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 2);
    // free the req bufs
    nuvo_pr_client_buf_free_req(req);

    // make sure we can allocate all the freed bufs
    for(uint32_t i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
    {
        bufs[i] = nuvo_pr_client_buf_alloc();
        ck_assert_ptr_ne(bufs[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_client_buf_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS; i++)
    {
        nuvo_pr_client_buf_free(bufs[i]);
    }

    nuvo_pr_client_req_free(req);
}
END_TEST

START_TEST(nuvo_pr_test_buf_alloc_free_list_max)
{
    struct nuvo_pr_buf_alloc buf_alloc;
    void *bufs[NUVO_PR_MAX_BUFS];

    void *buf_list[NUVO_MAX_IO_BLOCKS];

    // fill out buf alloc struct
    nuvo_pr_buf_alloc_init_list(&buf_alloc,
        buf_list,
        NUVO_MAX_IO_BLOCKS,
        (union nuvo_tag)((void*)&buf_alloc),
        nuvo_pr_test_buf_alloc_cb);

    // do a buf req alloc
    nuvo_pr_test_buf_alloc_cb_count = 0;
    nuvo_pr_client_buf_alloc_batch(&buf_alloc);
    // verify it completed successfully
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);

    // free allocated bufs
    nuvo_pr_client_buf_free_list(buf_list, NUVO_MAX_IO_BLOCKS);

    // consume all available bufs
    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS; i++)
    {
        bufs[i] = nuvo_pr_client_buf_alloc();
        if (bufs[i] == NULL)
        {
            ck_assert_ptr_ne(bufs[i], NULL);
        }
    }

    // verify no bufs left
    ck_assert_ptr_eq(nuvo_pr_client_buf_alloc(), NULL);

    // submit buf req alloc
    nuvo_pr_client_buf_alloc_batch(&buf_alloc);
    // verify it didn't succeed yet
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);

    // free some bufs
    for(uint32_t i = 0; i < NUVO_MAX_IO_BLOCKS - 1; i++)
    {
        nuvo_pr_client_buf_free(bufs[i]);
    }
    // verify buf req alloc didn't succeed yet
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);
    nuvo_pr_client_buf_free(bufs[NUVO_PR_MAX_BUFS - 1]);
    // verify buf req alloc did succeed
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 2);
    // free the req bufs
    nuvo_pr_client_buf_free_list(buf_list, NUVO_MAX_IO_BLOCKS);

    // make sure we can allocate all the freed bufs
    for(uint32_t i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
    {
        bufs[i] = nuvo_pr_client_buf_alloc();
        ck_assert_ptr_ne(bufs[i], NULL);
    }
    ck_assert_ptr_eq(nuvo_pr_client_buf_alloc(), NULL);

    for(uint32_t i = 0; i < NUVO_PR_MAX_BUFS; i++)
    {
        nuvo_pr_client_buf_free(bufs[i]);
    }
}
END_TEST

static int32_t nuvo_pr_test_submit_pd = 153;
static uint32_t nuvo_pr_test_submit_reads = 0;
static uint32_t nuvo_pr_test_submit_writes = 0;
static uint32_t nuvo_pr_test_submit_opens = 0;
static uint32_t nuvo_pr_test_submit_closes = 0;
static uint32_t nuvo_pr_test_submit_allocs = 0;
static uint32_t nuvo_pr_test_submit_frees = 0;
static uint32_t nuvo_pr_test_submit_dev_infos = 0;

static uint64_t nuvo_pr_test_device_size;
static uint64_t nuvo_pr_test_parcel_size;

static uuid_t nuvo_pr_test_parcel_id;
static uuid_t nuvo_pr_test_dev_id;
static uuid_t nuvo_pr_test_volume_id;

static bool nuvo_pm_set_dup_op_error = false;

void nuvo_pm_submit(struct nuvo_dlist *submit_list)
{
    struct nuvo_io_request *req;
    while((req = nuvo_dlist_remove_head_object(submit_list, struct nuvo_io_request, list_node)) != NULL)
    {
        switch (req->operation)
        {
            case NUVO_OP_READ:
            case NUVO_OP_READ_VERIFY:
                ck_assert_uint_eq(req->rw.native_parcel_desc, nuvo_pr_test_submit_pd);
                nuvo_pr_test_submit_reads++;
                for(unsigned int i = 0; i < req->rw.block_count; i++)
                {
                    memset(req->rw.iovecs[i].iov_base, req->rw.block_offset + i, NUVO_BLOCK_SIZE);
                    req->rw.block_hashes[i] = nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
                }
            break;
            case NUVO_OP_WRITE:
                ck_assert_uint_eq(req->rw.native_parcel_desc, nuvo_pr_test_submit_pd);
                // verify data
                for(uint32_t i = 0; i < req->rw.block_count; i++)
                {
                    uint32_t block_num = req->rw.block_offset + i;
                    uint32_t bytes_invalid = 0;
                    for(uint32_t n = 0; n < NUVO_BLOCK_SIZE; n++)
                    {
                        uint8_t *buf = (uint8_t*)req->rw.iovecs[i].iov_base;
                        bytes_invalid += buf[n] == (uint8_t)block_num ? 0 : 1;
                    }
                    ck_assert_uint_eq(bytes_invalid, 0);
                }

                nuvo_pr_test_submit_writes++;
            break;
            case NUVO_OP_OPEN:
                nuvo_pr_test_submit_opens++;
                req->open.parcel_desc = nuvo_pr_test_submit_pd;
            break;
            case NUVO_OP_CLOSE:
                nuvo_pr_test_submit_closes++;
                ck_assert_uint_eq(req->close.native_parcel_desc, nuvo_pr_test_submit_pd);
            break;
            case NUVO_OP_ALLOC:
                nuvo_pr_test_submit_allocs++;

                uuid_generate(nuvo_pr_test_parcel_id);
                uuid_copy(req->alloc.parcel_uuid, nuvo_pr_test_parcel_id);
                uuid_copy(nuvo_pr_test_volume_id, req->alloc.volume_uuid);
            break;
            case NUVO_OP_FREE:
                ck_assert_int_eq(uuid_compare(req->free.parcel_uuid, nuvo_pr_test_parcel_id), 0);
                ck_assert_int_eq(uuid_compare(req->free.device_uuid, nuvo_pr_test_dev_id), 0);
                ck_assert_int_eq(uuid_compare(req->free.volume_uuid, nuvo_pr_test_volume_id), 0);
                nuvo_pr_test_submit_frees++;
            break;
            case NUVO_OP_DEV_INFO:
                nuvo_pr_test_parcel_size = (rand() % 2048) * 1024ull * 1024;
                nuvo_pr_test_device_size = (rand() % 64*1024) * nuvo_pr_test_parcel_size;

                req->dev_info.device_size = nuvo_pr_test_device_size;
                req->dev_info.parcel_size = nuvo_pr_test_parcel_size;
                nuvo_pr_test_submit_dev_infos++;
            break;
        }
        if (!nuvo_pm_set_dup_op_error)
        {
            req->status = 0;
        }
        else
        {
            switch (req->operation)
            {
                case NUVO_OP_ALLOC:
                    req->status = -NUVO_E_PARCEL_ALREADY_ALLOC;
                    break;
                case NUVO_OP_OPEN:
                    req->status = -NUVO_E_PARCEL_ALREADY_OPEN;
                    break;
                case NUVO_OP_CLOSE:
                    req->status = -NUVO_E_PARCEL_ALREADY_CLOSED;
                    break;
                case NUVO_OP_FREE:
                    req->status = -NUVO_E_PARCEL_ALREADY_FREE;
                    break;
                default:
                    // Trying to set dup error on op type that fake pm
                    // doesn't yet support.
                    ck_assert_int_ge(nuvo_pm_set_dup_op_error, false);
                    break;
            }
            nuvo_pm_set_dup_op_error = false;
        }
        nuvo_pr_complete(req);
    }
}

static nuvo_mutex_t signal;

void nuvo_pr_test_submit_callback(struct nuvo_io_request *req)
{
    ck_assert_ptr_eq((struct nuvo_io_request *)req->tag.ptr, req);
    nuvo_mutex_unlock(&signal);
}

START_TEST(nuvo_pr_test_submit)
{
    struct nuvo_dlist submit_list;
    // we reserve the signal, so we can wait until it is signaled
    // by a completion
    nuvo_mutex_lock(&signal);
    int_fast64_t ret;
    uuid_t volume_id;
    uuid_t parcel_id;

    nuvo_pr_test_submit_reads = 0;
    nuvo_pr_test_submit_writes = 0;
    nuvo_pr_test_submit_opens = 0;
    nuvo_pr_test_submit_closes = 0;
    nuvo_pr_test_submit_allocs = 0;
    nuvo_pr_test_submit_frees = 0;
    nuvo_pr_test_submit_dev_infos = 0;

    uuid_generate(volume_id);
    // add device to local node
    uuid_generate(nuvo_pr_test_dev_id);
    ret = nuvo_pr_device_insert(nuvo_pr_test_dev_id, local_node_id);
    ck_assert_int_ge(ret, 0);
    // alloc a req
    struct nuvo_io_request *req = nuvo_pr_client_req_alloc();
    ck_assert_ptr_ne(req, NULL);
    // query device info
    req->operation = NUVO_OP_DEV_INFO;
    req->callback = nuvo_pr_test_submit_callback;
    req->tag.ptr = req;
    uuid_copy(req->dev_info.device_uuid, nuvo_pr_test_dev_id);

    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);

    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_dev_infos, 1);
    ck_assert_int_ge(req->status, 0);
    ck_assert_uint_eq(req->dev_info.device_size, nuvo_pr_test_device_size);
    ck_assert_uint_eq(req->dev_info.parcel_size, nuvo_pr_test_parcel_size);

    // allocate parcel from device
    req->operation = NUVO_OP_ALLOC;
    req->callback = nuvo_pr_test_submit_callback;
    req->tag.ptr = req;
    uuid_copy(req->alloc.volume_uuid, volume_id);
    uuid_copy(req->alloc.device_uuid, nuvo_pr_test_dev_id);
    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);

    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_allocs, 1);
    ck_assert_int_ge(req->status, 0);
    ck_assert_int_eq(uuid_compare(req->alloc.parcel_uuid, nuvo_pr_test_parcel_id), 0);
    uuid_copy(parcel_id, req->alloc.parcel_uuid);

    // open parcel
    req->operation = NUVO_OP_OPEN;
    uuid_copy(req->open.parcel_uuid, parcel_id);
    uuid_copy(req->open.device_uuid, nuvo_pr_test_dev_id);
    uuid_copy(req->open.volume_uuid, volume_id);
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);

    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_opens, 1);
    ck_assert_int_ge(req->status, 0);
    uint32_t parcel_desc = req->open.parcel_desc;

    // prep for read io
    req->operation = NUVO_OP_READ;
    req->tag.ptr = req;
    req->rw.parcel_desc = parcel_desc;
    req->rw.block_count = NUVO_MAX_IO_BLOCKS;
    req->rw.block_offset = 12345;
    // alloc req buffers
    struct nuvo_pr_buf_alloc buf_alloc;
    nuvo_pr_test_buf_alloc_cb_count = 0;

    nuvo_pr_buf_alloc_init_req(&buf_alloc,
        req,
        (union nuvo_tag)((void*)&buf_alloc),
        nuvo_pr_test_buf_alloc_cb);

    nuvo_pr_client_buf_alloc_batch(&buf_alloc);
    ck_assert_int_eq(nuvo_pr_test_buf_alloc_cb_count, 1);

    // submit read io
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);

    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_reads, 1);
    ck_assert_int_ge(req->status, 0);
    // verify data
    for(uint32_t i = 0; i < req->rw.block_count; i++)
    {
        uint32_t block_num = req->rw.block_offset + i;
        uint32_t bytes_invalid = 0;
        for(uint32_t n = 0; n < NUVO_BLOCK_SIZE; n++)
        {
            uint8_t *buf = (uint8_t*)req->rw.iovecs[i].iov_base;
            bytes_invalid += buf[n] == (uint8_t)block_num ? 0 : 1;
        }
        ck_assert_uint_eq(bytes_invalid, 0);
    }

    // now we turn around and write the exact same data
    req->operation = NUVO_OP_WRITE;
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);

    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_writes, 1);
    ck_assert_int_ge(req->status, 0);

    // Send duplicate parcel config operations and ensure the idempotent errors
    // are translated correctly (into success)

    // reopen an already open parcel
    struct nuvo_io_request *req2 = nuvo_pr_client_req_alloc();
    req2->tag.ptr = req2;
    req2->callback = nuvo_pr_test_submit_callback;
    req2->operation = NUVO_OP_OPEN;
    uuid_copy(req2->open.parcel_uuid, parcel_id);
    uuid_copy(req2->open.device_uuid, nuvo_pr_test_dev_id);
    uuid_copy(req2->open.volume_uuid, volume_id);
    nuvo_dlist_insert_tail(&submit_list, &req2->list_node);
    nuvo_pm_set_dup_op_error = true;
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);

    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_opens, 2);
    ck_assert_int_ge(req2->status, 0);
    ck_assert_int_eq(req2->idempotent_status_flag, 1);

    // close parcel
    req2->operation = NUVO_OP_CLOSE;
    req2->close.parcel_desc = parcel_desc;
    // submit close io
    nuvo_dlist_insert_tail(&submit_list, &req2->list_node);
    nuvo_pr_submit(&submit_list);
    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_closes, 1);
    ck_assert_int_ge(req2->status, 0);

    // attempt to close a closed parcel
    req2->operation = NUVO_OP_CLOSE;
    req2->close.parcel_desc = parcel_desc;
    // submit close io
    nuvo_dlist_insert_tail(&submit_list, &req2->list_node);
    nuvo_pm_set_dup_op_error = true;
    nuvo_pr_submit(&submit_list);
    // wait for completion callback
    nuvo_mutex_lock(&signal);
    // Request doesn't make it to fake pm, so this doesn't get bumped.
    ck_assert_int_eq(nuvo_pr_test_submit_closes, 1);
    ck_assert_int_ge(req2->status, 0);
    ck_assert_int_eq(req2->idempotent_status_flag, 1);
    nuvo_pr_client_req_free(req2);

    // attempt to do a read to a closed parcel
    req->operation = NUVO_OP_READ;
    // submit read io
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);
    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_reads, 1);
    ck_assert_int_lt(req->status, 0);

    // free req bufs
    nuvo_pr_client_buf_free_req(req);

    // free parcel
    req->operation = NUVO_OP_FREE;
    uuid_copy(req->free.parcel_uuid, parcel_id);
    uuid_copy(req->free.device_uuid, nuvo_pr_test_dev_id);
    uuid_copy(req->free.volume_uuid, volume_id);
    // submit read io
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);
    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_frees, 1);
    ck_assert_int_ge(req->status, 0);

    // free a parcel that is already free
    nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    nuvo_pm_set_dup_op_error = true;
    nuvo_pr_submit(&submit_list);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&submit_list), NULL);
    // wait for completion callback
    nuvo_mutex_lock(&signal);
    ck_assert_int_eq(nuvo_pr_test_submit_frees, 2);
    ck_assert_int_ge(req->status, 0);
    ck_assert_int_eq(req->idempotent_status_flag, 1);

    // remove device
    ret = nuvo_pr_device_remove(nuvo_pr_test_dev_id);
    ck_assert_int_ge(ret, 0);
}
END_TEST

void nuvo_pr_test_setup(void)
{
    (void) nuvo_mutex_init(&signal);
    uuid_generate(local_node_id);
    uint_fast16_t port = 0;
    int_fast64_t ret = nuvo_pr_init(port);
    nuvo_pr_set_node_uuid(local_node_id);
    nuvo_pr_enable(true);

    ck_assert_int_ge(ret, 0);
}

void nuvo_pr_test_teardown(void)
{
    nuvo_pr_shutdown();
    nuvo_mutex_destroy(&signal);
}

Suite * nuvo_pr_suite(void)
{
    Suite *s;
    TCase *tc_pr;

    s = suite_create("NuvoPR");

    tc_pr = tcase_create("NuvoPR");
    tcase_add_checked_fixture(tc_pr, nuvo_pr_test_setup, nuvo_pr_test_teardown);
    tcase_add_test(tc_pr, nuvo_pr_test_init);
    tcase_add_test(tc_pr, nuvo_pr_test_node_alloc_free_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_node_alloc_free_max);
    tcase_add_test(tc_pr, nuvo_pr_test_node_insert_addr_long);
    tcase_add_test(tc_pr, nuvo_pr_test_node_insert_get_remove);
    tcase_add_test(tc_pr, nuvo_pr_test_device_insert_lookup_remove);
    tcase_add_test(tc_pr, nuvo_pr_test_device_insert_remove_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_device_update);
    tcase_add_test(tc_pr, nuvo_pr_test_cconn_alloc_free_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_cconn_alloc_free_max);
    tcase_add_test(tc_pr, nuvo_pr_test_sconn_alloc_free_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_sconn_alloc_free_max);
    tcase_add_test(tc_pr, nuvo_pr_test_req_alloc_free_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_req_alloc_free_max);
    tcase_add_test(tc_pr, nuvo_pr_test_req_alloc_free_cb_max);
    tcase_add_test(tc_pr, nuvo_pr_test_pdef_alloc_free_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_pdef_alloc_free_max);
    tcase_add_test(tc_pr, nuvo_pr_test_pdef_get_to_pdesc);
    tcase_add_test(tc_pr, nuvo_pr_test_pdef_outstanding);
    tcase_add_test(tc_pr, nuvo_pr_test_buf_alloc_free_cycle);
    tcase_add_test(tc_pr, nuvo_pr_test_buf_alloc_free_max);
    tcase_add_test(tc_pr, nuvo_pr_test_buf_alloc_free_req_max);
    tcase_add_test(tc_pr, nuvo_pr_test_buf_alloc_free_list_max);
    tcase_add_test(tc_pr, nuvo_pr_test_submit);

    suite_add_tcase(s, tc_pr);

    return s;
}
