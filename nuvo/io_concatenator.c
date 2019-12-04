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

#include "io_concatenator.h"

struct nuvo_io_concat_control nuvo_io_concat_control = { 1 };

struct {
    nuvo_mutex_t              pool_mutex;
    struct nuvo_dlist         free_list;
    struct nuvo_io_concat_op *ops;
    unsigned                  num_ops;
} nuvo_io_concat_pool;

nuvo_return_t nuvo_io_concat_pool_init(unsigned num)
{
    nuvo_return_t rc;

    NUVO_ASSERT(nuvo_io_concat_pool.ops == NULL);
    nuvo_io_concat_pool.num_ops = 0;
    nuvo_dlist_init(&nuvo_io_concat_pool.free_list);
    rc = nuvo_mutex_init(&nuvo_io_concat_pool.pool_mutex);
    if (rc < 0)
    {
        return (-NUVO_ENOMEM);
    }

    NUVO_ASSERT(nuvo_io_concat_pool.ops == NULL);
    if (num > 0)
    {
        nuvo_io_concat_pool.ops = calloc(num, sizeof(*nuvo_io_concat_pool.ops));
        if (nuvo_io_concat_pool.ops == NULL)
        {
            rc = -NUVO_ENOMEM;
            goto destroy_pool;
        }
    }

    for (unsigned i = 0; i < num; i++)
    {
        rc = nuvo_mutex_init(&nuvo_io_concat_pool.ops[i].io_concat_op_mutex);
        if (rc < 0)
        {
            goto destroy_pool;
        }
        nuvo_dlnode_init(&nuvo_io_concat_pool.ops[i].list_node);
        nuvo_dlist_init(&nuvo_io_concat_pool.ops[i].io_req_list);
        nuvo_dlist_insert_tail(&nuvo_io_concat_pool.free_list, &nuvo_io_concat_pool.ops[i].list_node);
        nuvo_io_concat_pool.num_ops = i + 1;
    }
    return (0);

destroy_pool:
    nuvo_io_concat_pool_destroy();
    return (rc);
}

void nuvo_io_concat_pool_destroy()
{
    nuvo_mutex_destroy(&nuvo_io_concat_pool.pool_mutex);
    for (unsigned i = 0; i < nuvo_io_concat_pool.num_ops; i++)
    {
        nuvo_mutex_destroy(&nuvo_io_concat_pool.ops[i].io_concat_op_mutex);
    }
    if (nuvo_io_concat_pool.ops != NULL)
    {
        free(nuvo_io_concat_pool.ops);
        nuvo_io_concat_pool.ops = NULL;
    }
}

/**
 * \brief Change the number of outstanding ops.
 * \param io_concatenator io_concatenator that has the number of outstanding changed.
 * \param num The number to change.  Probably 1 or -1.
 * \returns How many outstanding are left.
 */
uint_fast16_t nuvo_io_concat_change_outstanding(struct nuvo_io_concatenator *io_concatenator,
                                                int_fast16_t                 num)
{
    nuvo_mutex_lock(&io_concatenator->outstanding_ops_mutex);
    int32_t new_count = (int32_t)io_concatenator->outstanding_ops + (int32_t)num;
    NUVO_ASSERT(0 <= new_count && new_count <= UINT16_MAX);
    io_concatenator->outstanding_ops = new_count;
    nuvo_mutex_unlock(&io_concatenator->outstanding_ops_mutex);
    return (new_count);
}

/**
 * \brief Add the req from op to the list to submit, and change outstanding on io_concatenator.
 * \param submit_list The list to add the io_req to.
 * \param io_concatenator The concatenator, to increment the oustanding count.
 * \param op The op that has the req to submit.
 */
static inline void add_concat_to_submit(struct nuvo_dlist           *submit_list,
                                        struct nuvo_io_concatenator *io_concatenator,
                                        struct nuvo_io_concat_op    *op)
{
    NUVO_ASSERT_MUTEX_HELD(&op->io_concat_op_mutex);
    nuvo_mutex_unlock(&op->io_concat_op_mutex);
    nuvo_io_concat_change_outstanding(io_concatenator, 1);
    nuvo_dlist_insert_tail(submit_list, &op->req->list_node);
}

/**
 * \brief Submit the current op if there is one.
 * \param io_concatenator The concatenator that might have oustanding io.
 */
void nuvo_io_concat_flush(struct nuvo_io_concatenator *io_concatenator)
{
    struct nuvo_io_concat_op *prev_op = NULL;

    nuvo_mutex_lock(&io_concatenator->io_concat_current_op_mutex);
    prev_op = io_concatenator->current_op;
    io_concatenator->current_op = NULL;
    nuvo_mutex_unlock(&io_concatenator->io_concat_current_op_mutex);
    if (prev_op != NULL)
    {
        struct nuvo_dlist submit_list;
        nuvo_dlist_init(&submit_list);
        nuvo_mutex_lock(&prev_op->io_concat_op_mutex);
        add_concat_to_submit(&submit_list, io_concatenator, prev_op);
        io_concatenator->submit(&submit_list);
    }
}

/**
 * \brief A req on the concat_op (or another related) has completed
 * The req of the op, or he previous op has completed.  Send replies
 * if it is really done.
 * \param concat_op The concat op that an io_req has completed for.
 */
void nuvo_io_concat_io_outstanding_req_done(struct nuvo_io_concat_op *concat_op, nuvo_return_t status)
{
    struct nuvo_io_concatenator *io_concatenator = concat_op->io_concatenator;

    nuvo_mutex_lock(&concat_op->io_concat_op_mutex);
    NUVO_ASSERT(concat_op->outstanding_reqs > 0);
    concat_op->outstanding_reqs--;
    bool done = (concat_op->outstanding_reqs == 0);
    if (status != 0)
    {
        concat_op->status = status;
    }
    nuvo_mutex_unlock(&concat_op->io_concat_op_mutex);
    if (done)
    {
        if (concat_op->io_concat_next_op)
        {
            // decrement next, possibly finishing it.
            nuvo_io_concat_io_outstanding_req_done(concat_op->io_concat_next_op, concat_op->status);
        }

        nuvo_return_t     reqs_status = concat_op->status;
        struct nuvo_dlist reqs;
        nuvo_dlist_init(&reqs);
        nuvo_dlist_insert_list_head(&reqs, &concat_op->io_req_list);

        nuvo_pr_client_req_free(concat_op->req);
        concat_op->req = NULL;
        nuvo_io_concat_op_free(concat_op);

        if (nuvo_io_concat_change_outstanding(io_concatenator, -1) < nuvo_io_concat_control.min_outstanding)
        {
            nuvo_io_concat_flush(io_concatenator);
        }
        struct nuvo_io_request *part_req;
        while (NULL != (part_req = nuvo_dlist_remove_head_object(&reqs, struct nuvo_io_request, list_node)))
        {
            part_req->status = reqs_status;
            part_req->callback(part_req);
        }
    }
}

/**
 * \brief Call back for when the io returns to an io_concatenator.
 */
static void nuvo_io_concat_io_cb(struct nuvo_io_request *io_req)
{
    struct nuvo_io_concat_op *concat_op = (struct nuvo_io_concat_op *)io_req->tag.ptr;

    NUVO_ASSERT(io_req == concat_op->req);

    nuvo_io_concat_io_outstanding_req_done(concat_op, io_req->status);
}

// Documented in header.
nuvo_return_t nuvo_io_concat_init(struct nuvo_io_concatenator *io_concatenator, void (*submit)(struct nuvo_dlist *submit_list))
{
    io_concatenator->current_op = NULL;
    io_concatenator->outstanding_ops = 0;
    io_concatenator->submit = submit;

    if (0 > nuvo_mutex_init(&io_concatenator->io_concat_current_op_mutex))
    {
        return (-NUVO_ENOMEM);
    }
    if (0 > nuvo_mutex_init(&io_concatenator->outstanding_ops_mutex))
    {
        nuvo_mutex_destroy(&io_concatenator->io_concat_current_op_mutex);
        return (-NUVO_ENOMEM);
    }
    return (0);
}

// Documented in header
void nuvo_io_concat_destroy(struct nuvo_io_concatenator *io_concatenator)
{
    nuvo_mutex_lock(&io_concatenator->io_concat_current_op_mutex);
    NUVO_ASSERT(io_concatenator->current_op == NULL);
    nuvo_mutex_unlock(&io_concatenator->io_concat_current_op_mutex);
    nuvo_mutex_lock(&io_concatenator->outstanding_ops_mutex);
    NUVO_ASSERT(io_concatenator->outstanding_ops == 0);
    nuvo_mutex_unlock(&io_concatenator->outstanding_ops_mutex);
    nuvo_mutex_destroy(&io_concatenator->io_concat_current_op_mutex);
    nuvo_mutex_destroy(&io_concatenator->outstanding_ops_mutex);
}

// Documented in header
struct nuvo_io_concat_op *nuvo_io_concat_op_alloc(struct nuvo_io_concatenator *io_concatenator, struct nuvo_vol *vol)
{
    struct nuvo_io_request *req = nuvo_pr_client_req_alloc();

    if (req == NULL)
    {
        return (NULL);
    }

    nuvo_mutex_lock(&nuvo_io_concat_pool.pool_mutex);
    if (nuvo_dlist_empty(&nuvo_io_concat_pool.free_list))
    {
        nuvo_pr_client_req_free(req);
        nuvo_mutex_unlock(&nuvo_io_concat_pool.pool_mutex);
        return (NULL);
    }
    struct nuvo_io_concat_op *op = nuvo_dlist_remove_head_object(&nuvo_io_concat_pool.free_list, struct nuvo_io_concat_op, list_node);
    nuvo_mutex_unlock(&nuvo_io_concat_pool.pool_mutex);

    nuvo_dlnode_init(&req->list_node);
    req->callback = nuvo_io_concat_io_cb;
    req->tag.ptr = op;
    req->operation = NUVO_OP_WRITE;
    req->rw.block_count = 0;
    req->rw.vol = vol;

    op->io_concatenator = io_concatenator;
    op->req = req;
    op->outstanding_reqs = 1;
    op->io_concat_next_op = NULL;
    op->status = 0;

    return (op);
}

// Documented in header
void nuvo_io_concat_op_free(struct nuvo_io_concat_op *op)
{
    NUVO_ASSERT(op->req == NULL);
    NUVO_ASSERT(op->outstanding_reqs == 0);
    NUVO_ASSERT(nuvo_dlist_empty(&op->io_req_list));
    nuvo_mutex_lock(&nuvo_io_concat_pool.pool_mutex);
    nuvo_dlist_insert_head(&nuvo_io_concat_pool.free_list, &op->list_node);
    nuvo_mutex_unlock(&nuvo_io_concat_pool.pool_mutex);
}

#define NUVO_IO_CONCAT_MIN_FRAGMENT    8
// Documented in header
void nuvo_io_concat_submit_req(struct nuvo_io_concatenator *io_concatenator, struct nuvo_io_request *req)
{
    NUVO_ASSERT(req->operation == NUVO_OP_WRITE);

    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);

    struct nuvo_io_concat_op *next_op = NULL;

    nuvo_mutex_lock(&io_concatenator->io_concat_current_op_mutex);

    NUVO_ASSERT(io_concatenator->current_op == NULL || io_concatenator->current_op->req->rw.vol == req->rw.vol);

    // Check to see if req extends current_req
    if (io_concatenator->current_op != NULL)
    {
        nuvo_mutex_lock(&io_concatenator->current_op->io_concat_op_mutex);
        if (io_concatenator->current_op->req->rw.parcel_desc != req->rw.parcel_desc ||
            io_concatenator->current_op->req->rw.block_offset + io_concatenator->current_op->req->rw.block_count != req->rw.block_offset ||
            io_concatenator->current_op->req->rw.cache_hint != req->rw.cache_hint)
        {
            // Does not extend, move the current the submit list.  We'll send at end.
            add_concat_to_submit(&submit_list, io_concatenator, io_concatenator->current_op);
            io_concatenator->current_op = NULL;
        }
    }

    // If we don't have a current op, we try to start a new one.
    if (io_concatenator->current_op == NULL)
    {
        io_concatenator->current_op = nuvo_io_concat_op_alloc(io_concatenator, req->rw.vol);
        if (io_concatenator->current_op != NULL)
        {
            nuvo_mutex_lock(&io_concatenator->current_op->io_concat_op_mutex);
        }
    }

    if (io_concatenator->current_op == NULL)
    {
        goto send_all;
    }

    uint_fast16_t blks_in_next, blks_in_current;
    // Do we need a next op?
    if (io_concatenator->current_op->req->rw.block_count + req->rw.block_count <= NUVO_MAX_IO_BLOCKS)
    {
        blks_in_next = 0;
    }
    else
    {
        // need to spread this op over this and another.
        next_op = nuvo_io_concat_op_alloc(io_concatenator, req->rw.vol);
        if (next_op == NULL)
        {
            // Cannot get a next op. We'll just send the parallel op we have off and then send the req off.
            add_concat_to_submit(&submit_list, io_concatenator, io_concatenator->current_op);
            io_concatenator->current_op = NULL;
            goto send_all;
        }
        // Need to figure out how many blocks to put in current and how many in next.
        // Want to avoid spilling over by less than NUVO_IO_CONCAT_MIN_FRAGMENT.
        // Really only matters if req is NUVO_IO_CONCAT_MIN_FRAGMENT or more
        // and less than NUVO_IO_CONCAT_MIN_FRAGMENT will spill over if we fill the current.
        blks_in_next = io_concatenator->current_op->req->rw.block_count + req->rw.block_count - NUVO_MAX_IO_BLOCKS;
        if (blks_in_next < NUVO_IO_CONCAT_MIN_FRAGMENT && req->rw.block_count >= NUVO_IO_CONCAT_MIN_FRAGMENT)
        {
            blks_in_next = NUVO_IO_CONCAT_MIN_FRAGMENT;
        }
        blks_in_current = req->rw.block_count - blks_in_next;
    }
    blks_in_current = req->rw.block_count - blks_in_next;


    // Put the req on either the current op or the next op, and chain them together if there is a split.
    if (next_op == NULL)
    {
        nuvo_dlist_insert_tail(&io_concatenator->current_op->io_req_list, &req->list_node);
    }
    else
    {
        nuvo_dlist_insert_tail(&next_op->io_req_list, &req->list_node);
        next_op->outstanding_reqs += 1;  // Next op need it's own IO and current one to finish io that is on it's list.
    }

    if (blks_in_current > 0)
    {
        // Extending (possibly creating) the current op.
        if (io_concatenator->current_op->req->rw.block_count == 0)
        {
            // Creating the "current_op"
            io_concatenator->current_op->req->rw.parcel_desc = req->rw.parcel_desc;
            io_concatenator->current_op->req->rw.block_offset = req->rw.block_offset;
            io_concatenator->current_op->req->rw.cache_hint = req->rw.cache_hint;
            io_concatenator->current_op->req->rw.io_origin = req->rw.io_origin;
        }
        else if (req->rw.io_origin == NUVO_IO_ORIGIN_USER)
        {
            // Extending, and any NUVO_IO_ORIGIN_USER makes teh req NUVO_IO_ORIGIN_USER
            io_concatenator->current_op->req->rw.io_origin = NUVO_IO_ORIGIN_USER;
        }

        for (uint_fast16_t i = 0; i < blks_in_current; i++)
        {
            io_concatenator->current_op->req->rw.iovecs[io_concatenator->current_op->req->rw.block_count].iov_base = req->rw.iovecs[i].iov_base;
            io_concatenator->current_op->req->rw.iovecs[io_concatenator->current_op->req->rw.block_count].iov_len = req->rw.iovecs[i].iov_len;
            io_concatenator->current_op->req->rw.block_hashes[io_concatenator->current_op->req->rw.block_count] = req->rw.block_hashes[i];
            io_concatenator->current_op->req->rw.block_count++;
        }
    }

    if (io_concatenator->current_op->req->rw.block_count == NUVO_MAX_IO_BLOCKS || blks_in_next > 0)
    {
        // Done with current.
        NUVO_ASSERT(blks_in_next == 0 || next_op != NULL);
        struct nuvo_io_concat_op *prev_op = io_concatenator->current_op;
        io_concatenator->current_op = NULL;
        if (next_op != NULL)
        {
            prev_op->io_concat_next_op = next_op;
            nuvo_mutex_lock(&next_op->io_concat_op_mutex);
            io_concatenator->current_op = next_op;
            next_op = NULL;
        }
        add_concat_to_submit(&submit_list, io_concatenator, prev_op);
    }

    // Now remaining blocks go into the new current.
    if (blks_in_current < req->rw.block_count)
    {
        io_concatenator->current_op->req->rw.parcel_desc = req->rw.parcel_desc;
        io_concatenator->current_op->req->rw.block_offset = req->rw.block_offset + blks_in_current;
        io_concatenator->current_op->req->rw.cache_hint = req->rw.cache_hint;
        io_concatenator->current_op->req->rw.io_origin = req->rw.io_origin;

        for (uint_fast16_t i = blks_in_current; i < req->rw.block_count; i++)
        {
            io_concatenator->current_op->req->rw.iovecs[io_concatenator->current_op->req->rw.block_count].iov_base = req->rw.iovecs[i].iov_base;
            io_concatenator->current_op->req->rw.iovecs[io_concatenator->current_op->req->rw.block_count].iov_len = req->rw.iovecs[i].iov_len;
            io_concatenator->current_op->req->rw.block_hashes[io_concatenator->current_op->req->rw.block_count] = req->rw.block_hashes[i];
            io_concatenator->current_op->req->rw.block_count++;
        }
    }
    // Is there any circumstance in which we spill over AND have to send the next?  I think not.

    req = NULL;

send_all:
    if (io_concatenator->current_op != NULL)
    {
        if (nuvo_io_concat_control.min_outstanding > io_concatenator->outstanding_ops)
        {
            // Not enough outstanding.  Go ahead and send the current.
            add_concat_to_submit(&submit_list, io_concatenator, io_concatenator->current_op);
            io_concatenator->current_op = NULL;
        }
        else
        {
            // Done with current op.
            nuvo_mutex_unlock(&io_concatenator->current_op->io_concat_op_mutex);
        }
    }

    // Done messing with pointer to current op.
    nuvo_mutex_unlock(&io_concatenator->io_concat_current_op_mutex);

    if (req)
    {
        nuvo_dlist_insert_tail(&submit_list, &req->list_node);
    }
    if (!nuvo_dlist_empty(&submit_list))
    {
        io_concatenator->submit(&submit_list);
    }
}
