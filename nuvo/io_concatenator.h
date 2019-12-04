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
 * \file io_concatenator.h
 * \brief data structures for concatenating writes.
 *
 */
#pragma once
#include "nuvo_lock.h"
#include "nuvo_pr.h"


/**
 * \brief Structure for controlling how long to wait for more ios.
 *
 * If an nuvo_io_concat_op is in the logger and there are less than min_outstanding
 * nuvo_io_concat_op already down underlying io layer, the nuvo_io_concat_op gets sent.
 * Typical running case is 1.  Might want to tune more.
 */
struct nuvo_io_concat_control {
    uint_fast16_t min_outstanding;
};
extern struct nuvo_io_concat_control nuvo_io_concat_control;

struct nuvo_io_concatenator;

/**
 * \brief An op with a set of IO reqs that have data in a single underlying IO req.
 * Requests come in. If they extend the req we are building we add them on and put
 * the req on io_req_list.  If only part fits the rest will go on the
 * io_concat_next_op->req and the incoming req will go on io_concat_next_op->io_req_list.
 * In that case this op counts against io_concat_next_op->outstanding_reqs.
 */
struct nuvo_io_concat_op {
    struct nuvo_dlnode           list_node;

    nuvo_mutex_t                 io_concat_op_mutex;
    struct nuvo_io_request      *req;                 /**< The request we will send down */
    uint_fast16_t                outstanding_reqs;    /**< How many underlying reqs are we waiting for.  This might include
                                                       *   the above req and the previous ops req if an incoming io is torn */
    struct nuvo_dlist            io_req_list;         /**< The io's that we resond to when outstanding_reqs goes to 0.*/
    struct nuvo_io_concat_op    *io_concat_next_op;   /**< The next op if the last incoming io_req in this op. */
    struct nuvo_io_concatenator *io_concatenator;     /**< The concatenator this was dispatched on. */
    nuvo_return_t                status;
};


/**
 * \brief This is a structure that collects IOs (just writes for now), concatenating consecutive ones.
 *
 * The intended use case is something that will generate consecutive ios (like a logger segment) will
 * have one of these and submit ios to this instead of the pr or rl.
 */
struct nuvo_io_concatenator {
    nuvo_mutex_t              io_concat_current_op_mutex;                /**< mutex protecting current op. */
    struct nuvo_io_concat_op *current_op;                                /**< The op we are currently building */

    nuvo_mutex_t              outstanding_ops_mutex;                     /**< mutex protecting outstanding_ops. */
    uint_fast16_t             outstanding_ops;                           /**< count of how many ops have been submitted to lower layer. */

    void                      (*submit)(struct nuvo_dlist *submit_list); /**< The routine to submit a list of ios. */
};

/**
 * \brief Initialize a nuvo_io_concatenator
 * \param io_concatenator The struct to initialize.
 * \param submit routing to submit ios.  e.g. nuvo_pr_submit or nuvo_rl_submit
 *
 * \retval 0 Success
 * \retval -NUVO_ENOMEM Mutex initialization failed.
 */
nuvo_return_t nuvo_io_concat_init(struct nuvo_io_concatenator *io_concatenator, void (*submit)(struct nuvo_dlist *submit_list));

/**
 * \brief Destroy a concatenator.
 * \param io_concatenator The struct to destroy.
 */
void nuvo_io_concat_destroy(struct nuvo_io_concatenator *io_concatenator);

/**
 * \brief Flush the current_op, if there is one.
 *
 * NOTE - this only sends the io off.  It doesn't wait for it to come back.
 * \param io_concatenator
 */
void nuvo_io_concat_flush(struct nuvo_io_concatenator *io_concatenator);

/**
 * \brief Allocate a nuvo_io_concat_op
 */
struct nuvo_io_concat_op *nuvo_io_concat_op_alloc(struct nuvo_io_concatenator *io_concatenator, struct nuvo_vol *vol);

/**
 * \brief Free a nuvo_io_concat_op
 * This is called from the the callback that a req is done.
 * \param op The op that is done and is being deleted.
 */
void nuvo_io_concat_op_free(struct nuvo_io_concat_op *op);

/**
 * \brief Submit a single request.
 * \param io_concatenator The concatenator
 * \param req The io req to submit.
 */
void nuvo_io_concat_submit_req(struct nuvo_io_concatenator *io_concatenator, struct nuvo_io_request *req);

/**
 * \brief init pool of nuvo_io_concat_op
 * Can init with 0, especially for testing purposes.
 * \param num The number of ops to create.
 * \retval -NUVO_ENOMEM Out of memmory.
 * \retval 0 Success.
 */
nuvo_return_t nuvo_io_concat_pool_init(unsigned num);

/**
 * \brief Destroy the pool of nuvo_io_concat_op
 */
void nuvo_io_concat_pool_destroy();
