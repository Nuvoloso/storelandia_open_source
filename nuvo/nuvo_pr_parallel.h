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
#include "nuvo_lock.h"
#include "nuvo_pr.h"

/**
 * \file nuvo_pr_parallel.h
 * \brief Parallel io interface.
 *
 * This is a set of routines that allow us to send off a set of parallel io's
 * and then wait for the final one to come back.   For now, this succeeds or fails
 * all together.
 *
 * Workflow is to
 *   1) Call nuvo_pr_parallel_init which inits the mutex.
 *   2) Set the callback and tag which will be called whn done.
 *   3) Repeat allocing and setting up an IO and calling nuvo_pr_parallel_submit.
 *   4) Call nuvo_pr_parallel_finalize.
 *
 * The internals free each IO, but not attached buffers.  So this works well
 * for using a preallocated buffer.  It would require enhancement to use
 * dynamically allocated buffers.
 *
 * It might be desirable to wrap the generic finalize and wait case, so
 * people wouldn't have to write their own callbacks.
 *
 * If you are going to reuse the same structure without reinitialization,
 * set ios_outstanding to 1 adn the status to 0 before each reuse.
 */

/**
 * \brief Structure for running a parallel IO.
 */
struct nuvo_parallel_io {
    nuvo_mutex_t   mutex;                                        /** Mutex to protect the structure. */
    uint_fast32_t  ios_outstanding;                              /** How many ios have have been sent. */

    nuvo_return_t  status;                                       /** All or nothing. */
    void           (*callback)(struct nuvo_parallel_io *par_io); /** Callback function. */
    union nuvo_tag tag;                                          /** tag for callback to use. */
};

typedef void (*nuvo_parallel_io_cb_t )(struct nuvo_parallel_io *);

/**
 * \brief Initialize a parallel IO structure.
 *
 * \param par_io The structure.
 * \returns 0 or memory error.
 * \retval -NUVO_ENOMEM Mutex or condition initialization failure.
 */
nuvo_return_t nuvo_pr_parallel_init(struct nuvo_parallel_io *par_io);

/**
 * \brief Destroy a parallel IO structure.
 *
 * \param par_io The structure.
 */
void nuvo_pr_parallel_destroy(struct nuvo_parallel_io *par_io);

/**
 * \brief Send an IO.
 *
 * Sends the IO, incrementing the ios_outstanding until it returns, when it
 * decrements ios_outstanding and when it hits 0, broadcast on the condition.
 * Then frees the io_req. If you allocated buffers on it, you will be unhappy.
 *
 * \param par_io The structure.
 * \param io_req The io_req to send.
 */
void nuvo_pr_parallel_submit(struct nuvo_parallel_io *par_io, struct nuvo_io_request *io_req);

/**
 * \brief Called after sending last IO to enable callback.
 *
 * This will either cause the last IO returning to execute the callback. If
 * all IOs have already returned this will immediately call the callback.
 * Calling nuvo_pr_parallel_submit after nuvo_pr_parallel_finalize before the
 * callback will result in unhappy, unpredicatble results.
 */
void nuvo_pr_parallel_finalize(struct nuvo_parallel_io *par_io);
