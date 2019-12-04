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
#include "status.h"
#include "nuvo_list.h"

#include <stdbool.h>

/**
 * \file parallel.h
 * \brief Parallel op interface.
 *
 * This is a set of routines that allow us to send off a set of parallel ops
 * and then wait for the final one to come back.   For now, this succeeds or fails
 * all together.
 *
 * Workflow is to
 *   1) Call nuvo_parallel_op_init which inits the mutex.
 *   2) Set the callback and tag which will be called when done.
 *   3) Repeat allocing and setting up an op and calling nuvo_parallel_op_submitting while
 *      submitting the op.
 *   3a) Each op in it's callback should call nuvo_parallel_op_done.
 *   4) Call nuvo_parallel_op_finalize.
 *
 * The internals don't free anything.
 *
 * It might be desirable to wrap the generic finalize and wait case, so
 * people wouldn't have to write their own callbacks.
 *
 * If you are going to reuse the same structure without reinitialization,
 * set ops_outstanding to 0, finalized to false and the status to 0 before each reuse.
 */

// TODO - REWRITE NUVO_PARALLEL_OPS USER TO USE THIS INSTEAD.

/**
 * \brief Structure for running parallel ops, such as pr or map.
 */
struct nuvo_parallel_op {
    nuvo_mutex_t   mutex;            /** Mutex to protect the structure. */
    uint_fast32_t  ops_outstanding;  /** How many map ops have have been sent. */
    uint_fast32_t  ops_submitted;    /** How many map ops have have submitted. */
    bool           finalized;

    nuvo_return_t  status;                                       /** All or nothing. */
    void           (*callback)(struct nuvo_parallel_op *par_op); /** Function to call when done */
    union nuvo_tag tag;
};

/**
 * \brief Initialize a parallel op structure.
 *
 * \param par_op The structure.
 * \returns 0 or memory error.
 * \retval -NUVO_ENOMEM Mutex or condition initialization failure.
 */
nuvo_return_t nuvo_parallel_op_init(struct nuvo_parallel_op *par_op);

/**
 * \brief Destroy a parallel op structure.
 *
 * \param par_op The structure.
 */
void nuvo_parallel_op_destroy(struct nuvo_parallel_op *par_op);

/**
 * \brief One of the ops within the parallel op is done.
 *
 * This may trigger the callback of the parallel op.
 * \param par_op The structure.
 * \param status The status of the single op that just finished.
 */
void nuvo_parallel_op_done(struct nuvo_parallel_op *par_op, nuvo_return_t status);

/**
 * \brief An op is being submitted.
 *
 * This should be called right before submitting an individual op.
 * If you do it after the op, there is a chance that the op will
 * complete before this and things will go sideways.
 *
 * \param par_op The structure.
 */
void nuvo_parallel_op_submitting(struct nuvo_parallel_op *par_op);

/**
 * \brief We have submitted the last parallel operation.
 *
 * This marks the operation as having been fully submitted.
 * If all requests within the op have returned already, this will
 * execute the callback.
 *
 * \param par_op The parallel operation.
 */
void nuvo_parallel_op_finalize(struct nuvo_parallel_op *par_op);
