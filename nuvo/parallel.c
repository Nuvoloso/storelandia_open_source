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

#include "parallel.h"
// Documented in header.
nuvo_return_t nuvo_parallel_op_init(struct nuvo_parallel_op *par_op)
{
    par_op->ops_outstanding = 0;
    par_op->ops_submitted = 0;
    par_op->finalized = false;

    par_op->status = 0;
    par_op->callback = NULL;
    //par_op->tag.ptr = NULL;

    return (nuvo_mutex_init(&par_op->mutex));
}

// Documented in header.
void nuvo_parallel_op_destroy(struct nuvo_parallel_op *par_op)
{
    nuvo_mutex_destroy(&par_op->mutex);
}

// Documented in header.
void nuvo_parallel_op_done(struct nuvo_parallel_op *par_op, nuvo_return_t status)
{
    nuvo_mutex_lock(&par_op->mutex);
    par_op->ops_outstanding--;
    if (status != 0)
    {
        par_op->status = status;  // Return one of the calls.
    }
    bool done = (par_op->finalized && par_op->ops_outstanding == 0);
    nuvo_mutex_unlock(&par_op->mutex);

    if (done)
    {
        par_op->callback(par_op);
    }
}

// Documented in header.
void nuvo_parallel_op_submitting(struct nuvo_parallel_op *par_op)
{
    nuvo_mutex_lock(&par_op->mutex);
    par_op->ops_outstanding++;
    par_op->ops_submitted++;
    nuvo_mutex_unlock(&par_op->mutex);
}

// Documented in header.
void nuvo_parallel_op_finalize(struct nuvo_parallel_op *par_op)
{
    nuvo_mutex_lock(&par_op->mutex);
    par_op->finalized = true;
    bool already_done = (par_op->ops_outstanding == 0);
    nuvo_mutex_unlock(&par_op->mutex);
    if (already_done)
    {
        par_op->callback(par_op);
    }
}
