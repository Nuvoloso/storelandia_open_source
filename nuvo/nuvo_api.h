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
 * @file nuvo_api.h
 * @brief Exposes the nuvo api to the external code.
 *
 * All the external code really needs to know right now is that this is here
 * and there is a function to start a pthread on.
 */
#pragma once
#include <nuvo.pb-c.h>
#include "nuvo_lock.h"
#include "nuvo_list.h"

/** \fn void* nuvo_api_thread(void *arg)
 * \brief Thread receiving API commands and dispatch them to worker threads.
 */
void *nuvo_api_thread(void *arg);

/**
 * \brief Per-volume Worker thread that executes volume-specific API commands.
 */
void *nuvo_api_thread_worker_vol(void *arg);

/**
 * \brief Worker thread that executes non volume-specific commands.
 */
void *nuvo_api_thread_worker_nonvol(void *arg);

/** NUVO_API_SOCKET_NAME
 * \brief Name for the unix domain socket receiving API requests.
 */
#define NUVO_DEFAULT_API_SOCKET_NAME    "/tmp/nuvo_api.socket"

struct nuvo_api_params {
    struct nuvo_exit_ctrl_s *exit_ctrl;
    char                    *socket_name;
    int                      full_enable;
};

/**
 * \brief Track current number of per-volume worker threads.
 */
struct nuvo_num_worker {
    unsigned int num;
    nuvo_mutex_t mutex;
    nuvo_cond_t  zero_cond;
};

extern struct nuvo_num_worker num_workers;

/**
 * \brief Control command used to terminate API worker thread (poison pill).
 */
enum api_queue_ctrl_cmd
{
    QUEUE_CTRL_NONE = 0,            /**< Not a control command */
    QUEUE_CTRL_TERMINATE,           /**< Terminate worker thread */
    QUEUE_CTRL_CLOSE_VOL_TERMINATE  /**< Close volume and terminate worker thread */
};

/**
 * \brief A structure for tracking API requests
 */
struct nuvo_api_req {
    struct nuvo_dlnode      list_node;
    Nuvo__Cmd              *cmd;           /**< API command */
    struct nuvo_vol        *vol;           /**< The volume structure if applicable */
    int                     cmd_socket;    /**< The fd to reply to */
    enum api_queue_ctrl_cmd ctrl_cmd;      /**< Out-of-band control command for worker thread */
};
