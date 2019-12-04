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
 * @file nuvo_exit.h
 * @brief Routines for coordinating exiting.
 */
#pragma once
#include "nuvo_lock.h"

struct nuvo_exit_ctrl_s {
    nuvo_mutex_t exit_mutex;
    nuvo_cond_t  exit_cond;
    int          api_thread_pipe[2];
    bool         exiting;
};

extern struct nuvo_exit_ctrl_s exit_ctrl;
void nuvo_exiting_init(struct nuvo_exit_ctrl_s *exit);
void nuvo_exiting_set(struct nuvo_exit_ctrl_s *exit);
bool nuvo_exiting_get(struct nuvo_exit_ctrl_s *exit);
void nuvo_exiting_wait(struct nuvo_exit_ctrl_s *exit);
void nuvo_exiting_destroy(struct nuvo_exit_ctrl_s *exit);
