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

/*
 * TODO - Put this signal handler stuff and teh other siognal handler
 * into one file together.   That will require moving the nuvo_exit stuff
 * out of the nuvo_api file so that the linking of test will work properly,
 * so doing it now will create a lot of moving code churn that
 * will obfuscate this commit.
 */
#include "nuvo_exit.h"
#pragma once
int nuvo_register_signal_handlers_fuse(struct nuvo_exit_ctrl_s *exit_ctrl);
void nuvo_remove_signal_handlers_fuse();
