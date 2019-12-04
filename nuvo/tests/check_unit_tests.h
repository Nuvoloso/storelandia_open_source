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
 * @file check_unit_tests.h
 * @brief Suites for unit tests
 *
 * Tests that pass valgrind are here.
 */
#include <check.h>
#pragma once
Suite * nuvo_api_suite(void);
Suite * nuvo_list_suite(void);
Suite * nuvo_log_level_suite(void);
Suite * nuvo_stats_suite(void);
Suite * nuvo_status_suite(void);
Suite * nuvo_fuse_suite(void);
Suite * nuvo_segment_suite(void);
Suite * nuvo_valgrind_suite(void);
