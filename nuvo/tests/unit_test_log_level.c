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
#include <check.h>
#include <stdlib.h>

#include "../nuvo.h"
#include "../status.h"

START_TEST(log_level)
{
    nuvo_return_t rc = nuvo_log_set_level("mfst", 20);
    ck_assert(rc == 0);
    ck_assert(nuvo_log.mfst.level == 20);
}
END_TEST

START_TEST(log_level_fail)
{
    nuvo_return_t rc = nuvo_log_set_level("no_such_module", 20);
    ck_assert(rc == -NUVO_E_NO_MODULE);
}
END_TEST

Suite * nuvo_log_level_suite(void)
{
    Suite *s;
    TCase *tc_log_level;

    s = suite_create("LogLevel");
    tc_log_level = tcase_create("LogLevel");
    tcase_add_test(tc_log_level, log_level);
    tcase_add_test(tc_log_level, log_level_fail);
    suite_add_tcase(s, tc_log_level);

    return s;
}
