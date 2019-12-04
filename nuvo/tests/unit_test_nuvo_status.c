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
#include "status.h"
#include <check.h>

nuvo_return_t return_no_segments()
{
    return -NUVO_E_CONN_CLOSED;
}

START_TEST(converting_types) 
{
    nuvo_return_t rc = -NUVO_E_CONN_CLOSED;
    ck_assert(rc == -NUVO_E_CONN_CLOSED);

    rc = return_no_segments();
    ck_assert(rc == -NUVO_E_CONN_CLOSED);

     ck_assert(-rc == NUVO_E_CONN_CLOSED);
}
END_TEST

START_TEST(posix) 
{
    ck_assert(NUVO_ERROR_IS_POSIX(0));
    ck_assert(NUVO_ERROR_IS_POSIX(NUVO_EHWPOISON));
    ck_assert(!NUVO_ERROR_IS_POSIX(NUVO_E_OUT_OF_SEGMENT_STRUCTS));
}
END_TEST

Suite * nuvo_status_suite(void)
{
    Suite *s;
    TCase *tc_status;

    s = suite_create("NuvoStatus");

    tc_status = tcase_create("NuvoStatus");
    tcase_add_test(tc_status, converting_types);
    tcase_add_test(tc_status, posix);
    suite_add_tcase(s, tc_status);

    return s;
}

