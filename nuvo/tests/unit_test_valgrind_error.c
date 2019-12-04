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

START_TEST(no_free1)
{
    void *a = malloc(100);
    (void) a;
}
END_TEST
START_TEST(no_free2)
{
    void *a = malloc(100);
    (void) a;
}
END_TEST

Suite * nuvo_valgrind_suite(void)
{
    Suite *s;
    TCase *tc_valgrind;

    s = suite_create("NuvoValgrind");
    tc_valgrind = tcase_create("Valgrind");
    tcase_add_test(tc_valgrind, no_free1);
    tcase_add_test(tc_valgrind, no_free2);
    suite_add_tcase(s, tc_valgrind);

    return s;
}
