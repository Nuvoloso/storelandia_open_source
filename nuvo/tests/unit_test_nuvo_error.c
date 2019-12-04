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
#include "nuvo.h"
#include <errno.h>
#include <stdlib.h>
#include <signal.h>

START_TEST(Nuvo_Error_Test_Panic)
{
    NUVO_PANIC("boo%d", 24);
}
END_TEST

#if 0
// Need to figure out if we can look for string in the panic
START_TEST(Nuvo_Error_Test_Panic_Errno)
{
    ASSERT_DEATH(NUVO_PANIC_ERRNO(ENOENT, "boo"), "boo : No such file or directory");
}
END_TEST
#endif

START_TEST(Nuvo_Error_Test_Panic_Cond_Fail)
{
    NUVO_PANIC_COND(1, "boohoo%llx", 0xfeedfacedeadbeefull);
}
END_TEST

START_TEST(Nuvo_Error_Test_Panic_Cond_NoFail)
{
    NUVO_PANIC_COND(0, "boo");
}
END_TEST

Suite * nuvo_error_suite(void)
{
    Suite *s;
    TCase *tc_error;

    s = suite_create("ErrorTest");

    tc_error = tcase_create("ErrorTest");
    tcase_add_test_raise_signal(tc_error, Nuvo_Error_Test_Panic, SIGABRT);
    tcase_add_test_raise_signal(tc_error, Nuvo_Error_Test_Panic_Cond_Fail, SIGABRT);
    tcase_add_test(tc_error, Nuvo_Error_Test_Panic_Cond_NoFail);
    suite_add_tcase(s, tc_error);

    return s;
}
