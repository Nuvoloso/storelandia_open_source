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
#include "check_unit_tests.h"
#include "nuvo.h"
#include <errno.h>
#include <stdlib.h>

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = nuvo_api_suite();
    sr = srunner_create(s);
    srunner_add_suite(sr, nuvo_list_suite());
    srunner_add_suite(sr, nuvo_log_level_suite());
    srunner_add_suite(sr, nuvo_stats_suite());
    srunner_add_suite(sr, nuvo_status_suite());
    srunner_add_suite(sr, nuvo_fuse_suite());
    srunner_add_suite(sr, nuvo_segment_suite());
    srunner_add_suite(sr, nuvo_valgrind_suite());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
