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
#include "../segment.h"
#include "nuvo_ck_assert.h"

START_TEST(segment_list)
{
   struct nuvo_segment_free_list free_list;
   nuvo_return_t rc;
   unsigned num_segments = 10;
   rc = nuvo_segment_free_list_create(&free_list, num_segments);
   ck_assert(rc == 0);

   struct nuvo_segment *segment;
   struct nuvo_dlist parking;
   nuvo_dlist_init(&parking);

   for (unsigned i = 0; i < num_segments; i++)
   {
        segment = nuvo_segment_alloc(&free_list);
        ck_assert(segment != NULL);
        nuvo_dlist_insert_head(&parking, &segment->list_node);
   }

    segment = nuvo_segment_alloc(&free_list);
    ck_assert(segment == NULL);

   for (unsigned i = 0; i < 2; i++)
   {
        segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node);
        nuvo_segment_free(&free_list, segment);
   }

   for (unsigned i = 0; i < 2; i++)
   {
        segment = nuvo_segment_alloc(&free_list);
        ck_assert(segment != NULL);
        nuvo_dlist_insert_head(&parking, &segment->list_node);
   }
 
    for (unsigned i = 0; i < num_segments; i++)
    {
        segment = nuvo_dlist_remove_head_object(&parking, struct nuvo_segment, list_node);
        nuvo_segment_free(&free_list, segment);
    }

    nuvo_segment_free_list_destroy(&free_list);
}
END_TEST

Suite *nuvo_segment_suite(void)
{
    Suite *s = suite_create("Segment");
    TCase *tc_segment = tcase_create("Segment");
    tcase_add_test(tc_segment, segment_list);
     suite_add_tcase(s, tc_segment);
    return s;
}
