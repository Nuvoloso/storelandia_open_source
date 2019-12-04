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
#include "nuvo_list.h"
#include <errno.h>
#include <fcntl.h>
#include <check.h>

struct my_object {
    int                 an_int;
    float               a_float;
    struct nuvo_dlnode  dlist_node;
    struct nuvo_lnode   list_node;
    uint64_t            a_uint64_t;
};

START_TEST(NuvoListTest_dlist_init)
{
    struct nuvo_dlist dlist;
    nuvo_dlist_init(&dlist);
    ck_assert_ptr_eq(dlist.node.next, &dlist.node);
    ck_assert_ptr_eq(dlist.node.prev, &dlist.node);
}
END_TEST

START_TEST(NuvoListTest_dlnode_init)
{
    struct nuvo_dlnode node;
    nuvo_dlnode_init(&node);
    // we don't have ck_assert_ptr_null
    ck_assert_ptr_eq(NULL, node.next);
    ck_assert_ptr_eq(NULL, node.prev);
}
END_TEST

START_TEST(NuvoListTest_dnode_insert_get_remove_head)
{
    struct nuvo_dlist dlist;
    nuvo_dlist_init(&dlist);

    struct nuvo_dlnode node1, node2, node3;
    nuvo_dlnode_init(&node1);
    nuvo_dlnode_init(&node2);
    nuvo_dlnode_init(&node3);

    ck_assert_ptr_eq(nuvo_dlist_get_head(&dlist), NULL);
    nuvo_dlist_insert_head(&dlist, &node1);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&dlist), &node1);
    nuvo_dlist_insert_head(&dlist, &node2);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&dlist), &node2);
    nuvo_dlist_insert_head(&dlist, &node3);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&dlist), &node3);

    ck_assert_ptr_eq(nuvo_dlist_get_tail(&dlist), &node1);

    ck_assert_ptr_eq(nuvo_dlist_remove_head(&dlist), &node3);
    ck_assert_ptr_eq(nuvo_dlist_get_head(&dlist), &node2);

    nuvo_dlist_remove(&node2);
    ck_assert_ptr_eq(nuvo_dlist_remove_head(&dlist), &node1);
    ck_assert_ptr_eq(nuvo_dlist_remove_head(&dlist), NULL);
}
END_TEST

START_TEST(NuvoListTest_dnode_insert_get_remove_tail)
{
    struct nuvo_dlist dlist;
    nuvo_dlist_init(&dlist);

    struct nuvo_dlnode node1, node2, node3;
    nuvo_dlnode_init(&node1);
    nuvo_dlnode_init(&node2);
    nuvo_dlnode_init(&node3);

    ck_assert_ptr_eq(nuvo_dlist_get_tail(&dlist), NULL);
    nuvo_dlist_insert_tail(&dlist, &node1);
    ck_assert_ptr_eq(nuvo_dlist_get_tail(&dlist), &node1);
    nuvo_dlist_insert_tail(&dlist, &node2);
    ck_assert_ptr_eq(nuvo_dlist_get_tail(&dlist), &node2);
    nuvo_dlist_insert_tail(&dlist, &node3);
    ck_assert_ptr_eq(nuvo_dlist_get_tail(&dlist), &node3);

    ck_assert_ptr_eq(nuvo_dlist_get_head(&dlist), &node1);

    ck_assert_ptr_eq(nuvo_dlist_remove_tail(&dlist), &node3);
    ck_assert_ptr_eq(nuvo_dlist_get_tail(&dlist), &node2);

    nuvo_dlist_remove(&node2);
    ck_assert_ptr_eq(nuvo_dlist_remove_tail(&dlist), &node1);
    ck_assert_ptr_eq(nuvo_dlist_remove_tail(&dlist), NULL);
}
END_TEST

START_TEST(NuvoListTest_dnode_get_next_prev)
{
    struct nuvo_dlist dlist;
    nuvo_dlist_init(&dlist);

    struct nuvo_dlnode node1, node2, node3, *node;
    nuvo_dlnode_init(&node1);
    nuvo_dlnode_init(&node2);
    nuvo_dlnode_init(&node3);

    nuvo_dlist_insert_tail(&dlist, &node1);
    nuvo_dlist_insert_tail(&dlist, &node2);
    nuvo_dlist_insert_tail(&dlist, &node3);

    ck_assert_ptr_eq(node = nuvo_dlist_get_head(&dlist), &node1);
    ck_assert_ptr_eq(node = nuvo_dlist_get_next(&dlist, node), &node2);
    ck_assert_ptr_eq(node = nuvo_dlist_get_next(&dlist, node), &node3);
    ck_assert_ptr_eq(node = nuvo_dlist_get_next(&dlist, node), NULL);

    ck_assert_ptr_eq(node = nuvo_dlist_get_tail(&dlist), &node3);
    ck_assert_ptr_eq(node = nuvo_dlist_get_prev(&dlist, node), &node2);
    ck_assert_ptr_eq(node = nuvo_dlist_get_prev(&dlist, node), &node1);
    ck_assert_ptr_eq(node = nuvo_dlist_get_prev(&dlist, node), NULL);
}
END_TEST

START_TEST(NuvoListTest_dnode_get_next_prev_object)
{
    struct nuvo_dlist dlist;
    nuvo_dlist_init(&dlist);

    struct my_object *obj, obj1, obj2, obj3;
    nuvo_dlnode_init(&obj1.dlist_node);
    nuvo_dlnode_init(&obj2.dlist_node);
    nuvo_dlnode_init(&obj3.dlist_node);

    nuvo_dlist_insert_tail(&dlist, &obj1.dlist_node);
    nuvo_dlist_insert_tail(&dlist, &obj2.dlist_node);
    nuvo_dlist_insert_tail(&dlist, &obj3.dlist_node);

    obj = nuvo_dlist_get_head_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj1);
    obj = nuvo_dlist_get_next_object(&dlist, obj, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj2);
    obj = nuvo_dlist_get_next_object(&dlist, obj, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj3);
    obj = nuvo_dlist_get_next_object(&dlist, obj, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, NULL);

    obj = nuvo_dlist_get_tail_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj3);
    obj = nuvo_dlist_get_prev_object(&dlist, obj, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj2);
    obj = nuvo_dlist_get_prev_object(&dlist, obj, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj1);
    obj = nuvo_dlist_get_prev_object(&dlist, obj, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, NULL);
}
END_TEST

START_TEST(NuvoListTest_dnode_remove_head_tail_object)
{
    struct nuvo_dlist dlist;
    nuvo_dlist_init(&dlist);

    struct my_object *obj, obj1, obj2, obj3;
    nuvo_dlnode_init(&obj1.dlist_node);
    nuvo_dlnode_init(&obj2.dlist_node);
    nuvo_dlnode_init(&obj3.dlist_node);

    nuvo_dlist_insert_tail(&dlist, &obj1.dlist_node);
    nuvo_dlist_insert_tail(&dlist, &obj2.dlist_node);
    nuvo_dlist_insert_tail(&dlist, &obj3.dlist_node);

    obj = nuvo_dlist_remove_head_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj1);
    obj = nuvo_dlist_remove_tail_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj3);
    obj = nuvo_dlist_remove_head_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, &obj2);
    obj = nuvo_dlist_remove_tail_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, NULL);
    obj = nuvo_dlist_remove_head_object(&dlist, struct my_object, dlist_node);
    ck_assert_ptr_eq(obj, NULL);
}
END_TEST

START_TEST(NuvoListTest_list_init)
{
    struct nuvo_list list;
    nuvo_list_init(&list);

    ck_assert_ptr_eq(list.node.next, NULL);
}
END_TEST

START_TEST(NuvoListTest_lnode_init)
{
    struct nuvo_lnode node;
    nuvo_lnode_init(&node);

    ck_assert_ptr_eq(node.next, NULL);
}
END_TEST

START_TEST(NuvoListTest_list_insert_get_remove_head)
{
    struct nuvo_list list;
    nuvo_list_init(&list);

    struct nuvo_lnode *node, node1, node2, node3;
    nuvo_lnode_init(&node1);
    nuvo_lnode_init(&node2);
    nuvo_lnode_init(&node3);

    ck_assert_ptr_eq(node = nuvo_list_remove_head(&list), NULL);
    ck_assert_ptr_eq(node = nuvo_list_get_head(&list), NULL);
    nuvo_list_insert_head(&list, &node1);
    ck_assert_ptr_eq(node = nuvo_list_get_head(&list), &node1);
    nuvo_list_insert_head(&list, &node2);
    ck_assert_ptr_eq(node = nuvo_list_get_head(&list), &node2);
    nuvo_list_insert_head(&list, &node3);
    ck_assert_ptr_eq(node = nuvo_list_get_head(&list), &node3);

    ck_assert_ptr_eq(node = nuvo_list_remove_head(&list), &node3);
    ck_assert_ptr_eq(node = nuvo_list_get_head(&list), &node2);
    ck_assert_ptr_eq(node = nuvo_list_remove_head(&list), &node2);
    ck_assert_ptr_eq(node = nuvo_list_remove_head(&list), &node1);
    ck_assert_ptr_eq(node = nuvo_list_remove_head(&list), NULL);
    ck_assert_ptr_eq(node = nuvo_list_get_head(&list), NULL);
}
END_TEST

START_TEST(NuvoListTest_list_get_remove_head_object)
{
    struct nuvo_list list;
    nuvo_list_init(&list);

    struct my_object *obj, obj1, obj2, obj3;
    nuvo_lnode_init(&obj1.list_node);
    nuvo_lnode_init(&obj2.list_node);
    nuvo_lnode_init(&obj3.list_node);

    obj = nuvo_list_remove_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, NULL);
    obj = nuvo_list_get_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, NULL);

    nuvo_list_insert_head(&list, &obj1.list_node);
    obj = nuvo_list_get_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj1);
    nuvo_list_insert_head(&list, &obj2.list_node);
    obj = nuvo_list_get_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj2);
    nuvo_list_insert_head(&list, &obj3.list_node);
    obj = nuvo_list_get_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj3);

    obj = nuvo_list_remove_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj3);
    obj = nuvo_list_get_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj2);
    obj = nuvo_list_remove_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj2);
    obj = nuvo_list_remove_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, &obj1);
    obj = nuvo_list_remove_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, NULL);
    obj = nuvo_list_get_head_object(&list, struct my_object, list_node);
    ck_assert_ptr_eq(obj, NULL);
}
END_TEST

START_TEST(NuvoListTest_dnode_on_dlist)
{
    struct nuvo_dlist list;
    nuvo_dlist_init(&list);

    struct nuvo_dlnode node;
    nuvo_dlnode_init(&node);

    ck_assert(false == nuvo_dlnode_on_list(&node));

    nuvo_dlist_insert_head(&list, &node);
    ck_assert(true == nuvo_dlnode_on_list(&node));

    nuvo_dlist_remove(&node);
    ck_assert(false == nuvo_dlnode_on_list(&node));
}
END_TEST

Suite * nuvo_list_suite(void)
{
    Suite *s;
    TCase *tc_list;

    s = suite_create("NuvoList");

    tc_list = tcase_create("NuvoList");
    tcase_add_test(tc_list, NuvoListTest_dlnode_init);
    tcase_add_test(tc_list, NuvoListTest_dlist_init);
    tcase_add_test(tc_list, NuvoListTest_dnode_insert_get_remove_head);
    tcase_add_test(tc_list, NuvoListTest_dnode_insert_get_remove_tail);
    tcase_add_test(tc_list, NuvoListTest_dnode_get_next_prev);
    tcase_add_test(tc_list, NuvoListTest_dnode_get_next_prev_object);
    tcase_add_test(tc_list, NuvoListTest_dnode_remove_head_tail_object);
    tcase_add_test(tc_list, NuvoListTest_list_init);
    tcase_add_test(tc_list, NuvoListTest_lnode_init);
    tcase_add_test(tc_list, NuvoListTest_list_insert_get_remove_head);
    tcase_add_test(tc_list, NuvoListTest_list_get_remove_head_object);
    tcase_add_test(tc_list, NuvoListTest_dnode_on_dlist);
    suite_add_tcase(s, tc_list);

    return s;
}
