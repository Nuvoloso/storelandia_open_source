
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
#include <errno.h>
#include <fcntl.h>
#include <check.h>
#include <stdlib.h>

#include "lun.h"
#include "nuvo_fuse.h"
#include "nuvo_vol_series.h"

nuvo_node_t *f;
nuvo_node_t *d;
struct nuvo_lun lun;

void file_test_setup()
{
    lun.lun_state = NUVO_LUN_STATE_VALID;
    lun.export_state = NUVO_LUN_EXPORT_UNEXPORTED;
    lun.size = 0;
    lun.vol = NULL;

    nuvo_fs_setup(&lun, true);
    f = &lun.lun_file_system.nodes[NUVO_FUSE_LUN_INO];
    d = &lun.lun_file_system.nodes[NUVO_FUSE_ROOT_INO];
}

void file_test_teardown()
{
}

START_TEST(nuvo_file_test_stat_file)
{
    struct stat s;
    memset(&s, 0, sizeof(s));
    nuvo_fill_attr(f, &s);
    ck_assert_uint_eq((long unsigned int)f->inum, s.st_ino);
    ck_assert_uint_eq(f->mode, s.st_mode);
    ck_assert_uint_eq(f->nlink, s.st_nlink);
    ck_assert_uint_eq((long int)f->u.file.lun->size, s.st_size);
}
END_TEST

START_TEST(nuvo_file_test_stat_dir)
{
    struct stat s;
    memset(&s, 0, sizeof(s));
    nuvo_fill_attr(d, &s);
    ck_assert_uint_eq((long unsigned int)d->inum, s.st_ino);
    ck_assert_uint_eq(d->mode, s.st_mode);
    ck_assert_uint_eq(d->nlink, s.st_nlink);
    ck_assert_uint_eq((long int)f->u.file.lun->size, s.st_size);
}
END_TEST

START_TEST(nuvo_file_test_find_dir_ent)
{
    fuse_ino_t inum;
    unsigned int idx;
    nuvo_return_t r;
    r = nuvo_find_dir_ent(d, ".", &inum, &idx);
    ck_assert_int_eq(0, r);
    ck_assert_uint_eq(d->inum, inum);
    ck_assert_uint_eq((unsigned)0, idx);

    r = nuvo_find_dir_ent(d, "..", &inum, &idx);
    ck_assert_int_eq(0, r);
    ck_assert_uint_eq((unsigned)1, idx);
    ck_assert_uint_eq(d->u.dir.ents[idx].inum, inum);

    r = nuvo_find_dir_ent(d, "vol", &inum, &idx);
    ck_assert_int_eq(0, r);
    ck_assert_uint_eq((unsigned)2, idx);
    ck_assert_uint_eq(d->u.dir.ents[idx].inum, inum);

    r = nuvo_find_dir_ent(d, "foo1", &inum, &idx);
    ck_assert_int_eq(-NUVO_ENOENT, r);

    r = nuvo_find_dir_ent(d, "fo", &inum, &idx);
    ck_assert_int_eq(-NUVO_ENOENT, r);
}
END_TEST

//
// This test does a lock step walk with two threads
// and three locks, A, B, C.  The goal is to make sure
// the thread lock/unlock triggering is working properly.
// The ranges are adjacent to make sure the ranges are
// working properly.
//
static struct nuvo_range_lock rl;
static int protected_var;

#define A_RANGE 0
#define B_RANGE 2
#define C_RANGE 4
#define RANGE_LEN 2

void *range_lock_thread(void *arg)
{
    void *a_handle, *b_handle, *c_handle;

    a_handle = arg;

    c_handle = nuvo_lock_range_wait(&rl, C_RANGE, RANGE_LEN);
    protected_var++;
    nuvo_unlock_range(&rl, a_handle);

    b_handle = nuvo_lock_range_wait(&rl, B_RANGE, RANGE_LEN);

    ck_assert_int_eq(protected_var, 2);
    protected_var++;

    nuvo_unlock_range(&rl, c_handle);

    a_handle = nuvo_lock_range_wait(&rl, A_RANGE, RANGE_LEN);

    ck_assert_int_eq(protected_var, 4);
    protected_var++;

    nuvo_unlock_range(&rl, b_handle);

    c_handle = nuvo_lock_range_wait(&rl, C_RANGE, RANGE_LEN);

    ck_assert_int_eq(protected_var, 6);
    protected_var++;

    nuvo_unlock_range(&rl, c_handle);
    nuvo_unlock_range(&rl, a_handle);

    return NULL;
}


START_TEST(nuvo_test_range_lock)
{
    void *a_handle, *b_handle, *c_handle;
    int i;
    pthread_t thread;

    protected_var = 0;

    nuvo_range_lock_freelist_init();
    nuvo_range_lock_init(&rl);

    a_handle = nuvo_lock_range_wait(&rl, A_RANGE, RANGE_LEN);
    b_handle = nuvo_lock_range_wait(&rl, B_RANGE, RANGE_LEN);

    protected_var = 0;

    i = pthread_create(&thread, NULL, range_lock_thread, (void *)a_handle);
    ck_assert_int_eq(i, 0);

    // Wait for the other thread to trigger me
    a_handle = nuvo_lock_range_wait(&rl, A_RANGE, RANGE_LEN);

    ck_assert_int_eq(protected_var, 1);
    protected_var++;

    nuvo_unlock_range(&rl, b_handle);

    c_handle = nuvo_lock_range_wait(&rl, C_RANGE, RANGE_LEN);

    ck_assert_int_eq(protected_var, 3);
    protected_var++;

    nuvo_unlock_range(&rl, a_handle);
    b_handle = nuvo_lock_range_wait(&rl, B_RANGE, RANGE_LEN);

    ck_assert_int_eq(protected_var, 5);
    protected_var++;

    nuvo_unlock_range(&rl, c_handle);
    nuvo_unlock_range(&rl, b_handle);

    pthread_join(thread, NULL);
    nuvo_range_lock_destroy(&rl);
}
END_TEST

Suite * nuvo_fuse_suite(void)
{
    Suite *s;
    TCase *tc_list;

    s = suite_create("NuvoFuse");

    tc_list = tcase_create("NuvoFuse");
    tcase_add_checked_fixture(tc_list, file_test_setup, file_test_teardown);
    tcase_add_test(tc_list, nuvo_file_test_stat_file);
    tcase_add_test(tc_list, nuvo_file_test_stat_dir);
    tcase_add_test(tc_list, nuvo_file_test_find_dir_ent);
    tcase_add_test(tc_list, nuvo_test_range_lock);
    suite_add_tcase(s, tc_list);

    return s;
}
