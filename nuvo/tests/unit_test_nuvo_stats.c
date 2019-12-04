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
#include "nuvo_stats.h"
#include <errno.h>
#include <check.h>

START_TEST(nuvo_stats_test_init) 
{
    int_fast64_t ret;
    struct nuvo_io_stats stats;
    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    struct nuvo_io_stats_snap snap;
    snap.size_hist = size_hist;
    snap.latency_hist = latency_hist;

    ret = nuvo_io_stats_init(&stats);
    ck_assert_int_ge(ret, 0);

    ck_assert_uint_eq(stats.count, 0);
    ck_assert_uint_eq(stats.size_sum, 0);
    ck_assert_uint_eq(stats.latency_sum, 0);
    ck_assert(stats.latency_sum_squared == 0.0);

    for(unsigned i = 0; i < NUVO_STATS_SIZE_BINS; i++)
    {
        nuvo_io_stats_get_snapshot(&stats, &snap, 0);
        ck_assert_uint_eq(snap.size_hist[i], 0);
    }

    for(unsigned i = 0; i < NUVO_STATS_LAT_BINS; i++)
    {
        nuvo_io_stats_get_snapshot(&stats, &snap, 0);
        ck_assert_uint_eq(snap.latency_hist[i], 0);
    }

    nuvo_io_stats_destroy(&stats);
}
END_TEST

START_TEST(nuvo_stats_test_add)
{
    int_fast64_t ret;
    struct nuvo_io_stats stats;
    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    struct nuvo_io_stats_snap snap;
    snap.size_hist = size_hist;
    snap.latency_hist = latency_hist;

    ret = nuvo_io_stats_init(&stats);
    ck_assert_int_ge(ret, 0);

    nuvo_io_stats_add(&stats, 4095, 123456);
    nuvo_io_stats_get_snapshot(&stats, &snap, 0);

    ck_assert_uint_eq(snap.count, 1);
    ck_assert(snap.size_total == 4095);
    ck_assert(snap.latency_mean == 123456.0);
    ck_assert(snap.latency_stdev == 0.0);
   
    ck_assert_uint_eq(snap.size_hist[11], 1);

    nuvo_io_stats_add(&stats, 4096, 1234567);
    nuvo_io_stats_get_snapshot(&stats, &snap, 0);

    ck_assert_uint_eq(snap.count, 2);
    ck_assert(snap.size_total == 4095 + 4096);
    ck_assert(snap.latency_mean == 679011.5);

    double mean = (123456.0 + 1234567.0)/2.0;

    ck_assert(snap.latency_stdev == 
              sqrt((123456.0 * 123456.0 + 1234567.0 * 1234567.0) / 2 - mean * mean));

    ck_assert_uint_eq(snap.size_hist[11], 1);
    ck_assert_uint_eq(snap.size_hist[12], 1);

    nuvo_io_stats_destroy(&stats);
}
END_TEST

START_TEST(nuvo_stats_test_clear) 
{
    int_fast64_t ret;
    struct nuvo_io_stats stats;
    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    struct nuvo_io_stats_snap snap;
    snap.size_hist = size_hist;
    snap.latency_hist = latency_hist;

    ret = nuvo_io_stats_init(&stats);
    ck_assert_int_ge(ret, 0);

    nuvo_io_stats_add(&stats, 4095, 123456);
    nuvo_io_stats_add(&stats, 4096, 1234567);

    nuvo_io_stats_clear(&stats);

    nuvo_io_stats_get_snapshot(&stats, &snap, 0);

    ck_assert_uint_eq(snap.count, 0);
    ck_assert_uint_eq(snap.size_total, 0);
    ck_assert_uint_eq(snap.latency_mean, 0);
    ck_assert(snap.latency_stdev == 0.0);

    for(unsigned i = 0; i < NUVO_STATS_SIZE_BINS; i++)
    {
        ck_assert_uint_eq(snap.size_hist[i], 0);
    }

    for(unsigned i = 0; i < NUVO_STATS_LAT_BINS; i++)
    {
        ck_assert_uint_eq(snap.latency_hist[i], 0);
    }

    nuvo_io_stats_destroy(&stats);
}
END_TEST

START_TEST(nuvo_stats_test_uuid)
{
    int_fast64_t ret;
    struct nuvo_io_stats stats;
    ret = nuvo_io_stats_init(&stats);
    ck_assert_int_ge(ret, 0);

    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    struct nuvo_io_stats_snap snap;
    snap.size_hist = size_hist;
    snap.latency_hist = latency_hist;

    uuid_t series_uuid;
    // Re-reading stats should not clear the uuid.
    nuvo_io_stats_get_snapshot(&stats, &snap, false);
    uuid_copy(series_uuid, snap.series_uuid);
    nuvo_io_stats_get_snapshot(&stats, &snap, false);
    ck_assert(0 == uuid_compare(series_uuid, snap.series_uuid));

    // Clearing stats gives a new uuid
    nuvo_io_stats_clear(&stats);
    nuvo_io_stats_get_snapshot(&stats, &snap, false);
    ck_assert(0 != uuid_compare(series_uuid, snap.series_uuid));

    // Reading with clear gives back same uuid, but resets for next time.
    uuid_copy(series_uuid, snap.series_uuid);
    nuvo_io_stats_get_snapshot(&stats, &snap, true);
    ck_assert(0 == uuid_compare(series_uuid, snap.series_uuid));
    nuvo_io_stats_get_snapshot(&stats, &snap, false);
    ck_assert(0 != uuid_compare(series_uuid, snap.series_uuid));

    nuvo_io_stats_destroy(&stats);
}
END_TEST

START_TEST(nuvo_stats_test_size_hist_range) 
{
    uint_fast64_t start, end, new_start, new_end;

    nuvo_io_stats_size_hist_range(0, &start, &end);
    ck_assert_uint_eq(start, 0);

    for(unsigned i = 1; i < NUVO_STATS_SIZE_BINS; i++)
    {
        nuvo_io_stats_size_hist_range(i, &new_start, &new_end);
        ck_assert_uint_eq(new_start, end + 1ull);

        start = new_start;
        end = new_end;
    }
}
END_TEST

START_TEST(nuvo_stats_test_latency_hist_range) 
{
    uint_fast64_t start, end, new_start, new_end;

    nuvo_io_stats_latency_hist_range(0, &start, &end);
    ck_assert_uint_eq(start, 0);

    for(unsigned i = 1; i < NUVO_STATS_LAT_BINS; i++)
    {
        nuvo_io_stats_latency_hist_range(i, &new_start, &new_end);
        ck_assert_uint_eq(new_start, end + 1ull);

        start = new_start;
        end = new_end;
    }
}
END_TEST

START_TEST(nuvo_stats_test_size_hist) 
{
    int_fast64_t ret;
    uint_fast64_t start, end;
    struct nuvo_io_stats stats;
    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    struct nuvo_io_stats_snap snap;
    snap.size_hist = size_hist;
    snap.latency_hist = latency_hist;

    ret = nuvo_io_stats_init(&stats);
    ck_assert_int_ge(ret, 0);

    for(unsigned n = 0; n < NUVO_STATS_SIZE_BINS; n++)
    {
        nuvo_io_stats_clear(&stats);
        nuvo_io_stats_size_hist_range(n, &start, &end);
        nuvo_io_stats_add(&stats, start, 123456);
        nuvo_io_stats_add(&stats, (start + end)/2, 123456);
        nuvo_io_stats_add(&stats, end, 123456);
        for(unsigned i = 0; i < NUVO_STATS_SIZE_BINS; i++)
        {
            nuvo_io_stats_get_snapshot(&stats, &snap, 0);
            if (i == n)
            {
                ck_assert_uint_eq(snap.size_hist[i], 3);
            }
            else
            {
                ck_assert_uint_eq(snap.size_hist[i], 0);
            }
        }
    }
    nuvo_io_stats_destroy(&stats);
}
END_TEST

START_TEST(nuvo_stats_test_latency_hist) 
{
    int_fast64_t ret;
    uint_fast64_t start, end;
    struct nuvo_io_stats stats;
    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    struct nuvo_io_stats_snap snap;
    snap.size_hist = size_hist;
    snap.latency_hist = latency_hist;

    ret = nuvo_io_stats_init(&stats);
    ck_assert_int_ge(ret, 0);

    for(unsigned n = 0; n < NUVO_STATS_SIZE_BINS; n++)
    {
        nuvo_io_stats_clear(&stats);
        nuvo_io_stats_latency_hist_range(n, &start, &end);
        nuvo_io_stats_add(&stats, 4096, start);
        nuvo_io_stats_add(&stats, 4096, (start + end)/2);
        nuvo_io_stats_add(&stats, 4096, end);
        for(unsigned i = 0; i < NUVO_STATS_SIZE_BINS; i++)
        {
            nuvo_io_stats_get_snapshot(&stats, &snap, 0);
            if (i == n)
            {
                ck_assert_uint_eq(snap.latency_hist[i], 3);
            }
            else
            {
                ck_assert_uint_eq(snap.latency_hist[i], 0);
            }
        }
    }
    nuvo_io_stats_destroy(&stats);
}
END_TEST

Suite * nuvo_stats_suite(void)
{
    Suite *s;
    TCase *tc_stats;

    s = suite_create("NuvoStats");

    tc_stats = tcase_create("NuvoStats");
    tcase_add_test(tc_stats, nuvo_stats_test_init);
    tcase_add_test(tc_stats, nuvo_stats_test_add);
    tcase_add_test(tc_stats, nuvo_stats_test_clear);
    tcase_add_test(tc_stats, nuvo_stats_test_uuid);
    tcase_add_test(tc_stats, nuvo_stats_test_size_hist_range);
    tcase_add_test(tc_stats, nuvo_stats_test_latency_hist_range);
    tcase_add_test(tc_stats, nuvo_stats_test_size_hist);
    tcase_add_test(tc_stats, nuvo_stats_test_latency_hist);
    suite_add_tcase(s, tc_stats);

    return s;
}

