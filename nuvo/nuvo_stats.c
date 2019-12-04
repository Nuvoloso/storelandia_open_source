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

#include <string.h>

/**
 * \brief Determine the histogram bin index for a size value.
 *
 * Nuvo IO Stats internal use only.
 * This function determines the histogram bin index for a given size value.
 *
 * \param size The size value.
 * \returns The index of the bin in the size histogram that the value falls
 * into.
 */
uint_fast8_t nuvo_io_stats_get_size_bin(uint_fast64_t size);

/**
 * \brief Determine the histogram bin index for a latency value.
 *
 * Nuvo IO Stats internal use only.
 * This function determines the histogram bin index for a given latency value.
 *
 * \param latency The latency value.
 * \returns The index of the bin in the latency histogram that the value falls
 * into.
 */
int nuvo_io_stats_get_lat_bin(uint_fast64_t latency);

int_fast64_t nuvo_io_stats_init(struct nuvo_io_stats *stats)
{
    int_fast64_t ret;

    ret = nuvo_mutex_init(&stats->mutex);
    if (ret < 0)
    {
        return (-1);
    }
    nuvo_io_stats_clear(stats);

    return (0);
}

void nuvo_io_stats_destroy(struct nuvo_io_stats *stats)
{
    nuvo_mutex_destroy(&stats->mutex);
}

static void nuvo_io_stats_clear_locked(struct nuvo_io_stats *stats)
{
    stats->count = 0;
    stats->size_sum = 0;

    for (unsigned i = 0; i < NUVO_STATS_SIZE_BINS; i++)
    {
        stats->size_hist[i] = 0;
    }

    stats->latency_sum = 0;
    stats->latency_sum_squared = 0;

    for (unsigned i = 0; i < NUVO_STATS_LAT_BINS; i++)
    {
        stats->latency_hist[i] = 0;
    }

    uuid_generate(stats->series_uuid);
}

void nuvo_io_stats_clear(struct nuvo_io_stats *stats)
{
    nuvo_mutex_lock(&stats->mutex);
    nuvo_io_stats_clear_locked(stats);
    nuvo_mutex_unlock(&stats->mutex);
}

uint_fast8_t nuvo_io_stats_get_size_bin(uint_fast64_t size)
{
    int          clz = __builtin_clzll(size);
    uint_fast8_t bin = 63 - clz;

    // check for case of zero
    if (size == 0)
    {
        bin = 0;
    }

    // check for unlikely overflow
    if (bin >= NUVO_STATS_SIZE_BINS)
    {
        bin = NUVO_STATS_SIZE_BINS - 1;
    }

    return (bin);
}

int nuvo_io_stats_get_lat_bin(uint_fast64_t latency)
{
    uint_fast64_t latency_shifted = latency >> NUVO_STATS_LAT_SUB_BITS;
    int           clz = __builtin_clzll(latency_shifted);
    int           pow_bits = (64 - clz);

    int shift_bits = pow_bits - 1;

    if (latency_shifted == 0)
    {
        pow_bits = 0;
        shift_bits = 0;
    }

    int lin_bits = (latency >> shift_bits) & ((1ull << NUVO_STATS_LAT_SUB_BITS) - 1ull);

    int ret = (pow_bits << NUVO_STATS_LAT_SUB_BITS) | lin_bits;
    if (pow_bits >= NUVO_STATS_LAT_BITS)
    {
        ret = (NUVO_STATS_LAT_BITS << NUVO_STATS_LAT_SUB_BITS) - 1;
    }

    return (ret);
}

void nuvo_io_stats_add(struct nuvo_io_stats *stats, uint_fast64_t size, uint_fast64_t latency)
{
    nuvo_mutex_lock(&stats->mutex);
    stats->count++;

    stats->size_sum += size;
    stats->latency_sum += latency;
    stats->latency_sum_squared += ((double)latency) * (double)latency;

    stats->size_hist[nuvo_io_stats_get_size_bin(size)]++;
    stats->latency_hist[nuvo_io_stats_get_lat_bin(latency)]++;
    nuvo_mutex_unlock(&stats->mutex);
}

void nuvo_io_stats_get_snapshot(struct nuvo_io_stats *stats, struct nuvo_io_stats_snap *snap, bool clear)
{
    nuvo_mutex_lock(&stats->mutex);

    snap->count = stats->count;
    snap->size_total = stats->size_sum;
    snap->latency_mean = snap->count == 0 ? 0.0 : (double)stats->latency_sum / (double)stats->count;
    snap->latency_stdev = snap->count == 0 ? 0.0 : sqrt(fabs(stats->latency_sum_squared / (double)snap->count - snap->latency_mean * snap->latency_mean));
    memcpy(snap->size_hist, stats->size_hist, sizeof stats->size_hist);
    memcpy(snap->latency_hist, stats->latency_hist, sizeof stats->latency_hist);
    uuid_copy(snap->series_uuid, stats->series_uuid);

    if (clear)
    {
        nuvo_io_stats_clear_locked(stats);
    }

    nuvo_mutex_unlock(&stats->mutex);
}

void nuvo_io_stats_size_hist_range(uint_fast8_t bin, uint_fast64_t *start, uint_fast64_t *end)
{
    *start = (1ull << bin);
    *end = (1ull << (bin + 1)) - 1ull;

    if (bin == 0)
    {
        (*start)--;
    }
}

void nuvo_io_stats_latency_hist_range(uint_fast16_t bin, uint_fast64_t *start, uint_fast64_t *end)
{
    unsigned      pow_bits = bin >> NUVO_STATS_LAT_SUB_BITS;
    unsigned      shift_bits = pow_bits == 0 ? 0 : pow_bits - 1;
    unsigned      lin_bits = bin & ((1ull << NUVO_STATS_LAT_SUB_BITS) - 1ull);
    uint_fast64_t sig_bits = pow_bits == 0 ? lin_bits : ((1ull << NUVO_STATS_LAT_SUB_BITS) | lin_bits);

    *start = sig_bits << shift_bits;
    *end = ((sig_bits + 1) << shift_bits) - 1ull;
}
