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
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <uuid/uuid.h>

#include "nuvo_lock.h"

#define NUVO_STATS_SIZE_BINS       32

#define NUVO_STATS_LAT_BITS        32
#define NUVO_STATS_LAT_SUB_BITS    2
#define NUVO_STATS_LAT_BINS        (NUVO_STATS_LAT_BITS * (1ull << NUVO_STATS_LAT_SUB_BITS))

struct nuvo_io_stats_snap {
    uint_fast64_t  count;
    uint_fast64_t  size_total;
    uint_fast64_t *size_hist;
    double         latency_mean;
    double         latency_stdev;
    uint_fast64_t *latency_hist;
    uuid_t         series_uuid;
};

struct nuvo_io_stats {
    nuvo_mutex_t  mutex;

    uint_fast64_t count;
    uint_fast64_t size_sum;
    uint_fast64_t size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t latency_sum;
    double        latency_sum_squared;
    uint_fast64_t latency_hist[NUVO_STATS_LAT_BINS];
    uuid_t        series_uuid;
};

/**
 * \brief Initialize a struct nuvo_io_stats.
 *
 * This function performs any necessary initialization for a
 * struct nuvo_io_stats object.  This should be called on any
 * struct nuvo_io_stats object before it is used by any other function.
 *
 * \param stats A pointer to the struct nuvo_io_stats object to initialize.
 * \returns On success either 0 or greater value is returned.  On failure,
 * a negative value is returned.
 */
int_fast64_t nuvo_io_stats_init(struct nuvo_io_stats *stats);

/**
 * \brief Clean-up a struct nuvo_io_stats.
 *
 * This function performs any necessary clean-up for a struct nuvo_io_stats
 * object.  This function should be invoked on any struct nuvo_io_stats object
 * after it is finished being used.
 *
 * \param stats A pointer to the struct nuvo_io_stats object to initialize.
 */
void nuvo_io_stats_destroy(struct nuvo_io_stats *stats);

/**
 * \brief Clear all event information stored in a struct nuvo_io_stats object.
 *
 * This function clears all event information stored in a struct nuvo_io_stats
 * object.  After this call, the struct nuvo_io_stats object will be as if no
 * events had ever been added to it.
 *
 * \param stats A pointer to the struct nuvo_io_stats object to clear.
 */
void nuvo_io_stats_clear(struct nuvo_io_stats *stats);

/**
 * \brief Add an event to the struct nuvo_io_stats.
 *
 * This function allows the caller to update the statistics data stored in the
 * struct nuvo_io_stats object to include a new event.  This will place the
 * event into the histograms and update data for calculating the means and
 * standard deviations.
 *
 * \param stats A pointer to the struct nuvo_io_stats object to update.
 * \param size The size of the IO performed in bytes.
 * \param latency The latency of the IO performed.
 */
void nuvo_io_stats_add(struct nuvo_io_stats *stats, uint_fast64_t size, uint_fast64_t latency);

/**
 * \brief Atomically get a snap shot of all stats in a struct nuvo_io_stats
 * object and optionally clear it.
 *
 * This function atomically gets a snapshot of the current stats represented
 * by a struct nuvo_io_stats object and optionally clears the object.
 *
 * \param stats A pointer to the struct nuvo_io_stats object.
 * \param snap A pointer to the struct nuvo_io_stats_snap object to populate.
 * \param clear Indicates where the function should clear \p stats populating
 * the stats snapshot.
 */
void nuvo_io_stats_get_snapshot(struct nuvo_io_stats *stats, struct nuvo_io_stats_snap *snap, bool clear);

/**
 * \brief Get the size range of a size histogram bin.
 *
 * This function returns the range of sizes (inclusive) that would be counted
 * into the size histogram bin indexed by \p bin.
 *
 * \param bin The index of the size histogram bin to retrieve.
 * \param start A pointer to return the minimum value that is counted in the bin.
 * \param end A pointer to return the maximum value that is counted in the bin.
 */
void nuvo_io_stats_size_hist_range(uint_fast8_t bin, uint_fast64_t *start, uint_fast64_t *end);

/**
 * \brief Get the latency range of a latency histogram bin.
 *
 * This function returns the range of latencies (inclusive) that would be
 * counted into the size histogram bin indexed by \p bin.
 *
 * \param bin The index of the latency histogram bin to retrieve.
 * \param start A pointer to return the minimum value that is counted in the bin.
 * \param end A pointer to return the maximum value that is counted in the bin.
 */
void nuvo_io_stats_latency_hist_range(uint_fast16_t bin, uint_fast64_t *start, uint_fast64_t *end);
