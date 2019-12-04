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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lun.h"
#include "nuvo_vol_series.h"
#include "map_priv.h"
#include "nuvo_lock.h"
#include "nuvo_range_lock.h"
#include "nuvo_ck_assert.h"
#include "map_diff.h"
#include "fake_rl.h"
#include "map_ut.h"

#define NUVO_MAP_TEST_PARCELS           128
#define NUVO_MAP_TEST_PARCEL_BLOCKS     256
#define NUVO_MAP_TEST_SEGMENT_BLOCKS    64
#define NUVO_MAP_TEST_SEGMENTS          (NUVO_MAP_TEST_PARCEL_BLOCKS * NUVO_MAP_TEST_PARCELS / NUVO_MAP_TEST_SEGMENT_BLOCKS)

#define NUVO_MAP_TEST_PIDX_OFFSET       281
#define NUVO_MAP_TEST_PD_OFFSET         499

// TODO - Changed because it was overflowing when I changed to number of map cleaning groups form 4 to 6
#define NUVO_MAP_TEST_MAP_MEMORY        (1ull << 23)

static char last_test_name[128];

static uint8_t *parcel_bufs[NUVO_MAP_TEST_PARCELS][NUVO_MAP_TEST_PARCEL_BLOCKS];
static uint16_t segment_usage[NUVO_MAP_TEST_SEGMENTS];
static uint16_t segment_pin[NUVO_MAP_TEST_SEGMENTS];

static uint32_t alloc_counter;

static struct nuvo_io_request io_reqs[512];
static struct nuvo_dlist io_req_freelist;

static uint64_t log_seq;
static uint64_t log_seq_completed;

static struct nuvo_dlist log_req_list;
static nuvo_mutex_t log_mutex;

struct nuvo_vol my_vol;
static struct nuvo_vol replay_vol;

static struct nuvo_lun *log_replay_lun = NULL;

static nuvo_mutex_t completion_list_mutex;
static nuvo_cond_t completion_list_cond;
static struct nuvo_dlist completion_list;
static pthread_t completion_tid;
static bool completion_th_running = false;
// set use_completion_th to false run tests single threaded
static bool use_completion_th = true;

extern inline bool nuvo_logger_is_running(struct nuvo_logger *logger);

static void __nuvo_map_test_intermediate_shadow();
static void __nuvo_map_test_percolate_and_cp();

nuvo_cond_t cp_cond;
nuvo_mutex_t cp_mutex;
struct nuvo_lun *g_lun = NULL;

void nuvo_space_trigger_cp(struct nuvo_space_vol *space)
{
    struct nuvo_vol * vol = nuvo_containing_object(space, struct nuvo_vol, log_volume.space);
    struct nuvo_map_entry cp_map_entry;

    //TODO do a fake cp here?
    // doing a real cp for now
    // TODO change interface of this to return an array of cp map entries
    if (g_lun)
    {
        g_lun->mfl_state = NUVO_LUN_MFL_CP_IN_PROGRESS;
        g_lun = NULL;
    }
    nuvo_return_t ret = nuvo_map_checkpoint_sync(vol, &cp_map_entry);
    NUVO_ASSERT(!ret);
    nuvo_mutex_lock(&cp_mutex);
    nuvo_mutex_unlock(&cp_mutex);
    nuvo_cond_signal(&cp_cond);
}

struct nuvo_lun *
nuvo_get_next_lun_to_delete(struct nuvo_vol *vol)
{
    (void)vol;
    struct nuvo_lun *lun = NULL;

    if (g_lun)
    {
        lun = g_lun;
    }
    return lun;
}

void *completion_th(__attribute__((unused)) void *arg)
{
    struct nuvo_log_request *log_req;
    while (completion_th_running)
    {
        nuvo_mutex_lock(&completion_list_mutex);
        log_req = nuvo_dlist_remove_head_object(&completion_list, struct nuvo_log_request, list_node);
        if (!log_req)
        {
            nuvo_cond_wait(&completion_list_cond, &completion_list_mutex);
            nuvo_mutex_unlock(&completion_list_mutex);
            continue;
        }
        else
        {
            nuvo_mutex_unlock(&completion_list_mutex);
            log_req->callback(log_req);
        }
    }
    return NULL;
}
struct nuvo_lun * gsnap_lun = NULL;
/* mock up lun allocator/manager */
struct lun_list_t
{
    struct nuvo_lun lun_list[64];
    int lun_cnt;
    int lun_index;
};
// set use_completion_th to false run tests single threaded

struct lun_list_t luns;
/* fake function to make cp of snap_lun work
  since we dont want to bring in the lun.* files
 the snap lun would be returned as the next lun in CP
*/

struct nuvo_lun * nuvo_lun_get_next(struct nuvo_vol *vol, struct nuvo_lun  *lun, bool pin)
{
    (void)lun;
    (void)pin;

    struct nuvo_lun * rlun = NULL;

    for ( ; luns.lun_index < luns.lun_cnt; luns.lun_index++)
    {
        rlun = &luns.lun_list[luns.lun_index];

        if (rlun->vol != vol)
        {
            continue;
        }
        luns.lun_index++;
        return rlun;
    }

    luns.lun_index = 0;
    return NULL;
}
// return youngest lun
struct nuvo_lun * nuvo_get_peer_cow_lun(struct nuvo_vol *vol, bool pin)
{
    (void)vol;
    (void)pin;
    return &luns.lun_list[luns.lun_cnt - 1];
}

bool nuvo_is_peer_cow_lun(struct nuvo_lun *lun)
{
    return (lun == &luns.lun_list[luns.lun_cnt - 1]);
}

struct nuvo_lun *nuvo_get_next_younger_lun(struct nuvo_lun *lun, bool pin)
{
    (void)pin;
    for (int i = 0; i < luns.lun_cnt; i++)
    {
        if (lun != &luns.lun_list[i])
        {
            if (i == (luns.lun_cnt - 1))
            {
                return (&luns.lun_list[i + 1]);
            }
            else
            {
                return ((void *)0);
            }
        }
    }
    return ((void *)0);
}

struct nuvo_lun *
nuvo_get_lun_by_snapid(struct nuvo_vol *vol, uint64_t snap_id, bool pin)
{
    (void) pin;
    if (snap_id == NUVO_MFST_ACTIVE_LUN_SNAPID)
    {
        NUVO_ASSERT(vol->log_volume.lun.vol == vol);
        return &vol->log_volume.lun;
    }

    for (int i = 0; i < luns.lun_cnt; i++)
    {
        struct nuvo_lun * rlun = &luns.lun_list[i];
        if ((rlun->vol == vol) && (rlun->snap_id == snap_id))
        {
            return rlun;
        }
    }
    return NULL;
}

void lun_dealloc_all()
{
    memset(&luns, 0, sizeof(struct lun_list_t));
    luns.lun_index = 0;
    luns.lun_cnt = 0;
}

void
lun_close_all()
{
    for (int i = 0; i < luns.lun_cnt; i++)
    {
        nuvo_map_lun_close(&luns.lun_list[i], &luns.lun_list[i].root_map_entry);
    }
}

struct nuvo_lun *lun_alloc()
{
    NUVO_ASSERT(luns.lun_cnt < 64);
    struct nuvo_lun * lun =  &luns.lun_list[luns.lun_cnt++];
    memset(lun, 0, sizeof(*lun));
    return lun;
}
struct nuvo_lun *nuvo_lun_alloc(struct nuvo_vol *vol, bool pin)
{
    (void)pin;
    struct nuvo_lun * lun = lun_alloc();
    lun->vol = vol;
    nuvo_mutex_init(&lun->mutex);
    return lun;
}
void map_de_batch_print(struct map_de * map_de_batch , uint32_t batch_size)
{
    for (uint32_t i = 0; i< batch_size; i++)
    {
        NUVO_ERROR_PRINT("i:%d offset:%llu len:%llu\n",
                    i, map_de_batch[i].start_offset, map_de_batch[i].length);
    }

}
void mdr_print(struct nuvo_map_diff_request *mdr)
{
    NUVO_ERROR_PRINT("batch size:%d\n", mdr->batch_size);

    for (uint32_t i = 0; i< mdr->batch_size; i++)
    {
        NUVO_ERROR_PRINT("i:%d offset:%llu len:%llu\n",
                    i, mdr->map_de_batch[i].start_offset, mdr->map_de_batch[i].length);
    }
    NUVO_ERROR_PRINT("\n");
}

uint64_t get_segment_usage()
{
    uint32_t usage = 0;
    for(int i = 0; i < NUVO_MAP_TEST_SEGMENTS; i++)
    {
        if (segment_usage[i] || segment_pin[i])
        {
            NUVO_ERROR_PRINT("seg %d use:%d pin:%d", i, segment_usage[i], segment_pin[i]);
            usage += segment_usage[i];
        }
    }
    NUVO_ERROR_PRINT("total usage :%lu ", usage);
    return usage;
}

void nuvo_map_test_setup(void)
{
    log_seq = 0;
    log_seq_completed = 0;
    alloc_counter = 0;
    for(int i = 0; i < NUVO_MAP_TEST_PARCELS; i++)
    {
        parcel_bufs[i][0] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_MAP_TEST_PARCEL_BLOCKS * NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(parcel_bufs[i][0], NULL);
        for(int j = 1; j < NUVO_MAP_TEST_PARCEL_BLOCKS; j++)
        {
            parcel_bufs[i][j] = parcel_bufs[i][j-1] + NUVO_BLOCK_SIZE;
        }
    }

    for(int i = 0; i < NUVO_MAP_TEST_SEGMENTS; i++)
    {
        segment_usage[i] = 0;
        segment_pin[i] = 0;
    }

    nuvo_dlist_init(&io_req_freelist);
    for(unsigned i = 0; i < NUVO_ARRAY_LENGTH(io_reqs); i++)
    {
        nuvo_dlnode_init(&io_reqs[i].list_node);
        nuvo_dlist_insert_head(&io_req_freelist, &io_reqs[i].list_node);
    }

    nuvo_dlist_init(&log_req_list);
    nuvo_mutex_init(&log_mutex);

    if (use_completion_th)
    {
        nuvo_mutex_init(&completion_list_mutex);
        nuvo_cond_init(&completion_list_cond);
        nuvo_dlist_init(&completion_list);
        completion_th_running = true;
        (void) pthread_create(&completion_tid, NULL, &completion_th, NULL);
    }

    int_fast64_t ret = nuvo_map_init_mem(NUVO_MAP_TEST_MAP_MEMORY);
    ck_assert_int_ge(ret, 0);

    my_vol.log_volume.logger.state = NUVO_LOG_STATE_RUNNING;
    my_vol.snap_generation = 0;
    replay_vol.log_volume.logger.state = NUVO_LOG_STATE_REPLAY;

    nuvo_map_vol_state_init(&my_vol.log_volume.map_state, &my_vol);
    nuvo_map_vol_state_init(&replay_vol.log_volume.map_state, &replay_vol);
}

void nuvo_map_test_teardown(void)
{
    NUVO_ERROR_PRINT("Tear down %s", last_test_name);
    NUVO_ASSERT(log_seq == log_seq_completed);
    nuvo_map_shutdown();

    for(int i = 0; i < NUVO_MAP_TEST_PARCELS; i++)
    {
        free(parcel_bufs[i][0]);
    }

    if (use_completion_th)
    {
        nuvo_mutex_lock(&completion_list_mutex);
        completion_th_running = false;
        nuvo_cond_signal(&completion_list_cond);
        nuvo_mutex_unlock(&completion_list_mutex);
        pthread_join(completion_tid, NULL);
        nuvo_mutex_destroy(&completion_list_mutex);
        nuvo_cond_destroy(&completion_list_cond);
    }
}

bool nuvo_mfst_slog_filling(struct nuvo_vol *vol)
{
    (void)vol;
    return false;
}

void nuvo_mfst_segment_use_blks(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry)
{
    (void)mfst;
    for(unsigned i = 0; i < num; i++)
    {
        if (map_entry[i].type == NUVO_ME_MEDIA)
        {
            ck_assert_uint_ge(map_entry[i].media_addr.parcel_index, NUVO_MAP_TEST_PIDX_OFFSET);
            ck_assert_uint_lt(map_entry[i].media_addr.block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);

            unsigned seg_idx =
            (   (map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET)
              * NUVO_MAP_TEST_PARCEL_BLOCKS + map_entry[i].media_addr.block_offset
            ) / NUVO_MAP_TEST_SEGMENT_BLOCKS;

            segment_usage[seg_idx]++;
        }
    }
}

void nuvo_mfst_segment_free_blks_int(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry,
        bool cow_write)
{
    (void)mfst;
    for(unsigned i = 0; i < num; i++)
    {
        if ((map_entry[i].type == NUVO_ME_MEDIA) && (!cow_write || map_entry[i].cow == NUVO_MAP_ENTRY_NONE))
        {
            ck_assert_uint_ge(map_entry[i].media_addr.parcel_index, NUVO_MAP_TEST_PIDX_OFFSET);
            ck_assert_uint_lt(map_entry[i].media_addr.block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);

            unsigned seg_idx =
            (   (map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET)
              * NUVO_MAP_TEST_PARCEL_BLOCKS + map_entry[i].media_addr.block_offset
            ) / NUVO_MAP_TEST_SEGMENT_BLOCKS;

            ck_assert_uint_gt(segment_usage[seg_idx], 0);
            segment_usage[seg_idx]--;
        }
    }
}

void nuvo_mfst_segment_free_blks_for_cow(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_segment_free_blks_int(mfst, num, map_entry, true);
}
void nuvo_mfst_segment_free_blks(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry)
{
    nuvo_mfst_segment_free_blks_int(mfst, num, map_entry, false);

}

void nuvo_mfst_pin(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry)
{
    (void)mfst;
    for(unsigned i = 0; i < num; i++)
    {
        if (map_entry[i].type == NUVO_ME_MEDIA)
        {
            ck_assert_uint_ge(map_entry[i].media_addr.parcel_index, NUVO_MAP_TEST_PIDX_OFFSET);
            ck_assert_uint_lt(map_entry[i].media_addr.block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);

            unsigned seg_idx =
            (   (map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET)
              * NUVO_MAP_TEST_PARCEL_BLOCKS + map_entry[i].media_addr.block_offset
            ) / NUVO_MAP_TEST_SEGMENT_BLOCKS;

            segment_pin[seg_idx]++;
        }
    }
}
int_fast64_t nuvo_mfst_pin_open(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry,
        uint_fast32_t *parcel_descs)
{
    (void)mfst;
    for(unsigned i = 0; i < num; i++)
    {
        if (map_entry[i].type == NUVO_ME_MEDIA)
        {
            ck_assert_uint_ge(map_entry[i].media_addr.parcel_index, NUVO_MAP_TEST_PIDX_OFFSET);
            ck_assert_uint_lt(map_entry[i].media_addr.block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);

            unsigned seg_idx =
            (   (map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET)
              * NUVO_MAP_TEST_PARCEL_BLOCKS + map_entry[i].media_addr.block_offset
            ) / NUVO_MAP_TEST_SEGMENT_BLOCKS;

            parcel_descs[i] = map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET + NUVO_MAP_TEST_PD_OFFSET;
            segment_pin[seg_idx]++;
        }
    }
    return 0;
}
int_fast64_t nuvo_mfst_open(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry,
        uint_fast32_t *parcel_descs)
{
    (void)mfst;
    for(unsigned i = 0; i < num; i++)
    {
        if (map_entry[i].type == NUVO_ME_MEDIA)
        {
            ck_assert_uint_ge(map_entry[i].media_addr.parcel_index, NUVO_MAP_TEST_PIDX_OFFSET);
            ck_assert_uint_lt(map_entry[i].media_addr.block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);

            parcel_descs[i] = map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET + NUVO_MAP_TEST_PD_OFFSET;
        }
    }
    return 0;
}
void nuvo_mfst_open_async(struct nuvo_mfst_map_open *pin_req)
{
    pin_req->status = nuvo_mfst_open(pin_req->mfst, pin_req->num_map_entries, pin_req->map_entry, pin_req->pds);
    pin_req->callback(pin_req);
}
void nuvo_mfst_unpin(struct nuvo_mfst *mfst,
        uint_fast32_t num,
        const struct nuvo_map_entry *map_entry)
{
    (void)mfst;
    for(unsigned i = 0; i < num; i++)
    {
        if (map_entry[i].type == NUVO_ME_MEDIA)
        {
            ck_assert_uint_ge(map_entry[i].media_addr.parcel_index, NUVO_MAP_TEST_PIDX_OFFSET);
            ck_assert_uint_lt(map_entry[i].media_addr.block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);

            unsigned seg_idx =
            (   (map_entry[i].media_addr.parcel_index - NUVO_MAP_TEST_PIDX_OFFSET)
              * NUVO_MAP_TEST_PARCEL_BLOCKS + map_entry[i].media_addr.block_offset
            ) / NUVO_MAP_TEST_SEGMENT_BLOCKS;

            ck_assert_uint_gt(segment_pin[seg_idx], 0);
            segment_pin[seg_idx]--;
        }
    }
}

struct nuvo_io_request *nuvo_pr_sync_client_req_alloc(nuvo_mutex_t *sync_signal)
{
    (void)sync_signal;

    struct nuvo_io_request *req = nuvo_dlist_remove_head_object(&io_req_freelist, struct nuvo_io_request, list_node);

    ck_assert_ptr_ne(req, NULL);

    return req;
}
void nuvo_pr_client_req_alloc_cb(struct nuvo_pr_req_alloc *alloc)
{
    nuvo_mutex_t sync_signal;
    nuvo_mutex_init(&sync_signal);
    alloc->req = nuvo_pr_sync_client_req_alloc(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    alloc->callback(alloc);
}
void nuvo_pr_sync_submit(struct nuvo_io_request *req, nuvo_mutex_t *sync_signal)
{
    // validate that req is in range, and then perform the IO
    ck_assert(req->operation == NUVO_OP_READ || req->operation == NUVO_OP_WRITE);
    uint64_t my_parcel_index = req->rw.parcel_desc - NUVO_MAP_TEST_PD_OFFSET;
    ck_assert_uint_lt(my_parcel_index, NUVO_MAP_TEST_PARCELS);
    uint64_t my_block_offset = req->rw.block_offset;
    ck_assert_uint_lt(my_block_offset, NUVO_MAP_TEST_PARCEL_BLOCKS);
    ck_assert_uint_le(my_block_offset + req->rw.block_count, NUVO_MAP_TEST_PARCEL_BLOCKS);

    if (req->operation == NUVO_OP_READ)
    {
        for(unsigned i = 0; i < req->rw.block_count; i++)
        {
            ck_assert_uint_eq(req->rw.iovecs[i].iov_len, NUVO_BLOCK_SIZE);
            memcpy(req->rw.iovecs[i].iov_base, parcel_bufs[my_parcel_index][my_block_offset + i], NUVO_BLOCK_SIZE);
            req->rw.block_hashes[i] = nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
        }
    }
    else if (req->operation == NUVO_OP_WRITE)
    {
        for(unsigned i = 0; i < req->rw.block_count; i++)
        {
            ck_assert_uint_eq(req->rw.iovecs[i].iov_len, NUVO_BLOCK_SIZE);
            memcpy(parcel_bufs[my_parcel_index][my_block_offset + i], req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
        }
    }

    req->status = 0;

    (void)sync_signal;
}
void nuvo_pr_submit(struct nuvo_dlist *list)
{
    struct nuvo_io_request *io_req;
    while ((io_req = nuvo_dlist_remove_head_object(list, struct nuvo_io_request, list_node)) != NULL)
    {
        nuvo_mutex_t sync_signal;
        nuvo_mutex_init(&sync_signal);
        nuvo_pr_sync_submit(io_req, &sync_signal);
        nuvo_mutex_destroy(&sync_signal);
        io_req->callback(io_req);
    }
}
extern inline void nuvo_pr_submit_req(struct nuvo_io_request *req);

void nuvo_pr_client_req_free(struct nuvo_io_request *req)
{
    nuvo_dlist_insert_head(&io_req_freelist, &req->list_node);
}

bool log_is_snap_op(int op)
{
   return ((op == NUVO_LOG_OP_CREATE_SNAP) ||
           (op == NUVO_LOG_OP_DELETE_SNAP));
}

void nuvo_log_submit(struct nuvo_log_request *log_req)
{
   ck_assert_ptr_ne(log_req, NULL);

   if (log_is_snap_op(log_req->operation))
   {
       goto log_blocks_processing_done;
   }

    // alloc linearly from the parcel bufs we have and write data to them
    for(unsigned i = 0; i < log_req->block_count; i++)
    {
        uint64_t const_val;
        int is_cv;
        nuvo_hash_t hash = nuvo_hash_cv(log_req->log_io_blocks[i].data, NUVO_BLOCK_SIZE, &const_val, &is_cv);

#if 0
        if  (log_req->log_io_blocks[i].map_is_zero && log_req->operation == NUVO_LOG_OP_MAP)
        {
            NUVO_ERROR_PRINT("const_val :%d is_cv:%d", const_val, is_cv);
        }
#endif

        memset(&log_req->nuvo_map_entries[i], 0, sizeof(log_req->nuvo_map_entries[i]));
        if (is_cv && log_req->operation == NUVO_LOG_OP_DATA)
        {
            log_req->nuvo_map_entries[i].cow = 0;
            log_req->nuvo_map_entries[i].type = NUVO_ME_CONST;
            log_req->nuvo_map_entries[i].media_addr.parcel_index = -1;
            log_req->nuvo_map_entries[i].media_addr.block_offset = -1;
            log_req->nuvo_map_entries[i].pattern = const_val;
        }
        else if  (log_req->operation == NUVO_LOG_OP_MAP && log_req->log_io_blocks[i].map_is_zero)
        {
            log_req->nuvo_map_entries[i].cow = 0;
            log_req->nuvo_map_entries[i].type = NUVO_ME_CONST;
            log_req->nuvo_map_entries[i].media_addr.parcel_index = NUVO_LOG_MEDIA_ADDR_FREE;
            log_req->nuvo_map_entries[i].media_addr.block_offset = NUVO_LOG_BLOCK_OFFSET_FREE;
            log_req->nuvo_map_entries[i].pattern = NUVO_MAP_IS_ZERO_PATTERN;

        }
        else
        {
            ck_assert_uint_lt(alloc_counter, NUVO_MAP_TEST_PARCELS * NUVO_MAP_TEST_PARCEL_BLOCKS);
            uint64_t my_block = alloc_counter++;
            uint64_t my_parcel_index = my_block / NUVO_MAP_TEST_PARCEL_BLOCKS;
            uint64_t my_block_offset = my_block % NUVO_MAP_TEST_PARCEL_BLOCKS;

            log_req->nuvo_map_entries[i].cow = 0;
            log_req->nuvo_map_entries[i].type = NUVO_ME_MEDIA;
            log_req->nuvo_map_entries[i].media_addr.parcel_index = my_parcel_index + NUVO_MAP_TEST_PIDX_OFFSET;
            log_req->nuvo_map_entries[i].media_addr.block_offset = my_block_offset;
            log_req->nuvo_map_entries[i].hash = hash;
            // copy the data
            memcpy(parcel_bufs[my_parcel_index][my_block_offset],
                log_req->log_io_blocks[i].data, NUVO_BLOCK_SIZE);
        }
    }

log_blocks_processing_done:

    log_req->status = 0;

    bool do_callback = false;

    nuvo_mutex_lock(&log_mutex);
    // assign sequence number
    log_req->sequence_tag.uint = log_seq++;

    // if we're at the head of the sequence, do callback.
    // otherwise, put ourselves on the log req list
    ck_assert_uint_ge(log_req->sequence_tag.uint, log_seq_completed);
    if (log_req->sequence_tag.uint == log_seq_completed)
    {
        if (use_completion_th)
        {
            nuvo_mutex_lock(&completion_list_mutex);
            nuvo_dlist_insert_tail(&completion_list, &log_req->list_node);
            nuvo_cond_signal(&completion_list_cond);
            nuvo_mutex_unlock(&completion_list_mutex);
        }
        else
        {
            do_callback = true;
        }
    }
    else
    {
        nuvo_dlist_insert_tail(&log_req_list, &log_req->list_node);
    }
    nuvo_mutex_unlock(&log_mutex);

    if (!use_completion_th && do_callback)
    {
        log_req->callback(log_req);
    }
}
void map_snap_op_fake_replay(struct nuvo_log_request *log_req)
{
    NUVO_ASSERT((log_req->operation == NUVO_LOG_OP_CREATE_SNAP) ||
            (log_req->operation == NUVO_LOG_OP_DELETE_SNAP));

    struct nuvo_vol *vol  = log_req->vs_ptr;
    uuid_t * pit_uuid = &log_req->pit_uuid;
    uint32_t pit_id   = log_req->pit_id;

    if (log_req->operation == NUVO_LOG_OP_CREATE_SNAP)
    {
        NUVO_LOG(map, 0, "create snap replay lun(%d)", pit_id);
        struct nuvo_lun * lun = nuvo_map_create_snap(vol, *pit_uuid);
        NUVO_ASSERT(lun);
        NUVO_ASSERT(lun->snap_id == pit_id);
    }
    else
    {
        NUVO_LOG(map, 0, "delete lun replay lun(%d)", pit_id);
        struct nuvo_lun *lun =
            nuvo_get_lun_by_snapid(vol, pit_id, false);
        nuvo_return_t ret =  map_ut_delete_lun_int(lun);
        NUVO_ASSERT(!ret);
    }
}

int in_replay = 0;

void nuvo_log_ack_sno(struct nuvo_log_request *log_req)
{
    struct nuvo_dlist local_comp_list;

    // only do the real work if we're not in replay
    if (in_replay == 0)
    {
        nuvo_dlist_init(&local_comp_list);
        nuvo_mutex_lock(&log_mutex);
        ck_assert_uint_eq(log_req->sequence_tag.uint, log_seq_completed);
        log_seq_completed++;

        struct nuvo_log_request *req;
        while((req = nuvo_dlist_get_head_object(&log_req_list, struct nuvo_log_request, list_node)) != NULL)
        {
            if (req->sequence_tag.uint <= log_seq_completed)
            {
                nuvo_dlist_remove(&req->list_node);
                if (use_completion_th)
                {
                    nuvo_mutex_lock(&completion_list_mutex);
                    nuvo_dlist_insert_tail(&completion_list, &req->list_node);
                    nuvo_cond_signal(&completion_list_cond);
                    nuvo_mutex_unlock(&completion_list_mutex);
                }
                else
                {
                    nuvo_dlist_insert_tail(&local_comp_list, &req->list_node);
                }
            }
            else
            {
                break;
            }
        }
        nuvo_mutex_unlock(&log_mutex);

        if (!use_completion_th)
        {
            while((req = nuvo_dlist_remove_head_object(&local_comp_list, struct nuvo_log_request, list_node)) != NULL)
            {
                req->callback(req);
            }
        }

        // lastly, if there is a replay lun, run it through replay
        if (log_replay_lun != NULL)
        {
            in_replay = 1;
            log_req->vs_ptr = log_replay_lun->vol;

            if (log_is_snap_op(log_req->operation))
            {
                map_snap_op_fake_replay(log_req);
            }
            else
            {
                nuvo_map_replay(log_req);
            }
            in_replay = 0;
        }
    }
}

void nuvo_map_test_log_cb(struct nuvo_log_request *log_req)
{
    nuvo_mutex_t *mutex = (nuvo_mutex_t*)log_req->tag.ptr;

    nuvo_mutex_unlock(mutex);
}

START_TEST(nuvo_map_test_init)
{
}
END_TEST

START_TEST(nuvo_map_test_mixed_clean_insert_remove)
{
    struct nuvo_map_track *map_a, *map_b, *map_c, *map_d;
    struct nuvo_dlist comp_list;
    nuvo_dlist_init(&comp_list);

    nuvo_mutex_lock(&nuvo_map->list_mutex);
    // check that maps are correctly being put and removed from the mixed and clean lists
    ck_assert_int_eq(nuvo_map->mixed_count, 0);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count);
    ck_assert_int_eq(nuvo_map->pinned_count, 0);

    // check that the mixed list is empty
    map_a = nuvo_dlist_get_head_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_a, NULL);

    // get a map from the clean list
    map_a = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_ne(map_a, NULL);

    nuvo_map_clean_remove(map_a);
    ck_assert_ptr_eq(map_a->list_node.next, NULL);
    ck_assert_ptr_eq(map_a->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-1);

    map_a->vol = &my_vol;
    map_a->state = NUVO_MAP_MIXED_LIST;
    nuvo_map_mixed_insert(map_a, &comp_list);
    ck_assert_int_eq(nuvo_map->mixed_count, 1);
    map_b = nuvo_dlist_get_head_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_b, map_a);

    // put another on the mixed list
    map_b = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_ne(map_b, NULL);

    nuvo_map_clean_remove(map_b);
    ck_assert_ptr_eq(map_b->list_node.next, NULL);
    ck_assert_ptr_eq(map_b->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-2);

    map_b->vol = &my_vol;
    map_b->state = NUVO_MAP_MIXED_LIST;
    nuvo_map_mixed_insert(map_b, &comp_list);
    ck_assert_int_eq(nuvo_map->mixed_count, 2);
    map_c = nuvo_dlist_get_head_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_c, map_b);

    // put another on the mixed list
    map_c = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_ne(map_c, NULL);

    nuvo_map_clean_remove(map_c);
    ck_assert_ptr_eq(map_c->list_node.next, NULL);
    ck_assert_ptr_eq(map_c->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-3);

    map_c->vol = &my_vol;
    map_c->state = NUVO_MAP_MIXED_LIST;
    nuvo_map_mixed_insert(map_c, &comp_list);
    ck_assert_int_eq(nuvo_map->mixed_count, 3);
    map_d = nuvo_dlist_get_head_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_d, map_c);

    // remove the middle node of the mixed list
    nuvo_map_mixed_remove(map_b);
    ck_assert_ptr_eq(map_b->list_node.next, NULL);
    ck_assert_ptr_eq(map_b->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->mixed_count, 2);

    // put on the head of the clean list
    map_b->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_noalloc(map_b);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-2);
    map_d = nuvo_dlist_get_head_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_b, map_d);

    // remove the head of the mixed list
    nuvo_map_mixed_remove(map_c);
    ck_assert_ptr_eq(map_c->list_node.next, NULL);
    ck_assert_ptr_eq(map_c->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->mixed_count, 1);

    // put on the tail of the clean list
    map_c->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_tail_noalloc(map_c);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-1);
    map_d = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_c, map_d);

    // remove the last node on the mixed list
    nuvo_map_mixed_remove(map_a);
    ck_assert_ptr_eq(map_a->list_node.next, NULL);
    ck_assert_ptr_eq(map_a->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->mixed_count, 0);

    // put on the tail of the clean list
    map_a->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_tail_noalloc(map_a);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count);
    map_d = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_a, map_d);

    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    // since there are no outstanding alloc requests, nothing should have completed
    ck_assert_ptr_eq(nuvo_dlist_get_head(&comp_list), NULL);
}
END_TEST


START_TEST(nuvo_map_test_pinned_clean_insert_remove)
{
    struct nuvo_map_track *map_a, *map_b, *map_c, *map_d;
    struct nuvo_dlist comp_list;
    nuvo_dlist_init(&comp_list);
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    // check that maps are correctly being put and removed from the pinned and clean lists
    ck_assert_uint_eq(nuvo_map->pinned_count, 0);
    ck_assert_uint_eq(nuvo_map->clean_count, nuvo_map->map_table_count);
    ck_assert_uint_eq(nuvo_map->pinned_count, 0);

    // check that the pinned list is empty
    map_a = nuvo_dlist_get_head_object(&nuvo_map->pinned_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_a, NULL);

    // get a map from the clean list
    map_a = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_ne(map_a, NULL);

    nuvo_map_clean_remove(map_a);
    ck_assert_ptr_eq(map_a->list_node.next, NULL);
    ck_assert_ptr_eq(map_a->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-1);

    map_a->state = NUVO_MAP_PINNED;
    nuvo_map_pinned_insert(map_a);
    ck_assert_int_eq(nuvo_map->pinned_count, 1);
    map_b = nuvo_dlist_get_head_object(&nuvo_map->pinned_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_b, map_a);

    // put another on the pinned list
    map_b = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_ne(map_b, NULL);

    nuvo_map_clean_remove(map_b);
    ck_assert_ptr_eq(map_b->list_node.next, NULL);
    ck_assert_ptr_eq(map_b->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-2);

    map_b->state = NUVO_MAP_PINNED;
    nuvo_map_pinned_insert(map_b);
    ck_assert_int_eq(nuvo_map->pinned_count, 2);
    map_c = nuvo_dlist_get_head_object(&nuvo_map->pinned_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_c, map_b);

    // put another on the pinned list
    map_c = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_ne(map_c, NULL);

    nuvo_map_clean_remove(map_c);
    ck_assert_ptr_eq(map_c->list_node.next, NULL);
    ck_assert_ptr_eq(map_c->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-3);

    map_c->state = NUVO_MAP_PINNED;
    nuvo_map_pinned_insert(map_c);
    ck_assert_int_eq(nuvo_map->pinned_count, 3);
    map_d = nuvo_dlist_get_head_object(&nuvo_map->pinned_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_d, map_c);

    // remove the middle node of the pinned list
    nuvo_map_pinned_remove(map_b);
    ck_assert_ptr_eq(map_b->list_node.next, NULL);
    ck_assert_ptr_eq(map_b->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->pinned_count, 2);

    // put on the head of the clean list
    map_b->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_noalloc(map_b);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-2);
    map_d = nuvo_dlist_get_head_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_b, map_d);

    // remove the head of the pinned list
    nuvo_map_pinned_remove(map_c);
    ck_assert_ptr_eq(map_c->list_node.next, NULL);
    ck_assert_ptr_eq(map_c->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->pinned_count, 1);

    // put on the tail of the clean list
    map_c->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_tail_noalloc(map_c);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count-1);
    map_d = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_c, map_d);

    // remove the last node on the pinned list
    nuvo_map_pinned_remove(map_a);
    ck_assert_ptr_eq(map_a->list_node.next, NULL);
    ck_assert_ptr_eq(map_a->list_node.prev, NULL);
    ck_assert_int_eq(nuvo_map->pinned_count, 0);

    // put on the tail of the clean list
    map_a->state = NUVO_MAP_CLEAN_LIST;
    nuvo_map_clean_insert_tail_noalloc(map_a);
    ck_assert_int_eq(nuvo_map->clean_count, nuvo_map->map_table_count);
    map_d = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map_a, map_d);

    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    // since there are no outstanding alloc requests, nothing should have completed
    ck_assert_ptr_eq(nuvo_dlist_get_head(&comp_list), NULL);
}
END_TEST

START_TEST(nuvo_map_test_get_table_index)
{
    uint_fast32_t index;

    index = nuvo_map_get_table_index(0x0123456789abcdefull, 0);
    ck_assert_uint_eq(index, 0xef);
    index = nuvo_map_get_table_index(0x0123456789abcdefull, 1);
    ck_assert_uint_eq(index, 0xcd);
    index = nuvo_map_get_table_index(0x0123456789abcdefull, 2);
    ck_assert_uint_eq(index, 0xab);
    index = nuvo_map_get_table_index(0x0123456789abcdefull, 3);
    ck_assert_uint_eq(index, 0x89);
    index = nuvo_map_get_table_index(0x0123456789abcdefull, 4);
    ck_assert_uint_eq(index, 0x67);
    index = nuvo_map_get_table_index(0x0123456789abcdefull, 5);
    ck_assert_uint_eq(index, 0x45);
}
END_TEST

START_TEST(nuvo_map_test_get_base_offset)
{
    uint_fast64_t offset;

    offset = nuvo_map_get_base_offset(0x0123456789abcdefull, 0);
    ck_assert_uint_eq(offset, 0x0123456789abcd00ull);
    offset = nuvo_map_get_base_offset(0x0123456789abcdefull, 1);
    ck_assert_uint_eq(offset, 0x0123456789ab0000ull);
    offset = nuvo_map_get_base_offset(0x0123456789abcdefull, 2);
    ck_assert_uint_eq(offset, 0x0123456789000000ull);
    offset = nuvo_map_get_base_offset(0x0123456789abcdefull, 3);
    ck_assert_uint_eq(offset, 0x0123456700000000ull);
    offset = nuvo_map_get_base_offset(0x0123456789abcdefull, 4);
    ck_assert_uint_eq(offset, 0x0123450000000000ull);
    offset = nuvo_map_get_base_offset(0x0123456789abcdefull, 5);
    ck_assert_uint_eq(offset, 0x0123000000000000ull);
}
END_TEST

START_TEST(nuvo_map_test_balance)
{
    struct nuvo_dlist comp_list;
    nuvo_dlist_init(&comp_list);
    // goal of this test is to move clean maps from the clean lru and put
    // them on the mixed lru, causeing the balancing to kick in and move
    // them back onto the clean lru again
    nuvo_mutex_lock(&nuvo_map->list_mutex);

    struct nuvo_map_track *map;
    for(unsigned i = 0; i < nuvo_map->map_table_count*4; i++)
    {
        // pull a map from the clean list
        map = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
        ck_assert_ptr_ne(map, NULL);

        nuvo_map_clean_remove(map);
        ck_assert_ptr_eq(map->list_node.next, NULL);
        ck_assert_ptr_eq(map->list_node.prev, NULL);

        // put map on mixed list
        map->state = NUVO_MAP_MIXED_LIST;
        map->vol = &my_vol;
        nuvo_map_mixed_insert(map, &comp_list);
    }

    ck_assert_int_ge(nuvo_map->clean_count, nuvo_map->mixed_count);

    // now clean up by putting all maps on clean list
    while ((map = nuvo_dlist_get_tail_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node)) != NULL)
    {
        nuvo_map_mixed_remove(map);
        map->state = NUVO_MAP_CLEAN_LIST;
        nuvo_map_clean_insert_noalloc(map);
    }

    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    // since there are no outstanding alloc requests, nothing should have completed
    ck_assert_ptr_eq(nuvo_dlist_get_head(&comp_list), NULL);
}
END_TEST

START_TEST(nuvo_map_test_write_read)
{
    int_fast64_t ret;
    // goal is to do a basic write-then-read test
    // we must first setup a vol and a lun for that vol

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &log_signal;
    log_req.vs_ptr = &my_vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req.log_io_blocks[i].data = write_bufs[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;

    }
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map;
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);

    // verify that the segment usage was marked
    ck_assert_uint_eq(segment_usage[0], 32);

    // ack to the logger
    nuvo_log_ack_sno(&log_req);

    // map read and pin
    struct nuvo_map_entry map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    // verify that map returned exactly what we wrote earlier
    for(int i = 0; i < 32; i++)
    {
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].type,
                          map_entries[i].type);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[i].media_addr.parcel_index);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[i].media_addr.block_offset);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].pattern,
                          map_entries[i].pattern);
    }

    // verify segment pinning
    ck_assert_uint_eq(segment_pin[0], 32);

    // read the data and verify it is the same (just some test sanity checking)
    nuvo_mutex_t signal;
    nuvo_mutex_init(&signal);
    for(int i = 0; i < 32; i++)
    {
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&signal);
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = pds[i];
        req->rw.block_count = 1;
        req->rw.block_offset = map_entries[i].media_addr.block_offset;
        req->rw.iovecs[0].iov_base = read_bufs[i];
        req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;

        nuvo_pr_sync_submit(req, &signal);

        ck_assert_int_eq(memcmp(read_bufs[i], write_bufs[i], NUVO_BLOCK_SIZE), 0);

        nuvo_pr_client_req_free(req);
    }

    // read-release map data
    nuvo_map_read_release(my_lun, 32, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }

    // we're done, clean up the maps
    nuvo_map_lun_close(my_lun, &root_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_write_read_spanner)
{
    int_fast64_t ret;
    // goal is to do a basic write-then-read test that spans map tables
    // we must first setup a vol and a lun for that vol

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, NUVO_MAP_RADIX * NUVO_MAP_RADIX - 7, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &log_signal;
    log_req.vs_ptr = &my_vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req.log_io_blocks[i].data = write_bufs[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map;
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);

    // verify that the segment usage was marked
    ck_assert_uint_eq(segment_usage[0], 32);

    // ack to the logger
    nuvo_log_ack_sno(&log_req);

    // map read and pin
    struct nuvo_map_entry map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, NUVO_MAP_RADIX * NUVO_MAP_RADIX - 7, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    // verify that map returned exactly what we wrote earlier
    for(int i = 0; i < 32; i++)
    {
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].type,
                          map_entries[i].type);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[i].media_addr.parcel_index);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[i].media_addr.block_offset);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].pattern,
                          map_entries[i].pattern);
    }

    // verify segment pinning
    ck_assert_uint_eq(segment_pin[0], 32);

    // read the data and verify it is the same (just some test sanity checking)
    nuvo_mutex_t signal;
    nuvo_mutex_init(&signal);
    for(int i = 0; i < 32; i++)
    {
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&signal);
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = pds[i];
        req->rw.block_count = 1;
        req->rw.block_offset = map_entries[i].media_addr.block_offset;
        req->rw.iovecs[0].iov_base = read_bufs[i];
        req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;

        nuvo_pr_sync_submit(req, &signal);

        ck_assert_int_eq(memcmp(read_bufs[i], write_bufs[i], NUVO_BLOCK_SIZE), 0);

        nuvo_pr_client_req_free(req);
    }

    // read-release map data
    nuvo_map_read_release(my_lun, 32, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }

    // we're done, clean up the maps
    nuvo_map_lun_close(my_lun, &root_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_write_read_split)
{
    int_fast64_t ret;
    // goal is to do a basic write-then-read test that spans map tables
    // we must first setup a vol and a lun for that vol

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, NUVO_MAP_RADIX - 7, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req0;
    nuvo_dlnode_init(&log_req0.list_node);
    log_req0.operation = NUVO_LOG_OP_DATA;
    log_req0.atomic = true;
    log_req0.tag.ptr = &log_signal;
    log_req0.vs_ptr = &my_vol;
    log_req0.data_class = NUVO_DATA_CLASS_A;
    log_req0.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req0.log_io_blocks[i].data = write_bufs[i];
        log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req0.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req0.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req0);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req0.nuvo_map_entries);

    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map;
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);

    // verify that the segment usage was marked
    ck_assert_uint_eq(segment_usage[0], 32);

    // ack to the logger
    nuvo_log_ack_sno(&log_req0);

    // do map request
    nuvo_map_request_init(&map_req, my_lun, NUVO_MAP_RADIX - 7 + 48, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    struct nuvo_log_request log_req1;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    nuvo_dlnode_init(&log_req1.list_node);
    log_req1.operation = NUVO_LOG_OP_DATA;
    log_req1.atomic = true;
    log_req1.tag.ptr = &log_signal;
    log_req1.vs_ptr = &my_vol;
    log_req1.data_class = NUVO_DATA_CLASS_A;
    log_req1.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req1.log_io_blocks[i].data = write_bufs[i];
        log_req1.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req1.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req1.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req1);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req1.nuvo_map_entries);

    // verify that all maps were freed on the map_req
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);

    // verify that the segment usage was marked
    ck_assert_uint_eq(segment_usage[0], 64);

    // ack to the logger
    nuvo_log_ack_sno(&log_req1);


    // map read and pin
    struct nuvo_map_entry map_entries[112];
    uint_fast32_t pds[112];
    nuvo_map_request_init(&map_req, my_lun, NUVO_MAP_RADIX - 7 - 16, 112);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    // verify that map returned exactly what we wrote earlier
    uint_fast32_t bidx = 0;
    for(unsigned i = 0; i < 16; i++, bidx++)
    {
        ck_assert_uint_eq(map_entries[bidx].type, NUVO_ME_CONST);
        ck_assert_uint_eq(map_entries[bidx].pattern, 0);
    }
    for(unsigned i = 0; i < 32; i++, bidx++)
    {
        ck_assert_uint_eq(log_req0.nuvo_map_entries[i].type,
                          map_entries[bidx].type);
        ck_assert_uint_eq(log_req0.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[bidx].media_addr.parcel_index);
        ck_assert_uint_eq(log_req0.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[bidx].media_addr.block_offset);
        ck_assert_uint_eq(log_req0.nuvo_map_entries[i].pattern,
                          map_entries[bidx].pattern);
    }
    for(unsigned i = 0; i < 16; i++, bidx++)
    {
        ck_assert_uint_eq(map_entries[bidx].type, NUVO_ME_CONST);
        ck_assert_uint_eq(map_entries[bidx].pattern, 0);
    }
    for(unsigned i = 0; i < 32; i++, bidx++)
    {
        ck_assert_uint_eq(log_req1.nuvo_map_entries[i].type,
                          map_entries[bidx].type);
        ck_assert_uint_eq(log_req1.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[bidx].media_addr.parcel_index);
        ck_assert_uint_eq(log_req1.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[bidx].media_addr.block_offset);
        ck_assert_uint_eq(log_req1.nuvo_map_entries[i].pattern,
                          map_entries[bidx].pattern);
    }
    for(unsigned i = 0; i < 16; i++, bidx++)
    {
        ck_assert_uint_eq(map_entries[bidx].type, NUVO_ME_CONST);
        ck_assert_uint_eq(map_entries[bidx].pattern, 0);
    }

    // verify segment pinning
    ck_assert_uint_eq(segment_pin[0], 64);


    // read the data and verify it
    nuvo_mutex_t signal;
    nuvo_mutex_init(&signal);
    for(int i = 16; i < 48; i++)
    {
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&signal);
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = pds[i];
        req->rw.block_count = 1;
        req->rw.block_offset = map_entries[i].media_addr.block_offset;
        req->rw.iovecs[0].iov_base = read_bufs[i - 16];
        req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;

        nuvo_pr_sync_submit(req, &signal);

        ck_assert_int_eq(memcmp(read_bufs[i - 16], write_bufs[i - 16], NUVO_BLOCK_SIZE), 0);

        nuvo_pr_client_req_free(req);
    }
    for(int i = 64; i < 96; i++)
    {
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&signal);
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = pds[i];
        req->rw.block_count = 1;
        req->rw.block_offset = map_entries[i].media_addr.block_offset;
        req->rw.iovecs[0].iov_base = read_bufs[i - 64];
        req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;

        nuvo_pr_sync_submit(req, &signal);

        ck_assert_int_eq(memcmp(read_bufs[i - 64], write_bufs[i - 64], NUVO_BLOCK_SIZE), 0);

        nuvo_pr_client_req_free(req);
    }

    // read-release map
    nuvo_map_read_release(my_lun, 112, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }

    // we're done, clean up the maps
    nuvo_map_lun_close(my_lun, &root_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

// goal is to do a basic write test followed by a conditional rewrite test
// We do a write than spans tables.  Then we get the addresses that were in
// the original write and save those (as if we are doing a moving write). Then
// do an overwrite in the middle of the original range.  Then send in the
// conditional write for the range.  Then read addresses again and confirm the
// conditional write affected the ends of the range but not the middle.
struct {
    uint32_t start_bno;
    uint8_t  num_blocks;
    uint32_t overwrite_start_bno;
    uint8_t  overwrite_num_blocks;
} write_condition_params[7] =  {
        { 0, 1,  0, 1},   // within one map block, one block , basic sanity
        { NUVO_MAP_RADIX + 4, 8, NUVO_MAP_RADIX + 4, 8},   // within one map block, complete overwrite
        { NUVO_MAP_RADIX + 4, 8, NUVO_MAP_RADIX + 4, 0},   // witin one map block, no overwrite
       { NUVO_MAP_RADIX - 4, 8, NUVO_MAP_RADIX - 4, 8},   // span map blocks, complete overwrite
        { NUVO_MAP_RADIX - 4, 8, NUVO_MAP_RADIX - 4, 0},   // span map map block, no overwrite
        { NUVO_MAP_RADIX + 4, 8, NUVO_MAP_RADIX + 6, 3},   // within one map block, partial overwrite
        { NUVO_MAP_RADIX - 4, 8, NUVO_MAP_RADIX - 2, 4},   // span map block, partial overwrite
};


START_TEST(nuvo_map_test_shared_snap_read)
{
    int_fast64_t ret;
    struct nuvo_lun *snap_lun;
    my_vol.snap_generation = 0;
#if 0
    uint32_t block_num = write_condition_params[_i].start_bno;
    uint8_t  num_blocks = write_condition_params[_i].num_blocks;
    uint32_t overwrite_block_num = write_condition_params[_i].overwrite_start_bno;
    uint8_t overwrite_num_blocks = write_condition_params[_i].overwrite_num_blocks;
#endif
    //NUVO_ASSERT(0);

    uint32_t block_num = rand() % 262144;
    uint8_t  num_blocks = 32;
    // we must first setup a vol and a lun for that vol

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    //read from the active before any writes

    struct nuvo_map_request map_req;
    struct nuvo_map_request map_req_snap;
    struct nuvo_map_entry read_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, false, read_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    for (unsigned i = 0; i < num_blocks; i++)
    {
        NUVO_ASSERT(read_entries[i].cow == NUVO_MAP_ENTRY_NONE);
        NUVO_ASSERT(read_entries[i].type == NUVO_ME_CONST);
    }
    snap_lun = lun_alloc();
    memset(snap_lun, 0 , sizeof(struct nuvo_lun));
    snap_lun->vol = &my_vol;
    nuvo_mutex_init(&snap_lun->mutex);
    snap_lun->lun_state = NUVO_LUN_STATE_VALID;
    snap_lun->export_state = NUVO_LUN_EXPORT_UNEXPORTED;

    uuid_t lun_uuid;
    uuid_generate(lun_uuid);
    uuid_copy(snap_lun->lun_uuid, lun_uuid);
    snap_lun->snap_id = ++(my_vol.snap_generation);
    snap_lun->size = 1ull << 36;
    snap_lun->map_height = 3;

    nuvo_return_t rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
    ck_assert(rc == 0);

    __nuvo_map_create_snap(my_lun, snap_lun);

    // read from pit lun

    nuvo_map_request_init(&map_req, snap_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    NUVO_ASSERT(!map_req.status);
    nuvo_map_fault_in_sync(&map_req);
    NUVO_ASSERT(!map_req.status);
    nuvo_map_read_and_pin_sync(&map_req, false, read_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    for (unsigned i = 0; i < num_blocks; i++)
    {
        NUVO_ASSERT(read_entries[i].cow == NUVO_MAP_ENTRY_SHARED);
        //NUVO_ASSERT(read_entries[i].type == NUVO_ME_CONST);
    }
    //read from the active before any writes but after snap

    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, false, read_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    for (unsigned i = 0; i < num_blocks; i++)
    {
        NUVO_ASSERT(read_entries[i].cow == NUVO_MAP_ENTRY_COW);
        NUVO_ASSERT(read_entries[i].type == NUVO_ME_CONST);
    }
    uint8_t *write_bufs[32];
    for(unsigned i = 0; i < num_blocks; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
    }

    for (int k = 0; k < 100; k++)
    {
        uint32_t block_num = rand() % 262144;

        // get some data to write to active
        // do map request
        nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        nuvo_map_request_init(&map_req_snap, snap_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req_snap);
        ck_assert_int_ge(map_req_snap.status, 0);
        // start logger
        nuvo_mutex_t log_signal;
        ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        struct nuvo_log_request log_req0;
        nuvo_dlnode_init(&log_req0.list_node);
        log_req0.operation = NUVO_LOG_OP_DATA;
        log_req0.atomic = true;
        log_req0.tag.ptr = &log_signal;
        log_req0.vs_ptr = &my_vol;
        log_req0.data_class = NUVO_DATA_CLASS_A;
        log_req0.block_count = num_blocks;
        for(unsigned i = 0; i < num_blocks; i++)
        {
            log_req0.log_io_blocks[i].data = write_bufs[i];
            log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req0.log_io_blocks[i].bno = map_req.block_start + i;
        }
        log_req0.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req0);
        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_fault_in_sync(&map_req_snap);
        ck_assert_int_ge(map_req.status, 0);
        // wait for logger
        nuvo_mutex_lock(&log_signal);
        // commit map
        nuvo_map_multi_lun_commit_write(&map_req, &map_req_snap,  log_req0.nuvo_map_entries);
        // verify that all maps were freed on the map_req
        // ack to the logger
        struct nuvo_map_track *map;
        map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
        ck_assert_ptr_eq(map, NULL);
        nuvo_log_ack_sno(&log_req0);

        //read from pit and ensure all is COW
        // read from pit lun

        nuvo_map_request_init(&map_req, snap_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        NUVO_ASSERT(!map_req.status);
        nuvo_map_fault_in_sync(&map_req);
        NUVO_ASSERT(!map_req.status);
        nuvo_map_read_and_pin_sync(&map_req, false, read_entries, pds);
        ck_assert_int_ge(map_req.status, 0);

        for (unsigned i = 0; i < num_blocks; i++)
        {
            NUVO_ASSERT(read_entries[i].cow == NUVO_MAP_ENTRY_COW);
            NUVO_ASSERT(read_entries[i].type == NUVO_ME_CONST);
            //NUVO_ASSERT(read_entries[i].type == NUVO_ME_CONST);
        }
    }

    rc = nuvo_map_lun_close(my_lun, &root_map_entry);
    NUVO_ASSERT(!rc);
    rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
    NUVO_ASSERT(!rc);
    lun_dealloc_all();
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
    for(unsigned i = 0; i < num_blocks; i++)
    {
        free(write_bufs[i]);
    }

}
END_TEST

static void nuvo_map_test_write_conditional(int _i , bool multi_lun)
{
    int_fast64_t ret;
    struct nuvo_lun *snap_lun;
    my_vol.snap_generation = 0;

    uint32_t block_num = write_condition_params[_i].start_bno;
    uint8_t  num_blocks = write_condition_params[_i].num_blocks;
    uint32_t overwrite_block_num = write_condition_params[_i].overwrite_start_bno;
    uint8_t overwrite_num_blocks = write_condition_params[_i].overwrite_num_blocks;

    // we must first setup a vol and a lun for that vol

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    for(unsigned i = 0; i < num_blocks; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
    }
  // Initial write
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req0;
    nuvo_dlnode_init(&log_req0.list_node);
    log_req0.operation = NUVO_LOG_OP_DATA;
    log_req0.atomic = true;
    log_req0.tag.ptr = &log_signal;
    log_req0.vs_ptr = &my_vol;
    log_req0.data_class = NUVO_DATA_CLASS_A;
    log_req0.block_count = num_blocks;
    for(unsigned i = 0; i < num_blocks; i++)
    {
        log_req0.log_io_blocks[i].data = write_bufs[i];
        log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req0.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req0.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req0);
    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    // wait for logger
    nuvo_mutex_lock(&log_signal);
    // commit map
    nuvo_map_commit_write(&map_req, log_req0.nuvo_map_entries);
    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map;
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);
    // ack to the logger
    nuvo_log_ack_sno(&log_req0);

  // Now get addresses - could get out of log, but let's be fastidious

    // Now do read (not whole read, just get addresses)
    struct nuvo_map_entry original_map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, false, original_map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    struct nuvo_media_addr old_media_addrs[32];
    struct nuvo_map_entry snap_lun_entries[32];

    for (unsigned i = 0; i < num_blocks; i++)
    {
        NUVO_ASSERT(original_map_entries[i].cow == NUVO_MAP_ENTRY_NONE);
        old_media_addrs[i] = original_map_entries[i].media_addr;
    }
    // Now do the 512 block write test
    for (int cnt = 0; cnt < 32; cnt++)
    {
        uint64_t blkno = rand() % 262144;
        //NUVO_ERROR_PRINT("blkno:%llu", blkno);
        unsigned int numblks = 1;

        // Now do an overwrite multilun on active and snap
        nuvo_map_request_init(&map_req, my_lun, blkno, numblks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);


        nuvo_dlnode_init(&log_req0.list_node);
        log_req0.operation = NUVO_LOG_OP_DATA;
        log_req0.atomic = true;
        log_req0.tag.ptr = &log_signal;
        log_req0.vs_ptr = &my_vol;
        log_req0.data_class = NUVO_DATA_CLASS_A;
        log_req0.block_count = numblks;
        for(unsigned i = 0; i < numblks; i++)
        {
            //NUVO_ASSERT(0 <= (int64_t)(i + blkno - numblks));
            log_req0.log_io_blocks[i].data = write_bufs[i];
            log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req0.log_io_blocks[i].bno = map_req.block_start + i;
        }
        log_req0.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req0);

        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        // wait for logger
        nuvo_mutex_lock(&log_signal);
        // commit map

        nuvo_map_commit_write(&map_req, log_req0.nuvo_map_entries);
        // verify that all maps were freed on the map_req
        map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
        ck_assert_ptr_eq(map, NULL);

        // ack to the logger
        nuvo_log_ack_sno(&log_req0);
    }

    // close and reopen the active lun
    // create snap
    // read and verify
    // close-reopen
    // read again and verify

    if (multi_lun)
    {
        // close and reopen the active lun
        nuvo_return_t rc = nuvo_map_lun_close(my_lun, &root_map_entry);
        NUVO_ASSERT(!rc);
        rc = nuvo_map_lun_open(my_lun, &root_map_entry);
        NUVO_ASSERT(!rc);
    }

// TODO  basic snapshot test , move this out to a new test
#if 0
    if (multi_lun)
    {
        // create snap
        snap_lun = lun_alloc();
        memset(snap_lun, 0 , sizeof(struct nuvo_lun));
        snap_lun->vol = &my_vol;
        nuvo_mutex_init(&snap_lun->mutex);
        snap_lun->lun_state = NUVO_LUN_STATE_VALID;
        snap_lun->export_state = NUVO_LUN_EXPORT_UNEXPORTED;

        uuid_t lun_uuid;
        uuid_generate(lun_uuid);

        uuid_copy(snap_lun->lun_uuid, lun_uuid);
        snap_lun->snap_id = ++(my_vol.snap_generation);
        snap_lun->size = 1ull << 36;
        snap_lun->map_height = 3;

        nuvo_return_t rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
        ck_assert(rc == 0);

        __nuvo_map_create_snap(my_lun, snap_lun);

        // read and verify after snap
        nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, false, original_map_entries, pds);
        ck_assert_int_ge(map_req.status, 0);

        for (unsigned i = 0; i < num_blocks; i++)
        {
            NUVO_ASSERT(original_map_entries[i].cow == NUVO_MAP_ENTRY_COW);
        }

        // close and reopen the lun

        rc = nuvo_map_lun_close(my_lun, &root_map_entry);
        NUVO_ASSERT(!rc);
        rc = nuvo_map_lun_open(my_lun, &root_map_entry);
        NUVO_ASSERT(!rc);

        //read and verify after snap create + reopen

        nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, false, original_map_entries, pds);
        ck_assert_int_ge(map_req.status, 0);

        for (unsigned i = 0; i < num_blocks; i++)
        {
            NUVO_ASSERT(original_map_entries[i].cow == NUVO_MAP_ENTRY_COW);
        }
    }
#endif

    //create a snapshot before the overwrite
    struct nuvo_map_entry overwrite_map_entries[32];

    /* creat snaps 5 times , reopen and check */
    for(int j = 0; j < 5; j++)
    {
        if (multi_lun)
        {

            snap_lun = lun_alloc();
            memset(snap_lun, 0 , sizeof(struct nuvo_lun));
            snap_lun->vol = &my_vol;
            nuvo_mutex_init(&snap_lun->mutex);
            snap_lun->lun_state = NUVO_LUN_STATE_VALID;
            snap_lun->export_state = NUVO_LUN_EXPORT_UNEXPORTED;
            uuid_t lun_uuid;
            uuid_generate(lun_uuid);

            uuid_copy(snap_lun->lun_uuid, lun_uuid);
            snap_lun->snap_id = ++(my_vol.snap_generation);
            snap_lun->size = 1ull << 36;
            snap_lun->map_height = 3;

            nuvo_return_t rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
            ck_assert(rc == 0);

            __nuvo_map_create_snap(my_lun, snap_lun);


            bool reread_test  = true;
            (void)reread_test;
            do
            {
read_after_snap_create:
                //READ again from active and make sure the entries are COW
                nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
                nuvo_map_reserve_sync(&map_req);
                ck_assert_int_ge(map_req.status, 0);
                nuvo_map_fault_in_sync(&map_req);
                ck_assert_int_ge(map_req.status, 0);
                nuvo_map_read_and_pin_sync(&map_req, false, original_map_entries, pds);
                ck_assert_int_ge(map_req.status, 0);

                for (unsigned i = 0; i < num_blocks; i++)
                {
                    NUVO_ASSERT(original_map_entries[i].cow == NUVO_MAP_ENTRY_COW);
                    old_media_addrs[i] = original_map_entries[i].media_addr;
                }

                {
                    // check snap shot is all shared
                    struct nuvo_map_request map_req;
                    nuvo_map_request_init(&map_req, snap_lun, block_num, num_blocks);
                    nuvo_map_reserve_sync(&map_req);
                    ck_assert_int_ge(map_req.status, 0);
                    nuvo_map_fault_in_sync(&map_req);
                    ck_assert_int_ge(map_req.status, 0);
                    nuvo_map_read_and_pin_sync(&map_req, false, original_map_entries, pds);
                    ck_assert_int_ge(map_req.status, 0);

                    for (unsigned i = 0; i < num_blocks; i++)
                    {
                        NUVO_ASSERT(original_map_entries[i].cow == NUVO_MAP_ENTRY_SHARED);
                    }
                }
                rc = nuvo_map_lun_close(my_lun, &root_map_entry);
                NUVO_ASSERT(!rc);
                if (multi_lun)
                {
                    rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
                    NUVO_ASSERT(!rc);
                }
                rc = nuvo_map_lun_open(my_lun, &root_map_entry);
                NUVO_ASSERT(!rc);
                rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
                NUVO_ASSERT(!rc);


               if (reread_test)
               {
                    reread_test = false;
                    goto read_after_snap_create;
               }
            } while(false);
        }


        struct nuvo_map_request map_req_snap;

        // Now do an overwrite multilun on active and snap
        nuvo_map_request_init(&map_req, my_lun, overwrite_block_num, overwrite_num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        if (multi_lun)
        {
            nuvo_map_request_init(&map_req_snap, snap_lun, overwrite_block_num, overwrite_num_blocks);
            nuvo_map_reserve_sync(&map_req_snap);
            ck_assert_int_ge(map_req_snap.status, 0);
        }

        nuvo_dlnode_init(&log_req0.list_node);
        log_req0.operation = NUVO_LOG_OP_DATA;
        log_req0.atomic = true;
        log_req0.tag.ptr = &log_signal;
        log_req0.vs_ptr = &my_vol;
        log_req0.data_class = NUVO_DATA_CLASS_A;
        log_req0.block_count = overwrite_num_blocks;
        for(unsigned i = 0; i < overwrite_num_blocks; i++)
        {
            NUVO_ASSERT(0 <= (int64_t)i + overwrite_block_num - block_num);
            NUVO_ASSERT(i + overwrite_block_num - block_num <= 32);
            log_req0.log_io_blocks[i].data = write_bufs[i + overwrite_block_num - block_num];
            log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req0.log_io_blocks[i].bno = map_req.block_start + i;
        }
        log_req0.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req0);
        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        if (multi_lun)
        {
            nuvo_map_fault_in_sync(&map_req_snap);
            ck_assert_int_ge(map_req_snap.status, 0);
        }
        // wait for logger
        nuvo_mutex_lock(&log_signal);
        // commit map

        if (!multi_lun)
        {
            nuvo_map_commit_write(&map_req, log_req0.nuvo_map_entries);
        }
        else
        {
            nuvo_map_multi_lun_commit_write(&map_req, &map_req_snap, log_req0.nuvo_map_entries);
        }
        // verify that all maps were freed on the map_req
        map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
        ck_assert_ptr_eq(map, NULL);
        if (multi_lun)
        {
            map = nuvo_dlist_get_head_object(&map_req_snap.map_list, struct nuvo_map_track, list_node);
            NUVO_ASSERT(map == NULL);
        }
        // ack to the logger
        nuvo_log_ack_sno(&log_req0);

        // Now get addresses - could get out of log, but let's be fastidious
        // Now do read (not whole read, just get addresses)
        nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, false, overwrite_map_entries, pds);
        ck_assert_int_ge(map_req.status, 0);

        //bool reread_test = true; // so that we can re-read after lun close
//read_begin:
        int r = 0;

        while  (multi_lun && overwrite_num_blocks && r < 2)
        {
            // read the snap and make sure that things are cow or shared depending
            // on whether overwrite happened or not

            //struct nuvo_map_request map_req_snap;
            struct nuvo_map_entry temp_map_entries[32];
            nuvo_map_request_init(&map_req_snap, snap_lun, block_num, num_blocks);
            NUVO_ASSERT((map_req_snap.status >= 0));
            nuvo_map_reserve_sync(&map_req_snap);
            NUVO_ASSERT((map_req_snap.status >= 0));
            nuvo_map_fault_in_sync(&map_req_snap);
            NUVO_ASSERT((map_req_snap.status >= 0));
            nuvo_map_read_and_pin_sync(&map_req_snap, false, temp_map_entries, pds);
            NUVO_ASSERT((map_req_snap.status >= 0));

            for (unsigned i = 0; i < num_blocks; i++)
            {
                if (block_num + i >= overwrite_block_num && block_num + i < overwrite_block_num + overwrite_num_blocks)
                {
                    // if overwritten the entry must be cow on snapshot
                    NUVO_ASSERT(temp_map_entries[i].cow == NUVO_MAP_ENTRY_COW);
                }
                else
                {
                    // else this entry must be shared on snap
                    NUVO_ASSERT(temp_map_entries[i].cow == NUVO_MAP_ENTRY_SHARED);
                }
            }
            // read ovewritten from active
            // and check for none
            struct nuvo_map_request map_req;
            nuvo_map_request_init(&map_req, my_lun, overwrite_block_num, overwrite_num_blocks);
            nuvo_map_reserve_sync(&map_req);
            ck_assert_int_ge(map_req.status, 0);
            nuvo_map_fault_in_sync(&map_req);
            ck_assert_int_ge(map_req.status, 0);
            nuvo_map_read_and_pin_sync(&map_req, false, temp_map_entries, pds);

            for (unsigned i = 0; i < overwrite_num_blocks; i++)
            {
                NUVO_ASSERT(temp_map_entries[i].cow == NUVO_MAP_ENTRY_NONE);
            }

            if (multi_lun)
            {
                // trigger a multi run read
                // and assert all read entries must be COW

                struct nuvo_map_request map_req_snap;
                nuvo_map_request_init(&map_req_snap, snap_lun, block_num, num_blocks);
                nuvo_map_reserve_sync(&map_req_snap);
                ck_assert_int_ge(map_req_snap.status, 0);
                nuvo_map_fault_in_sync(&map_req_snap);
                ck_assert_int_ge(map_req_snap.status, 0);

                struct nuvo_map_request map_req_active;
                nuvo_map_request_init(&map_req_active, my_lun, block_num, num_blocks);
                nuvo_map_reserve_sync(&map_req_active);
                ck_assert_int_ge(map_req_active.status, 0);
                nuvo_map_fault_in_sync(&map_req_active);
                ck_assert_int_ge(map_req_active.status, 0);

                nuvo_map_multi_lun_read_sync(&map_req_snap, true, &map_req_active, snap_lun_entries, pds);

                // multi lun read from snapshot could get read from snapshot
                // or may go to active
                // so all must be cow either from shared or active.
                for (unsigned i = 0; i < num_blocks; i++)
                {
                    NUVO_ASSERT(snap_lun_entries[i].cow == NUVO_MAP_ENTRY_COW);
                }

                // all overwritten blocks in snap must be COW assert

                nuvo_map_request_init(&map_req_snap, snap_lun, overwrite_block_num, overwrite_num_blocks);
                nuvo_map_reserve_sync(&map_req_snap);
                ck_assert_int_ge(map_req_snap.status, 0);
                nuvo_map_fault_in_sync(&map_req_snap);
                ck_assert_int_ge(map_req_snap.status, 0);
                nuvo_map_read_and_pin_sync(&map_req_snap, false, snap_lun_entries, pds);

                // snap lun must be all cow

                for (unsigned i = 0; i < overwrite_num_blocks; i++)
                {
                    NUVO_ASSERT(snap_lun_entries[i].cow == NUVO_MAP_ENTRY_COW);
                }
            }
            // close, reopen and repeat to ensure that
            // cp didnt thing anything
            /*close and reopen */
            nuvo_return_t rc = nuvo_map_lun_close(my_lun, &root_map_entry);
            NUVO_ASSERT(!rc);
            if (multi_lun)
            {
                rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
                NUVO_ASSERT(!rc);
            }
            rc = nuvo_map_lun_open(my_lun, &root_map_entry);
            NUVO_ASSERT(!rc);
            if (multi_lun)
            {
                rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
                NUVO_ASSERT(!rc);
            }
            r++;
        }

    }

    // Now do gc conditional rewrite
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    nuvo_dlnode_init(&log_req0.list_node);
    log_req0.operation = NUVO_LOG_OP_DATA;
    log_req0.atomic = true;
    log_req0.tag.ptr = &log_signal;
    log_req0.vs_ptr = &my_vol;
    log_req0.data_class = NUVO_DATA_CLASS_A;
    log_req0.block_count = num_blocks;
    for(unsigned i = 0; i < num_blocks; i++)
    {
        log_req0.log_io_blocks[i].data = write_bufs[i];
        log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req0.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req0.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req0);
    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    // wait for logger
    nuvo_mutex_lock(&log_signal);
    // commit map
    uint_fast32_t succeeded = 0;
    uint_fast32_t failed = 0;
    nuvo_map_commit_gc_write(&map_req, log_req0.nuvo_map_entries, old_media_addrs, &succeeded, &failed);
    ck_assert(failed == overwrite_num_blocks);

    // verify that all maps were freed on the map_req
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    NUVO_ASSERT(map == NULL);
    // ack to the logger
    nuvo_log_ack_sno(&log_req0);
  // Now do read (not whole read, just get addresses)
    struct nuvo_map_entry final_map_entries[32];
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, false, final_map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    for (unsigned i = 0; i < num_blocks; i++)
    {
        if (block_num + i >= overwrite_block_num && block_num + i < overwrite_block_num + overwrite_num_blocks)
        {
            // final_map_entries should be equal to overwrite version
            ck_assert(overwrite_map_entries[i].media_addr.parcel_index == final_map_entries[i].media_addr.parcel_index);
            ck_assert(overwrite_map_entries[i].media_addr.block_offset == final_map_entries[i].media_addr.block_offset);
        }
        else
        {
            // final_map_entries should be equal to new version
            ck_assert(log_req0.nuvo_map_entries[i].media_addr.parcel_index == final_map_entries[i].media_addr.parcel_index);
            ck_assert(log_req0.nuvo_map_entries[i].media_addr.block_offset == final_map_entries[i].media_addr.block_offset);
        }
    }
    if (!multi_lun || !overwrite_num_blocks)
    {
        goto _out;
    }


#if 0
    //* lets make sure that COW/NONE are correct even after evicting
    // verify lazy parent update
    // so we walk the mixed list and clean the dirty ones
    // then we walk the clean list and evict them
    // re-read maps and make sure entries are NONE/COW accordingly
    // we could have closed the lun and reread it
    // however lun_close today doenst clean out the dirty maps
    // refer to the documentation in the definiton
    // in nuvo_map_lun_close

    // since lun close is not complete
    // we are hand cleaning the maps only in this UT
    // since we dont do checkpoint for the luns
    // clean and evict in this UT


    struct nuvo_map_track *cur_map;
    struct nuvo_map_track *tmap;
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    int dirty_count = 0;

    cur_map = nuvo_dlist_get_tail_object(&nuvo_map->mixed_lru_list, struct nuvo_map_track, list_node);

    while (cur_map)
    {
        tmap = nuvo_dlist_get_prev_object(&nuvo_map->mixed_lru_list, cur_map,
                                            struct nuvo_map_track, list_node);
        nuvo_mutex_lock(&cur_map->mutex);
        if (cur_map->is_dirty)
        {
            nuvo_mutex_lock(&cur_map->vol->mutex);
            nuvo_mutex_lock(&cur_map->parent->mutex);
            struct nuvo_vol *vol = cur_map->vol;
            nuvo_map_mixed_remove(cur_map);
            cur_map->state = NUVO_MAP_CLEANING;
            nuvo_mutex_unlock(&nuvo_map->list_mutex);
            nuvo_map_writer_add_map(cur_map, NUVO_MW_FLUSH_AUTO);
            nuvo_mutex_unlock(&cur_map->parent->mutex);
            nuvo_mutex_unlock(&vol->mutex);
            nuvo_mutex_lock(&nuvo_map->list_mutex);
            dirty_count++;
        }
        else
        {
            nuvo_mutex_unlock(&cur_map->mutex);
        }
        cur_map = tmap;

    }
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    nuvo_map_writer_lock(&my_vol);
    // do one flush
    nuvo_map_writer_flush(&my_vol);


    nuvo_mutex_lock(&nuvo_map->list_mutex);

    cur_map = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);

    while (cur_map)
    {
        nuvo_mutex_lock(&cur_map->mutex);

        if (cur_map->parent)
        {
            struct nuvo_map_track *parent = cur_map->parent;
            nuvo_mutex_lock(&parent->mutex);
            nuvo_map_evict_table(cur_map);
            nuvo_mutex_unlock(&parent->mutex);
        }

        nuvo_mutex_unlock(&cur_map->mutex);
        cur_map = nuvo_dlist_get_prev_object(&nuvo_map->clean_lru_list, cur_map,
                                            struct nuvo_map_track, list_node);

    }
    nuvo_mutex_unlock(&nuvo_map->list_mutex);

    //dirty maps are evicted by now, So re-read and check for cow
    {

        // read ovewritten from active
        // and check for none

        struct nuvo_map_entry temp_map_entries[32];
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, overwrite_block_num, overwrite_num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, false, temp_map_entries, pds);

        for (unsigned i = 0; i < overwrite_num_blocks; i++)
        {
            NUVO_ASSERT(temp_map_entries[i].cow == NUVO_MAP_ENTRY_NONE);
        }

        // snap init, reserve and fault in
        // read from snap and assert for cow
        struct nuvo_map_request map_req_snap;
        nuvo_map_request_init(&map_req_snap, snap_lun, overwrite_block_num, overwrite_num_blocks);
        nuvo_map_reserve_sync(&map_req_snap);
        ck_assert_int_ge(map_req_snap.status, 0);
        nuvo_map_fault_in_sync(&map_req_snap);
        ck_assert_int_ge(map_req_snap.status, 0);
        nuvo_map_read_and_pin_sync(&map_req_snap, false, snap_lun_entries, pds);

        // snap lun must be all cow

        for (unsigned i = 0; i < overwrite_num_blocks; i++)
        {
            NUVO_ASSERT(snap_lun_entries[i].cow == NUVO_MAP_ENTRY_COW);
        }
    }
#endif
_out:


    // we're done, clean up the maps
    //TODO close the snap lun and destroy
    nuvo_map_lun_close(my_lun, &root_map_entry);
    /* close all the luns */
    if (multi_lun)
    {
        lun_close_all();
    }
    lun_dealloc_all();
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
    for(unsigned i = 0; i < num_blocks; i++)
    {
        free(write_bufs[i]);
    }
}
START_TEST(nuvo_map_test_map_diff)
{
    int_fast64_t ret;
    struct nuvo_lun *snap_lun;
    my_vol.snap_generation = 0;
    int _i = 0;

    uint32_t block_num = write_condition_params[_i].start_bno;
    uint8_t  num_blocks = write_condition_params[_i].num_blocks;
    //uint32_t overwrite_block_num = write_condition_params[_i].overwrite_start_bno;
   // uint8_t overwrite_num_blocks = write_condition_params[_i].overwrite_num_blocks;

    // we must first setup a vol and a lun for that vol

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 4;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    for(unsigned i = 0; i < num_blocks; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
    }
  // Initial write
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req0;
    nuvo_dlnode_init(&log_req0.list_node);
    log_req0.operation = NUVO_LOG_OP_DATA;
    log_req0.atomic = true;
    log_req0.tag.ptr = &log_signal;
    log_req0.vs_ptr = &my_vol;
    log_req0.data_class = NUVO_DATA_CLASS_A;
    log_req0.block_count = num_blocks;
    for(unsigned i = 0; i < num_blocks; i++)
    {
        log_req0.log_io_blocks[i].data = write_bufs[i];
        log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req0.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req0.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req0);
    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    // wait for logger
    nuvo_mutex_lock(&log_signal);
    // commit map
    nuvo_map_commit_write(&map_req, log_req0.nuvo_map_entries);
    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map;
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);
    // ack to the logger
    nuvo_log_ack_sno(&log_req0);


  // Now get addresses - could get out of log, but let's be fastidious

    // Now do read (not whole read, just get addresses)
    struct nuvo_map_entry original_map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, false, original_map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    struct nuvo_media_addr old_media_addrs[32];

    for (unsigned i = 0; i < num_blocks; i++)
    {
        NUVO_ASSERT(original_map_entries[i].cow == NUVO_MAP_ENTRY_NONE);
        old_media_addrs[i] = original_map_entries[i].media_addr;
    }

    // close and reopen the active lun
    // create snap
    // read and verify
    // close-reopen
    // read again and verify

    // close and reopen the active lun
    nuvo_return_t rc = nuvo_map_lun_close(my_lun, &root_map_entry);
    NUVO_ASSERT(!rc);
    rc = nuvo_map_lun_open(my_lun, &root_map_entry);
    NUVO_ASSERT(!rc);


    //create a snapshot before the overwrite
    struct nuvo_map_entry overwrite_map_entries[32];

    /* creat snaps a few times , reopen and check */
    for(int j = 0; j < 5; j++)
    {

        snap_lun = lun_alloc();
        memset(snap_lun, 0 , sizeof(struct nuvo_lun));
        snap_lun->lun_state = NUVO_LUN_STATE_VALID;
        snap_lun->export_state = NUVO_LUN_EXPORT_UNEXPORTED;
        snap_lun->vol = &my_vol;
        nuvo_mutex_init(&snap_lun->mutex);

        uuid_t lun_uuid;
        uuid_generate(lun_uuid);
        uuid_copy(snap_lun->lun_uuid, lun_uuid);
        snap_lun->snap_id = ++(my_vol.snap_generation);
        snap_lun->size = 1ull << 36;
        snap_lun->map_height = 3;

        nuvo_return_t rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
        ck_assert(rc == 0);

        __nuvo_map_create_snap(my_lun, snap_lun);

        do
        {
            // basically create snap and do snap diff
            // clsoe reopen and map diff and make sure results are same
#if 0

            nuvo_return_t ret1;

            {
                uint64_t offset_end = 0;
                struct map_de map_de_array[256];
                uint32_t batch_size;
                ret1 = nuvo_map_diff_api_helper(snap_lun, NULL , 0, map_de_array, &batch_size,  &offset_end);
                NUVO_ERROR_PRINT("md ret1:%d offset end:%llu\n", ret1, offset_end);
                if (ret1)
                {
                    map_de_batch_print(map_de_array , batch_size);
                }

            }
#endif


            rc = nuvo_map_lun_close(my_lun, &root_map_entry);
            NUVO_ASSERT(!rc);
            rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
            NUVO_ASSERT(!rc);

             // can assert pinned_count == 0 only first time since we are creating snapshot every iteration
            NUVO_ASSERT(j || nuvo_map->pinned_count == 0); // map_diff must not pin anything more
            rc = nuvo_map_lun_open(my_lun, &root_map_entry);
            NUVO_ASSERT(!rc);
            rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
            NUVO_ASSERT(!rc);
#if 0
            nuvo_return_t ret2;
            {
                uint64_t offset_end = 0;
                struct map_de map_de_array[256];
                uint32_t batch_size;
                ret2 = nuvo_map_diff_api_helper(snap_lun, NULL, 0, map_de_array, &batch_size, &offset_end);
                NUVO_ERROR_PRINT("md returns ret2:%d offset end:%llu\n", ret2, offset_end);
                if (ret2)
                {
                    map_de_batch_print(map_de_array , batch_size);
                }
            }
            NUVO_ASSERT(ret1 == ret2);


#endif
        } while(false);

        for (int cnt = 0; cnt < 32; cnt++)
        {
            uint64_t blkno = rand() % 262144;
            //NUVO_ERROR_PRINT("blkno:%llu", blkno);
            unsigned int numblks = 1;
            struct nuvo_map_request map_req_snap;

            // Now do an overwrite multilun on active and snap
            nuvo_map_request_init(&map_req, my_lun, blkno, numblks);
            nuvo_map_reserve_sync(&map_req);
            ck_assert_int_ge(map_req.status, 0);

            nuvo_map_request_init(&map_req_snap, snap_lun, blkno, numblks);
            nuvo_map_reserve_sync(&map_req_snap);
            ck_assert_int_ge(map_req_snap.status, 0);

            nuvo_dlnode_init(&log_req0.list_node);
            log_req0.operation = NUVO_LOG_OP_DATA;
            log_req0.atomic = true;
            log_req0.tag.ptr = &log_signal;
            log_req0.vs_ptr = &my_vol;
            log_req0.data_class = NUVO_DATA_CLASS_A;
            log_req0.block_count = numblks;
            for(unsigned i = 0; i < numblks; i++)
            {
                //NUVO_ASSERT(0 <= (int64_t)(i + blkno - numblks));
                log_req0.log_io_blocks[i].data = write_bufs[i];
                log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
                log_req0.log_io_blocks[i].bno = map_req.block_start + i;
            }
            log_req0.callback = nuvo_map_test_log_cb;
            nuvo_log_submit(&log_req0);

            // fault-in map
            nuvo_map_fault_in_sync(&map_req);
            ck_assert_int_ge(map_req.status, 0);
            nuvo_map_fault_in_sync(&map_req_snap);
            ck_assert_int_ge(map_req_snap.status, 0);
            // wait for logger
            nuvo_mutex_lock(&log_signal);
            // commit map

            nuvo_map_multi_lun_commit_write(&map_req, &map_req_snap, log_req0.nuvo_map_entries);
            // verify that all maps were freed on the map_req
            map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
            ck_assert_ptr_eq(map, NULL);
            map = nuvo_dlist_get_head_object(&map_req_snap.map_list, struct nuvo_map_track, list_node);
            NUVO_ASSERT(map == NULL);

            // ack to the logger
            nuvo_log_ack_sno(&log_req0);
        }

#if 0
            nuvo_return_t ret3;
            {
                uint64_t offset_end = 0;
                struct map_de map_de_array[256];
                uint32_t batch_size;
                ret3 = nuvo_map_diff_api_helper(snap_lun, NULL, 0, map_de_array, &batch_size, &offset_end);
                NUVO_ERROR_PRINT("md returns ret1:%d offset end:%llu\n", ret3, offset_end);
                if (ret3)
                {
                    map_de_batch_print(map_de_array , batch_size);
                }
            }
#endif


            rc = nuvo_map_lun_close(my_lun, &root_map_entry);
            NUVO_ASSERT(!rc);
            rc = nuvo_map_lun_close(snap_lun, &snap_lun->root_map_entry);
            NUVO_ASSERT(!rc);
            // can assert pinned_count == 0 only first time since we are creating snapshot every iteration
            NUVO_ASSERT(j || nuvo_map->pinned_count == 0); // map_diff must not pin anything more

            rc = nuvo_map_lun_open(my_lun, &root_map_entry);
            NUVO_ASSERT(!rc);
            rc = nuvo_map_lun_open(snap_lun, &snap_lun->root_map_entry);
            NUVO_ASSERT(!rc);

#if 0
            nuvo_return_t ret4;
            {
                uint64_t offset_end = 0;
                struct map_de map_de_array[256];
                uint32_t batch_size;
                ret4 = nuvo_map_diff_api_helper(snap_lun, NULL, 0, map_de_array, &batch_size, &offset_end);
                NUVO_ERROR_PRINT("md ret1:%d offset end:%llu\n", ret4, offset_end);
                if (ret4)
                {
                    map_de_batch_print(map_de_array , batch_size);
                }
            }

            NUVO_ASSERT(ret3 == ret4);
#endif


        // Now get addresses - could get out of log, but let's be fastidious
        // Now do read (not whole read, just get addresses)
        nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, false, overwrite_map_entries, pds);
        ck_assert_int_ge(map_req.status, 0);


        //bool reread_test = true; // so that we can re-read after lun close

    }

    // Now do gc conditional rewrite
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    nuvo_dlnode_init(&log_req0.list_node);
    log_req0.operation = NUVO_LOG_OP_DATA;
    log_req0.atomic = true;
    log_req0.tag.ptr = &log_signal;
    log_req0.vs_ptr = &my_vol;
    log_req0.data_class = NUVO_DATA_CLASS_A;
    log_req0.block_count = num_blocks;
    for(unsigned i = 0; i < num_blocks; i++)
    {
        log_req0.log_io_blocks[i].data = write_bufs[i];
        log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req0.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req0.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req0);
    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    // wait for logger
    nuvo_mutex_lock(&log_signal);
    // commit map
    uint_fast32_t succeeded = 0;
    uint_fast32_t failed = 0;
    nuvo_map_commit_gc_write(&map_req, log_req0.nuvo_map_entries, old_media_addrs, &succeeded, &failed);
    ck_assert(failed == 0);  // Overwrote whole range
    // verify that all maps were freed on the map_req
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);
    // ack to the logger
    nuvo_log_ack_sno(&log_req0);
#if 0
    {
        nuvo_return_t ret3;
        uint64_t offset_end = 0;
        struct map_de map_de_array[256];
        uint32_t batch_size;
        ret3 = nuvo_map_diff_api_helper(snap_lun, NULL, 0, map_de_array, &batch_size, &offset_end);
        NUVO_ERROR_PRINT("md returns ret1:%d offset end:%llu\n", ret3, offset_end);
        if (ret3)
        {
            map_de_batch_print(map_de_array , batch_size);
        }
    }
#endif

    // we're done, clean up the maps
    //TODO close the snap lun and destroy
    nuvo_map_lun_close(my_lun, &root_map_entry);
    lun_close_all();
    lun_dealloc_all();
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
    for(unsigned i = 0; i < num_blocks; i++)
    {
        free(write_bufs[i]);
    }
}
END_TEST

START_TEST(nuvo_map_test_mfl)
{
    //start an active lun
    //create a snap
    //delete the lun
    //create a snap
    //write to x offsets.
    //delete snap
    //create snap
    //overwrite x offsets.
    //delete the lun

    // begin with some clarity
    nuvo_log_set_level("map", 100);

    nuvo_cond_init(&cp_cond);
    nuvo_mutex_init(&cp_mutex);

    NUVO_ERROR_PRINT("\n===================\nnuvo_map_test_mfl begin\n=====================\n");
    struct nuvo_vol *vol = &my_vol;
    struct nuvo_space_vol * space_vol = &vol->log_volume.space;

    nuvo_return_t rc = nuvo_space_init();
    NUVO_ASSERT(!rc);
    rc = nuvo_space_vol_init(space_vol);
    NUVO_ASSERT(!rc);
    nuvo_map_vol_state_init(&vol->log_volume.map_state, vol);

    // create and init vol
    rc = nuvo_mutex_init(&vol->mutex);
    NUVO_ASSERT(!rc);

    nuvo_map_writer_init(&vol->log_volume.map_state.writer, vol);

    // create and init lun
    map_ut_init_active(vol);

    struct nuvo_lun * active_lun  = &vol->log_volume.lun;

    // write to the active max_iter random blocks
    int seed = 0;
    map_ut_multi_write(active_lun, /*snap_lun = */NULL, /*max_iter = */256, /*num_blocks = */32,
                                            /*seq = */false, &seed);
    // create snap
    struct nuvo_lun * snap_lun = map_ut_create_snap(vol);
    // delete snap
    g_lun = snap_lun; //to make the fake nuvo_get_lun_next_to_delete() for mfl to work
    map_ut_delete_lun_int(snap_lun);

    // lets wait for the cp to finish
    // the fake cp trigger have a cond broadcast
    nuvo_mutex_lock(&cp_mutex);
    nuvo_cond_wait(&cp_cond, &cp_mutex);
    nuvo_mutex_unlock(&cp_mutex);

    // lets assert that the lun is deleted
    NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&snap_lun->root_map_entry));

    g_lun = NULL;

    NUVO_ERROR_PRINT("snap lun (%d) map_entry type:%d addr:<%lu:%lu>",
                                    snap_lun->snap_id,
                                    snap_lun->root_map_entry.type,
                                    snap_lun->root_map_entry.media_addr.parcel_index,
                                    snap_lun->root_map_entry.media_addr.block_offset);
    // create snap(2)
    snap_lun = map_ut_create_snap(vol);
    map_ut_multi_write(active_lun, snap_lun, /*max iter = */256, /*num_blocks = */32, /*seq = */ false, &seed);

    g_lun = snap_lun; //to make the fake nuvo_get_lun_next_to_delete() for mfl to work
    map_ut_delete_lun_int(snap_lun);

    // wait for cp to be done
    nuvo_mutex_lock(&cp_mutex);
    nuvo_cond_wait(&cp_cond, &cp_mutex);
    nuvo_mutex_unlock(&cp_mutex);

    NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&snap_lun->root_map_entry));
    g_lun = NULL;
    //clean up
    // TODO stop the space thread we started.
    nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);

    nuvo_space_halt();
    nuvo_cond_destroy(&cp_cond);
    nuvo_mutex_destroy(&cp_mutex);

    lun_close_all();
    lun_dealloc_all();
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);

    NUVO_ERROR_PRINT("\n==================\nnuvo_map_test_mfl DONE !!\n=====================\n");
}
END_TEST

// do all of the previous simple mfl test but now with replay
// to do replay, we set up a replay lun
// and set log_replay_lun to the replay lun
// this would trigger a replay wherever we call nuvo_log_ack_sno()
// on the original lun
START_TEST(nuvo_map_test_mfl_replay)
{
    // start an active lun
    // set up a replay lun
    // create a snap
    // write to some offsets
    // delete the snap
    NUVO_ERROR_PRINT("\n===================\nnuvo_map_test_mfl_replay begin\n=====================\n");

    nuvo_log_set_level("map", 0);
    nuvo_log_set_level("space", 0);
    nuvo_log_set_level("lun", 100);

    nuvo_cond_init(&cp_cond);
    nuvo_mutex_init(&cp_mutex);
    nuvo_return_t rc = nuvo_space_init();
    NUVO_ASSERT(!rc);

    struct nuvo_vol *vol = &my_vol;
    struct nuvo_vol * vol_replay = &replay_vol;

    //general volume init for vol and replay vol
    map_ut_vol_init(vol);
    map_ut_vol_init(vol_replay);

    // create and init active luns for both the volumes
    map_ut_init_active(vol);
    map_ut_init_active(vol_replay);

    struct nuvo_lun * active_lun  = &vol->log_volume.lun;
    struct nuvo_lun * replay_lun  = &vol_replay->log_volume.lun;
    // setup log replay lun
    log_replay_lun = replay_lun;

    // write to the active max_iter random blocks
    int seed = 0;
    map_ut_multi_write(active_lun, /*snap_lun = */NULL, /*max iter = */1, /*num_blocks = */1, /*seq = */ true, &seed);

    // create snap
    struct nuvo_lun * snap_lun = map_ut_create_snap(vol);

    // write again to cow some blocks to the pit
    map_ut_multi_write(active_lun, snap_lun, /*max iter = */1, /*num_blocks = */1, /*seq = */ true, &seed);

    // fake log the "delete lun" op
    map_ut_log_delete_lun(vol, snap_lun);
    g_lun = snap_lun; //hack to make the fake nuvo_get_lun_next_to_delete() to work
    // and  queue the delete lun work to the fake space thread
    map_ut_delete_lun_int(snap_lun);

    // lets wait for the cp to finish, triggered by lun delete
    // the fake cp trigger have a cond broadcast
    nuvo_mutex_lock(&cp_mutex);
    nuvo_cond_wait(&cp_cond, &cp_mutex);
    nuvo_mutex_unlock(&cp_mutex);

    // lets assert that the lun is deleted
    NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&snap_lun->root_map_entry));

    g_lun = NULL;
    log_replay_lun = NULL; //we dont want any more replays


    NUVO_ERROR_PRINT("snap lun (%d) map_entry type:%d addr:<%lu:%lu>",
                                    snap_lun->snap_id,
                                    snap_lun->root_map_entry.type,
                                    snap_lun->root_map_entry.media_addr.parcel_index,
                                    snap_lun->root_map_entry.media_addr.block_offset);
    // clean up before you leave

    nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);

    lun_close_all();
    lun_dealloc_all();
    nuvo_map_lun_close(replay_lun, &replay_lun->root_map_entry);

    nuvo_space_halt();
    nuvo_cond_destroy(&cp_cond);
    nuvo_mutex_destroy(&cp_mutex);

    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);

    NUVO_ERROR_PRINT("\n==================\nnuvo_map_test_mfl_replay DONE !!\n=====================\n");
}
END_TEST
START_TEST(nuvo_map_test_map_free_rollup)
{
    int_fast64_t ret;
    strcpy(last_test_name, __func__);

    //nuvo_log_set_level("map", 100);

    NUVO_ERROR_PRINT("\n===================\nnuvo_map_test_free_rollup\n=====================\n");

    struct nuvo_vol *vol = &my_vol;
    struct nuvo_lun * active_lun  = &vol->log_volume.lun;
    //uint32_t overwrite_block_num = write_condition_params[_i].overwrite_start_bno;
   // uint8_t overwrite_num_blocks = write_condition_params[_i].overwrite_num_blocks;
    // we must first setup a vol and a lun for that vol
    nuvo_return_t rc = nuvo_mutex_init(&vol->mutex);
    NUVO_ASSERT(!rc);
    nuvo_map_writer_init(&vol->log_volume.map_state.writer, vol);
    // create and init lun
    map_ut_init_active(vol);
    //write to max_iter number of blocks in active
    int seed = 0;
    map_ut_multi_write(active_lun, /*snap_lun =*/NULL, /*max iter = */8192, /*num_blocks = */32, /*seq = */true, &seed);
    get_segment_usage();
    //lun close does a map cp.
    // now assert that the root map entry is NOT zero since we wrote something
    ret = nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);
    NUVO_ASSERT(!(NUVO_ME_IS_MFL_DONE(&active_lun->root_map_entry)));

    //open the lun again
    ret = nuvo_map_lun_open(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);

    uint32_t usage = get_segment_usage();
    NUVO_ASSERT(usage);
    //free the maps
    // fault in l0 maps and call free lun
    active_lun->mfl_state = NUVO_LUN_MFL_CP_PENDING; // to keep map code happy during roll ups

    //test roll up with mfl state
    ret = nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);
    // mfl not done assert since we didnt punch the L0s yet.
    NUVO_ASSERT(!NUVO_ME_IS_MFL_DONE(&active_lun->root_map_entry));

    //reopen and punch
    ret = nuvo_map_lun_open(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);

    for (int cnt = 0, blkno = 0; cnt < 8192; cnt++,blkno+= 256)
    {
        unsigned int numblks = 1;
        struct nuvo_map_request map_req;
        // Now punch holes on all the L0s
        // and leave them dirty. This would eventually roll up to the root
        // during evictions or CP
        nuvo_map_request_init(&map_req, active_lun, blkno, numblks);
        nuvo_map_reserve_sync(&map_req);
        NUVO_ASSERT(!map_req.status);
        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        nuvo_mutex_lock(&map_req.lun->vol->mutex);
        map_req.cp_commit_gen = map_req.lun->vol->log_volume.map_state.checkpoint_gen;
        nuvo_map_commit_lock(&map_req);
        nuvo_mutex_unlock(&map_req.lun->vol->mutex);

        map_mfl_free_entries(map_req.first_map);
        nuvo_map_commit_unlock(&map_req);

        struct nuvo_map_track *map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
        NUVO_ASSERT(!map);
        // ack to the logger
    }
    // For some day , when we want to test gc and FL
#if 0
    nuvo_map_request_init(&map_req, my_lun, block_num, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    nuvo_dlnode_init(&log_req0.list_node);
    log_req0.operation = NUVO_LOG_OP_DATA;
    log_req0.atomic = true;
    log_req0.tag.ptr = &log_signal;
    log_req0.vs_ptr = &my_vol;
    log_req0.data_class = NUVO_DATA_CLASS_A;
    log_req0.block_count = num_blocks;
    for(unsigned i = 0; i < num_blocks; i++)
    {
        log_req0.log_io_blocks[i].data = write_bufs[i];
        log_req0.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req0.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req0.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req0);
    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    // wait for logger
    nuvo_mutex_lock(&log_signal);
    // commit map
    uint_fast32_t succeeded;
    rc = nuvo_map_commit_gc_write(&map_req, log_req0.nuvo_map_entries, old_media_addrs, &succeeded);
    ck_assert(rc == 0);  // Overwrote whole range
    // verify that all maps were freed on the map_req
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);
    // ack to the logger
    nuvo_log_ack_sno(&log_req0);
#endif
    // lun close does a cp .
    // this must free interemdiate maps as well
    // now assert that the root map entry IS ZERO since we freed everything zero
    // and rolled up to the root
    ret = nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);
    NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&active_lun->root_map_entry));
    //reopen and ensure usage is zero
    // now that we freed, usage must be zero
    // close must have done a map cp which must have rolled up to the freeing to the root map block
    ret = nuvo_map_lun_open(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);

    usage = get_segment_usage();
    // assert everything is freed
    NUVO_ASSERT(!usage);

    ret = nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);
    NUVO_ASSERT(NUVO_ME_IS_MFL_DONE(&active_lun->root_map_entry));

    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
    active_lun->mfl_state = 0; // reset the global lun after use.
    NUVO_ERROR_PRINT("\n==================\nuvo_map_test_map_free_rollup DONE !!\n=====================\n");
    NUVO_ERROR_PRINT("\nlog_seq_completed:%d log_seq:%d\n=====================\n", log_seq_completed, log_seq);
}
END_TEST
START_TEST(nuvo_map_test_write_active_lun_conditional)
{
    strcpy(last_test_name, __func__);
    nuvo_map_test_write_conditional(_i, false);
}
END_TEST

START_TEST(nuvo_map_test_write_multi_lun_conditional)
{
    strcpy(last_test_name, __func__);
    nuvo_map_test_write_conditional(_i, true);
}
END_TEST


START_TEST(nuvo_map_test_map_flush)
{
    // goal is to get the map to flush by writing lots of CVs into it
    int_fast64_t ret;

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    uint8_t *write_bufs[128];
    for(unsigned i = 0; i < 128; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
    }
    // loop doing 128 block IOs from start of lun up to 32GB
    for(unsigned i = 0; i < 128*1024; i+=128)
    {
        // set write bufs to match block number
        for(int n = 0; n < 128; n++)
        {
            uint32_t *buf = (uint32_t*)write_bufs[n];
            for(unsigned m = 0; m < 4096 / sizeof(uint32_t); m++)
            {
                buf[m] = i+n;
            }
        }
        // do map request
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, i, 128);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // start logger
        nuvo_mutex_t log_signal;
        ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        struct nuvo_log_request log_req;
        nuvo_dlnode_init(&log_req.list_node);
        log_req.operation = NUVO_LOG_OP_DATA;
        log_req.atomic = true;
        log_req.tag.ptr = &log_signal;
        log_req.vs_ptr = &my_vol;
        log_req.data_class = NUVO_DATA_CLASS_A;
        log_req.block_count = 128;
        for(unsigned i = 0; i < 128; i++)
        {
            log_req.log_io_blocks[i].data = write_bufs[i];
            log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req.log_io_blocks[i].bno = map_req.block_start + i;
        }
        log_req.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req);

        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // wait for logger
        nuvo_mutex_lock(&log_signal);

        // commit map
        nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

        // ack to the logger
        nuvo_log_ack_sno(&log_req);
    }
    // clean up write bufs
    for(unsigned i = 0; i < 128; i++)
    {
        free(write_bufs[i]);
    }
    // read back the regions written, and verify map data
    // loop doing 128 block IOs from start of lun up to 32GB
    for(unsigned i = 0; i < 128*1024; i+=128)
    {
        // do map request
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, i, 128);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // read map
        struct nuvo_map_entry map_entries[128];
        uint_fast32_t pds[128];
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
        ck_assert_int_ge(map_req.status, 0);

        // check all map entries
        for(int n = 0; n < 128; n++)
        {
            uint32_t buf_num = i+n;
            ck_assert_int_eq(map_entries[n].type, NUVO_ME_CONST);
            ck_assert_uint_eq(map_entries[n].pattern,
                        ((uint64_t)(buf_num) << 32) | (buf_num));
        }

        // read-release map
        nuvo_map_read_release(my_lun, 128, map_entries);
    }

    nuvo_map_lun_close(my_lun, &root_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_map_fault)
{
    // goal is to get the map to flush by writing lots of CVs into it
    int_fast64_t ret;

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    uint8_t *write_bufs[128];
    for(unsigned i = 0; i < 128; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
    }
    // loop doing 128 block IOs from start of lun up to 32GB
    for(unsigned i = 0; i < 128*1024; i+=128)
    {
        // set write bufs to match block number
        for(int n = 0; n < 128; n++)
        {
            uint32_t *buf = (uint32_t*)write_bufs[n];
            for(unsigned m = 0; m < 4096 / sizeof(uint32_t); m++)
            {
                buf[m] = i+n;
            }
        }
        // do map request
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, i, 128);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // start logger
        nuvo_mutex_t log_signal;
        ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        struct nuvo_log_request log_req;
        nuvo_dlnode_init(&log_req.list_node);
        log_req.operation = NUVO_LOG_OP_DATA;
        log_req.atomic = true;
        log_req.tag.ptr = &log_signal;
        log_req.vs_ptr = &my_vol;
        log_req.data_class = NUVO_DATA_CLASS_A;
        log_req.block_count = 128;
        for(unsigned i = 0; i < 128; i++)
        {
            log_req.log_io_blocks[i].data = write_bufs[i];
            log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req.log_io_blocks[i].bno = map_req.block_start + i;
        }
        log_req.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req);

        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // wait for logger
        nuvo_mutex_lock(&log_signal);

        // commit map
        nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

        // ack to the logger
        nuvo_log_ack_sno(&log_req);
    }
    // clean up write bufs
    for(unsigned i = 0; i < 128; i++)
    {
        free(write_bufs[i]);
    }
    // read back the regions written, and verify map data
    // loop doing 128 block IOs from start of lun up to 32GB
    for(unsigned j = 0; j < 2*1024; j++)
    {
        unsigned i = lrand48() % (128*1024 - 128);

        // do map request
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, i, 128);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // read map
        struct nuvo_map_entry map_entries[128];
        uint_fast32_t pds[128];
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);
        nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
        ck_assert_int_ge(map_req.status, 0);

        // check all map entries
        for(int n = 0; n < 128; n++)
        {
            uint32_t buf_num = i+n;
            ck_assert_int_eq(map_entries[n].type, NUVO_ME_CONST);
            ck_assert_uint_eq(map_entries[n].pattern,
                        ((uint64_t)(buf_num) << 32) | (buf_num));
        }

        // read-release map
        nuvo_map_read_release(my_lun, 128, map_entries);
    }

    nuvo_map_lun_close(my_lun, &root_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST


void fake_map_checkpoint_start(struct nuvo_vol *vol)
{
    nuvo_mutex_lock(&vol->mutex);
    vol->log_volume.map_state.checkpoint_gen++;
    nuvo_mutex_unlock(&vol->mutex);
}

void fake_map_checkpoint_finish_cb(struct nuvo_map_checkpoint_req *req)
{
    nuvo_mutex_t *sync_signal = (nuvo_mutex_t*)req->tag.ptr;
    nuvo_mutex_unlock(sync_signal);
}

void nuvo_map_checkpoint_alloc_cb(struct nuvo_map_alloc_req *req);
void nuvo_map_checkpoint_sync_cb(struct nuvo_map_checkpoint_req *req);

void fake_map_checkpoint_finish(struct nuvo_map_checkpoint_req *req)
{
    nuvo_mutex_lock(&req->vol->mutex);
    req->prev_gen = req->vol->log_volume.map_state.checkpoint_gen - 1;
    req->cp_gen = req->vol->log_volume.map_state.checkpoint_gen;
    nuvo_mutex_unlock(&req->vol->mutex);
    nuvo_dlist_init(&req->map_list);
    req->lun = &req->vol->log_volume.lun;
    req->lun_cnt = 0;
    req->map_alloc_req.callback = nuvo_map_checkpoint_alloc_cb;
    req->map_alloc_req.count = req->vol->log_volume.lun.map_height * NUVO_MAP_CP_ALLOC_BATCH;
    req->map_alloc_req.map_list = &req->map_list;
    req->map_alloc_req.tag.ptr = req;

    nuvo_map_alloc_tables(&req->map_alloc_req, false);
}

nuvo_return_t fake_map_checkpoint_finish_sync(struct nuvo_vol *vol, struct nuvo_map_entry *map_entry)
{
    nuvo_return_t ret = 0;
    nuvo_mutex_t sync_signal;
    struct nuvo_map_checkpoint_req cp_req;
    ret = nuvo_mutex_init(&sync_signal);
    if (ret < 0)
    {
        return ret;
    }

    cp_req.tag.ptr = &sync_signal;
    cp_req.callback = nuvo_map_checkpoint_sync_cb;
    cp_req.vol = vol;
    //we have already bumped up the number.
    // cp_begin makes the cp_gen increment atomic with respect to the root map shadow.
    // This is not necessary here.
    cp_req.cp_begin = false;

    nuvo_mutex_lock(&sync_signal);

    fake_map_checkpoint_finish(&cp_req);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);

    *map_entry = cp_req.lun_cp_map_entry[0].root_map_entry;

    return cp_req.status;
}

typedef enum
{
    CLEAN_NONE = 0,
    CLEAN_FIRST,  // set first_map to be in CLEANING
    CLEAN_SECOND, // set last_map to be in CLEANING
    CLEAN_BOTH,   // set first_map and last_map to be in CLEANING
    CLEAN_REPRO_CUM_2234 // CUM 2234, make fault in see the first_map as CLEANING, details below

} clean_mode_t;

static void map_test_shadow(uint64_t bno, unsigned num_reqs, bool checkpoint, clean_mode_t clean_mode)
{
    int_fast64_t ret;
    bool write_on_clean = true;
    // goal of this test is to cause a map table to be in shadow state
    // More precisely, we cause a map to be in cleaing state and then
    // issue one or more writes to force shadowing.
    // If num_reqs is 2, two writes will be issued and the second will encounter
    // the shadow created by the first.
    // The test covers 8 blocks, so you can choose the starting bno to hit
    // one map or two.

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    uint32_t num_blocks = 8;
    // TODO - handle straddling higher boundary.
    unsigned num_map_blocks = 1 + ((bno + num_blocks - 1) / NUVO_MAP_RADIX) - (bno / NUVO_MAP_RADIX);
    for(unsigned i = 0; i < num_blocks; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, bno, num_blocks);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &log_signal;
    log_req.vs_ptr = &my_vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = num_blocks;
    for(unsigned i = 0; i < num_blocks; i++)
    {
        log_req.log_io_blocks[i].data = write_bufs[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);


    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map = map_req.first_map;
    struct nuvo_map_track * map2 = map_req.last_map;

    struct nuvo_map_track *tmap = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    NUVO_ASSERT(tmap ==  NULL);

    // verify that the segment usage was marked for the blocks written.
    ck_assert_uint_eq(segment_usage[0], num_blocks);

    // ack to the logger
    nuvo_log_ack_sno(&log_req);

    if (checkpoint)
    {
        fake_map_checkpoint_start(&my_vol);
    }

    switch(clean_mode)
    {
        case CLEAN_NONE:
            break;
        case CLEAN_FIRST:
        case CLEAN_SECOND:
        case CLEAN_BOTH:
            // force create a shadow map
            map_ut_force_clean(map, true);

            /*clean the second one , if we have been told so and if there is a second one */
            if ((clean_mode == CLEAN_BOTH) && (map != map2))
            {
                map_ut_force_clean(map2, true);
            }
            break;

            // CUM 2234 repro
            // this needs the condition that "nuvo_map_fault_in"
            // needs to run into in an L0 CLEANING map
            // The bug happens because we hold on to the parent map lock
            // if the "next map" in memory is CLEANING.
            // but since we also do this for the L0 map, we end up holding the parent map lock
            // even after fault in is done, causing eventual deadlocks.
            //
            // Also the maps cannot be already in memory during reserve
            // else reserve would make the L0 map as the fault in map.
            // And thus the fault in loop in nuvo_map_fault_in would not get executed.
            // So we evict the L0 map, before the next reserve
            // and interject a fault in of the L0 map and force the map to be in CLEANING.
            //
            //
        case CLEAN_REPRO_CUM_2234:

            // clean, wait for clean and evict the map
            // so that subsequent reserve doesnt see this map
            // and we can force a "fault in"

            map_ut_force_clean(map, true); //force clean
            map_ut_wait_clean(map); //wait for clean to be done
            map_ut_evict(map); // and evict the map

    }

    // the map should now be in the cleaning state (unless clean_mode == CLEAN_REPRO_CUM_2234)
    // now we do a write that is within it's range
    // do map request(s)
    struct nuvo_map_request map_reqs[2];
    struct nuvo_log_request log_reqs[2];
    nuvo_mutex_t log_signals[2];
    for (unsigned req_num = 0; req_num < num_reqs; req_num++)
    {
        NUVO_ASSERT(!(nuvo_mutex_init(&log_signals[req_num])));
    }

do_writes:

    for (unsigned req_num = 0; req_num < num_reqs; req_num++)
    {
        nuvo_map_request_init(&map_reqs[req_num], my_lun, bno, num_blocks);
        nuvo_map_reserve_sync(&map_reqs[req_num]);
        NUVO_ASSERT(!map_reqs[req_num].status);

        // start logger
        nuvo_mutex_lock(&log_signals[req_num]);

        nuvo_dlnode_init(&log_reqs[req_num].list_node);
        log_reqs[req_num].operation = NUVO_LOG_OP_DATA;
        log_reqs[req_num].atomic = true;
        log_reqs[req_num].tag.ptr = &log_signals[req_num];
        log_reqs[req_num].vs_ptr = &my_vol;
        log_reqs[req_num].data_class = NUVO_DATA_CLASS_A;
        log_reqs[req_num].block_count = num_blocks;
        for(unsigned i = 0; i < num_blocks; i++)
        {
            log_reqs[req_num].log_io_blocks[i].data = write_bufs[i];
            log_reqs[req_num].log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_reqs[req_num].log_io_blocks[i].bno = map_reqs[req_num].block_start + i;
        }
        log_reqs[req_num].callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_reqs[req_num]);

        // We interject the current request with another fault in
        // (simulate a multi thread fault in).
        // and then force the map to be in CLEANING.
        // This would cause the subsequent fault in in the "nuvo_map_fault_in" loop
        // so see the map as INMEM but CLEANING causing CUM-2234
        //
        struct nuvo_map_request req;
        if (clean_mode == CLEAN_REPRO_CUM_2234)
        {
             map_ut_reserve_and_fault_in(&req, my_lun, bno, num_blocks);

             // read_lock and unlock to release the above pinned faulted in maps
             nuvo_map_read_lock(&req);
             nuvo_map_read_unlock(&req);

             // now make the map as CLEANING
             map_ut_force_clean(req.first_map, false);
        }

        // fault-in map
        nuvo_map_fault_in_sync(&map_reqs[req_num]);
        NUVO_ASSERT(!map_reqs[req_num].status);


    }

    for (unsigned req_num = 0; req_num < num_reqs; req_num++)
    {
        // wait for logger
        nuvo_mutex_lock(&log_signals[req_num]);

        // commit map, which encounters clean and creates shadow
        nuvo_map_commit_write(&map_reqs[req_num], log_reqs[req_num].nuvo_map_entries);

        // verify that all maps were freed on the map_reqs[req_num]
        map = nuvo_dlist_get_head_object(&map_reqs[req_num].map_list, struct nuvo_map_track, list_node);
        NUVO_ASSERT(!map);

        // verify that the segment usage was marked for the blocks written
        // this has to be disabled now that we have cp running who needs map blocks
        // so the segment_usage cant be same as the number of blocks.
        //NUVO_ASSERT(segment_usage[0] ==  num_blocks);

        // ack to the logger
        nuvo_log_ack_sno(&log_reqs[req_num]);
        nuvo_mutex_unlock(&log_signals[req_num]);
    }

    /* our maps are clean now after CP.
       now write on the clean ones with a checkpoint in progress */
    NUVO_ERROR_PRINT("segment usage[0] :%d num_blocks:%d", segment_usage[0], num_blocks);
    if (checkpoint)
    {
        struct nuvo_map_entry cp_map_entry;
        fake_map_checkpoint_finish_sync(&my_vol, &cp_map_entry);

        if(write_on_clean)
        {
            write_on_clean = false;

            // we do another cp start and finish
            // we did the last writes for the next cp, so this ( ie the one we are going to do)
            // must clean everything
            // after the clean ,we would do writes again so that the writes overwrite
            // clean but onmem maps

            fake_map_checkpoint_start(&my_vol);
            // every thing must be clean now.
            fake_map_checkpoint_finish_sync(&my_vol, &cp_map_entry);

            // start another cp and write.
            // this time we would overwrite clean maps.
            fake_map_checkpoint_start(&my_vol);

            goto do_writes;
        }
    }


    nuvo_map_writer_lock(&my_vol);
    nuvo_map_writer_flush(&my_vol);

    for(unsigned i = 0; i < num_blocks; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }


    nuvo_map_lun_close(my_lun, &root_map_entry);

    // verify that the segment usage was marked for the blocks written, plus the map(s), plus
    // two higher level maps.
    ck_assert_uint_eq(segment_usage[0], num_blocks + num_map_blocks + (my_lun->map_height - 1));
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}

START_TEST(nuvo_map_test_shadow_1)
{
    map_test_shadow(20, 1, false, CLEAN_FIRST);
}
END_TEST
START_TEST(nuvo_map_test_CUM_2234)
{
    map_test_shadow(20, 1, false, CLEAN_REPRO_CUM_2234);
}
END_TEST

START_TEST(nuvo_map_test_shadow_split_1)
{
    map_test_shadow(250, 1, false, CLEAN_FIRST);
}
END_TEST
START_TEST(nuvo_map_test_shadow_split_1_clean_second)
{
    map_test_shadow(250, 1, false, CLEAN_SECOND);
}
END_TEST

START_TEST(nuvo_map_test_shadow_2)
{
    map_test_shadow(20, 2, false, CLEAN_FIRST);
}
END_TEST

START_TEST(nuvo_map_test_shadow_split_2)
{
    map_test_shadow(250, 2, false, CLEAN_FIRST);
}
END_TEST
START_TEST(nuvo_map_test_shadow_split_2_clean_second)
{
    map_test_shadow(250, 2, false, CLEAN_SECOND);
}
END_TEST

START_TEST(nuvo_map_test_shadow_1_cp)
{
    map_test_shadow(20, 1, true, CLEAN_FIRST);
}
END_TEST

START_TEST(nuvo_map_test_shadow_split_1_cp)
{
    map_test_shadow(250, 1, true, CLEAN_FIRST);
}
END_TEST

START_TEST(nuvo_map_test_shadow_split_1_clean_second_cp)
{
    map_test_shadow(250, 1, true, CLEAN_SECOND);
}
END_TEST
START_TEST(nuvo_map_test_shadow_2_cp)
{
    map_test_shadow(20, 2, true, CLEAN_FIRST);
}
END_TEST

START_TEST(nuvo_map_test_shadow_split_2_cp)
{
    map_test_shadow(250, 2, true, CLEAN_FIRST);
}
END_TEST
START_TEST(nuvo_map_test_shadow_split_2_clean_second_cp)
{
    map_test_shadow(250, 2, true, CLEAN_SECOND);

}
END_TEST
START_TEST(nuvo_map_test_shadow_split_2_clean_both_cp)
{
    map_test_shadow(250, 2, true, CLEAN_BOTH);
}
END_TEST
START_TEST(nuvo_map_test_cp_and_writes)
{
    map_test_shadow(20, 2, true, CLEAN_NONE);
}
END_TEST
START_TEST(nuvo_map_test_split_2_cp_and_writes)
{
    map_test_shadow(250, 2, true, CLEAN_NONE);
}
END_TEST

START_TEST(nuvo_map_test_open_close)
{
    int_fast64_t ret;
    // in this test we are going to:
    //      create a new lun map
    //      write some data to lun map
    //      close the lun map
    //      re-open the lun map
    //      read and verify original data written
    //      close the lun map

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &log_signal;
    log_req.vs_ptr = &my_vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req.log_io_blocks[i].data = write_bufs[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

    // verify that all maps were freed on the map_req
    struct nuvo_map_track *map;
    map = nuvo_dlist_get_head_object(&map_req.map_list, struct nuvo_map_track, list_node);
    ck_assert_ptr_eq(map, NULL);

    // verify that the segment usage was marked
    ck_assert_uint_eq(segment_usage[0], 32);

    // ack to the logger
    nuvo_log_ack_sno(&log_req);

    // close the lun map
    ret = nuvo_map_lun_close(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // open the lun map again
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // map read and pin
    struct nuvo_map_entry map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    // verify that map returned exactly what we wrote earlier
    for(int i = 0; i < 32; i++)
    {
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].type,
                          map_entries[i].type);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[i].media_addr.parcel_index);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[i].media_addr.block_offset);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].pattern,
                          map_entries[i].pattern);
    }

    // verify segment pinning
    ck_assert_uint_eq(segment_pin[0], 32);

    // read the data and verify it is the same (just some test sanity checking)
    nuvo_mutex_t signal;
    nuvo_mutex_init(&signal);
    for(int i = 0; i < 32; i++)
    {
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&signal);
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = pds[i];
        req->rw.block_count = 1;
        req->rw.block_offset = map_entries[i].media_addr.block_offset;
        req->rw.iovecs[0].iov_base = read_bufs[i];
        req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;

        nuvo_pr_sync_submit(req, &signal);

        ck_assert_int_eq(memcmp(read_bufs[i], write_bufs[i], NUVO_BLOCK_SIZE), 0);

        nuvo_pr_client_req_free(req);
    }

    // read-release map data
    nuvo_map_read_release(my_lun, 32, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }

    ret = nuvo_map_lun_close(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // one last plain open-close
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);
    ret = nuvo_map_lun_close(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_dirty_close)
{
    // goal is to get the map to flush by writing lots of CVs into it
    int_fast64_t ret;

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    uint8_t *write_bufs[128];
    for(unsigned i = 0; i < 128; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
    }

    // do writes until we have a lot of dirty maps
    for(unsigned i = 0; nuvo_map->mixed_count < nuvo_map->clean_count/2; i+=128)
    {
        // set write bufs to match block number
        for(int n = 0; n < 128; n++)
        {
            uint32_t *buf = (uint32_t*)write_bufs[n];
            for(unsigned m = 0; m < 4096 / sizeof(uint32_t); m++)
            {
                buf[m] = i+n;
            }
        }
        // do map request
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, i, 128);
        nuvo_map_reserve_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // start logger
        nuvo_mutex_t log_signal;
        ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        struct nuvo_log_request log_req;
        nuvo_dlnode_init(&log_req.list_node);
        log_req.operation = NUVO_LOG_OP_DATA;
        log_req.atomic = true;
        log_req.tag.ptr = &log_signal;
        log_req.vs_ptr = &my_vol;
        log_req.data_class = NUVO_DATA_CLASS_A;
        log_req.block_count = 128;
        for(unsigned i = 0; i < 128; i++)
        {
            log_req.log_io_blocks[i].data = write_bufs[i];
            log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req.log_io_blocks[i].bno = map_req.block_start + i;
        }
        log_req.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req);

        // fault-in map
        nuvo_map_fault_in_sync(&map_req);
        ck_assert_int_ge(map_req.status, 0);

        // wait for logger
        nuvo_mutex_lock(&log_signal);

        // commit map
        nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

        // ack to the logger
        nuvo_log_ack_sno(&log_req);
    }
    // clean up write bufs
    for(unsigned i = 0; i < 128; i++)
    {
        free(write_bufs[i]);
    }

    // close, forcing a checkpoint

    nuvo_map_lun_close(my_lun, &root_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_checkpoint)
{
    int_fast64_t ret;
    // in this test we are going to:
    //      create a new lun map
    //      write some data to lun map
    //      checkpoint the lun map
    //      write some more data to lun map
    //      close the lun map
    //      re-open the lun map at the checkpoint
    //      read and verify original data written
    //      close the lun map

    // create and init vol
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &log_signal;
    log_req.vs_ptr = &my_vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req.log_io_blocks[i].data = write_bufs[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

    // ack to the logger
    nuvo_log_ack_sno(&log_req);

    // checkpoint the lun map
    struct nuvo_map_entry cp_map_entry;
    ret = nuvo_map_checkpoint_sync(&my_vol, &cp_map_entry);
    ck_assert_int_ge(ret, 0);

    // overwrite the previous data
    for(unsigned i = 0; i < 32; i++)
    {
        memset(write_bufs[i], i + 42, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
    }
    // do map request
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req_ow;
    nuvo_dlnode_init(&log_req_ow.list_node);
    log_req_ow.operation = NUVO_LOG_OP_DATA;
    log_req_ow.atomic = true;
    log_req_ow.tag.ptr = &log_signal;
    log_req_ow.vs_ptr = &my_vol;
    log_req_ow.data_class = NUVO_DATA_CLASS_A;
    log_req_ow.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req_ow.log_io_blocks[i].data = write_bufs[i];
        log_req_ow.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req_ow.log_io_blocks[i].bno = map_req.block_start + i;
    }
    log_req_ow.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req_ow);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req_ow.nuvo_map_entries);

    // ack to the logger
    nuvo_log_ack_sno(&log_req_ow);

    // close the lun map
    ret = nuvo_map_lun_close(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // open the lun map again
    ret = nuvo_map_lun_open(my_lun, &cp_map_entry);
    ck_assert_int_ge(ret, 0);

    // map read and pin
    struct nuvo_map_entry map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    // verify that map returned exactly what we wrote earlier
    for(int i = 0; i < 32; i++)
    {
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].type,
                          map_entries[i].type);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[i].media_addr.parcel_index);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[i].media_addr.block_offset);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].pattern,
                          map_entries[i].pattern);
    }

    // verify segment pinning
    ck_assert_uint_eq(segment_pin[0], 32);

    // re-generate original data
    for(unsigned i = 0; i < 32; i++)
    {
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
    }

    // read the data and verify it is the same (just some test sanity checking)
    nuvo_mutex_t signal;
    nuvo_mutex_init(&signal);
    for(int i = 0; i < 32; i++)
    {
        struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&signal);
        req->operation = NUVO_OP_READ;
        req->rw.parcel_desc = pds[i];
        req->rw.block_count = 1;
        req->rw.block_offset = map_entries[i].media_addr.block_offset;
        req->rw.iovecs[0].iov_base = read_bufs[i];
        req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;

        nuvo_pr_sync_submit(req, &signal);

        ck_assert_int_eq(memcmp(read_bufs[i], write_bufs[i], NUVO_BLOCK_SIZE), 0);

        nuvo_pr_client_req_free(req);
    }

    // read-release map data
    nuvo_map_read_release(my_lun, 32, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }

    ret = nuvo_map_lun_close(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // one last plain open-close
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);
    ret = nuvo_map_lun_close(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_simple_replay)
{
    int_fast64_t ret;
    // goal is to do a basic write-then-read test
    // we must first setup a vol and a lun for that vol

    // create and init vol
    nuvo_log_set_level("map", 100);
    NUVO_PRINT("\n**********begin %s*********\n", __func__);
    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // create and init another vol
    ck_assert_int_eq(nuvo_mutex_init(&replay_vol.mutex), 0);
    nuvo_map_writer_init(&replay_vol.log_volume.map_state.writer, &replay_vol);

    // create and init lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);

    // create and init another lun
    struct nuvo_lun *replay_lun = &replay_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&replay_lun->mutex), 0);
    replay_lun->vol = &replay_vol;
    replay_lun->size = 1ull << 36;
    replay_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(replay_lun);

    // get a map
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // get a map for replay
    struct nuvo_map_entry replay_map_entry;
    replay_map_entry.cow = 0;
    replay_map_entry.type = NUVO_ME_CONST;
    replay_map_entry.unused = 0;
    replay_map_entry.media_addr.parcel_index = 0;
    replay_map_entry.media_addr.block_offset = 0;
    replay_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(replay_lun, &replay_map_entry);
    ck_assert_int_ge(ret, 0);

    // setup log replay lun
    log_replay_lun = replay_lun;

    // get some data to write
    uint8_t *write_bufs[32];
    uint8_t *read_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(write_bufs[i], NULL);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
        write_bufs[i][0] = ~write_bufs[i][0];
        read_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        ck_assert_ptr_ne(read_bufs[i], NULL);
    }
    // do map request
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // start logger
    nuvo_mutex_t log_signal;
    ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
    nuvo_mutex_lock(&log_signal);

    struct nuvo_log_request log_req;
    nuvo_dlnode_init(&log_req.list_node);
    log_req.operation = NUVO_LOG_OP_DATA;
    log_req.atomic = true;
    log_req.tag.ptr = &log_signal;
    log_req.vs_ptr = &my_vol;
    log_req.data_class = NUVO_DATA_CLASS_A;
    log_req.block_count = 32;
    for(unsigned i = 0; i < 32; i++)
    {
        log_req.log_io_blocks[i].data = write_bufs[i];
        log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
        log_req.log_io_blocks[i].bno = map_req.block_start + i;
        LOG_PIT_INFO_SET_DATA(log_req.log_io_blocks[i].pit_info, 1, 2); // 2 is fake next_pit.
    }
    log_req.callback = nuvo_map_test_log_cb;
    nuvo_log_submit(&log_req);

    // fault-in map
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);

    // wait for logger
    nuvo_mutex_lock(&log_signal);

    // commit map
    nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

    // ack to the logger (this will trigger replay)
    nuvo_log_ack_sno(&log_req);

    // map read and pin
    struct nuvo_map_entry map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, replay_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);


    // verify that replay map returned exactly what we wrote earlier
    for(int i = 0; i < 32; i++)
    {
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].type,
                          map_entries[i].type);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[i].media_addr.parcel_index);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[i].media_addr.block_offset);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].pattern,
                          map_entries[i].pattern);
    }

    // read-release map data
    nuvo_map_read_release(replay_lun, 32, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
        free(read_bufs[i]);
    }

    // we're done, clean up the maps
    nuvo_map_lun_close(my_lun, &root_map_entry);

    log_replay_lun = NULL;

    // closing the replay map will cause a checkpoint, which is meaningless
    //  since the replay lun is just a big hack here, but we need to free the
    //  resources
    nuvo_map_lun_close(replay_lun, &replay_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST


START_TEST(nuvo_map_test_replay_extended)
{
    // This test's purpose is to test replay of a L1 map
    // while it has some children in memory
    // (CUM 1410)

    // we want the parent level maps to be flushed while
    // the L0s are still in memory
    // We use GC map rewrite just to rewrite the L1 map
    // For this we need a CP, gc rewrite and a data op
    // While CP is writing out a GC dirtied map, we want a data op to
    // intersect

    // The steps are as follows.
    // First, we write something and close the lun
    // this ensures there is some media address given to the path
    // Now, we reload the parent L1 map and dirty it using gc_rewrite.
    // Then, we start a CP.
    // create a shadow of the above L1 map
    // and pretend that a a data op came in the middle of CP
    // do a data op, dirty the L0 map
    // and now let the shadow get written ,
    // and let the CP

    // setup log replay lun to NULL
    // we will write something and close the lun first

    NUVO_PRINT("\n\n**********begin %s*********\n\n", __func__);
    log_replay_lun = NULL;

    ck_assert_int_eq(nuvo_mutex_init(&my_vol.mutex), 0);
    nuvo_map_writer_init(&my_vol.log_volume.map_state.writer, &my_vol);

    // set up the active lun
    struct nuvo_lun *my_lun = &my_vol.log_volume.lun;
    ck_assert_int_eq(nuvo_mutex_init(&my_lun->mutex), 0);
    my_lun->vol = &my_vol;
    my_lun->size = 1ull << 36;
    my_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(my_lun);
    struct nuvo_map_entry root_map_entry;
    root_map_entry.cow = 0;
    root_map_entry.type = NUVO_ME_CONST;
    root_map_entry.unused = 0;
    root_map_entry.media_addr.parcel_index = 0;
    root_map_entry.media_addr.block_offset = 0;
    root_map_entry.pattern = 0;
    nuvo_return_t ret = nuvo_map_lun_open(my_lun, &root_map_entry);
    ck_assert_int_ge(ret, 0);

    // setup the replay lun
    struct nuvo_lun *replay_lun = &replay_vol.log_volume.lun;
    ret = nuvo_mutex_init(&replay_lun->mutex);
    NUVO_ASSERT(!ret);
    replay_lun->vol = &replay_vol;
    replay_lun->size = 1ull << 36;
    replay_lun->map_height = 3;
    NUVO_LUN_SET_ACTIVE(replay_lun);
    struct nuvo_map_entry replay_map_entry;
    replay_map_entry.cow = 0;
    replay_map_entry.type = NUVO_ME_CONST;
    replay_map_entry.unused = 0;
    replay_map_entry.media_addr.parcel_index = 0;
    replay_map_entry.media_addr.block_offset = 0;
    replay_map_entry.pattern = 0;
    ret = nuvo_map_lun_open(replay_lun, &replay_map_entry);
    NUVO_ASSERT(!ret);

    // every log ack sno from here is a replay op on the replay lun
    log_replay_lun = replay_lun;

    // get some data to write

    uint8_t *write_bufs[32];
    for(unsigned i = 0; i < 32; i++)
    {
        write_bufs[i] = aligned_alloc(NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
        NUVO_ASSERT(write_bufs[i]);
        memset(write_bufs[i], i, NUVO_BLOCK_SIZE);
    }

    //lets write some data  , close and reopen the lun
    // so that we have media addr for gc to rewrite
    struct nuvo_log_request log_req;
    {
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, 20, 32);
        nuvo_map_reserve_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        // start logger
        nuvo_mutex_t log_signal;
        ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        nuvo_dlnode_init(&log_req.list_node);
        log_req.operation = NUVO_LOG_OP_DATA;
        log_req.atomic = true;
        log_req.tag.ptr = &log_signal;
        log_req.vs_ptr = &my_vol;
        log_req.data_class = NUVO_DATA_CLASS_A;
        log_req.block_count = 32;
        for(unsigned i = 0; i < 32; i++)
        {
            log_req.log_io_blocks[i].data = write_bufs[i];
            log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req.log_io_blocks[i].bno = map_req.block_start + i;
            LOG_PIT_INFO_SET_DATA(log_req.log_io_blocks[i].pit_info, 1, 2); // 2 is fake next_pit.
        }

        log_req.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req);

        nuvo_map_fault_in_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        nuvo_mutex_lock(&log_signal);
        nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

        nuvo_log_ack_sno(&log_req);

        // close and reopen the lun

        struct nuvo_map_entry root_map_entry;
        nuvo_return_t rc = nuvo_map_lun_close(my_lun, &root_map_entry);
        NUVO_ASSERT(!rc);
        rc = nuvo_map_lun_open(my_lun, &root_map_entry);
        NUVO_ASSERT(!rc);

    }

    // do gc rewrite of the L1 map
    struct nuvo_map_request map_req;
    nuvo_map_request_init(&map_req, my_lun, 20, 32);
    map_req.target_level = 1; //load the level 1 map
    nuvo_map_reserve_sync(&map_req);
    NUVO_ASSERT(!map_req.status);

    nuvo_map_fault_in_sync(&map_req);
    NUVO_ASSERT(!map_req.status);

    struct nuvo_map_entry map_entry;
    map_req.map_entries = &map_entry;
    map_req.map_entries[0].type = map_req.first_map->map_entry.type;
    map_req.map_entries[0].media_addr = map_req.first_map->map_entry.media_addr;

    //use gc map move interface to rewrite the map at L1
    nuvo_map_rewrite(&map_req);

    //make a map list for the shadow_reg to work
    struct nuvo_dlist map_list;
    nuvo_dlist_init(&map_list);
    struct nuvo_map_track *cur_map = nuvo_dlist_get_tail_object(&nuvo_map->clean_lru_list, struct nuvo_map_track, list_node);
    nuvo_mutex_lock(&nuvo_map->list_mutex);
    nuvo_map_clean_remove(cur_map);
    nuvo_mutex_unlock(&nuvo_map->list_mutex);
    nuvo_dlist_insert_head(&map_list, &cur_map->list_node);

    // start CP and take CP to the point of making a shadow of the L1 map
    fake_map_checkpoint_start(&my_vol);
    nuvo_mutex_lock(&map_req.first_map->mutex);
    ret = nuvo_map_shadow_reg(&map_list, map_req.first_map);
    MAP_SET_CP(map_req.first_map, my_vol.log_volume.map_state.checkpoint_gen);

    struct nuvo_map_track *shadow = map_req.first_map->shadow_link;
    nuvo_mutex_unlock(&map_req.first_map->mutex);

    // now inject a data op in parallel
    {
        struct nuvo_map_request map_req;
        nuvo_map_request_init(&map_req, my_lun, 20, 32);
        nuvo_map_reserve_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        nuvo_mutex_t log_signal;
        ck_assert_int_eq(nuvo_mutex_init(&log_signal), 0);
        nuvo_mutex_lock(&log_signal);

        nuvo_dlnode_init(&log_req.list_node);
        log_req.operation = NUVO_LOG_OP_DATA;
        log_req.atomic = true;
        log_req.tag.ptr = &log_signal;
        log_req.vs_ptr = &my_vol;
        log_req.data_class = NUVO_DATA_CLASS_A;
        log_req.block_count = 32;
        for(unsigned i = 0; i < 32; i++)
        {
            log_req.log_io_blocks[i].data = write_bufs[i];
            log_req.log_io_blocks[i].log_entry_type = NUVO_LE_DATA;
            log_req.log_io_blocks[i].bno = map_req.block_start + i;
            LOG_PIT_INFO_SET_DATA(log_req.log_io_blocks[i].pit_info, 1, 2); // 2 is fake next_pit.
        }

        log_req.callback = nuvo_map_test_log_cb;
        nuvo_log_submit(&log_req);

        nuvo_map_fault_in_sync(&map_req);
        NUVO_ASSERT(!map_req.status);

        nuvo_mutex_lock(&log_signal);
        nuvo_map_commit_write(&map_req, log_req.nuvo_map_entries);

        nuvo_log_ack_sno(&log_req);
    }

    // flush the map (like a real CP would do)

    // the log ack seq no of the flush map will trigger replay
    // will cause the L1 to be replayed with a child in memory
    // and cause the assert in CUM 1410

    nuvo_mutex_lock(&shadow->mutex);
    nuvo_map_writer_add_map(shadow, NUVO_MW_FLUSH_FORCE);

    struct nuvo_map_entry cp_map_entry;
    // wait for CP to be done, this will make sure the log flush callbacks are done
    fake_map_checkpoint_finish_sync(&my_vol, &cp_map_entry);


    // read back from the replay lun to verify
    struct nuvo_map_entry map_entries[32];
    uint_fast32_t pds[32];
    nuvo_map_request_init(&map_req, replay_lun, 20, 32);
    nuvo_map_reserve_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_fault_in_sync(&map_req);
    ck_assert_int_ge(map_req.status, 0);
    nuvo_map_read_and_pin_sync(&map_req, true, map_entries, pds);
    ck_assert_int_ge(map_req.status, 0);

    // verify that replay map returned exactly what we wrote earlier
    for(int i = 0; i < 32; i++)
    {
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].type,
                          map_entries[i].type);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.parcel_index,
                          map_entries[i].media_addr.parcel_index);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].media_addr.block_offset,
                          map_entries[i].media_addr.block_offset);
        ck_assert_uint_eq(log_req.nuvo_map_entries[i].pattern,
                          map_entries[i].pattern);
    }

    // read-release map data
    nuvo_map_read_release(replay_lun, 32, map_entries);

    for(unsigned i = 0; i < 32; i++)
    {
        free(write_bufs[i]);
    }

    // we're done, clean up the maps
    nuvo_map_lun_close(my_lun, &root_map_entry);

    log_replay_lun = NULL;

    // closing the replay map will cause a checkpoint, which is meaningless
    //  since the replay lun is just a big hack here, but we need to free the
    //  resources
    nuvo_map_lun_close(replay_lun, &replay_map_entry);
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);
}
END_TEST

START_TEST(nuvo_map_test_intermediate_shadow)
{
    NUVO_LOG(map, 80 , "\n\n******begin %s**********\n\n", __func__);
    __nuvo_map_test_intermediate_shadow();
}
END_TEST

// CUM-2460 repro test
// hopefully john would appreciate the usage of nice map ut functions:)
// steps:
// force clean a map and write to the map to force a shadow.
// now we have a cleaning shadow and a live map at cp gen 0
// dont flush the shadow out so that next CP can see the shadow.
// Now, start a CP now for cp_gen: 0 -> 1.
// CP sees a shadow and will wait for it to be written out.
// Now the shadow(cp_gen:0) will get written out and will write its address to the parent shadow (at cp_gen:0) in CP.
// This finishes the CP but however would leave the live map at cp_gen:0
// next cp from 1 -2 will assert req->prev_gen == map->cp_gen
// 
START_TEST(nuvo_map_test_CUM_2460)
{
    struct nuvo_vol * vol = &my_vol;

    // init vol and luns etc 
    // TODO : shouldnt this be in test set up?
    map_ut_vol_init(vol);
    map_ut_init_active(vol);

    struct nuvo_lun * active_lun = &vol->log_volume.lun;
    // write to offset 0 , 1 block 
    map_ut_multi_write(active_lun, NULL, /*max_iter = */1, /*num_blocks = */1, /*seq * = */true, /*random_seed = */NULL);

    // read the one map block back
    struct nuvo_map_request req;
    map_ut_read_map(&req, active_lun,/*bno = */ 1);

    struct nuvo_map_track *map = req.first_map;
    // put the map in cleaning
    map_ut_force_clean(map, /*flush =*/false);
    NUVO_ASSERT(map->state == NUVO_MAP_CLEANING);

    // write to offset 0, 1 block
    // this will force a shadow and a live map 
    // note that the live map cp gen is 0 since we havent started any CP.
    map_ut_multi_write(active_lun, NULL, /*max_iter = */1, /*num_blocks = */1, /*seq * = */true, /*random_seed = */NULL);
    NUVO_ASSERT(map->state == NUVO_MAP_SHADOW);

    // start a cp, for cp_gen from 0 -> 1
    {
        fake_map_checkpoint_start(vol); 
        // and do the cp
        struct nuvo_map_entry cp_map_entry;
        fake_map_checkpoint_finish_sync(vol, &cp_map_entry);
    }

    // now cp would see the shadow and wait
    // now we flush the shadow map. This would finish the CP
    // but however would leave the live map at cp gen 0
    nuvo_map_writer_lock(vol);
    nuvo_map_writer_flush(vol);


    ///lets do another cp, this will run into the map at cp gen 0
    {
        fake_map_checkpoint_start(vol); 
        struct nuvo_map_entry cp_map_entry;
        fake_map_checkpoint_finish_sync(vol, &cp_map_entry);
 
    }
    nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
}
END_TEST

void __nuvo_map_test_intermediate_shadow()
{
    // set up active.
    // write to 3-4 L1 maps, something to active.
    // get the intermediate map ptr
    // evict children.
    // make the intermediate map as cleaning.
    // read a few children .this must go to disk and trigger a read callback
    // In parallell, or as a next step, create a pit
    // read the path now  ->this will trigger percolate on a cleaning L1 map
    // and result in a shadow.

    // create and init vol
    struct nuvo_vol *vol = &my_vol;
    nuvo_return_t rc = nuvo_mutex_init(&vol->mutex);
    NUVO_ASSERT(!rc);
    nuvo_map_writer_init(&vol->log_volume.map_state.writer, vol);
    // create and init lun
    map_ut_init_active(vol);
    struct nuvo_lun * active_lun  = &vol->log_volume.lun;

    /*1024 iterations seq covers 4 map blocks */
    map_ut_multi_write(active_lun, /*snap_lun = */NULL, /*max_iter = */1024, /*num_blocks = */32,
                         /*seq = */true, /*seed = */NULL);

    // close and reopen the lun for clearing out dirty maps
    // we can only evict clean maps
    nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    nuvo_return_t ret = nuvo_map_lun_open(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);

    //fault in
    uint_fast64_t block = 0;
    struct nuvo_map_track *parent;

    for (int i = 0; i < 4; i++)
    {
        struct nuvo_map_request map_req;
        map_ut_reserve_fault_in(&map_req, active_lun, block);
        parent = map_req.first_map->parent;

        nuvo_map_read_lock(&map_req); // to release the pins
        nuvo_map_read_unlock(&map_req);
        NUVO_ASSERT((map_req.first_map == map_req.last_map));
        // Evict the children
        map_ut_evict(map_req.first_map);
        block += 256;
    }

    // set the parent map as CLEANING
    map_ut_set_map_cleaning(parent);

    // CUM-2383 deadlock when fault in an interemdiate CLEANING map
    // parent is in CLEANING and at level 1 now, so lets try fault-in that
    //

    {
        struct nuvo_map_request map_req;
        int level = 1;
        block = 0;
        map_ut_reserve_fault_in_intermediate(&map_req, active_lun, block, level);
        NUVO_ASSERT(map_req.first_map == map_req.last_map);
        nuvo_map_read_lock(&map_req); // to release the pins
        nuvo_map_read_unlock(&map_req);
    }

    // read two children
    block = 0;
    for (int i = 0; i < 2; i++)
    {
        struct nuvo_map_request map_req;
        map_ut_reserve_fault_in(&map_req, active_lun, block);
        NUVO_ASSERT(map_req.first_map == map_req.last_map);
        nuvo_map_read_lock(&map_req); // to release the pins
        nuvo_map_read_unlock(&map_req);
        block += 256;
    }

    // now we have cleaning L1 map with two children
    // lets create a  pit and read

    // create a pit !!
    struct nuvo_lun * snap_lun = map_ut_create_snap(vol);
    NUVO_ASSERT(snap_lun);

    for (int i = 0; i < 4; i++)
    {
        struct nuvo_map_request map_req;
        map_ut_reserve_fault_in(&map_req, active_lun, block);
        nuvo_map_read_lock(&map_req); // to release the pins
        nuvo_map_read_unlock(&map_req);
        block += 256;
    }

    nuvo_map_writer_lock(&my_vol);
    nuvo_map_writer_flush(vol);
    sleep(1); // for the flush callbacks to be done in the logger thread.
    rc = nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!rc);

    lun_close_all();
    lun_dealloc_all();
    nuvo_map_writer_destroy(&my_vol.log_volume.map_state.writer);

}

START_TEST(nuvo_map_test_percolate_and_cp)
{
    NUVO_LOG(map, 80 , "\n\n******begin %s**********\n\n", __func__);
    __nuvo_map_test_percolate_and_cp();
}
END_TEST

// purpose of the test is
// to exercise the code path of intersecting cp with percolate.
//
// steps:
// set up active.
// write to 3-4 L1 maps, something to active.
// create a pit
// start a fake cp
// read the path now -> this will trigger percolate intersecting a cp
//
//
void __nuvo_map_test_percolate_and_cp()
{

    // create and init vol
    struct nuvo_vol *vol = &my_vol;
    uint_fast64_t block;
    nuvo_return_t rc = nuvo_mutex_init(&vol->mutex);
    NUVO_ASSERT(!rc);
    nuvo_map_writer_init(&vol->log_volume.map_state.writer, vol);
    // create and init lun
    map_ut_init_active(vol);
    struct nuvo_lun * active_lun  = &vol->log_volume.lun;

    //write a few things
    //max_iter = 1024 covers 4 map blocks
    map_ut_multi_write(active_lun, /*snap_lun = */NULL, /*max_iter = */1024, /*num_blocks = */32,
                        /*seq = */true, /*seed = */NULL);

    // close and reopen the lun for clearing out dirty maps
    nuvo_map_lun_close(active_lun, &active_lun->root_map_entry);
    nuvo_return_t ret = nuvo_map_lun_open(active_lun, &active_lun->root_map_entry);
    NUVO_ASSERT(!ret);

    //read some of the L1s back into memory
    block = 0;
    for (int i = 0; i < 4; i++)
    {
        struct nuvo_map_request map_req;
        map_ut_reserve_fault_in(&map_req, active_lun, block);
        nuvo_map_read_lock(&map_req); // to release the pins
        nuvo_map_read_unlock(&map_req);
        block += 256;
    }

    // create a pit
    map_ut_create_snap(vol);

    // start a fake cp
    fake_map_checkpoint_start(vol);

    // since we created a pit, this subsequent read must trigger percolate on the L1 map
    //
    block = 0;

    for (int i = 0; i < 4; i++)
    {
        struct nuvo_map_request map_req;
        map_ut_reserve_fault_in(&map_req, active_lun, block);
        nuvo_map_read_lock(&map_req); // to release the pins
        nuvo_map_read_unlock(&map_req);
        block += 256;
    }

    // finish off the cp
    struct nuvo_map_entry cp_map_entry;
    fake_map_checkpoint_finish_sync(vol, &cp_map_entry);

    struct nuvo_map_entry map_entry;
    rc = nuvo_map_lun_close(active_lun, &map_entry);
    NUVO_ASSERT(!rc);

    lun_close_all();
    lun_dealloc_all();

    nuvo_map_writer_destroy(&vol->log_volume.map_state.writer);
}

Suite * nuvo_map_suite(void)
{
    Suite *s;
    TCase *tc_map;

    s = suite_create("NuvoMap");

    tc_map = tcase_create("NuvoMap");

    tcase_add_checked_fixture(tc_map, nuvo_map_test_setup, nuvo_map_test_teardown);
    tcase_add_test(tc_map, nuvo_map_test_init);
    tcase_add_test(tc_map, nuvo_map_test_mixed_clean_insert_remove);
    tcase_add_test(tc_map, nuvo_map_test_pinned_clean_insert_remove);
    tcase_add_test(tc_map, nuvo_map_test_get_table_index);
    tcase_add_test(tc_map, nuvo_map_test_get_base_offset);
    tcase_add_test(tc_map, nuvo_map_test_balance);
    tcase_add_test(tc_map, nuvo_map_test_write_read);
    tcase_add_test(tc_map, nuvo_map_test_write_read_spanner);
    tcase_add_test(tc_map, nuvo_map_test_write_read_split);
    tcase_add_test(tc_map, nuvo_map_test_map_flush);
    tcase_add_test(tc_map, nuvo_map_test_map_fault);
    tcase_add_test(tc_map, nuvo_map_test_shadow_1);
    tcase_add_test(tc_map, nuvo_map_test_CUM_2234);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_1);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_1_clean_second);
    tcase_add_test(tc_map, nuvo_map_test_shadow_2);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_2);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_2_clean_second);
    tcase_add_test(tc_map, nuvo_map_test_shadow_1_cp);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_1_cp);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_1_clean_second_cp);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_2_clean_both_cp);
    tcase_add_test(tc_map, nuvo_map_test_cp_and_writes);
    tcase_add_test(tc_map, nuvo_map_test_split_2_cp_and_writes);
    tcase_add_test(tc_map, nuvo_map_test_shadow_2_cp);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_2_cp);
    tcase_add_test(tc_map, nuvo_map_test_shadow_split_2_clean_second_cp);
    tcase_add_test(tc_map, nuvo_map_test_open_close);
    tcase_add_test(tc_map, nuvo_map_test_dirty_close);
    tcase_add_test(tc_map, nuvo_map_test_checkpoint);
    tcase_add_test(tc_map, nuvo_map_test_simple_replay);
    tcase_add_test(tc_map, nuvo_map_test_replay_extended);
    tcase_add_test(tc_map, nuvo_map_test_shared_snap_read);
    tcase_add_test(tc_map, nuvo_map_test_intermediate_shadow);
    tcase_add_test(tc_map, nuvo_map_test_percolate_and_cp);
    tcase_add_test(tc_map, nuvo_map_test_mfl);
    tcase_add_test(tc_map, nuvo_map_test_mfl_replay);
    tcase_add_test(tc_map, nuvo_map_test_map_free_rollup);
    tcase_add_test(tc_map, nuvo_map_test_CUM_2460);
    tcase_add_loop_test(tc_map, nuvo_map_test_write_active_lun_conditional, 0, 7);
    tcase_add_loop_test(tc_map, nuvo_map_test_write_multi_lun_conditional, 0, 7);

    tcase_add_loop_test(tc_map, nuvo_map_test_map_diff, 0 , 7);

    suite_add_tcase(s, tc_map);

    return s;
}




