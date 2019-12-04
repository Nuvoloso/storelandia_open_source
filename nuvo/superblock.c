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
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "status.h"
#include "superblock.h"
#include "resilience.h"
#include "nuvo_vol_series.h"
#include <version_nuvo.h>

/**
 * \brief check to see if a superblock is valid.
 *
 * Look at the magic and then check the hash.
 * this changes the value in the hash field.
 *
 * \param sb The superblock.
 * \retval 0 Looks good.
 * \retval -NUVO_E_BAD_MAGIC The superblock has a bad magic number.
 * \retval -NUVO_E_BAD_HASH The superblock has a good magic, but a bad hash.
 */
nuvo_return_t nuvo_sb_check(struct nuvo_sb_superblock *sb)
{
    if (sb->magic != NUVO_SB_MAGIC)
    {
        return (-NUVO_E_BAD_MAGIC);
    }
    struct nuvo_sb_superblock sbc;
    memcpy(&sbc, sb, sizeof(sbc));
    nuvo_hash_t hash = sbc.hash;
    sbc.hash = 0;
    if (hash != nuvo_hash(&sbc, sizeof(sbc)))
    {
        return (-NUVO_E_BAD_HASH);
    }
    return (0);
}

/**
 * \brief Managing reading two copies of the superblock.
 *
 * Holy overengineering, Batman.
 *
 * This manages the long chain of calls and callbacks to read the
 * two copies of the superblocks and arbitrate between them
 *
 * At the start we have the parcel we are reading from.
 * This goes and finds the two copies of the superblock, reading
 * them in separately, in case we decide to make them non-sequential on
 * disk, and decides which one is best (generation and hash) and returns
 * that.
 */

// Documented in the header.
nuvo_return_t nuvo_sb_sync_read(struct nuvo_sb_superblock *sb, uint_fast32_t root_parcel_desc)
{
    uint8_t sb_buf[2][4096] __attribute__((aligned NUVO_BLOCK_SIZE));

    NUVO_ASSERT(NUVO_SB_BLOCK_OFFSET_0 + 1 == NUVO_SB_BLOCK_OFFSET_1);
    NUVO_ASSERT(sizeof(sb_buf) == 2 * NUVO_BLOCK_SIZE);
    nuvo_return_t rc = nuvo_pr_sync_read(root_parcel_desc, NUVO_SB_BLOCK_OFFSET_0, 2, &sb_buf[0][0]);
    if (rc < 0)
    {
        return (rc);
    }
    struct nuvo_sb_superblock *sb_cand[NUVO_SB_BLOCK_COPIES];
    sb_cand[0] = (struct nuvo_sb_superblock *)sb_buf[0];
    sb_cand[1] = (struct nuvo_sb_superblock *)sb_buf[1];
    if (sb_cand[0]->generation < sb_cand[1]->generation)
    {
        struct nuvo_sb_superblock *temp = sb_cand[0];
        sb_cand[0] = sb_cand[1];
        sb_cand[1] = temp;
    }
    for (unsigned int i = 0; i < NUVO_SB_BLOCK_COPIES; i++)
    {
        rc = nuvo_sb_check(sb_cand[i]);
        if (rc == 0)
        {
            // Winner!
            *sb = *sb_cand[i];
            return (0);
        }
    }
    return (-NUVO_E_NO_SUPERBLOCK);
}

struct nuvo_sb_write_op {
    /* Inputs */
    uint64_t                   parcel_desc;
    struct nuvo_sb_superblock *sb;
    void                       (*callback)(struct nuvo_sb_write_op *);
    union  nuvo_tag            tag;

    /* Outputs */
    nuvo_return_t              status;

    /* Internals */
    uint32_t                   block_offset;

    struct nuvo_io_request    *req;
    struct nuvo_pr_req_alloc   req_alloc;
    struct nuvo_pr_buf_alloc   buf_alloc;
};

void nuvo_sb_write_start(struct nuvo_sb_write_op *op);
void nuvo_sb_write_req_alloc_cb(struct nuvo_pr_req_alloc *req);
void nuvo_sb_write_buf_alloc_cb(struct nuvo_pr_buf_alloc *req);
void nuvo_sb_write_io_cb(struct nuvo_io_request *req);

void nuvo_sb_write_start(struct nuvo_sb_write_op *op)
{
    op->sb->generation += 1;
    op->sb->hash = 0;
    op->sb->hash = nuvo_hash(op->sb, sizeof(*op->sb));
    op->block_offset = (op->sb->generation % 2) == 0 ? NUVO_SB_BLOCK_OFFSET_0 : NUVO_SB_BLOCK_OFFSET_1;

    // setup
    nuvo_dlnode_init(&op->req_alloc.list_node);
    op->req_alloc.callback = nuvo_sb_write_req_alloc_cb;
    op->req_alloc.tag.ptr = op;
    nuvo_pr_client_req_alloc_cb(&op->req_alloc);
}

void nuvo_sb_write_req_alloc_cb(struct nuvo_pr_req_alloc *req)
{
    struct nuvo_sb_write_op *op = (struct nuvo_sb_write_op *)req->tag.ptr;

    op->req = op->req_alloc.req;
    NUVO_SET_IO_TYPE(op->req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(op->req, NUVO_CACHE_DEFAULT);
    op->req->rw.vol = nuvo_containing_object(op->sb, struct nuvo_vol, log_volume.sb);
    op->req->rw.parcel_desc = op->parcel_desc;
    op->req->rw.block_offset = op->block_offset;
    op->req->rw.block_count = 1;
    op->req->rw.iovecs[0].iov_len = NUVO_BLOCK_SIZE;
    op->req->callback = nuvo_sb_write_io_cb;
    op->req->tag.ptr = op;

    nuvo_pr_buf_alloc_init_req(&op->buf_alloc,
                               op->req,
                               (union nuvo_tag)((void *)op),
                               nuvo_sb_write_buf_alloc_cb);

    nuvo_pr_client_buf_alloc_batch(&op->buf_alloc);
}

void nuvo_sb_write_buf_alloc_cb(struct nuvo_pr_buf_alloc *req)
{
    struct nuvo_sb_write_op *op = (struct nuvo_sb_write_op *)req->tag.ptr;

    memset(op->req->rw.iovecs[0].iov_base, 0, NUVO_BLOCK_SIZE);
    memcpy(op->req->rw.iovecs[0].iov_base, op->sb, sizeof(*op->sb));
    op->req->rw.block_hashes[0] = nuvo_hash(op->req->rw.iovecs[0].iov_base, NUVO_BLOCK_SIZE);
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);
    nuvo_dlist_insert_tail(&submit_list, &op->req->list_node);
    nuvo_rl_submit(&submit_list);
}

void nuvo_sb_write_io_cb(struct nuvo_io_request *req)
{
    struct nuvo_sb_write_op *op = (struct nuvo_sb_write_op *)req->tag.ptr;

    op->status = op->req->status;
    nuvo_pr_client_buf_free_req(op->req);
    nuvo_pr_client_req_free(op->req);
    op->callback(op);
}

/**
 * \brief Callback to make writing a manifest synchronous.
 */
void nuvo_sb_sync_write_callback(struct nuvo_sb_write_op *op)
{
    nuvo_mutex_unlock((nuvo_mutex_t *)op->tag.ptr);
}

// Documented in header
nuvo_return_t nuvo_sb_sync_write(struct nuvo_sb_superblock *sb, uint_fast32_t parcel_desc)
{
    nuvo_mutex_t sync_signal;

    if (0 != nuvo_mutex_init(&sync_signal))
    {
        return (NUVO_ENOMEM);
    }
    nuvo_mutex_lock(&sync_signal);
    struct nuvo_sb_write_op op;
    op.sb = sb;
    op.parcel_desc = parcel_desc;
    op.callback = nuvo_sb_sync_write_callback;
    op.tag.ptr = &sync_signal;
    nuvo_sb_write_start(&op);
    nuvo_mutex_lock(&sync_signal);
    nuvo_mutex_unlock(&sync_signal);
    nuvo_mutex_destroy(&sync_signal);
    return (op.status);
}

// Documented in header.
const struct nuvo_sb_table_location *nuvo_sb_get_parcel_manifest_addr(struct nuvo_sb_superblock *sb, int zero_one)
{
    NUVO_ASSERT(zero_one == 0 || zero_one == 1);
    return (&sb->parcel_manifest[zero_one]);
}

// Documented in header.
const struct nuvo_sb_table_location *nuvo_sb_get_segment_table_addr(struct nuvo_sb_superblock *sb, int zero_one)
{
    NUVO_ASSERT(zero_one == 0 || zero_one == 1);
    return (&sb->segment_table[zero_one]);
}

/**
 * \brief Convenience routine to set the a nuvo_sb_table_location
 *
 * \param loc The location to set.
 * \param parcel_index The parcel index of the location.
 * \param block_offset The block offset of the location.
 * \param block_length the block length of the location.
 */
void nuvo_sb_set_loc(struct nuvo_sb_table_location *loc,
                     uint64_t                       parcel_index,
                     uint64_t                       block_offset,
                     uint32_t                       block_length)
{
    memset(loc, 0, sizeof(*loc));
    loc->parcel_index = parcel_index;
    loc->block_offset = block_offset;
    loc->block_length = block_length;
}

// Documented in header
void nuvo_sb_init(struct nuvo_sb_superblock *sb,
                  const uuid_t               vol_series_uuid,
                  uint16_t                   init_pm_blks,
                  uint16_t                   init_st_blks)
{
    memset(sb, 0, sizeof(*sb));
    sb->magic = NUVO_SB_MAGIC;
    sb->generation = 0;
    sb->replay_count = 0;
    sb->git_hash = nuvo_short_git_hash();
    uuid_copy(sb->vol_series_uuid, vol_series_uuid);
    uint_fast32_t start = NUVO_SB_MFST_START;
    NUVO_ASSERT(NUVO_SB_BLOCK_OFFSET_0 == 0 && NUVO_SB_BLOCK_OFFSET_1 == 1);
    nuvo_sb_set_loc(&sb->parcel_manifest[0], 0, start, init_pm_blks);
    start += init_pm_blks;
    nuvo_sb_set_loc(&sb->parcel_manifest[1], 0, start, init_pm_blks);
    start += init_pm_blks;
    nuvo_sb_set_loc(&sb->segment_table[0], 0, start, init_st_blks);
    start += init_st_blks;
    nuvo_sb_set_loc(&sb->segment_table[1], 0, start, init_st_blks);
}
