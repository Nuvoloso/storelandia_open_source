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
#include <sys/mount.h>
#include "nuvo_fuse.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include <pthread.h>

#include "nuvo.h"
#include "nuvo_vol_series.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "nuvo_stats.h"
#include "parcel_vol.h"
#include "log_volume.h"
#include "lun.h"

#include <fuse3/fuse.h>
#include <fuse3/fuse_common.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>

/*
 * Bare minimum open routine.
 * Find the inode number and then call regular file open or throw an error.
 */
void nuvo_open(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    (void)fs;
    switch (ino)
    {
    case NUVO_FUSE_ROOT_INO:
        // The root dir.
        NUVO_ERROR_PRINT("Fuse error - open: directory open not supported.");
        nuvo_fuse_reply_err(req, EISDIR);
        break;

    case NUVO_FUSE_LUN_INO:
        // The volume.
        /* Should record reference on file */
        fuse_reply_open(req, fi);
        break;

    default:
        NUVO_ERROR_PRINT("Fuse error - open: inode number out of range.  ino %u", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        break;
    }
}

nuvo_return_t nuvo_find_dir_ent(nuvo_node_t *d, const char *name, fuse_ino_t *inum, unsigned int *idx)
{
    for (unsigned int i = 0; i < d->u.dir.num_entries; i++)
    {
        if (d->u.dir.ents[i].name == NULL)
        {
            continue;
        }
        if (0 == strcmp(name, d->u.dir.ents[i].name))
        {
            if (inum != NULL)
            {
                *inum = d->u.dir.ents[i].inum;
            }
            if (idx != NULL)
            {
                *idx = i;
            }
            return (0);
        }
    }
    return (-NUVO_ENOENT);
}

void nuvo_fill_attr(nuvo_node_t *f, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_ino = f->inum;
    stbuf->st_nlink = f->nlink;
    stbuf->st_mode = f->mode;
    stbuf->st_mtim = f->mtim;
    stbuf->st_ctim = f->ctim;
    switch (f->type)
    {
    case NUVO_REG:
        stbuf->st_size = f->u.file.lun->size;
        break;

    default:
        break;
    }
}

struct parcel_read_state {
    struct nuvo_io_request *req[2];
};

static int parcel_read_internal(struct nuvo_vol *nvs_p, uint64_t bno, uint64_t num_blocks, struct iovec *iovecs,
                                struct parcel_read_state *state)
{
    int_fast64_t ret = 0;

    NUVO_ASSERT(num_blocks <= NUVO_MAX_IO_BLOCKS);
    nuvo_mutex_t sync_signal;

    state->req[0] = NULL;
    state->req[1] = NULL;

    ret = nuvo_mutex_init(&sync_signal);
    if (ret != 0)
    {
        return (ENOMEM);
    }

    // 2 reqs in case this spans parcel boundaries.
    // req[0] gets up to parcel boundary, req[0] rest.
    // nuvo_parcel_vol_find_location figures out how many.
    struct nuvo_io_request *req;
    uint64_t      req_bno = bno;
    uint64_t      req_blocks_left = num_blocks;
    uint_fast32_t i = 0;
    while (req_blocks_left)
    {
        state->req[i] = req = nuvo_pr_sync_client_req_alloc(&sync_signal);
        NUVO_SET_IO_TYPE(req, NUVO_OP_READ, NUVO_IO_ORIGIN_USER);
        NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
        ret = nuvo_parcel_vol_find_location(nvs_p, req_bno, req_blocks_left,
                                            &req->rw.parcel_desc, &req->rw.block_offset, &req->rw.block_count);
        if (ret != 0)
        {
            ret = EINVAL;
            goto done;
        }
        nuvo_pr_sync_buf_alloc_req(req, &sync_signal);
        req_bno += req->rw.block_count;
        req_blocks_left -= req->rw.block_count;
        NUVO_ASSERT(i == 0 || req_blocks_left == 0);   // Make sure we only use 2 reqs.

        nuvo_pr_sync_submit(req, &sync_signal);
        if (req->status != 0)
        {
            // This error is not correct, but not sure what to change it to.
            // Could be any number of errors not related to memory.
            ret = ENOMEM;
            goto done;
        }
        i++;
    }

    req = state->req[0];
    memcpy(iovecs, req->rw.iovecs, req->rw.block_count * sizeof(struct iovec));
    if ((req = state->req[1]) != NULL)
    {
        memcpy(&iovecs[req->rw.block_count], req->rw.iovecs, req->rw.block_count * sizeof(struct iovec));
    }

done:
    nuvo_mutex_destroy(&sync_signal);

    return (ret);
}

void
parcel_read_free_state(struct parcel_read_state *state)
{
    uint_fast32_t i = 0;

    for (i = 0; i < 2; i++)
    {
        if (state->req[i] != NULL)
        {
            nuvo_pr_client_buf_free_req(state->req[i]);
            nuvo_pr_client_req_free(state->req[i]);
        }
    }
}

/**
 * return the latency, sleeping if necessary to get over minimum.
 */
static uint_fast64_t calc_and_enforce_latency(uint_fast64_t submit_time, uint_fast64_t latency_min)
{
    uint_fast64_t complete_time = nuvo_get_timestamp();

    if (submit_time + latency_min <= complete_time)
    {
        return (complete_time - submit_time);
    }
    struct timespec lat_timeout;
    uint_fast64_t   sleep_nano = latency_min + submit_time - complete_time;
    lat_timeout.tv_sec = sleep_nano / 1000000000L;
    lat_timeout.tv_nsec = sleep_nano % 1000000000L;
    while (1)
    {
        int r = nanosleep(&lat_timeout, &lat_timeout);
        if (r == 0 || errno != EINTR)
        {
            return (nuvo_get_timestamp() - submit_time);
        }
    }
}

/*
 * Bare minimum read routine.
 * Find the inode number and then call regular file read or throw an error.
 */
void nuvo_read(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, size_t size,
               off_t off, struct fuse_file_info *fi)
{
    (void)fi;
    if (ino != NUVO_FUSE_LUN_INO)
    {
        NUVO_ERROR_PRINT("Fuse error - read: inode number out of range, ino %u", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }
    nuvo_node_t *f = &fs->nodes[NUVO_FUSE_LUN_INO];

    if (f->inum == 0)
    {
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }

    uint_fast64_t io_submit_time = nuvo_get_timestamp();
    NUVO_LOG(fuse, 50, "Fuse read ino: %u offset %" PRIu64 " length %" PRIu64, ino, off, size);

    switch (f->type)
    {
    case NUVO_REG:
        nuvo_mutex_lock(&f->u.file.lun->mutex);
        if (f->u.file.lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED)
        {
            NUVO_ERROR_PRINT("read: lun is being unexported and not accessible (ino: %u).", ino);
            nuvo_fuse_reply_err(req, ENOENT);
            nuvo_mutex_unlock(&f->u.file.lun->mutex);
            return;
        }
        if (off < 0 || (size_t)off >= f->u.file.lun->size)
        {
            NUVO_ERROR_PRINT("Fuse error - read: requested offset %d out of range 0 - %d.",
                             off, f->u.file.lun->size - 1);
            //TODO do a fault injector here later to induce fuse error
            // change line below from reply_buf to reply_err to induce fuse error
            // nuvo_fuse_reply_err(req, EINVAL);
            fuse_reply_buf(req, NULL, 0);
            nuvo_mutex_unlock(&f->u.file.lun->mutex);
            return;
        }
        if (off % NUVO_BLOCK_SIZE != 0 || size % NUVO_BLOCK_SIZE != 0)
        {
            // NUVO_ERROR_PRINT("Misaligned Read %ld, %ld", off, size);
        }

        f->u.file.lun->io_pending_count++;
        nuvo_mutex_unlock(&f->u.file.lun->mutex);

        switch (f->u.file.lun->vol->type)
        {
        case NUVO_VOL_PASSTHROUGH:
        {
            char *buf;
            int   r = posix_memalign((void **)&buf, NUVO_BLOCK_SIZE, size);
            NUVO_PANIC_COND(r, "posix_memalign faliure");
            size_t sr = pread(f->u.file.lun->vol->ptvol.fd, buf, size, off);
            if (sr != size)
            {
                NUVO_ERROR_PRINT("read error");
            }
            nuvo_io_stats_add(&f->u.file.lun->read_io_stats, size,
                              calc_and_enforce_latency(io_submit_time, f->u.file.lun->read_latency_min));
            fuse_reply_buf(req, buf, size);

            free(buf);
            break;
        }

        case NUVO_VOL_PARCEL:
        {
            struct parcel_read_state state;
            size_t       nblocks = ((off + size - 1) / NUVO_BLOCK_SIZE) - (off / NUVO_BLOCK_SIZE) + 1;
            struct iovec iovecs[NUVO_MAX_IO_BLOCKS];
            size_t       i;
            off_t        block_off;

            for (i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
            {
                iovecs[i].iov_base = NULL;
                iovecs[i].iov_len = 0;
            }

            block_off = off / NUVO_BLOCK_SIZE;
            void *rlh;

            rlh = nuvo_lock_range_wait(&f->u.file.lun->range_lock, block_off, nblocks);

            int r = parcel_read_internal(f->u.file.lun->vol,
                                         block_off, nblocks, &(iovecs[0]), &state);

            nuvo_unlock_range(&f->u.file.lun->range_lock, rlh);

            if (r != 0)
            {
                NUVO_ERROR_PRINT("Fuse error - read: parcel read failed with %d.", r);
                nuvo_fuse_reply_err(req, r);
            }
            else
            {
                // Adjust the iovecs to align with the user request
                // If 4K block alignment, these are a no-op
                // First iovec, must adjust the iov_base and iov_len
                iovecs[0].iov_base += off % NUVO_BLOCK_SIZE;
                iovecs[0].iov_len = NUVO_BLOCK_SIZE - (off % NUVO_BLOCK_SIZE);
                // Last iovec, adjust just the length
                if ((off + size) % NUVO_BLOCK_SIZE) // incomplete final block
                {
                    iovecs[nblocks - 1].iov_len -= NUVO_BLOCK_SIZE - ((off + size) % NUVO_BLOCK_SIZE);
                }

                {       // Just for ASSERTs
                    size_t total_size = 0;

                    for (i = 0; i < nblocks; i++)
                    {
                        total_size += iovecs[i].iov_len;
                    }
                    NUVO_ASSERT(total_size == size);
                }   // END of ASSERTS

                nuvo_io_stats_add(&f->u.file.lun->read_io_stats, size,
                                  calc_and_enforce_latency(io_submit_time, f->u.file.lun->read_latency_min));
                fuse_reply_iov(req, iovecs, nblocks);
            }
            parcel_read_free_state(&state);
            break;
        }

        case NUVO_VOL_LOG_VOL:
        {
            size_t nblocks = ((off + size - 1) / NUVO_BLOCK_SIZE) - (off / NUVO_BLOCK_SIZE) + 1;
            void  *buf_list[NUVO_MAX_IO_BLOCKS];

            unsigned int i;
            off_t        block_off;


            block_off = off / NUVO_BLOCK_SIZE;

            nuvo_mutex_t sync_signal;
            nuvo_mutex_init(&sync_signal);


            nuvo_pr_sync_buf_alloc_list(buf_list, nblocks, &sync_signal);

            nuvo_mutex_destroy(&sync_signal);

            int r = nuvo_log_vol_lun_read(f->u.file.lun, block_off, nblocks, buf_list, NULL /* req cb*/);

            if (r != 0)
            {
                NUVO_ERROR_PRINT("Fuse error - read: log volume read failed with %d.", r);
                nuvo_fuse_reply_err(req, r);
            }
            else
            {
                struct iovec iovecs[NUVO_MAX_IO_BLOCKS];

                for (i = 0; i < nblocks; i++)
                {
                    iovecs[i].iov_base = buf_list[i];
                    iovecs[i].iov_len = NUVO_BLOCK_SIZE;
                }

                // Adjust the iovecs to align with the user request
                // If 4K block alignment, these are a no-op
                // First iovec, must adjust the iov_base and iov_len
                iovecs[0].iov_base += off % NUVO_BLOCK_SIZE;
                iovecs[0].iov_len = NUVO_BLOCK_SIZE - (off % NUVO_BLOCK_SIZE);
                // Last iovec, adjust just the length
                if ((off + size) % NUVO_BLOCK_SIZE) // incomplete final block
                {
                    iovecs[nblocks - 1].iov_len -= NUVO_BLOCK_SIZE - ((off + size) % NUVO_BLOCK_SIZE);
                }

                {       // Just for ASSERTs
                    size_t total_size = 0;

                    for (i = 0; i < nblocks; i++)
                    {
                        total_size += iovecs[i].iov_len;
                    }
                    NUVO_ASSERT(total_size == size);
                }   // END of ASSERTS
                uint_fast64_t latency = (f->want_stats || f->u.file.lun->read_latency_min != 0) ?
                                        calc_and_enforce_latency(io_submit_time, f->u.file.lun->read_latency_min) : 0;
                if (f->want_stats)
                {
                    nuvo_io_stats_add(&f->u.file.lun->read_io_stats, size, latency);
                }
                fuse_reply_iov(req, iovecs, nblocks);
            }

            nuvo_pr_client_buf_free_list(buf_list, nblocks);

            break;
        }

        default:
            NUVO_ERROR_PRINT("Fuse error - read: volume type not supported.");
            nuvo_fuse_reply_err(req, EINVAL);
            break;
        }

        nuvo_mutex_lock(&f->u.file.lun->mutex);
        if ((--f->u.file.lun->io_pending_count == 0) && (f->u.file.lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED))
        {
            nuvo_cond_signal(&f->u.file.lun->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&f->u.file.lun->mutex);

        break;

    case NUVO_DIR:
        NUVO_ERROR_PRINT("Fuse error - read: directory type not supported.");
        nuvo_fuse_reply_err(req, EISDIR);
        break;

    default:
        NUVO_ERROR_PRINT("Fuse error - read: unsupported type %d.", f->type);
        nuvo_fuse_reply_err(req, EINVAL);
    }
}

static int parcel_write_internal(struct nuvo_vol *nvs_p, uint64_t bno, uint64_t num_blocks, const char *buf)
{
    NUVO_ASSERT(num_blocks <= NUVO_MAX_IO_BLOCKS);
    nuvo_mutex_t sync_signal;
    int_fast64_t rc = nuvo_mutex_init(&sync_signal);
    if (rc != 0)
    {
        return (-NUVO_ENOMEM);
    }
    int64_t ret;

    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);

    NUVO_SET_IO_TYPE(req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_USER);
    NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
    // Sequential if we cross parcel boundaries. That's ok from a perf POV.
    // From a correctness POV there is a torn io problem.
    // Ignoring because parcel vols are not "product".
    while (num_blocks > 0)
    {
        ret = nuvo_parcel_vol_find_location(nvs_p, bno, num_blocks,
                                            &req->rw.parcel_desc, &req->rw.block_offset, &req->rw.block_count);
        if (ret != 0)
        {
            goto free_req;
        }
        nuvo_pr_sync_buf_alloc_req(req, &sync_signal);
        for (uint_fast32_t i = 0; i < req->rw.block_count; i++)
        {
            // TODO optimize for case that buf is page aligned
            memcpy(req->rw.iovecs[i].iov_base, buf, NUVO_BLOCK_SIZE);
            req->rw.block_hashes[i] = nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
            buf += NUVO_BLOCK_SIZE;
        }
        nuvo_pr_sync_submit(req, &sync_signal);
        nuvo_pr_client_buf_free_req(req);
        if (req->status != 0)
        {
            ret = req->status;
            goto free_req;
        }
        num_blocks -= req->rw.block_count;
    }
    ret = 0;

free_req:
    nuvo_pr_client_req_free(req);
    nuvo_mutex_destroy(&sync_signal);
    return (ret);
}

static int parcel_writev_internal(struct nuvo_vol *nvs_p, uint64_t bno, uint64_t num_blocks, const struct iovec *iov)
{
    NUVO_ASSERT(num_blocks <= NUVO_MAX_IO_BLOCKS);
    nuvo_mutex_t sync_signal;
    int          iov_index = 0;
    int_fast64_t rc = nuvo_mutex_init(&sync_signal);
    if (rc != 0)
    {
        // TODO ERROR CODE
        return (ENOMEM);
    }
    int64_t ret;

    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);

    NUVO_SET_IO_TYPE(req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_USER);
    NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
    // Sequential if we cross parcel boundaries. That's ok from a perf POV.
    // From a correctness POV there is a torn io problem.
    // Ignoring because parcel vols are not "product".
    while (num_blocks > 0)
    {
        ret = nuvo_parcel_vol_find_location(nvs_p, bno, num_blocks,
                                            &req->rw.parcel_desc, &req->rw.block_offset, &req->rw.block_count);
        if (ret != 0)
        {
            goto free_req;
        }
        nuvo_pr_sync_buf_alloc_req(req, &sync_signal);
        for (uint_fast32_t i = 0; i < req->rw.block_count; i++)
        {
            // Could do iovec copy instead of iovec.iov_base copy.
            memcpy(req->rw.iovecs[i].iov_base, iov[iov_index].iov_base, NUVO_BLOCK_SIZE);
            req->rw.block_hashes[i] = nuvo_hash(req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
            iov_index++;
        }
        nuvo_pr_sync_submit(req, &sync_signal);
        nuvo_pr_client_buf_free_req(req);
        if (req->status != 0)
        {
            ret = req->status;
            goto free_req;
        }
        num_blocks -= req->rw.block_count;
    }
    ret = 0;

free_req:
    nuvo_pr_client_req_free(req);
    nuvo_mutex_destroy(&sync_signal);
    return (ret);
}

/*
 * Bare minimum write routine.
 * Find the inode number and then call regular file write or throw an error.
 */
void nuvo_write(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, const char *buf,
                size_t size, off_t off, struct fuse_file_info *fi)
{
    (void)fi;

    if (ino != NUVO_FUSE_LUN_INO)
    {
        NUVO_ERROR_PRINT("Fuse error - write: inode number out of range, ino %u", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }
    nuvo_node_t *f = &fs->nodes[NUVO_FUSE_LUN_INO];

    if (f->inum == 0)
    {
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }

    uint_fast64_t io_submit_time = nuvo_get_timestamp();
    NUVO_LOG(fuse, 50, "Fuse write ino: %u offset %" PRIu64 " length %" PRIu64, ino, off, size);

    switch (f->type)
    {
    case NUVO_REG:
        nuvo_mutex_lock(&f->u.file.lun->mutex);
        if (f->u.file.lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED)
        {
            NUVO_ERROR_PRINT("write: lun is being unexported and not accessible (ino: %u).", ino);
            nuvo_fuse_reply_err(req, ENOENT);
            nuvo_mutex_unlock(&f->u.file.lun->mutex);
            return;
        }
        if (f->u.file.lun->export_state != NUVO_LUN_EXPORT_WRITABLE)
        {
            NUVO_ERROR_PRINT("Fuse error - write: lun is not writeable.");
            nuvo_fuse_reply_err(req, EROFS);
            nuvo_mutex_unlock(&f->u.file.lun->mutex);
            return;
        }
        if (off < 0)
        {
            NUVO_ERROR_PRINT("Fuse error - write: requested offset %d out of range.", off);
            nuvo_fuse_reply_err(req, EINVAL);
            nuvo_mutex_unlock(&f->u.file.lun->mutex);
            return;
        }
        f->u.file.lun->io_pending_count++;
        nuvo_mutex_unlock(&f->u.file.lun->mutex);

        if (off % NUVO_BLOCK_SIZE != 0 || size % NUVO_BLOCK_SIZE != 0)
        {
            // NUVO_ERROR_PRINT("Misaligned Write %ld, %ld", off, size);
        }

        switch (f->u.file.lun->vol->type)
        {
        case NUVO_VOL_PASSTHROUGH:
            // I really wish the incoming buf pointer was block aligned.
            // That would make my life more chill.
            // TODO: count these.
            if ((long unsigned int)buf % NUVO_BLOCK_SIZE == 0)
            {
                size_t size_written = pwrite(f->u.file.lun->vol->ptvol.fd, buf, size, off);
                if (size_written != size)
                {
                    NUVO_ERROR_PRINT("%ld, %ld, %d", size_written, size, errno);
                }
                nuvo_io_stats_add(&f->u.file.lun->write_io_stats, size,
                                  calc_and_enforce_latency(io_submit_time, f->u.file.lun->write_latency_min));
                fuse_reply_write(req, size_written);
            }
            else
            {
                char *p_buf;
                int   r;
                r = posix_memalign((void **)&p_buf, NUVO_BLOCK_SIZE, size);
                NUVO_PANIC_COND(r, "posix_memalign failure");
                memcpy(p_buf, buf, size);
                size_t size_written = pwrite(f->u.file.lun->vol->ptvol.fd, p_buf, size, off);
                if (size_written != size)
                {
                    NUVO_ERROR_PRINT("%lx, %ld, %ld, %d", (long unsigned int)p_buf, size_written, size, errno);
                }
                nuvo_io_stats_add(&f->u.file.lun->write_io_stats, size,
                                  calc_and_enforce_latency(io_submit_time, f->u.file.lun->write_latency_min));
                fuse_reply_write(req, size);
                free(p_buf);
            }
            break;

        case NUVO_VOL_PARCEL:
        {
            struct parcel_read_state state;
            int   read_modify_write = (off % NUVO_BLOCK_SIZE != 0 || size % NUVO_BLOCK_SIZE != 0);
            int   r;
            void *rlh;

            // calculate nblocks with potential misalignment
            size_t first_block = off / NUVO_BLOCK_SIZE;
            size_t nblocks = ((off + size - 1) / NUVO_BLOCK_SIZE) - (off / NUVO_BLOCK_SIZE) + 1;
            rlh = nuvo_lock_range_wait(&f->u.file.lun->range_lock, first_block, nblocks);

            if (read_modify_write)
            {
                struct iovec iovecs[NUVO_MAX_IO_BLOCKS];
                int          i;

                for (i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
                {
                    iovecs[i].iov_base = NULL;
                }

                r = parcel_read_internal(f->u.file.lun->vol,
                                         off / NUVO_BLOCK_SIZE, nblocks, &(iovecs[0]), &state);

                if (r != 0)
                {
                    nuvo_unlock_range(&f->u.file.lun->range_lock, rlh);
                    NUVO_ERROR_PRINT("Fuse error - write: parcel read failed with error: %d.", r);
                    nuvo_fuse_reply_err(req, r);
                    parcel_read_free_state(&state);
                    break;
                }

                // iovecs contains the existing data
                // buf contains the new user data.
                // overwrite the existing data with the user data

                const char  *bufp = buf;
                unsigned int iov_index = 0;
                size_t       remaining = size;

                if (off % NUVO_BLOCK_SIZE != 0) // Front edge
                {
                    size_t cpsize = NUVO_MIN(NUVO_BLOCK_SIZE - ((size_t)off % NUVO_BLOCK_SIZE), size);
                    memcpy(iovecs[0].iov_base + off % NUVO_BLOCK_SIZE, bufp, cpsize);
                    bufp += cpsize;
                    remaining -= cpsize;
                    iov_index++;
                }

                while (remaining > NUVO_BLOCK_SIZE) // Blocks in the middle
                {
                    memcpy(iovecs[iov_index].iov_base, bufp, NUVO_BLOCK_SIZE);
                    bufp += NUVO_BLOCK_SIZE;
                    NUVO_ASSERT(remaining >= NUVO_BLOCK_SIZE);
                    remaining -= NUVO_BLOCK_SIZE;
                    iov_index++;
                }

                if (remaining) // Last edge
                {
                    NUVO_ASSERT(iov_index == (nblocks - 1));
                    NUVO_ASSERT(remaining <= NUVO_BLOCK_SIZE);
                    memcpy(iovecs[nblocks - 1].iov_base, bufp, remaining);
                }

                r = parcel_writev_internal(f->u.file.lun->vol, off / NUVO_BLOCK_SIZE, nblocks, &(iovecs[0]));
                parcel_read_free_state(&state); // don't need the buffers anymore
            }
            else
            {
                r = parcel_write_internal(f->u.file.lun->vol, off / NUVO_BLOCK_SIZE, nblocks, buf);
            }
            nuvo_unlock_range(&f->u.file.lun->range_lock, rlh);

            if (r != 0)
            {
                NUVO_ERROR_PRINT("Fuse error - write: parcel write failed with error: %d.", r);
                nuvo_fuse_reply_err(req, r);
                break;
            }
            nuvo_io_stats_add(&f->u.file.lun->write_io_stats, size,
                              calc_and_enforce_latency(io_submit_time, f->u.file.lun->write_latency_min));
            fuse_reply_write(req, size);
            break;
        }

        case NUVO_VOL_LOG_VOL:
        {
            uint64_t      block_offset = off / NUVO_BLOCK_SIZE;
            size_t        nblocks = ((off + size - 1) / NUVO_BLOCK_SIZE) - (off / NUVO_BLOCK_SIZE) + 1;
            void         *rlh; // range lock handle
            int           read_modify_write = (off % NUVO_BLOCK_SIZE != 0 || size % NUVO_BLOCK_SIZE != 0);
            nuvo_return_t ret;
            nuvo_mutex_t  sync_signal;
            void         *buf_list[NUVO_MAX_IO_BLOCKS];

            ret = nuvo_mutex_init(&sync_signal);
            if (ret != 0)
            {
                NUVO_ERROR_PRINT("Fuse error - write: failed to initialize mutex.");
                nuvo_fuse_reply_err(req, ENOMEM);
                break;
            }
            // allocate the buffers that we will need
            nuvo_pr_sync_buf_alloc_list(buf_list, nblocks, &sync_signal);
            nuvo_mutex_destroy(&sync_signal);

            rlh = nuvo_lock_range_wait(&f->u.file.lun->range_lock, block_offset, nblocks);
            if (read_modify_write)
            {
                ret = nuvo_log_vol_lun_read(f->u.file.lun, block_offset, nblocks, buf_list, NULL);
                if (ret != 0)
                {
                    nuvo_unlock_range(&f->u.file.lun->range_lock, rlh);
                    nuvo_pr_client_buf_free_list(buf_list, nblocks);
                    NUVO_ERROR_PRINT("Fuse error - write: failed log volume read with error: %d.", ret);
                    nuvo_fuse_reply_err(req, ret);
                    break;
                }

                const char  *bufp = buf;
                unsigned int buf_index = 0;
                size_t       remaining = size;

                if (off % NUVO_BLOCK_SIZE != 0) // Front edge
                {
                    size_t cpsize = NUVO_MIN(NUVO_BLOCK_SIZE - ((size_t)off % NUVO_BLOCK_SIZE), size);
                    memcpy(buf_list[0] + off % NUVO_BLOCK_SIZE, bufp, cpsize);
                    bufp += cpsize;
                    remaining -= cpsize;
                    buf_index++;
                }

                while (remaining > NUVO_BLOCK_SIZE) // Blocks in the middle
                {
                    memcpy(buf_list[buf_index], bufp, NUVO_BLOCK_SIZE);
                    bufp += NUVO_BLOCK_SIZE;
                    NUVO_ASSERT(remaining >= NUVO_BLOCK_SIZE);
                    remaining -= NUVO_BLOCK_SIZE;
                    buf_index++;
                }

                if (remaining) // Last edge
                {
                    NUVO_ASSERT(buf_index == (nblocks - 1));
                    NUVO_ASSERT(remaining <= NUVO_BLOCK_SIZE);
                    memcpy(buf_list[nblocks - 1], bufp, remaining);
                }
            }
            else
            {
                // copy the datain to the buffers
                for (uint_fast32_t i = 0; i < nblocks; i++)
                {
                    memcpy(buf_list[i], buf + i * NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);
                }
            }

            // buffers are built with all of the data

            ret = nuvo_log_vol_write(f->u.file.lun->vol, block_offset, nblocks, buf_list);

            nuvo_unlock_range(&f->u.file.lun->range_lock, rlh);
            nuvo_pr_client_buf_free_list(buf_list, nblocks);
            if (ret != 0)
            {
                NUVO_ERROR_PRINT("Fuse error - write: failed log volume write with error: %d.", ret);
                nuvo_fuse_reply_err(req, ret);
                break;
            }
            uint_fast64_t latency = (f->want_stats || f->u.file.lun->write_latency_min != 0) ?
                                    calc_and_enforce_latency(io_submit_time, f->u.file.lun->write_latency_min) : 0;
            if (f->want_stats)
            {
                nuvo_io_stats_add(&f->u.file.lun->write_io_stats, size, latency);
            }
            fuse_reply_write(req, size);
            break;
        }

        default:
            NUVO_ERROR_PRINT("Fuse error - write: volume type not supported.");
            nuvo_fuse_reply_err(req, EINVAL);
            break;
        }

        nuvo_mutex_lock(&f->u.file.lun->mutex);
        if ((--f->u.file.lun->io_pending_count == 0) && (f->u.file.lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED))
        {
            nuvo_cond_signal(&f->u.file.lun->io_pending_count_zero_cond);
        }
        nuvo_mutex_unlock(&f->u.file.lun->mutex);

        break;

    case NUVO_DIR:
        NUVO_ERROR_PRINT("Fuse error - write: directory type not supported.");
        nuvo_fuse_reply_err(req, EISDIR);

        break;

    default:
        NUVO_ERROR_PRINT("Fuse error - write: unsupported type %d.", f->type);
        nuvo_fuse_reply_err(req, EINVAL);
    }
}

/*
 * Bare minimum readdir routine.
 * Find the inode number and then call directory readdir or throw an error.
 * Off is arbitrary from callers perspective, but it's the cookie.
 */
static void nuvo_readdir_int(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, size_t size,
                             off_t off, struct fuse_file_info *fi)
{
    (void)size;
    (void)fi;
    if (ino != NUVO_FUSE_ROOT_INO)
    {
        NUVO_ERROR_PRINT("Fuse error - readdir: inode number out of range, ino %u", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }
    nuvo_node_t *dir = &fs->nodes[ino];
    if (dir->type != NUVO_DIR)
    {
        NUVO_ERROR_PRINT("Fuse error - readdir: specified inode is not a directory.");
        nuvo_fuse_reply_err(req, ENOTDIR);
        return;
    }

    size_t alloced_buf_size = NUVO_BLOCK_SIZE;
    char   reply_buf[NUVO_BLOCK_SIZE];
    // should check alloc failure
    memset(reply_buf, 0, alloced_buf_size);
    size_t buf_used = 0;
    // I'm assuming "." and ".."" come first and second
    for (unsigned int i = 0; i < dir->u.dir.num_entries; i++)
    {
        if (i < off)
        {
            continue;
        }
        if (dir->u.dir.ents[i].name == NULL)
        {
            continue;
        }
        size_t entry_size = fuse_add_direntry(req, NULL, 0,
                                              dir->u.dir.ents[i].name, NULL, 0);
        size_t      new_used = buf_used + entry_size;
        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        stbuf.st_ino = dir->u.dir.ents[i].inum;
        fuse_add_direntry(req, reply_buf + buf_used,
                          alloced_buf_size - buf_used,
                          dir->u.dir.ents[i].name, &stbuf, i + 1);
        buf_used = new_used;
    }
    // Ugly - could be replying with buf_used > alloced_buf_size.
    fuse_reply_buf(req, reply_buf, buf_used);
}

void nuvo_readdir(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, size_t size,
                  off_t off, struct fuse_file_info *fi)
{
    NUVO_LOG(fuse, 40, "Fuse readdir ino: %u offset %" PRIu64 " length %" PRIu64, ino, off, size);
    nuvo_readdir_int(fs, req, ino, size, off, fi);
}

/*
 * Bare minimum getattr.
 */
void nuvo_getattr(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino,
                  struct fuse_file_info *fi)
{
    (void)fi;
    NUVO_LOG(fuse, 40, "Fuse getattr ino: %u", ino);
    if (ino != NUVO_FUSE_ROOT_INO && ino != NUVO_FUSE_LUN_INO)
    {
        NUVO_ERROR_PRINT("Fuse error - getattr: inode number out of range, ino %u", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }

    if (fs->nodes[ino].type == NUVO_UNUSED)
    {
        NUVO_ERROR_PRINT("Fuse error - getattr: ino %u unused", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }

    struct stat stbuf;
    nuvo_fill_attr(&fs->nodes[ino], &stbuf);
    fuse_reply_attr(req, &stbuf, 1.0);
}

/*
 * Bare minimum setattr for mtime and ctime.
 */

void nuvo_setattr(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    NUVO_LOG(fuse, 40, "Fuse setattr ino: %u to_set: %d\n", ino, to_set);
    if (ino != NUVO_FUSE_ROOT_INO && ino != NUVO_FUSE_LUN_INO)
    {
        NUVO_ERROR_PRINT("Fuse error - setattr: inode number out of range, ino %u", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }

    if (fs->nodes[ino].type == NUVO_UNUSED)
    {
        NUVO_ERROR_PRINT("Fuse error - setattr: ino %u unused.", ino);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }

    if (to_set & (FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_CTIME))
    {
        nuvo_node_t *f = &fs->nodes[ino];

        if (to_set & FUSE_SET_ATTR_MTIME)
        {
            f->mtim = attr->st_mtim;
        }

        if (to_set & FUSE_SET_ATTR_CTIME)
        {
            f->ctim = attr->st_ctim;
        }
    }

    return (nuvo_getattr(fs, req, ino, fi));
}

/*
 * Bare minimum lookup.
 */
static void nuvo_lookup_int(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t parent, const char *name)
{
    if (parent != NUVO_FUSE_ROOT_INO && parent != NUVO_FUSE_LUN_INO)
    {
        NUVO_ERROR_PRINT("Fuse error - lookup: inode number out of range, ino %u", parent);
        nuvo_fuse_reply_err(req, ENOENT);
        return;
    }
    nuvo_node_t *dir = &fs->nodes[parent];
    if (dir->type != NUVO_DIR)
    {
        NUVO_ERROR_PRINT("Fuse error - lookup: specified inode is not a directory.");
        nuvo_fuse_reply_err(req, ENOTDIR);
        return;
    }

    fuse_ino_t              inum;
    unsigned int            idx;
    struct fuse_entry_param e;
    if (0 == nuvo_find_dir_ent(dir, name, &inum, &idx))
    {
        switch (fs->nodes[inum].type)
        {
        case NUVO_REG:
        case NUVO_DIR:
            memset(&e, 0, sizeof(e));
            e.ino = inum;
            e.attr_timeout = 1.0;
            e.entry_timeout = 1.0;
            nuvo_fill_attr(&fs->nodes[inum], &e.attr);
            fuse_reply_entry(req, &e);
            break;

        default:
            NUVO_ERROR_PRINT("Fuse error - lookup: unsupported type %d.",
                             fs->nodes[inum].type);
            nuvo_fuse_reply_err(req, EINVAL);
            break;
        }
        return;
    }
    else
    {
        NUVO_ERROR_PRINT("Fuse error - lookup: dir ent not found.");
        nuvo_fuse_reply_err(req, ENOENT);
    }
}

void nuvo_lookup(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t parent, const char *name)
{
    NUVO_LOG(fuse, 40, "Fuse lookup parent ino: %u name: %s", parent, name);
    nuvo_lookup_int(fs, req, parent, name);
}

void nuvo_fs_setup(struct nuvo_lun *lun, bool writable)
{
    nuvo_fs_t *fs = &lun->lun_file_system;

    memset(fs, 0, sizeof(*fs));

    nuvo_node_t *d = &fs->nodes[NUVO_FUSE_ROOT_INO];
    nuvo_node_t *v = &fs->nodes[NUVO_FUSE_LUN_INO];

    d->inum = NUVO_FUSE_ROOT_INO;
    d->mode = 0755 | S_IFDIR;
    d->nlink = 2;
    d->type = NUVO_DIR;
    d->u.dir.num_entries = 3;

    d->u.dir.ents[0].inum = NUVO_FUSE_ROOT_INO;
    int rc = snprintf(d->u.dir.ents[0].name, NUVO_DIRENT_MAX_NAME, ".");
    NUVO_ASSERT(rc <= NUVO_DIRENT_MAX_NAME);
    d->u.dir.ents[1].inum = NUVO_FUSE_ROOT_INO;
    rc = snprintf(d->u.dir.ents[1].name, NUVO_DIRENT_MAX_NAME, "..");
    NUVO_ASSERT(rc <= NUVO_DIRENT_MAX_NAME);
    d->u.dir.ents[2].inum = NUVO_FUSE_LUN_INO;
    rc = snprintf(d->u.dir.ents[2].name, NUVO_DIRENT_MAX_NAME, "vol");
    NUVO_ASSERT(rc <= NUVO_DIRENT_MAX_NAME);

    v->inum = NUVO_FUSE_LUN_INO;
    v->type = NUVO_REG;
    if (writable)
    {
        v->mode = 0666 | S_IFREG;
        v->want_stats = 1;
    }
    else
    {
        v->mode = 0444 | S_IFREG;
        v->want_stats = 0;
    }
    v->nlink = 1;
    v->u.file.lun = lun;
}

char *nuvo_main_directory;

/**
 * Maximum length of the path for a fuse export.
 */
static int nuvo_fuse_get_lun_export_path(char *buffer, const char *export_dir, const char *lun_name)
{
    return (snprintf(buffer, MOUNT_POINT_BUFFER_MAX, "%s/%s", export_dir, lun_name));
}

static nuvo_return_t export_lun_int(struct nuvo_vol *nvs_p, const uuid_t pit_uuid, const char *lun_name, int writable)
{
    nuvo_return_t r;

    if (!nvs_p)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    nuvo_mutex_lock(&nvs_p->mutex);

    struct nuvo_lun *lun;
    switch (nvs_p->type)
    {
    case NUVO_VOL_PASSTHROUGH:
        if (!uuid_is_null(pit_uuid))
        {
            r = -NUVO_E_WRONG_VOL_TYPE;
            goto unlock_vol;
        }
        lun = &nvs_p->ptvol.lun;
        break;

    case NUVO_VOL_PARCEL:
        lun = &nvs_p->parvol.lun;
        lun->size = pm_total_size(&nvs_p->parvol.pm) - NUVO_SIMPLE_PARCEL_MANIFEST_SIZE;
        if (!uuid_is_null(pit_uuid))
        {
            r = -NUVO_E_WRONG_VOL_TYPE;
            goto unlock_vol;
        }
        break;

    case NUVO_VOL_LOG_VOL:
        if (!uuid_is_null(pit_uuid))
        {
            if (writable)
            {
                r = -NUVO_EROFS;
                goto unlock_vol;
            }

            lun = nuvo_get_lun_by_uuid_locked(nvs_p, pit_uuid, false);

            if (!lun)
            {
                r = -NUVO_ENOENT;
                goto unlock_vol;
            }
            break;
        }

        lun = &nvs_p->log_volume.lun;
        break;

    default:
        NUVO_PANIC("Unknown volume type");
    }

    nuvo_mutex_lock(&lun->mutex);

    if (lun->lun_state != NUVO_LUN_STATE_VALID || lun->export_state != NUVO_LUN_EXPORT_UNEXPORTED)
    {
        r = -NUVO_E_LUN_EXPORTED;
        goto unlock_lun;
    }


    if (nvs_p->type == NUVO_VOL_PARCEL)
    {
        lun->size = pm_total_size(&nvs_p->parvol.pm) - NUVO_SIMPLE_PARCEL_MANIFEST_SIZE;
    }

    // exporting a volume
    r = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_VALID,
                                  writable ? NUVO_LUN_EXPORT_WRITABLE : NUVO_LUN_EXPORT_READONLY);
    if (r != 0)
    {
        goto unlock_lun;
    }

    nuvo_fs_setup(lun, writable);
    r = nuvo_fuse_spawn(lun, nuvo_main_directory, lun_name);
    NUVO_ASSERT(r == 0);

unlock_lun:
    nuvo_mutex_unlock(&lun->mutex);
unlock_vol:
    nuvo_mutex_unlock(&nvs_p->mutex);
    return (r);
}

nuvo_return_t nuvo_export_lun(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name, int writable)
{
    // TODO - some locking? nuvo_mutex_lock(&fs->dir_mutex);
    nuvo_return_t r = export_lun_int(vol, pit_uuid, lun_name, writable);

    // TODO nuvo_mutex_unlock(&fs->dir_mutex);
    return (r);
}

static nuvo_return_t unexport_lun_int(struct nuvo_vol *nvs_p, const uuid_t pit_uuid, const char *lun_name)
{
    (void)lun_name;

    nuvo_return_t r;
    if (!nvs_p)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    nuvo_mutex_lock(&nvs_p->mutex);

    struct nuvo_lun *lun_p = NULL;
    switch (nvs_p->type)
    {
    case NUVO_VOL_PASSTHROUGH:
        lun_p = &nvs_p->ptvol.lun;
        break;

    case NUVO_VOL_PARCEL:
        lun_p = &nvs_p->parvol.lun;
        break;

    case NUVO_VOL_LOG_VOL:
        if (!uuid_is_null(pit_uuid))
        {
            lun_p = nuvo_get_lun_by_uuid_locked(nvs_p, pit_uuid, false);
            // We now have the lun pinned.

            if (!lun_p)
            {
                r = -NUVO_ENOENT;
                goto unlock_vol;
            }
            break;
        }
        lun_p = &nvs_p->log_volume.lun;
        break;

    default:
        NUVO_PANIC("Invalid volume type");
    }

    if (lun_p->export_state == NUVO_LUN_EXPORT_UNEXPORTED)
    {
        r = -NUVO_ENOENT;
        goto unlock_vol;
    }
    char export_path[MOUNT_POINT_BUFFER_MAX];
    int  rc = nuvo_fuse_get_lun_export_path(export_path, nuvo_main_directory, lun_name);
    if (rc > MOUNT_POINT_BUFFER_MAX)
    {
        NUVO_ERROR_PRINT("Lun name too long: %s", lun_name);
        r = -NUVO_ENOENT;
        goto unlock_vol;
    }
    if (0 != strcmp(export_path, lun_p->lun_fuse_mount_point))
    {
        NUVO_ERROR_PRINT("Unexport lun name %s does not match exported name %s", lun_name, lun_p->lun_fuse_mount_point);
        r = -NUVO_ENOENT;
        goto unlock_vol;
    }

    nuvo_mutex_unlock(&nvs_p->mutex);
    r = nuvo_fuse_stop(lun_p);
    if (r == -EBUSY)
    {
        NUVO_ERROR_PRINT("Unexport lun failed, EBUSY %s", lun_name);
        return (r);
    }
    nuvo_mutex_lock(&lun_p->mutex);

    NUVO_ASSERT(lun_p->export_state == NUVO_LUN_EXPORT_UNEXPORTED);
    NUVO_ASSERT(lun_p->io_pending_count == 0);

    // Wait for pending I/O to complete
    while (lun_p->io_pending_count != 0)
    {
        NUVO_LOG(fuse, 20, "Unexport waiting for pending I/O, count: %u", lun_p->io_pending_count);
        nuvo_cond_wait(&lun_p->io_pending_count_zero_cond, &lun_p->mutex);
    }

    r = 0;

    nuvo_mutex_unlock(&lun_p->mutex);

    nuvo_mutex_lock(&nvs_p->mutex);
    // I changed the fs and made the inum always 2
    if (uuid_is_null(pit_uuid))
    {
        NUVO_LOG(fuse, 0, "Unexport name: %s vs_uuid: " NUVO_LOG_UUID_FMT " ino: %d",
                 lun_name, NUVO_LOG_UUID(nvs_p->vs_uuid), NUVO_FUSE_LUN_INO);
    }
    else
    {
        NUVO_LOG(fuse, 0, "Unexport name: %s vs_uuid: " NUVO_LOG_UUID_FMT " pit_uuid " NUVO_LOG_UUID_FMT " ino: %d",
                 lun_name, NUVO_LOG_UUID(nvs_p->vs_uuid), NUVO_LOG_UUID(pit_uuid), NUVO_FUSE_LUN_INO);
    }

unlock_vol:
    nuvo_mutex_unlock(&nvs_p->mutex);
    return (r);
}

nuvo_return_t nuvo_unexport_lun(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name)
{
    // TODO nuvo_mutex_lock(&fs->dir_mutex);
    nuvo_return_t r = unexport_lun_int(vol, pit_uuid, lun_name);

    // nuvo_mutex_unlock(&fs->dir_mutex);
    return (r);
}

nuvo_return_t nuvo_lun_latency_limit(struct nuvo_vol *nvs_p,
                                     const uuid_t     lun_uuid,
                                     uint64_t         write_latency,
                                     uint64_t         read_latency)
{
    nuvo_return_t r;

    nuvo_mutex_lock(&nvs_p->mutex);

    struct nuvo_lun *lun_p = NULL;
    switch (nvs_p->type)
    {
    case NUVO_VOL_PASSTHROUGH:
        lun_p = &nvs_p->ptvol.lun;
        break;

    case NUVO_VOL_PARCEL:
        lun_p = &nvs_p->parvol.lun;
        break;

    case NUVO_VOL_LOG_VOL:
        if (uuid_is_null(lun_uuid) || 0 == uuid_compare(nvs_p->vs_uuid, lun_uuid))
        {
            lun_p = &nvs_p->log_volume.lun;
        }
        else if (!uuid_is_null(lun_uuid))
        {
            lun_p = nuvo_get_lun_by_uuid_locked(nvs_p, lun_uuid, false);
        }
        break;

    default:
        NUVO_PANIC("Invalid volume type");
    }
    if (!lun_p)
    {
        r = -NUVO_ENOENT;
        goto unlock_vol;
    }

    if (!lun_p)
    {
        r = -NUVO_ENOENT;
        goto unlock_vol;
    }

    lun_p->read_latency_min = read_latency;
    lun_p->write_latency_min = write_latency;
    r = 0;

unlock_vol:
    nuvo_mutex_unlock(&nvs_p->mutex);
    return (r);
}

/**
 * \brief Wrapper function around fuse_reply_err()
 *
 * We double check that we aren't sending nuvo specfic errors
 * (nuvo_error > NUVO_CUSTOM_ERROR) or -1 or -errno to fuse.
 * If we are, sadly we cast everything to EINVAL.
 *
 * TODO: Make this better by having nuvo functions return more accurate
 * error codes, and potentially adding a nuvo_error to fuse error translation
 * function.
 *
 * \retval 0 Success or -errno for failure to send reply to fuse
 */
int nuvo_fuse_reply_err(fuse_req_t req, int err)
{
    // This feels bad, but callers need to send better errors.
    if (err < 0 || err >= NUVO_CUSTOM_ERROR)
    {
        NUVO_ERROR_PRINT("Incorrect error passed to fuse.  Modifying error %d to %d.",
                         err, EINVAL);
        err = EINVAL;
    }

    return (fuse_reply_err(req, err));
}

static inline nuvo_fs_t *fuse_req_to_fs(fuse_req_t req)
{
    struct nuvo_lun *lun = (struct nuvo_lun *)fuse_req_userdata(req);

    return (&lun->lun_file_system);
}

void nuvo_fs_open(fuse_req_t req, long unsigned ino, struct fuse_file_info *fi)
{
    nuvo_open(fuse_req_to_fs(req), req, ino, fi);
}

void nuvo_fs_read(fuse_req_t req, fuse_ino_t ino, size_t size,
                  off_t off, struct fuse_file_info *fi)
{
    nuvo_read(fuse_req_to_fs(req), req, ino, size, off, fi);
}

void nuvo_fs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                   size_t size, off_t off, struct fuse_file_info *fi)
{
    nuvo_write(fuse_req_to_fs(req), req, ino, buf, size, off, fi);
}

void nuvo_fs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                     off_t off, struct fuse_file_info *fi)
{
    nuvo_readdir(fuse_req_to_fs(req), req, ino, size, off, fi);
}

void nuvo_fs_getattr(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info *fi)
{
    nuvo_getattr(fuse_req_to_fs(req), req, ino, fi);
}

void nuvo_fs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                     int to_set, struct fuse_file_info *fi)
{
    nuvo_setattr(fuse_req_to_fs(req), req, ino, attr, to_set, fi);
}

void nuvo_fs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    nuvo_lookup(fuse_req_to_fs(req), req, parent, name);
}

static void nuvo_fs_init(void *userdata, struct fuse_conn_info *conn)
{
    int writeback = 1;

    (void)userdata;

    if (writeback && conn->capable & FUSE_CAP_WRITEBACK_CACHE)
    {
        conn->want |= FUSE_CAP_WRITEBACK_CACHE;
        NUVO_LOG(fuse, 0, "FUSE writeback cache enabled\n");
    }
    else
    {
        NUVO_LOG(fuse, 0, "FUSE writeback cache disabled\n");
    }
}

static struct fuse_lowlevel_ops fs_ops =
{
    .init    = nuvo_fs_init,
    .lookup  = nuvo_fs_lookup,
    .getattr = nuvo_fs_getattr,
    .setattr = nuvo_fs_setattr,
    .readdir = nuvo_fs_readdir,
    .open    = nuvo_fs_open,
    .read    = nuvo_fs_read,
    .write   = nuvo_fs_write,
};

/*
 * Fuse session thread for an export.
 *
 * This runs the fuse session loop and on exit of the loop exits the
 * session.
 * \param arg The lun to export.
 */
static void *
nuvo_fuse_thread(void *arg)
{
    struct nuvo_lun *lun = (struct nuvo_lun *)arg;

    lun->vol->export_cnt++;
#if 0
    // TODO - update the fuse library so we can pass in the number of max idle threads.
    struct fuse_loop_config loop_config;
    loop_config.clone_fd = 0;
    loop_config.max_idle_threads = 12;
    int err = fuse_session_loop_mt(lun->lun_fuse_session, &loop_config);
#endif
    int err = fuse_session_loop_mt(lun->lun_fuse_session, 0);
    NUVO_PRINT("Mount %s exited %d", lun->lun_fuse_mount_point, err);
    nuvo_mutex_lock(&lun->mutex);
    nuvo_return_t r = nuvo_lun_state_transition(lun, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);
    NUVO_ASSERT(r == 0);
    NUVO_ASSERT(lun->vol->export_cnt >= 0);
    lun->vol->export_cnt--;
    nuvo_mutex_lock(&lun->lun_fuse_session_mutex);
    fuse_session_unmount(lun->lun_fuse_session);
    fuse_session_destroy(lun->lun_fuse_session);
    lun->lun_fuse_session = NULL;
    nuvo_mutex_unlock(&lun->lun_fuse_session_mutex);
    nuvo_mutex_unlock(&lun->mutex);
    pthread_exit(0);
    return (NULL);
}

/**
 * Create fuse handling for an exported lun.
 * \param lun The lun to spawn a thread on and export/mount.
 * \param export_dir Where to create the lun directory.
 * \param lun_name The name of the lun directory.
 */
nuvo_return_t nuvo_fuse_spawn(struct nuvo_lun *lun,
                              const char      *export_dir,
                              const char      *lun_name)
{
    int           rc;
    nuvo_return_t ret_val;

    nuvo_mutex_lock(&lun->lun_fuse_session_mutex);
    NUVO_ASSERT(lun->lun_fuse_session == NULL);
    rc = nuvo_fuse_get_lun_export_path(lun->lun_fuse_mount_point, export_dir, lun_name);
    if (rc > MOUNT_POINT_BUFFER_MAX)
    {
        NUVO_ERROR_PRINT("Export failed: mount point %s/%s too long", export_dir, lun_name);
        ret_val = -NUVO_ENOMEM;
        goto unlock_session;
    }

    /* This works well provided things are proceeding sanely and
     * we are unmounting from a previous crash.
     */
    rc = umount2(lun->lun_fuse_mount_point, MNT_FORCE);
    if (rc != 0 && errno != EINVAL && errno != ENOENT)
    {
        NUVO_ERROR_PRINT("Export failed: unable to unmount existing mount on %s %d", lun->lun_fuse_mount_point, errno);
        ret_val = rc;
        goto unlock_session;
    }
    rc = mkdir(lun->lun_fuse_mount_point, 0x700);
    if (rc != 0 && errno != EEXIST)
    {
        NUVO_ERROR_PRINT("Export failed: unable to create dir %s", lun->lun_fuse_mount_point, errno);
        ret_val = rc;
        goto unlock_session;
    }

    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    rc = fuse_opt_add_arg(&args, "nuvo");
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Export failed: unable to add fuse arg");
        ret_val = -NUVO_ENOMEM;
        goto remove_dir;
    }
    rc = fuse_opt_add_arg(&args, "-osubtype=nuvo");
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Export failed: unable to add fuse arg");
        fuse_opt_free_args(&args);
        ret_val = -NUVO_ENOMEM;
        goto remove_dir;
    }
    lun->lun_fuse_session = fuse_session_new(&args, &fs_ops, sizeof(fs_ops), lun);
    if (lun->lun_fuse_session == NULL)
    {
        NUVO_ERROR_PRINT("Export failed: fuse_session_new failed: %d", errno);
        fuse_opt_free_args(&args);
        ret_val = -NUVO_ENOMEM;
        goto unlock_session;
    }
    rc = fuse_session_mount(lun->lun_fuse_session, lun->lun_fuse_mount_point);
    if (rc != 0)
    {
        NUVO_ERROR_PRINT("Export failed: fuse_session_mount failed: %d, %d", rc, errno);
        ret_val = -1;
        goto free_session;
    }
    rc = pthread_create(&lun->lun_fuse_thread, NULL, nuvo_fuse_thread, lun);
    if (rc != 0)
    {
        NUVO_ASSERT(errno == EAGAIN);
        NUVO_ERROR_PRINT("Could not start fuse thread.");
        ret_val = -NUVO_ENOMEM;
        goto unmount_session;
    }
    nuvo_mutex_unlock(&lun->lun_fuse_session_mutex);
    return (0);

unmount_session:
    fuse_session_unmount(lun->lun_fuse_session);
free_session:
    fuse_session_destroy(lun->lun_fuse_session);
    lun->lun_fuse_session = NULL;
remove_dir:
    (void)rmdir(lun->lun_fuse_mount_point);
unlock_session:
    nuvo_mutex_unlock(&lun->lun_fuse_session_mutex);
    return (ret_val);
}

/*
 * Shutdown fuse handling for a node
 * \param lun The lun to unexport.
 */
nuvo_return_t nuvo_fuse_stop(struct nuvo_lun *lun)
{
    nuvo_return_t ret = 0;

    nuvo_mutex_lock(&lun->mutex);
    NUVO_ASSERT(lun->export_state != NUVO_LUN_EXPORT_UNEXPORTED);
    nuvo_mutex_unlock(&lun->mutex);

    nuvo_mutex_lock(&lun->lun_fuse_session_mutex);
    int rc = 0;
    if (lun->lun_fuse_session != NULL)
    {
        /*
         * The standard method to unmount fuse is from the mount (client side).
         * Unmounting there will send a the closing of the session over the
         * communication socket, letting the client threads close and then
         * closing the service thread.
         *
         * If we instead closed via sending fuse a stop and doing a
         * internal fuse unmount, we invite either semi-deadlock as the
         * worker threads sit waiting for someone to tell them to stop
         * or we shutdown violently as the stop/unmount cause unclean
         * shutdown of worker threads which leads to horrible things like
         * them dying while holding the stderr lock.
         *
         * Short version - by unmounting in a more "normal" way we avoid
         * a squirrely hell of unusual code paths.
         *
         *  Could possibly use system("fusermount -u -z " mountpoint)
         *
         * Sometimes unmount can fail because the kernel has not yet released
         * reference to lun_fuse_mount_point, so do some retry before giving up.
         */
        int max_try = (NUVO_UMOUNT_MAX_RETRY_ATTEMPT > 0 ? NUVO_UMOUNT_MAX_RETRY_ATTEMPT : 1);
        int num_try;

        for (num_try = 1; num_try <= max_try; num_try++)
        {
            if ((rc = umount2(lun->lun_fuse_mount_point, MNT_FORCE)) == 0)
            {
                ret = 0;
                break;
            }

            if (errno == EINVAL)
            {
                // Not mounted - could be racing with an external unmount.
                // Just go join the thread.
                ret = 0;
                break;
            }
            ret = -errno;

            usleep(NUVO_UMOUNT_RETRY_BACKOFF_MS * 1000);
        }

        if (rc == 0)
        {
            NUVO_LOG(fuse, 0, "Unmount %s succeeded after %d attempt(s)",
                     lun->lun_fuse_mount_point, num_try);
        }
        else
        {
            NUVO_ERROR_PRINT("Unexpected failure to unmount %s : %d", lun->lun_fuse_mount_point, errno);
        }
    }
    nuvo_mutex_unlock(&lun->lun_fuse_session_mutex);
    if (ret != 0)
    {
        return (ret);
    }

    ret = pthread_join(lun->lun_fuse_thread, NULL);
    NUVO_ASSERT(lun->lun_fuse_session == NULL);
    nuvo_mutex_lock(&lun->mutex);
    NUVO_ASSERT(lun->export_state == NUVO_LUN_EXPORT_UNEXPORTED);
    nuvo_mutex_unlock(&lun->mutex);
    return (ret);
}
