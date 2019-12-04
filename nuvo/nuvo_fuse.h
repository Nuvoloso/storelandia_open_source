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
// TODO - Why 32?
#define FUSE_USE_VERSION    32

#include <fuse3/fuse_lowlevel.h>
#include <uuid/uuid.h>

#include "lun.h"
#include "nuvo_lock.h"
#include "nuvo_list.h"
#include "nuvo_range_lock.h"
#include "status.h"

int nuvo_create_passthrough(const char *vol, const char *blk_dev, size_t size);
nuvo_return_t nuvo_export_lun(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name, int writable);
nuvo_return_t nuvo_unexport_lun(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name);

void nuvo_open(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void nuvo_create(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t parent, const char *name,
                 mode_t mode, struct fuse_file_info *fi);
void nuvo_read(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, size_t size,
               off_t off, struct fuse_file_info *fi);
void nuvo_write(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, const char *buf,
                size_t size, off_t off, struct fuse_file_info *fi);
void nuvo_readdir(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino, size_t size,
                  off_t off, struct fuse_file_info *fi);
void nuvo_getattr(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino,
                  struct fuse_file_info *fi);
void nuvo_setattr(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t ino,
                  struct stat *attr, int to_set, struct fuse_file_info *fi);
void nuvo_lookup(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t parent, const char *name);
void nuvo_rename(nuvo_fs_t *fs, fuse_req_t req, fuse_ino_t parent, const char *name,
                 fuse_ino_t newparent, const char *newname, unsigned int flags);

// Wrapper for fuse_reply_err()
int nuvo_fuse_reply_err(fuse_req_t req, int err);

/*
 * Included for unit testing.
 */
void nuvo_fs_setup(struct nuvo_lun *lun, bool writable);
void nuvo_fill_attr(nuvo_node_t *f, struct stat *stbuf);
nuvo_return_t nuvo_find_dir_ent(nuvo_node_t *d, const char *name, fuse_ino_t *inum, unsigned int *idx);
void nuvo_add_dir_entry(nuvo_node_t *dir, const char *name, unsigned int inum);


nuvo_return_t nuvo_fuse_spawn(struct nuvo_lun *lun,
                              const char      *export_dir,
                              const char      *lun_name);
nuvo_return_t nuvo_fuse_stop(struct nuvo_lun *lun);

/*
 * Maximum amount of time (in seconds) to spend on retrying unmount when stopping FUSE
 */
#define NUVO_UMOUNT_MAX_RETRY_SEC        5

/*
 * Duration of time (in milliseconds) to wait before next retry. Cannot be zero.
 */
#define NUVO_UMOUNT_RETRY_BACKOFF_MS     100

/*
 * Number of attempts to retry
 */
#define NUVO_UMOUNT_MAX_RETRY_ATTEMPT    ((NUVO_UMOUNT_MAX_RETRY_SEC * 1000) / NUVO_UMOUNT_RETRY_BACKOFF_MS)
