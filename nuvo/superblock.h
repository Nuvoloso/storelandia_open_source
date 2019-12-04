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

/**
 * @file superblock.h
 */
#pragma once
#include <inttypes.h>
#include <stdbool.h>
#include "nuvo_hash.h"
#include "status.h"

/**
 * \brief location of key tables within the system.
 * Implicitly assumes we can get the parcel manfest to look up the index.
 */
struct __attribute__((packed)) nuvo_sb_table_location {
    uint32_t parcel_index;  /** The parcel index. */
    uint32_t block_offset;  /** The offset within the block. */
    uint32_t block_length;  /** Length of this location within the parcel. */
};

/**
 * \brief The superblock of a volume series.
 *
 * This is the block placed at the beginning of a volume series.
 * We keep two copies of manifest and the segment table.
 * There is a strong case to be made that this should be an array of two
 * copies of the structure of the manifest and the segment table,
 * rather than an array for reach.
 */
struct __attribute__((packed)) nuvo_sb_superblock {
    uint64_t    magic;                                  /** Magic number for a superblock. */
    nuvo_hash_t hash;                                   /** Hash of this data structure with hash set to 0. */
    uuid_t      vol_series_uuid;                        /** The volume uuid of this volume series. */
    uint64_t    generation;                             /** Increase by one each time we write it out. */
    uint32_t    git_hash;                               /** Git short commit id of software version that last wrote this superblock. */
    uint8_t     replay_count;                           /** Number of replay attempts since the last successful open. */
    struct nuvo_sb_table_location parcel_manifest[2];   /** Header, devices, parcels */
    struct nuvo_sb_table_location segment_table[2];     /** Segments. */
};

#define NUVO_SB_MAGIC             0x24f17a5b77c7dab1
#define NUVO_SB_BLOCK_OFFSET_0    0
#define NUVO_SB_BLOCK_OFFSET_1    1
#define NUVO_SB_BLOCK_COPIES      2
#define NUVO_SB_MFST_START        (NUVO_SB_BLOCK_OFFSET_1 + 1)

/**
 * \brief Get the address of a copy of the manifest.
 *
 * Returns the address of either copy 0 or copy 1 of the manifest from the superblock
 *
 * \param sb The superblock
 * \param zero_one 0 or 1 to return address of copy 0 or copy 1.
 */
const struct nuvo_sb_table_location *nuvo_sb_get_parcel_manifest_addr(struct nuvo_sb_superblock *sb, int zero_one);

/**
 * \brief Get the address of a copy of the segment table.
 *
 * Returns the address of either copy 0 or copy 1 of the manifest from the superblock
 *
 * \param sb The superblock
 * \param zero_one 0 or 1 to return address of copy 0 or copy 1.
 */
const struct nuvo_sb_table_location *nuvo_sb_get_segment_table_addr(struct nuvo_sb_superblock *sb, int zero_one);

/**
 * \brief Read the superblock from the open parcel.
 *
 * This reads both copies of the superblock from the device and returns the one with the highest
 * generation number and hash.  The assumption is that the hash will be wrong due to failure in the
 * middle of write, so the other version is the current version.
 *
 * \param sb Pointer to the locaiton to read.
 * \param root_parcel_desc The parcel descriptor to the open parcel.
 */
nuvo_return_t nuvo_sb_sync_read(struct nuvo_sb_superblock *sb, uint_fast32_t root_parcel_desc);

/**
 * \brief Write a single copy of the super block.
 *
 * This increments the generation of the superblock and then decides where to write it based on the
 * new value of the superblock.
 *
 * \param sb The superblock to write.
 * \param parcel_desc The parcel descriptor of the root parcel.
 * \retval 0 Success
 * \retval negative some sort of IO error.
 */
nuvo_return_t nuvo_sb_sync_write(struct nuvo_sb_superblock *sb, uint_fast32_t parcel_desc);

/**
 * \brief Setup a new superblock
 *
 * This setups up the superblock with addresses for the requested size reserved for the
 * manifest (\c init_st_blks) and for the segment table (\c init_st_blks).  It currently
 * lays out the space in the root parcel (parcel index 0) as:
 *
 * superlock 0: 1 block. (offset 0 for 1 block)
 * superblock 1: 1 block (offset 1 for 1 block)
 * pm 0: init_pm_blks blocks (offset 2 for init_pm_blks blocks)
 * pm 1: init_pm_blks blocks (offset 2 + init_pm_blks for init_pm_blks blocks)
 * st 0: init_st_blks blocks (offset 2 + 2 * init_pm_blks) for init_st_blks blocks)
 * st 1: init_st_blks blocks (offset 2 + 2 * init_pm_blks + init_st_blks) for init_st_blks blocks)
 *
 * \param sb The superblock to init.
 * \param vol_series_uuid The uuid of the volume series.
 * \param init_pm_blks How many blocks to reserve for each copy of the header/device table/parcel table.
 * \param init_st_blks How many blocks to reserve for each copy of the segment table.
 */
void nuvo_sb_init(struct        nuvo_sb_superblock *sb,
                  const uuid_t                      vol_series_uuid,
                  uint16_t                          init_pm_blks,
                  uint16_t                          init_st_blks);
