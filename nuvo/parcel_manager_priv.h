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

#include "parcel_manager.h"
#include "nuvo_list.h"
#include "nuvo_lock.h"
#include <stdint.h>
#include <uuid/uuid.h>
#include "nuvo_pr.h"

#define NUVO_PM_DEVICE_PRIVATEREGION_SIZE       ((NUVO_PM_DEVICE_MAX_PARCELBLOCKS * NUVO_PM_DEVICE_PARCELBLOCK_SIZE) + NUVO_PM_DEVICE_SUPERBLOCK_SIZE)
#define NUVO_PM_DEVICE_SUPERBLOCK_SIZE          (4096)
#define NUVO_PM_DEVICE_SUPERBLOCK_SIGNATURE     (0x4f56554e)
#define NUVO_PM_DEVICE_SUPERBLOCK_REVISION      (1)

#define NUVO_PM_PARCEL_MIN_SIZE                 (1048576)
#define NUVO_PM_DEVICE_PARCELBLOCK_SIZE         (4096)
#define NUVO_PM_PARCELBLOCK_HEADER_SIGNATURE    (0x4f534f4c)
#define NUVO_PM_PARCELBLOCK_HEADER_REVISION     (1)
#define NUVO_PM_PARCELBLOCK_ENTRY_SIGNATURE     (0x544e4550)

#define NUVO_PM_DEVICE_MAX_PARCELBLOCKS         ((1ull << NUVO_PM_MAX_PARCELBLOCKS_BITS) - 1ull)
#define NUVO_PM_PARCELBLOCK_ENTRIES             ((1ull << NUVO_PM_MAX_PARCELBLOCK_ENTRIES_BITS) - 1ull)
#define NUVO_PM_MAX_DEVICES                     ((1ull << NUVO_PM_MAX_DEVICES_BITS) - 1ull)
#define NUVO_PM_MAX_GENID                       ((1ull << NUVO_PM_MAX_GENID_BITS) - 1ull)
#define NUVO_PM_DEVICE_MAX_PARCELS              (NUVO_PM_DEVICE_MAX_PARCELBLOCKS * NUVO_PM_PARCELBLOCK_ENTRIES)

#define NUVO_PM_MAX_PARCELBLOCKS_BITS           (11)
#define NUVO_PM_MAX_DEVICES_BITS                (8)
#define NUVO_PM_MAX_PARCELBLOCK_ENTRIES_BITS    (6)
#define NUVO_PM_MAX_GENID_BITS                  (CHAR_BIT * sizeof(uint32_t) - (NUVO_PM_MAX_DEVICES_BITS + NUVO_PM_MAX_PARCELBLOCKS_BITS + NUVO_PM_MAX_PARCELBLOCK_ENTRIES_BITS))

#define NUVO_PM_JOIN_WAIT                       (6)

union native_parcel_descriptor
{
    uint32_t native_parcel_desc;
    struct {
        uint32_t gen_id  : NUVO_PM_MAX_GENID_BITS;
        uint32_t dev_idx : NUVO_PM_MAX_DEVICES_BITS;
        uint32_t pb_idx  : NUVO_PM_MAX_PARCELBLOCKS_BITS;
        uint32_t ent_idx : NUVO_PM_MAX_PARCELBLOCK_ENTRIES_BITS;
    };
};


/* max number of events to get at a time */
/* max number of iocbs to submit on a single io_submit */
#define NUVO_PM_MAX_EVENTS    (4096)
/* used for initializing the aio queue. must be less than equal /proc/sys/fs/aio-max-nr. typically 64K, this default is too large */
#define NUVO_PM_AIO_MAX_NR    (2 * NUVO_PM_MAX_EVENTS)
/* the mininum number of events to get before io_getevents returns */
#define NUVO_PM_MIN_EVENTS    (1)

/* signature tells us the data layout is ours */
/* checksum tells us the data isn't corrupted */
struct __attribute__((packed)) superblock {
    uint32_t signature;     /* identifies this as a superblock */
    uint32_t version;       /* version of the superblock layout */
    uint64_t gen_id;        /* generation id of the superblock */
    uuid_t   device_uuid;   /* the uuid of the device */
    uint64_t device_size;   /* raw device size in bytes */
    uint64_t parcel_size;   /* parcel size used to format the devivce in bytes */
    uint64_t ctime;         /* time the superblock was created */
    uint64_t utime;         /* time the superblock was updated */
    uint64_t checksum;      /* checksum covers whole block with this field zeroed */
};
static_assert(sizeof(struct superblock) == 72, "Somebody changed size of superblock, NBD.");

struct __attribute__((packed)) parcelblock_header {
    uint32_t signature;     /* identifies this as a parcelblock */
    uint32_t version;       /* version of the parcelblock layout */
    uint32_t block_idx;     /* index of this block in parceltable */
    uint64_t gen_id;        /* generation id of the parcelblock */
    uint32_t reserved[9];   /* unused */
    uint64_t checksum;
};
static_assert(sizeof(struct parcelblock_header) == 64, "Somebody changed size of parcelblock_header. Everything is broken.");

struct __attribute__((packed)) parcel_record {
    uint32_t signature;     /* identifies this as a parcel entry */
    uint32_t version;       /* version of the parcel entry layout */
    uuid_t   parcel_uuid;   /* uuid of this parcel */
    uuid_t   volume_uuid;   /* uuid of the volume this parcel belongs to */
    uint64_t parcel_offset; /* raw device offset of the parcel */
    uint64_t ctime;         /* time this entry was added to the parcelblock */
    uint32_t reserved[2];   /* unused */
};
static_assert(sizeof(struct parcelblock_header) == 64, "Somebody changed size of parcel_record. Everything is broken.");

/* each 4K block has a header and 63 parcel table entries. */
struct __attribute__((packed)) device_parcelblock {
    struct parcelblock_header header;
    struct parcel_record      parcels[NUVO_PM_PARCELBLOCK_ENTRIES];
};
static_assert(sizeof(struct device_parcelblock) == NUVO_BLOCK_SIZE, "Somebody changed size of device_parcelblock. Everything is broken.");

struct parcel_metadata {
    uint32_t gen_id;
    uint32_t open;
};

struct parcelblock {
    struct device_parcelblock *device_parcelblock;
    struct parcel_metadata     meta[NUVO_PM_PARCELBLOCK_ENTRIES];
    uint32_t                   pending_update; /* set to 1 when an update to this parcelblock is outstanding */
    uint32_t                   allocated_cnt;  /* how many devices have had records allocated */
    nuvo_mutex_t               pb_lock;        /* TODO: change to a spinlock */
    struct nuvo_dlist          deferred_list;  /* list of deferred io requests */
    nuvo_mutex_t               deferred_list_lock;
};

struct device_record {
    struct superblock   *superblock;
    struct parcelblock   parcelblocks[NUVO_PM_DEVICE_MAX_PARCELBLOCKS];
    struct device_info   device_info;
    struct nuvo_io_stats write_io_stats;
    struct nuvo_io_stats read_io_stats;
    int64_t              io_delay;       /* Make every IO take at least this many nanoseconds */
    int                  allocated;      /* device record is allocated and in use, but no necessarily open */
    int                  open;           /* device is open with parcels allocated. note device records aren't reopened */
    int                  fd;             /* file descriptor for the device */
    nuvo_mutex_t         device_lock;
};

struct device_records {
    struct device_record devices[NUVO_PM_MAX_DEVICES];   /* device array */
    nuvo_mutex_t         devices_lock;
};
#define DEVICE_INDEX(d)    (d - &g_devices.devices[0])
