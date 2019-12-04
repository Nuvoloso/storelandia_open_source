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
 * \file parcel_manager.c
 * \brief Implements the Parcel Manager
 *
 * The parcel manager is responsible for all I/O operations to local devices.
 * It provides synchronous functions for formatting a new device, pm_device_format(),
 * and a function to subsequently use the device, nuvo_pm_device_open().  nuvo_pm_device_info()
 * provides utilization and offset information about the device.
 *
 * After a device is opened for use, I/O operations are supported through the asynchronous
 * nuvo_pm_submit function. The nuvo_pm_submit function provides an interface for issuing I/O requests
 * to a device or devices and will call a pre-defined callback on completion to provide
 * notification of the completion, or an error status.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include "nuvo.h"
#include "nuvo_stats.h"
#include "nuvo_pr.h"
#include "parcel_manager_priv.h"
#include "signal_handler.h"
#include "nuvo_vol_series.h"
#include "status.h"

static int            g_pm_initialized = 0; /* initialization flag */
static int            g_pm_shutdown = 0;    /* shutdown flag */
static pthread_t      g_tid;                /* the getevents thread id */
static io_context_t   g_ctx;                /* the AIO context */
struct device_records g_devices;            /* the global device list */

static void *pm_getevents_th(__attribute__((unused)) void *arg);
static int64_t pm_parcel_open(const uuid_t parcel_uuid, const uuid_t device_uuid, const uuid_t volume_uuid, uint_fast32_t *native_parcel_desc);
static int64_t pm_parcel_close(struct nuvo_io_request *io_req);
static bool pm_parcel_uuid_exists(struct device_record *device, uuid_t parcel_uuid);
static void nuvo_pm_submit_internal(struct nuvo_dlist *submit_list);

enum superblock_header_index
{
    NUVO_PM_SUPERBLOCK_A = 0,
    NUVO_PM_SUPERBLOCK_B,
    NUVO_PM_SUPERBLOCKS
};

/**
 * \brief Converts a 32 bit gen_id in the parcel entry to a NUVO_PM_GENID_BITS gen_id
 *
 * The gen_id stored in the parcel descriptor is modulo NUVO_PM_MAX_GENID + 1
 *
 * \param gen_id A parcel entry generation count.
 * \returns a NUVO_PM_GENID_BITS gen_id.
 */
static inline uint8_t pm_parcel_to_desc_genid(uint32_t gen_id)
{
    return (gen_id % (NUVO_PM_MAX_GENID + 1));
}

/**
 * \fn struct device_record *alloc_device_record(const uuid_t device_uuid)
 * \brief returns a pointer to the first free device record, and associates
 * the entry with given device_uuid.
 *
 *  caller needs to hold &g_devices.devices_lock before calling this.
 *
 * \param device_uuid  The device_uuid to be used for the device.
 * \return A pointer to the first free device record, otherwise NULL.
 */
static struct device_record *alloc_device_record(const uuid_t device_uuid)
{
    struct device_record *device = NULL;
    uint32_t idx = 0;
    int      found = 0;

    if (g_pm_shutdown)
    {
        return (NULL);
    }

    while (!found && (idx < NUVO_PM_MAX_DEVICES))
    {
        if (g_devices.devices[idx].allocated)
        {
            idx++;
            continue;
        }
        else
        {
            found = 1;
        }
    }

    if (found)
    {
        device = &g_devices.devices[idx];

        /*
         * clear out the device record
         * and initialize the mutex.
         */
        for (uint32_t i = 0; i < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; i++)
        {
            memset(&device->parcelblocks[i], 0, sizeof(struct parcelblock));
            if ((nuvo_mutex_init(&device->parcelblocks[i].pb_lock) != 0) ||
                (nuvo_mutex_init(&device->parcelblocks[i].deferred_list_lock) != 0))
            {
                NUVO_ERROR_PRINT("unable initialize mutex");
                return (NULL);
            }
        }
        device->superblock = NULL;
        device->io_delay = 0;
        device->open = 0;
        device->fd = 0;
        memset(&device->device_info, 0, sizeof(struct device_info));

        /* associate the record with the device uuid and mark it allocated */
        uuid_copy(device->device_info.device_uuid, device_uuid);
        device->allocated = 1;
    }

    return (device);
}

/**
 * \fn void free_device_record(struct device_record *device)
 * \brief marks the given device_record for reuse.
 *
 * frees and zeros out the device record pointed to by the device
 * parameter, making the device available for reuse.
 *
 * Call with the &g_devices.devices_lock and the &g_devices.devices[].device_lock.
 * should be called only when the device is already closed.
 *
 * \param device  A pointer to the record to free.
 * \return none.
 */
static void free_device_record(struct device_record *device)
{
    if (device)
    {
        for (uint32_t j = 0; j < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; j++)
        {
            struct device_parcelblock *pb = device->parcelblocks[j].device_parcelblock;
            if (pb)
            {
                free(pb);
                pb = NULL;
            }
            device->parcelblocks[j].pending_update = 0;
            device->parcelblocks[j].allocated_cnt = 0;
        }

        if (device->superblock)
        {
            free(device->superblock);
            device->superblock = NULL;
        }

        device->open = 0;
        device->allocated = 0;
    }
}

/**
 * \fn struct device_record *get_device_record_by_fd(int fd)
 * \brief returns a pointer to the requested device record.
 *
 * \param fd  The fd of the device.
 * \return A pointer to the requested device record, otherwise NULL.
 */
struct device_record *get_device_record_by_fd(int fd)
{
    struct device_record *device = NULL;

    NUVO_ASSERT_MUTEX_HELD(&g_devices.devices_lock);

    for (uint32_t i = 0; i < NUVO_PM_MAX_DEVICES; i++)
    {
        if (g_devices.devices[i].allocated == 1)
        {
            if (g_devices.devices[i].fd == fd)
            {
                device = &g_devices.devices[i];
                break;
            }
        }
    }
    return (device);
}

/**
 * \fn struct device_record *get_device_record(const uuid_t device_uuid)
 * \brief returns a pointer to the requested device record.
 *
 * should hold &g_devices.devices_lock before calling this.
 * this routine can be used to lookup devices during shutdown.
 *
 * \param device_uuid  The uuid of the device being looked up.
 * \return A pointer to the requested device record, otherwise NULL.
 */
struct device_record *get_device_record(const uuid_t device_uuid)
{
    struct device_record *device = NULL;

    NUVO_ASSERT_MUTEX_HELD(&g_devices.devices_lock);

    for (uint32_t i = 0; i < NUVO_PM_MAX_DEVICES; i++)
    {
        if (g_devices.devices[i].allocated == 1)
        {
            if (uuid_compare(device_uuid, g_devices.devices[i].device_info.device_uuid) == 0)
            {
                device = &g_devices.devices[i];
                break;
            }
        }
    }

    return (device);
}

/**
 * \fn struct device_record *get_open_device_record(uuid_t device_uuid)
 * \brief returns a pointer to the requested device record if the device is open.
 *
 * should hold &g_devices.devices_lock before calling this.
 *
 * \param device_uuid  The uuid of the device being looked up.
 * \return A pointer to the requested device record, otherwise NULL.
 */
struct device_record *get_open_device_record(const uuid_t device_uuid)
{
    struct device_record *device = NULL;

    NUVO_ASSERT_MUTEX_HELD(&g_devices.devices_lock);
    device = get_device_record(device_uuid);
    if (!device || (device->open == 0))
    {
        device = NULL;
    }

    return (device);
}

/**
 * \fn int valid_device_superblock(struct superblock *superblock)
 * \brief returns if the data passed is a valid superblock
 *
 * validates the signature and checksum.
 *
 * \param superblock  A pointer to a 4K superblock.
 * \return 1 if valid, otherwise 0.
 */
static int valid_device_superblock(struct superblock *superblock)
{
    int valid;

    if (superblock->signature != NUVO_PM_DEVICE_SUPERBLOCK_SIGNATURE)
    {
        valid = 0;
    }
    else
    {
        uint64_t checksum = superblock->checksum;
        superblock->checksum = 0;
        if (checksum != nuvo_hash(superblock, NUVO_PM_DEVICE_SUPERBLOCK_SIZE))
        {
            valid = 0;
        }
        else
        {
            valid = 1;
        }
        superblock->checksum = checksum;
    }

    return (valid);
}

/**
 * \fn int get_device_size(int fd, uint64_t *size)
 * \brief Gets the device size
 *
 * returns the size of either a regular file or block device specified by
 * the file descriptor fd.
 *
 * \param fd The file descriptor for device or file.
 * \param size Pointer to memory to return the size value.
 * \return 0 on success, otherwise -errno.
 */
static int get_device_size(int fd, uint64_t *size)
{
    struct stat device_stat;

    if (fstat(fd, &device_stat) < 0)
    {
        return (-errno);
    }

    if (S_ISREG(device_stat.st_mode))
    {
        *size = device_stat.st_size;
    }
    else if (S_ISBLK(device_stat.st_mode))
    {
        if (ioctl(fd, BLKGETSIZE64, size) < 0)
        {
            return (-errno);
        }
    }
    else
    {
        return (-EINVAL);
    }

    return (0);
}

/**
 * \fn uint64_t nuvo_device_superblock_offset(uint64_t device_size, uint32_t superblock_idx)
 * \brief returns the address of the device superblock specified by idx
 *
 * There are two copies of the superblock. the active copy of the superblock is
 * identified by its generation id.
 * The first superblock and parcel table starts at lba 0.
 * The second superblock and parcel table is offset from end of device aligned on a 4K  boundary.
 *
 * \param device_size The size of the device.
 * \param superblock_idx The superblock copy.
 * \return none.
 */
static inline uint64_t nuvo_device_superblock_offset(uint64_t device_size, uint32_t superblock_idx)
{
    NUVO_ASSERT(superblock_idx == 0 || superblock_idx == 1);
    return (((device_size - NUVO_PM_DEVICE_PRIVATEREGION_SIZE) & ~(NUVO_BLOCK_SIZE - 1)) * superblock_idx);
}

/**
 * \fn uint64_t nuvo_device_parcelblock_offset(uint64_t superblock_offset, uint32_t parcelblock_idx)
 * \brief returns the device address of the parcelblock at the specificed by idx
 *
 * \param superblock_offset device offset of the superblock.
 * \param parcelblock_idx The index of the parcelblock
 * \return none.
 */
static inline uint64_t nuvo_device_parcelblock_offset(uint64_t superblock_offset, uint32_t parcelblock_idx)
{
    return (superblock_offset + NUVO_PM_DEVICE_SUPERBLOCK_SIZE + (NUVO_PM_DEVICE_PARCELBLOCK_SIZE * parcelblock_idx));
}

/**
 * \fn uint64_t nuvo_parcel_offset(const struct device_info *device_info, uint32_t parcelblock_idx, uint32_t parcel_idx)
 * \brief returns the device offset of the parcel at the specified by parcelblock_idx:parcel_idx
 *
 * \param device_info The device record.
 * \param parcelblock_idx The index of the parcelblock.
 * \param parcel_idx The index of the parcel entry.
 * \return none.
 */
static inline uint64_t nuvo_parcel_offset(const struct device_info *device_info, uint32_t parcelblock_idx, uint32_t parcel_idx)
{
    return (device_info->formatted_start_offset + ((parcelblock_idx * NUVO_PM_PARCELBLOCK_ENTRIES) * device_info->parcel_size) + (device_info->parcel_size * parcel_idx));
}

/**
 * \fn static inline void init_device_info_and_stats(struct device_record *device)
 * \brief Initializes the device_info struct containing device partitioning offsets.
 *
 * The device handle must be initialized with a valid superblock before calling.
 *
 * \param device - The device handle
 * \return 0 on success, otherwise -errno.
 */
static inline int64_t init_device_info_and_stats(struct device_record *device)
{
    int64_t ret = 0;

    uuid_copy(device->device_info.device_uuid, device->superblock->device_uuid);
    device->device_info.device_type = NUVO_DEV_TYPE_SSD;
    device->device_info.parcel_size = device->superblock->parcel_size;
    device->device_info.device_size = device->superblock->device_size;
    device->device_info.header_size = (uint64_t)NUVO_PM_DEVICE_PRIVATEREGION_SIZE;
    device->device_info.even_header_start_offset = nuvo_device_superblock_offset(device->superblock->device_size, 0);
    device->device_info.even_header_end_offset = device->device_info.even_header_start_offset + device->device_info.header_size;
    device->device_info.odd_header_start_offset = nuvo_device_superblock_offset(device->superblock->device_size, 1);
    device->device_info.odd_header_end_offset = device->device_info.odd_header_start_offset + device->device_info.header_size;
    device->device_info.formatted_start_offset = device->device_info.even_header_end_offset;
    device->device_info.formatted_end_offset = device->device_info.odd_header_start_offset;
    device->device_info.formatted_size = device->device_info.formatted_end_offset - device->device_info.formatted_start_offset;
    device->device_info.max_parcels = device->device_info.formatted_size / device->device_info.parcel_size;
    if (device->device_info.max_parcels > NUVO_PM_DEVICE_MAX_PARCELS)
    {
        device->device_info.max_parcels = NUVO_PM_DEVICE_MAX_PARCELS;
    }
    device->device_info.formatted_aligned_size = device->device_info.max_parcels * device->device_info.parcel_size;
    device->device_info.formatted_aligned_end_offset = device->device_info.formatted_start_offset + device->device_info.formatted_aligned_size;
    device->device_info.parceltable_full = 0;

    if ((ret = nuvo_io_stats_init(&device->write_io_stats)) < 0)
    {
        NUVO_ERROR_PRINT("error initializing write io stats\n");
    }
    else if ((ret = nuvo_io_stats_init(&device->read_io_stats)) < 0)
    {
        nuvo_io_stats_destroy(&device->write_io_stats);
        NUVO_ERROR_PRINT("error initializing read io stats\n");
    }
    return (ret);
}

/**
 * \fn void init_device_superblock(struct superblock *superblock, uuid_t device_uuid, uint64_t parcel_size, uint64_t device_size, uint64_t gen_id)
 * \brief initializes a device superblock struct
 * \param superblock The struct superblock to initialize.
 * \param device_uuid The uuid of the device.
 * \param parcel_size The size of parcels on the device.
 * \param device_size The size of the device.
 * \param gen_id The version of the structure.
 * \return none.
 */
static inline void init_device_superblock(struct superblock *superblock, const uuid_t device_uuid, const uint64_t parcel_size, const uint64_t device_size, const uint64_t gen_id)
{
    memset(superblock, 0, NUVO_PM_DEVICE_SUPERBLOCK_SIZE);
    uuid_copy(superblock->device_uuid, device_uuid);
    superblock->signature = NUVO_PM_DEVICE_SUPERBLOCK_SIGNATURE;
    superblock->version = NUVO_PM_DEVICE_SUPERBLOCK_REVISION;
    superblock->gen_id = gen_id;
    superblock->parcel_size = parcel_size;
    superblock->device_size = device_size;
    superblock->ctime = time(NULL);
    superblock->utime = time(NULL);
    superblock->checksum = 0;
    superblock->checksum = nuvo_hash(superblock, NUVO_PM_DEVICE_SUPERBLOCK_SIZE);
}

/**
 * \fn struct device_parcelblock *new_device_parcelblock()
 * \brief allocates 4K aligned memory for staging a new parcelbock
 * \return The device_parcelblock struct, otherwise NULL;
 */
struct device_parcelblock *new_device_parcelblock()
{
    void *data;

    if (posix_memalign((void **)&data, NUVO_BLOCK_SIZE, NUVO_PM_DEVICE_PARCELBLOCK_SIZE))
    {
        NUVO_ERROR_PRINT_ERRNO(errno, "%s: posix_memalign failed\n", __func__);
        return (NULL);
    }

    return ((struct device_parcelblock *)data);
}

/**
 * \fn void free_device_parcelblock(struct device_parcelblock *device_parcelblock)
 * \brief frees the memory pointed to be device_parcelblock.
 * \param device_parcelblock The device_parcelblock struct.
 * \return none
 */
static void free_device_parcelblock(struct device_parcelblock *device_parcelblock)
{
    free(device_parcelblock);
}

/**
 * \fn void init_device_parcelblock(struct device_parcelblock *device_parcelblock, uint32_t parcelblock_idx, uint64_t gen_id)
 * \brief initializes a parcel table block struct
 * \param device_parcelblock The device_parcelblock struct.
 * \param parcelblock_idx The parcel table block index.
 * \param gen_id A generation id.
 * \return none.
 */
static inline void init_device_parcelblock(struct device_parcelblock *device_parcelblock, uint32_t parcelblock_idx, uint64_t gen_id)
{
    memset(device_parcelblock, 0, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);
    device_parcelblock->header.signature = NUVO_PM_PARCELBLOCK_HEADER_SIGNATURE;
    device_parcelblock->header.version = NUVO_PM_PARCELBLOCK_HEADER_REVISION;
    device_parcelblock->header.block_idx = parcelblock_idx;
    device_parcelblock->header.gen_id = gen_id;
    device_parcelblock->header.checksum = 0;
    device_parcelblock->header.checksum = nuvo_hash(device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);
}

/**
 * \fn  int valid_device_parcelblock(struct device_parcelblock *device_parcelblock)
 * \brief returns if the device_parcelblock is valid.
 * \param device_parcelblock The device_parcelblock struct.
 * \return 1 if valid, otherwise 0.
 */
static int valid_device_parcelblock(struct device_parcelblock *device_parcelblock)
{
    int valid;

    if (device_parcelblock->header.signature != NUVO_PM_PARCELBLOCK_HEADER_SIGNATURE)
    {
        valid = 0;
    }
    else
    {
        uint64_t checksum = device_parcelblock->header.checksum;
        device_parcelblock->header.checksum = 0;
        if (checksum != nuvo_hash(device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE))
        {
            valid = 0;
        }
        else
        {
            valid = 1;
        }
        device_parcelblock->header.checksum = checksum;
    }
    return (valid);
}

/**
 * \fn int64_t pm_update_current_parcelblock(int op, struct device_parcelblock *device_parcelblock, struct device_record *device)
 * \brief updates the in memory parcel table with the new parcel block.
 *
 *  caller must hold the device lock.
 *
 * \param op The type of operation causing this.
 * \param device_parcelblock - pointer to the parcel block
 * \param device - a device handle for the device the parcel block is on
 * \return 0 on success
 */
int64_t pm_update_current_parcelblock(int op, struct device_parcelblock *device_parcelblock, struct device_record *device)
{
    NUVO_ASSERT(device_parcelblock != NULL);
    NUVO_ASSERT(device != NULL);

    if (device->open)
    {
        uint32_t parcelblock_idx = device_parcelblock->header.block_idx;
        nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);

        /* swap the new parcel block in and free the old one */
        struct device_parcelblock *old_parcelblock = device->parcelblocks[parcelblock_idx].device_parcelblock;
        device->parcelblocks[parcelblock_idx].device_parcelblock = device_parcelblock;
        device->parcelblocks[parcelblock_idx].pending_update = 0;
        free_device_parcelblock(old_parcelblock);
        if (op == NUVO_OP_FREE)
        {
            device->device_info.parceltable_full = 0;
            device->device_info.parcels_allocated--;
            device->parcelblocks[parcelblock_idx].allocated_cnt--;
        }
        else
        {
            device->device_info.parcels_allocated++;
            if (device->device_info.parcels_allocated == device->device_info.max_parcels)
            {
                device->device_info.parceltable_full = 1;
            }
        }
        nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);
    }
    else
    {
        /*
         * The device is closed/closing the in memory parcel table isn't updated
         * still return success since this commit was noop, not an error.
         */
        free_device_parcelblock(device_parcelblock);
    }
    return (0);
}

/**
 * \fn inline int check_empty(void *data, size_t size)
 * \brief Checks if the give data pointer is zero'd.
 * \param data - pointer to the data
 * \param size - number of bytes in the data buffer
 * \return 1 if empty, otherwise 0.
 */
static inline int check_empty(void *data, size_t size)
{
    for (unsigned int i = 0; i < size; i++)
    {
        if (*(char *)data++ != 0)
        {
            return (0);
        }
    }
    return (1);
}

static inline void init_parcelblock_entry(const uuid_t volume_uuid, const uuid_t parcel_uuid, const uint64_t offset, struct parcel_record *parcel)
{
    parcel->signature = NUVO_PM_PARCELBLOCK_ENTRY_SIGNATURE;
    if (uuid_is_null(parcel_uuid))
    {
        uuid_generate(parcel->parcel_uuid);
    }
    else
    {
        uuid_copy(parcel->parcel_uuid, parcel_uuid);
    }
    uuid_copy(parcel->volume_uuid, volume_uuid);
    parcel->parcel_offset = offset;
    parcel->ctime = time(NULL);
}

/**
 * \fn int64_t pm_prep_parcel_free(struct device_record *device, struct nuvo_io_request *io_req)
 * \brief prepares a new device_parcelblock record freeing the entry.
 *
 *  ESHUTDOWN - shutdown in progress.
 *  NUVO_E_PARCEL_ALREADY_FREE - the parcel wasn't found or isn't open.
 *  EPERM - an incorrect volume_uuid was specified.
 *  EAGAIN - the parcelblock is in use.
 *
 *  caller must hold the device lock.
 *
 * \param device The device the request is for.
 * \param io_req contains the information on the parcel.
 * \return 0 on success, otherwise -errno.
 */
int64_t pm_prep_parcel_free(struct device_record *device, struct nuvo_io_request *io_req)
{
    int      err = 0;
    uint32_t parcelblock_idx;
    uint64_t parcelblock_offset;
    uint32_t parcel_idx;
    int      parcelblock_found = 0;

    NUVO_ASSERT(device != NULL);
    NUVO_ASSERT(io_req != NULL);
    NUVO_ASSERT(io_req->operation == NUVO_OP_FREE);

    if (g_pm_shutdown)
    {
        err = ESHUTDOWN;
        io_req->status = -err;
        goto out;
    }
    else if (!device->open)
    {
        err = ENOENT;
        io_req->status = -err;
        goto out;
    }

    /*
     * lookup the parcelblock and entry index for the parcel entry.
     * verifies the volume uuid provided in the request matches the parcel entry.
     */
    if (!io_req->free.deferred_flag)
    {
        /* find this parcel */
        parcelblock_idx = 0;
        int last_parcelblock = 0;
        while (!parcelblock_found && !last_parcelblock && !err && (parcelblock_idx < NUVO_PM_DEVICE_MAX_PARCELBLOCKS))
        {
            nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);
            if (device->parcelblocks[parcelblock_idx].device_parcelblock != NULL)
            {
                for (parcel_idx = 0; parcel_idx < NUVO_PM_PARCELBLOCK_ENTRIES; parcel_idx++)
                {
                    uuid_t *uuid = &device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[parcel_idx].parcel_uuid;
                    if (uuid_compare(io_req->free.parcel_uuid, *uuid) == 0)
                    {
                        uuid = &device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[parcel_idx].volume_uuid;
                        if (uuid_compare(io_req->free.volume_uuid, *uuid) == 0)
                        {
                            parcelblock_found = 1;
                            break;
                        }
                        else
                        {
                            /* found the requested parcel, but it doesn't match the volume uuid provided */
                            NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Unable to free parcel. Unexpected volume uuid "NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(io_req->free.parcel_uuid), NUVO_LOG_UUID(*uuid));
                            err = EPERM;
                            io_req->status = -err;
                            break;
                        }
                    }
                }
            }
            else
            {
                /* no parcelblocks left to search that had entries */
                last_parcelblock = 1;
            }
            nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);
            if (!parcelblock_found && !last_parcelblock && !err)
            {
                parcelblock_idx++;
            }
        }

        if (!parcelblock_found)
        {
            // This parcel has already been freed or doesn't exist.  Either way
            // the end result is a free parcel.  This error will be translated
            // to success by the parcel router.
            NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Parcel is already free.", NUVO_LOG_UUID(io_req->free.parcel_uuid));
            err = NUVO_E_PARCEL_ALREADY_FREE;
            io_req->status = -err;
        }
    }
    else
    {
        /*
         * this parcel was previously looked up and found but the request was deferred.
         * use the parcelblock_idx from the first time it was looked it up
         */
        parcelblock_idx = io_req->free.parcelblock_idx;
        parcel_idx = io_req->free.parcel_idx;
        parcelblock_found = 1;
    }

    if (parcelblock_found)
    {
        nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);

        if (device->parcelblocks[parcelblock_idx].pending_update)
        {
            err = EAGAIN;
            io_req->status = -err;
            io_req->free.deferred_flag = 1;
            io_req->free.parcelblock_idx = parcelblock_idx;
            io_req->free.parcel_idx = parcel_idx;
            io_req->free.pb = NULL;
        }
        else
        {
            struct device_parcelblock *device_parcelblock = new_device_parcelblock();
            if (device_parcelblock)
            {
                /*
                 * confirm we're deleting the correct entry
                 * this entry was previously located and verified to be in this parcel block at the parcel_idx.
                 * so this check should always succeed.
                 */
                uuid_t *uuid = &device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[parcel_idx].parcel_uuid;
                if (uuid_compare(io_req->free.parcel_uuid, *uuid) == 0)
                {
                    /* assert the parcel is closed and reset the gen_id */
                    NUVO_ASSERT(device->parcelblocks[parcelblock_idx].meta[parcel_idx].open == 0)
                    device->parcelblocks[parcelblock_idx].meta[parcel_idx].gen_id = 0;

                    memcpy(device_parcelblock, device->parcelblocks[parcelblock_idx].device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);
                    device->parcelblocks[parcelblock_idx].pending_update = 1;
                    uint64_t sb_offset;
                    if ((device_parcelblock->header.gen_id % 2) == 0)
                    {
                        sb_offset = nuvo_device_superblock_offset(device->device_info.device_size, NUVO_PM_SUPERBLOCK_B);
                    }
                    else
                    {
                        sb_offset = nuvo_device_superblock_offset(device->device_info.device_size, NUVO_PM_SUPERBLOCK_A);
                    }
                    parcelblock_offset = nuvo_device_parcelblock_offset(sb_offset, parcelblock_idx);

                    /* zero out previous parcel entry */
                    memset(&device_parcelblock->parcels[parcel_idx], 0, sizeof(struct parcel_record));

                    device_parcelblock->header.gen_id++;
                    device_parcelblock->header.checksum = 0;
                    device_parcelblock->header.checksum = nuvo_hash(device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);

                    io_req->free.parcelblock_idx = parcelblock_idx;
                    io_req->free.parcel_idx = parcel_idx;
                    io_req->free.pb = device_parcelblock;
                    io_req->free.deferred_flag = 0;
                    io_req->status = 0;
                }
                else
                {
                    /* the parcel at parcel_idx in the io_req no longer references the correct parcel uuid  */
                    /* we shouldn't land here */
                    NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Parcel index to be freed does not match the given uuid.", NUVO_LOG_UUID(io_req->free.parcel_uuid));
                    err = EFAULT;
                    io_req->status = -err;
                }
            }
            else
            {
                NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Unable to allocate buffer to stage parcelblock update.", NUVO_LOG_UUID(io_req->free.parcel_uuid));
                device->parcelblocks[parcelblock_idx].allocated_cnt -= 1;
                err = ENOMEM;
                io_req->status = -err;
            }
        }
        nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);
    }

out:
    if (err)
    {
        return (-err);
    }
    return ((int64_t)parcelblock_offset);
}

/**
 * \fn int64_t pm_prep_parcel_alloc(struct device_parcelblock *device_parcelblock, struct device_record *device, uuid_t volume_uuid)
 * \brief Writes a new parcel record to the parcel table.
 *
 *  ESHUTDOWN - shutdown in progress.
 *  ENOENT  - the device wasn't found or isn't open.
 *  ENOSPC  - the device either has no formatted space available, or no more slots in parceltable.
 *  EPERM - an incorrect volume_uuid was specified.
 *  EAGAIN - the parcelblock is in use.
 *  EEXIST - parcel_uuid already exists (Maybe should handle this before calling this) look at pm_prep_parcel_free for lookup
 *
 * \param volume_uuid The volume the parcel belongs to.
 * \return 0 on success, otherwise -errno.
 */
int64_t pm_prep_parcel_alloc(struct device_record *device, struct nuvo_io_request *io_req)
{
    int      err = 0;
    int      parcelblock_reserved = 0;
    uint32_t parcelblock_idx;
    uint64_t parcelblock_offset;

    NUVO_ASSERT(device != NULL);
    NUVO_ASSERT(io_req != NULL);
    NUVO_ASSERT(io_req->operation == NUVO_OP_ALLOC);

    if (g_pm_shutdown)
    {
        err = ESHUTDOWN;
        goto out;
    }
    else if (!device->open)
    {
        err = ENOENT;
        goto out;
    }
    else if (!uuid_is_null(io_req->alloc.parcel_uuid))
    {
        if (pm_parcel_uuid_exists(device, io_req->alloc.parcel_uuid))
        {
            err = EEXIST;
            goto out;
        }
        /* Since single threaded can't be being created before I get to */
    }

    /*
     * when a new parcel alloc is requested, a parcelblock with a free entry is found,
     * the request is assigned to that parcelblock and the allocated_cnt is incremented.
     * The exact parcel entry will be determined when the io is prepared. If this request
     * is subsequently deferred it keeps it's assigment to this parcelblock.
     */
    if (!io_req->alloc.deferred_flag)
    {
        parcelblock_idx = 0;
        uint32_t parcel_cnt = 0;
        while (!parcelblock_reserved && (parcel_cnt < device->device_info.max_parcels))
        {
            nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);
            if (device->parcelblocks[parcelblock_idx].allocated_cnt < NUVO_PM_PARCELBLOCK_ENTRIES)
            {
                parcel_cnt += device->parcelblocks[parcelblock_idx].allocated_cnt;
                if (parcel_cnt < device->device_info.max_parcels)
                {
                    device->parcelblocks[parcelblock_idx].allocated_cnt++;
                    parcelblock_reserved = 1;
                }
            }
            nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);

            if (!parcelblock_reserved)
            {
                parcelblock_idx++;
                parcel_cnt = parcelblock_idx * NUVO_PM_PARCELBLOCK_ENTRIES;
            }
        }
        if (parcelblock_reserved)
        {
            io_req->alloc.parcelblock_idx = parcelblock_idx;
        }
        else
        {
            /* no more space in the parcel table is available */
            parcelblock_reserved = 0;
            device->device_info.parceltable_full = 1;
            err = ENOSPC;
        }
    }
    else
    {
        /* this deferred request previously had a parcelblock assigned */
        parcelblock_idx = io_req->alloc.parcelblock_idx;
        parcelblock_reserved = 1;
    }

    /*
     * the request has a parcelblock assigned.
     * check if the parcelblock has a pending update, if it does the request is deferred.
     * if it's free get a an entry and mark the parcelblock pending update
     */
    if (parcelblock_reserved)
    {
        nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);
        if (!device->parcelblocks[parcelblock_idx].device_parcelblock && !device->parcelblocks[parcelblock_idx].pending_update)
        {
            /* this parcel request was assigned to a new parcel block, and is the first entry */
            uint64_t parcel_start_offset = nuvo_parcel_offset(&device->device_info, parcelblock_idx, 0);
            if ((parcel_start_offset + device->superblock->parcel_size) <= device->device_info.formatted_aligned_end_offset)
            {
                struct device_parcelblock *device_parcelblock = new_device_parcelblock();
                if (device_parcelblock)
                {
                    /*
                     * prepare the new parcel block entry.
                     * initialize the parcel block header, genid = 1
                     */
                    init_device_parcelblock(device_parcelblock, parcelblock_idx, 1);
                    init_parcelblock_entry(io_req->alloc.volume_uuid, io_req->alloc.parcel_uuid, parcel_start_offset, &device_parcelblock->parcels[0]);
                    device_parcelblock->header.checksum = 0;
                    device_parcelblock->header.checksum = nuvo_hash(device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);
                    device->parcelblocks[parcelblock_idx].pending_update = 1;

                    uint64_t sb_offset = nuvo_device_superblock_offset(device->device_info.device_size, NUVO_PM_SUPERBLOCK_B);
                    parcelblock_offset = nuvo_device_parcelblock_offset(sb_offset, parcelblock_idx);
                    io_req->alloc.parcelblock_idx = parcelblock_idx;
                    io_req->alloc.parcel_idx = 0;
                    io_req->alloc.pb = device_parcelblock;
                    io_req->alloc.deferred_flag = 0;

                    /* the new parcel uuid is returned in the request */
                    uuid_copy(io_req->alloc.parcel_uuid, device_parcelblock->parcels[0].parcel_uuid);
                }
                else
                {
                    NUVO_ERROR_PRINT("Unable to allocate buffer to stage parcelblock update.");
                    device->parcelblocks[parcelblock_idx].allocated_cnt--;
                    err = ENOMEM;
                }
            }
            else
            {
                /* no more formatted space on the device is available to allocate this parcel */
                device->parcelblocks[parcelblock_idx].allocated_cnt--;
                device->device_info.parceltable_full = 1;
                err = ENOSPC;
            }
        }
        else if (!device->parcelblocks[parcelblock_idx].pending_update)
        {
            /* this parcel request was assigned to an existing parcel block, find a free spot */
            int prep_alloc_done = 0;
            for (uint32_t i = 0; i < NUVO_PM_PARCELBLOCK_ENTRIES; i++)
            {
                if (check_empty(&device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[i], sizeof(struct parcel_record)))
                {
                    uint64_t parcel_start_offset = nuvo_parcel_offset(&device->device_info, parcelblock_idx, i);
                    if ((parcel_start_offset + device->superblock->parcel_size) <= device->device_info.formatted_aligned_end_offset)
                    {
                        /* prepare the new parcel block entry */
                        /* copy the current parcel block */
                        struct device_parcelblock *device_parcelblock = new_device_parcelblock();
                        if (device_parcelblock)
                        {
                            device->parcelblocks[parcelblock_idx].pending_update = 1;
                            memcpy(device_parcelblock, device->parcelblocks[parcelblock_idx].device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);
                            init_parcelblock_entry(io_req->alloc.volume_uuid, io_req->alloc.parcel_uuid, parcel_start_offset, &device_parcelblock->parcels[i]);
                            device_parcelblock->header.gen_id++;
                            device_parcelblock->header.checksum = 0;
                            device_parcelblock->header.checksum = nuvo_hash(device_parcelblock, NUVO_PM_DEVICE_PARCELBLOCK_SIZE);

                            uint64_t sb_offset;
                            if ((device_parcelblock->header.gen_id % 2) == 0)
                            {
                                sb_offset = nuvo_device_superblock_offset(device->device_info.device_size, NUVO_PM_SUPERBLOCK_B);
                            }
                            else
                            {
                                sb_offset = nuvo_device_superblock_offset(device->device_info.device_size, NUVO_PM_SUPERBLOCK_A);
                            }
                            parcelblock_offset = nuvo_device_parcelblock_offset(sb_offset, parcelblock_idx);
                            io_req->alloc.parcelblock_idx = parcelblock_idx;
                            io_req->alloc.parcel_idx = i;
                            io_req->alloc.pb = device_parcelblock;
                            io_req->alloc.deferred_flag = 0;

                            /* copy the new parcel uuid that was assigned to the new entry */
                            uuid_copy(io_req->alloc.parcel_uuid, device_parcelblock->parcels[i].parcel_uuid);
                            prep_alloc_done = 1;
                            break;
                        }
                        else
                        {
                            NUVO_ERROR_PRINT("Unable to allocate buffer to stage parcelblock update.");
                            device->parcelblocks[parcelblock_idx].allocated_cnt--;
                            err = ENOMEM;
                            break;
                        }
                    }
                    else
                    {
                        /* no more formatted space on the device is available to allocate this parcel */
                        device->device_info.parceltable_full = 1;
                        device->parcelblocks[parcelblock_idx].allocated_cnt--;
                        err = ENOSPC;
                        break;
                    }
                }
            }
            if (!prep_alloc_done && !err)
            {
                /* we shouldn't land here */
                NUVO_ERROR_PRINT("Parcel allocation request had reservation in full parcelblock.");
                err = EFAULT;
            }
        }
        else
        {
            err = EAGAIN;
            io_req->alloc.deferred_flag = 1;
            io_req->alloc.parcelblock_idx = parcelblock_idx;
            io_req->alloc.pb = NULL;
            io_req->alloc.parcel_idx = 0;
        }
        nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);
    }

out:
    if (err)
    {
        return (-err);
    }
    return ((int64_t)parcelblock_offset);
}

/**
 * \fn void nuvo_pm_init
 * \brief initializes the parcel manager.
 *
 * creates an global AIO context.
 * creates an thread for gathering io completions.
 *
 * \return A pointer to the requested device record, otherwise NULL.
 */
int64_t nuvo_pm_init()
{
    int64_t ret;

    if (g_pm_initialized)
    {
        /* pm already initialized */
        return (0);
    }

    /* initialize data structures */
    if ((ret = nuvo_mutex_init(&g_devices.devices_lock)) == 0)
    {
        for (uint32_t i = 0; i < NUVO_PM_MAX_DEVICES; i++)
        {
            memset(&g_devices.devices[i], 0, sizeof(struct device_record));
            if ((ret = nuvo_mutex_init(&g_devices.devices[i].device_lock)) != 0)
            {
                break;
            }
        }
    }

    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Failed to initialize mutex.");
    }
    else if ((ret = nuvo_register_signal_handlers()) != 0)
    {
        NUVO_ERROR_PRINT("Failed to register signal handler.");
    }
    else if ((ret = io_queue_init(NUVO_PM_AIO_MAX_NR, &g_ctx)) != 0)
    {
        NUVO_ERROR_PRINT_ERRNO(-ret, "Failed to initialize io queue.");
    }
    else if ((ret = pthread_create(&g_tid, NULL, &pm_getevents_th, NULL)) != 0)
    {
        (void)io_queue_release(g_ctx);
        NUVO_ERROR_PRINT_ERRNO(ret, "Failed to create parcel manager thread.");
        ret = -ret;
    }
    else
    {
        g_pm_shutdown = 0;
        g_pm_initialized = 1;
    }

    return (ret);
}

/**
 * \fn void pm_shutdown
 * \brief frees all allocated memory on the device list
 *
 * \return A pointer to the requested device record, otherwise NULL.
 */
static void pm_shutdown()
{
    /*
     * set shutdown flag
     * this will cause subsequently called functions to return ESHUTDOWN
     * if nuvo_pm_submit is processing a submit list, the shutdown flag will cause it to call callbacks for all unprocessed operations.
     * after this flag is set no more AIO io_submits will happen.
     */
    g_pm_shutdown = 1;

    /* mark all devices closed */
    nuvo_mutex_lock(&g_devices.devices_lock);

    /* for each device, free all parcel table entries */
    for (uint32_t i = 0; i < NUVO_PM_MAX_DEVICES; i++)
    {
        /* free the parcel table  */
        nuvo_mutex_lock(&g_devices.devices[i].device_lock);
        g_devices.devices[i].open = 0;
        if (g_devices.devices[i].allocated)
        {
            for (uint32_t j = 0; j < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; j++)
            {
                if (g_devices.devices[i].parcelblocks[j].device_parcelblock)
                {
                    nuvo_mutex_lock(&g_devices.devices[i].parcelblocks[j].pb_lock);
                    free(g_devices.devices[i].parcelblocks[j].device_parcelblock);
                    nuvo_mutex_unlock(&g_devices.devices[i].parcelblocks[j].pb_lock);
                }

                /* send completions for anything remaining on the deferred list */
                if ((g_devices.devices[i].parcelblocks[j].deferred_list).node.next != NULL)
                {
                    struct nuvo_dlist      *deferred_list = &g_devices.devices[i].parcelblocks[j].deferred_list;
                    struct nuvo_io_request *io_req;
                    while ((io_req = nuvo_dlist_remove_head_object(deferred_list, struct nuvo_io_request, list_node)) != NULL)
                    {
                        io_req->status = -ESHUTDOWN;
                        nuvo_pr_complete(io_req);
                    }
                }
            }
        }

        /* free the superblock */
        if (g_devices.devices[i].superblock)
        {
            free(g_devices.devices[i].superblock);
        }

        /* close the device */
        if (g_devices.devices[i].fd > 0)
        {
            close(g_devices.devices[i].fd);
        }
        nuvo_mutex_unlock(&g_devices.devices[i].device_lock);
        memset(&g_devices.devices[i], 0, sizeof(struct device_record));
    }
    nuvo_mutex_unlock(&g_devices.devices_lock);
}

/**
 * \fn void nuvo_pm_destroy
 * \brief cleans up the in memory device and parceltable, destroys the AIO context, and terminates the thread.
 *
 * \return 0 if success, otherwise -err.
 */
int64_t nuvo_pm_destroy()
{
    int ret;
    int err = 0;

    if (!g_pm_initialized || g_pm_shutdown)
    {
        return (-EINVAL);
    }

    /* cleans up the device list and associated parceltable */
    pm_shutdown();

    /*
     * io_queue_release destroys the context which is used by io_getevents.
     * if the context is destroyed while the completion handler thread is
     * is blocked in io_getevents, io_getevents returns EINVAL. this
     * error is handled in the pm_getevents_thread function.
     */
    if ((ret = io_queue_release(g_ctx)) != 0)
    {
        err = ret;
        NUVO_ERROR_PRINT_ERRNO(err, "io queue release failed");
    }
    g_ctx = NULL;

    /*
     * send the thread SIGUSR1.
     * this is required for cases where the thread is blocked in io_getevents
     * since it's possible that the first signal could be missed, retry once.
     */
    while (1)
    {
        struct timespec ts;

        pthread_kill(g_tid, SIGUSR1);
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += NUVO_PM_JOIN_WAIT;
        ret = pthread_timedjoin_np(g_tid, NULL, &ts);
        if (ret == 0)
        {
            break;
        }
    }

    g_pm_initialized = 0;

    return (err);
}

/**
 * \fn static inline void reset_pending_parcelblock_update_flag(struct nuvo_io_request *iorp)
 * \brief resets the pending_update flag in the parcelblock to zero.
 *
 * This is a convenience function to hide all the necessary locking.
 * This function is only necessary for parcel alloc or free operations.
 * iorp->status will be set ENOENT if the device cannot be found.
 *
 * \param iorp a pointer to a nuvo_io_request.
 * \return none
 */
static inline void reset_pending_parcelblock_update_flag(struct nuvo_io_request *iorp)
{
    if (!g_pm_shutdown && ((iorp->operation == NUVO_OP_ALLOC) || (iorp->operation == NUVO_OP_FREE)))
    {
        struct device_record *device;
        nuvo_mutex_lock(&g_devices.devices_lock);
        if ((device = get_open_device_record(iorp->alloc.device_uuid)) != NULL)
        {
            uint32_t block_idx;
            nuvo_mutex_lock(&device->device_lock);
            nuvo_mutex_unlock(&g_devices.devices_lock);
            if (iorp->operation == NUVO_OP_ALLOC)
            {
                block_idx = ((struct device_parcelblock *)iorp->alloc.pb)->header.block_idx;
            }
            else
            {
                block_idx = ((struct device_parcelblock *)iorp->free.pb)->header.block_idx;
            }
            nuvo_mutex_lock(&device->parcelblocks[block_idx].pb_lock);
            device->parcelblocks[block_idx].pending_update = 0;
            nuvo_mutex_unlock(&device->parcelblocks[block_idx].pb_lock);
            nuvo_mutex_unlock(&device->device_lock);
        }
        else
        {
            nuvo_mutex_unlock(&g_devices.devices_lock);
            iorp->status = -ENOENT;
        }
    }
}

/**
 * \fn void nuvo_pm_submit(struct nuvo_dlist *submit_list)
 * \brief process io requests on the submit list
 *
 * given a linked list of nuvo_io_requests, processes the list an performs the requested operation.
 *
 * NUVO_OP_WRITE
 * NUVO_OP_READ
 *   prepares an list of iocbs to be processed async by io_submit.
 * NUVO_OP_ALLOC
 *   allocates a new parcel entry in the parcel table.
 * NUVO_OP_FREE
 *   free's a parcel entry in the parcel table.
 * NUVO_OP_OPEN
 *   opens a parcel entry in the parcel table.
 * NUVO_OP_CLOSE
 *   closes a parcel entry in the parcel table.
 * NUVO_OP_DEV_INFO
 *   returns the raw device size, and the parcel size used to format the device.
 *
 * nuvo_pm_submit prepares io requests for each item on request on the submit list, and calls io_submit
 * to perform aio. caller supplies a callback in the nuvo_io_request which is called upon completion.
 * the completion may occur before the call to nuvo_pm_submit returns.
 *
 * when nuvo_pm_submit returns, all requests have been prepared and either a callback has been invoked, or
 * the io request is has been submitted via io_submit.
 *
 * returns 0
 */
void nuvo_pm_submit(struct nuvo_dlist *submit_list)
{
    struct nuvo_io_request *io_req;

    NUVO_ASSERT(submit_list != NULL);

    io_req = nuvo_dlist_get_head_object(submit_list, struct nuvo_io_request, list_node);
    while (io_req != NULL)
    {
        switch (io_req->operation)
        {
        case NUVO_OP_ALLOC:
            memset(&io_req->alloc.iocb, 0, sizeof(struct iocb));
            io_req->alloc.pb = NULL;
            io_req->alloc.parcelblock_idx = 0;
            io_req->alloc.parcel_idx = 0;
            io_req->alloc.deferred_flag = 0;
            break;

        case NUVO_OP_FREE:
            memset(&io_req->free.iocb, 0, sizeof(struct iocb));
            io_req->free.pb = NULL;
            io_req->free.parcelblock_idx = 0;
            io_req->free.parcel_idx = 0;
            io_req->alloc.deferred_flag = 0;
            break;

        default:
            break;
        }
        io_req = nuvo_dlist_get_next_object(submit_list, io_req, struct nuvo_io_request, list_node);
    }

    nuvo_pm_submit_internal(submit_list);
}

void nuvo_pm_submit_internal(struct nuvo_dlist *submit_list)
{
    int64_t                 ret;
    struct iocb            *iocbs[NUVO_PM_MAX_EVENTS];
    struct nuvo_io_request *io_req;
    int     submit_count = 0;
    int32_t fd;
    struct device_record *device = NULL;
    int err = 0;

    NUVO_ASSERT(submit_list != NULL);

    if (g_pm_shutdown)
    {
        goto cancel;
    }

    do
    {
        int parceltable_update_flag = 0;
        submit_count = 0;

        while (!g_pm_shutdown && (submit_count < NUVO_PM_MAX_EVENTS) && (!parceltable_update_flag))
        {
            io_req = nuvo_dlist_remove_head_object(submit_list, struct nuvo_io_request, list_node);
            if (io_req == NULL)
            {
                break;
            }
            io_req->earliest_response = 0;
            switch (io_req->operation)
            {
            case NUVO_OP_WRITE:
            case NUVO_OP_READ:
            case NUVO_OP_READ_VERIFY:
            {
                err = 0;
                uint64_t parcel_start_offset;
                uint64_t parcel_io_start_offset;
                uint64_t parcel_end_offset;
                uint64_t parcel_io_end_offset;
                union native_parcel_descriptor npd;

                npd.native_parcel_desc = io_req->rw.native_parcel_desc;
                nuvo_mutex_lock(&g_devices.devices[npd.dev_idx].device_lock);
                nuvo_mutex_lock(&g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].pb_lock);
                if (g_devices.devices[npd.dev_idx].io_delay > 0)
                {
                    io_req->earliest_response = nuvo_get_timestamp() + g_devices.devices[npd.dev_idx].io_delay;
                }
                if (npd.gen_id != pm_parcel_to_desc_genid(g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].meta[npd.ent_idx].gen_id))
                {
                    err = EBADF;
                }
                else
                {
                    /* get the fd for the device */
                    fd = g_devices.devices[npd.dev_idx].fd;

                    /* convert the parcel relative offset to a device relative offset */
                    parcel_start_offset = g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].device_parcelblock->parcels[npd.ent_idx].parcel_offset;
                    parcel_io_start_offset = parcel_start_offset + (io_req->rw.block_offset * NUVO_BLOCK_SIZE);
                    parcel_end_offset = parcel_start_offset + g_devices.devices[npd.dev_idx].superblock->parcel_size;
                    parcel_io_end_offset = parcel_io_start_offset + (io_req->rw.block_count * NUVO_BLOCK_SIZE);

                    if (parcel_io_end_offset > parcel_end_offset)
                    {
                        /* i/o request is out of bounds */
                        err = ERANGE;
                    }
                }
                nuvo_mutex_unlock(&g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].pb_lock);
                nuvo_mutex_unlock(&g_devices.devices[npd.dev_idx].device_lock);

                if (!err)
                {
                    if (io_req->operation == NUVO_OP_WRITE)
                    {
                        io_prep_pwritev(&io_req->rw.iocb, fd, io_req->rw.iovecs, io_req->rw.block_count, parcel_io_start_offset);
                    }
                    else
                    {
                        io_prep_preadv(&io_req->rw.iocb, fd, io_req->rw.iovecs, io_req->rw.block_count, parcel_io_start_offset);
                    }
                    io_req->rw.iocb.data = io_req;
                    iocbs[submit_count] = &io_req->rw.iocb;
                    submit_count++;
                }
                else
                {
                    io_req->status = -err;
                    nuvo_pr_complete(io_req);
                }
            }
            break;

            case NUVO_OP_OPEN:
                /* starts a parcel open operation, descriptor is returned in the struct */
                /* this call operates synchronously since it doesn't do i/o, the callback is called here */
                if ((ret = pm_parcel_open(io_req->open.parcel_uuid, io_req->open.device_uuid, io_req->open.volume_uuid, &io_req->open.parcel_desc)) < 0)
                {
                    io_req->status = ret;
                    if (ret == -NUVO_E_PARCEL_ALREADY_OPEN)
                    {
                        // Could make duplicate parcel opens idempotent here.
                    }
                    else
                    {
                        NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Unable to open parcel.", NUVO_LOG_UUID(io_req->open.parcel_uuid));
                        io_req->open.parcel_desc = 0; /* invalid desc */
                    }
                }
                else
                {
                    io_req->status = 0;
                }
                /* run the callback to inform completion */
                nuvo_pr_complete(io_req);
                break;

            case NUVO_OP_CLOSE:
                /* starts a parcel close operation */
                /* this call is synchronous because it doesn't do i/o, so the callback is called here on return */
                if ((ret = pm_parcel_close(io_req)) < 0)
                {
                    io_req->status = ret;
                    if (ret == -NUVO_E_PARCEL_ALREADY_CLOSED)
                    {
                        // Could make duplicate parcel closes idempotent here.
                    }
                    else
                    {
                        NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Unable to close parcel.", NUVO_LOG_UUID(io_req->open.parcel_uuid));
                    }
                }
                else
                {
                    io_req->status = 0;
                }
                /* run the callback to inform completion */
                nuvo_pr_complete(io_req);
                break;

            case NUVO_OP_ALLOC:
            case NUVO_OP_FREE:

                err = 0;
                nuvo_mutex_lock(&g_devices.devices_lock);
                if (io_req->operation == NUVO_OP_ALLOC)
                {
                    device = get_open_device_record(io_req->alloc.device_uuid);
                }
                else
                {
                    device = get_open_device_record(io_req->free.device_uuid);
                }
                if (device)
                {
                    nuvo_mutex_lock(&device->device_lock);
                    nuvo_mutex_unlock(&g_devices.devices_lock);
                    if (io_req->operation == NUVO_OP_ALLOC)
                    {
                        ret = pm_prep_parcel_alloc(device, io_req);
                    }
                    else
                    {
                        ret = pm_prep_parcel_free(device, io_req);
                    }
                    if (ret >= 0)
                    {
                        uint64_t parcelblock_offset = (uint64_t)ret;
                        if (io_req->operation == NUVO_OP_ALLOC)
                        {
                            io_prep_pwrite(&io_req->alloc.iocb, device->fd, io_req->alloc.pb, NUVO_PM_DEVICE_PARCELBLOCK_SIZE, parcelblock_offset);
                            io_req->alloc.iocb.data = io_req;
                            iocbs[submit_count] = &io_req->alloc.iocb;
                        }
                        else
                        {
                            io_prep_pwrite(&io_req->free.iocb, device->fd, io_req->free.pb, NUVO_PM_DEVICE_PARCELBLOCK_SIZE, parcelblock_offset);
                            io_req->free.iocb.data = io_req;
                            iocbs[submit_count] = &io_req->free.iocb;
                        }
                        /* set flag to submit parcel request immediately */
                        parceltable_update_flag = 1;
                        submit_count++;
                    }
                    else if (ret == -EAGAIN)
                    {
                        /*
                         * move this request onto the device deferred list.
                         * there's a parcel allocation in progress that's blocking this one.
                         * parcelblock_idx in the io_req was set to the index of the assigned parcelblock.
                         */
                        int parcelblock_idx;
                        if (io_req->operation == NUVO_OP_ALLOC)
                        {
                            parcelblock_idx = io_req->alloc.parcelblock_idx;
                        }
                        else
                        {
                            parcelblock_idx = io_req->free.parcelblock_idx;
                        }
                        nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].deferred_list_lock);
                        nuvo_dlist_insert_tail(&device->parcelblocks[parcelblock_idx].deferred_list, &io_req->list_node);
                        nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].deferred_list_lock);
                    }
                    else
                    {
                        /*
                         * if this request was previously deferred, there may be io_reqs on the deferred list
                         * that were pending this completion. They need to be put back on the submit list to be
                         * called again, otherwise they'll stay deferred indefinitely.
                         */
                        err = ret;
                        int parcelblock_idx;
                        int deferred_flag;
                        if (io_req->operation == NUVO_OP_ALLOC)
                        {
                            deferred_flag = io_req->alloc.deferred_flag;
                            parcelblock_idx = io_req->alloc.parcelblock_idx;
                        }
                        else
                        {
                            deferred_flag = io_req->free.deferred_flag;
                            parcelblock_idx = io_req->free.parcelblock_idx;
                        }
                        if (deferred_flag)
                        {
                            struct nuvo_io_request *deferred_io_req;
                            nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].deferred_list_lock);
                            while ((deferred_io_req = nuvo_dlist_remove_head_object(&device->parcelblocks[parcelblock_idx].deferred_list, struct nuvo_io_request, list_node)) != NULL)
                            {
                                nuvo_dlist_insert_tail(submit_list, &deferred_io_req->list_node);
                            }
                            nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].deferred_list_lock);
                        }
                    }
                    nuvo_mutex_unlock(&device->device_lock);
                }
                else
                {
                    nuvo_mutex_unlock(&g_devices.devices_lock);
                    err = -ENOENT;
                }

                if (err)
                {
                    io_req->status = err;
                    nuvo_pr_complete(io_req);
                }
                break;

            case NUVO_OP_DEV_INFO:

                nuvo_mutex_lock(&g_devices.devices_lock);
                device = get_device_record(io_req->dev_info.device_uuid);
                if (device)
                {
                    nuvo_mutex_lock(&device->device_lock);
                    nuvo_mutex_unlock(&g_devices.devices_lock);
                    io_req->dev_info.device_size = device->device_info.device_size;
                    io_req->dev_info.parcel_size = device->device_info.parcel_size;
                    io_req->dev_info.device_type = device->device_info.device_type;
                    io_req->status = 0;
                    nuvo_mutex_unlock(&device->device_lock);
                }
                else
                {
                    nuvo_mutex_unlock(&g_devices.devices_lock);
                    if (g_pm_shutdown)
                    {
                        ret = -ESHUTDOWN;
                    }
                    else
                    {
                        ret = -ENOENT;
                    }
                    io_req->dev_info.device_size = 0;
                    io_req->dev_info.parcel_size = 0;
                    io_req->status = ret;
                }
                nuvo_pr_complete(io_req);

                break;

            default:
                /* invalid operation */
                io_req->status = -EINVAL;
                nuvo_pr_complete(io_req);
                break;
            }
        }

        while (submit_count > 0)
        {
            if (g_pm_shutdown)
            {
                goto cancel;
            }

            /*
             * io_submit returns immediately after all requests are enqueued.
             * returns the number of iocbs submitted or a -errno.
             * if ret is less than submit_cnt, the remaining requests are re-submitted.
             * with a -errno, in some cases, the remaining requests can be re-submitted.
             * before calling io_submit set the submit time on the io_req.
             * all io_reqs on the same io_submit will be given the same timestamp.
             */
            uint_fast64_t io_submit_time = nuvo_get_timestamp();
            for (int i = 0; i < submit_count; i++)
            {
                struct nuvo_io_request *iorp = (struct nuvo_io_request *)iocbs[i]->data;
                iorp->io_submit_time = io_submit_time;
            }

            ret = io_submit(g_ctx, submit_count, iocbs);
            if (ret == submit_count)
            {
                submit_count = 0;
            }
            else
            {
                if (ret < 0)
                {
                    if (ret == -EBADF || ret == -EINVAL)
                    {
                        /*
                         * EBADF means the iocb contains a file descriptor that does not exist. we remove the iocb and retry.
                         * EINVAL could a problem with aio context, or the iocb. since we can't tell remove the iocb and retry the rest.
                         * these can also happen in a race condition during shutdown, where the aio context or fd is closed.
                         * in the case of shutdown this list will be processed in this functions cancel handler.
                         * get the orginal io_req from the iocb->data;
                         *
                         * if this was an alloc request then we need to mark the parcel block as no longer pending update.
                         * skip this if doing shutdown.
                         *
                         * we don't use IO_CMD_NOP to ignore this iocb because it's allocated as part of the io_req.
                         * after calling the io completion callback it may be deallocated or reused.
                         */
                        struct nuvo_io_request *iorp = (struct nuvo_io_request *)iocbs[0]->data;
                        iorp->status = ret;
                        if ((iorp->operation == NUVO_OP_ALLOC) && iorp->alloc.pb)
                        {
                            reset_pending_parcelblock_update_flag(iorp);
                            free_device_parcelblock(iorp->alloc.pb);
                        }
                        else if ((iorp->operation == NUVO_OP_FREE) && iorp->free.pb)
                        {
                            reset_pending_parcelblock_update_flag(iorp);
                            free_device_parcelblock(iorp->free.pb);
                        }
                        nuvo_pr_complete(iorp);
                        submit_count--;
                        for (int i = 0; i < submit_count; i++)
                        {
                            iocbs[i] = iocbs[i + 1];
                        }
                    }
                    else if (ret == -EFAULT)
                    {
                        /* EFAULT is memory error on the iocbs  */
                        for (int i = 0; i < submit_count; i++)
                        {
                            struct nuvo_io_request *iorp = (struct nuvo_io_request *)iocbs[i]->data;
                            iorp->status = ret;
                            if ((iorp->operation == NUVO_OP_ALLOC) && iorp->alloc.pb)
                            {
                                reset_pending_parcelblock_update_flag(iorp);
                                free_device_parcelblock(iorp->alloc.pb);
                            }
                            else if ((iorp->operation == NUVO_OP_FREE) && iorp->free.pb)
                            {
                                reset_pending_parcelblock_update_flag(iorp);
                                free_device_parcelblock(iorp->free.pb);
                            }
                            nuvo_pr_complete(iorp);
                        }
                        submit_count = 0;
                    }
                }
                else
                {
                    /* retry remaining iocbs */
                    submit_count -= ret;
                    for (int i = 0; i < submit_count; i++)
                    {
                        iocbs[i] = iocbs[ret + i];
                    }
                }
            }
        }
    } while (io_req != NULL);

    return;

cancel:
    /* cancel all operations prepared but not yet submitted */
    for (int i = 0; i < submit_count; i++)
    {
        struct nuvo_io_request *iorp = (struct nuvo_io_request *)iocbs[i]->data;
        iorp->status = -ESHUTDOWN;
        nuvo_pr_complete(io_req);
    }
    /* cancel the remaining submit list */
    do
    {
        io_req = nuvo_dlist_remove_head_object(submit_list, struct nuvo_io_request, list_node);
        if (io_req)
        {
            io_req->status = ret;
            nuvo_pr_complete(io_req);
        }
    } while (io_req != NULL);
    return;
}

/**
 * Handle return of a READ/READ_VERIFY/WRITE, which may be delayed by debug trigger on device.
 */
void pm_handle_io_req_return(struct nuvo_io_request *io_req, uint64_t io_complete_time)
{
    union native_parcel_descriptor npd;

    switch (io_req->operation)
    {
    case NUVO_OP_READ:
    case NUVO_OP_READ_VERIFY:
    case NUVO_OP_WRITE:
        /* update the device io stats */
        npd.native_parcel_desc = io_req->rw.native_parcel_desc;
        nuvo_mutex_lock(&g_devices.devices[npd.dev_idx].device_lock);
        if (io_req->operation == NUVO_OP_WRITE)
        {
            nuvo_io_stats_add(&g_devices.devices[npd.dev_idx].write_io_stats, io_req->rw.block_count * NUVO_BLOCK_SIZE, io_complete_time - io_req->io_submit_time);
        }
        else
        {
            nuvo_io_stats_add(&g_devices.devices[npd.dev_idx].read_io_stats, io_req->rw.block_count * NUVO_BLOCK_SIZE, io_complete_time - io_req->io_submit_time);
        }
        nuvo_mutex_unlock(&g_devices.devices[npd.dev_idx].device_lock);

        nuvo_pr_complete(io_req);
        break;

    default:
        NUVO_PANIC("invalid operation.");
        break;
    }
}

static void pm_log_io_error(struct nuvo_io_request *io_req, struct io_event *ep)
{
    NUVO_ASSERT_MUTEX_HELD(&g_devices.devices_lock);
    uuid_t v_uuid, d_uuid;
    char  *err_str = NULL;
    if ((int64_t)ep->res < 0)
    {
        err_str = nuvo_status_alloc_error_str(-ep->res);
    }
    struct device_record *device = get_device_record_by_fd(ep->obj->aio_fildes);
    (device) ? uuid_copy(d_uuid, device->device_info.device_uuid) : uuid_clear(d_uuid);
    (io_req->rw.vol) ? uuid_copy(v_uuid, io_req->rw.vol->vs_uuid) : uuid_clear(v_uuid);
    switch (io_req->operation)
    {
    case NUVO_OP_WRITE:
    case NUVO_OP_READ:
    case NUVO_OP_READ_VERIFY:
        NUVO_ERROR_PRINT("IO error. Device uuid: "NUVO_LOG_UUID_FMT " (%s %s). op %d aio opcode %d on fd %d at offset %llu [%lu:%lu] length: %lu origin: %d. IO error res: %ld res2: %ld. %s",
                         NUVO_LOG_UUID(d_uuid),
                         (device) ? nuvo_dev_type_str[device->device_info.device_type] : "device",
                         (device) ? device->device_info.device_path : "unknown",
                         io_req->operation,
                         ep->obj->aio_lio_opcode,
                         ep->obj->aio_fildes,
                         ep->obj->u.c.offset,
                         io_req->rw.parcel_desc,
                         io_req->rw.block_offset,
                         ep->obj->u.c.nbytes,
                         io_req->rw.io_origin,
                         ep->res, ep->res2,
                         (err_str) ? err_str : "Unknown");
        NUVO_ERROR_PRINT("IO error. Volume uuid: "NUVO_LOG_UUID_FMT " Device uuid: "NUVO_LOG_UUID_FMT " (%s %s) op %d at device offset %llu [%lu:%lu]. %s",
                         NUVO_LOG_UUID(v_uuid),
                         NUVO_LOG_UUID(d_uuid),
                         (device) ? nuvo_dev_type_str[device->device_info.device_type] : "device",
                         (device) ? device->device_info.device_path : "unknown",
                         io_req->operation,
                         ep->obj->u.c.offset,
                         io_req->rw.parcel_desc,
                         io_req->rw.block_offset,
                         (err_str) ? err_str : "Unknown");
        break;

    default:
        NUVO_ERROR_PRINT("IO error. Device uuid: "NUVO_LOG_UUID_FMT " (%s %s). Operation %d aio opcode %d on fd %d at offset %llu length: %lu. IO error res: %ld res2: %ld. %s",
                         NUVO_LOG_UUID(d_uuid),
                         (device) ? nuvo_dev_type_str[device->device_info.device_type] : "device",
                         (device) ? device->device_info.device_path : "unknown",
                         io_req->operation,
                         ep->obj->aio_lio_opcode,
                         ep->obj->aio_fildes,
                         ep->obj->u.c.offset,
                         ep->obj->u.c.nbytes,
                         ep->res, ep->res2,
                         (err_str) ? err_str : "Unknown");
        break;
    }
    if (err_str)
    {
        free(err_str);
    }
}

static void pm_log_hash_error(struct nuvo_io_request *io_req, struct io_event *ep, uint32_t iov_index, uint64_t bad_hash, uint64_t expected_hash)
{
    NUVO_ASSERT_MUTEX_HELD(&g_devices.devices_lock);
    uuid_t v_uuid, d_uuid;
    struct device_record *device = get_device_record_by_fd(ep->obj->aio_fildes);
    (device) ? uuid_copy(d_uuid, device->device_info.device_uuid) : uuid_clear(d_uuid);
    (io_req->rw.vol) ? uuid_copy(v_uuid, io_req->rw.vol->vs_uuid) : uuid_clear(v_uuid);
    NUVO_ERROR_PRINT("Bad hash. Device uuid: "NUVO_LOG_UUID_FMT " (%s %s). Operation %d aio opcode %d on fd %d at offset %llu [%lu:%lu] length: %lu origin: %d. Invalid hash at index %lu. hash: %lu expected: %lu",
                     NUVO_LOG_UUID(d_uuid),
                     (device) ? nuvo_dev_type_str[device->device_info.device_type] : "device",
                     (device) ? device->device_info.device_path : "unknown",
                     io_req->operation,
                     ep->obj->aio_lio_opcode,
                     ep->obj->aio_fildes,
                     ep->obj->u.c.offset,
                     io_req->rw.parcel_desc,
                     io_req->rw.block_offset,
                     ep->obj->u.c.nbytes,
                     io_req->rw.io_origin,
                     iov_index,
                     bad_hash,
                     expected_hash);
    NUVO_ERROR_PRINT("Bad hash. Volume uuid: "NUVO_LOG_UUID_FMT " Device uuid: "NUVO_LOG_UUID_FMT " (%s %s) Verification of block at device offset %llu [%lu:%lu] failed. ",
                     NUVO_LOG_UUID(v_uuid),
                     NUVO_LOG_UUID(d_uuid),
                     (device) ? nuvo_dev_type_str[device->device_info.device_type] : "device",
                     (device) ? device->device_info.device_path : "unknown",
                     ep->obj->u.c.offset + (iov_index * NUVO_BLOCK_SIZE),
                     io_req->rw.parcel_desc,
                     io_req->rw.block_offset + iov_index);
}

/**
 * \fn void *pm_getevents_th(__attribute__((unused)) void *arg)
 * \brief The main event thread responsible for processing io completion events
 *
 * \return 0 on exit
 */
static void *pm_getevents_th(__attribute__((unused)) void *arg)
{
    struct io_event  events[NUVO_PM_MAX_EVENTS];
    struct io_event *ep;
    int event_count = 0;

    struct nuvo_dlist deferred_list;

    nuvo_dlist_init(&deferred_list);

    /*
     * If we have been asked to guarantee a minimum latency for IOs on a device,
     * we may want to hold onto an IO after it is done, but before we respond.
     */
    struct nuvo_dlist stall_list;
    nuvo_dlist_init(&stall_list);

    int ret;

    while (1)
    {
        struct timespec         pm_timeout;
        struct timespec        *pm_timeout_p = NULL;
        struct nuvo_io_request *io_req;

        // If we aren't slowing down a device, this will always return NULL.
        io_req = nuvo_dlist_get_head_object(&stall_list, struct nuvo_io_request, list_node);
        if (io_req != NULL)
        {
            uint64_t current_time = nuvo_get_timestamp();
            uint64_t earliest_response = UINT64_MAX;
            // Respond to io's that have waited long enough, and find how long we need to wait for next.
            while (io_req != NULL)
            {
                struct nuvo_io_request *next_io_req = nuvo_dlist_get_next_object(&stall_list, io_req, struct nuvo_io_request, list_node);
                if (io_req->earliest_response <= current_time)
                {
                    nuvo_dlist_remove(&io_req->list_node);
                    pm_handle_io_req_return(io_req, current_time);
                }
                else if (earliest_response > io_req->earliest_response)
                {
                    earliest_response = io_req->earliest_response;
                }
                io_req = next_io_req;
            }

            if (earliest_response != UINT64_MAX)
            {
                NUVO_ASSERT(NULL != nuvo_dlist_get_head_object(&stall_list, struct nuvo_io_request, list_node));
                NUVO_ASSERT(earliest_response > current_time);
                earliest_response -= current_time;
                pm_timeout.tv_sec = earliest_response / 1000000000L;
                pm_timeout.tv_nsec = earliest_response % 1000000000L;
                pm_timeout_p = &pm_timeout;
            }
            else
            {
                // Pulled everybody off list.
                // pm_timeout_p is NULL because we set it above.
                NUVO_ASSERT(NULL == nuvo_dlist_get_head_object(&stall_list, struct nuvo_io_request, list_node));
            }
        }

        // Return when NUVO_PM_MIN_EVENTS are done or when timeout, if a timeout is set.
        ret = io_getevents(g_ctx, NUVO_PM_MIN_EVENTS, NUVO_PM_MAX_EVENTS, events, pm_timeout_p);
        if (ret < 0)
        {
            if (!g_pm_shutdown)
            {
                if (ret == -EINTR)
                {
                    continue;
                }
                else
                {
                    /* EFAULT, EINVAL, ENOSYS */
                    /* panic, could also terminate the thread with an error */
                    NUVO_PANIC_ERRNO(-ret, "io_getevents() returned error");
                }
            }
            else
            {
                /* program is exiting */
                break;
            }
        }
        else
        {
            event_count = ret;
        }

        struct device_record      *device;
        struct device_parcelblock *parcelblock;
        uuid_t        device_uuid;
        int           parcelblock_idx;
        uint_fast64_t io_complete_time = nuvo_get_timestamp();

        for (ep = events; event_count-- > 0; ep++)
        {
            int64_t res = (int64_t)ep->res;
            io_req = (struct nuvo_io_request *)ep->data;
            if (!io_req)
            {
                /* not good */
                NUVO_PANIC("unable to call io completion callback. missing io_req");
            }
            switch (io_req->operation)
            {
            case NUVO_OP_READ:
            case NUVO_OP_READ_VERIFY:
            case NUVO_OP_WRITE:

                /*
                 * If ep->res < 0 it's set to a -errno, otherwise it will be set to the number of bytes written.
                 * Reads and writes are prepared using the io_prep_preadv and io_prep_pwritev functions.
                 * These functions will both set iocb->u.c.nbytes to the iovec count, which in our case is
                 * the number of 4K blocks to be written. Because res is returned in bytes, ep->obj->u.c.nbytes
                 * must be multiplied by 4K to confirm the expected byte count was actually written.
                 */
                if ((res < 0) || (ep->res2 != 0) || ((uint64_t)res < (ep->obj->u.c.nbytes * NUVO_BLOCK_SIZE)))
                {
                    /*
                     * In addition to device errors, will land here when using an unaligned buffer
                     * for io, out of range address, or if using a sparse device it runs out of space.
                     *
                     * It's not definitive if an aio short read or write can happen in circumstances
                     * other than an attempt to go beyond the end of the device.
                     *
                     * for now panic.
                     */
                    nuvo_mutex_lock(&g_devices.devices_lock);
                    pm_log_io_error(io_req, ep);
                    nuvo_mutex_unlock(&g_devices.devices_lock);
                    NUVO_PANIC("Fatal io failure");
                }
                else
                {
                    io_req->status = 0;
                }

                if (io_req->operation == NUVO_OP_READ)
                {
                    for (uint32_t i = 0; i < io_req->rw.block_count; i++)
                    {
                        io_req->rw.block_hashes[i] = nuvo_hash(io_req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
                    }
                }
                else if (io_req->operation == NUVO_OP_READ_VERIFY)
                {
                    for (uint32_t i = 0; i < io_req->rw.block_count; i++)
                    {
                        nuvo_hash_t hash = nuvo_hash(io_req->rw.iovecs[i].iov_base, NUVO_BLOCK_SIZE);
                        if (io_req->rw.block_hashes[i] != hash)
                        {
                            // set an error on the io_req, skip checking the remaining read buffers
                            nuvo_mutex_lock(&g_devices.devices_lock);
                            pm_log_hash_error(io_req, ep, i, hash, io_req->rw.block_hashes[i]);
                            nuvo_mutex_unlock(&g_devices.devices_lock);
                            io_req->status = -NUVO_E_BAD_HASH;
                            break;
                        }
                    }
                }
                if (io_req->earliest_response != 0)
                {
                    nuvo_dlist_insert_tail(&stall_list, &io_req->list_node);
                }
                else
                {
                    pm_handle_io_req_return(io_req, io_complete_time);
                }
                break;

            case NUVO_OP_ALLOC:
            case NUVO_OP_FREE:
                if (io_req->operation == NUVO_OP_ALLOC)
                {
                    parcelblock = io_req->alloc.pb;
                    parcelblock_idx = io_req->alloc.parcelblock_idx;
                    uuid_copy(device_uuid, io_req->alloc.device_uuid);
                }
                else
                {
                    parcelblock = io_req->free.pb;
                    parcelblock_idx = io_req->free.parcelblock_idx;
                    uuid_copy(device_uuid, io_req->free.device_uuid);
                }

                nuvo_mutex_lock(&g_devices.devices_lock);
                if ((device = get_open_device_record(device_uuid)) != NULL)
                {
                    /*
                     * If ep->res < 0 it's set to a -errno, otherwise it will be set to the number of bytes written.
                     * Writes for parcel allocs and frees are prepared using the io_prep_pwrite function.
                     * iocb->u.c.nbytes is set to the number of bytes we expected to write.
                     */
                    if ((res < 0) || (ep->res2 != 0) || ((uint64_t)res != ep->obj->u.c.nbytes))
                    {
                        /*
                         * panic for now.
                         */
                        pm_log_io_error(io_req, ep);
                        nuvo_mutex_unlock(&g_devices.devices_lock);
                        NUVO_PANIC("Fatal io failure");
                    }
                    else
                    {
                        nuvo_mutex_lock(&device->device_lock);
                        nuvo_mutex_unlock(&g_devices.devices_lock);
                        pm_update_current_parcelblock(io_req->operation, parcelblock, device);
                        io_req->status = 0;
                    }

                    /* submit the next request on the deferred list if any, could be either an alloc or a free */
                    nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);
                    struct nuvo_io_request *deferred_io_req;
                    deferred_io_req = nuvo_dlist_remove_head_object(&device->parcelblocks[parcelblock_idx].deferred_list, struct nuvo_io_request, list_node);
                    if (deferred_io_req)
                    {
                        nuvo_dlist_insert_tail(&deferred_list, &deferred_io_req->list_node);
                    }
                    nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);

                    /*
                     * update the device io stats
                     * parcel updates are always one 4K block
                     */
                    nuvo_io_stats_add(&device->write_io_stats, NUVO_BLOCK_SIZE, io_complete_time - io_req->io_submit_time);

                    nuvo_mutex_unlock(&device->device_lock);

                    /* done with this io_req */
                    nuvo_pr_complete(io_req);

                    /* re-submit the defferred alloc or free operation */
                    if (deferred_io_req)
                    {
                        (void)nuvo_pm_submit_internal(&deferred_list);
                    }
                }
                else
                {
                    nuvo_mutex_unlock(&g_devices.devices_lock);
                    NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
                }
                break;

            default:
                NUVO_PANIC("invalid operation.");
                break;
            }
        }
    }
    return (NULL);
}

/**
 * \fn int64_t nuvo_pm_device_format(char *device_path, uuid_t device_uuid, uint64_t parcel_size)
 * \brief Writes a new superblock header and initializes device space for the parcel table.
 *
 * Initializes 8 MiB of space for the superblock header and parcel table and writes a new superblock header.
 * A primary and backup superblock and parcel table region are written to the device. The primary is written
 * beginning at device offset 0, and the backup is written in the last 8MiB of the device.
 *
 * TODO doc all the rets.
 *
 * \param device_path The device to format.
 * \param device_uuid The uuid that is to be used for this device.
 * \param parcel_size The amount of space to be allocated for each parcel.
 * \return 0 on success, otherwise -errno.
 */
int64_t nuvo_pm_device_format(const char *device_path, const uuid_t device_uuid, uint64_t parcel_size)
{
    int      ret = 0;
    int      fd = -1;
    void    *private_region = NULL;
    char     device_superblock[NUVO_PM_DEVICE_SUPERBLOCK_SIZE];
    char     device_parcelblock[NUVO_PM_DEVICE_PARCELBLOCK_SIZE];
    uint64_t device_size;

    NUVO_ASSERT(device_path != NULL);
    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);

    nuvo_mutex_lock(&g_devices.devices_lock);
    struct device_record *device;
    device = get_device_record(device_uuid);
    nuvo_mutex_unlock(&g_devices.devices_lock);
    if (device == NULL)
    {
        /* make sure we didn't find it because of shutdown */
        if (g_pm_shutdown)
        {
            ret = -ESHUTDOWN;
            goto out;
        }
    }
    else
    {
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Device is in use.", NUVO_LOG_UUID(device_uuid), device_path);
        return (-NUVO_E_DEVICE_ALREADY_OPEN);
    }

    fd = open(device_path, O_DIRECT | O_RDWR);
    if (fd < 0)
    {
        char *err_str = nuvo_status_alloc_error_str(errno);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Open failed. %s.", NUVO_LOG_UUID(device_uuid), device_path, err_str ? err_str : "Unknown");
        if (err_str)
        {
            free(err_str);
        }
        ret = -errno;
        goto out;
    }

    if ((ret = get_device_size(fd, &device_size)) < 0)
    {
        goto out;
    }

    /* device must be large enough for the private region and one parcel */
    if ((int64_t)(device_size - (NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2) - parcel_size) < 0)
    {
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Device is too small.", NUVO_LOG_UUID(device_uuid), device_path);
        ret = -ENOSPC;
        goto out;
    }

    if (parcel_size == 0)
    {
        /* setting parcel_size to 0 is treated as a flag to set the parcel_size to */
        /* use a single parcel that uses the entire device */
        /* this value must be queried using dev_info */
        parcel_size = device_size - (NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2);
        parcel_size -= (parcel_size % NUVO_BLOCK_SIZE);
    }

    if (parcel_size < NUVO_PM_PARCEL_MIN_SIZE)
    {
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Parcel size %lu is less than min parcel size %d.", NUVO_LOG_UUID(device_uuid), device_path, parcel_size, NUVO_PM_PARCEL_MIN_SIZE);
        ret = -EINVAL;
        goto out;
    }
    else if ((parcel_size & (NUVO_BLOCK_SIZE - 1)) != 0)
    {
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Parcel size %lu is not %d byte aligned.", NUVO_LOG_UUID(device_uuid), device_path, parcel_size, NUVO_BLOCK_SIZE);
        ret = -EINVAL;
        goto out;
    }

    /* aligned buffer for staging the superblock and parceltable */
    if (posix_memalign((void **)&private_region, NUVO_BLOCK_SIZE, NUVO_PM_DEVICE_PRIVATEREGION_SIZE))
    {
        ret = -errno;
        goto out;
    }

    /* when newly formatted, both private regions are identical */
    init_device_superblock((struct superblock *)&device_superblock, device_uuid, parcel_size, device_size, 0);
    memcpy(private_region, &device_superblock, NUVO_PM_DEVICE_SUPERBLOCK_SIZE);

    /* initialize all the parcel blocks in the private region */
    /* when newly formatted, the empty parcel blocks have the same zero gen_id. */
    for (uint32_t parcelblock_idx = 0; parcelblock_idx < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; parcelblock_idx++)
    {
        uint64_t parcelblock_offset = nuvo_device_parcelblock_offset(0, parcelblock_idx);
        init_device_parcelblock((struct device_parcelblock *)device_parcelblock, parcelblock_idx, 0);
        memcpy(private_region + parcelblock_offset, device_parcelblock, sizeof(struct device_parcelblock));
    }

    /* write the private region out to the device */
    struct iovec iov[NUVO_MAX_IO_BLOCKS];
    for (uint32_t blk = 0; blk < (NUVO_PM_DEVICE_PRIVATEREGION_SIZE / NUVO_MAX_IO_SIZE); blk++)
    {
        for (int i = 0; i < NUVO_MAX_IO_BLOCKS; i++)
        {
            uint32_t offset = ((blk * NUVO_MAX_IO_SIZE) + (i * NUVO_BLOCK_SIZE));
            iov[i].iov_base = private_region + offset;
            iov[i].iov_len = NUVO_BLOCK_SIZE;
        }
        /* write both private regions */
        for (uint32_t sb_idx = 0; sb_idx < NUVO_PM_SUPERBLOCKS; sb_idx++)
        {
            uint64_t sb_offset = nuvo_device_superblock_offset(device_size, sb_idx);
            sb_offset += (blk * NUVO_MAX_IO_SIZE);
            int bytes_written = pwritev(fd, iov, NUVO_MAX_IO_BLOCKS, sb_offset);
            if (bytes_written != NUVO_MAX_IO_SIZE)
            {
                if (bytes_written < 0)
                {
                    ret = -errno;
                    goto out;
                }
                else
                {
                    ret = -EIO;
                    goto out;
                }
            }
        }
    }

out:
    if (fd != -1)
    {
        close(fd);
    }
    if (private_region != NULL)
    {
        free(private_region);
    }
    return (ret);
}

/**
 * \fn int64_t nuvo_pm_device_delay(uuid_t device_uuid, uint64_t delay)
 *
 * Given a device_uuid, set a delay in nanoseconds
 *
 * \param device_uuid The uuid of the device.
 * \param delay The number of nanoseconds to delay each read/write
 * \return 0 on success, otherwise -errno.
 */
int64_t nuvo_pm_device_delay(const uuid_t device_uuid, uint64_t delay)
{
    int64_t ret = 0;
    struct device_record *device = NULL;

    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);

    nuvo_mutex_lock(&g_devices.devices_lock);
    if ((device = get_open_device_record(device_uuid)) == NULL)
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
        ret = -ENOENT;
    }
    else
    {
        nuvo_mutex_lock(&device->device_lock);
        nuvo_mutex_unlock(&g_devices.devices_lock);
        device->io_delay = delay;
        nuvo_mutex_unlock(&device->device_lock);
    }

    return (ret);
}

/**
 * \fn int64_t nuvo_pm_device_info(uuid_t device_uuid, device_info *device_info)
 *
 * Given a device_uuid returns a struct device_info
 *
 * \param device_uuid The uuid of the device.
 * \param device_info The address of a struct device_info to fill.
 * \return 0 on success, otherwise -errno.
 */
int64_t nuvo_pm_device_info(const uuid_t device_uuid, struct device_info *device_info)
{
    int64_t ret = 0;
    struct device_record *device = NULL;

    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);
    NUVO_ASSERT(device_info != NULL);

    nuvo_mutex_lock(&g_devices.devices_lock);
    if ((device = get_open_device_record(device_uuid)) == NULL)
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
        ret = -ENOENT;
    }
    else
    {
        nuvo_mutex_lock(&device->device_lock);
        nuvo_mutex_unlock(&g_devices.devices_lock);
        memcpy(device_info, &device->device_info, sizeof(struct device_info));
        nuvo_mutex_unlock(&device->device_lock);
    }

    return (ret);
}

/**
 * \fn int64_t nuvo_pm_device_stats(const uuid_t device_uuid, const int type, const bool clear, struct nuvo_io_stats_snap *stats_snapshot)
 * \brief Retrieve either read or write io statistics for the specified device.
 *
 * Given a device_uuid fills in and returns current statistics of the specified type in struct nuvo_io_stats_snap.
 * Statistics of the specified may be optionally reset by setting the clear flag.
 *
 * \param device_uuid The uuid of the device.
 * \param type Then type of stats to retrieve. Valid values are NUVO_OP_READ or NUVO_OP_WRITE.
 * \param clear If true, the device statics of the specified type will be reset on retrieval.
 * \param stats_snapshot The address of a struct nuvo_io_stats_snap to fill.
 * \return 0 on success, otherwise -errno.
 */
int64_t nuvo_pm_device_stats(const uuid_t device_uuid, const int type, const bool clear, struct nuvo_io_stats_snap *stats_snapshot)
{
    int64_t ret = 0;
    struct device_record *device = NULL;

    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);
    NUVO_ASSERT(stats_snapshot != NULL);

    nuvo_mutex_lock(&g_devices.devices_lock);
    if ((device = get_open_device_record(device_uuid)) == NULL)
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
        ret = -ENOENT;
    }
    else
    {
        nuvo_mutex_lock(&device->device_lock);
        nuvo_mutex_unlock(&g_devices.devices_lock);
        switch (type)
        {
        case NUVO_OP_READ:
            nuvo_io_stats_get_snapshot(&device->read_io_stats, stats_snapshot, clear);
            break;

        case NUVO_OP_WRITE:
            nuvo_io_stats_get_snapshot(&device->write_io_stats, stats_snapshot, clear);
            break;

        default:
            ret = -EINVAL;
            break;
        }
        nuvo_mutex_unlock(&device->device_lock);
    }

    return (ret);
}

/**
 * \fn int64_t nuvo_pm_device_reset_stats(const uuid_t device_uuid)
 * \brief Resets both read or write io statistics for the specified device.
 *
 * \param device_uuid The uuid of the device.
 * \return 0 on success, otherwise -errno.
 */
int64_t nuvo_pm_device_reset_stats(const uuid_t device_uuid)
{
    int64_t ret = 0;
    struct device_record *device = NULL;

    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);

    nuvo_mutex_lock(&g_devices.devices_lock);
    if ((device = get_open_device_record(device_uuid)) == NULL)
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
        ret = -ENOENT;
    }
    else
    {
        nuvo_mutex_lock(&device->device_lock);
        nuvo_mutex_unlock(&g_devices.devices_lock);

        nuvo_io_stats_clear(&device->read_io_stats);
        nuvo_io_stats_clear(&device->write_io_stats);

        nuvo_mutex_unlock(&device->device_lock);
    }

    return (ret);
}

/**
 * \brief Checks if the device has any parcels in use
 *
 * \param node_id The UUID of the node.
 * \returns true if the device has any open parcels.
 * \returns false if the device has no open parcels.
 */
bool nuvo_pm_is_device_in_use(const uuid_t dev_uuid)
{
    struct device_record *device = NULL;
    uint32_t pb_idx;
    uint32_t parcel_idx;


    /* look up the device */
    nuvo_mutex_lock(&g_devices.devices_lock);
    device = get_open_device_record(dev_uuid);

    if (!device)
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        return (false);
    }

    nuvo_mutex_lock(&device->device_lock);
    nuvo_mutex_unlock(&g_devices.devices_lock);

    for (pb_idx = 0; pb_idx < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; pb_idx++)
    {
        nuvo_mutex_lock(&device->parcelblocks[pb_idx].pb_lock);
        if (device->parcelblocks[pb_idx].device_parcelblock == NULL)
        {
            nuvo_mutex_unlock(&device->parcelblocks[pb_idx].pb_lock);
            continue;
        }

        for (parcel_idx = 0; parcel_idx < NUVO_PM_PARCELBLOCK_ENTRIES;
             parcel_idx++)
        {
            if (device->parcelblocks[pb_idx].meta[parcel_idx].open == 1)
            {
                nuvo_mutex_unlock(&device->parcelblocks[pb_idx].pb_lock);
                nuvo_mutex_unlock(&device->device_lock);
                return (true);
            }
        }
        nuvo_mutex_unlock(&device->parcelblocks[pb_idx].pb_lock);
    }

    nuvo_mutex_unlock(&device->device_lock);

    return (false);
}

int64_t nuvo_pm_device_close(const uuid_t device_uuid)
{
    struct device_record *device;

    nuvo_mutex_lock(&g_devices.devices_lock);
    /* look up the device, we shouldn't find it */
    device = get_device_record(device_uuid);
    if (device)
    {
        nuvo_mutex_lock(&device->device_lock);
        nuvo_mutex_unlock(&g_devices.devices_lock);
        device->open = 0;
        if (device->allocated)
        {
            for (uint32_t j = 0; j < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; j++)
            {
                if (device->parcelblocks[j].device_parcelblock)
                {
                    nuvo_mutex_lock(&device->parcelblocks[j].pb_lock);
                    free(device->parcelblocks[j].device_parcelblock);
                    device->parcelblocks[j].device_parcelblock = NULL;
                    nuvo_mutex_unlock(&device->parcelblocks[j].pb_lock);
                }

                /* send completions for anything remaining on the deferred list */
                if ((device->parcelblocks[j].deferred_list).node.next != NULL)
                {
                    struct nuvo_dlist      *deferred_list = &device->parcelblocks[j].deferred_list;
                    struct nuvo_io_request *io_req;
                    while ((io_req = nuvo_dlist_remove_head_object(deferred_list, struct nuvo_io_request, list_node)) != NULL)
                    {
                        io_req->status = -ESHUTDOWN;
                        nuvo_pr_complete(io_req);
                    }
                }
            }
        }

        /* free the superblock */
        if (device->superblock)
        {
            free(device->superblock);
            device->superblock = NULL;
        }

        /* close the device */
        if (device->fd > 0)
        {
            close(device->fd);
            device->fd = 0;
        }

        nuvo_io_stats_destroy(&device->read_io_stats);
        nuvo_io_stats_destroy(&device->write_io_stats);

        memset(&device->device_info, 0, sizeof(struct device_info));
        device->allocated = 0;
        nuvo_mutex_unlock(&device->device_lock);
        return (0);
    }
    else
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
        return (-ENOENT);
    }
}

/**
 * \fn int64_t nuvo_pm_device_open(char *device_path, uuid_t device_uuid, uint64_t parcel_size)
 * \brief Opens a device for subsequent parcel I/O operations.
 *
 * Given a device_uuid and a path to a device previously formatted with pm_device_format, A call to nuvo_pm_device_open
 * open(2)'s the device with a O_RDWR access mode, and the O_DIRECT flag. The device superblock and parcel table entries
 * are read the device_uuid is verified along with parcel table checksums. The device superblock and parcel table is
 * stored in memory for subsequent parcel offset lookups.
 *
 * A call to nuvo_pm_device_open creates a new record storing the file descriptor, which is used internally on
 * subsequent i/o operations to the device with pm_submit and pm_device_close. The file descriptor is generally
 * expected to remain open for the life of the calling process.
 *
 * TODO doc all the rets.
 *
 * \param device_path The device to open.
 * \param device_uuid The uuid of the device.
 * \param device_type The type of device.
 * \return 0 on success, otherwise -errno.
 */
int64_t nuvo_pm_device_open(const char *device_path, const uuid_t device_uuid, const enum nuvo_dev_type device_type)
{
    uint64_t              device_size;
    struct iovec          iov[2][NUVO_MAX_IO_BLOCKS];
    struct device_record *device = NULL;
    int fd;
    int ret;

    NUVO_ASSERT(device_path != NULL);
    NUVO_ASSERT(uuid_is_null(device_uuid) == 0);
    NUVO_ASSERT(device_type < NUVO_MAX_DEV_TYPES);

    memset(iov, 0, sizeof(iov));

    if (g_pm_shutdown)
    {
        return (-ESHUTDOWN);
    }

    nuvo_mutex_lock(&g_devices.devices_lock);
    if ((device = get_device_record(device_uuid)) != NULL)
    {
        /* look up the device, we shouldn't find it */
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Device is already open.", NUVO_LOG_UUID(device_uuid), device_path);
        ret = -NUVO_E_DEVICE_ALREADY_OPEN;
    }
    else if ((fd = open(device_path, O_DIRECT | O_RDWR)) < 0)
    {
        char *err_str = nuvo_status_alloc_error_str(errno);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Open failed. %s.", NUVO_LOG_UUID(device_uuid), device_path, err_str ? err_str : "Unknown");
        if (err_str)
        {
            free(err_str);
        }
        ret = -errno;
    }
    else if ((ret = get_device_size(fd, &device_size)) < 0)
    {
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Unable to get device size.", NUVO_LOG_UUID(device_uuid), device_path);
    }
    else if ((device = alloc_device_record(device_uuid)) == NULL)
    {
        /* reserve a slot in the device table */
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT " (%s). Failed to allocate new record.", NUVO_LOG_UUID(device_uuid), device_path);
        ret = -ENOMEM;
    }
    else
    {
        nuvo_mutex_lock(&device->device_lock);
    }
    nuvo_mutex_unlock(&g_devices.devices_lock);

    if (ret != 0)
    {
        return (ret);
    }

    /*
     * the device record is now ours until it's marked open
     * this also means during a shutdown we need to do the
     * cleanup here, as shutdown cleanup doesn't touch
     * devices that aren't open
     */

    uint32_t blk = 0;
    int      done = 0;
    int      pb_idx = 0;
    int      parcel_cnt = 0;
    while (!done && (blk < (NUVO_PM_DEVICE_PRIVATEREGION_SIZE / NUVO_MAX_IO_SIZE)))
    {
        /* set up the io buffers for reading both private regions */
        for (int i = 0; i < NUVO_PM_SUPERBLOCKS; i++)
        {
            for (int j = 0; j < NUVO_MAX_IO_BLOCKS; j++)
            {
                if (posix_memalign((void **)&iov[i][j].iov_base, NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE))
                {
                    ret = -errno;
                    goto free_out;
                }
                iov[i][j].iov_len = NUVO_BLOCK_SIZE;
            }
        }

        /* read in 256 4K blocks from the two private regions */
        for (int sb_idx = 0; sb_idx < NUVO_PM_SUPERBLOCKS; sb_idx++)
        {
            uint64_t offset = nuvo_device_superblock_offset(device_size, sb_idx) + (blk * NUVO_MAX_IO_SIZE);
            int      bytes_read = preadv(fd, iov[sb_idx], NUVO_MAX_IO_BLOCKS, offset);
            if (bytes_read != NUVO_MAX_IO_SIZE)
            {
                if (bytes_read < NUVO_MAX_IO_SIZE)
                {
                    /* TODO - handle */
                    ret = -EIO;
                }
                else
                {
                    ret = -errno;
                }
                goto free_out;
            }
        }

        /* populate the parcel table with block with the most recent genid */
        for (int p = 0; p < NUVO_MAX_IO_BLOCKS; p++)
        {
            if (p == 0 && blk == 0)
            {
                /* superblock starts at block 0 offset 0, the rest are parcel blocks */
                struct superblock *sb;
                struct superblock *sb0 = (struct superblock *)iov[0][p].iov_base;
                struct superblock *sb1 = (struct superblock *)iov[1][p].iov_base;
                if (valid_device_superblock(sb1))
                {
                    if (valid_device_superblock(sb0))
                    {
                        if (sb0->gen_id >= sb1->gen_id)
                        {
                            sb = sb0;
                            free(iov[1][p].iov_base);
                            iov[1][p].iov_base = NULL;
                        }
                        else
                        {
                            sb = sb1;
                            free(iov[0][p].iov_base);
                            iov[0][p].iov_base = NULL;
                        }
                        if (uuid_compare(sb->device_uuid, device_uuid) != 0)
                        {
                            ret = -ENOENT;
                            goto free_out;
                        }
                        if (sb->device_size > device_size)
                        {
                            ret = -ENOSPC;
                            goto free_out;
                        }
                        /* add the parcel block to the parcel table */
                        device->superblock = sb;
                    }
                    else
                    {
                        /* need both blocks to compare gen id's*/
                        ret = -EFAULT;
                        goto free_out;
                    }
                }
                else
                {
                    /* need both blocks to compare gen id's*/
                    ret = -EFAULT;
                    goto free_out;
                }
            }
            else if (valid_device_parcelblock((struct device_parcelblock *)iov[0][p].iov_base))
            {
                struct device_parcelblock *pb;
                struct device_parcelblock *pb0 = (struct device_parcelblock *)iov[0][p].iov_base;
                struct device_parcelblock *pb1 = (struct device_parcelblock *)iov[1][p].iov_base;
                if (valid_device_parcelblock(pb1))
                {
                    if (pb0->header.gen_id >= pb1->header.gen_id)
                    {
                        pb = pb0;
                        free(iov[1][p].iov_base);
                        iov[1][p].iov_base = NULL;
                    }
                    else
                    {
                        pb = pb1;
                        free(iov[0][p].iov_base);
                        iov[0][p].iov_base = NULL;
                    }

                    /*
                     * a parcel block with gen_id 0 has never been used.
                     * if we get back an valid current parcel block with gen_id 0 it means
                     * we've reached the end of allocated parcel blocks. so stop here.
                     */
                    if (pb->header.gen_id == 0)
                    {
                        /* free the remaining empty parcel blocks */
                        for (int i = 0; i < NUVO_PM_SUPERBLOCKS; i++)
                        {
                            for (int j = p; j < NUVO_MAX_IO_BLOCKS; j++)
                            {
                                free(iov[i][j].iov_base);
                            }
                        }
                        done = 1;
                        break;
                    }
                    else
                    {
                        /* add the parcel block to the parcel table */
                        device->parcelblocks[pb_idx].device_parcelblock = pb;

                        /* iterate over the parcel blocks for the tracking array totals */
                        for (uint32_t i = 0; i < NUVO_PM_PARCELBLOCK_ENTRIES; i++)
                        {
                            if (!check_empty(&device->parcelblocks[pb_idx].device_parcelblock->parcels[i], sizeof(struct parcel_record)))
                            {
                                device->parcelblocks[pb_idx].allocated_cnt++;
                                parcel_cnt++;
                            }
                        }
                        pb_idx++;
                    }
                }
                else
                {
                    /* need both blocks to compare gen id's*/
                    ret = -EFAULT;
                    goto free_out;
                }
            }
            else
            {
                /* need both blocks to compare gen id's*/
                ret = -EFAULT;
                goto free_out;
            }
        }
        blk++;
    }

    for (uint32_t i = 0; i < NUVO_PM_DEVICE_MAX_PARCELBLOCKS; i++)
    {
        nuvo_dlist_init(&device->parcelblocks[i].deferred_list);
    }

    if ((ret = init_device_info_and_stats(device)) < 0)
    {
        goto free_out;
    }

    device->device_info.device_type = device_type;
    device->device_info.parcels_allocated = parcel_cnt;
    if (device->device_info.parcels_allocated == device->device_info.max_parcels)
    {
        device->device_info.parceltable_full = 1;
    }
    snprintf(device->device_info.device_path, sizeof(device->device_info.device_path), "%s", device_path);
    device->fd = fd;
    device->open = 1;

    nuvo_mutex_unlock(&device->device_lock);
    return (0);

free_out:
    /* free the iocbs we're hanging onto */
    for (int i = 0; i < NUVO_PM_SUPERBLOCKS; i++)
    {
        for (int j = 0; j < NUVO_MAX_IO_BLOCKS; j++)
        {
            if (iov[i][j].iov_base != NULL)
            {
                free(iov[i][j].iov_base);
            }
        }
    }

    free_device_record(device);
    nuvo_mutex_unlock(&device->device_lock);
    return (ret);
}

/**
 * \fn int64_t pm_parcel_open(uuid_t parcel_uuid, uuid_t device_uuid, uuid_t volume_uuid)
 * \brief Opens a parcel record and returns a parcel_uuid that can be used for subsequent lookups
 *
 *  TODO doc all the rets.
 *
 * \param parcel_uuid The uuid of the parcel
 * \param device_uuid The uuid of the device the parcel is on.
 * \param volume_uuid The uuid of the volume the parcel belongs to.
 * \return 0 on success, otherwise -errno.
 */
static int64_t pm_parcel_open(const uuid_t parcel_uuid, const uuid_t device_uuid, const uuid_t volume_uuid, uint_fast32_t *native_parcel_desc)
{
    struct device_record *device = NULL;
    uint32_t parcelblock_idx;
    uint32_t parcel_idx;
    int64_t  ret;

    if (g_pm_shutdown)
    {
        ret = -ESHUTDOWN;
        goto out;
    }

    /* look up the device */
    nuvo_mutex_lock(&g_devices.devices_lock);
    device = get_open_device_record(device_uuid);

    if (!device)
    {
        nuvo_mutex_unlock(&g_devices.devices_lock);
        NUVO_ERROR_PRINT("Device uuid: "NUVO_LOG_UUID_FMT ". Device not found", NUVO_LOG_UUID(device_uuid));
        ret = -ENOENT;
        goto out;
    }
    else
    {
        nuvo_mutex_lock(&device->device_lock);
        nuvo_mutex_unlock(&g_devices.devices_lock);
    }

    /* lookup parcel and find the uuid */
    int found = 0;
    parcelblock_idx = 0;
    int last_parcelblock = 0;
    ret = -ENOENT;
    while (!found && !last_parcelblock && (parcelblock_idx < NUVO_PM_DEVICE_MAX_PARCELBLOCKS))
    {
        nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);
        if (device->parcelblocks[parcelblock_idx].device_parcelblock != NULL)
        {
            for (parcel_idx = 0; parcel_idx < NUVO_PM_PARCELBLOCK_ENTRIES; parcel_idx++)
            {
                uuid_t *uuid = &device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[parcel_idx].parcel_uuid;
                if (uuid_compare(parcel_uuid, *uuid) == 0)
                {
                    found = 1;
                    uuid = &device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[parcel_idx].volume_uuid;
                    if (uuid_compare(volume_uuid, *uuid) == 0)
                    {
                        union native_parcel_descriptor npd;

                        if (device->parcelblocks[parcelblock_idx].meta[parcel_idx].open == 1)
                        {
                            /* only one open permitted */
                            ret = -NUVO_E_PARCEL_ALREADY_OPEN;
                        }
                        else
                        {
                            /* bump the genid and mark open */
                            device->parcelblocks[parcelblock_idx].meta[parcel_idx].gen_id++;
                            device->parcelblocks[parcelblock_idx].meta[parcel_idx].open = 1;
                            ret = 0;
                        }

                        /* encode the parcel descriptor */
                        npd.gen_id = pm_parcel_to_desc_genid(device->parcelblocks[parcelblock_idx].meta[parcel_idx].gen_id);
                        npd.dev_idx = DEVICE_INDEX(device);
                        npd.pb_idx = parcelblock_idx;
                        npd.ent_idx = parcel_idx;
                        *native_parcel_desc = npd.native_parcel_desc;

                        break;
                    }
                    else
                    {
                        /* found the requested parcel, but it doesn't match the volume uuid provided */
                        NUVO_ERROR_PRINT("Parcel uuid: "NUVO_LOG_UUID_FMT ". Unexpected volume uuid "NUVO_LOG_UUID_FMT, NUVO_LOG_UUID(parcel_uuid), NUVO_LOG_UUID(*uuid));
                        ret = -EPERM;
                        break;
                    }
                }
            }
        }
        else
        {
            /* no parcelblocks left to search that've had entries */
            last_parcelblock = 1;
        }
        nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);
        if (!found && !last_parcelblock)
        {
            parcelblock_idx++;
        }
    }
    nuvo_mutex_unlock(&device->device_lock);
out:
    return (ret);
}

/**
 * \fn int64_t pm_parcel_close(struct nuvo_io_request *io_req)
 * \brief Closes a parcel record
 *
 * returns EBADF if the file descriptor is current generation, but the parcel open count would go negative.
 * in the case of a bad file description that's before the current generation just return success?
 * returns -NUVO_E_PARCEL_ALREADY_CLOSED if the parcel record is already closed.
 *
 * \param io_req The io_req containing the descriptor to be closed.
 * \return 0 on success, otherwise -errno.
 */
static int64_t pm_parcel_close(struct nuvo_io_request *io_req)
{
    int64_t ret = 0;
    union native_parcel_descriptor npd;
    uint32_t parcel_gen_id = 0;

    npd.native_parcel_desc = io_req->close.native_parcel_desc;

    nuvo_mutex_lock(&g_devices.devices[npd.dev_idx].device_lock);
    nuvo_mutex_lock(&g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].pb_lock);
    parcel_gen_id = g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].meta[npd.ent_idx].gen_id;
    if (npd.gen_id != pm_parcel_to_desc_genid(parcel_gen_id))
    {
        NUVO_ERROR_PRINT("Parcel descriptor [%d.%d.%d]. Generation %d is not current generation %d.", npd.gen_id, npd.dev_idx, npd.pb_idx, npd.gen_id, pm_parcel_to_desc_genid(parcel_gen_id));
        ret = -EBADF;
    }
    else
    {
        if (g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].meta[npd.ent_idx].open == 1)
        {
            g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].meta[npd.ent_idx].open = 0;
        }
        else
        {
            ret = -NUVO_E_PARCEL_ALREADY_CLOSED;
        }
    }
    nuvo_mutex_unlock(&g_devices.devices[npd.dev_idx].parcelblocks[npd.pb_idx].pb_lock);
    nuvo_mutex_unlock(&g_devices.devices[npd.dev_idx].device_lock);
    return (ret);
}

/**
 * \brief Checks if a parcel UUID already exists
 *
 * Used to detect if a requested UUID already exists
 *
 * \param device The device_record of interest
 * \param parcel_uuid The uuid for which to search
 * \return true or false
 */
static bool pm_parcel_uuid_exists(struct device_record *device, uuid_t parcel_uuid)
{
    bool     found = false;
    uint32_t parcelblock_idx = 0;
    uint32_t parcel_idx;

    NUVO_ASSERT_MUTEX_HELD(&device->device_lock);

    while (!found && (parcelblock_idx < NUVO_PM_DEVICE_MAX_PARCELBLOCKS))
    {
        nuvo_mutex_lock(&device->parcelblocks[parcelblock_idx].pb_lock);
        if (device->parcelblocks[parcelblock_idx].device_parcelblock != NULL)
        {
            for (parcel_idx = 0; parcel_idx < NUVO_PM_PARCELBLOCK_ENTRIES; parcel_idx++)
            {
                uuid_t *uuid = &device->parcelblocks[parcelblock_idx].device_parcelblock->parcels[parcel_idx].parcel_uuid;
                if (uuid_compare(parcel_uuid, *uuid) == 0)
                {
                    found = true;
                }
            }
        }
        nuvo_mutex_unlock(&device->parcelblocks[parcelblock_idx].pb_lock);

        if (!found)
        {
            parcelblock_idx++;
        }
    }

    return (found);
}
