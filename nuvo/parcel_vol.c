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
#include <uuid/uuid.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "nuvo.h"
#include "nuvo_vol_series.h"
#include "nuvo_pr.h"
#include "nuvo_pr_sync.h"
#include "device_type.h"

/**
 * @file parcel_vol.c
 * @brief Routines around parcel volumes
 */

/**
 * \brief Write out the parcel table for a parcel volume.
 *
 * This is purposely sucky. In partuclar, we write out the
 * whole thing at once and don't do anything fancier.
 * Need to lock protect this, but it's ok for now since
 * this is only called downstream of the API thread.
 *
 * \param nvs_p Pointer to the volume series.
 */
nuvo_return_t nuvo_parcel_vol_write_manifest(struct nuvo_vol *nvs_p)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t ret = nuvo_mutex_init(&sync_signal);

    if (ret != 0)
    {
        return (ret);
    }
    // NUVO_ASSERT(nvs_p->type == NUVO_VOL_PARCEL);
    struct nuvo_io_request *req = nuvo_pr_sync_client_req_alloc(&sync_signal);

    // Have to free req before exiting.
    // Now set up the write.
    NUVO_SET_IO_TYPE(req, NUVO_OP_WRITE, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
    req->tag.ptr = NULL;
    req->rw.parcel_desc = nvs_p->parvol.pds[0];
    req->rw.block_offset = 0;
    req->rw.block_count = NUVO_SIMPLE_PARCEL_MANIFEST_BLKS;
    nuvo_pr_sync_buf_alloc_req(req, &sync_signal);
    // Now need to free buffers on error.
    // Need to compute hash on the parcel manifest.
    nvs_p->parvol.pm.hash = 0;
    nvs_p->parvol.pm.hash = nuvo_hash(&nvs_p->parvol.pm, sizeof(struct nuvo_simple_parcel_manifest));
    // Need to put the data in the buffers and compute hash.
    uint64_t bytes_left = sizeof(struct nuvo_simple_parcel_manifest);
    uint8_t *start = (uint8_t *)&nvs_p->parvol.pm;
    for (uint32_t i = 0; i < req->rw.block_count; i++)
    {
        uint8_t *buf = (uint8_t *)req->rw.iovecs[i].iov_base;
        if (bytes_left < NUVO_BLOCK_SIZE)
        {
            memset(buf, 0, NUVO_BLOCK_SIZE);  // overkill
            memcpy(buf, start, bytes_left);
        }
        else
        {
            memcpy(buf, start, NUVO_BLOCK_SIZE);
        }
        start += NUVO_BLOCK_SIZE;
        bytes_left -= NUVO_BLOCK_SIZE;
        req->rw.block_hashes[i] = nuvo_hash(buf, NUVO_BLOCK_SIZE);
    }
    nuvo_pr_sync_submit(req, &sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
    }
    nuvo_pr_client_buf_free_req(req);
    nuvo_pr_client_req_free(req);

    nuvo_mutex_destroy(&sync_signal);
    return (ret);
}

/**
 * \brief Read in the parcel table for a parcel volume.
 *
 * This is purposely sucky. In partuclar, we read in the
 * whole thing at once and don't do anything fancier.
 * Need to lock protect this, but it's ok for now since
 * this is only called downstream of the API thread.
 * It is assumed that nvs_p has the root descriptor for
 * the volume open.
 *
 * \param nvs_p Pointer to the volume series.
 * \param sync_signal mutex to us to make synhchronous.
 */
int nuvo_parcel_vol_read_manifest(struct nuvo_vol *nvs_p, nuvo_mutex_t *sync_signal)
{
    //NUVO_ASSERT(nvs_p->type == NUVO_VOL_PARCEL);
    struct nuvo_io_request *req = nuvo_pr_client_req_alloc();

    if (req == NULL)
    {
        return (-EAGAIN);
    }

    int ret = 0;
    // Have to free req before exiting.
    // Now set up the write.
    NUVO_SET_IO_TYPE(req, NUVO_OP_READ, NUVO_IO_ORIGIN_INTERNAL);
    NUVO_SET_CACHE_HINT(req, NUVO_CACHE_DEFAULT);
    req->tag.ptr = NULL;
    req->rw.parcel_desc = nvs_p->parvol.pds[0];
    req->rw.block_offset = 0;
    req->rw.block_count = NUVO_SIMPLE_PARCEL_MANIFEST_BLKS;
    nuvo_pr_sync_buf_alloc_req(req, sync_signal);
    // Now need to free buffers on error.
    nuvo_pr_sync_submit(req, sync_signal);
    if (req->status != 0)
    {
        ret = req->status;
        goto buf_free;
    }

    // Need to get the data out of the buffers
    uint64_t bytes_left = sizeof(struct nuvo_simple_parcel_manifest);
    uint8_t *start = (uint8_t *)&nvs_p->parvol.pm;
    for (uint32_t i = 0; i < req->rw.block_count; i++)
    {
        uint8_t *buf = (uint8_t *)req->rw.iovecs[i].iov_base;
        if (bytes_left < NUVO_BLOCK_SIZE)
        {
            memcpy(start, buf, bytes_left);
        }
        else
        {
            memcpy(start, buf, NUVO_BLOCK_SIZE);
        }
        start += NUVO_BLOCK_SIZE;
        bytes_left -= NUVO_BLOCK_SIZE;
    }
    // Need to compute hash on the parcel manifest.
    nuvo_hash_t hash = nvs_p->parvol.pm.hash;
    nvs_p->parvol.pm.hash = 0;
    nvs_p->parvol.pm.hash = nuvo_hash(&nvs_p->parvol.pm, sizeof(struct nuvo_simple_parcel_manifest));
    if (hash != nvs_p->parvol.pm.hash)
    {
        // we're screwed.
        memset(&nvs_p->parvol.pm, 0, sizeof(nvs_p->parvol.pm));
        ret = -NUVO_E_BAD_HASH;
        goto buf_free;
    }

buf_free:
    nuvo_pr_client_buf_free_req(req);
    nuvo_pr_client_req_free(req);
    return (ret);
}

static void nuvo_parcel_vol_parcel_init(struct nuvo_vol *nvs_p)
{
    for (uint_fast32_t i = 0; i < MAX_PARCELS_IN_PARCEL_VOL; i++)
    {
        nvs_p->parvol.pds[i] = NUVO_VOL_PD_UNUSED;
    }
}

static nuvo_return_t parcel_vol_load(struct nuvo_vol *nvs_p,
                                     const uuid_t     device_uuid,
                                     const uuid_t     root_parcel_uuid,
                                     nuvo_mutex_t    *sync_signal)
{
    nuvo_return_t ret = 0;

    nuvo_parcel_vol_parcel_init(nvs_p);

    uint_fast32_t parcel_desc;
    ret = nuvo_pr_sync_parcel_open(&parcel_desc, root_parcel_uuid, device_uuid, nvs_p->vs_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Opening root parcel failed.");
        return (ret);
    }
    nvs_p->parvol.pds[0] = parcel_desc;
    ret = nuvo_parcel_vol_read_manifest(nvs_p, sync_signal);
    if (ret != 0)
    {
        int ret2 = nuvo_pr_sync_parcel_close(parcel_desc);
        if (ret2)
        {
            NUVO_ERROR_PRINT("Parcel close failed after read manifest failed.");
        }
        return (ret);
    }
    return (0);
}

/**
 * \brief Open a parcel vol series.
 *
 * Find a slot fo the vol series, open the root parcel,
 * read in the parcel manifest, get the volume all ready to
 * be exported.
 *
 * \param vol The vol series to open.
 * \param device_uuid The device holding the root parcel.
 * \param root_parcel_uuid The root parcel.
 * \param sync_signal Signal used to make stuff sync.
 */
nuvo_return_t nuvo_parcel_vol_open_work(struct nuvo_vol *nvs_p, const uuid_t device_uuid,
                                        const uuid_t root_parcel_uuid, nuvo_mutex_t *sync_signal)
{
    int ret = parcel_vol_load(nvs_p, device_uuid,
                              root_parcel_uuid, sync_signal);

    if (ret != 0)
    {
        return (ret);
    }

    for (uint_fast32_t i = 1; i < nvs_p->parvol.pm.num_parcels; i++)
    {
        ret = nuvo_pr_sync_parcel_open(&nvs_p->parvol.pds[i], nvs_p->parvol.pm.manifest[i].parcel_id,
                                       nvs_p->parvol.pm.manifest[i].device_id, nvs_p->vs_uuid);
        if (ret != 0)
        {
            NUVO_ERROR_PRINT("Failed to open parcel");
            return (ret);
        }
    }

    nvs_p->type = NUVO_VOL_PARCEL;
    ret = nuvo_mutex_init(&nvs_p->mutex);  // destroy mutex on error, but this is already a shambles of error handling.
    NUVO_ASSERT(ret == 0);
    ret = nuvo_lun_init(&nvs_p->parvol.lun, nvs_p);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Failed to init parcel vol");
        return (ret);
    }
    nuvo_lun_state_init(&nvs_p->parvol.lun, nvs_p, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);
    return (0);
}

nuvo_return_t nuvo_parcel_vol_destroy(struct nuvo_vol *nvs_p,
                                      const uuid_t     device_uuid,
                                      const uuid_t     root_parcel_uuid,
                                      nuvo_mutex_t    *sync_signal)
{
    if (nvs_p)
    {
        return (-NUVO_EBUSY);
    }
    int ret = parcel_vol_load(nvs_p, device_uuid,
                              root_parcel_uuid, sync_signal);
    if (ret != 0)
    {
        return (ret);
    }
    ret = nuvo_pr_sync_parcel_close(nvs_p->parvol.pds[0]);
    if (ret)
    {
        NUVO_ERROR_PRINT("Parcel close failed.");
        // We'll leak the parcel, but the volume is not
        // marked in use, so no leaking of resources
        // there.
        return (ret);
    }

    while (nvs_p->parvol.pm.num_parcels > 0)
    {
        uint_fast32_t i = nvs_p->parvol.pm.num_parcels - 1;
        ret = nuvo_pr_sync_parcel_free(
            nvs_p->parvol.pm.manifest[i].parcel_id,
            nvs_p->parvol.pm.manifest[i].device_id,
            nvs_p->vs_uuid);
        if (ret != 0)
        {
            NUVO_ERROR_PRINT("Failed to free parcel");
            return (ret);
        }
        nvs_p->parvol.pm.num_parcels--;
    }
    return (0);
}

/**
 * \brief Create a parcel vol series.
 *
 * Find a slot for the vol series, allocate the root parcel,
 * write out the parcel manifest, get the volume all ready to
 * be exported.
 *
 * \param root_parcel_uuid The root parcel uuid to use.
 * \param device_uuid The device holding the root parcel.
 * \param vs_uuid The vol series to open.
 */
nuvo_return_t nuvo_parcel_vol_create_work(struct nuvo_vol *nvs_p, const uuid_t device_uuid, uuid_t root_parcel_uuid)
{
    int ret = 0;

    nuvo_parcel_vol_parcel_init(nvs_p);
    uint64_t           device_size, parcel_size;
    enum nuvo_dev_type device_type;
    ret = nuvo_pr_sync_dev_info(device_uuid, &device_size, &parcel_size, &device_type);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Get device info failed.");
        return (ret);  // CUM-1258 Error value
    }

    ret = nuvo_pr_sync_parcel_alloc(root_parcel_uuid, device_uuid, nvs_p->vs_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Allocating a root parcel failed.");
        return (ret);   // CUM-1258 Error value
    }
    // Now on fail need to free parcel
    uint_fast32_t parcel_desc;
    ret = nuvo_pr_sync_parcel_open(&parcel_desc, root_parcel_uuid, device_uuid, nvs_p->vs_uuid);
    if (ret != 0)
    {
        // CUM-1258 Leaking root parcel
        NUVO_ERROR_PRINT("Opening root parcel failed.");
        return (ret);
    }
    uuid_copy(nvs_p->parvol.pm.manifest[0].parcel_id, root_parcel_uuid);
    uuid_copy(nvs_p->parvol.pm.manifest[0].device_id, device_uuid);
    nvs_p->parvol.pm.manifest[0].size_in_blocks = parcel_size / NUVO_BLOCK_SIZE;
    nvs_p->parvol.pm.num_parcels = 1;
    nvs_p->parvol.pds[0] = parcel_desc;
    ret = nuvo_parcel_vol_write_manifest(nvs_p);
    if (ret != 0)
    {
        // CUM-1258 free the parcel
        NUVO_ERROR_PRINT("Write manifest failed on new volume. Leaking parcel.");
        return (ret);
    }

    nvs_p->type = NUVO_VOL_PARCEL;
    ret = nuvo_mutex_init(&nvs_p->mutex); // destroy mutex on error, but this is already a shambles of error handling.
    NUVO_ASSERT(ret == 0);
    ret = nuvo_lun_init(&nvs_p->parvol.lun, nvs_p);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Failed to init parcel vol");
        return (ret);
    }
    nuvo_lun_state_init(&nvs_p->parvol.lun, nvs_p, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);

    return (0);
}

nuvo_return_t nuvo_parcel_vol_alloc_parcels(struct nuvo_vol *nvs_p, const uuid_t dev_uuid, uint64_t num)
{
    nuvo_return_t ret = 0;

    NUVO_ASSERT(nvs_p->type == NUVO_VOL_PARCEL);

    for (uint_fast32_t i = 0; i < num; i++)
    {
        uint64_t           device_size, parcel_size;
        enum nuvo_dev_type device_type;
        ret = nuvo_pr_sync_dev_info(dev_uuid, &device_size, &parcel_size, &device_type);
        if (ret != 0)
        {
            NUVO_ERROR_PRINT("Get device info failed.");
            return (ret);
        }
        uuid_t new_parcel_uuid;

        uuid_clear(new_parcel_uuid);

        ret = nuvo_pr_sync_parcel_alloc(new_parcel_uuid, dev_uuid, nvs_p->vs_uuid);

        if (ret != 0)
        {
            NUVO_ERROR_PRINT("Allocating a new parcel failed.");
            return (ret);
        }
        // Now on fail need to free parcel
        uint_fast32_t parcel_desc;
        ret = nuvo_pr_sync_parcel_open(&parcel_desc, new_parcel_uuid, dev_uuid, nvs_p->vs_uuid);
        if (ret != 0)
        {
            // CUM-1258 Leaking a parcel
            NUVO_ERROR_PRINT("Opening new parcel failed.");
            return (ret);
        }
        uuid_copy(nvs_p->parvol.pm.manifest[nvs_p->parvol.pm.num_parcels].parcel_id, new_parcel_uuid);
        uuid_copy(nvs_p->parvol.pm.manifest[nvs_p->parvol.pm.num_parcels].device_id, dev_uuid);
        nvs_p->parvol.pm.manifest[nvs_p->parvol.pm.num_parcels].size_in_blocks = parcel_size / NUVO_BLOCK_SIZE;
        nvs_p->parvol.pds[nvs_p->parvol.pm.num_parcels] = parcel_desc;
        nvs_p->parvol.pm.num_parcels++;
    }
    ret = nuvo_parcel_vol_write_manifest(nvs_p);
    if (ret != 0)
    {
        // CUM-1258 free the parcel
        NUVO_ERROR_PRINT("Write manifest failed on new volume. Leaking parcel.");
        return (ret);
    }

    return (0);
}

nuvo_return_t nuvo_parcel_vol_close(struct nuvo_vol *nvs_p)
{
    nuvo_mutex_lock(&vol_table.mutex);
    NUVO_ASSERT(nvs_p->type == NUVO_VOL_PARCEL);
    if (NUVO_LUN_IS_EXPORTED(&nvs_p->parvol.lun))
    {
        if (nvs_p->shutdown_in_progress)
        {
            NUVO_ERROR_PRINT("Exported Parcel Lun detected during shutdown.");
        }
        else
        {
            nuvo_mutex_unlock(&vol_table.mutex);
            return (-NUVO_E_LUN_EXPORTED);
        }
    }

    for (uint_fast32_t i = 0; i < nvs_p->parvol.pm.num_parcels; i++)
    {
        if (nvs_p->parvol.pds[i] != NUVO_VOL_PD_UNUSED)
        {
            int rc;
            if (0 != (rc = nuvo_pr_sync_parcel_close(nvs_p->parvol.pds[i])))
            {
                NUVO_ERROR_PRINT("Could not close parcel");
            }
            nvs_p->parvol.pds[i] = NUVO_VOL_PD_UNUSED;
        }
    }

    nuvo_lun_destroy(&nvs_p->parvol.lun);

    nvs_p->type = NUVO_VOL_FREE;
    nuvo_mutex_unlock(&vol_table.mutex);
    return (0);
}

nuvo_return_t nuvo_parcel_vol_find_location(const struct nuvo_vol *nvs,
                                            uint64_t               bno,
                                            uint64_t               num_blocks,
                                            uint_fast32_t         *pdesc,
                                            uint_fast32_t         *pd_boff,
                                            uint_fast32_t         *pd_num)
{
    NUVO_ASSERT(nvs->type == NUVO_VOL_PARCEL);
    const struct nuvo_simple_parcel_manifest *pm = &nvs->parvol.pm;
    bno += NUVO_SIMPLE_PARCEL_MANIFEST_BLKS;
    uint_fast32_t i = 0;
    while (i < pm->num_parcels && pm->manifest[i].size_in_blocks <= bno)
    {
        bno -= pm->manifest[i].size_in_blocks;
        i++;
    }
    if (i == pm->num_parcels)
    {
        return (-ERANGE);
    }
    NUVO_ASSERT(nvs->parvol.pds[i] != NUVO_VOL_PD_UNUSED);
    *pdesc = nvs->parvol.pds[i];
    *pd_boff = bno;
    *pd_num = (pm->manifest[i].size_in_blocks - bno >= num_blocks) ?
              num_blocks : pm->manifest[i].size_in_blocks - bno;
    return (0);
}
