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

/**
 * @file passthrough_vol.c
 * @brief Routines around passthrough volumes
 */

nuvo_return_t nuvo_passthrough_open_work(struct nuvo_vol *nvs_p, const char *blk_dev, size_t size)
{
    NUVO_ASSERT(nvs_p);
    NUVO_ASSERT(nvs_p->type == NUVO_VOL_PASSTHROUGH);

    // validate size
    if (size == 0 || (size % BLOCK_SIZE != 0))
    {
        return (-EINVAL);
    }

    int fd = open(blk_dev, O_RDWR | O_DIRECT | O_LARGEFILE);
    if (fd == -1)
    {
        return (-errno);
    }

    nuvo_return_t ret = nuvo_mutex_init(&nvs_p->mutex);
    if (ret != 0)
    {
        ret = -NUVO_ENOMEM;
        goto close_file;
    }
    NUVO_ASSERT(ret == 0);
    nvs_p->ptvol.fd = fd;

    ret = nuvo_lun_init(&nvs_p->ptvol.lun, nvs_p);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Failed to init parcel vol");
        ret = -ENOMEM;
        nvs_p->type = NUVO_VOL_FREE;
        goto destroy_mutex;
    }
    nuvo_lun_state_init(&nvs_p->ptvol.lun, nvs_p, NUVO_LUN_STATE_VALID, NUVO_LUN_EXPORT_UNEXPORTED);
    nvs_p->ptvol.lun.size = size;

    return (0);

destroy_mutex:
    nuvo_mutex_destroy(&nvs_p->mutex);
close_file:
    (void)close(nvs_p->ptvol.fd);
    return (ret);
}

nuvo_return_t nuvo_passthrough_close_vol(struct nuvo_vol *nvs_p)
{
    nuvo_mutex_lock(&vol_table.mutex);
    NUVO_ASSERT(nvs_p->type == NUVO_VOL_PASSTHROUGH);
    if (nvs_p->ptvol.lun.export_state != NUVO_LUN_EXPORT_UNEXPORTED)
    {
        nuvo_mutex_unlock(&vol_table.mutex);
        return (-NUVO_E_LUN_EXPORTED);
    }
    close(nvs_p->ptvol.fd);
    nuvo_lun_destroy(&nvs_p->ptvol.lun);

    nvs_p->type = NUVO_VOL_FREE;
    nuvo_mutex_unlock(&vol_table.mutex);
    return (0);
}
