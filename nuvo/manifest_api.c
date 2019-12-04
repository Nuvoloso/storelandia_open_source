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
#include <stdlib.h>

#include <nuvo.pb-c.h>

#include "nuvo.h"
#include "manifest.h"
#include "manifest_priv.h"
#include "nuvo_vol_series.h"

nuvo_return_t nuvo_mfst_get_manifest(struct nuvo_mfst *mfst,
                                     Nuvo__Manifest   *msg,
                                     bool              short_reply)
{
    nuvo_mfst_in_core_lock(mfst);
    // get lock
    msg->devices = calloc(mfst->header.num_used_devices, sizeof(*msg->devices));
    if (msg->devices == NULL)
    {
        goto mem_error;
    }
    msg->n_devices = mfst->header.num_used_devices;
    for (unsigned i = 0; i < mfst->header.num_used_devices; i++)
    {
        msg->devices[i] = malloc(sizeof(*msg->devices[i]));
        if (msg->devices[i] == NULL)
        {
            goto mem_error;
        }
        nuvo__manifest_device__init(msg->devices[i]);
    }
    unsigned i = 0;
    unsigned dev_index = 0;
    while (i < mfst->header.num_used_devices)
    {
        NUVO_ASSERT(dev_index < NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks));
        if (!uuid_is_null(mfst->device_state_media[dev_index].device_uuid))
        {
            msg->devices[i]->device_index = dev_index;
            msg->devices[i]->device_uuid = malloc(UUID_UNPARSED_LEN);
            if (msg->devices[i]->device_uuid == NULL)
            {
                goto mem_error;
            }
            uuid_unparse(mfst->device_state_media[dev_index].device_uuid, msg->devices[i]->device_uuid);
            msg->devices[i]->target_parcels = mfst->device_state_media[dev_index].target_parcels;
            msg->devices[i]->device_class = mfst->device_state_media[dev_index].device_class;
            msg->devices[i]->parcel_size = mfst->device_state_media[dev_index].parcel_size_in_blocks * NUVO_BLOCK_SIZE;
            msg->devices[i]->alloced_parcels = mfst->device_state_media[dev_index].alloced_parcels;
            msg->devices[i]->free_segments = mfst->device_state_mem[dev_index].free_segments;
            msg->devices[i]->blocks_used = 0;
            for (unsigned p = 0; p < mfst->header.num_used_parcels; p++)
            {
                if (mfst->parcel_state_media[p].type != NUVO_MFST_PARCEL_ENTRY_PARCEL ||
                    dev_index != mfst->parcel_state_media[p].normal.device_idx)
                {
                    continue;
                }
                unsigned num_segments = nuvo_mfst_parcel_segment_number_get(mfst, p);
                for (unsigned si = 0; si < num_segments; si++)
                {
                    unsigned seg_idx = mfst->parcel_state_mem[p].segment_offset + si;
                    msg->devices[i]->blocks_used += mfst->segment_state_media[seg_idx].seg_blks_used;
                }
            }
            i++;
        }
        dev_index++;
    }

    if (!short_reply)
    {
        msg->parcels = calloc(mfst->header.num_used_parcels, sizeof(*msg->parcels));
        if (msg->parcels == NULL)
        {
            goto mem_error;
        }
        msg->n_parcels = mfst->header.num_used_parcels;
        for (unsigned i = 0; i < mfst->header.num_used_parcels; i++)
        {
            msg->parcels[i] = malloc(sizeof(*msg->parcels[i]));
            if (msg->parcels[i] == NULL)
            {
                goto mem_error;
            }
            nuvo__manifest_parcel__init(msg->parcels[i]);
        }
        i = 0;
        unsigned parcel_index = 0;
        while (i < mfst->header.num_used_parcels)
        {
            if (mfst->parcel_state_media[i].type == NUVO_MFST_PARCEL_ENTRY_PARCEL)
            {
                msg->parcels[i]->parcel_index = parcel_index;
                msg->parcels[i]->parcel_uuid = malloc(UUID_UNPARSED_LEN);
                if (msg->parcels[i]->parcel_uuid == NULL)
                {
                    goto mem_error;
                }
                uuid_unparse(mfst->parcel_state_media[parcel_index].normal.parcel_uuid, msg->parcels[i]->parcel_uuid);
                msg->parcels[i]->device_index = mfst->parcel_state_media[parcel_index].normal.device_idx;
                msg->parcels[i]->segment_size = nuvo_mfst_parcel_segment_size_get(mfst, parcel_index);
                msg->parcels[i]->n_segments = nuvo_mfst_parcel_segment_number_get(mfst, parcel_index);
                msg->parcels[i]->segments = calloc(msg->parcels[i]->n_segments, sizeof(&msg->parcels[i]->segments[0]));
                if (msg->parcels[i]->segments == NULL)
                {
                    goto mem_error;
                }
                for (unsigned j = 0; j < msg->parcels[i]->n_segments; j++)
                {
                    msg->parcels[i]->segments[j] = malloc(sizeof(*msg->parcels[i]->segments[j]));
                    if (msg->parcels[i]->segments[j] == NULL)
                    {
                        goto mem_error;
                    }
                    nuvo__manifest_segment__init(msg->parcels[i]->segments[j]);
                    unsigned seg_idx = mfst->parcel_state_mem[parcel_index].segment_offset + j;
                    msg->parcels[i]->segments[j]->blks_used = mfst->segment_state_media[seg_idx].seg_blks_used;
                    msg->parcels[i]->segments[j]->age = mfst->segment_state_media[seg_idx].seg_age;
                    msg->parcels[i]->segments[j]->reserved = (mfst->segment_state_media[seg_idx].seg_reserved == 1);
                    msg->parcels[i]->segments[j]->logger = (mfst->segment_state_mem[seg_idx].seg_space_used == 1);
                    msg->parcels[i]->segments[j]->pin_cnt = mfst->segment_state_mem[seg_idx].seg_io;
                }
                switch (mfst->parcel_state_mem[i].state)
                {
                case NUVO_MFST_PARCEL_NONE:
                    msg->parcels[i]->state = NUVO__MANIFEST_PARCEL__STATE__UNUSED;
                    break;

                case NUVO_MFST_PARCEL_ADDING:
                    msg->parcels[i]->state = NUVO__MANIFEST_PARCEL__STATE__ADDING;
                    break;

                case NUVO_MFST_PARCEL_USABLE:
                    msg->parcels[i]->state = NUVO__MANIFEST_PARCEL__STATE__USABLE;
                    break;

                case NUVO_MFST_PARCEL_OPENING:
                    msg->parcels[i]->state = NUVO__MANIFEST_PARCEL__STATE__OPENING;
                    break;

                case NUVO_MFST_PARCEL_OPEN:
                    msg->parcels[i]->state = NUVO__MANIFEST_PARCEL__STATE__OPEN;
                    break;
                }
                i++;
            }
            parcel_index++;
        }
    }
    nuvo_mfst_in_core_unlock(mfst);
    return (0);

mem_error:
    nuvo_mfst_in_core_unlock(mfst);
    return (-NUVO_ENOMEM);
}

nuvo_return_t nuvo_mfst_get_vol_status(struct nuvo_mfst *mfst, Nuvo__VolStatus *status)
{
    nuvo_mfst_in_core_lock(mfst);
    uint32_t num_devices = NUVO_MFST_BLKS_TO_DEVICES(mfst->header.num_device_blocks);
    uint32_t num_classes = 0;
    for (unsigned index = 0; index < num_devices; index++)
    {
        if (mfst->device_state_media[index].device_class >= num_classes)
        {
            num_classes = mfst->device_state_media[index].device_class + 1;
        }
    }
    status->n_data_class_space = num_classes;
    status->data_class_space = calloc(num_classes, sizeof(*status->data_class_space));
    if (status->data_class_space == NULL)
    {
        goto mem_error;
    }
    for (unsigned class = 0; class < num_classes; class++)
    {
        status->data_class_space[class] = malloc(sizeof(*status->data_class_space[class]));
        if (status->data_class_space[class] == NULL)
        {
            goto mem_error;
        }
        nuvo__data_class_space__init(status->data_class_space[class]);
        status->data_class_space[class]->has_class_ = true;
        status->data_class_space[class]->class_ = class;
        status->data_class_space[class]->has_blocks_used = true;
        status->data_class_space[class]->blocks_used = mfst->data_class[class].used_blocks;
        status->data_class_space[class]->has_blocks_allocated = true;
        status->data_class_space[class]->blocks_allocated = mfst->data_class[class].total_mfst_blocks;
        status->data_class_space[class]->has_blocks_total = true;
        status->data_class_space[class]->blocks_total = mfst->data_class[class].total_parcel_blocks;
    }

    nuvo_mfst_in_core_unlock(mfst);
    return (0);

mem_error:
    nuvo_mfst_in_core_unlock(mfst);
    // Don't need to free memory we allocated since the freeing of the message will handle that.
    return (-NUVO_ENOMEM);
}
