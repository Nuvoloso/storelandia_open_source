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
 * \file nuvo_api.c
 * \brief Contains that API socket and socket handling functions.
 *
 * We expose a Unix domain socket which receives commands and respoinds to them.
 * the format of every messge is a packed protobuf message preceded by a uint32
 * indicating the size of the packed protobuf.
 *
 * There is a single handler thread that listens for API requests.
 */
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <version_nuvo.h>

#include <nuvo.pb-c.h>

#include "log_volume.h"
#include "nuvo.h"
#include "nuvo_api.h"
#include "nuvo_api_test.h"
#include "nuvo_exit.h"
#include "nuvo_fuse.h"
#include "nuvo_lock.h"
#include "nuvo_vol_series.h"
#include "parcel_manager.h"
#include "nuvo_pr.h"
#include "passthrough_vol.h"
#include "parcel_vol.h"
#include "cache.h"
#include "space.h"
#include "map.h"
#include "fault_inject.h"
#include "device_type.h"

/**
 * \def NUVO_API_SOCK_BACKLOG
 * \brief How big of a backlog to allow of pending API socket connections requests.
 */
#define NUVO_API_SOCK_BACKLOG    20

/**
 * The single API request queue for non volume-specific commands.
 * */
struct nuvo_api_queue nonvol_queue;

/**
 * \brief Current number of per-volume worker threads.
 */
struct nuvo_num_worker num_workers;

/**
 * \fn int read_bytes(int data_socket, uint8_t *data, uint32_t bytes_to_read)
 * \brief reads data from a socket, looping to hand EINTR, etc.
 * \param data_socket The descriptor of the socket from which to read.
 * \param data Where to put the data.
 * \param bytes_to_read The number of bytes to read.
 * \return bytes read or -errno.
 */
static int read_bytes(int data_socket, uint8_t *data, uint32_t bytes_to_read)
{
    uint32_t bytes_read = 0;

    while (bytes_read < bytes_to_read)
    {
        int ret = read(data_socket, data + bytes_read, bytes_to_read - bytes_read);
        if (ret == -1)
        {
            if (EINTR == errno)
            {
                continue;
            }
            return (-errno);
        }
        bytes_read += ret;
    }
    return (bytes_to_read);
}

/**
 * \fn int recv_command(int data_socket, uint8_t **cmd)
 * \brief receive a command from a socket.
 *
 * This reads a (packet) command from the socket and returns the packed
 * bytes in a malloced buffer. It is the callers responsibility to free the buffer.
 *
 * \param data_socket The file descriptor of the socket to read from.
 * \param cmd return a pointer to the malloced buffer holding the data.
 * \returns the number of bytes in the buffer or -errno.
 */
static int recv_command(int data_socket, uint8_t **cmd)
{
    uint32_t pbuf_size;
    int      ret;

    *cmd = NULL;
    ret = read_bytes(data_socket, (uint8_t *)&pbuf_size, sizeof(pbuf_size));
    if (ret < 0)
    {
        return (ret);
    }
    uint8_t *c = malloc(pbuf_size);
    if (c == NULL)
    {
        // Ugh - how to deal with this.
        return (-errno);
    }

    ret = read_bytes(data_socket, c, pbuf_size);
    if (ret < 0)
    {
        free(c);
        return (-errno);
    }
    *cmd = c;
    return (pbuf_size);
}

/**
 * \fn int write_bytes(int data_socket, uint8_t *data, uint32_t bytes_to_write)
 * \brief writes data to a socket, looping to hand EINTR, etc.
 * \param data_socket The descriptor of the socket to which to write.
 * \param data The actual data to write.
 * \param bytes_to_write The number of bytes to write.
 * \return bytes written or -errno.
 */
static int write_bytes(int data_socket, uint8_t *data, uint32_t bytes_to_write)
{
    uint32_t bytes_written = 0;

    while (bytes_written < bytes_to_write)
    {
        int ret = write(data_socket, data + bytes_written, bytes_to_write - bytes_written);
        if (ret == -1)
        {
            if (EINTR == errno)
            {
                continue;
            }
            return (-errno);
        }
        bytes_written += ret;
    }
    return (bytes_written);
}

/**
 * \fn void send_reply(int cmd_socket, Nuvo__Cmd *reply)
 * \brief Pack a reply and send it over a socket.
 *
 * This takes a reply, packs it and sends it over the socket.
 * We're about to close the socket, so there is nothing to do with errors
 * above, so we eat them here.  Mmmm.  Errors.  Mmmmmm.
 *
 * \param cmd_socket The descriptor to send the data over.
 * \param reply The protobuf to pack and send.
 */
static void send_reply(int cmd_socket, Nuvo__Cmd *reply)
{
    uint32_t reply_size = nuvo__cmd__get_packed_size(reply);
    uint32_t rep_length = sizeof(reply_size) + reply_size;
    uint8_t *reply_buf = malloc(rep_length);

    if (reply_buf)
    {
        memcpy(reply_buf, &reply_size, sizeof(reply_size));
        nuvo__cmd__pack(reply, reply_buf + sizeof(reply_size));
        (void)write_bytes(cmd_socket, reply_buf, rep_length);
        free(reply_buf);
    }
}

/**
 * \fn Nuvo__Cmd* nuvo_api_use_device(Nuvo__Cmd *req, use_device_work_t do_work)
 * \brief Handle a USE_DEVICE command request.
 *
 * This converts the incoming NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REQ
 * into NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY and then processes
 * each request in the array. It provides per request results and
 * in the event of failure, an error message. The exception is if the
 * request is simply malformed, we only return NUVO__USE_DEVICE__RESULT__INVALID.
 *
 * \param req The request.
 * \param do_work The internal handler function to use. Good for testing.
 * \returns The request that was sent in, converted to a reply.
 */
Nuvo__Cmd *nuvo_api_use_device(struct nuvo_api_req    *api_req,
                               use_device_work_t       do_device_work,
                               use_device_cache_work_t do_cache_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: use device - Started");

    for (unsigned int i = 0; i < req->n_use_device; i++)
    {
        Nuvo__UseDevice *use_dev = req->use_device[i];
        if (use_dev->explanation != NULL || use_dev->has_result)
        {
            use_dev->has_result = 1;
            use_dev->result = NUVO__USE_DEVICE__RESULT__INVALID;
            continue;
        }
        else if (use_dev->dev_type >= (int)NUVO_MAX_DEV_TYPES)
        {
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: use device: %s uuid: %s type: Invalid (%d)", use_dev->path, use_dev->uuid, use_dev->dev_type);
            use_dev->has_result = 1;
            use_dev->result = NUVO__USE_DEVICE__RESULT__INVALID;
            use_dev->explanation = strdup("Device type invalid");
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: Invalid (%d) - Failed, error %d %s",
                             use_dev->path, use_dev->uuid, use_dev->dev_type, NUVO_E_DEVICE_TYPE_BAD, use_dev->explanation);
            continue;
        }
        else
        {
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: use device: %s uuid: %s type: %s", use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type]);
        }

        uuid_t dev_uuid;
        int    r = uuid_parse(use_dev->uuid, dev_uuid);
        if (r != 0)
        {
            use_dev->has_result = 1;
            use_dev->result = NUVO__USE_DEVICE__RESULT__INVALID;
            use_dev->explanation = strdup("UUID invalid");
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, error %d %s",
                             use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], NUVO_EINVAL, use_dev->explanation);
            continue;
        }
        uint8_t dev_type = NUVO_DEV_TYPE_SSD;       // Default to SSD for now
        if (use_dev->dev_type)
        {
            switch (use_dev->dev_type)
            {
            case NUVO__USE_DEVICE__DEV_TYPE__SSD:
                dev_type = NUVO_DEV_TYPE_SSD;
                break;

            case NUVO__USE_DEVICE__DEV_TYPE__HDD:
                dev_type = NUVO_DEV_TYPE_HDD;
                break;

            case NUVO__USE_DEVICE__DEV_TYPE__EPH:
                dev_type = NUVO_DEV_TYPE_EPH;
                break;

            default:
                use_dev->has_result = 1;
                use_dev->result = NUVO__USE_DEVICE__RESULT__INVALID;
                use_dev->explanation = strdup("Device type invalid");
                NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, error %d %s",
                                 use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], NUVO_E_DEVICE_TYPE_BAD, use_dev->explanation);
                continue;
            }
        }

        uint64_t      size = 0;
        uint64_t      alloc_size = 0;
        nuvo_return_t ret_val = (dev_type == NUVO_DEV_TYPE_EPH) ?
                                do_cache_work(use_dev->path, dev_uuid, &size, &alloc_size) :
                                do_device_work(use_dev->path, dev_uuid, dev_type);
        use_dev->has_result = 1;
        switch (ret_val)
        {
        case 0:
        case -NUVO_E_DEVICE_ALREADY_OPEN:
            if (dev_type == NUVO_DEV_TYPE_EPH)
            {
                NUVO_LOG(api, NUVO_LL_API, "Nuvo api: use device: %s uuid: %s type: %s. size: %lu allocation size: %lu - Succeeded",
                         use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], size, alloc_size);
                use_dev->has_size = 1;
                use_dev->size = size;
                use_dev->has_alloc_size = 1;
                use_dev->alloc_size = alloc_size;
            }
            else
            {
                NUVO_LOG(api, NUVO_LL_API, "Nuvo api: use device: %s uuid: %s type: %s - Succeeded", use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type]);
            }
            use_dev->result = NUVO__USE_DEVICE__RESULT__OK;
            break;

        case -NUVO_E_DEVICE_NOT_USABLE:
            use_dev->result = NUVO__USE_DEVICE__RESULT__DEVICE_NOT_USABLE;
            use_dev->explanation = strdup("Unable to use additional cache device");
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, error %d %s",
                             use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], -ret_val, use_dev->explanation);
            break;

        case -NUVO_ENOENT:
            use_dev->result = NUVO__USE_DEVICE__RESULT__DEVICE_NOT_FOUND;
            use_dev->explanation = strdup("Cannot find device");
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, error %d %s",
                             use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], -ret_val, use_dev->explanation);
            break;

        case -NUVO_EEXIST:
            use_dev->result = NUVO__USE_DEVICE__RESULT__UUID_MISMATCH;
            use_dev->explanation = strdup("Wrong uuid");
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, error %d %s",
                             use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], -ret_val, use_dev->explanation);
            break;

        case -NUVO_ENOMEM:
            use_dev->result = NUVO__USE_DEVICE__RESULT__NO_MEM;
            use_dev->explanation = strdup("Device table full");
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, error %d %s",
                             use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], -ret_val, use_dev->explanation);
            break;

        default:
            use_dev->result = NUVO__USE_DEVICE__RESULT__ERROR;
            use_dev->explanation = nuvo_status_alloc_error_str(-ret_val);
            NUVO_ERROR_PRINT("Nuvo api: use device: %s uuid: %s type: %s - Failed, unknown error %d %s",
                             use_dev->path, use_dev->uuid, nuvo_dev_type_str[use_dev->dev_type], -ret_val, use_dev->explanation);
            break;
        }
    }
    return (req);
}

/**
 * \fn Nuvo__Cmd *nuvo_api_close_device(Nuvo__Cmd *req, close_device_work_t do_work)
 * \brief Handle a CLOSE_DEVICE command request.
 *
 * This converts the incoming NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REQ
 * into NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REPLY and then processes
 * each request in the array. It provides per request results and
 * in the event of failure, an error message. The exception is if the
 * request is simply malformed, we only return NUVO__FORMAT_DEVICE__RESULT__INVALID.
 *
 * \param req The request.
 * \param do_work The internal handler function to use. Good for testing.
 * \returns The request that was sent in, converted to a reply.
 */
Nuvo__Cmd *nuvo_api_close_device(struct nuvo_api_req *api_req, close_device_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: close device - Started");

    for (unsigned int i = 0; i < req->n_close_device; i++)
    {
        Nuvo__CloseDevice *close_dev = req->close_device[i];
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: close device: %s", close_dev->uuid);

        if (close_dev->explanation != NULL || close_dev->has_result)
        {
            close_dev->has_result = 1;
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__INVALID;
            continue;
        }
        uuid_t dev_uuid;
        int    r = uuid_parse(close_dev->uuid, dev_uuid);
        if (r != 0)
        {
            close_dev->has_result = 1;
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__INVALID;
            close_dev->explanation = strdup("UUID invalid");
            NUVO_ERROR_PRINT("Nuvo api: close device: %s - Failed, error %d %s",
                             close_dev->uuid, NUVO_EINVAL, close_dev->explanation);
            continue;
        }
        nuvo_return_t ret_val = do_work(dev_uuid);
        close_dev->has_result = 1;
        switch (ret_val)
        {
        case 0:
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: close device: %s - Succeeded",
                     close_dev->uuid);
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__OK;
            break;

        case -NUVO_E_DEVICE_IN_USE:
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__DEVICE_IN_USE;
            close_dev->explanation = strdup("Device has parcels in use");
            NUVO_ERROR_PRINT("Nuvo api: close device: %s - Failed, error %d device has parcels in use", close_dev->uuid, -ret_val);
            break;

        case -NUVO_ENODEV:
        case -NUVO_ENOENT:
            NUVO_ERROR_PRINT("Nuvo api: close device: %s - Failed, error %d device not found", close_dev->uuid, -ret_val);
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__DEVICE_NOT_FOUND;
            close_dev->explanation = strdup("Cannot find device");
            break;

        default:
            NUVO_ERROR_PRINT("Nuvo api: close device: %s - Failed, error %d unknown error: %d", close_dev->uuid, -ret_val);
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__ERROR;
            close_dev->explanation = nuvo_status_alloc_error_str(-ret_val);
            break;
        }
    }
    return (req);
}

/**
 * \fn Nuvo__Cmd* nuvo_api_format_device(Nuvo__Cmd *req, format_device_work_t do_work)
 * \brief Handle a FORMAT_DEVICE command request.
 *
 * This converts the incoming NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REQ
 * into NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY and then processes
 * each request in the array. It provides per request results and
 * in the event of failure, an error message. The exception is if the
 * request is simply malformed, we only return NUVO__FORMAT_DEVICE__RESULT__INVALID.
 *
 * \param req The request.
 * \param do_work The internal handler function to use. Good for testing.
 * \returns The request that was sent in, converted to a reply.
 */
Nuvo__Cmd *nuvo_api_format_device(struct nuvo_api_req *api_req, format_device_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: format device - Started");

    for (unsigned int i = 0; i < req->n_format_device; i++)
    {
        Nuvo__FormatDevice *format_dev = req->format_device[i];
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: format device: %s uuid: %s parcel size: %d", format_dev->path, format_dev->uuid, format_dev->parcel_size);

        if (format_dev->explanation != NULL || format_dev->has_result)
        {
            format_dev->has_result = 1;
            format_dev->result = NUVO__FORMAT_DEVICE__RESULT__INVALID;
            continue;
        }
        uuid_t dev_uuid;
        int    r = uuid_parse(format_dev->uuid, dev_uuid);
        if (r != 0)
        {
            format_dev->has_result = 1;
            format_dev->result = NUVO__FORMAT_DEVICE__RESULT__INVALID;
            format_dev->explanation = strdup("UUID invalid");
            NUVO_ERROR_PRINT("Nuvo api: format device: %s uuid: %s parcel size: %d - Failed, error %d %s",
                             format_dev->path, format_dev->uuid, format_dev->parcel_size, NUVO_EINVAL, format_dev->explanation);
            continue;
        }
        nuvo_return_t ret_val = do_work(format_dev->path, dev_uuid, format_dev->parcel_size);
        format_dev->has_result = 1;
        switch (ret_val)
        {
        case 0:
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: format device: %s uuid: %s parcel size: %d - Succeeded",
                     format_dev->path, format_dev->uuid, format_dev->parcel_size);
            format_dev->result = NUVO__FORMAT_DEVICE__RESULT__OK;
            break;

        case -NUVO_ENOENT:
            format_dev->result = NUVO__FORMAT_DEVICE__RESULT__DEVICE_NOT_FOUND;
            format_dev->explanation = strdup("Cannot find device");
            NUVO_ERROR_PRINT("Nuvo api: format device: %s uuid: %s parcel size: %d - Failed, error %d %s",
                             format_dev->path, format_dev->uuid, format_dev->parcel_size, -ret_val, format_dev->explanation);
            break;

        default:
            format_dev->result = NUVO__FORMAT_DEVICE__RESULT__ERROR;
            format_dev->explanation = nuvo_status_alloc_error_str(-ret_val);
            NUVO_ERROR_PRINT("Nuvo api: format device: %s uuid: %s parcel size: %d - Failed, unknown error %d %s",
                             format_dev->path, format_dev->uuid, format_dev->parcel_size, -ret_val, format_dev->explanation);
            break;
        }
    }
    return (req);
}

/**
 * \ brief Add a device node location, or update the location.
 */
nuvo_return_t device_insert_or_update(const uuid_t dev_id, const uuid_t node_id)
{
    nuvo_return_t rc = nuvo_pr_device_insert(dev_id, node_id);

    if (rc == -NUVO_EEXIST)
    {
        rc = nuvo_pr_device_update(dev_id, node_id);
    }
    return (rc);
}

/**
 * \brief Closes a device. No parcels should be in use on the device, and
 * after the device is closed, no new parcels will be used from the device.
 *
 * \param device_path The device to open.
 * \param device_uuid The uuid of the device.
 * \return 0 on success, otherwise -errno.
 */
nuvo_return_t close_device_work(const uuid_t device_uuid)
{
    nuvo_return_t ret = 0;

    if (nuvo_pr_is_device_remote(device_uuid))
    {
        NUVO_ERROR_PRINT("Close device: " NUVO_LOG_UUID_FMT " failed.  Device located on remote node", NUVO_LOG_UUID(device_uuid));
        return (-NUVO_ENODEV);
    }

    if (nuvo_pm_is_device_in_use(device_uuid))
    {
        NUVO_ERROR_PRINT("Close device: " NUVO_LOG_UUID_FMT " issued on device with open parcels", NUVO_LOG_UUID(device_uuid));
        return (-NUVO_E_DEVICE_IN_USE);
    }

    ret = nuvo_pr_device_remove(device_uuid);
    if (ret != 0)
    {
        // It is possible that kontroller did not issue a device location call
        // before device close.  In this case the parcel router won't find the
        // device but the parcel manager can still need to close the device.
        NUVO_ERROR_PRINT("Close device: " NUVO_LOG_UUID_FMT " issued on device unknown to parcel router, error %d", NUVO_LOG_UUID(device_uuid), ret);
    }

    ret = nuvo_pm_device_close(device_uuid);
    if (ret != 0)
    {
        NUVO_ERROR_PRINT("Close device: " NUVO_LOG_UUID_FMT " failed with error %d", NUVO_LOG_UUID(device_uuid), ret);
        return (ret);
    }

    return (ret);
}

/**
 * \brief Handle a DEVICE_LOCATION command request.
 *
 * This converts the incoming NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REQ
 * into NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY and then processes
 * each request in the array. It provides per request results and
 * in the event of failure, an error message. The exception is if the
 * request is simply malformed, we only return NUVO__DEVICE_LOCATION__RESULT__INVALID.
 *
 * \param req The request.
 * \param do_work The internal handler function to use. Good for testing.
 * \returns The request that was sent in, converted to a reply.
 */
Nuvo__Cmd *nuvo_api_device_location(struct nuvo_api_req *api_req, device_location_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: device location - Started");
    for (unsigned int i = 0; i < req->n_device_location; i++)
    {
        Nuvo__DeviceLocation *dev_loc = req->device_location[i];
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: device location: device %s, node %s",
                 dev_loc->device, dev_loc->node);
    }

    for (unsigned int i = 0; i < req->n_device_location; i++)
    {
        Nuvo__DeviceLocation *dev_loc = req->device_location[i];
        if (dev_loc->explanation != NULL || dev_loc->has_result)
        {
            dev_loc->has_result = 1;
            dev_loc->result = NUVO__DEVICE_LOCATION__RESULT__INVALID;
            continue;
        }
        uuid_t dev_uuid, node_uuid;
        int    r = uuid_parse(dev_loc->device, dev_uuid);
        int    r2 = uuid_parse(dev_loc->node, node_uuid);
        if (r != 0 || r2 != 0)
        {
            dev_loc->has_result = 1;
            dev_loc->result = NUVO__DEVICE_LOCATION__RESULT__INVALID;
            dev_loc->explanation = strdup("UUID invalid");
            continue;
        }

        nuvo_return_t ret_val = do_work(dev_uuid, node_uuid);
        dev_loc->has_result = 1;
        switch (ret_val)
        {
        case 0:
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: device location: device %s, node %s - Succeeded",
                     dev_loc->device, dev_loc->node);
            dev_loc->result = NUVO__DEVICE_LOCATION__RESULT__OK;
            break;

        case -NUVO_ENOMEM:
            NUVO_ERROR_PRINT("Nuvo api: device location: device %s, node %s - Failed, error %d table full",
                             dev_loc->device, dev_loc->node, -ret_val);
            dev_loc->result = NUVO__DEVICE_LOCATION__RESULT__NO_MEM;
            dev_loc->explanation = strdup("Table full");
            break;

        default:
            NUVO_ERROR_PRINT("Nuvo api: device location: device %s, node %s - Failed, error %d ",
                             dev_loc->device, dev_loc->node, -ret_val);
            dev_loc->result = NUVO__DEVICE_LOCATION__RESULT__ERROR;
            dev_loc->explanation = nuvo_status_alloc_error_str(-ret_val);
            break;
        }
    }
    return (req);
}

/**
 * \fn int node_location_work(const uuid_t uuid, const char *ip_addr, uint16_t port)
 * \brief Actual handler for setting node location.
 * \param uuid The node uuid.
 * \param ip_addr String containing the ip address or netowrk name.
 * \param port The port number.
 *
 * This is the routine that should call the actual code to do what is necessary
 * to record where a node is.  deja vu.
 *
 * \returns 0 on success or an errno
 * \retval 0 Success. For some value of success.
 * \retval -NUVO_EINVAL Address length was larger than NUVO_MAX_ADDR_LEN.
 * \retval -NUVO_EEXIST Node with this UUID already exists.
 * \retval -NUVO_ENOMEM Failed to allocate a local node structure.
 */
nuvo_return_t node_location_work(const uuid_t uuid, const char *ip_addr, uint16_t port)
{
    return (nuvo_pr_node_insert(uuid, ip_addr, port));
}

/**
 * \fn Nuvo__Cmd* nuvo_api_node_location(Nuvo__Cmd* req, node_location_work_t do_work)
 * \brief Handle a NODE_LOCATION command request.
 *
 * Have you ever considered using macros to generate doxygen comments for similar
 * functions? I have. This converts the incoming NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REQ
 * into NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY and then processes
 * each request in the array. It provides per request results and
 * in the event of failure, an error message. The exception is if the
 * request is simply malformed, we only return NUVO__NODE_LOCATION__RESULT__INVALID.
 *
 * \param req The request.
 * \param do_work The internal handler function to use. Good for testing.
 * \returns The request that was sent in, converted to a reply.
 */
Nuvo__Cmd *nuvo_api_node_location(struct nuvo_api_req *api_req, node_location_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: node location - Started");
    for (unsigned int i = 0; i < req->n_node_location; i++)
    {
        Nuvo__NodeLocation *node_loc = req->node_location[i];
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: node location: node %s, ip_addr %s, port %d",
                 node_loc->uuid, node_loc->ipv4_addr, node_loc->port);
    }

    for (unsigned int i = 0; i < req->n_node_location; i++)
    {
        Nuvo__NodeLocation *node_loc = req->node_location[i];
        if (node_loc->explanation != NULL || node_loc->has_result ||
            node_loc->port > UINT16_MAX)
        {
            node_loc->has_result = 1;
            node_loc->result = NUVO__NODE_LOCATION__RESULT__INVALID;
            continue;
        }
        uuid_t uuid;
        int    r = uuid_parse(node_loc->uuid, uuid);
        if (r != 0)
        {
            node_loc->has_result = 1;
            node_loc->result = NUVO__NODE_LOCATION__RESULT__INVALID;
            node_loc->explanation = strdup("UUID invalid");
            continue;
        }
        nuvo_return_t ret_val = do_work(uuid, node_loc->ipv4_addr, node_loc->port);
        node_loc->has_result = 1;
        switch (ret_val)
        {
        case 0:
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: node location: node %s, ip_addr %s, port %d - Succeeded",
                     node_loc->uuid, node_loc->ipv4_addr, node_loc->port);
            node_loc->result = NUVO__NODE_LOCATION__RESULT__OK;
            break;

        case -NUVO_ENOMEM:
            NUVO_ERROR_PRINT("Nuvo api: node location: node %s, ip_addr %s, port %d - Failed, error %d table full",
                             node_loc->uuid, node_loc->ipv4_addr,
                             node_loc->port, -ret_val);
            node_loc->result = NUVO__NODE_LOCATION__RESULT__NO_MEM;
            node_loc->explanation = strdup("Table full");
            break;

        default:
            NUVO_ERROR_PRINT("Nuvo api: node location: node %s, ip_addr %s, port %d - Failed, error %d",
                             node_loc->uuid, node_loc->ipv4_addr,
                             node_loc->port, -ret_val);
            node_loc->result = NUVO__NODE_LOCATION__RESULT__ERROR;
            node_loc->explanation = nuvo_status_alloc_error_str(-ret_val);
            break;
        }
    }
    return (req);
}

/**
 * \fn nuvo_return_t node_init_done_work(const uuid_t uuid)
 * \brief Handler for informing the pr that node initialization is done.
 * \param uuid The node uuid.
 * \param clear For testing, used to clear the node_init_done flag.
 *
 * This routine is called once the kontroller is finished with the initial
 * node configuration.  It will set the flag that allows the pr server
 * thread to start.
 *
 * \retval 0 Success.
 * \retval -NUVO_ENOENT Node UUID not found.
 */
nuvo_return_t node_init_done_work(const uuid_t node_uuid, bool clear)
{
    return (nuvo_pr_node_init_done(node_uuid, clear));
}

/**
 * \fn Nuvo__Cmd *nuvo_api_node_init_done(Nuvo__Cmd *req, node_init_done_work_t do_work)
 * \brief Handle a NODE_INIT_DONE command request.
 *
 * \param req The request.
 * \param do_work The internal handler function to use. Good for testing.
 * \returns The request that was sent in, converted to a reply.
 */
Nuvo__Cmd *nuvo_api_node_init_done(struct nuvo_api_req  *api_req,
                                   node_init_done_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REPLY;
    Nuvo__NodeInitDone *msg = req->node_init_done;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: node init done - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: node init done: node %s, clear %d",
                 msg->uuid, msg->clear);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__NODE_INIT_DONE__RESULT__INVALID;
        return (req);
    }

    uuid_t node_uuid;
    if (strlen(msg->uuid) > 0)
    {
        int r = uuid_parse(msg->uuid, node_uuid);
        if (r != 0)
        {
            msg->has_result = 1;
            msg->result = NUVO__NODE_INIT_DONE__RESULT__INVALID;
            msg->explanation = strdup("UUID invalid");
            return (req);
        }
    }
    else
    {
        uuid_clear(node_uuid);
    }

    bool          clear = (msg->clear != 0) ? true : false;
    nuvo_return_t ret_val = do_work(node_uuid, clear);
    msg->has_result = 1;

    switch (ret_val)
    {
    case 0:
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: node init done: node %s - Succeeded",
                 msg->uuid);
        msg->result = NUVO__NODE_INIT_DONE__RESULT__OK;
        break;

    case -NUVO_ENOENT:
        NUVO_ERROR_PRINT("Nuvo api: node init done: node %s - Failed, Specified node not found, error %d",
                         msg->uuid, -ret_val);
        msg->result = NUVO__NODE_INIT_DONE__RESULT__NODE_NOT_FOUND;
        msg->explanation = strdup("Node not found");
        break;

    default:
        NUVO_ERROR_PRINT("Nuvo api: node init done: node %s - Failed, error %d",
                         msg->uuid, -ret_val);
        msg->result = NUVO__NODE_INIT_DONE__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
        break;
    }

    return (req);
}

/**
 * \fn Nuvo__Cmd* passthrough_volume(Nuvo__Cmd* req, passthrough_vol_work_t do_work)
 * \brief Handler to start passthrough volume.
 *
 * This calls the volume manager code to start using a volume as a passthrough device.
 *
 * \param req The command to start the volume.
 * \param do_work The routine to do the work.  Or do the test. It's your nickel.
 * \returns The request transformed into a reply.
 */
Nuvo__Cmd *nuvo_api_passthrough_open_volume(struct nuvo_api_req *api_req, passthrough_open_vol_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REPLY;
    Nuvo__OpenPassThroughVolume *msg = req->open_pass_through_vol;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: passthrough open - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: passthrough open: %s path %s, size %" PRIu64,
                 msg->uuid, msg->path, msg->size);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__INVALID;
        return (req);
    }

    nuvo_return_t ret_val = do_work(api_req->vol, msg->path, msg->size);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: passthrough open: %s path %s, size %" PRIu64 " - Succeeded",
                 msg->uuid, msg->path, msg->size);
        msg->has_result = 1;
        msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: passthrough open: %s path %s, size %" PRIu64 " - Failed error: %d",
                         msg->uuid, msg->path, msg->size, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t export_lun_work(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name, int writable)
{
    return (nuvo_export_lun(vol, pit_uuid, lun_name, writable));
}

/**
 * \fn Nuvo__Cmd* nuvo_api_export_lun(Nuvo__Cmd* req, export_lun_work_t do_work)
 * \brief Handler to export a LUN from a volume series.
 *
 * This does rough validation of the parameters in the message (you have the fields
 * you should have, not the ones you should not, uuid decodes to a uuid) and then
 * calls the passed in work handler to actually do the export.  The handler routine
 * does validation of it's own and returns errors (already exported, name used, etc.)
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_export_lun(struct nuvo_api_req *api_req, export_lun_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REPLY;
    Nuvo__ExportLun *msg = req->export_lun;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: export lun - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: export lun: vol %s, pit %s, name %s",
                 msg->vol_series_uuid, msg->pit_uuid, msg->export_name);
    }
    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__EXPORT_LUN__RESULT__INVALID;
        return (req);
    }
    uuid_t vs_uuid;
    int    r = uuid_parse(msg->vol_series_uuid, vs_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__EXPORT_LUN__RESULT__BAD_UUID;
        msg->explanation = strdup("Vol Series UUID invalid");
        return (req);
    }

    uuid_t pit_uuid;
    if (msg->pit_uuid != NULL)
    {
        r = uuid_parse(msg->pit_uuid, pit_uuid);
        if (r != 0)
        {
            msg->has_result = 1;
            msg->result = NUVO__EXPORT_LUN__RESULT__BAD_UUID;
            msg->explanation = strdup("PiT UUID invalid");
            return (req);
        }
    }
    else
    {
        uuid_clear(pit_uuid);
    }
    nuvo_return_t ret_val = do_work(api_req->vol, pit_uuid, msg->export_name, msg->writable);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: export lun: vol %s, pit %s, name %s - Succeeded",
                 msg->vol_series_uuid, msg->pit_uuid, msg->export_name);
        msg->has_result = 1;
        msg->result = NUVO__EXPORT_LUN__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: export lun: vol %s, pit %s, name %s - Failed error: %d",
                         msg->vol_series_uuid, msg->pit_uuid, msg->export_name, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__EXPORT_LUN__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t unexport_lun_work(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name)
{
    return (nuvo_unexport_lun(vol, pit_uuid, lun_name));
}

/**
 * \fn Nuvo__Cmd* nuvo_api_unexport_lun(Nuvo__Cmd* req, unexport_lun_work_t do_work)
 * \brief Handler to unexport an exported LUN
 *
 * This does rough validation of the parameters in the message (you have the fields
 * you should have, not the ones you should not, uuid decodes to a uuid) and then
 * calls the passed in work handler to actually do the unexport.  The handler routine
 * does validation of it's own and returns errors.
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_unexport_lun(struct nuvo_api_req *api_req, unexport_lun_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REPLY;
    Nuvo__UnexportLun *msg = req->unexport_lun;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: unexport lun - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: unexport lun: vol %s, pit %s, name %s",
                 msg->vol_series_uuid, msg->pit_uuid, msg->export_name);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__UNEXPORT_LUN__RESULT__INVALID;
        return (req);
    }
    uuid_t vs_uuid;
    int    r = uuid_parse(msg->vol_series_uuid, vs_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__UNEXPORT_LUN__RESULT__BAD_UUID;
        msg->explanation = strdup("Vol Series UUID invalid");
        return (req);
    }

    uuid_t pit_uuid;
    if (msg->pit_uuid != NULL)
    {
        int r = uuid_parse(msg->pit_uuid, pit_uuid);
        if (r != 0)
        {
            msg->has_result = 1;
            msg->result = NUVO__UNEXPORT_LUN__RESULT__BAD_UUID;
            msg->explanation = strdup("PiT UUID invalid");
            return (req);
        }
    }
    else
    {
        uuid_clear(pit_uuid);
    }

    nuvo_return_t ret_val = do_work(api_req->vol, pit_uuid, msg->export_name);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: unexport lun: vol %s, pit %s, name %s - Succeeded",
                 msg->vol_series_uuid, msg->pit_uuid, msg->export_name);
        msg->has_result = 1;
        msg->result = NUVO__UNEXPORT_LUN__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: unexport lun: vol %s, pit %s, name %s - Failed error: %d",
                         msg->vol_series_uuid, msg->pit_uuid, msg->export_name, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__UNEXPORT_LUN__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t create_volume_work(struct nuvo_vol *vol, const uuid_t rd_uuid, uuid_t rp_uuid, bool log_vol, uint64_t size)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t rc = nuvo_mutex_init(&sync_signal);

    if (rc != 0)
    {
        return (rc);
    }
    if (log_vol)
    {
        rc = nuvo_log_vol_create_work(vol, rd_uuid, NUVO_DATA_CLASS_A, rp_uuid, size); // TODO get real class
    }
    else
    {
        rc = nuvo_parcel_vol_create_work(vol, rd_uuid, rp_uuid, &sync_signal);
    }
    nuvo_mutex_destroy(&sync_signal);
    return (rc);
}

/**
 * \brief Handler to create a volume
 *
 * This does rough validation of the parameters in the message (you have the fields
 * you should have, not the ones you should not, uuid decodes to a uuid, etc.) and then
 * calls the passed in work handler to actually do the volume creation.  The handler routine
 * does validation of it's own and returns errors.
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_create_volume(struct nuvo_api_req *api_req, create_volume_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY;
    Nuvo__CreateVolume *msg = req->create_volume;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: create volume - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: create volume (%s): uuid %s, root device uuid %s, root parcel uuid %s, size %" PRIu64,
                 msg->log_volume ? "log" : "parcel", msg->vol_series_uuid,
                 msg->root_device_uuid, msg->root_parcel_uuid,
                 msg->has_size ? msg->size : 0);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__INVALID;
        return (req);
    }

    uuid_t rd_uuid;
    int    r = uuid_parse(msg->root_device_uuid, rd_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__BAD_UUID;
        msg->explanation = strdup("Root Device UUID invalid");
        return (req);
    }
    uuid_t rp_uuid;
    r = uuid_parse(msg->root_parcel_uuid, rp_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__BAD_UUID;
        msg->explanation = strdup("Root Parcel UUID invalid");
        return (req);
    }
    if (msg->log_volume && (!msg->has_size || msg->size == 0 || msg->size % NUVO_BLOCK_SIZE != 0))
    {
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__INVALID;
        msg->explanation = strdup("Bad volume size");
        return (req);
    }
    nuvo_return_t ret_val = do_work(api_req->vol, rd_uuid, rp_uuid, msg->log_volume, msg->has_size ? msg->size : 0);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: create volume (%s): uuid %s, root device uuid %s, root parcel uuid %s, size %" PRIu64 " - Succeeded",
                 msg->log_volume ? "log" : "parcel", msg->vol_series_uuid, msg->root_device_uuid, msg->root_parcel_uuid, msg->has_size ? msg->size : 0);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: create volume (%s): uuid %s, root device uuid %s, root parcel uuid %s, size %" PRIu64 " - Failed, error: %d",
                         msg->log_volume ? "log" : "parcel",
                         msg->vol_series_uuid, msg->root_device_uuid,
                         msg->root_parcel_uuid, msg->has_size ? msg->size : 0,
                         -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t open_volume_work(struct nuvo_vol *vol, const uuid_t rd_uuid, const uuid_t rp_uuid, bool log_vol)
{
    nuvo_mutex_t  sync_signal;
    nuvo_return_t rc = nuvo_mutex_init(&sync_signal);

    if (rc != 0)
    {
        return (rc);
    }
    if (log_vol)
    {
        rc = nuvo_log_vol_open_work(vol, rd_uuid, rp_uuid);
    }
    else
    {
        rc = nuvo_parcel_vol_open_work(vol, rd_uuid, rp_uuid, &sync_signal);
    }
    nuvo_mutex_destroy(&sync_signal);
    return (rc);
}

/**
 * \brief Handler to open a volume
 *
 * This does rough validation of the parameters in the message (you have the fields
 * you should have, not the ones you should not, uuid decodes to a uuid, etc.) and then
 * calls the passed in work handler to actually do the volume creation.  The handler routine
 * does validation of it's own and returns errors.
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_open_volume(struct nuvo_api_req *api_req, open_volume_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY;
    Nuvo__OpenVolume *msg = req->open_volume;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: open volume - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: open volume (%s): uuid %s, root device uuid %s, root parcel uuid %s",
                 msg->log_volume ? "log" : "parcel", msg->vol_series_uuid, msg->root_device_uuid, msg->root_parcel_uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__OPEN_VOLUME__RESULT__INVALID;
        return (req);
    }

    uuid_t rd_uuid;
    int    r = uuid_parse(msg->root_device_uuid, rd_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__OPEN_VOLUME__RESULT__BAD_UUID;
        msg->explanation = strdup("Root Device UUID invalid");
        return (req);
    }
    uuid_t rp_uuid;
    r = uuid_parse(msg->root_parcel_uuid, rp_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__OPEN_VOLUME__RESULT__BAD_UUID;
        msg->explanation = strdup("Root Parcel UUID invalid");
        return (req);
    }
    nuvo_return_t ret_val = do_work(api_req->vol, rd_uuid, rp_uuid, msg->log_volume);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: open volume (%s): uuid %s, root device uuid %s, root parcel uuid %s - Succeeded",
                 msg->log_volume ? "log" : "parcel", msg->vol_series_uuid, msg->root_device_uuid, msg->root_parcel_uuid);
        msg->has_result = 1;
        msg->result = NUVO__OPEN_VOLUME__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: open volume (%s): uuid %s, root device uuid %s, root parcel uuid %s - Failed, error: %d",
                         msg->log_volume ? "log" : "parcel",
                         msg->vol_series_uuid, msg->root_device_uuid,
                         msg->root_parcel_uuid, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__OPEN_VOLUME__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t alloc_parcels_work(struct nuvo_vol *nvs_p, const uuid_t dev_uuid, uint64_t num)
{
    if (!nvs_p)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    switch (nvs_p->type)
    {
    case NUVO_VOL_PARCEL:
        return (nuvo_parcel_vol_alloc_parcels(nvs_p, dev_uuid, num));

    case NUVO_VOL_LOG_VOL:
        return (nuvo_log_vol_alloc_parcels(nvs_p, dev_uuid, NUVO_DATA_CLASS_A, num));

    default:
        return (-NUVO_EINVAL);
    }
}

/**
 * \fn Nuvo__Cmd* nuvo_api_alloc_parcels(Nuvo__Cmd* req, alloc_parcels_work_t do_work)
 * \brief Handler to allocate parcels to a volume
 *
 * This does rough validation of the parameters in the message (you have the fields
 * you should have, not the ones you should not, uuid decodes to a uuid, etc.) and then
 * calls the passed in work handler to actually do the volume creation.  The handler routine
 * does validation of it's own and returns errors.
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_alloc_parcels(struct nuvo_api_req *api_req, alloc_parcels_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REPLY;
    Nuvo__AllocParcels *msg = req->alloc_parcels;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: alloc parcels - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: alloc parcels: vol uuid %s, device uuid %s, num parcels %d",
                 msg->vol_series_uuid, msg->device_uuid, msg->num);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_PARCELS__RESULT__INVALID;
        return (req);
    }

    uuid_t dev_uuid;
    int    r = uuid_parse(msg->device_uuid, dev_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_PARCELS__RESULT__BAD_UUID;
        msg->explanation = strdup("Device UUID invalid");
        return (req);
    }
    nuvo_return_t ret_val = do_work(api_req->vol, dev_uuid, msg->num);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: alloc parcels: vol uuid: %s, device uuid: %s, num parcels %d - Succeeded",
                 msg->vol_series_uuid, msg->device_uuid, msg->num);
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_PARCELS__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: alloc parcels: vol uuid: %s, device uuid: %s, num parcels %d - Failed, error: %d",
                         msg->vol_series_uuid, msg->device_uuid, msg->num, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_PARCELS__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t alloc_cache_work(struct nuvo_vol *nvs_p, uint64_t size)
{
    if (!nvs_p)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    switch (nvs_p->type)
    {
    case NUVO_VOL_LOG_VOL:
        return (nuvo_cache_vol_allocate(nvs_p, size));

    default:
        return (-NUVO_EINVAL);
    }
}

/**
 * \brief Handler to allocate cache to a volume
 *
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_alloc_cache(struct nuvo_api_req *api_req, alloc_cache_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REPLY;
    Nuvo__AllocCache *msg = req->alloc_cache;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: allocate cache - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: allocate cache : vol uuid %s, size %lu",
                 msg->vol_series_uuid, msg->size_bytes);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_CACHE__RESULT__INVALID;
        return (req);
    }

    nuvo_return_t ret_val = do_work(api_req->vol, msg->size_bytes);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: allocate cache: vol uuid: %s, size %lu - Succeeded",
                 msg->vol_series_uuid, msg->size_bytes);
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_CACHE__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: allocate cache: vol uuid: %s, size %lu - Failed, error: %d",
                         msg->vol_series_uuid, msg->size_bytes, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__ALLOC_CACHE__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

nuvo_return_t close_vol_work(struct nuvo_vol *vol)
{
    return (nuvo_vol_series_close_vol(vol));
}

/**
 * \brief Handler to close a volume
 *
 * The request contains the uuid of the volume.
 * It should fail if the volume is exported or possibly
 * for other reasons in the future.
 *
 * \param req The protobuf command.
 * \param do_work The handler routine.
 * \returns Response to send back.  Actually req turned into response.
 */
Nuvo__Cmd *nuvo_api_close_vol(struct nuvo_api_req *api_req, close_vol_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REPLY;
    Nuvo__CloseVol *msg = req->close_vol;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: close volume - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: close volume: uuid: %s",
                 msg->vol_series_uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__CLOSE_VOL__RESULT__INVALID;
        return (req);
    }

    int r = do_work(api_req->vol);
    if (r == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: close volume: uuid: %s - Succeeded", msg->vol_series_uuid);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_VOLUME__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: close volume: uuid: %s - Failed error: %d",
                         msg->vol_series_uuid, -r);
        msg->has_result = 1;
        msg->result = NUVO__CLOSE_VOL__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-r);
    }
    return (req);
}

Nuvo__GetStats__Statistics *nuvo_build_getstats_stats()
{
    Nuvo__GetStats__Statistics *msg;

    msg = malloc(sizeof(*msg));
    if (msg == NULL)
    {
        goto nomem;
    }
    nuvo__get_stats__statistics__init(msg);
    msg->size_hist = calloc(NUVO_STATS_SIZE_BINS, sizeof(*msg->size_hist));
    msg->latency_hist = calloc(NUVO_STATS_LAT_BINS, sizeof(*msg->latency_hist));
    if (msg->size_hist == NULL || msg->latency_hist == NULL)
    {
        goto nomem;
    }

    return (msg);

nomem:
    if (msg && msg->size_hist)
    {
        free(msg->size_hist);
    }
    if (msg && msg->latency_hist)
    {
        free(msg->latency_hist);
    }
    if (msg)
    {
        free(msg);
    }
    return (NULL);
}

void fill_getstats_stats(Nuvo__GetStats__Statistics *msg, struct nuvo_io_stats_snap *stats)
{
    msg->has_count = true;
    msg->count = stats->count;
    msg->has_size_total = true;
    msg->size_total = stats->size_total;
    msg->has_latency_mean = true;
    msg->latency_mean = stats->latency_mean;

    msg->has_latency_stdev = true;
    msg->latency_stdev = stats->latency_stdev;
    msg->has_latency_sub_bits = true;
    msg->latency_sub_bits = NUVO_STATS_LAT_SUB_BITS;
    msg->n_size_hist = NUVO_STATS_SIZE_BINS;
    msg->n_latency_hist = NUVO_STATS_LAT_BINS;
    char series_uuid_string[UUID_UNPARSED_LEN];
    uuid_unparse(stats->series_uuid, series_uuid_string);
    msg->series_uuid = strdup(series_uuid_string);
}

nuvo_return_t get_stats_work(const Nuvo__GetStats__Type      type,
                             const Nuvo__GetStats__ReadWrite rw,
                             const bool                      reset,
                             const uuid_t                    uuid,
                             Nuvo__GetStats__Statistics    **stats)
{
    nuvo_return_t             rc;
    struct nuvo_io_stats_snap stats_snapshot;

    *stats = nuvo_build_getstats_stats();
    stats_snapshot.size_hist = (*stats)->size_hist;
    stats_snapshot.latency_hist = (*stats)->latency_hist;
    int stats_type;
    switch (rw)
    {
    case NUVO__GET_STATS__READ_WRITE__READ:
        stats_type = NUVO_OP_READ;
        break;

    case NUVO__GET_STATS__READ_WRITE__WRITE:
        stats_type = NUVO_OP_WRITE;
        break;

    default:
        return (-EINVAL);
    }
    switch (type)
    {
    case NUVO__GET_STATS__TYPE__DEVICE:
        rc = nuvo_pm_device_stats(uuid, stats_type, reset, &stats_snapshot);
        if (rc < 0)
        {
            return (rc);
        }
        fill_getstats_stats(*stats, &stats_snapshot);
        return (0);

    case NUVO__GET_STATS__TYPE__VOLUME:
        rc = nuvo_vol_lun_stats(uuid, stats_type, reset, &stats_snapshot);
        if (rc < 0)
        {
            return (rc);
        }
        fill_getstats_stats(*stats, &stats_snapshot);

        return (0);

    default:
        // Protobufs have a stupid value to force size and force default handling.
        return (-EINVAL);
    }
    return (0);
}

Nuvo__Cmd *nuvo_api_get_stats(struct nuvo_api_req *api_req, get_stats_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_STATS_REPLY;
    Nuvo__GetStats *msg = req->get_stats;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get stats - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get stats: uuid %s", msg->uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__GET_STATS__RESULT__INVALID;
        return (req);
    }
    uuid_t uuid;
    int    r = uuid_parse(msg->uuid, uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__GET_STATS__RESULT__BAD_UUID;
        msg->explanation = strdup("UUID invalid");
        return (req);
    }
    nuvo_return_t rc = do_work(msg->type, msg->rw, msg->clear != 0 ? true : false, uuid, &msg->stats);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get stats: uuid %s - Succeeded", msg->uuid);
        msg->has_result = 1;
        msg->result = NUVO__GET_STATS__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: get stats: uuid %s - Failed, error: %d",
                         msg->uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__GET_STATS__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

Nuvo__GetVolumeStats__Statistics *nuvo_build_getvolume_stats()
{
    Nuvo__GetVolumeStats__Statistics *msg;

    msg = malloc(sizeof(*msg));
    if (msg == NULL)
    {
        goto nomem;
    }
    nuvo__get_volume_stats__statistics__init(msg);
    msg->size_hist = calloc(NUVO_STATS_SIZE_BINS, sizeof(*msg->size_hist));
    msg->latency_hist = calloc(NUVO_STATS_LAT_BINS, sizeof(*msg->latency_hist));
    if (msg->size_hist == NULL || msg->latency_hist == NULL)
    {
        goto nomem;
    }

    return (msg);

nomem:
    if (msg && msg->size_hist)
    {
        free(msg->size_hist);
    }
    if (msg && msg->latency_hist)
    {
        free(msg->latency_hist);
    }
    if (msg)
    {
        free(msg);
    }
    return (NULL);
}

void fill_get_volume_stats(Nuvo__GetVolumeStats__Statistics *msg, struct nuvo_io_stats_snap *stats)
{
    msg->has_count = true;
    msg->count = stats->count;
    msg->has_size_total = true;
    msg->size_total = stats->size_total;
    msg->has_latency_mean = true;
    msg->latency_mean = stats->latency_mean;

    msg->has_latency_stdev = true;
    msg->latency_stdev = stats->latency_stdev;
    msg->has_latency_sub_bits = true;
    msg->latency_sub_bits = NUVO_STATS_LAT_SUB_BITS;
    msg->n_size_hist = NUVO_STATS_SIZE_BINS;
    msg->n_latency_hist = NUVO_STATS_LAT_BINS;
    char series_uuid_string[UUID_UNPARSED_LEN];
    uuid_unparse(stats->series_uuid, series_uuid_string);
    msg->series_uuid = strdup(series_uuid_string);
}

Nuvo__GetVolumeStats__CacheStats *nuvo_build_getvolumecache_stats()
{
    Nuvo__GetVolumeStats__CacheStats *msg;

    msg = malloc(sizeof(*msg));
    if (msg != NULL)
    {
        nuvo__get_volume_stats__cache_stats__init(msg);
    }
    return (msg);
}

void fill_get_volume_cache_stats(Nuvo__GetVolumeStats__CacheStats *msg, struct nuvo_cache_stats *stats)
{
    msg->has_io_read_total = true;
    msg->io_read_total = stats->ioreq_read_count;
    msg->has_cache_io_read_line_total_count = true;
    msg->cache_io_read_line_total_count = stats->cio_read_count;
    msg->has_cache_io_read_line_hit_count = true;
    msg->cache_io_read_line_hit_count = stats->cio_read_hit_count;
    msg->has_cache_io_read_line_miss_count = true;
    msg->cache_io_read_line_miss_count = stats->cio_read_miss_count;
    msg->has_io_write_total = true;
    msg->io_write_total = stats->ioreq_write_count;
    msg->has_cache_io_write_line_total_count = true;
    msg->cache_io_write_line_total_count = stats->cio_write_count;
}

nuvo_return_t get_volume_stats_work(const bool            reset,
                                    const uuid_t          uuid,
                                    Nuvo__GetVolumeStats *stats)
{
    nuvo_return_t             rc;
    struct nuvo_io_stats_snap stats_snapshot;

    stats->read_stats = nuvo_build_getvolume_stats();
    stats->write_stats = nuvo_build_getvolume_stats();
    stats->cache_stats_user = nuvo_build_getvolumecache_stats();
    stats->cache_stats_metadata = nuvo_build_getvolumecache_stats();

    if (stats->read_stats == NULL || stats->write_stats == NULL ||
        stats->cache_stats_user == NULL || stats->cache_stats_metadata == NULL)
    {
        // Message cleanup will handle freeing any allocations.
        return (-NUVO_ENOMEM);
    }

    stats_snapshot.size_hist = stats->read_stats->size_hist;
    stats_snapshot.latency_hist = stats->read_stats->latency_hist;
    rc = nuvo_vol_lun_stats(uuid, NUVO_OP_READ, false, &stats_snapshot);
    if (rc < 0)
    {
        return (rc);
    }
    fill_get_volume_stats(stats->read_stats, &stats_snapshot);

    stats_snapshot.size_hist = stats->write_stats->size_hist;
    stats_snapshot.latency_hist = stats->write_stats->latency_hist;
    rc = nuvo_vol_lun_stats(uuid, NUVO_OP_WRITE, false, &stats_snapshot);
    if (rc < 0)
    {
        return (rc);
    }
    fill_get_volume_stats(stats->write_stats, &stats_snapshot);

    struct nuvo_cache_stats cache_data;
    struct nuvo_cache_stats cache_metadata;

    rc = nuvo_vol_cache_stats(uuid, false, &cache_data, &cache_metadata);
    if (rc < 0)
    {
        return (rc);
    }
    fill_get_volume_cache_stats(stats->cache_stats_user, &cache_data);
    fill_get_volume_cache_stats(stats->cache_stats_metadata, &cache_metadata);

    if (reset)
    {
        nuvo_vol_lun_stats(uuid, NUVO_OP_READ, true, &stats_snapshot);
        nuvo_vol_lun_stats(uuid, NUVO_OP_WRITE, true, &stats_snapshot);
        nuvo_vol_cache_stats(uuid, true, &cache_data, &cache_metadata);
    }
    return (0);
}

Nuvo__Cmd *nuvo_api_get_volume_stats(struct nuvo_api_req *api_req, get_volume_stats_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REPLY;
    Nuvo__GetVolumeStats *msg = req->get_volume_stats;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get volume stats - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get volume stats: volume uuid %s", msg->uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__GET_VOLUME_STATS__RESULT__INVALID;
        return (req);
    }

    nuvo_return_t rc = do_work(msg->clear != 0 ? true : false, api_req->vol->vs_uuid, msg);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get volume stats: uuid %s - Succeeded", msg->uuid);
        msg->has_result = 1;
        msg->result = NUVO__GET_VOLUME_STATS__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: get volume stats: uuid %s - Failed, error: %d",
                         msg->uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__GET_VOLUME_STATS__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

nuvo_return_t destroy_vol_work(bool             log_volume,
                               struct nuvo_vol *vol,
                               const uuid_t     device_uuid,
                               const uuid_t     root_parcel_uuid)
{
    if (log_volume)
    {
        return (nuvo_log_vol_destroy(vol, device_uuid, root_parcel_uuid));
    }
    else
    {
        nuvo_mutex_t sync_signal;
        int_fast64_t rc = nuvo_mutex_init(&sync_signal);
        if (rc != 0)
        {
            return (rc);
        }
        rc = nuvo_parcel_vol_destroy(vol, device_uuid, root_parcel_uuid, &sync_signal);

        nuvo_mutex_destroy(&sync_signal);
        return (rc);
    }
}

Nuvo__Cmd *nuvo_api_destroy_vol(struct nuvo_api_req *api_req, destroy_vol_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY;
    Nuvo__DestroyVol *msg = req->destroy_vol;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: destroy volume - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: destroy volume (%s): uuid:%s, root device uuid %s, root parcel uuid %s",
                 msg->log_volume ? "log" : "parcel", msg->vol_uuid, msg->root_device_uuid, msg->root_parcel_uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__DESTROY_VOL__RESULT__INVALID;
        return (req);
    }

    uuid_t rd_uuid;
    int    r = uuid_parse(msg->root_device_uuid, rd_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__DESTROY_VOL__RESULT__BAD_UUID;
        msg->explanation = strdup("Root Device UUID invalid");
        return (req);
    }
    uuid_t rp_uuid;
    r = uuid_parse(msg->root_parcel_uuid, rp_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__DESTROY_VOL__RESULT__BAD_UUID;
        msg->explanation = strdup("Root Parcel UUID invalid");
        return (req);
    }
    nuvo_return_t rc = do_work(msg->log_volume, api_req->vol, rd_uuid, rp_uuid);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: destroy volume (%s): uuid %s, root device uuid %s, root parcel uuid %s - Succeeded",
                 msg->log_volume ? "log" : "parcel", msg->vol_uuid, msg->root_device_uuid, msg->root_parcel_uuid);
        msg->has_result = 1;
        msg->result = NUVO__DESTROY_VOL__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: destroy volume (%s): uuid %s, root device uuid %s, root parcel uuid %s - Failed, error: %d",
                         msg->log_volume ? "log" : "parcel", msg->vol_uuid,
                         msg->root_device_uuid, msg->root_parcel_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__DESTROY_VOL__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

nuvo_return_t use_node_uuid_work(const uuid_t node_uuid)
{
    int_fast64_t ret;

    ret = nuvo_pr_set_node_uuid(node_uuid);
    if (ret >= 0)
    {
        nuvo_pr_enable(false);
    }
    return (ret);
}

Nuvo__Cmd *nuvo_api_set_node_uuid(struct nuvo_api_req *api_req, set_node_uuid_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REPLY;
    Nuvo__UseNodeUuid *msg = req->use_node_uuid;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: set node uuid - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: set node uuid: %s", msg->uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__USE_NODE_UUID__RESULT__INVALID;
        return (req);
    }
    uuid_t node_uuid;
    int    r = uuid_parse(msg->uuid, node_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__USE_NODE_UUID__RESULT__BAD_UUID;
        msg->explanation = strdup("Node UUID invalid");
        return (req);
    }
    nuvo_return_t ret_val = do_work(node_uuid);
    if (ret_val == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: set node uuid: %s - Succeeded", msg->uuid);
        msg->has_result = 1;
        msg->result = NUVO__USE_NODE_UUID__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: set node uuid: %s - Failed, error: %d",
                         msg->uuid, -ret_val);
        msg->has_result = 1;
        msg->result = NUVO__USE_NODE_UUID__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-ret_val);
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_capabilties(struct nuvo_api_req *api_req)
{
    Nuvo__Cmd *req = api_req->cmd;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: capabilities");
    req->msg_type = NUVO__CMD__MESSAGE_TYPE__CAPABILITIES_REPLY;
    if (req->capabilities != NULL)
    {
        req->capabilities->has_multifuse = true;
        req->capabilities->multifuse = true;
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_get_manifest(struct nuvo_api_req *api_req, get_manifest_work_t do_work)
{
    Nuvo__Cmd *req = api_req->cmd;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__MANIFEST_REPLY;
    Nuvo__Manifest *msg = req->manifest;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get manifest - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get manifest: volume uuid %s",
                 msg->vol_uuid);
    }

    if (msg->has_result || msg->explanation != NULL)
    {
        msg->has_result = 1;
        msg->result = NUVO__MANIFEST__RESULT__INVALID;
        return (req);
    }

    nuvo_return_t rc = do_work(api_req->vol, msg, msg->short_reply);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: get manifest: volume uuid %s - Succeeded",
                 msg->vol_uuid);
        msg->has_result = 1;
        msg->result = NUVO__MANIFEST__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: get manifest: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__MANIFEST__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

#define SIGNIFICANT_DIRT     (75 * MEG)
#define MAX_NUM_PIT_DIFFS    128

nuvo_return_t nuvo_vol_diff_pits(struct nuvo_vol   *vol,
                                 const uuid_t       base_pit_uuid,
                                 const uuid_t       incr_pit_uuid,
                                 Nuvo__GetPitDiffs *msg)
{
    nuvo_return_t rc;

    if (vol == NULL ||
        (vol->type != NUVO_VOL_LOG_VOL))
    {
        return (-NUVO_ENOTBLK);
    }

    struct nuvo_lun *base_pit, *incr_pit;

    // TODO PIN these?
    base_pit = NULL;
    if (!uuid_is_null(base_pit_uuid))
    {
        if ((base_pit = nuvo_get_lun_by_uuid(vol, base_pit_uuid, false)) == NULL)
        {
            return (-NUVO_ENOENT);
        }
    }

    if ((incr_pit = nuvo_get_lun_by_uuid(vol, incr_pit_uuid, false)) == NULL)
    {
        return (-NUVO_ENOENT);
    }

    size_t   lun_size = vol->log_volume.lun.size;
    uint32_t diff_entries = 0;
    size_t   remaining_bytes = lun_size - msg->offset;
    uint64_t offset = msg->offset;

    if (remaining_bytes == 0)
    {
        msg->diffs = NULL;
        msg->n_diffs = 0;
        msg->offset = lun_size;
        NUVO_LOG(api, 0, "differ returning count = %d, offset = %lx", msg->n_diffs, msg->offset);
        return (0);
    }

    if (remaining_bytes > (MAX_NUM_PIT_DIFFS * DIFF_ENTRY_SPAN))
    {
        diff_entries = MAX_NUM_PIT_DIFFS;
    }
    else
    {
        // Remaining bytes is small enough that it will fit
        // in this last chunk of entries.
        diff_entries = (int)remaining_bytes / DIFF_ENTRY_SPAN;
    }

    msg->diffs = calloc(diff_entries, sizeof(*msg->diffs));
    if (msg->diffs == NULL)
    {
        return (-ENOMEM);
    }
    uint64_t dirty_bytes = 0;

    uint32_t count = 0;
    bool     stop_early = 0;
    while (count < diff_entries && !stop_early)
    {
        bool diff;

        rc = nuvo_log_vol_pit_diff_block(base_pit, incr_pit, offset, &diff);
        if (rc != 0)
        {
            if (count)
            {
                // Give back what we have
                NUVO_ERROR_PRINT("Error Triggered return");
                stop_early = 1;
                continue;
            }
            else
            {
                free(msg->diffs);
                // count == 0, no diffs to free
                return (rc);
            }
        }
        if (diff)
        {
            dirty_bytes += DIFF_ENTRY_SPAN;
        }
        if (count && msg->diffs[count - 1]->dirty == diff)
        {
            // Extending Previous Diff
            NUVO_ASSERT(offset == msg->diffs[count - 1]->offset + msg->diffs[count - 1]->length)
            msg->diffs[count - 1]->length += DIFF_ENTRY_SPAN;
            msg->offset = offset + DIFF_ENTRY_SPAN;
            offset += DIFF_ENTRY_SPAN;
        }
        else
        {
            msg->diffs[count] = malloc(sizeof(*msg->diffs[count]));
            if (msg->diffs[count] == NULL)
            {
                // Ran out of memory. Give back what we have
                if (count)
                {
                    NUVO_ERROR_PRINT("Out of Memory Triggered return");
                    stop_early = 1;
                    continue;
                }
                // free up allocated
                free(msg->diffs);
                // count == 0, no diffs to free
                return (-ENOMEM);
            }
            nuvo__get_pit_diffs__pit_diff__init(msg->diffs[count]);
            msg->diffs[count]->offset = offset;
            msg->diffs[count]->length = DIFF_ENTRY_SPAN;
            msg->diffs[count]->dirty = diff;
            msg->offset = offset + DIFF_ENTRY_SPAN;
            offset += DIFF_ENTRY_SPAN;
            msg->n_diffs++;
            count++;
        }
        if (offset == lun_size || dirty_bytes > SIGNIFICANT_DIRT)
        {
            NUVO_LOG(api, 10, "Significant Dirt Hit: Dirty bytes %ld", dirty_bytes);
            stop_early = 1;
        }
    }
    for (unsigned int i = 0; i < count; i++)
    {
        NUVO_LOG(api, 5, "Diff[%d], offset = 0x%lx, length = 0x%lx, %s", i,
                 msg->diffs[i]->offset, msg->diffs[i]->length, msg->diffs[i]->dirty ? "Dirty" : "Clean");
    }

    return (0);
}

Nuvo__Cmd *nuvo_api_diff_pits(struct nuvo_api_req *api_req, diff_pits_work_t do_work)
{
    Nuvo__Cmd         *req = api_req->cmd;
    Nuvo__GetPitDiffs *msg = req->get_pit_diffs;
    uuid_t             base_pit_uuid, incr_pit_uuid;
    int r;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: diff pits - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: diff pits: volume uuid %s, base pit uuid %s, incremental pit uuid %s, offset %d",
                 msg->vol_uuid, msg->base_pit_uuid, msg->incr_pit_uuid,
                 msg->offset);
    }

    // Get the Base Pit UUID
    if (msg->base_pit_uuid != NULL && *msg->base_pit_uuid != '\0')
    {
        r = uuid_parse(msg->base_pit_uuid, base_pit_uuid);
        if (r != 0)
        {
            msg->has_result = 1;
            msg->result = NUVO__GET_PIT_DIFFS__RESULT__BAD_UUID;
            msg->explanation = strdup("Base PiT UUID invalid");
            return (req);
        }
    }
    else
    {
        // No base specified
        uuid_clear(base_pit_uuid);
    }

    // Get the Incr Pit UUID
    r = uuid_parse(msg->incr_pit_uuid, incr_pit_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__GET_PIT_DIFFS__RESULT__BAD_UUID;
        msg->explanation = strdup("Incremental PiT UUID invalid");
        return (req);
    }

    // Check the offset
    if ((msg->offset % DIFF_ENTRY_SPAN) != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__GET_PIT_DIFFS__RESULT__OFFSET_MISALIGNED;
        msg->explanation = strdup("Offset Not multiple of 1M");
        return (req);
    }

    nuvo_return_t rc = do_work(api_req->vol, base_pit_uuid, incr_pit_uuid, msg);
    switch (rc)
    {
    case 0:
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: diff pits: volume uuid %s, base pit uuid %s, incremental pit uuid %s, offset %d - Succeeded",
                 msg->vol_uuid, msg->base_pit_uuid, msg->incr_pit_uuid,
                 msg->offset);
        msg->has_result = 1;
        msg->result = NUVO__GET_PIT_DIFFS__RESULT__OK;
        break;

    case -NUVO_ENOTBLK:
        NUVO_ERROR_PRINT("Nuvo api: diff pits: volume uuid %s, base pit uuid %s,  incremental pit uuid %s, offset %d - Failed, error: %d",
                         msg->vol_uuid, msg->base_pit_uuid, msg->incr_pit_uuid,
                         msg->offset, -rc);
        msg->has_result = 1;
        msg->result = NUVO__GET_PIT_DIFFS__RESULT__VOLUME_NOT_FOUND;
        msg->explanation = strdup("Volume Series Not Found");
        break;

    case -NUVO_ENOENT:
        NUVO_ERROR_PRINT("Nuvo api: diff pits: volume uuid %s, base pit uuid %s,  incremental pit uuid %s, offset %d - Failed, error: %d",
                         msg->vol_uuid, msg->base_pit_uuid, msg->incr_pit_uuid,
                         msg->offset, -rc);
        msg->has_result = 1;
        msg->result = NUVO__GET_PIT_DIFFS__RESULT__PIT_NOT_FOUND;
        msg->explanation = strdup("Pit Not Found");
        break;

    case -NUVO_ENOMEM:
    default:
        NUVO_ERROR_PRINT("Nuvo api: diff pits: volume uuid %s, base pit uuid %s,  incremental pit uuid %s, offset %d - Failed, error: %d",
                         msg->vol_uuid, msg->base_pit_uuid, msg->incr_pit_uuid,
                         msg->offset, -rc);
        msg->has_result = 1;
        msg->result = NUVO__GET_PIT_DIFFS__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
        break;
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_create_pit(struct nuvo_api_req *api_req, create_pit_work_t do_work)
{
    Nuvo__Cmd       *req = api_req->cmd;
    uuid_t           pit_uuid;
    Nuvo__CreatePit *msg = req->create_pit;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: create pit - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: create pit: volume uuid %s, pit uuid %s",
                 msg->vol_uuid, msg->pit_uuid);
    }

    int r = uuid_parse(msg->pit_uuid, pit_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__BAD_UUID;
        msg->explanation = strdup("PiT UUID invalid");
        return (req);
    }

    nuvo_return_t rc = do_work(api_req->vol, pit_uuid);
    switch (rc)
    {
    case 0:
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: create pit: volume uuid %s, pit uuid %s - Succeeded",
                 msg->vol_uuid, msg->pit_uuid);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__OK;
        break;

    case -NUVO_EEXIST:
        NUVO_ERROR_PRINT("Nuvo api: create pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__PIT_UUID_INUSE;
        msg->explanation = strdup("Pit Exists with this UUID");
        break;

    case -NUVO_EBUSY:
        NUVO_ERROR_PRINT("Nuvo api: create pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        // I'm not sure this should be an error
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__NOT_PAUSED;
        msg->explanation = strdup("I/O Not Paused");
        break;

    case -NUVO_ENOTBLK:
        NUVO_ERROR_PRINT("Nuvo api: create pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__VOLUME_NOT_FOUND;
        msg->explanation = strdup("Volume Series Not Found");
        break;

    case -NUVO_ENOSPC:
        NUVO_ERROR_PRINT("Nuvo api: create pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__CANT_CREATE;
        msg->explanation = strdup("Can't Create");
        break;

    default:
        NUVO_ERROR_PRINT("Nuvo api: create pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__CREATE_PIT__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
        break;
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_delete_pit(struct nuvo_api_req *api_req, delete_pit_work_t do_work)
{
    Nuvo__Cmd       *req = api_req->cmd;
    uuid_t           pit_uuid;
    Nuvo__DeletePit *msg = req->delete_pit;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: delete pit - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: delete pit: volume uuid %s, pit uuid %s",
                 msg->vol_uuid, msg->pit_uuid);
    }

    int r = uuid_parse(msg->pit_uuid, pit_uuid);
    if (r != 0)
    {
        msg->has_result = 1;
        msg->result = NUVO__DELETE_PIT__RESULT__BAD_UUID;
        msg->explanation = strdup("PiT UUID invalid");
        return (req);
    }

    nuvo_return_t rc = do_work(api_req->vol, pit_uuid);
    switch (rc)
    {
    case 0:
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: delete pit: volume uuid %s, pit uuid %s - Succeeded",
                 msg->vol_uuid, msg->pit_uuid);
        msg->has_result = 1;
        msg->result = NUVO__DELETE_PIT__RESULT__OK;
        break;

    case -NUVO_ENOENT:
        NUVO_ERROR_PRINT("Nuvo api: delete pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__DELETE_PIT__RESULT__PIT_NOT_FOUND;
        msg->explanation = strdup("No PiT with specified UUID");
        break;

    case -NUVO_EBUSY:
        NUVO_ERROR_PRINT("Nuvo api: delete pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__DELETE_PIT__RESULT__PIT_BUSY;
        msg->explanation = strdup("PiT In-use");
        break;

    case -NUVO_ENOTBLK:
        NUVO_ERROR_PRINT("Nuvo api: delete pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__DELETE_PIT__RESULT__VOLUME_NOT_FOUND;
        msg->explanation = strdup("Volume Series Not Found");
        break;

    default:
        NUVO_ERROR_PRINT("Nuvo api: delete pit: volume uuid %s, pit uuid %s - Failed, error: %d",
                         msg->vol_uuid, msg->pit_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__DELETE_PIT__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
        break;
    }
    return (req);
}

/* worker function for getting the list vols for nuvo api */

nuvo_return_t list_vols_work(Nuvo__ListVols *msg)
{
    char             uuid_str[UUID_UNPARSED_LEN]; // max UUID size
    struct nuvo_vol *vol_list[NUVO_MAX_VOL_SERIES_OPEN];
    int n_vols = 0;

    nuvo_mutex_lock(&vol_table.mutex);
    int cnt = nuvo_vol_list_vols(vol_list);

    if (!cnt)
    {
        nuvo_mutex_unlock(&vol_table.mutex);
        return (-NUVO_E_NO_VOLUME);
    }

    msg->vols = (Nuvo__ListVols__Vol **)malloc(cnt * sizeof(*msg->vols));
    msg->n_vols = 0;

    if (!msg->vols)
    {
        nuvo_mutex_unlock(&vol_table.mutex);
        return (-NUVO_ENOMEM);
    }

    for (int i = 0; i < cnt; i++)
    {
        msg->vols[n_vols] = malloc(sizeof(*msg->vols[n_vols]));

        if (!msg->vols[n_vols])
        {
            /* nuvo__cmd__free_unpacked() gets called after the reply is sent
             * which takes care of the freeing of the memory alloced till now
             */
            nuvo_mutex_unlock(&vol_table.mutex);
            return (-NUVO_ENOMEM);
        }

        nuvo__list_vols__vol__init(msg->vols[n_vols]);

        nuvo_mutex_lock(&vol_list[i]->mutex);

        /* Don't include uninitialized and closing volumes */
        if (NUVO_VOL_FREE != vol_list[i]->type &&
            NUVO_VOL_OP_STATE_INITIALIZED == vol_list[i]->op_state)
        {
            uuid_unparse(vol_list[i]->vs_uuid, uuid_str);
            msg->vols[n_vols]->vol_uuid = strdup(uuid_str);
            n_vols++;
        }

        nuvo_mutex_unlock(&vol_list[i]->mutex);
    }

    msg->n_vols = n_vols;
    nuvo_mutex_unlock(&vol_table.mutex);
    return (0);
}

nuvo_return_t nuvo_log_vol_list_pit(struct nuvo_vol *vol, Nuvo__ListPits *msg)
{
    char          uuid_str[UUID_UNPARSED_LEN]; // max UUID size
    nuvo_return_t ret;

    msg->n_pits = 0;

    uuid_t uuid_list[NUVO_MFST_MAX_LUNS];

    nuvo_mutex_lock(&vol->mutex);
    msg->n_pits = nuvo_vol_list_lun_uuids(vol, uuid_list);
    nuvo_mutex_unlock(&vol->mutex);

    if (msg->n_pits == 0)
    {
        ret = 0;
        goto _out;
    }

    msg->pits = calloc(msg->n_pits, sizeof(*msg->pits));
    if (!msg->pits)
    {
        ret = NUVO_ENOMEM;
        goto _out;
    }
    int pit_count = 0;

    for (uint_fast32_t i = 0; i < msg->n_pits; i++)
    {
        msg->pits[pit_count] = malloc(sizeof(*msg->pits[i]));

        if (!msg->pits[pit_count])
        {
            /* nuvo__cmd__free_unpacked() gets called after the reply is sent
             * which takes care of the freeing of the memory alloced till now
             */
            ret = NUVO_ENOMEM;
            goto _out;
        }
        //TODO error handle
        nuvo__list_pits__pit__init(msg->pits[pit_count]);

        uuid_unparse(uuid_list[i], uuid_str);
        msg->pits[pit_count]->pit_uuid = strdup(uuid_str);

        pit_count++;
    }

    return (0);

_out:
    return (-ret);
}

Nuvo__Cmd *nuvo_api_list_pits(struct nuvo_api_req *api_req, list_pit_work_t do_work)
{
    Nuvo__Cmd      *req = api_req->cmd;
    Nuvo__ListPits *msg = req->list_pits;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: list pits - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: list pits: volume uuid %s",
                 msg->vol_uuid);
    }

    nuvo_return_t rc = do_work(api_req->vol, msg);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: list pits: volume uuid %s - Succeeded",
                 msg->vol_uuid);
        msg->has_result = 1;
        msg->result = NUVO__LIST_PITS__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: list pits: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__LIST_PITS__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_list_vols(struct nuvo_api_req *api_req, list_vol_work_t do_work)
{
    Nuvo__Cmd      *req = api_req->cmd;
    Nuvo__ListVols *msg = req->list_vols;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_VOLS_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: list vols - Started");

    nuvo_return_t rc = do_work(msg);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: list vols - Succeeded");
        msg->has_result = 1;
        msg->result = NUVO__LIST_VOLS__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: list vols - Failed, error: %d", -rc);
        msg->has_result = 1;
        msg->result = NUVO__LIST_VOLS__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

nuvo_return_t nuvo_vol_freeze_flush(struct nuvo_vol *vol)
{
    if (vol->type != NUVO_VOL_LOG_VOL)
    {
        return (-NUVO_EINVAL);
    }
    nuvo_return_t rc = nuvo_space_snap_frozen_set(&vol->log_volume.space, true);
    return (rc);
}

nuvo_return_t nuvo_vol_unfreeze_flush(struct nuvo_vol *vol)
{
    if (vol->type != NUVO_VOL_LOG_VOL)
    {
        return (-NUVO_EINVAL);
    }
    nuvo_return_t rc = nuvo_space_snap_frozen_set(&vol->log_volume.space, false);
    return (rc);
}

Nuvo__Cmd *nuvo_api_pause_io(struct nuvo_api_req *api_req, pause_io_work_t do_work)
{
    Nuvo__Cmd     *req = api_req->cmd;
    Nuvo__PauseIo *msg = req->pause_io;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: pause io - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: pause io: volume uuid %s",
                 msg->vol_uuid);
    }

    nuvo_return_t rc = do_work(api_req->vol);
    switch (rc)
    {
    case 0:
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: pause io: volume uuid %s - Succeeded",
                 msg->vol_uuid);
        msg->has_result = 1;
        msg->result = NUVO__PAUSE_IO__RESULT__OK;
        break;

    case -NUVO_ENOTBLK:
        NUVO_ERROR_PRINT("Nuvo api: pause io: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__PAUSE_IO__RESULT__VOLUME_NOT_FOUND;
        msg->explanation = strdup("Volume Series Not Found");
        break;

    case -NUVO_ETIMEDOUT:
        NUVO_ERROR_PRINT("Nuvo api: pause io: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__PAUSE_IO__RESULT__TIMED_OUT;
        msg->explanation = strdup("Pause Timed Out");
        break;

    default:
        NUVO_ERROR_PRINT("Nuvo api: pause io: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__PAUSE_IO__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
        break;
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_resume_io(struct nuvo_api_req *api_req, resume_io_work_t do_work)
{
    Nuvo__Cmd      *req = api_req->cmd;
    Nuvo__ResumeIo *msg = req->resume_io;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: resume io - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: resume io: volume uuid %s",
                 msg->vol_uuid);
    }

    nuvo_return_t rc = do_work(api_req->vol);
    switch (rc)
    {
    case 0:
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: resume io: volume uuid %s - Succeeded",
                 msg->vol_uuid);
        msg->has_result = 1;
        msg->result = NUVO__RESUME_IO__RESULT__OK;
        break;

    case -NUVO_EINVAL:
        NUVO_ERROR_PRINT("Nuvo api: resume io: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__RESUME_IO__RESULT__NOT_PAUSED;
        msg->explanation = strdup("Resuming But Not Paused");
        break;

    case -NUVO_ENOTBLK:
        NUVO_ERROR_PRINT("Nuvo api: resume io: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__RESUME_IO__RESULT__VOLUME_NOT_FOUND;
        msg->explanation = strdup("Volume Series Not Found");
        break;

    default:
        NUVO_ERROR_PRINT("Nuvo api: resume io: volume uuid %s - Failed, error: %d",
                         msg->vol_uuid, -rc);
        msg->has_result = 1;
        msg->result = NUVO__RESUME_IO__RESULT__ERROR;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
        break;
    }
    return (req);
}

Nuvo__Cmd *nuvo_api_log_level(struct nuvo_api_req *api_req, log_level_work_t do_work)
{
    Nuvo__Cmd      *req = api_req->cmd;
    Nuvo__LogLevel *msg = req->log_level;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log level - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log level: module %s",
                 msg->module_name);
    }

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REPLY;
    nuvo_return_t rc = do_work(msg->module_name, msg->level);
    if (rc == 0)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log level: module %s - Succeeded",
                 msg->module_name);
        msg->has_result = 1;
        msg->result = NUVO__LOG_LEVEL__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: log level: module %s - Failed, error: %d",
                         msg->module_name, -rc);
        NUVO_ASSERT(rc == -NUVO_E_NO_MODULE);
        msg->has_result = 1;
        msg->result = NUVO__LOG_LEVEL__RESULT__NO_MODULE;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

nuvo_return_t nuvo_node_status(Nuvo__NodeStatus *msg)
{
    (void)msg;
    uuid_t        local_node_id;
    nuvo_return_t rc = nuvo_pr_get_node_uuid(local_node_id);
    if (rc < 0)
    {
        return (rc);
    }
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(local_node_id, uuid_str);
    msg->node_uuid = strdup(uuid_str);
    if (msg->node_uuid == NULL)
    {
        return (-NUVO_ENOMEM);
    }

    msg->git_build_hash = strdup(VERSION_GIT_COMMIT_HASH);
    if (msg->git_build_hash == NULL)
    {
        return (-NUVO_ENOMEM);
    }

    NUVO_LOG_CAN_SUPPRESS(api, NUVO_LL_API, SUP_GRP_PRINT_VERSION, 1, "nuvo_version_hash: %s", msg->git_build_hash);
    NUVO_LOG_CAN_SUPPRESS(api, NUVO_LL_API, SUP_GRP_PRINT_VERSION, 0, "nuvo_version_build: " VERSION_GIT_BRANCH_NAME " : " VERSION_GIT_COMMIT_DATE);
    NUVO_LOG_CAN_SUPPRESS(api, NUVO_LL_API, SUP_GRP_PRINT_VERSION, 0, "nuvo_version_timestamp: " VERSION_MAKE_TIMESTAMP);

    return (nuvo_vol_get_statuses(msg));
}

Nuvo__Cmd *nuvo_api_node_status(struct nuvo_api_req *api_req, node_status_work_t do_work)
{
    Nuvo__Cmd        *req = api_req->cmd;
    Nuvo__NodeStatus *msg = req->node_status;

    NUVO_LOG_CAN_SUPPRESS(api, NUVO_LL_API, SUP_GRP_NODE_STATUS, 1, "Nuvo api: node status - Started");

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REPLY;

    nuvo_return_t rc = do_work(msg);

    if (rc == 0)
    {
        NUVO_LOG_CAN_SUPPRESS(api, NUVO_LL_API, SUP_GRP_NODE_STATUS, 0, "Nuvo api: node status - Succeeded");
        msg->has_result = 1;
        msg->result = NUVO__NODE_STATUS__RESULT__OK;
    }
    else
    {
        NUVO_ERROR_PRINT("Nuvo api: node status - Failed, error: %d", -rc);
        NUVO_ASSERT(rc == -NUVO_ENOMEM);
        msg->has_result = 1;
        msg->result = NUVO__NODE_STATUS__RESULT__ENOMEM;
        msg->explanation = nuvo_status_alloc_error_str(-rc);
    }
    return (req);
}

void nuvo_debug_trigger_fi_set(Nuvo__DebugTrigger  *msg,
                               struct test_fi_info *fi_info)
{
    // Set basic fault injection values
    if (!msg->has_inject_error_type || !msg->has_inject_return_code ||
        !msg->has_inject_repeat_cnt)
    {
        return;
    }
    int skip_cnt = 0;
    if (msg->has_inject_skip_cnt)
    {
        skip_cnt = msg->inject_skip_cnt;
    }

    test_fi_set_basic_error(fi_info, msg->inject_error_type,
                            msg->inject_return_code,
                            msg->inject_repeat_cnt, skip_cnt);

    // Check msg for uuids and set them for fault injection
    uuid_t node_uuid;
    uuid_t vol_uuid;
    uuid_t dev_uuid;

    uuid_clear(node_uuid);
    uuid_clear(vol_uuid);
    uuid_clear(dev_uuid);

    // has_<field_name> doesn't work on strings, so doing this.
    // Skip "0" uuids, they can be used as wildcards by some tests.
    if ((msg->node_uuid) && (strlen(msg->node_uuid) > 0) &&
        (strcmp(msg->node_uuid, "0")))
    {
        int r = uuid_parse(msg->node_uuid, node_uuid);
        if (r != 0)
        {
            NUVO_ERROR_PRINT("Fault Injection - error, failed to set node_uuid %s",
                             msg->node_uuid);
            return;
        }
    }
    if ((msg->vol_uuid) && (strlen(msg->vol_uuid) > 0) &&
        (strcmp(msg->vol_uuid, "0")))
    {
        int r = uuid_parse(msg->vol_uuid, vol_uuid);
        if (r != 0)
        {
            NUVO_ERROR_PRINT("Fault Injection - error, failed to set vol_uuid %s",
                             msg->vol_uuid);
            return;
        }
    }
    if ((msg->dev_uuid) && (strlen(msg->dev_uuid) > 0) &&
        (strcmp(msg->dev_uuid, "0")))
    {
        int r = uuid_parse(msg->dev_uuid, dev_uuid);
        if (r != 0)
        {
            NUVO_ERROR_PRINT("Fault Injection - error, failed to set dev_uuid %s",
                             msg->dev_uuid);
            return;
        }
    }
    test_fi_set_uuids(fi_info, node_uuid, vol_uuid, dev_uuid);

    // Check msg for multiuse values and set them for fault injection
    uint64_t muse1 = 0;
    uint64_t muse2 = 0;
    uint64_t muse3 = 0;

    if (msg->has_multiuse1)
    {
        muse1 = msg->multiuse1;
    }
    if (msg->has_multiuse2)
    {
        muse2 = msg->multiuse2;
    }
    if (msg->has_multiuse3)
    {
        muse3 = msg->multiuse3;
    }
    test_fi_set_multiuse(fi_info, muse1, muse2, muse3);

    NUVO_ERROR_PRINT("Fault Injection - Set Success");

    return;
}

nuvo_return_t nuvo_lun_latency_limit(struct nuvo_vol *vol,
                                     const uuid_t     pit_uuid,
                                     uint64_t         write_latency,
                                     uint64_t         read_latency);

Nuvo__Cmd *nuvo_api_debug_trigger(struct nuvo_api_req *api_req)
{
    Nuvo__Cmd          *req = api_req->cmd;
    Nuvo__DebugTrigger *msg = req->debug_trigger;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REPLY;

    if (msg->trigger == NULL)
    {
        return (req);
    }

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s - Started", msg->trigger);

    if (0 == strcmp(msg->trigger, "cp_start"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s",
                 msg->trigger, msg->vol_uuid);
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);
        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_space_trigger_cp(&nuvo_vol->log_volume.space);
            }
        }
    }
    else if (0 == strcmp(msg->trigger, "gc_vol"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s",
                 msg->trigger, msg->vol_uuid);
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);

        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_space_vol_need_empty_segments(&nuvo_vol->log_volume.space, 0);
            }
        }
    }
    else if (0 == strcmp(msg->trigger, "gc_segment"))
    {
        bool no_cp = (msg->has_multiuse1 && msg->multiuse1 != 0);
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s %s",
                 msg->trigger, msg->vol_uuid, no_cp ? " with no CP" : "");
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);

        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_space_vol_gc_seg_debug(&nuvo_vol->log_volume.space,
                                            msg->parcel_index,
                                            msg->segment_index,
                                            no_cp);
                NUVO_ERROR_PRINT("Debug trigger for gc " NUVO_LOG_UUID_FMT " (%d, %d).",
                                 NUVO_LOG_UUID(vs_uuid), msg->parcel_index, msg->segment_index);
            }
        }
    }

    else if (0 == strcmp(msg->trigger, "disable_cp"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s",
                 msg->trigger, msg->vol_uuid);
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);
        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_space_vol_manage_cps_stop(&nuvo_vol->log_volume.space);
                NUVO_ERROR_PRINT("CPs stopped on " NUVO_LOG_UUID_FMT ".  This will end well.",
                                 NUVO_LOG_UUID(vs_uuid));
            }
        }
    }

    else if (0 == strcmp(msg->trigger, "disable_gc"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s",
                 msg->trigger, msg->vol_uuid);
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);
        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_space_vol_manage_gc_stop(&nuvo_vol->log_volume.space);
                NUVO_ERROR_PRINT("GC disabled on " NUVO_LOG_UUID_FMT ".  This will end well.",
                                 NUVO_LOG_UUID(vs_uuid));
            }
        }
    }

    else if (0 == strcmp(msg->trigger, "enable_gc"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s",
                 msg->trigger, msg->vol_uuid);
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);
        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_space_vol_manage_gc_start(&nuvo_vol->log_volume.space);
                NUVO_ERROR_PRINT("GC enabled on " NUVO_LOG_UUID_FMT ".  This will end well.",
                                 NUVO_LOG_UUID(vs_uuid));
            }
        }
    }

    else if (0 == strcmp(msg->trigger, "pr_error"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: error_type %d, return_code %d, repeat %d, skip %d",
                 msg->trigger, msg->inject_error_type, msg->inject_return_code,
                 msg->inject_repeat_cnt, msg->inject_skip_cnt);
        struct test_fi_info *fi_info = nuvo_pr_get_test_fi();
        if (fi_info)
        {
            nuvo_debug_trigger_fi_set(msg, fi_info);
        }
    }
    if (0 == strcmp(msg->trigger, "map_panic"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: error_type %d, return_code %d, repeat %d, skip %d"
                 "has multiuse1:%d multi_use1:%lu has_multi_use2:%d multiuse2:%lu",
                 msg->trigger, msg->inject_error_type, msg->inject_return_code,
                 msg->inject_repeat_cnt, msg->inject_skip_cnt,
                 msg->has_multiuse1, msg->multiuse1, msg->has_multiuse2, msg->multiuse2);
        struct test_fi_info *fi_info = nuvo_map_get_test_fi();
        if (fi_info)
        {
            nuvo_debug_trigger_fi_set(msg, fi_info);
        }
    }

    else if (0 == strcmp(msg->trigger, "nanosleep"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: seconds: %" PRIu64 ", nano_seconds: %" PRIu64, msg->trigger, msg->multiuse1, msg->multiuse2);
        struct timespec sleep_time;
        sleep_time.tv_sec = msg->multiuse1;
        sleep_time.tv_nsec = msg->multiuse2;
        nanosleep(&sleep_time, NULL);
    }
    // log_marker command injecst arbitrary strings (specified as --device) to nuvo log
    // This could be useful for correlating a functional test command to nuvo_log
    else if (0 == strcmp(msg->trigger, "log_marker"))
    {
        NUVO_LOG(api, NUVO_LL_API, "log_marker: %s", msg->dev_uuid);
    }
    // Only one instance of this can be used at a time.  This is here for
    // fault injection items that are hard to set.  For example, you want to
    // set FI for a volume on replay, but the vol isn't loaded in memory yet.
    else if (0 == strcmp(msg->trigger, "fi_general_use"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: error_type %d, return_code %d, repeat %d, skip %d",
                 msg->trigger, msg->inject_error_type, msg->inject_return_code,
                 msg->inject_repeat_cnt, msg->inject_skip_cnt);
        struct test_fi_info *fi_info = test_fi_general_use_fi_get();
        if (fi_info)
        {
            nuvo_debug_trigger_fi_set(msg, fi_info);
        }
    }
    else if (0 == strcmp(msg->trigger, "mfl_dirty_threshold"))
    {
        if (msg->has_multiuse1)
        {
            int threshold = msg->multiuse1;
            nuvo_map_mfl_set_dirty_cnt_threshold(threshold);
        }
    }
    else if (0 == strcmp(msg->trigger, "pr_log_stats"))
    {
        nuvo_pr_log_stats();
    }
    else if (0 == strcmp(msg->trigger, "pr_dev_config_done"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: setting to: %d",
                 msg->trigger, msg->multiuse1);
        bool is_done = (bool)msg->multiuse1;
        nuvo_pr_kontroller_config_done(is_done);
    }
    else if (0 == strcmp(msg->trigger, "set_vol_state"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s, new state %d",
                 msg->trigger, msg->vol_uuid, msg->multiuse1);
        uuid_t vs_uuid;
        int    r = uuid_parse(msg->vol_uuid, vs_uuid);

        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vs_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                if ((msg->has_multiuse1) &&
                    (msg->multiuse1 <= NUVO_VOL_STATE_FENCED))
                {
                    nuvo_vol->vol_state = msg->multiuse1;
                }
            }
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: new vol state: %d",
                     msg->trigger, nuvo_vol->vol_state);
        }
    }
    else if (0 == strcmp(msg->trigger, "manley"))
    {
        NUVO_PANIC("All your base are belong to us.");
    }
    else if (0 == strcmp(msg->trigger, "vol_destroy"))
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: error_type %d, return_code %d, repeat %d, skip %d"
                 "has multiuse1:%d multi_use1:%lu has_multi_use2:%d multiuse2:%lu",
                 msg->trigger, msg->inject_error_type, msg->inject_return_code,
                 msg->inject_repeat_cnt, msg->inject_skip_cnt,
                 msg->has_multiuse1, msg->multiuse1, msg->has_multiuse2, msg->multiuse2);
        struct test_fi_info *fi_info = nuvo_vol_ops_test_fi();
        if (fi_info)
        {
            nuvo_debug_trigger_fi_set(msg, fi_info);
        }
    }
    else if (0 == strcmp(msg->trigger, "device_latency"))
    {
        uuid_t dev_uuid;
        int    r = uuid_parse(msg->dev_uuid, dev_uuid);
        if (r == 0 && msg->has_multiuse1)
        {
            nuvo_pm_device_delay(dev_uuid, msg->multiuse1);
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: dev_uuid %s, delay %" PRIu64,
                     msg->trigger, msg->dev_uuid, msg->multiuse1);
        }
    }
    else if (0 == strcmp(msg->trigger, "lun_latency"))
    {
        uuid_t vol_uuid;
        (void)uuid_parse(msg->vol_uuid, vol_uuid);
        struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vol_uuid);
        uuid_t           lun_uuid;
        (void)uuid_parse(msg->dev_uuid, lun_uuid);
        nuvo_lun_latency_limit(nuvo_vol, lun_uuid, msg->multiuse1, msg->multiuse2);
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: vol_uuid %s, lun_uuid %s, write latency delay %" PRIu64 " read latency %" PRIu64,
                 msg->trigger, msg->vol_uuid, msg->dev_uuid, msg->multiuse1, msg->multiuse2);
    }
    else if (0 == strcmp(msg->trigger, "drop_cache"))
    {
        uuid_t vol_uuid;
        int    r = uuid_parse(msg->vol_uuid, vol_uuid);

        if (r == 0)
        {
            struct nuvo_vol *nuvo_vol = nuvo_vol_lookup(vol_uuid);
            if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
            {
                nuvo_drop_cache(nuvo_vol);
            }
        }
    }

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: debug trigger %s: might have - Succeeded",
             msg->trigger);

    return (req);
}

Nuvo__Cmd *nuvo_api_log_summary(struct nuvo_api_req *api_req)
{
    Nuvo__Cmd        *req = api_req->cmd;
    Nuvo__LogSummary *msg = req->log_summary;

    req->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REPLY;

    NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log summary - Started");
    if (msg)
    {
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log summary: volume uuid %s",
                 msg->vol_uuid);
    }

    if (msg == NULL)
    {
        return (req);
    }

    struct nuvo_vol *nuvo_vol = api_req->vol;
    if (nuvo_vol != NULL && nuvo_vol->type == NUVO_VOL_LOG_VOL)
    {
        struct nuvo_segment_digest digest;
        nuvo_return_t rc;
        rc = nuvo_space_read_digest_debug(&nuvo_vol->log_volume.space,
                                          msg->parcel_index,
                                          msg->segment_index,
                                          &digest);
        if (rc >= 0)
        {
            nuvo_logger_fill_log_summary(msg, &digest);
            NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log summary: volume uuid %s - Succeeded",
                     msg->vol_uuid);
        }
        else
        {
            NUVO_ERROR_PRINT("Nuvo api: log summary: volume uuid %s - Failed, error: %d",
                             msg->vol_uuid, -rc);
        }
    }

    return (req);
}

/**
 * \fn Nuvo__Cmd* run_command(Nuvo__Cmd *cmd)
 * \brief Take a Nuvo__Cmd and do it.
 *
 * This processes the unpacked command. Consumes the request and may return
 * a reply, which the caller has to free.  It's possible the request pointer
 * and the repsonse are the same.  Think of them as different, so you don't
 * get screwed if someone actually doesn't do that.
 *
 * \param cmd The unpacked request.
 * \returns The reply (if any) to be sent.
 * \retval NULL Your request made no sense.  We threw it away.
 */
static Nuvo__Cmd *run_command(struct nuvo_api_req *api_req)
{
    Nuvo__Cmd *cmd = api_req->cmd;

    if (cmd == NULL)
    {
        return (NULL);
    }
    switch (cmd->msg_type)
    {
    case NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REQ:
        return (nuvo_api_use_device(api_req, nuvo_pm_device_open, nuvo_cache_device_open));

    case NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REQ:
        return (nuvo_api_close_device(api_req, close_device_work));

    case NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REQ:
        return (nuvo_api_format_device(api_req, nuvo_pm_device_format));

    case NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REQ:
        return (nuvo_api_device_location(api_req, device_insert_or_update));

    case NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REQ:
        return (nuvo_api_node_location(api_req, node_location_work));

    case NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REQ:
        return (nuvo_api_node_init_done(api_req, node_init_done_work));

    case NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ:
        return (nuvo_api_passthrough_open_volume(api_req, nuvo_passthrough_open_work));

    case NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REQ:
        return (nuvo_api_export_lun(api_req, export_lun_work));

    case NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REQ:
        return (nuvo_api_unexport_lun(api_req, unexport_lun_work));

    case NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ:
        return (nuvo_api_create_volume(api_req, create_volume_work));

    case NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ:
        return (nuvo_api_open_volume(api_req, open_volume_work));

    case NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REQ:
        return (nuvo_api_alloc_parcels(api_req, alloc_parcels_work));

    case NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REQ:
        return (nuvo_api_alloc_cache(api_req, alloc_cache_work));

    case NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REQ:
        return (nuvo_api_close_vol(api_req, close_vol_work));

    case NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ:
        return (nuvo_api_get_stats(api_req, get_stats_work));

    case NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REQ:
        return (nuvo_api_get_volume_stats(api_req, get_volume_stats_work));

    case NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ:
        return (nuvo_api_destroy_vol(api_req, destroy_vol_work));

    case NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REQ:
        return (nuvo_api_set_node_uuid(api_req, use_node_uuid_work));

    case NUVO__CMD__MESSAGE_TYPE__CAPABILITIES_REQ:
        return (nuvo_api_capabilties(api_req));

    case NUVO__CMD__MESSAGE_TYPE__MANIFEST_REQ:
        return (nuvo_api_get_manifest(api_req, nuvo_vol_get_manifest));

    case NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REQ:
        return (nuvo_api_create_pit(api_req, nuvo_log_vol_create_pit));

    case NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REQ:
        return (nuvo_api_diff_pits(api_req, nuvo_vol_diff_pits));

    case NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REQ:
        return (nuvo_api_delete_pit(api_req, nuvo_log_vol_delete_pit));

    case NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REQ:
        return (nuvo_api_list_pits(api_req, nuvo_log_vol_list_pit));

    case NUVO__CMD__MESSAGE_TYPE__LIST_VOLS_REQ:
        return (nuvo_api_list_vols(api_req, list_vols_work));

    case NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REQ:
        return (nuvo_api_pause_io(api_req, nuvo_vol_freeze_flush));

    case NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REQ:
        return (nuvo_api_resume_io(api_req, nuvo_vol_unfreeze_flush));

    case NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REQ:
        return (nuvo_api_log_level(api_req, nuvo_log_set_level));

    case NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REQ:
        return (nuvo_api_node_status(api_req, nuvo_node_status));

    case NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REQ:
        return (nuvo_api_debug_trigger(api_req));

    case NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REQ:
        return (nuvo_api_log_summary(api_req));

    default:
        nuvo__cmd__free_unpacked(cmd, NULL);
        return (NULL);
    }
}

/**
 * \brief Setup reply for API dispatcher thread to return error.
 *
 * Kontroller key off the error string instead of error code, so we must
 * preserve the original error string including existing inconsistencies.
 *
 * \param cmd The API command
 * \param err Type of error
 * \param rc Specific error code if applicable. Used by NUVO_E_ALLOC_VOLUME only.
 */
void prep_dispatcher_err_reply(Nuvo__Cmd *cmd, nuvo_return_t err, nuvo_return_t rc)
{
    if (cmd == NULL)
    {
        return;
    }

    NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER ||
                err == NUVO_E_INVALID_VS_UUID ||
                err == NUVO_E_ALLOC_VOLUME ||
                err == NUVO_E_NO_VOLUME);

    char *explanation = NULL; // To point to malloced buffer containing error string
    switch (err)
    {
    case NUVO_E_CMD_BAD_ORDER:
    case NUVO_E_INVALID_VS_UUID:
    case NUVO_E_NO_VOLUME:
        explanation = nuvo_status_alloc_error_str(err);
        break;

    case NUVO_E_ALLOC_VOLUME:
        explanation = nuvo_status_alloc_error_str(-rc);
        break;

    default:
        NUVO_PANIC("Invalid error code");
    }

    switch (cmd->msg_type)
    {
    case NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REQ:
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY;

        for (unsigned int i = 0; i < cmd->n_use_device; i++)
        {
            Nuvo__UseDevice *use_dev = cmd->use_device[i];
            use_dev->has_result = 1;
            use_dev->result = NUVO__USE_DEVICE__RESULT__BAD_ORDER;
            use_dev->explanation = strdup(explanation);
        }
        free(explanation);
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REQ:
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REPLY;

        for (unsigned int i = 0; i < cmd->n_close_device; i++)
        {
            Nuvo__CloseDevice *close_dev = cmd->close_device[i];
            close_dev->has_result = 1;
            close_dev->result = NUVO__CLOSE_DEVICE__RESULT__BAD_ORDER;
            close_dev->explanation = strdup(explanation);
        }
        free(explanation);
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REQ:
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY;
        for (unsigned int i = 0; i < cmd->n_format_device; i++)
        {
            Nuvo__FormatDevice *format_dev = cmd->format_device[i];
            format_dev->has_result = 1;
            format_dev->result = NUVO__FORMAT_DEVICE__RESULT__BAD_ORDER;
            format_dev->explanation = strdup(explanation);
        }
        free(explanation);
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REQ:
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY;
        for (unsigned int i = 0; i < cmd->n_device_location; i++)
        {
            Nuvo__DeviceLocation *dev_loc = cmd->device_location[i];
            dev_loc->has_result = 1;
            dev_loc->result = NUVO__DEVICE_LOCATION__RESULT__BAD_ORDER;
            dev_loc->explanation = strdup(explanation);
        }
        free(explanation);
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REQ:
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY;
        for (unsigned int i = 0; i < cmd->n_node_location; i++)
        {
            Nuvo__NodeLocation *node_loc = cmd->node_location[i];
            node_loc->has_result = 1;
            node_loc->result = NUVO__NODE_LOCATION__RESULT__BAD_ORDER;
            node_loc->explanation = strdup(explanation);
        }
        free(explanation);
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REQ:
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REPLY;
        Nuvo__NodeInitDone *nid_msg = cmd->node_init_done;
        nid_msg->has_result = 1;
        nid_msg->result = NUVO__NODE_INIT_DONE__RESULT__BAD_ORDER;
        nid_msg->explanation = explanation;
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REPLY;
        Nuvo__OpenPassThroughVolume *opv_msg = cmd->open_pass_through_vol;
        opv_msg->has_result = 1;
        opv_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            opv_msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            opv_msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__INVALID;
            break;

        case NUVO_E_ALLOC_VOLUME:
            opv_msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__ERROR;
            break;

        case NUVO_E_NO_VOLUME:
            opv_msg->result = NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__ERROR;
            break;
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REPLY;
        Nuvo__ExportLun *el_msg = cmd->export_lun;
        el_msg->has_result = 1;
        el_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            el_msg->result = NUVO__EXPORT_LUN__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            el_msg->result = NUVO__EXPORT_LUN__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            el_msg->result = NUVO__EXPORT_LUN__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REPLY;
        Nuvo__UnexportLun *uel_msg = cmd->unexport_lun;
        uel_msg->has_result = 1;
        uel_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            uel_msg->result = NUVO__UNEXPORT_LUN__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            uel_msg->result = NUVO__UNEXPORT_LUN__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            uel_msg->result = NUVO__UNEXPORT_LUN__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY;
        Nuvo__CreateVolume *cpv_msg = cmd->create_volume;
        cpv_msg->has_result = 1;
        cpv_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            cpv_msg->result = NUVO__CREATE_VOLUME__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            cpv_msg->result = NUVO__CREATE_VOLUME__RESULT__BAD_UUID;
            break;

        case NUVO_E_ALLOC_VOLUME:
            cpv_msg->result = NUVO__CREATE_VOLUME__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY;
        Nuvo__OpenVolume *opv_msg = cmd->open_volume;
        opv_msg->has_result = 1;
        opv_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            opv_msg->result = NUVO__OPEN_VOLUME__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            opv_msg->result = NUVO__OPEN_VOLUME__RESULT__BAD_UUID;
            break;

        case NUVO_E_ALLOC_VOLUME:
            opv_msg->result = NUVO__OPEN_VOLUME__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REPLY;
        Nuvo__AllocParcels *ap_msg = cmd->alloc_parcels;
        ap_msg->has_result = 1;
        ap_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            ap_msg->result = NUVO__ALLOC_PARCELS__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            ap_msg->result = NUVO__ALLOC_PARCELS__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            ap_msg->result = NUVO__ALLOC_PARCELS__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REPLY;
        Nuvo__AllocCache *ac_msg = cmd->alloc_cache;
        ac_msg->has_result = 1;
        ac_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            ac_msg->result = NUVO__ALLOC_CACHE__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            ac_msg->result = NUVO__ALLOC_CACHE__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            ac_msg->result = NUVO__ALLOC_CACHE__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REPLY;
        Nuvo__CloseVol *cv_msg = cmd->close_vol;
        cv_msg->has_result = 1;
        cv_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            cv_msg->result = NUVO__CLOSE_VOL__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            cv_msg->result = NUVO__CLOSE_VOL__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            cv_msg->result = NUVO__CLOSE_VOL__RESULT__ERROR;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_STATS_REPLY;
        Nuvo__GetStats *gs_msg = cmd->get_stats;
        gs_msg->has_result = 1;
        gs_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            gs_msg->result = NUVO__GET_STATS__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            gs_msg->result = NUVO__GET_STATS__RESULT__BAD_UUID;
            gs_msg->explanation = strdup("UUID invalid"); // Different error string
            free(explanation);
            break;

        case NUVO_E_NO_VOLUME:
            gs_msg->result = NUVO__GET_STATS__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REPLY;
        Nuvo__GetVolumeStats *gvs_msg = cmd->get_volume_stats;
        gvs_msg->has_result = 1;
        gvs_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            gvs_msg->result = NUVO__GET_VOLUME_STATS__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            gvs_msg->result = NUVO__GET_VOLUME_STATS__RESULT__BAD_UUID;
            gvs_msg->explanation = strdup("UUID invalid"); // Different error string
            free(explanation);
            break;

        case NUVO_E_NO_VOLUME:
            gvs_msg->result = NUVO__GET_VOLUME_STATS__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY;
        Nuvo__DestroyVol *dv_msg = cmd->destroy_vol;
        dv_msg->has_result = 1;
        dv_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            dv_msg->result = NUVO__DESTROY_VOL__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            dv_msg->result = NUVO__DESTROY_VOL__RESULT__BAD_UUID;
            break;

        case NUVO_E_ALLOC_VOLUME:
            dv_msg->result = NUVO__DESTROY_VOL__RESULT__ERROR;
            if (rc == -EEXIST)
            {
                free(explanation);
                dv_msg->explanation = nuvo_status_alloc_error_str(EBUSY);
            }
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REQ:
        // This shouldn't happen
    {
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REPLY;
        Nuvo__UseNodeUuid *unu_msg = cmd->use_node_uuid;
        unu_msg->has_result = 1;
        unu_msg->result = NUVO__USE_NODE_UUID__RESULT__INVALID;
        unu_msg->explanation = explanation;
        NUVO_ERROR_PRINT("Attempted BAD ORDER on wrong message");
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__SHUTDOWN:
        // We should never get here
        NUVO_ERROR_PRINT("Attempted BAD ORDER on wrong message");
        break;

    case NUVO__CMD__MESSAGE_TYPE__MANIFEST_REQ:
    {
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__MANIFEST_REPLY;
        Nuvo__Manifest *man_msg = cmd->manifest;
        man_msg->has_result = 1;
        man_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            man_msg->result = NUVO__MANIFEST__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            man_msg->result = NUVO__MANIFEST__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            man_msg->result = NUVO__MANIFEST__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
    }
    break;

    case NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY;
        Nuvo__GetPitDiffs *pitdiff_msg = cmd->get_pit_diffs;
        pitdiff_msg->has_result = 1;
        pitdiff_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            pitdiff_msg->result = NUVO__GET_PIT_DIFFS__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            pitdiff_msg->result = NUVO__GET_PIT_DIFFS__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            pitdiff_msg->result = NUVO__GET_PIT_DIFFS__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
        break;

    case NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REPLY;
        Nuvo__CreatePit *pit_msg = cmd->create_pit;
        pit_msg->has_result = 1;
        pit_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            pit_msg->result = NUVO__CREATE_PIT__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            pit_msg->result = NUVO__CREATE_PIT__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            pit_msg->result = NUVO__CREATE_PIT__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error code %u", err);
        }
        break;

    case NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REPLY;
        Nuvo__DeletePit *del_pit_msg = cmd->delete_pit;
        del_pit_msg->has_result = 1;
        del_pit_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            del_pit_msg->result = NUVO__DELETE_PIT__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            del_pit_msg->result = NUVO__DELETE_PIT__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            del_pit_msg->result = NUVO__DELETE_PIT__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error %u", err);
        }
        break;

    case NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REPLY;
        Nuvo__ListPits *list_pits_msg = cmd->list_pits;
        list_pits_msg->has_result = 1;
        list_pits_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            list_pits_msg->result = NUVO__LIST_PITS__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            list_pits_msg->result = NUVO__LIST_PITS__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            list_pits_msg->result = NUVO__LIST_PITS__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error %u", err);
        }
        break;

    case NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REPLY;
        Nuvo__PauseIo *pause_msg = cmd->pause_io;
        pause_msg->has_result = 1;
        pause_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            pause_msg->result = NUVO__PAUSE_IO__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            pause_msg->result = NUVO__PAUSE_IO__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            pause_msg->result = NUVO__PAUSE_IO__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error %u", err);
            break;
        }
        break;

    case NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REPLY;
        Nuvo__ResumeIo *resume_msg = cmd->resume_io;
        resume_msg->has_result = 1;
        resume_msg->explanation = explanation;
        switch (err)
        {
        case NUVO_E_CMD_BAD_ORDER:
            resume_msg->result = NUVO__RESUME_IO__RESULT__BAD_ORDER;
            break;

        case NUVO_E_INVALID_VS_UUID:
            resume_msg->result = NUVO__RESUME_IO__RESULT__BAD_UUID;
            break;

        case NUVO_E_NO_VOLUME:
            resume_msg->result = NUVO__RESUME_IO__RESULT__VOLUME_NOT_FOUND;
            break;

        default:
            NUVO_PANIC("Invalid error %u", err);
            break;
        }
        break;

    case NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REQ:
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REPLY;
        Nuvo__LogLevel *log_level_msg = cmd->log_level;
        log_level_msg->has_result = 1;
        log_level_msg->result = NUVO__LOG_LEVEL__RESULT__BAD_ORDER;
        log_level_msg->explanation = explanation;
        break;

    case NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REQ:
        NUVO_ASSERT(err == NUVO_E_CMD_BAD_ORDER);
        // Send back node status with empty UUID
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REPLY;
        break;

    case NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REQ:
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REPLY;
        NUVO_ERROR_PRINT("Debug trigger not proceessed, err %u", err);
        break;

    case NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REQ:
        // Preserving original behavior - log summary doesn't return error
        cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REPLY;
        NUVO_LOG(api, NUVO_LL_API, "Nuvo api: log summary error %u", err);
        break;

    default:
        NUVO_ERROR_PRINT("Unknown Message type");
        break;
    }
}

/**
 * \brief Return whether the command needs a new allocation of volume structure in volume table.
 */
bool cmd_need_alloc_vol(Nuvo__Cmd *cmd)
{
    return ((cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ) ||
            (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ) ||
            (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ) ||
            (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ));
}

/**
 * \brief Whether a command is specific to a volume already loaded in volume table.
 *
 * \param cmd The API command
 * \return Whether command is volume specific
 */
bool cmd_is_vol_specific(Nuvo__Cmd *cmd)
{
    NUVO_ASSERT(cmd != NULL);

    // Should not call this on commands that needs to allocate a new volume structure
    NUVO_ASSERT(!cmd_need_alloc_vol(cmd));

    switch (cmd->msg_type)
    {
    // Volume specific commands
    case NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REQ:
    case NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REQ:
    case NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REQ:
    case NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REQ:
    case NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REQ:
    case NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REQ:
    case NUVO__CMD__MESSAGE_TYPE__MANIFEST_REQ:
    case NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REQ:
    case NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REQ:
    case NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REQ:
    case NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REQ:
    case NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REQ:
    case NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REQ:
    case NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REQ:
        return (true);

    // Non-volume-specific commands
    case NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REQ:
    case NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REQ:
    case NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REQ:
    case NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REQ:
    case NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REQ:
    case NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REQ:
    case NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REQ:
    case NUVO__CMD__MESSAGE_TYPE__CAPABILITIES_REQ:
    case NUVO__CMD__MESSAGE_TYPE__LIST_VOLS_REQ:
    case NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REQ:
    case NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REQ:
    case NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REQ:
        return (false);

    // Could be either volume-specific or non-volume-specific
    case NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ:
        return (cmd->get_stats->type == NUVO__GET_STATS__TYPE__VOLUME);

    default:
        NUVO_ERROR_PRINT("Unknown command %u", cmd->msg_type);
        return (false);
    }
}

/**
 * \brief initialize global exit control structure.
 *
 * Sets up the mutex to police access to the structure,
 * the value of whether we are exiting, the pipes to allow
 * the api thread to wake up on accept calls, and the
 * thread id of the caller to allow sending a singal to
 * the thread when getting a halt message, since things only seem
 * to work if the correct thread gets the signal.  Yes I'm confused.
 *
 * \param exit_ctrl The global structure to hold everything.
 */
void nuvo_exiting_init(struct nuvo_exit_ctrl_s *exit_ctrl)
{
    int_fast64_t r;

    r = pipe(exit_ctrl->api_thread_pipe);
    if (r != 0)
    {
        NUVO_PANIC("exit pipe allocation");
    }
    r = nuvo_mutex_init(&exit_ctrl->exit_mutex);
    if (r != 0)
    {
        NUVO_PANIC("exit mutex allocation");
    }
    r = nuvo_cond_init(&exit_ctrl->exit_cond);
    if (r != 0)
    {
        NUVO_PANIC("exit condition allocation");
    }
    exit_ctrl->exiting = false;
}

/**
 * \fn void nuvo_exiting_set(struct nuvo_exit_ctrl_s *exit_ctrl)
 * \brief Set that we're exiting.
 *
 * Sets the value of the exiting flag, writes to the pipe
 * to let the api thread know that it is exiting and signal
 * the main thread to let it know. This errs on the side of
 * letting everyone know, including notifying themselves,
 * but that works and is less error prone than focussed calls.
 * \param exit_ctrl The global structure to hold everything.
 */
void nuvo_exiting_set(struct nuvo_exit_ctrl_s *exit_ctrl)
{
    nuvo_mutex_lock(&exit_ctrl->exit_mutex);
    exit_ctrl->exiting = 1;
    int r = write(exit_ctrl->api_thread_pipe[1], "die", 1);
    NUVO_PANIC_COND((r != 1), "write failed");
    nuvo_cond_broadcast(&exit_ctrl->exit_cond);
    nuvo_mutex_unlock(&exit_ctrl->exit_mutex);
}

/**
 * \fn int nuvo_exiting_get(struct nuvo_exit_ctrl_s *exit_ctrl)
 * \brief Get whether we are exiting.
 * \param exit_ctrl The global structure to hold everything.
 */
bool nuvo_exiting_get(struct nuvo_exit_ctrl_s *exit_ctrl)
{
    nuvo_mutex_lock(&exit_ctrl->exit_mutex);
    bool r = exit_ctrl->exiting;
    nuvo_mutex_unlock(&exit_ctrl->exit_mutex);
    return (r);
}

void nuvo_exiting_wait(struct nuvo_exit_ctrl_s *exit_ctrl)
{
    nuvo_mutex_lock(&exit_ctrl->exit_mutex);
    while (!exit_ctrl->exiting)
    {
        nuvo_cond_wait(&exit_ctrl->exit_cond, &exit_ctrl->exit_mutex);
    }
    nuvo_mutex_unlock(&exit_ctrl->exit_mutex);
}

/**
 * \fn void nuvo_exiting_destroy(struct nuvo_exit_ctrl_s *exit_ctrl)
 * \brief Tear down exit control because we're exiting.
 */
void nuvo_exiting_destroy(struct nuvo_exit_ctrl_s *exit_ctrl)
{
    nuvo_mutex_destroy(&exit_ctrl->exit_mutex);
    nuvo_cond_destroy(&exit_ctrl->exit_cond);
    close(exit_ctrl->api_thread_pipe[0]);
    close(exit_ctrl->api_thread_pipe[1]);
}

/**
 * \brief Check if the set_node_uuid message was successful.
 *
 * \param msg The UseNodeUUID message.
 * \returns 0 on failure.
 */
static int use_node_uuid_success(Nuvo__UseNodeUuid *msg)
{
    return (msg && msg->has_result && msg->result == 0);
}

/**
 * \brief Get a pointer to volume uuid in command structure
 *
 * \param req The API command
 * return Char pointer to volume uuid
 */
char *get_vol_uuid(Nuvo__Cmd *cmd)
{
    NUVO_ASSERT(cmd != NULL);

    switch (cmd->msg_type)
    {
    case NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ:
        return (cmd->open_pass_through_vol->uuid);

    case NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REQ:
        return (cmd->export_lun->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REQ:
        return (cmd->unexport_lun->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ:
        return (cmd->create_volume->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ:
        return (cmd->open_volume->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REQ:
        return (cmd->alloc_parcels->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REQ:
        return (cmd->alloc_cache->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REQ:
        return (cmd->close_vol->vol_series_uuid);

    case NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ:
        return (cmd->get_stats->uuid);

    case NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REQ:
        return (cmd->get_volume_stats->uuid);

    case NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ:
        return (cmd->destroy_vol->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__MANIFEST_REQ:
        return (cmd->manifest->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REQ:
        return (cmd->create_pit->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REQ:
        return (cmd->get_pit_diffs->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REQ:
        return (cmd->delete_pit->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REQ:
        return (cmd->list_pits->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REQ:
        return (cmd->pause_io->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REQ:
        return (cmd->resume_io->vol_uuid);

    case NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REQ:
        return (cmd->log_summary->vol_uuid);

    default:
        NUVO_ERROR_PRINT("Invalid cmd %u", cmd->msg_type);
        return (NULL);
    }
}

/**
 * \brief Non-volume-specific worker thread for API command processing.
 */
void *nuvo_api_thread_worker_nonvol(void *arg)
{
    struct nuvo_api_params *params = (struct nuvo_api_params *)arg;
    struct nuvo_api_queue  *queue = &nonvol_queue;
    struct nuvo_api_req    *req = NULL;
    Nuvo__Cmd *reply;

    NUVO_LOG(api, 0, "API nonvol worker tid %u started", pthread_self());

    while (true)
    {
        nuvo_mutex_lock(&queue->mutex);

        // Remove an item from queue
        while ((req = nuvo_dlist_remove_head_object(&queue->list, struct nuvo_api_req, list_node)) == NULL)
        {
            // Queue is empty, wait
            NUVO_ASSERT(queue->length == 0);
            nuvo_cond_wait(&queue->work_cond, &queue->mutex);
        }

        queue->length--;
        nuvo_mutex_unlock(&queue->mutex);

        if (req->ctrl_cmd != QUEUE_CTRL_NONE)
        {
            // Poison pill should be the last request in the queue
            NUVO_ASSERT(queue->length == 0);
            NUVO_LOG(api, 0, "API nonvol worker received ctrl cmd %u", req->ctrl_cmd);
            break;
        }

        NUVO_LOG(api, 0, "API nonvol worker received api cmd %u", req->cmd->msg_type);

        // Process command
        reply = run_command(req);

        if (reply)
        {
            NUVO_LOG(api, 30, "API nonvol worker sending reply for cmd %u", reply->msg_type);

            if (!params->full_enable &&
                (req->cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REPLY) &&
                use_node_uuid_success(req->cmd->use_node_uuid))
            {
                NUVO_LOG(api, 0, "API nonvol worker set full enable");
                params->full_enable = 1;
            }
            send_reply(req->cmd_socket, reply);
            nuvo__cmd__free_unpacked(reply, NULL);
        }

        if (req->cmd_socket >= 0)
        {
            close(req->cmd_socket);
        }

        nuvo_api_req_free(req);
    }

    // Free the ctrl request
    nuvo_api_req_free(req);

    nuvo_api_queue_destroy(queue, NULL);
    NUVO_LOG(api, 0, "API nonvol worker terminating");
    return (NULL);
}

/**
 * \brief Volume-specific worker thread for API command processing.
 */
void *nuvo_api_thread_worker_vol(void *arg)
{
    struct nuvo_api_queue *queue = (struct nuvo_api_queue *)arg;

    NUVO_ASSERT(queue != NULL);
    struct nuvo_vol *nvs_p = queue->vol;
    NUVO_ASSERT(nvs_p != NULL);
    struct nuvo_api_req *req = NULL;
    bool         terminate = false;
    Nuvo__Cmd   *reply = NULL;
    unsigned int table_index = nuvo_vol_index_lookup(nvs_p);
    uuid_t       vs_uuid; // Local copy so we can log on thread exit after volume is freed

    NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " started vol type %u",
             pthread_self(), table_index, NUVO_LOG_UUID(nvs_p->vs_uuid), nvs_p->type);
    uuid_copy(vs_uuid, nvs_p->vs_uuid);

    while (!terminate)
    {
        nuvo_mutex_lock(&queue->mutex);

        // Remove an item from queue
        while ((req = nuvo_dlist_remove_head_object(&queue->list, struct nuvo_api_req, list_node)) == NULL)
        {
            // Queue is empty, wait
            NUVO_ASSERT(queue->length == 0);
            nuvo_cond_wait(&queue->work_cond, &queue->mutex);
        }

        queue->length--;
        nuvo_mutex_unlock(&queue->mutex);

        if (req->ctrl_cmd != QUEUE_CTRL_NONE)
        {
            // Poison pill should be the last request in the queue
            NUVO_ASSERT(queue->length == 0);
            NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " received ctrl cmd %u",
                     pthread_self(), table_index, NUVO_LOG_UUID(nvs_p->vs_uuid), req->ctrl_cmd);
            break;
        }

        NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " received api cmd %u",
                 pthread_self(), table_index, NUVO_LOG_UUID(nvs_p->vs_uuid), req->cmd->msg_type);

        // Process command
        reply = run_command(req);

        // If the command was volume create, open, or destroy, which will also create
        // worker thread, but the command failed, terminate the thread
        if ((reply->msg_type == NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY &&
             reply->create_volume->result != NUVO__CREATE_VOLUME__RESULT__OK) ||
            (reply->msg_type == NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY &&
             reply->open_volume->result != NUVO__OPEN_VOLUME__RESULT__OK) ||
            (reply->msg_type == NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY &&
             reply->destroy_vol->result != NUVO__DESTROY_VOL__RESULT__OK) ||
            (reply->msg_type == NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REPLY &&
             reply->open_pass_through_vol->result != NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__OK))
        {
            NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " failed to alloc volume",
                     pthread_self(), table_index, NUVO_LOG_UUID(nvs_p->vs_uuid));
            nuvo_mutex_lock(&queue->mutex);
            NUVO_ASSERT(queue->length == 0);
            nuvo_mutex_unlock(&queue->mutex);

            terminate = true;
        }

        if (reply)
        {
            NUVO_LOG(api, 30, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " sending reply for cmd %u",
                     pthread_self(), table_index, NUVO_LOG_UUID(nvs_p->vs_uuid), reply->msg_type);
            send_reply(req->cmd_socket, reply);
            nuvo__cmd__free_unpacked(reply, NULL);
        }

        if (req->cmd_socket >= 0)
        {
            close(req->cmd_socket);
        }

        if (!terminate)
        {
            nuvo_api_req_free(req);
        }
    }

    // Cleanup before terminate
    if (req->ctrl_cmd == QUEUE_CTRL_CLOSE_VOL_TERMINATE)
    {
        nuvo_return_t rc = nuvo_vol_series_close_vol(nvs_p);
        NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " close volume %s rc %u",
                 pthread_self(), table_index, NUVO_LOG_UUID(vs_uuid), (rc == 0 ? "success" : "failed"), rc);
    }

    NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " terminating",
             pthread_self(), table_index, NUVO_LOG_UUID(vs_uuid));

    nuvo_mutex_lock(&vol_table.mutex);
    nuvo_api_queue_destroy(queue, nvs_p);
    nvs_p->type = NUVO_VOL_FREE;
    nvs_p->op_state = NUVO_VOL_OP_STATE_UNINITIALIZED;
    nuvo_mutex_unlock(&vol_table.mutex);

    // Free the ctrl request
    nuvo_api_req_free(req);

    nuvo_mutex_lock(&num_workers.mutex);
    if (--num_workers.num == 0)
    {
        nuvo_cond_signal(&num_workers.zero_cond);
    }
    unsigned int cur_num_workers = num_workers.num;
    nuvo_mutex_unlock(&num_workers.mutex);

    NUVO_LOG(api, 0, "API worker (%u - %u) for " NUVO_LOG_UUID_FMT " terminated, num workers %u)",
             pthread_self(), table_index, NUVO_LOG_UUID(vs_uuid), cur_num_workers);

    return (NULL);
}

/**
 * \fn void *nuvo_api_thread(void *arg)
 * \brief Thread handler for the API socket and dispatcher of API request.
 *
 * Receive command from socket. If command requires new entry in volume table,
 * allocate new volume entry and start the associated worker thread. Create a
 * request (api_req) that wraps the command (Nuvo__Cmd) and the volume pointer,
 * and submit the request to the volume's queue. Each volume has its own queue
 * and worker thread.
 *
 * If command is not volume-specific, submit the request to a non volume-specific
 * queue. There is a single queue and single worker thread to run all non
 * volume-specific commands.
 *
 * \param arg Don't do anything with this yet.
 * \returns
 */
void *
nuvo_api_thread(void *arg)
{
    struct sockaddr_un name;
    int                    api_connect_socket = 0;
    int                    ret;
    char                  *vol_uuid = NULL;
    uuid_t                 vs_uuid;
    struct nuvo_vol       *nvs_p = NULL;
    struct nuvo_api_queue *queue = NULL;
    nuvo_return_t          rc;

    struct nuvo_api_params *params = (struct nuvo_api_params *)arg;

    /*
     * Destroy old socket and create new one.
     */
    unlink(params->socket_name);
    api_connect_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (api_connect_socket == -1)
    {
        // No error here is recoverable.
        NUVO_ERROR_PRINT("socket create");
        goto eject_eject_eject;
    }

    memset(&name, 0, sizeof(name));
    name.sun_family = AF_UNIX;
    strncpy(name.sun_path, params->socket_name, sizeof(name.sun_path) - 1);

    ret = bind(api_connect_socket, (const struct sockaddr *)&name,
               sizeof(name));
    if (ret == -1)
    {
        // No error here is recoverable.
        NUVO_ERROR_PRINT("socket bind");
        goto eject_eject_eject;
    }

    ret = listen(api_connect_socket, NUVO_API_SOCK_BACKLOG);
    if (ret == -1)
    {
        // No error here is recoverable.
        NUVO_ERROR_PRINT("socket listen");
        goto eject_eject_eject;
    }

    NUVO_LOG(api, 0, "API dispatcher thread started tid %d", pthread_self());
    while (1)
    {
        /*
         * Check if exit has been set.  Is this redundant with the
         * pipe notification?
         */
        if (nuvo_exiting_get(params->exit_ctrl))
        {
            break;
        }

        /*
         * Select on the pipe and the socket so we're not going to
         * hang accept when we should be exiting.
         */
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(api_connect_socket, &fds);
        FD_SET(params->exit_ctrl->api_thread_pipe[0], &fds);
        int nfds = 1 + (api_connect_socket > params->exit_ctrl->api_thread_pipe[0] ?
                        api_connect_socket : params->exit_ctrl->api_thread_pipe[0]);
        int retval = select(nfds, &fds, NULL, NULL, NULL);
        if (retval < 0)
        {
            switch (errno)
            {
            case EBADF:
                NUVO_ERROR_PRINT("API socket bad fd");
                goto eject_eject_eject;
                break;

            case EINTR:
                // Go back around.
                continue;

            case ENOMEM:
            default:
                // Something has gone horribly wrong.
                NUVO_ERROR_PRINT_ERRNO(errno, "socket accept failed");
                goto eject_eject_eject;
            }
        }
        if (FD_ISSET(params->exit_ctrl->api_thread_pipe[0], &fds))
        {
            break;
        }
        else if (!FD_ISSET(api_connect_socket, &fds))
        {
            continue;
        }

        int cmd_socket;
        cmd_socket = accept(api_connect_socket, NULL, NULL);
        if (cmd_socket == -1)
        {
            NUVO_ERROR_PRINT_ERRNO(errno, "socket accept failed");
            // We're going to come right back to accept.
            continue;
        }

        /*
         * Read a request off the socket.
         */
        uint8_t *packed_req = NULL;
        NUVO_LOG(api, 30, "API dispatcher read request off socket");
        int req_len = recv_command(cmd_socket, &packed_req);
        nvs_p = NULL;
        if (req_len > 0)
        {
            Nuvo__Cmd *reply = NULL;
            Nuvo__Cmd *cmd = nuvo__cmd__unpack(NULL, req_len, packed_req);
            free(packed_req);
            NUVO_LOG(api, 30, "API dispatcher received request %u", cmd->msg_type);
            if (!cmd)
            {
                NUVO_ERROR_PRINT("API dispatcher received malformatted command");
            }
            else if (cmd->msg_type == NUVO__CMD__MESSAGE_TYPE__SHUTDOWN)
            {
                NUVO_LOG(api, 0, "API dispatcher received shutdown cmd");
                nuvo__cmd__free_unpacked(cmd, NULL);
                goto eject_eject_eject;
            }
            else if (!params->full_enable &&
                     (cmd->msg_type != NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REQ) &&
                     (cmd->msg_type != NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REQ) &&
                     (cmd->msg_type != NUVO__CMD__MESSAGE_TYPE__CAPABILITIES_REQ) &&
                     (cmd->msg_type != NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REQ))
            {
                // We only accept set node uuid, capability, and debug trigger
                // commands if not enabled
                NUVO_LOG(api, 0, "API dispatcher received cmd %u order violation",
                         cmd->msg_type);
                prep_dispatcher_err_reply(cmd, NUVO_E_CMD_BAD_ORDER, 0);
                reply = cmd;
            }
            else if (cmd_need_alloc_vol(cmd))
            {
                NUVO_LOG(api, 0, "API dispatcher recv cmd %u need to alloc vol",
                         cmd->msg_type);

                // Allocate a volume structure first for volume create, open, and destroy.
                // The worker thread for the volume will execute the operation.
                if ((!(vol_uuid = get_vol_uuid(cmd))) ||
                    (uuid_parse(vol_uuid, vs_uuid)))
                {
                    // Unable to get or parse uuid
                    prep_dispatcher_err_reply(cmd, NUVO_E_INVALID_VS_UUID, 0);
                    reply = cmd;
                }
                else if ((rc = nuvo_vol_alloc(cmd, vs_uuid, &nvs_p)))
                {
                    // Failed to allocate volume in volume table
                    prep_dispatcher_err_reply(cmd, NUVO_E_ALLOC_VOLUME, rc);
                    reply = cmd;
                }
                else
                {
                    // Volume allocated in table, don't reply in dispatcher thread.
                    queue = nvs_p->cmd_queue;
                    NUVO_ASSERT(reply == NULL);
                }
            }
            else
            {
                NUVO_LOG(api, 30, "API dispatcher received cmd %u no need to alloc vol",
                         cmd->msg_type);

                if (cmd_is_vol_specific(cmd))
                {
                    NUVO_LOG(api, 0, "API dispatcher recv cmd %u is volume specific", cmd->msg_type);
                    // Try to find the command queue for the volume
                    if ((!(vol_uuid = get_vol_uuid(cmd))) ||
                        (uuid_parse(vol_uuid, vs_uuid)))
                    {
                        // Unable to get or parse uuid
                        prep_dispatcher_err_reply(cmd, NUVO_E_INVALID_VS_UUID, 0);
                        reply = cmd;
                    }
                    else if (!(nvs_p = nuvo_vol_lookup(vs_uuid)))
                    {
                        // Volume not found
                        prep_dispatcher_err_reply(cmd, NUVO_E_NO_VOLUME, 0);
                        reply = cmd;
                    }
                    else
                    {
                        queue = nvs_p->cmd_queue;
                    }
                }
                else
                {
                    NUVO_LOG(api, 30, "API dispatcher recv cmd %u is non-volume-specific", cmd->msg_type);
                    queue = &nonvol_queue;
                }
            }

            if (reply)
            {
                send_reply(cmd_socket, reply);
                nuvo__cmd__free_unpacked(reply, NULL);
                close(cmd_socket);
            }
            else
            {
                // Create and submit API request to worker queue
                // Reply will be send by worker thread
                nuvo_api_queue_submit_req(queue, cmd_socket, cmd);
            }
        }
        else if (cmd_socket >= 0)
        {
            close(cmd_socket);
        }
    }
eject_eject_eject:
    if (api_connect_socket > 0)
    {
        close(api_connect_socket);
    }
    unlink(params->socket_name);
    nuvo_exiting_set(params->exit_ctrl);
    pthread_exit(0);
    return (0);
}
