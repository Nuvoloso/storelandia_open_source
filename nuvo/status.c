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
 * @file status.c
 * @brief Encapuslated status codes.
 *
 * Internal functions should return 0 on success and a negative number on errors.
 */
#include "nuvo.h"
#include "status.h"

#include <stdio.h>
#include <string.h>

struct nuvo_error_msg {
    enum nuvo_error error_num;
    char           *msg;
} nuvo_error_msgs[] =
{
    { NUVO_CUSTOM_ERROR,             "Nuvo error start"                                             },
    { NUVO_E_BAD_HASH,               "Bad data hash"                                                },
    { NUVO_E_BAD_MAGIC,              "Bad magic number in header"                                   },
    { NUVO_E_NO_SUPERBLOCK,          "No Superblock"                                                },
    { NUVO_E_SIG_HANDLER,            "Failed to register signal handler(s)."                        },
    { NUVO_E_NO_MODULE,              "No such module."                                              },
    { NUVO_E_IO_RETRY_CNT_EXCEEDED,  "Request retry limit exceeded."                                },
    { NUVO_E_BAD_STATE_TRANSITION,   "Bad state transition."                                        },
    { NUVO_E_CMD_BAD_ORDER,          "Not allowed before use node UUID command"                     },

    { NUVO_ERROR_DEVICE,             "Nuvo Device error section"                                    },
    { NUVO_E_NO_DEVICE,              "No such device"                                               },
    { NUVO_E_NO_DEVICES_CLASS,       "No devices of the request class."                             },
    { NUVO_E_DEVICE_CLASS_BAD,       "Attempt to set invalid device class."                         },
    { NUVO_E_DEVICE_CLASS_CHANGED,   "Attempt to change existing device class."                     },
    { NUVO_E_DEVICE_ALREADY_OPEN,    "Device was already open for use."                             },
    { NUVO_E_DEVICE_IN_USE,          "Device is in use, contains allocated parcels."                },
    { NUVO_E_DEVICE_NOT_USABLE,      "The device could not be used."                                },
    { NUVO_E_DEVICE_TYPE_BAD,        "Attempt to set invalid device type."                          },

    { NUVO_ERROR_VOLUME,             "Nuvo Volume error section"                                    },
    { NUVO_E_INVALID_VS_UUID,        "Vol Series UUID invalid"                                      },
    { NUVO_E_ALLOC_VOLUME,           "Failed to allocate volume"                                    },
    { NUVO_E_NO_VOLUME,              "No such volume"                                               },
    { NUVO_E_WRONG_VOL_TYPE,         "Wrong type of volume"                                         },
    { NUVO_E_REPLAYS_EXCEEDED,       "The maximum recovery retry count has been exceeded."          },

    { NUVO_ERROR_LUN,                "Nuvo Lun error section"                                       },
    { NUVO_E_NO_LUN,                 "No lun in volume"                                             },
    { NUVO_E_LUN_EXPORTED,           "Lun exported"                                                 },
    { NUVO_E_LUN_VOLUME_MISMATCH,    "Volume and lun mismatched"                                    },

    { NUVO_ERROR_PARCEL,             "Nuvo Parcel error section"                                    },
    { NUVO_E_PARCEL_RANGE,           "Parcel index out of range"                                    },
    { NUVO_E_PARCEL_NOT_OPEN,        "Parcel is not open"                                           },
    { NUVO_E_PARCEL_ALREADY_ALLOC,   "Parcel is already allocated"                                  },
    { NUVO_E_PARCEL_ALREADY_OPEN,    "Parcel is already open"                                       },
    { NUVO_E_PARCEL_ALREADY_CLOSED,  "Parcel is already closed"                                     },
    { NUVO_E_PARCEL_ALREADY_FREE,    "Parcel is already free"                                       },
    { NUVO_E_PARCEL_UNUSABLE,        "Parcel cannot be opened"                                      },
    { NUVO_E_PARCEL_IN_USE,          "Cannot close parcel that is in use"                           },

    { NUVO_ERROR_SEGMENT,            "Nuvo Segment error section"                                   },
    { NUVO_E_OUT_OF_SEGMENT_STRUCTS, "No segment structures available."                             },
    { NUVO_E_NO_FREE_SEGMENTS,       "No media segments available in this class."                   },
    { NUVO_E_NO_CLEANABLE_SEGMENT,   "No segment available for cleaning."                           },

    { NUVO_ERROR_CACHE,              "Nuvo Cache error section"                                     },
    { NUVO_E_NO_CACHE,               "Cache is not enabled on this node."                           },

    { NUVO_ERROR_NETWORK,            "Nuvo Network error section"                                   },
    { NUVO_E_SOCK_OPT,               "Failed to set socket options."                                },
    { NUVO_E_BIND,                   "Failed to bind socket."                                       },
    { NUVO_E_LISTEN,                 "Failed to put socket into listening mode."                    },
    { NUVO_E_EPOLL_CTL,              "Failed to add, delete, or modify epoll registration."         },
    { NUVO_E_SEND,                   "Attempt to send data on socket had an unrecoverable error."   },
    { NUVO_E_RECV,                   "Attempt to recv data from socket had an unrecoverable error." },
    { NUVO_E_CONN_CLOSED,            "Connection is closed."                                        },
    { NUVO_E_CONNECT,                "Failed to connect."                                           },
    { NUVO_E_BAD_TAG,                "Bad header tag"                                               },
    { 0,                             NULL                                                           }
};

/**
 * \def ERROR_STR_BUFFER_SIZE
 * Size of the buffer to pass to strerror_r which will not be used
 * because the universe hates me.
 */
#define ERROR_STR_BUFFER_SIZE    100

/**
 * \brief Return the error string for an nuvo_return_t in a malloced buffer.
 *
 * This routine mallocs a buffer to hold the string instead of using the
 * string returned from strerror_r, so it can be squirreled away in a protobuf
 * and freed with the protobuf free routine.
 * \param r The error number.
 * \returns malloced string containing the error.
 */
char *nuvo_status_alloc_error_str(nuvo_return_t r)
{
    char buffer[ERROR_STR_BUFFER_SIZE];

    memset(buffer, 0, ERROR_STR_BUFFER_SIZE);
#ifndef NDEBUG
    NUVO_PANIC_COND(r <= 0, "Bad error");
#endif
    if (NUVO_ERROR_IS_POSIX(r))
    {
        // Using GNU by default and GNU makes you pass the buffer just to torment you.
        // The answer comes back in the return value.
        char *err_str = strerror_r(r, buffer, ERROR_STR_BUFFER_SIZE);
        return (strdup(err_str));
    }
    else
    {
        struct nuvo_error_msg *err_msg = nuvo_error_msgs;
        while (err_msg->msg != NULL)
        {
            if (err_msg->error_num == r)
            {
                snprintf(buffer, ERROR_STR_BUFFER_SIZE, "%s : " NUVO_RETURN_FMT, err_msg->msg, r);
                return (strdup(buffer));
            }
            err_msg++;
        }
        snprintf(buffer, ERROR_STR_BUFFER_SIZE, "Unknown nuvo error: " NUVO_RETURN_FMT, r);
        return (strdup(buffer));
    }
}
