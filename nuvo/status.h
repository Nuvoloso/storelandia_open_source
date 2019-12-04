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
 * @file status.h
 * @brief Encapuslated status codes.
 *
 * Internal functions should return 0 on success and a negative number on errors.
 *
 */
#pragma once
#include <errno.h>
#include <inttypes.h>

/**
 * \brief return 0 or positive on success.
 *
 * On success return 0 or positive.  On failure, return a negative
 * that is a nuvo_error.
 */
typedef int_fast64_t nuvo_return_t;
#define NUVO_RETURN_FMT    "%" PRId64
#define NUVO_ERROR_IS_POSIX(e)    ((e) < NUVO_CUSTOM_ERROR)

enum nuvo_error
{
    NUVO_EPERM           = EPERM,
    NUVO_ENOENT          = ENOENT,
    NUVO_ESRCH           = ESRCH,
    NUVO_EINTR           = EINTR,
    NUVO_EIO             = EIO,
    NUVO_ENXIO           = ENXIO,
    NUVO_E2BIG           = E2BIG,
    NUVO_ENOEXEC         = ENOEXEC,
    NUVO_EBADF           = EBADF,
    NUVO_ECHILD          = ECHILD,
    NUVO_EAGAIN          = EAGAIN,
    NUVO_ENOMEM          = ENOMEM,
    NUVO_EACCES          = EACCES,
    NUVO_EFAULT          = EFAULT,
    NUVO_ENOTBLK         = ENOTBLK,
    NUVO_EBUSY           = EBUSY,
    NUVO_EEXIST          = EEXIST,
    NUVO_EXDEV           = EXDEV,
    NUVO_ENODEV          = ENODEV,
    NUVO_ENOTDIR         = ENOTDIR,
    NUVO_EISDIR          = EISDIR,
    NUVO_EINVAL          = EINVAL,
    NUVO_ENFILE          = ENFILE,
    NUVO_EMFILE          = EMFILE,
    NUVO_ENOTTY          = ENOTTY,
    NUVO_ETXTBSY         = ETXTBSY,
    NUVO_EFBIG           = EFBIG,
    NUVO_ENOSPC          = ENOSPC,
    NUVO_ESPIPE          = ESPIPE,
    NUVO_EROFS           = EROFS,
    NUVO_EMLINK          = EMLINK,
    NUVO_EPIPE           = EPIPE,
    NUVO_EDOM            = EDOM,
    NUVO_ERANGE          = ERANGE,
    NUVO_EDEADLK         = EDEADLK,
    NUVO_ENAMETOOLONG    = ENAMETOOLONG,
    NUVO_ENOLCK          = ENOLCK,
    NUVO_ENOSYS          = ENOSYS,
    NUVO_ENOTEMPTY       = ENOTEMPTY,
    NUVO_ELOOP           = ELOOP,
    NUVO_ENOMSG          = ENOMSG,
    NUVO_EIDRM           = EIDRM,
    NUVO_ECHRNG          = ECHRNG,
    NUVO_EL2NSYNC        = EL2NSYNC,
    NUVO_EL3HLT          = EL3HLT,
    NUVO_EL3RST          = EL3RST,
    NUVO_ELNRNG          = ELNRNG,
    NUVO_EUNATCH         = EUNATCH,
    NUVO_ENOCSI          = ENOCSI,
    NUVO_EL2HLT          = EL2HLT,
    NUVO_EBADE           = EBADE,
    NUVO_EBADR           = EBADR,
    NUVO_EXFULL          = EXFULL,
    NUVO_ENOANO          = ENOANO,
    NUVO_EBADRQC         = EBADRQC,
    NUVO_EBADSLT         = EBADSLT,
    NUVO_EBFONT          = EBFONT,
    NUVO_ENOSTR          = ENOSTR,
    NUVO_ENODATA         = ENODATA,
    NUVO_ETIME           = ETIME,
    NUVO_ENOSR           = ENOSR,
    NUVO_ENONET          = ENONET,
    NUVO_ENOPKG          = ENOPKG,
    NUVO_EREMOTE         = EREMOTE,
    NUVO_ENOLINK         = ENOLINK,
    NUVO_EADV            = EADV,
    NUVO_ESRMNT          = ESRMNT,
    NUVO_ECOMM           = ECOMM,
    NUVO_EPROTO          = EPROTO,
    NUVO_EMULTIHOP       = EMULTIHOP,
    NUVO_EDOTDOT         = EDOTDOT,
    NUVO_EBADMSG         = EBADMSG,
    NUVO_EOVERFLOW       = EOVERFLOW,
    NUVO_ENOTUNIQ        = ENOTUNIQ,
    NUVO_EBADFD          = EBADFD,
    NUVO_EREMCHG         = EREMCHG,
    NUVO_ELIBACC         = ELIBACC,
    NUVO_ELIBBAD         = ELIBBAD,
    NUVO_ELIBSCN         = ELIBSCN,
    NUVO_ELIBMAX         = ELIBMAX,
    NUVO_ELIBEXEC        = ELIBEXEC,
    NUVO_EILSEQ          = EILSEQ,
    NUVO_ERESTART        = ERESTART,
    NUVO_ESTRPIPE        = ESTRPIPE,
    NUVO_EUSERS          = EUSERS,
    NUVO_ENOTSOCK        = ENOTSOCK,
    NUVO_EDESTADDRREQ    = EDESTADDRREQ,
    NUVO_EMSGSIZE        = EMSGSIZE,
    NUVO_EPROTOTYPE      = EPROTOTYPE,
    NUVO_ENOPROTOOPT     = ENOPROTOOPT,
    NUVO_EPROTONOSUPPORT = EPROTONOSUPPORT,
    NUVO_ESOCKTNOSUPPORT = ESOCKTNOSUPPORT,
    NUVO_EOPNOTSUPP      = EOPNOTSUPP,
    NUVO_EPFNOSUPPORT    = EPFNOSUPPORT,
    NUVO_EAFNOSUPPORT    = EAFNOSUPPORT,
    NUVO_EADDRINUSE      = EADDRINUSE,
    NUVO_EADDRNOTAVAIL   = EADDRNOTAVAIL,
    NUVO_ENETDOWN        = ENETDOWN,
    NUVO_ENETUNREACH     = ENETUNREACH,
    NUVO_ENETRESET       = ENETRESET,
    NUVO_ECONNABORTED    = ECONNABORTED,
    NUVO_ECONNRESET      = ECONNRESET,
    NUVO_ENOBUFS         = ENOBUFS,
    NUVO_EISCONN         = EISCONN,
    NUVO_ENOTCONN        = ENOTCONN,
    NUVO_ESHUTDOWN       = ESHUTDOWN,
    NUVO_ETOOMANYREFS    = ETOOMANYREFS,
    NUVO_ETIMEDOUT       = ETIMEDOUT,
    NUVO_ECONNREFUSED    = ECONNREFUSED,
    NUVO_EHOSTDOWN       = EHOSTDOWN,
    NUVO_EHOSTUNREACH    = EHOSTUNREACH,
    NUVO_EALREADY        = EALREADY,
    NUVO_EINPROGRESS     = EINPROGRESS,
    NUVO_ESTALE          = ESTALE,
    NUVO_EUCLEAN         = EUCLEAN,
    NUVO_ENOTNAM         = ENOTNAM,
    NUVO_ENAVAIL         = ENAVAIL,
    NUVO_EISNAM          = EISNAM,
    NUVO_EREMOTEIO       = EREMOTEIO,
    NUVO_EDQUOT          = EDQUOT,
    NUVO_ENOMEDIUM       = ENOMEDIUM,
    NUVO_EMEDIUMTYPE     = EMEDIUMTYPE,
    NUVO_ECANCELED       = ECANCELED,
    NUVO_ENOKEY          = ENOKEY,
    NUVO_EKEYEXPIRED     = EKEYEXPIRED,
    NUVO_EKEYREVOKED     = EKEYREVOKED,
    NUVO_EKEYREJECTED    = EKEYREJECTED,
    NUVO_EOWNERDEAD      = EOWNERDEAD,
    NUVO_ENOTRECOVERABLE = ENOTRECOVERABLE,
    NUVO_ERFKILL         = ERFKILL,
    NUVO_EHWPOISON       = EHWPOISON,

    NUVO_CUSTOM_ERROR = 1000000000,      // Add nuvo general errors below here.
                                         // Also add error message in status.c
    NUVO_E_BAD_HASH,
    NUVO_E_BAD_MAGIC,
    NUVO_E_NO_SUPERBLOCK,
    NUVO_E_SIG_HANDLER,
    NUVO_E_NO_MODULE,
    NUVO_E_IO_RETRY_CNT_EXCEEDED,
    NUVO_E_BAD_STATE_TRANSITION,
    NUVO_E_CMD_BAD_ORDER,

    NUVO_ERROR_DEVICE = 1000000100,      // Device errors
    NUVO_E_NO_DEVICE,
    NUVO_E_NO_DEVICES_CLASS,
    NUVO_E_DEVICE_CLASS_BAD,
    NUVO_E_DEVICE_CLASS_CHANGED,
    NUVO_E_DEVICE_ALREADY_OPEN,
    NUVO_E_DEVICE_IN_USE,
    NUVO_E_DEVICE_NOT_USABLE,
    NUVO_E_DEVICE_TYPE_BAD,

    NUVO_ERROR_VOLUME = 1000000200,      // Volume errors
    NUVO_E_INVALID_VS_UUID,
    NUVO_E_ALLOC_VOLUME,
    NUVO_E_NO_VOLUME,
    NUVO_E_WRONG_VOL_TYPE,
    NUVO_E_REPLAYS_EXCEEDED,

    NUVO_ERROR_LUN = 1000000300,         // Lun errors
    NUVO_E_NO_LUN,
    NUVO_E_LUN_EXPORTED,
    NUVO_E_LUN_VOLUME_MISMATCH,

    NUVO_ERROR_PARCEL = 1000000400,      // Parcel errors
    NUVO_E_PARCEL_RANGE,
    NUVO_E_PARCEL_NOT_OPEN,
    NUVO_E_PARCEL_ALREADY_ALLOC,
    NUVO_E_PARCEL_ALREADY_OPEN,
    NUVO_E_PARCEL_ALREADY_CLOSED,
    NUVO_E_PARCEL_ALREADY_FREE,
    NUVO_E_PARCEL_UNUSABLE,
    NUVO_E_PARCEL_IN_USE,

    NUVO_ERROR_SEGMENT = 1000000500,     // Segment errors
    NUVO_E_OUT_OF_SEGMENT_STRUCTS,
    NUVO_E_NO_FREE_SEGMENTS,
    NUVO_E_NO_CLEANABLE_SEGMENT,

    NUVO_ERROR_CACHE = 1000000600,       // Cache errors
    NUVO_E_NO_CACHE,

    NUVO_ERROR_NETWORK = 1000000700,     // Network errors
    NUVO_E_SOCK_OPT,
    NUVO_E_BIND,
    NUVO_E_LISTEN,
    NUVO_E_EPOLL_CTL,
    NUVO_E_SEND,
    NUVO_E_RECV,
    NUVO_E_CONN_CLOSED,
    NUVO_E_CONNECT,
    NUVO_E_BAD_TAG
    // Add new errors to correct section to keep related error nums together
};

/**
 * \brief Return the error string for an nuvo_return_t in a malloced buffer.
 *
 * This routine mallocs a buffer to hold the string instead of using the
 * string returned from strerror_r, so it can be squirreled away in a protobuf
 * and freed with the protobuf free routine.
 * \param r The error number.
 * \returns malloced string containing the error.
 */
char *nuvo_status_alloc_error_str(nuvo_return_t r);
