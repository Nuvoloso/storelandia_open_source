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
 * @file nuvo.h
 * @brief System wide joy
 */
#pragma once
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>

#include "status.h"

/**
 * \brief Get a time stamp in nanoseconds since the Epoch.
 */
inline uint_fast64_t nuvo_get_timestamp()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_nsec + 1000000000ull * ts.tv_sec);
};

/**
 * \def NUVO_ISO8601_TS_SIZE
 * The minimum size of buffer needed to contain timestamp in ISO 8601 format
 *     at millisecond precision.
 */
#define NUVO_ISO8601_TS_SIZE    (sizeof("YYYY-MM-DDThh:mm:ss.SSSZ"))

/**
 * \brief Get a time stamp in ISO 8601 format. Caller provide buffer.
 */
char *nuvo_get_iso8601_timestamp(char *buf, size_t len);

/**
 * \brief Print function for printing to stderr.
 */
void nuvo_error_print(const char *func, const char *file, int line, const char *format, ...);

/**
 * \brief Variadic print function for printing to stderr.
 */
void nuvo_error_vprint(const char *func, const char *file, int line, const char *prepend_str, const char *format, va_list args);

/**
 * \brief Variadic print function for printing errors to stderr, as well as
 *      printing error message for an errno.
 */
void nuvo_error_print_errno(const char *func, const char *file, int line, int err, const char *format, ...);

/**
 * \brief Variadic print function for printing errors to stderr, as well as
 *      prepending a string before the message (and after the timestamp/file).
 */
void nuvo_error_print_prepend(const char *func, const char *file, int line, const char *prepend_str, const char *format, ...);

/**
 * \brief Print function for printing errors to stderr, as well as printing
 *      error message for an errno.
 */
void nuvo_error_vprint_errno(const char *func, const char *file, int line, int err, const char *format, va_list args);

/**
 * \brief A function to print the current stack trace.  Useful for debugging
 *      panic crashes.
 */
void nuvo_backtrace(const char *func, const char *file, int line);

/**
 * \brief A function that will print a message to stderr, print the stack
 *      trace, and abort the program.  Useful when code runs into unexpected
 *      error conditions.
 */
void nuvo_panic(bool panic, const char *func, const char *file, int line, const char *format, ...);

/**
 * \brief A function that will print a message to stderr, an error message
 *      for an errno, the stack trace, and abort the program.  Useful when
 *      code runs into unexpected error conditions.
 */
void nuvo_panic_errno(const char *func, const char *file, int line, int err, const char *format, ...);

/**
 * \def NUVO_ERROR_PRINT(format, ...)
 * Print the message to stderr.
 */
#define NUVO_ERROR_PRINT(...)    nuvo_error_print(__func__, __FILE__, __LINE__, __VA_ARGS__)

/**
 * \def NUVO_PRINT(format, ...)
 * Same as NUVO_ERROR_PRINT, but you dont want the name ERROR
 */

#define NUVO_PRINT(...)                nuvo_error_print(__func__, __FILE__, __LINE__, __VA_ARGS__)

/**
 * \def NUVO_ERROR_PRINT_ERRNO(err, format, ...)
 * Print the error number and message to stderr.
 */
#define NUVO_ERROR_PRINT_ERRNO(...)    nuvo_error_print_errno(__func__, __FILE__, __LINE__, __VA_ARGS__)

/**
 * \def NUVO_PANIC(msg)
 * Print the msg/stacktrace to stderr and abort.
 */
#define NUVO_PANIC(...)                nuvo_panic(true, __func__, __FILE__, __LINE__, __VA_ARGS__)

/**
 * \def NUVO_PANIC(msg)
 * Print the msg/stacktrace to stderr, does not abort
 */

/**
 * \def NUVO_PANIC_ERRNO(err, msg)
 * Print the msg to stderr with the string for the err and abort.
 */
#define NUVO_PANIC_ERRNO(...)      nuvo_panic_errno(__func__, __FILE__, __LINE__, __VA_ARGS__)

/**
 * \def NUVO_PANIC_COND(r, msg)
 * If r is true, print the msg to stderr and abort.
 */
#define NUVO_PANIC_COND(r, ...)    {                                     \
        if (r) {                                                         \
            nuvo_panic(true, __func__, __FILE__, __LINE__, __VA_ARGS__); \
        }                                                                \
}

#ifndef NDEBUG
#define NUVO_ASSERT(cond)          {                            \
        if (!(cond))  {                                         \
            NUVO_PANIC("ASSERT condition '" #cond "' failed."); \
        }                                                       \
}
#else
#define NUVO_ASSERT(cond)          (void)0
#endif


#define NUVO_ASSERT_LOG(cond, ...)      {                                \
        if (!(cond))  {                                                  \
            nuvo_panic(true, __func__, __FILE__, __LINE__, __VA_ARGS__); \
        }                                                                \
}


#define NUVO_DEBUG_ASSERT(cond, ...)    {                                 \
        if (!(cond))  {                                                   \
            nuvo_panic(false, __func__, __FILE__, __LINE__, __VA_ARGS__); \
        }                                                                 \
}

/**
 * \def NUVO_BLOCK_SIZE_BITS
 * The number of bits that can be encoded
 */
#define NUVO_BLOCK_SIZE_BITS    (12)

/**
 * \def NUVO_BLOCK_SIZE
 * The block size of all IO blocks in the nuvo software.
 */
#define NUVO_BLOCK_SIZE         (1 << NUVO_BLOCK_SIZE_BITS)

/**
 * \def NUVO_BLOCK_ROUND_UP(N)
 * Round N up to the next block size.
 */
#define NUVO_BLOCK_ROUND_UP(N)      (((N) + NUVO_BLOCK_SIZE - 1) & ~(NUVO_BLOCK_SIZE - 1))

/**
 * \def NUVO_BLOCK_ROUND_DOWN(N)
 * Round N down to the next block size.
 */
#define NUVO_BLOCK_ROUND_DOWN(N)    ((N)&(~NUVO_BLOCK_SIZE - 1))

#define UUID_UNPARSED_LEN    37

union nuvo_tag
{
    void         *ptr;
    uint_fast64_t uint;
};

struct nuvo_log_module {
    char *name;
    int   level;
};

#define NUVO_LOG_MODULES_MAX    20

/*
 * \brief Structure of all the module logging levels.
 *
 * If you add a structure here you should add a corresponding line in initialization in nuvo.c
 * Keep them in alphabetical order.
 */
union nuvo_log
{
    struct {
        struct nuvo_log_module api;
        struct nuvo_log_module fuse;
        struct nuvo_log_module logger;
        struct nuvo_log_module map;
        struct nuvo_log_module mfst;
        struct nuvo_log_module pm;
        struct nuvo_log_module pr;
        struct nuvo_log_module space;
        struct nuvo_log_module cache;
        struct nuvo_log_module lun;
        struct nuvo_log_module vol;
    };
    struct nuvo_log_module modules[NUVO_LOG_MODULES_MAX];
};

extern union nuvo_log nuvo_log;

#define NUVO_LOG(MODULE, LEVEL, ...)               {                     \
        if (nuvo_log.MODULE.level >= LEVEL) {                            \
            nuvo_error_print(__func__, __FILE__, __LINE__, __VA_ARGS__); \
        }                                                                \
}

/* log only if the condition (cond) is true */
#define NUVO_LOG_COND(MODULE, LEVEL, cond, ...)    {                     \
        if ((cond) && nuvo_log.MODULE.level >= LEVEL) {                  \
            nuvo_error_print(__func__, __FILE__, __LINE__, __VA_ARGS__); \
        }                                                                \
}

/*
 * \brief struct for tracking the suppression of certain log messages.
 */
struct nuvo_log_suppress {
    uint64_t next_print_ts;
    uint32_t suppress_for_sec;
    uint32_t num_suppressed : 31;
    uint32_t print_msg      : 1;
};
extern struct nuvo_log_suppress log_suppress[];

/*
 * \brief enum for the different groups of log messages that can be suppressed.
 *
 * When you add an entry, also add entry suppression values to log_suppress[] in
 * nuvo.c
 */
enum nuvo_log_suppress_group
{
    SUP_GRP_NODE_STATUS = 0,
    SUP_GRP_PRINT_VERSION,
    SUP_GRP_PR_REQ_BUF_USED,
    SUP_GRP_PR_SHUTDOWN_PENDING,
    SUP_GRP_DEBUG_TMP,
    SUP_GRP_MAX
};

/*
 * This will print a message only once per specified time period. This time
 * period is set in log_suppress, and is per suppression group. Since some
 * logging has entry/exit messages, you can create a group of related messages
 * to print. IE: you wouldn't want to see a started message without a completed
 * message and vice versa. So you can put them in the same suppression group.
 *
 * Only the first message in the group should set IS_FIRST to 1.  All others
 * should have IS_FIRST set to 0.
 */
#define NUVO_LOG_CAN_SUPPRESS(MODULE, LEVEL, SUP_GROUP, IS_FIRST, ...)    {      \
        NUVO_ASSERT(SUP_GROUP < SUP_GRP_MAX);                                    \
        if (nuvo_log.MODULE.level >= LEVEL) {                                    \
            if (IS_FIRST)                                                        \
            {                                                                    \
                nuvo_log_check_sup_time(SUP_GROUP);                              \
            }                                                                    \
            if (log_suppress[SUP_GROUP].print_msg)                               \
            {                                                                    \
                if (log_suppress[SUP_GROUP].num_suppressed)                      \
                {                                                                \
                    int  len = sizeof("(suppressed 4294967295U times): ");       \
                    char prepend_buf[len];                                       \
                    snprintf(prepend_buf, len, "(suppressed %d times): ",        \
                             log_suppress[SUP_GROUP].num_suppressed);            \
                    nuvo_error_print_prepend(__func__, __FILE__, __LINE__,       \
                                             prepend_buf, __VA_ARGS__);          \
                }                                                                \
                else                                                             \
                {                                                                \
                    nuvo_error_print(__func__, __FILE__, __LINE__, __VA_ARGS__); \
                }                                                                \
            }                                                                    \
        }                                                                        \
}

// The default Log Level for the module API, which currently prints everything
#define NUVO_LL_API          0

#define NUVO_LOG_UUID_FMT    "%02x%02x%02x%02x%c%02x%02x%c%02x%02x%c%02x%02x%c%02x%02x%02x%02x%02x%02x"
#define NUVO_LOG_UUID(u)    ((uint8_t *)u)[0], ((uint8_t *)u)[1], ((uint8_t *)u)[2], ((uint8_t *)u)[3], '-', \
    ((uint8_t *)u)[4], ((uint8_t *)u)[5], '-', ((uint8_t *)u)[6], ((uint8_t *)u)[7], '-',                    \
    ((uint8_t *)u)[8], ((uint8_t *)u)[9], '-', ((uint8_t *)u)[10], ((uint8_t *)u)[11],                       \
    ((uint8_t *)u)[12], ((uint8_t *)u)[13], ((uint8_t *)u)[14], ((uint8_t *)u)[15]

/**
 * \brief Set the level for the given module.
 *
 * \param module_name The name of the module.
 * \param level The level to set.
 * \retval 0 Success.
 * \retval -NUVO_E_NO_MODULE No module with that name.
 */
nuvo_return_t nuvo_log_set_level(const char *module_name, uint32_t level);

/**
 * \brief Checks if it's time to print messages for a log suppression group
 *
 * This sets a print flag so all messages of a suppression group will print.
 * It also takes care of the suppressed messages count and setting the
 * timestamp when we will allow the next print.
 *
 */
void nuvo_log_check_sup_time(enum nuvo_log_suppress_group sup_group);

/**
 * \brief wait in a loop for gdb to attach.
 *
 * If you call this function the code will hang until someone, somehow
 * clears the volatile variable inside.  gdb might help
 */
void nuvo_wait_for_gdb();
