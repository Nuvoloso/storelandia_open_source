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

#include "nuvo.h"
#include <version_nuvo.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <sys/time.h>
#include <unistd.h>

void nuvo_error_print(const char *func, const char *file, int line, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    nuvo_error_vprint(func, file, line, NULL, format, args);
    va_end(args);
}

void nuvo_error_print_errno(const char *func, const char *file, int line, int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    nuvo_error_vprint_errno(func, file, line, err, format, args);
    va_end(args);
}

void nuvo_error_print_prepend(const char *func, const char *file, int line, const char *prepend_str, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    nuvo_error_vprint(func, file, line, prepend_str, format, args);
    va_end(args);
}

extern uint_fast64_t nuvo_get_timestamp();

char *nuvo_get_iso8601_timestamp(char *buf, size_t len)
{
    char            ts[sizeof("YYYY-MM-DDThh:mm:ss")];
    struct timespec now;
    struct tm       time_info;

    clock_gettime(CLOCK_REALTIME, &now);
    if (gmtime_r(&now.tv_sec, &time_info) == NULL ||
        strftime(ts, sizeof(ts), "%FT%T", &time_info) == 0)
    {
        /* If error formatting time, print tv_sec component in hex */
        snprintf(ts, sizeof(ts), "0x%lx", now.tv_sec);
    }
    /* Print millisecond component */
    snprintf(buf, len, "%s.%03ldZ", ts, now.tv_nsec / 1000000);

    return (buf);
}

void nuvo_error_vprint(const char *func, const char *file, int line, const char *prepend_str, const char *format, va_list args)
{
    char ts_buf[NUVO_ISO8601_TS_SIZE];

    fprintf(stderr, "%s %s at %s:%d ", nuvo_get_iso8601_timestamp(ts_buf, sizeof(ts_buf)), func, file, line);
    if (prepend_str)
    {
        fprintf(stderr, "%s", prepend_str);
    }

    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}

void nuvo_error_vprint_errno(const char *func, const char *file, int line, int err, const char *format, va_list args)
{
    char err_buf[1024];
    char ts_buf[NUVO_ISO8601_TS_SIZE];

    fprintf(stderr, "%s %s at %s:%d ", nuvo_get_iso8601_timestamp(ts_buf, sizeof(ts_buf)), func, file, line);
    vfprintf(stderr, format, args);
    fprintf(stderr, " : %s\n", strerror_r(err, err_buf, 1024));
}

void nuvo_backtrace(const char *func, const char *file, int line)
{
    unw_cursor_t  cursor;
    unw_context_t context;
    unw_word_t    ip, off;
    char          buf[1024];
    const char   *format;

    if (sizeof(uintptr_t) > 4)
    {
        format = "0x%016lx : %s+0x%lx";
    }
    else
    {
        format = "0x%08lx : %s+0x%lx";
    }

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    nuvo_error_print(func, file, line, "Git hash of nuvo build: %s", VERSION_GIT_COMMIT_HASH);
    nuvo_error_print(func, file, line, "Stack trace:");

    while (unw_step(&cursor) > 0)
    {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (ip == 0)
        {
            break;
        }
        unw_get_proc_name(&cursor, buf, sizeof(buf), &off);
        nuvo_error_print(func, file, line, format, ip, buf, off);
    }
}

void nuvo_panic(bool panic, const char *func, const char *file, int line, const char *format, ...)
{
    va_list args;

    va_start(args, format);

    nuvo_error_print(func, file, line, panic ? "PANIC!!" : "ASSERT FAIL");
    nuvo_error_vprint(func, file, line, NULL, format, args);

    nuvo_backtrace(func, file, line);

    if (panic)
    {
        abort();
    }
    va_end(args);
}

void nuvo_panic_errno(const char *func, const char *file, int line, int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);

    nuvo_error_print(func, file, line, "PANIC!!!");
    nuvo_error_vprint_errno(func, file, line, err, format, args);

    nuvo_backtrace(func, file, line);

    abort();

    va_end(args);
}

#define NUVO_LOG_MAX_MODULE_NAME    20

union nuvo_log nuvo_log =
{
    .api    = { "api",    0 },
    .fuse   = { "fuse",   0 },
    .logger = { "logger", 0 },
    .map    = { "map",    0 },
    .mfst   = { "mfst",   0 },
    .pm     = { "pm",     0 },
    .pr     = { "pr",     0 },
    .space  = { "space",  0 },
    .cache  = { "cache",  0 },
    .lun    = { "lun",    0 },
    .vol    = { "vol",    0 }
};

nuvo_return_t nuvo_log_set_level(const char *module_name, uint32_t level)
{
    unsigned index = 0;

    while (nuvo_log.modules[index].name != NULL)
    {
        if (strncmp(nuvo_log.modules[index].name, module_name, NUVO_LOG_MAX_MODULE_NAME) == 0)
        {
            nuvo_log.modules[index].level = level;
            return (0);
        }
        index++;
    }
    return (-NUVO_E_NO_MODULE);
}

/*
 * Set the time in seconds to suppress messages
 *
 */
struct nuvo_log_suppress log_suppress[] =
{
    // Hourly: 3600  (60*60);   Daily: 86400  (60*60*24)
    { 0, 3600,  0, 0 }, // SUP_GRP_NODE_STATUS; print node status every hour.
    { 0, 43200, 0, 0 }, // SUP_GRP_PRINT_VERSION; print version every 12 hours.
    { 0, 1,     0, 0 }, // SUP_GRP_PR_REQ_BUF_USED; print req/buf usage stats.
    { 0, 1,     0, 0 }, // SUP_GRP_PR_SHUTDOWN_PENDING; print shutdown pending.
    { 0, 1,     0, 0 }  // SUP_GRP_DEBUG_TMP; print tmp debug msg every sec.
};

static_assert((sizeof(log_suppress) / sizeof(log_suppress[0])) == SUP_GRP_MAX,
              "Did you add a log suppression group without updating log_suppress[]?");

void nuvo_log_check_sup_time(enum nuvo_log_suppress_group sup_group)
{
    uint_fast64_t now = nuvo_get_timestamp();

    if (now > log_suppress[sup_group].next_print_ts)
    {
        // If we didn't suppress any messages between prints, we
        // need to clear num_suppressed.
        if (log_suppress[sup_group].print_msg == 1)
        {
            log_suppress[sup_group].num_suppressed = 0;
        }

        log_suppress[sup_group].next_print_ts = now +
                                                log_suppress[sup_group].suppress_for_sec * 1000000000ull;
        log_suppress[sup_group].print_msg = 1;
    }
    else
    {
        if (log_suppress[sup_group].print_msg)
        {
            // After printing msg, this is the first set we are suppressing.
            log_suppress[sup_group].num_suppressed = 1;
        }
        else
        {
            log_suppress[sup_group].num_suppressed++;
        }
        log_suppress[sup_group].print_msg = 0;
    }
}

void nuvo_wait_for_gdb()
{
    volatile int done = 0;

    while (!done)
    {
        sleep(1);
    }
}
