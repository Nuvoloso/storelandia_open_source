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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <version_nuvo.h> // Generated header file with git version info
#include "nuvo.h"
#include "fault_inject.h"

// To get version info from binary: $ strings nuvo | grep nuvo_version
#define NUVO_VERSION_PREFIX_STR    "nuvo_version"

char *nuvo_git_hash_str;
char *nuvo_git_branch_str;
char *nuvo_make_timestamp_str;
char *nuvo_boot_timestamp_str;

int nuvo_alloc_version_str()
{
    nuvo_git_hash_str = strdup(NUVO_VERSION_PREFIX_STR "_hash "
                               VERSION_GIT_COMMIT_HASH);

    nuvo_git_branch_str = strdup(NUVO_VERSION_PREFIX_STR "_build "
                                 VERSION_GIT_BRANCH_NAME " : "
                                 VERSION_GIT_COMMIT_DATE);

    nuvo_make_timestamp_str = strdup(NUVO_VERSION_PREFIX_STR "_timestamp "
                                     VERSION_MAKE_TIMESTAMP);

    nuvo_boot_timestamp_str = nuvo_create_boot_time_str();

    if ((nuvo_git_hash_str == NULL) || (nuvo_git_branch_str == NULL) ||
        (nuvo_make_timestamp_str == NULL) || (nuvo_boot_timestamp_str == NULL))
    {
        nuvo_free_version_str();
        return (-1);
    }

    return (0);
}

void nuvo_free_version_str()
{
    if (nuvo_git_hash_str != NULL)
    {
        free(nuvo_git_hash_str);
    }

    if (nuvo_git_branch_str != NULL)
    {
        free(nuvo_git_branch_str);
    }

    if (nuvo_make_timestamp_str != NULL)
    {
        free(nuvo_make_timestamp_str);
    }

    if (nuvo_boot_timestamp_str != NULL)
    {
        free(nuvo_boot_timestamp_str);
    }

    return;
}

uint32_t nuvo_short_git_hash()
{
    char    *hash_str = strndup(VERSION_GIT_COMMIT_HASH, 7);
    uint32_t short_id = strtol(hash_str, NULL, 16);

    nuvo_return_t short_id_override = short_id;

    if (test_fi_inject_rc(TEST_FI_GENERAL_VER_GIT_COMMIT_HASH_OVERRIDE, test_fi_general_use_fi_get(), &short_id_override))
    {
        NUVO_ERROR_PRINT("Debug: TEST_FI_GENERAL_VER_GIT_COMMIT_HASH_OVERRIDE. Overriding version short id from 0x%7X to 0x%7X", short_id, (uint32_t)short_id_override);
        short_id = (uint32_t)short_id_override;
    }

    free(hash_str);
    return (short_id);
}

char *nuvo_create_boot_time_str()
{
    char *prefix_str = NUVO_VERSION_PREFIX_STR "_boot_time ";
    int   prefix_len = strlen(prefix_str);
    char  buf[prefix_len + NUVO_ISO8601_TS_SIZE];
    char  ts_buf[NUVO_ISO8601_TS_SIZE];

    snprintf(buf, NUVO_ISO8601_TS_SIZE + prefix_len, "%s%s", prefix_str,
             nuvo_get_iso8601_timestamp(ts_buf, sizeof(ts_buf)));

    return (strdup(buf));
}
