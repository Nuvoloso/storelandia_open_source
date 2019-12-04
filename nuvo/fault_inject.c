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
#include "fault_inject.h"
#include "nuvo.h" // For NUVO_ERROR_PRINT()

// Comment out line to disable fault injection
#define NUVO_ENABLE_FAULT_INJECTION    1

// Global, can only be used for one error at a time.
struct test_fi_info *general_use_fi_info = NULL;

void test_fi_set_basic_error(struct test_fi_info *fi_info, uint32_t err_type,
                             int32_t err_rc, int32_t err_repeat_cnt,
                             int32_t err_skip_cnt)
{
#ifndef NUVO_ENABLE_FAULT_INJECTION
    return;
#endif

    uint32_t tmp_inject_cnt = fi_info->total_inject_cnt;

    if (fi_info == NULL)
    {
        return;
    }

    memset(fi_info, 0, sizeof(*fi_info));

    fi_info->total_inject_cnt = tmp_inject_cnt;
    fi_info->test_err_type = err_type;
    fi_info->test_err_rc = err_rc;
    fi_info->test_repeat_cnt = err_repeat_cnt;
    if (err_repeat_cnt < 0)
    {
        fi_info->infinite_repeat = true;
    }
    else
    {
        fi_info->infinite_repeat = false;
    }
    fi_info->test_skip_cnt = err_skip_cnt;

    NUVO_ERROR_PRINT("Fault Injection: Set Error. Type: %d , rc: %d , repeat: %d , skip %d",
                     err_type, err_rc, err_repeat_cnt, err_skip_cnt);
    return;
}

void test_fi_set_uuids(struct test_fi_info *fi_info, uuid_t node_uuid,
                       uuid_t vol_uuid, uuid_t dev_uuid)
{
    if (fi_info == NULL)
    {
        return;
    }

    uuid_copy(fi_info->node_uuid, node_uuid);
    uuid_copy(fi_info->vol_uuid, vol_uuid);
    uuid_copy(fi_info->dev_uuid, dev_uuid);
}

void test_fi_set_multiuse(struct test_fi_info *fi_info, uint64_t multiuse1,
                          uint64_t multiuse2, uint64_t multiuse3)
{
    if (fi_info == NULL)
    {
        return;
    }

    fi_info->multiuse1 = multiuse1;
    fi_info->multiuse2 = multiuse2;
    fi_info->multiuse3 = multiuse3;
}

bool test_fi_inject_rc(uint32_t err_type, struct test_fi_info *fi_info, nuvo_return_t *err_rc)
{
#ifndef NUVO_ENABLE_FAULT_INJECTION
    return (false);
#endif

    if ((fi_info == NULL) || (fi_info->test_err_type != err_type))
    {
        return (false);
    }

    // We have the right error type, now check if we need to inject
    // an error based on the repeat and skip cnt
    if (fi_info->test_skip_cnt > 0)
    {
        fi_info->test_skip_cnt--;
        return (false);
    }
    else if ((fi_info->test_repeat_cnt <= 0) && (!fi_info->infinite_repeat))
    {
        return (false);
    }

    NUVO_ERROR_PRINT("Fault Injection: INJECTED ERROR: %d; Modified return code from: %d to %d.",
                     err_type, *err_rc, fi_info->test_err_rc);
    fi_info->total_inject_cnt++;
    fi_info->test_repeat_cnt--;
    *err_rc = fi_info->test_err_rc;

    return (true);
}

bool test_fi_inject_vol_rc(uint32_t err_type, struct test_fi_info *fi_info,
                           uuid_t vol_uuid, nuvo_return_t *err_rc)
{
#ifndef NUVO_ENABLE_FAULT_INJECTION
    return (false);
#endif

    if ((fi_info == NULL) || (fi_info->test_err_type != err_type))
    {
        return (false);
    }

    // Allow empty uuids to be a wildcard, matching everything.
    if ((!uuid_is_null(fi_info->vol_uuid)) &&
        (uuid_compare(vol_uuid, fi_info->vol_uuid) != 0))
    {
        return (false);
    }

    return (test_fi_inject_rc(err_type, fi_info, err_rc));
}

bool test_fi_inject_node_rc(uint32_t err_type, struct test_fi_info *fi_info,
                            uuid_t node_uuid, nuvo_return_t *err_rc)
{
#ifndef NUVO_ENABLE_FAULT_INJECTION
    return (false);
#endif

    if ((fi_info == NULL) || (fi_info->test_err_type != err_type))
    {
        return (false);
    }

    // Allow empty uuids to be a wildcard, matching everything.
    if ((!uuid_is_null(fi_info->node_uuid)) &&
        (uuid_compare(node_uuid, fi_info->node_uuid) != 0))
    {
        return (false);
    }

    return (test_fi_inject_rc(err_type, fi_info, err_rc));
}

bool test_fi_inject_multi_use(uint32_t err_type, struct test_fi_info *fi_info,
                              uint64_t muse1, uint64_t muse2, uint64_t muse3,
                              nuvo_return_t *err_rc)
{
#ifndef NUVO_ENABLE_FAULT_INJECTION
    return (false);
#endif

    if ((fi_info == NULL) || (fi_info->test_err_type != err_type))
    {
        return (false);
    }

    if (muse1 != fi_info->multiuse1)
    {
        return (false);
    }

    if (muse2 != fi_info->multiuse2)
    {
        return (false);
    }

    if (muse3 != fi_info->multiuse3)
    {
        return (false);
    }

    return (test_fi_inject_rc(err_type, fi_info, err_rc));
}

struct test_fi_info *test_fi_general_use_fi_get(void)
{
#ifndef NUVO_ENABLE_FAULT_INJECTION
    return (false);
#endif

    if (general_use_fi_info == NULL)
    {
        general_use_fi_info = malloc(sizeof(struct test_fi_info));
        if (general_use_fi_info == NULL)
        {
            NUVO_ERROR_PRINT("Fault Injection: Failed to get generic trigger due to mem alloc fail");
            return (NULL);
        }
        memset(general_use_fi_info, 0, sizeof(*general_use_fi_info));
    }

    return (general_use_fi_info);
}

void nuvo_test_fi_free(void)
{
    if (general_use_fi_info != NULL)
    {
        free(general_use_fi_info);
        general_use_fi_info = NULL;
    }
}
