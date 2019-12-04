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
#include <check.h>
#include <nuvo.pb-c.h>
#include <errno.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdbool.h>

#include "nuvo_api_test.h"
#include "nuvo_fuse.h"

#include "nuvo.h"

#include "nuvo_vol_series.h"


/*
 * Define the globals
 */
nuvo_fs_t *fs = NULL;

/*
 * Define some static values so we can confirm that the
 * values passed in via messages get passed into the internal
 * handlers properly.
 */
static const char *uuid_str1 = (char *) "cdea706c-a0ef-11e7-abc4-cec278b6b50a";
static const char *uuid_str2 = (char *) "c5e424e8-a0f0-11e7-abc4-cec278b6b50a";
static const char *uuid_str3 = (char *) "c5e573ea-a0f0-11e7-abc4-cec278b6b50a";
static const char *uuid_str4 = (char *) "cdea706c-a0ef-11e7-abc4-cec278b6b50b";
static const char *uuid_str5 = (char *) "c5e424e8-a0f0-11e7-abc4-cec278b6b50c";
static const char *uuid_str6 = (char *) "c5e573ea-a0f0-11e7-abc4-cec278b6b50d";
static const char *dev_path1 = (char *) "/dev/xvdb";
static const char *dev_path2 = (char *) "/dev/xvdc";
static const char *dev_path3 = (char *) "/dev/xvdd";
static const char *dev_path4 = (char *) "/dev/xvde";
static const enum nuvo_dev_type dev_type1 = NUVO_DEV_TYPE_SSD;
static const enum nuvo_dev_type dev_type2 = NUVO_DEV_TYPE_SSD;
static const enum nuvo_dev_type dev_type3 = NUVO_DEV_TYPE_SSD;
static const enum nuvo_dev_type dev_type4 = NUVO_DEV_TYPE_HDD;
static const char *ipv4_str1 = (char *) "1.2.3.4";
static const char *ipv4_str2 = (char *) "5.6.7.8";
static const char *ipv4_str3 = (char *) "TodorSaysStringsAreFine";
static const uint32_t fixed_port1 = 22222u;
static const uint32_t fixed_port2 = 22223u;
static const uint32_t fixed_port3 = 22224u;
static const uint64_t parcel_size1 = 1073741824u;
static const uint64_t parcel_size2 = 1072693248u;
static const uint64_t parcel_size3 = 1071644672u;
static nuvo_return_t forced_rc = 0;

/***************************************************************************
 * USE_DEVICE tests
 */

/**
 * build an empty command for use_device. Handle all of the allocating of the
 * internal submessages. Just for the tests.
 */
static Nuvo__Cmd *build_use_device(unsigned int num_cmds)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REQ;
    cmd->n_use_device = num_cmds;
    if (num_cmds > 0)
    {
        cmd->use_device = (Nuvo__UseDevice **) calloc(num_cmds, sizeof (Nuvo__UseDevice *));
        cmd->use_device[0] = (Nuvo__UseDevice *) calloc(num_cmds, sizeof (Nuvo__UseDevice));
        nuvo__use_device__init(cmd->use_device[0]);
        for (unsigned int i = 1; i < num_cmds; i++)
        {
            cmd->use_device[i] = cmd->use_device[i-1]+1;
            nuvo__use_device__init(cmd->use_device[i]);
        }
    }
    return cmd;
}

static void free_use_device(Nuvo__Cmd *cmd)
{
    for (unsigned int i = 0; i < cmd->n_use_device; i++)
    {
        if (cmd->use_device[i]->path)
        {
            free(cmd->use_device[i]->path);
            cmd->use_device[i]->path = NULL;
        }
        if (cmd->use_device[i]->uuid)
        {
            free(cmd->use_device[i]->uuid);
            cmd->use_device[i]->uuid = NULL;
        }
        if (cmd->use_device[i]->explanation)
        {
            free(cmd->use_device[i]->explanation);
            cmd->use_device[i]->explanation = NULL;
        }
    }
    if (cmd->n_use_device)
    {
        free(cmd->use_device[0]);
        free(cmd->use_device);
    }
    free(cmd);
}

// Test that the  normal path works.
nuvo_return_t fake_use_device_success(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str1));
    ck_assert(0 == strcmp(dev_path1, path));
    ck_assert(dev_type1 == type);
    return 0;
}

nuvo_return_t fake_use_hdd_device_success(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str4));
    ck_assert(0 == strcmp(dev_path4, path));
    ck_assert(dev_type4 == type);
    return 0;
}

/**
 * This mirros the "preprocessing" of volume-specific commands in the API
 * dispatcher thread.
 */
Nuvo__Cmd *preprocess_cmd(Nuvo__Cmd *cmd)
{
    char *vol_uuid;
    uuid_t vs_uuid;
    Nuvo__Cmd *reply = NULL;

    if ((! (vol_uuid = get_vol_uuid(cmd))) ||
           (uuid_parse(vol_uuid, vs_uuid)))
    {
        // Unable to get or parse uuid
        prep_dispatcher_err_reply(cmd, NUVO_E_INVALID_VS_UUID, 0);
        reply = cmd;
    }

    return reply;
}


START_TEST(use_device_basic_hdd)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path4);
    cmd->use_device[0]->uuid = strdup(uuid_str4);
    cmd->use_device[0]->dev_type = dev_type4;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_hdd_device_success, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__OK == reply->use_device[0]->result);
    ck_assert(NULL == reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

START_TEST(use_device_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = dev_type1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_success, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__OK == reply->use_device[0]->result);
    ck_assert(NULL == reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

// The underlying code might tells us the device is not the one we're looking for
nuvo_return_t fake_use_device_already_open(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str2));
    ck_assert(0 == strcmp(dev_path2, path));
    ck_assert(dev_type2 == type);
    return -NUVO_E_DEVICE_ALREADY_OPEN;
}

START_TEST(use_device_device_already_open)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = dev_type1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_success, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__OK == reply->use_device[0]->result);
    ck_assert(NULL == reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

// Check that malformed messages work. Some, but not all, of these
// tests could be avoided if I used required fields in the protobuf,
// but people always seem to regret that later.
static void single_use_msg_invalid_check(Nuvo__Cmd *reply)
{
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__INVALID == reply->use_device[0]->result);
    ck_assert(NULL == reply->use_device[0]->explanation);
}

// Should not have a result already on the request
START_TEST(use_device_basic_has_result)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = dev_type1;
    cmd->use_device[0]->has_result = 1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_success, NULL);
    single_use_msg_invalid_check(reply);
    free_use_device(reply);
}
END_TEST


// A new request should not already have an explanation of what went wrong
START_TEST(use_device_basic_has_explanation)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = dev_type1;
    cmd->use_device[0]->explanation = strdup("boo");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_success, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__INVALID == reply->use_device[0]->result);
    free_use_device(reply);
}
END_TEST

// The uuid should be a, you know, uuid.
START_TEST(use_device_bad_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path2);
    cmd->use_device[0]->uuid = strdup("I'm not a uuid");
    cmd->use_device[0]->dev_type = dev_type2;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_success, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__INVALID == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "UUID invalid"));
    free_use_device(reply);
}
END_TEST

// If the table is full we might get an enomem error.
nuvo_return_t fake_use_device_enomem(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str3));
    ck_assert(0 == strcmp(dev_path3, path));
    ck_assert(dev_type3 == type);
    return -NUVO_ENOMEM;
}

START_TEST(use_device_table_full)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path3);
    cmd->use_device[0]->uuid = strdup(uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_enomem, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__NO_MEM == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Device table full"));
    free_use_device(reply);
}
END_TEST

// The underlying code might tells us the device is not the one we're looking for
nuvo_return_t fake_use_device_eexist(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str2));
    ck_assert(0 == strcmp(dev_path2, path));
    ck_assert(dev_type2 == type);
    return -NUVO_EEXIST;
}

START_TEST(use_device_device_exists)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path2);
    cmd->use_device[0]->uuid = strdup(uuid_str2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_eexist, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__UUID_MISMATCH ==reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Wrong uuid"));
    free_use_device(reply);
}
END_TEST

// The underlying code might tells us it couldn't find the device.
nuvo_return_t fake_use_device_nodevice(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str2));
    ck_assert(0 == strcmp(dev_path2, path));
    ck_assert(dev_type2 == type);
    return -NUVO_ENOENT;
}

START_TEST(use_device_unknown_device)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path2);
    cmd->use_device[0]->uuid = strdup(uuid_str2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_nodevice, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__DEVICE_NOT_FOUND == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Cannot find device"));
    free_use_device(reply);
}
END_TEST

// We might get some random error.  We shouldn't, but this is where they go to die.
nuvo_return_t fake_use_device_unknown_error(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str1));
    ck_assert(0 == strcmp(dev_path3, path));
    ck_assert(dev_type3 == type);
    return -NUVO_EPERM;
}

START_TEST(use_device_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path3);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_unknown_error, NULL);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__ERROR == reply->use_device[0]->result);
    ck_assert((char *)NULL != reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

// Now test multiple requests within one message.
nuvo_return_t fake_use_device_multi(const char *path, const uuid_t uuid, const enum nuvo_dev_type type)
{
    static unsigned int iter = 0;
    char uuid_str[UUID_UNPARSED_LEN];
    switch(iter)
    {
    case 0:
        uuid_unparse(uuid, uuid_str);
        ck_assert(0 == strcmp(uuid_str, uuid_str1));
        ck_assert(0 == strcmp(dev_path1, path));
        ck_assert(dev_type1 == type);
        iter++;
        return -NUVO_ENOMEM;
    case 1:
        uuid_unparse(uuid, uuid_str);
        ck_assert(0 == strcmp(uuid_str, uuid_str2));
        ck_assert(0 == strcmp(dev_path2, path));
        ck_assert(dev_type2 == type);
        iter++;
        return 0;
    case 2:
        uuid_unparse(uuid, uuid_str);
        ck_assert(0 == strcmp(uuid_str, uuid_str3));
        ck_assert(0 == strcmp(dev_path3, path));
        ck_assert(dev_type3 == type);
        iter++;
        return -NUVO_ENOENT;
    }
    return -NUVO_EEXIST;
}

START_TEST(use_device_multi_request)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(3);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = dev_type1;
    cmd->use_device[1]->path = strdup(dev_path2);
    cmd->use_device[1]->uuid = strdup(uuid_str2);
    cmd->use_device[1]->dev_type = dev_type2;
    cmd->use_device[2]->path = strdup(dev_path3);
    cmd->use_device[2]->uuid = strdup(uuid_str3);
    cmd->use_device[2]->dev_type = dev_type3;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, fake_use_device_multi, NULL);

    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 3u);

    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__NO_MEM == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Device table full"));

    ck_assert(0 != reply->use_device[1]->has_result);
    ck_assert(0 ==reply->use_device[1]->result);
    ck_assert(NULL == reply->use_device[1]->explanation);

    ck_assert(0 != reply->use_device[2]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__DEVICE_NOT_FOUND == reply->use_device[2]->result);
    ck_assert(0 == strcmp(reply->use_device[2]->explanation, "Cannot find device"));
    free_use_device(reply);
}
END_TEST

struct {
    char            name[256];
    uuid_t          uuid;
    nuvo_return_t   retval;
} fake_cache_device_expected;

void set_fake_cache_device_expected(const char *name, const char *uuid_str, nuvo_return_t retval)
{
    strncpy(fake_cache_device_expected.name, name, 256);
    uuid_parse(uuid_str, fake_cache_device_expected.uuid);
    fake_cache_device_expected.retval = retval;
}

nuvo_return_t fake_use_device_cache_work(const char *name, const uuid_t uuid, uint64_t *cache_size, uint64_t *alloc_size)
{
    ck_assert(0 == strncmp(name, fake_cache_device_expected.name, 256));
    ck_assert(0 == uuid_compare(uuid, fake_cache_device_expected.uuid));
    *cache_size = 0;
    *alloc_size = 0;
    return fake_cache_device_expected.retval;
}

START_TEST(use_cache_device_success)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__OK == reply->use_device[0]->result);
    ck_assert((char *)NULL == reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_basic_has_result)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path2);
    cmd->use_device[0]->uuid = strdup(uuid_str2);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    cmd->use_device[0]->has_result = 1;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__INVALID == reply->use_device[0]->result);
    ck_assert((char *)NULL == reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_basic_has_explanation)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path3);
    cmd->use_device[0]->uuid = strdup(uuid_str3);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    cmd->use_device[0]->explanation = strdup("boo");
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__INVALID == reply->use_device[0]->result);
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_bad_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path1);
    cmd->use_device[0]->uuid = strdup("I'm not a uuid");
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__INVALID == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "UUID invalid"));
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_table_full)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path2);
    cmd->use_device[0]->uuid = strdup(uuid_str2);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, -NUVO_ENOMEM);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__NO_MEM == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Device table full"));
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_device_exists)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path3);
    cmd->use_device[0]->uuid = strdup(uuid_str3);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, -NUVO_EEXIST);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__UUID_MISMATCH == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Wrong uuid"));
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_unknown_device)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path3);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, -NUVO_ENOENT);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__DEVICE_NOT_FOUND == reply->use_device[0]->result);
    ck_assert(0 == strcmp(reply->use_device[0]->explanation, "Cannot find device"));
    free_use_device(reply);
}
END_TEST

START_TEST(use_cache_device_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_use_device(1);
    cmd->use_device[0]->path = strdup(dev_path3);
    cmd->use_device[0]->uuid = strdup(uuid_str1);
    cmd->use_device[0]->dev_type = NUVO__USE_DEVICE__DEV_TYPE__EPH;
    set_fake_cache_device_expected(cmd->use_device[0]->path, cmd->use_device[0]->uuid, -NUVO_EBFONT);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_use_device(&api_req, NULL, fake_use_device_cache_work);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_use_device == 1u);
    ck_assert(0 != reply->use_device[0]->has_result);
    ck_assert(NUVO__USE_DEVICE__RESULT__ERROR == reply->use_device[0]->result);
    ck_assert((char *)NULL != reply->use_device[0]->explanation);
    free_use_device(reply);
}
END_TEST

/***************************************************************************
 * FORMAT_DEVICE tests
 * These feel really similar to the USE DEVICE tests
 */

/**
 * build an empty command for format_device. Handle all of the allocating of the
 * internal submessages. Just for the tests.
 */
static Nuvo__Cmd *build_format_device(unsigned int num_cmds)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REQ;
    cmd->n_format_device = num_cmds;
    if (num_cmds > 0)
    {
        cmd->format_device = (Nuvo__FormatDevice **) calloc(num_cmds, sizeof (Nuvo__FormatDevice *));
        cmd->format_device[0] = (Nuvo__FormatDevice *) calloc(num_cmds, sizeof (Nuvo__FormatDevice));
        nuvo__format_device__init(cmd->format_device[0]);
        for (unsigned int i = 1; i < num_cmds; i++)
        {
            cmd->format_device[i] = cmd->format_device[i-1]+1;
            nuvo__format_device__init(cmd->format_device[i]);
        }
    }
    return cmd;
}

static void free_format_device(Nuvo__Cmd *cmd)
{
    for (unsigned int i = 0; i < cmd->n_format_device; i++)
    {
        if (cmd->format_device[i]->path)
        {
            free(cmd->format_device[i]->path);
            cmd->format_device[i]->path = NULL;
        }
        if (cmd->format_device[i]->uuid)
        {
            free(cmd->format_device[i]->uuid);
            cmd->format_device[i]->uuid = NULL;
        }
        if (cmd->format_device[i]->explanation)
        {
            free(cmd->format_device[i]->explanation);
            cmd->format_device[i]->explanation = NULL;
        }
    }
    if (cmd->n_format_device)
    {
        free(cmd->format_device[0]);
        free(cmd->format_device);
    }
    free(cmd);
}

// Test that the  normal path works.
nuvo_return_t fake_format_device_success(const char *path, const uuid_t uuid, uint64_t parcel_size)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str1));
    ck_assert(0 == strcmp(dev_path1, path));
    ck_assert(parcel_size1 == parcel_size);
    return 0;
}

static Nuvo__Cmd *build_single_format_device(const char *path, const char *uuid_str, uint64_t parcel_size)
{
    Nuvo__Cmd *cmd = build_format_device(1);
    cmd->format_device[0]->path = strdup(path);
    cmd->format_device[0]->uuid = strdup(uuid_str);
    cmd->format_device[0]->parcel_size = parcel_size;
    return cmd;
}

START_TEST(format_device_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_single_format_device(dev_path1, uuid_str1, parcel_size1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_format_device(&api_req, fake_format_device_success);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_format_device == 1u);
    ck_assert(0 != reply->format_device[0]->has_result);
    ck_assert(NUVO__FORMAT_DEVICE__RESULT__OK == reply->format_device[0]->result);
    ck_assert(NULL == reply->format_device[0]->explanation);
    free_format_device(reply);
}
END_TEST

// Check that malformed messages work. Some, but not all, of these
// tests could be avoided if I used required fields in the protobuf,
// but people always seem to regret that later.
static void single_format_msg_invalid_check(Nuvo__Cmd *reply)
{
    ck_assert(NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_format_device == 1u);
    ck_assert(0 != reply->format_device[0]->has_result);
    ck_assert(NUVO__FORMAT_DEVICE__RESULT__INVALID == reply->format_device[0]->result);
    ck_assert(NULL == reply->format_device[0]->explanation);
}

// should not have a result already on the request
START_TEST(format_device_basic_has_result)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_single_format_device(dev_path1, uuid_str1, parcel_size1);
    cmd->format_device[0]->has_result = 1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_format_device(&api_req, fake_format_device_success);
    single_format_msg_invalid_check(reply);
    free_format_device(reply);
}
END_TEST


// A new request should not already have an explanation of what went wrong
START_TEST(format_device_basic_has_explanation)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_single_format_device(dev_path1, uuid_str1, parcel_size1);
    cmd->format_device[0]->explanation = strdup("Format has to be a as eparate command");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_format_device(&api_req, fake_format_device_success);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_format_device == 1u);
    ck_assert(0 != reply->format_device[0]->has_result);
    ck_assert(NUVO__FORMAT_DEVICE__RESULT__INVALID == reply->format_device[0]->result);
    ck_assert((char *) NULL != reply->format_device[0]->explanation);
    free_format_device(reply);
}
END_TEST

// The uuid should be a, you know, uuid.
START_TEST(format_device_basic_bad_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_single_format_device(dev_path2, "I'm not a uuid", parcel_size2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_format_device(&api_req, fake_format_device_success);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_format_device == 1u);
    ck_assert(0 != reply->format_device[0]->has_result);
    ck_assert(NUVO__FORMAT_DEVICE__RESULT__INVALID == reply->format_device[0]->result);
    ck_assert(0 == strcmp(reply->format_device[0]->explanation, "UUID invalid"));
    free_format_device(reply);
}
END_TEST

// The underlying code might tells us it couldn't find the device.
nuvo_return_t fake_format_device_nodevice(const char *path, const uuid_t uuid, uint64_t parcel_size)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str3));
    ck_assert(0 == strcmp(dev_path3, path));
    ck_assert(parcel_size3 == parcel_size);
    return -NUVO_ENOENT;
}

START_TEST(format_device_basic_no_device)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_single_format_device(dev_path3, uuid_str3, parcel_size3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_format_device(&api_req, fake_format_device_nodevice);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_format_device == 1u);
    ck_assert(0 != reply->format_device[0]->has_result);
    ck_assert(NUVO__FORMAT_DEVICE__RESULT__DEVICE_NOT_FOUND == reply->format_device[0]->result);
    ck_assert(0 == strcmp(reply->format_device[0]->explanation, "Cannot find device"));
    free_format_device(reply);
}
END_TEST

// We might get some random error.  We shouldn't, but this is where Todor sent me to die.
nuvo_return_t fake_format_device_error(const char *path, const uuid_t uuid, uint64_t parcel_size)
{
    char uuid_str[UUID_UNPARSED_LEN];
    uuid_unparse(uuid, uuid_str);
    ck_assert(0 == strcmp(uuid_str, uuid_str3));
    ck_assert(0 == strcmp(dev_path3, path));
    ck_assert(parcel_size3 == parcel_size);
    return -NUVO_EBUSY;
}

START_TEST(format_device_basic_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_single_format_device(dev_path3, uuid_str3, parcel_size3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_format_device(&api_req, fake_format_device_error);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REPLY == reply->msg_type);
    ck_assert(reply->n_format_device == 1u);
    ck_assert(0 != reply->format_device[0]->has_result);
    ck_assert(NUVO__FORMAT_DEVICE__RESULT__ERROR == reply->format_device[0]->result);
    ck_assert((char *) NULL != reply->format_device[0]->explanation);
    free_format_device(reply);
}
END_TEST

// TODO Now test multiple requests within one message.

/******************************************************************************************
 * DEVICE_LOCATION tests
 */
Nuvo__Cmd *build_device_location(unsigned int num_cmds)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REQ;
    cmd->n_device_location = num_cmds;
    if (num_cmds > 0)
    {
        cmd->device_location = (Nuvo__DeviceLocation **) calloc(num_cmds, sizeof (Nuvo__DeviceLocation *));
        cmd->device_location[0] = (Nuvo__DeviceLocation *) calloc(num_cmds, sizeof (Nuvo__DeviceLocation));
        nuvo__device_location__init(cmd->device_location[0]);
        for (unsigned int i = 1; i < num_cmds; i++)
        {
            cmd->device_location[i] = cmd->device_location[i-1]+1;
            nuvo__device_location__init(cmd->device_location[i]);
        }
    }
    return cmd;
}

static void free_device_location(Nuvo__Cmd *cmd)
{
    if (cmd->device_location)
    {
        for (unsigned int i = 0; i < cmd->n_device_location; i++)
        {
            Nuvo__DeviceLocation *dev_loc = cmd->device_location[i];
            if (dev_loc->device)
            {
                free(dev_loc->device);
                dev_loc->device = NULL;
            }
            if (dev_loc->node)
            {
                free(dev_loc->node);
                dev_loc->node = NULL;
            }
            if (dev_loc->explanation)
            {
                free(dev_loc->explanation);
                dev_loc->explanation = NULL;
            }
        }

        free(cmd->device_location[0]);
        free(cmd->device_location);
    }
    free(cmd);
}

static nuvo_return_t fake_device_location_basic(const uuid_t dev_uuid, const uuid_t node_uuid)
{
    char verbose_dev_uuid[UUID_UNPARSED_LEN];
    char verbose_node_uuid[UUID_UNPARSED_LEN];
    uuid_unparse(dev_uuid, verbose_dev_uuid);
    uuid_unparse(node_uuid, verbose_node_uuid);
    ck_assert(0 == strcmp(verbose_dev_uuid, uuid_str1));
    ck_assert(0 == strcmp(verbose_node_uuid, uuid_str2));
    return 0;
}

START_TEST(device_location_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup(uuid_str1);
    cmd->device_location[0]->node = strdup(uuid_str2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(1u ==  reply->n_device_location);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__OK == reply->device_location[0]->result);
    ck_assert(NULL == reply->device_location[0]->explanation);
    free_device_location(reply);
}
END_TEST

static void single_msg_dev_loc_invalid_check(Nuvo__Cmd *reply)
{
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(1u ==  reply->n_device_location);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__INVALID == reply->device_location[0]->result);
    ck_assert(NULL == reply->device_location[0]->explanation);
}

START_TEST(device_location_basic_has_result)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup(uuid_str1);
    cmd->device_location[0]->node = strdup(uuid_str2);
    cmd->device_location[0]->has_result = 1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_basic);
    single_msg_dev_loc_invalid_check(reply);
    free_device_location(reply);
}
END_TEST

START_TEST(device_location_basic_has_explanation)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup(uuid_str1);
    cmd->device_location[0]->node = strdup(uuid_str2);
    cmd->device_location[0]->explanation = strdup("boo");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(reply->n_device_location == 1u);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__INVALID == reply->device_location[0]->result);
    free_device_location(reply);
}
END_TEST

START_TEST(device_location_bad_uuid1)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup(uuid_str1);
    cmd->device_location[0]->node = strdup("You wanted a uuid");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(reply->n_device_location == 1u);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__INVALID == reply->device_location[0]->result);
    ck_assert(0 == strcmp(reply->device_location[0]->explanation, "UUID invalid"));
    free_device_location(reply);
}
END_TEST

START_TEST(device_location_bad_uuid2)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup("You wanted a uuid");
    cmd->device_location[0]->node = strdup(uuid_str1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(reply->n_device_location == 1u);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__INVALID == reply->device_location[0]->result);
    ck_assert(0 == strcmp(reply->device_location[0]->explanation, "UUID invalid"));
    free_device_location(reply);
}
END_TEST

// If the table is full we might get an enomem error.
nuvo_return_t fake_device_location_enomem(const uuid_t dev_uuid, const uuid_t node_uuid)
{
    (void) dev_uuid;
    (void) node_uuid;
    return -NUVO_ENOMEM;
}

START_TEST(device_location_table_full)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup(uuid_str2);
    cmd->device_location[0]->node = strdup(uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_enomem);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(reply->n_device_location == 1u);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__NO_MEM == reply->device_location[0]->result);
    ck_assert(0 == strcmp(reply->device_location[0]->explanation, "Table full"));
    free_device_location(reply);
}
END_TEST

// Test generic error
// If the table is full we might get an enomem error.
nuvo_return_t fake_device_location_error(const uuid_t dev_uuid, const uuid_t node_uuid)
{
    (void) dev_uuid;
    (void) node_uuid;
    return -NUVO_EBFONT;
}

START_TEST(device_location_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(1);
    cmd->device_location[0]->device = strdup(uuid_str3);
    cmd->device_location[0]->node = strdup(uuid_str2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_error);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(reply->n_device_location == 1u);
    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__ERROR == reply->device_location[0]->result);
    ck_assert((char *) NULL != reply->device_location[0]->explanation);
    free_device_location(reply);
}
END_TEST

static nuvo_return_t fake_device_location_multi(const uuid_t dev_uuid, const uuid_t node_uuid)
{
    (void) dev_uuid;
    (void) node_uuid;
    static int iter = 0;
    switch (iter)
    {
    case 0:
        iter = 1;
        return -NUVO_ENOMEM;
    case 1:
        iter = 2;
        return 0;
    default:
        return -NUVO_EBFONT;
    }
    return 0;
}

// Test multiple requests in one, with different errors.
START_TEST(device_location_multi)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_device_location(3);
    cmd->device_location[0]->device = strdup(uuid_str1);
    cmd->device_location[0]->node = strdup(uuid_str2);
    cmd->device_location[1]->device = strdup(uuid_str3);
    cmd->device_location[1]->node = strdup(uuid_str4);
    cmd->device_location[2]->device = strdup(uuid_str5);
    cmd->device_location[2]->node = strdup(uuid_str6);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_device_location(&api_req, fake_device_location_multi);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REPLY == reply->msg_type);
    ck_assert(3u == reply->n_device_location);

    ck_assert(0 != reply->device_location[0]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__NO_MEM == reply->device_location[0]->result);
    ck_assert(0 == strcmp("Table full", reply->device_location[0]->explanation));

    ck_assert(0 != reply->device_location[1]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__OK == reply->device_location[1]->result);
    ck_assert(NULL == reply->device_location[1]->explanation);

    ck_assert(0 != reply->device_location[2]->has_result);
    ck_assert(NUVO__DEVICE_LOCATION__RESULT__ERROR == reply->device_location[2]->result);
    ck_assert((char *)NULL != reply->device_location[2]->explanation);

    free_device_location(reply);
}
END_TEST

// Test NODE LOCATION messages.

/**
 * Build an empty node location message.  Handle the unpleasant malloc stuff.
 */
static Nuvo__Cmd *build_node_location(unsigned int num_cmds)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REQ;
    cmd->n_node_location = num_cmds;
    if (num_cmds > 0)
    {
        cmd->node_location = (Nuvo__NodeLocation **) calloc(num_cmds, sizeof (Nuvo__NodeLocation *));
        cmd->node_location[0] = (Nuvo__NodeLocation *) calloc(num_cmds, sizeof (Nuvo__NodeLocation));
        for (unsigned int i = 1; i < num_cmds; i++)
        {
            cmd->node_location[i] = cmd->node_location[i-1]+1;
        }
        for (unsigned int i = 0; i < num_cmds; i++)
        {
            nuvo__node_location__init(cmd->node_location[i]);
        }
    }
    return cmd;
}

static void free_node_location(Nuvo__Cmd *cmd)
{
    if (cmd->node_location)
    {
        for (unsigned int i = 0; i < cmd->n_node_location; i++)
        {
            Nuvo__NodeLocation *nloc = cmd->node_location[i];
            if (nloc->uuid)
            {
                free(nloc->uuid);
                nloc->uuid = NULL;
            }
            if (nloc->ipv4_addr)
            {
                free(nloc->ipv4_addr);
                nloc->ipv4_addr = NULL;
            }
            if (nloc->explanation)
            {
                free(nloc->explanation);
                nloc->explanation = NULL;
            }
        }
        free(cmd->node_location[0]);
        free(cmd->node_location);
    }
    free(cmd);
}

static nuvo_return_t fake_node_location_basic(const uuid_t node_uuid, const char *ipv4_addr, uint16_t port)
{
    char verbose_node_uuid[UUID_UNPARSED_LEN];
    uuid_unparse(node_uuid, verbose_node_uuid);
    ck_assert(0 == strcmp(verbose_node_uuid, uuid_str1));
    ck_assert(0 == strcmp(ipv4_addr, ipv4_str1));
    ck_assert(fixed_port1 ==  port);
    return 0;
}

static Nuvo__Cmd* build_basic_node_command()
{
    Nuvo__Cmd *cmd = build_node_location(1);
    cmd->node_location[0]->uuid = strdup(uuid_str1);
    cmd->node_location[0]->ipv4_addr = strdup(ipv4_str1);
    cmd->node_location[0]->port = fixed_port1;
    return cmd;
}

START_TEST(node_location_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_basic_node_command();
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__OK == reply->node_location[0]->result);
    ck_assert(NULL == reply->node_location[0]->explanation);
    free_node_location(reply);
}
END_TEST

// Test malformed request

// has result
START_TEST(node_location_has_result)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_basic_node_command();
    cmd->node_location[0]->has_result = 1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__INVALID ==reply->node_location[0]->result);
    ck_assert(NULL == reply->node_location[0]->explanation);
    free_node_location(reply);
}
END_TEST

// has explanation
START_TEST(node_location_has_explanation)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_basic_node_command();
    cmd->node_location[0]->explanation = strdup("I was told this would not be on the test");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__INVALID ==reply->node_location[0]->result);
    free_node_location(reply);
}
END_TEST

// port out of range (protobufs doesn't have uint16 - ugh)
START_TEST(node_location_port_out_of_range)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_basic_node_command();
    cmd->node_location[0]->port = 100000;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__INVALID ==reply->node_location[0]->result);
    ck_assert(NULL == reply->node_location[0]->explanation);
    free_node_location(reply);
}
END_TEST

// Invalid UUID
START_TEST(node_location_invalid_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_basic_node_command();
    free(cmd->node_location[0]->uuid);
    cmd->node_location[0]->uuid = strdup("Technically, this is unique");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__INVALID ==reply->node_location[0]->result);
    ck_assert(0 == strcmp(reply->node_location[0]->explanation, "UUID invalid"));
    free_node_location(reply);
}
END_TEST

static nuvo_return_t fake_node_location_enomem(const uuid_t node_uuid, const char *ipv4_addr, uint16_t port)
{
    (void) node_uuid;
    (void) ipv4_addr;
    (void) port;
    return -NUVO_ENOMEM;
}

// Table full
START_TEST(node_location_table_full)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_node_location(1);
    cmd->node_location[0]->uuid = strdup(uuid_str1);
    cmd->node_location[0]->ipv4_addr = strdup(ipv4_str1);
    cmd->node_location[0]->port = fixed_port1;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_enomem);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(0 == strcmp(reply->node_location[0]->explanation, "Table full"));
    free_node_location(reply);
}
END_TEST

static nuvo_return_t fake_node_location_ebusy(const uuid_t node_uuid, const char *ipv4_addr, uint16_t port)
{
    (void) node_uuid;
    (void) ipv4_addr;
    (void) port;
    return -NUVO_EBUSY;
}

// random error
START_TEST(node_location_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_node_location(1);
    cmd->node_location[0]->uuid = strdup(uuid_str1);
    cmd->node_location[0]->ipv4_addr = strdup(ipv4_str2);
    cmd->node_location[0]->port = fixed_port2;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_ebusy);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 1u);
    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__ERROR == reply->node_location[0]->result);
    ck_assert((char *)NULL != reply->node_location[0]->explanation);
    free_node_location(reply);
}
END_TEST

// multi
static nuvo_return_t fake_node_location_multi(const uuid_t node_uuid, const char *ipv4_addr, uint16_t port)
{
    (void) node_uuid;
    (void) ipv4_addr;
    (void) port;
    static int iter = 0;
    iter++;
    if (iter == 1)
    {
        return -NUVO_ENOMEM;
    }
    return 0;
}

START_TEST(node_location_multi)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_node_location(3);

    // No port out of range in first one - worker won't get called
    cmd->node_location[0]->uuid = strdup(uuid_str1);
    cmd->node_location[0]->port = 100000;

    // We'll return -Enomem on this one (first call)
    cmd->node_location[1]->uuid = strdup(uuid_str1);
    cmd->node_location[1]->ipv4_addr = strdup(ipv4_str2);
    cmd->node_location[1]->port = fixed_port2;

    // This one is ok.
    cmd->node_location[2]->uuid = strdup(uuid_str3);
    cmd->node_location[2]->ipv4_addr = strdup(ipv4_str3);
    cmd->node_location[2]->port = fixed_port3;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_node_location(&api_req, fake_node_location_multi);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REPLY ==  reply->msg_type);
    ck_assert(reply->n_node_location == 3u);

    ck_assert(0 != reply->node_location[0]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__INVALID == reply->node_location[0]->result);
    ck_assert((char *)NULL == reply->node_location[0]->explanation);

    ck_assert(0 != reply->node_location[1]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__NO_MEM == reply->node_location[1]->result);
    ck_assert(0 == strcmp(reply->node_location[1]->explanation, "Table full"));

    ck_assert(0 != reply->node_location[2]->has_result);
    ck_assert(NUVO__NODE_LOCATION__RESULT__OK == reply->node_location[2]->result);
    ck_assert(NULL == reply->node_location[2]->explanation);
    free_node_location(reply);
}
END_TEST

// Tests for passthrough volume. Protobuf only has one, not an array, so set up is simpler
static Nuvo__Cmd *build_open_passthrough(const char *uuid, const char *path, uint64_t size)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ;
    cmd->open_pass_through_vol = (Nuvo__OpenPassThroughVolume*) malloc(sizeof(*cmd->open_pass_through_vol));
    nuvo__open_pass_through_volume__init(cmd->open_pass_through_vol);
    if (uuid)
    {
        cmd->open_pass_through_vol->uuid = strdup(uuid);
    }
    if (path)
    {
        cmd->open_pass_through_vol->path = strdup(path);
    }
    cmd->open_pass_through_vol->size = size;

    return cmd;
}

static void free_passthrough(Nuvo__Cmd *cmd)
{
    if (cmd->open_pass_through_vol)
    {
        if (cmd->open_pass_through_vol->uuid)
        {
            free(cmd->open_pass_through_vol->uuid);
        }
        if (cmd->open_pass_through_vol->path)
        {
            free(cmd->open_pass_through_vol->path);
        }
        if (cmd->open_pass_through_vol->explanation)
        {
            free(cmd->open_pass_through_vol->explanation);
        }
        free(cmd->open_pass_through_vol);
    }
    free(cmd);
}

#define GB (1024*1024*1024ull)

static nuvo_return_t passthrough_work_basic(struct nuvo_vol *vol, const char *path, size_t size)
{
    (void) vol;
    ck_assert((char *) NULL != path);
    (void) fs;
    if (size % 4096 != 0)
    {
        return -EINVAL;
    }
    return 0;
}

START_TEST(open_passthrough_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_passthrough(uuid_str1, "/dev/xvdb", 100 * GB);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_passthrough_open_volume(&api_req, passthrough_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_pass_through_vol->has_result);
    ck_assert(NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__OK == reply->open_pass_through_vol->result);
    ck_assert(NULL == reply->open_pass_through_vol->explanation);
    free_passthrough(reply);
}
END_TEST

START_TEST(open_passthrough_bad_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_passthrough("New Storelandia", "/dev/xvdb", 100 * GB);
    cmd->open_pass_through_vol->size += 12;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_passthrough_open_volume(&api_req, passthrough_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_pass_through_vol->has_result);
    ck_assert(NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__INVALID == reply->open_pass_through_vol->result);
    ck_assert((char *) NULL != reply->open_pass_through_vol->explanation);
    free_passthrough(reply);
}
END_TEST

START_TEST(open_passthrough_weird_size)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_passthrough(uuid_str2, "/dev/xvdb", 100 * GB);
    cmd->open_pass_through_vol->size += 12;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_passthrough_open_volume(&api_req, passthrough_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_pass_through_vol->has_result);
    ck_assert(NUVO__OPEN_PASS_THROUGH_VOLUME__RESULT__ERROR == reply->open_pass_through_vol->result);
    ck_assert((char *) NULL != reply->open_pass_through_vol->explanation);
    free_passthrough(reply);
}
END_TEST

// Test for export lun
static Nuvo__Cmd *build_export_lun(const char *vs_uuid, const char *pit_uuid, const char *export_name, int writable)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REQ;
    cmd->export_lun = (Nuvo__ExportLun*) malloc(sizeof(*cmd->export_lun));
    nuvo__export_lun__init(cmd->export_lun);
    if (vs_uuid)
    {
        cmd->export_lun->vol_series_uuid = strdup(vs_uuid);
    }
    if (pit_uuid)
    {
        cmd->export_lun->pit_uuid = strdup(pit_uuid);
    }
    if (export_name)
    {
        cmd->export_lun->export_name = strdup(export_name);
    }
    cmd->export_lun->writable = (writable != 0);

    return cmd;
}

static void free_export_lun(Nuvo__Cmd *cmd)
{
    if (cmd->export_lun)
     {
        if (cmd->export_lun->vol_series_uuid)
        {
            free(cmd->export_lun->vol_series_uuid);
        }
        if (cmd->export_lun->pit_uuid)
        {
            free(cmd->export_lun->pit_uuid);
        }
        if (cmd->export_lun->export_name)
        {
            free(cmd->export_lun->export_name);
        }
        if (cmd->export_lun->explanation)
        {
            free(cmd->export_lun->explanation);
        }
        free(cmd->export_lun);
    }
    free(cmd);
}

static nuvo_return_t export_lun_work_basic(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name, int writable)
{
    (void) vol;
    (void) pit_uuid;
    ck_assert((char *) NULL != lun_name);
    (void) writable;
    return 0;
}

START_TEST(export_lun_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_export_lun(uuid_str1, uuid_str2, "volumeland", 1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_export_lun(&api_req, export_lun_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REPLY == reply->msg_type);
    ck_assert(0 != reply->export_lun->has_result);
    ck_assert(NUVO__EXPORT_LUN__RESULT__OK == reply->export_lun->result);
    ck_assert(NULL == reply->export_lun->explanation);
    free_export_lun(reply);
}
END_TEST

START_TEST(export_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_export_lun("Not a uuid", uuid_str2, "volumeland", 1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_export_lun(&api_req, export_lun_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REPLY == reply->msg_type);
    ck_assert(0 != reply->export_lun->has_result);
    ck_assert(NUVO__EXPORT_LUN__RESULT__BAD_UUID == reply->export_lun->result);
    ck_assert(NULL != reply->export_lun->explanation);
    free_export_lun(reply);
}
END_TEST

START_TEST(export_bad_puuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_export_lun(uuid_str1, "Not a uuid", "volumeland", 1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_export_lun(&api_req, export_lun_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REPLY == reply->msg_type);
    ck_assert(0 != reply->export_lun->has_result);
    ck_assert(NUVO__EXPORT_LUN__RESULT__BAD_UUID == reply->export_lun->result);
    ck_assert(NULL != reply->export_lun->explanation);
    free_export_lun(reply);
}
END_TEST

// Test for unexport lun
static Nuvo__Cmd *build_unexport_lun(const char *vs_uuid, const char *pit_uuid, const char *export_name)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REQ;
    cmd->unexport_lun = (Nuvo__UnexportLun*) malloc(sizeof(*cmd->unexport_lun));
    nuvo__unexport_lun__init(cmd->unexport_lun);
    if (vs_uuid)
    {
        cmd->unexport_lun->vol_series_uuid = strdup(vs_uuid);
    }
    if (pit_uuid)
    {
        cmd->unexport_lun->pit_uuid = strdup(pit_uuid);
    }
    if (export_name)
    {
        cmd->unexport_lun->export_name = strdup(export_name);
    }

    return cmd;
}

static void free_unexport_lun(Nuvo__Cmd *cmd)
{
    if (cmd->unexport_lun)
    {
        if (cmd->unexport_lun->vol_series_uuid)
        {
            free(cmd->unexport_lun->vol_series_uuid);
        }
        if (cmd->unexport_lun->pit_uuid)
        {
            free(cmd->unexport_lun->pit_uuid);
        }
        if (cmd->unexport_lun->export_name)
        {
            free(cmd->unexport_lun->export_name);
        }
        if (cmd->unexport_lun->explanation)
        {
            free(cmd->unexport_lun->explanation);
        }
        free(cmd->unexport_lun);
    }
    free(cmd);
}

static nuvo_return_t unexport_lun_work_basic(struct nuvo_vol *vol, const uuid_t pit_uuid, const char *lun_name)
{
    (void) vol;
    (void) pit_uuid;
    ck_assert((char *) NULL != lun_name);
    return 0;
}

START_TEST(unexport_lun_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_unexport_lun(uuid_str1, uuid_str2, "volumeland");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = nuvo_api_unexport_lun(&api_req, unexport_lun_work_basic);
    ck_assert(NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REPLY == reply->msg_type);
    ck_assert(0 != reply->unexport_lun->has_result);
    ck_assert(NUVO__UNEXPORT_LUN__RESULT__OK == reply->unexport_lun->result);
    ck_assert(NULL == reply->unexport_lun->explanation);
    free_unexport_lun(reply);
}
END_TEST

START_TEST(unexport_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_unexport_lun("Not a uuid", "pit uuid", "volumeland");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_unexport_lun(&api_req, unexport_lun_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REPLY == reply->msg_type);
    ck_assert(0 != reply->unexport_lun->has_result);
    ck_assert(NUVO__UNEXPORT_LUN__RESULT__BAD_UUID == reply->unexport_lun->result);
    ck_assert(NULL != reply->unexport_lun->explanation);
    free_unexport_lun(reply);
}
END_TEST

START_TEST(unexport_bad_puuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_unexport_lun(uuid_str1, "Not a uuid", "volumeland");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_unexport_lun(&api_req, unexport_lun_work_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REPLY == reply->msg_type);
    ck_assert(0 != reply->unexport_lun->has_result);
    ck_assert(NUVO__UNEXPORT_LUN__RESULT__BAD_UUID == reply->unexport_lun->result);
    ck_assert(NULL != reply->unexport_lun->explanation);
    free_unexport_lun(reply);
}
END_TEST

// Tests for creating a parcel volume
static Nuvo__Cmd *build_create_volume(const char *vs_uuid, const char *rd_uuid, const char *rp_uuid, bool log_vol, uint64_t size)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ;
    cmd->create_volume = (Nuvo__CreateVolume*) malloc(sizeof(*cmd->create_volume));
    nuvo__create_volume__init(cmd->create_volume);
    if (vs_uuid)
    {
        cmd->create_volume->vol_series_uuid = strdup(vs_uuid);
    }
    if (rd_uuid)
    {
        cmd->create_volume->root_device_uuid = strdup(rd_uuid);
    }
    if (rp_uuid)
    {
        cmd->create_volume->root_parcel_uuid = strdup(rp_uuid);
    }
    if (log_vol)
    {
        cmd->create_volume->log_volume = true;
        cmd->create_volume->has_size = true;
        cmd->create_volume->size = size;
    }
    else
    {
        cmd->create_volume->log_volume = false;
    }
    return cmd;
}

static void free_create_volume(Nuvo__Cmd *cmd)
{
    if (cmd->create_volume)
    {
        if (cmd->create_volume->vol_series_uuid)
        {
            free(cmd->create_volume->vol_series_uuid);
        }
        if (cmd->create_volume->root_device_uuid)
        {
            free(cmd->create_volume->root_device_uuid);
        }
        if (cmd->create_volume->root_parcel_uuid)
        {
            free(cmd->create_volume->root_parcel_uuid);
        }
        if (cmd->create_volume->explanation)
        {
            free(cmd->create_volume->explanation);
        }
        free(cmd->create_volume);
    }
    free(cmd);
}

static nuvo_return_t create_vol_basic(struct nuvo_vol *vol, const uuid_t rd_uuid, uuid_t rp_uuid, bool log_vol, uint64_t size)
{
    (void) vol;
    (void) rd_uuid;
    (void) rp_uuid;
    (void) log_vol;
    (void) size;
    return 0;
}

START_TEST(create_volume_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume(uuid_str1, uuid_str2, uuid_str6, false, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, create_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__OK == reply->create_volume->result);
    ck_assert(NULL == reply->create_volume->explanation);
    ck_assert_str_eq(reply->create_volume->root_parcel_uuid, uuid_str6);
    free_create_volume(reply);
}
END_TEST

START_TEST(create_volume_bad_vs_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume("I'm not a uuid", uuid_str2, uuid_str6, false, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, create_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__BAD_UUID == reply->create_volume->result);
    ck_assert(NULL != reply->create_volume->explanation);
    free_create_volume(reply);
}
END_TEST

START_TEST(create_volume_bad_rd_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume(uuid_str1, "I'm not a uuid either", uuid_str6, false, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, create_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__BAD_UUID == reply->create_volume->result);
    ck_assert(NULL != reply->create_volume->explanation);
    free_create_volume(reply);
}
END_TEST

START_TEST(create_volume_bad_rp_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume(uuid_str2, uuid_str1, "not even close", false, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, create_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__BAD_UUID == reply->create_volume->result);
    ck_assert(NULL != reply->create_volume->explanation);
    free_create_volume(reply);
}
END_TEST

START_TEST(create_log_volume_size_0)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume(uuid_str2, uuid_str1, uuid_str6, true, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, create_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__INVALID == reply->create_volume->result);
    ck_assert(NULL != reply->create_volume->explanation);
    free_create_volume(reply);
}
END_TEST

START_TEST(create_log_volume_size_wonky)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume(uuid_str2, uuid_str1, uuid_str6, true, 1024*1024ull - 1);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, create_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__INVALID == reply->create_volume->result);
    ck_assert(NULL != reply->create_volume->explanation);
    free_create_volume(reply);
}
END_TEST

static nuvo_return_t fake_create_volume_enomem(struct nuvo_vol *vol, const uuid_t rd_uuid, uuid_t rp_uuid, bool log_vol, uint64_t size)
{
    (void) vol;
    (void) rd_uuid;
    (void) rp_uuid;
    (void) log_vol;
    (void) size;
    return -NUVO_ENOMEM;
}

START_TEST(create_volume_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_volume(uuid_str2, uuid_str1, uuid_str6, false, 0);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_volume(&api_req, fake_create_volume_enomem);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_volume->has_result);
    ck_assert(NUVO__CREATE_VOLUME__RESULT__ERROR == reply->create_volume->result);
    ck_assert(NULL != reply->create_volume->explanation);
    free_create_volume(reply);
}
END_TEST

// Tests for opening a parcel volume
static Nuvo__Cmd *build_open_volume(const char *vs_uuid, const char *rd_uuid, const char *rp_uuid, bool log_vol)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ;
    cmd->open_volume = (Nuvo__OpenVolume*) malloc(sizeof(*cmd->open_volume));
    nuvo__open_volume__init(cmd->open_volume);
    if (vs_uuid)
    {
        cmd->open_volume->vol_series_uuid = strdup(vs_uuid);
    }
    if (rd_uuid)
    {
        cmd->open_volume->root_device_uuid = strdup(rd_uuid);
    }
    if (rp_uuid)
    {
        cmd->open_volume->root_parcel_uuid = strdup(rp_uuid);
    }
    cmd->open_volume->log_volume = log_vol;
    return cmd;
}

static void free_open_parcel_vol(Nuvo__Cmd *cmd)
{
    if (cmd->open_volume)
    {
        if (cmd->open_volume->vol_series_uuid)
        {
            free(cmd->open_volume->vol_series_uuid);
        }
        if (cmd->open_volume->root_device_uuid)
        {
            free(cmd->open_volume->root_device_uuid);
        }
        if (cmd->open_volume->root_parcel_uuid)
        {
            free(cmd->open_volume->root_parcel_uuid);
        }
        if (cmd->open_volume->explanation)
        {
            free(cmd->open_volume->explanation);
        }
        free(cmd->open_volume);
    }
    free(cmd);
}

static nuvo_return_t open_parcel_vol_basic(struct nuvo_vol *vol, const uuid_t rd_uuid, const uuid_t rp_uuid, bool log_vol)
{
    (void) vol;
    (void) rd_uuid;
    (void) rp_uuid;
    (void) log_vol;
    return 0;
}

START_TEST(open_parcel_volume_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_volume(uuid_str1, uuid_str2, uuid_str3, false);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_open_volume(&api_req, open_parcel_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_volume->has_result);
    ck_assert(NUVO__OPEN_VOLUME__RESULT__OK == reply->open_volume->result);
    ck_assert(NULL == reply->open_volume->explanation);
    free_open_parcel_vol(reply);
}
END_TEST

START_TEST(open_parcel_volume_bad_vs_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_volume("I'm not a uuid", uuid_str2, uuid_str3, false);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_open_volume(&api_req, open_parcel_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_volume->has_result);
    ck_assert(NUVO__OPEN_VOLUME__RESULT__BAD_UUID == reply->open_volume->result);
    ck_assert(NULL != reply->open_volume->explanation);
    free_open_parcel_vol(reply);
}
END_TEST

START_TEST(open_parcel_volume_bad_rd_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_volume(uuid_str2, "me too", uuid_str3, false);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_open_volume(&api_req, open_parcel_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_volume->has_result);
    ck_assert(NUVO__OPEN_VOLUME__RESULT__BAD_UUID == reply->open_volume->result);
    ck_assert(NULL != reply->open_volume->explanation);
    free_open_parcel_vol(reply);
}
END_TEST

START_TEST(open_parcel_volume_bad_rp_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_volume(uuid_str2, uuid_str3, "me three", false);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_open_volume(&api_req, open_parcel_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_volume->has_result);
    ck_assert(NUVO__OPEN_VOLUME__RESULT__BAD_UUID == reply->open_volume->result);
    ck_assert(NULL != reply->open_volume->explanation);
    free_open_parcel_vol(reply);
}
END_TEST

static nuvo_return_t fake_open_parcel_volume_enomem(struct nuvo_vol *vol, const uuid_t rd_uuid, const uuid_t rp_uuid, bool log_vol)
{
    (void) vol;
    (void) rd_uuid;
    (void) rp_uuid;
    (void) log_vol;
    return -NUVO_ENOMEM;
}

START_TEST(open_parcel_volume_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_open_volume(uuid_str2, uuid_str1, uuid_str4, false);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_open_volume(&api_req, fake_open_parcel_volume_enomem);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REPLY == reply->msg_type);
    ck_assert(0 != reply->open_volume->has_result);
    ck_assert(NUVO__OPEN_VOLUME__RESULT__ERROR == reply->open_volume->result);
    ck_assert(NULL != reply->open_volume->explanation);
    free_open_parcel_vol(reply);
}
END_TEST

// Tests for destroying a parcel volume
static Nuvo__Cmd *build_destroy_vol(const char *vs_uuid, const char *rd_uuid, const char *rp_uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ;
    cmd->destroy_vol = (Nuvo__DestroyVol*) malloc(sizeof(*cmd->destroy_vol));
    nuvo__destroy_vol__init(cmd->destroy_vol);
    if (vs_uuid)
    {
        cmd->destroy_vol->vol_uuid = strdup(vs_uuid);
    }
    if (rd_uuid)
    {
        cmd->destroy_vol->root_device_uuid = strdup(rd_uuid);
    }
    if (rp_uuid)
    {
        cmd->destroy_vol->root_parcel_uuid = strdup(rp_uuid);
    }
    return cmd;
}

static void free_destroy_vol(Nuvo__Cmd *cmd)
{
    if (cmd->destroy_vol)
    {
        if (cmd->destroy_vol->vol_uuid)
        {
            free(cmd->destroy_vol->vol_uuid);
        }
        if (cmd->destroy_vol->root_device_uuid)
        {
            free(cmd->destroy_vol->root_device_uuid);
        }
        if (cmd->destroy_vol->root_parcel_uuid)
        {
            free(cmd->destroy_vol->root_parcel_uuid);
        }
        if (cmd->destroy_vol->explanation)
        {
            free(cmd->destroy_vol->explanation);
        }
        free(cmd->destroy_vol);
    }
    free(cmd);
}

static nuvo_return_t destroy_vol_basic(bool log_volume, struct nuvo_vol *vol, const uuid_t rd_uuid, const uuid_t rp_uuid)
{
    (void) log_volume;
    (void) vol;
    (void) rd_uuid;
    (void) rp_uuid;
    return 0;
}

START_TEST(destroy_volume_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_destroy_vol(uuid_str1, uuid_str2, uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_destroy_vol(&api_req, destroy_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY == reply->msg_type);
    ck_assert(0 != reply->destroy_vol->has_result);
    ck_assert(NUVO__DESTROY_VOL__RESULT__OK == reply->destroy_vol->result);
    ck_assert(NULL == reply->destroy_vol->explanation);
    free_destroy_vol(reply);
}
END_TEST

START_TEST(destroy_volume_bad_vs_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_destroy_vol("I'm not a uuid", uuid_str2, uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_destroy_vol(&api_req, destroy_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY == reply->msg_type);
    ck_assert(0 != reply->destroy_vol->has_result);
    ck_assert(NUVO__DESTROY_VOL__RESULT__BAD_UUID == reply->destroy_vol->result);
    ck_assert(NULL != reply->destroy_vol->explanation);
    free_destroy_vol(reply);
}
END_TEST

START_TEST(destroy_volume_bad_rd_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_destroy_vol(uuid_str2, "me too", uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_destroy_vol(&api_req, destroy_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY == reply->msg_type);
    ck_assert(0 != reply->destroy_vol->has_result);
    ck_assert(NUVO__DESTROY_VOL__RESULT__BAD_UUID == reply->destroy_vol->result);
    ck_assert(NULL != reply->destroy_vol->explanation);
    free_destroy_vol(reply);
}
END_TEST

START_TEST(destroy_volume_bad_rp_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_destroy_vol(uuid_str2, uuid_str3, "me three");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_destroy_vol(&api_req, destroy_vol_basic);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY == reply->msg_type);
    ck_assert(0 != reply->destroy_vol->has_result);
    ck_assert(NUVO__DESTROY_VOL__RESULT__BAD_UUID == reply->destroy_vol->result);
    ck_assert(NULL != reply->destroy_vol->explanation);
    free_destroy_vol(reply);
}
END_TEST

static nuvo_return_t fake_destroy_volume_enomem(bool log_volume, struct nuvo_vol *vol, const uuid_t rd_uuid, const uuid_t rp_uuid)
{
    (void) log_volume;
    (void) vol;
    (void) rd_uuid;
    (void) rp_uuid;
    return -ENOMEM;
}

START_TEST(destroy_volume_random_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_destroy_vol(uuid_str2, uuid_str1, uuid_str4);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_destroy_vol(&api_req, fake_destroy_volume_enomem);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REPLY == reply->msg_type);
    ck_assert(0 != reply->destroy_vol->has_result);
    ck_assert(NUVO__DESTROY_VOL__RESULT__ERROR == reply->destroy_vol->result);
    ck_assert(NULL != reply->destroy_vol->explanation);
    free_destroy_vol(reply);
}
END_TEST

// Tests for allocating parcels to a volume.
static Nuvo__Cmd *build_alloc_parcels(const char *vs_uuid, const char *dev_uuid, const uint64_t num)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REQ;
    cmd->alloc_parcels = (Nuvo__AllocParcels*) malloc(sizeof(*cmd->alloc_parcels));
    nuvo__alloc_parcels__init(cmd->alloc_parcels);
    if (vs_uuid)
    {
        cmd->alloc_parcels->vol_series_uuid = strdup(vs_uuid);
    }
    if (dev_uuid)
    {
        cmd->alloc_parcels->device_uuid = strdup(dev_uuid);
    }
    cmd->alloc_parcels->num = num;
    return cmd;
}

static void free_alloc_parcels_vol(Nuvo__Cmd *cmd)
{
    if (cmd->alloc_parcels)
    {
        if (cmd->alloc_parcels->vol_series_uuid)
        {
            free(cmd->alloc_parcels->vol_series_uuid);
        }
        if (cmd->alloc_parcels->device_uuid)
        {
            free(cmd->alloc_parcels->device_uuid);
        }
        if (cmd->alloc_parcels->explanation)
        {
            free(cmd->alloc_parcels->explanation);
        }
        free(cmd->alloc_parcels);
    }
    free(cmd);
}

static nuvo_return_t alloc_parcels_basic_work(struct nuvo_vol *vol, const uuid_t dev_uuid, const uint64_t num)
{
    (void) vol;
    (void) dev_uuid;
    (void) num;
    return 0;
}

START_TEST(alloc_parcels_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_alloc_parcels(uuid_str1, uuid_str2, 2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_alloc_parcels(&api_req, alloc_parcels_basic_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REPLY == reply->msg_type);
    ck_assert(0 != reply->alloc_parcels->has_result);
    ck_assert(NUVO__ALLOC_PARCELS__RESULT__OK == reply->alloc_parcels->result);
    ck_assert(NULL == reply->alloc_parcels->explanation);
    free_alloc_parcels_vol(reply);
}
END_TEST

START_TEST(alloc_parcels_bad_vs)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_alloc_parcels("I'm not a volume", uuid_str2, 2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_alloc_parcels(&api_req, alloc_parcels_basic_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REPLY == reply->msg_type);
    ck_assert(0 != reply->alloc_parcels->has_result);
    ck_assert(NUVO__ALLOC_PARCELS__RESULT__BAD_UUID == reply->alloc_parcels->result);
    ck_assert(NULL != reply->alloc_parcels->explanation);
    free_alloc_parcels_vol(reply);
}
END_TEST

START_TEST(alloc_parcels_bad_device)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_alloc_parcels(uuid_str1, "I'm not a device", 2);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_alloc_parcels(&api_req, alloc_parcels_basic_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REPLY == reply->msg_type);
    ck_assert(0 != reply->alloc_parcels->has_result);
    ck_assert(NUVO__ALLOC_PARCELS__RESULT__BAD_UUID == reply->alloc_parcels->result);
    ck_assert(NULL != reply->alloc_parcels->explanation);
    free_alloc_parcels_vol(reply);
}
END_TEST

// Tests for closing volume to a volume. TODO

// Tests for getting stats
static Nuvo__Cmd *build_get_stats(const bool device, const bool is_read, const bool clear, const char *uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ;
    cmd->get_stats = (Nuvo__GetStats*) malloc(sizeof(*cmd->get_stats));
    nuvo__get_stats__init(cmd->get_stats);
    if (uuid)
    {
        cmd->get_stats->uuid = strdup(uuid);
    }
    cmd->get_stats->type = device ? NUVO__GET_STATS__TYPE__DEVICE : NUVO__GET_STATS__TYPE__VOLUME;
    cmd->get_stats->rw = is_read ? NUVO__GET_STATS__READ_WRITE__READ : NUVO__GET_STATS__READ_WRITE__WRITE;
    cmd->get_stats->clear = clear;
    return cmd;
}

static void free_get_stats(Nuvo__Cmd *cmd)
{
    if (cmd->get_stats)
    {
        if (cmd->get_stats->uuid)
        {
            free(cmd->get_stats->uuid);
        }
        if (cmd->get_stats->explanation)
        {
            free(cmd->get_stats->explanation);
        }
        if (cmd->get_stats->stats)
        {
            if (cmd->get_stats->stats->size_hist)
            {
                free(cmd->get_stats->stats->size_hist);
            }
            if (cmd->get_stats->stats->latency_hist)
            {
                free(cmd->get_stats->stats->latency_hist);
            }
            free(cmd->get_stats->stats);
        }
        free(cmd->get_stats);
    }
    free(cmd);
}

static nuvo_return_t get_stats_basic_work(const Nuvo__GetStats__Type type,
                                    const Nuvo__GetStats__ReadWrite rw,
                                    const bool clear,
                                    const uuid_t uuid,
                                    Nuvo__GetStats__Statistics **stats)
{
    (void) type;
    (void) rw;
    (void) clear;
    (void) uuid;
    *stats = nuvo_build_getstats_stats();

    return 0;
}

static nuvo_return_t get_stats_error_work(const Nuvo__GetStats__Type type,
                                    const Nuvo__GetStats__ReadWrite rw,
                                    const bool clear,
                                    const uuid_t uuid,
                                    Nuvo__GetStats__Statistics **stats)
{
    (void) type;
    (void) rw;
    (void) clear;
    (void) uuid;
    *stats = NULL;

    return -EINVAL;
}

START_TEST(get_stats_basic)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_get_stats(true, true, false, uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_get_stats(&api_req, get_stats_basic_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_STATS_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_stats->has_result);
    ck_assert(NUVO__GET_STATS__RESULT__OK == reply->get_stats->result);
    ck_assert(NULL == reply->get_stats->explanation);
    free_get_stats(reply);
}
END_TEST

START_TEST(get_stats_bad_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_get_stats(true, true, false, "I never heard of what.");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_get_stats(&api_req, get_stats_basic_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_STATS_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_stats->has_result);
    ck_assert(NUVO__GET_STATS__RESULT__BAD_UUID == reply->get_stats->result);
    ck_assert(NULL != reply->get_stats->explanation);
    free_get_stats(reply);
}
END_TEST

START_TEST(get_stats_error)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_get_stats(true, true, false, uuid_str3);
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_get_stats(&api_req, get_stats_error_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_STATS_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_stats->has_result);
    ck_assert(NUVO__GET_STATS__RESULT__ERROR == reply->get_stats->result);
    ck_assert(NULL != reply->get_stats->explanation);
    free_get_stats(reply);
}
END_TEST

START_TEST(get_stats_has_explanation)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_get_stats(true, true, false, uuid_str3);
    cmd->get_stats->explanation = strdup("I should not be here");
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_get_stats(&api_req, get_stats_error_work);
    }
    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_STATS_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_stats->has_result);
    ck_assert(NUVO__GET_STATS__RESULT__INVALID == reply->get_stats->result);
    ck_assert(NULL != reply->get_stats->explanation);
    free_get_stats(reply);
}
END_TEST


// Tests for Create PiT
nuvo_return_t nuvo_vol_test_create_pit(struct nuvo_vol *vol, const uuid_t pit_uuid) {
    (void)vol;
    (void)pit_uuid;
    return -forced_rc; // return codes are negative
}

static Nuvo__Cmd *build_create_pit(const char *vs_uuid, const char *pit_uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REQ;
    cmd->create_pit = (Nuvo__CreatePit*) malloc(sizeof(*cmd->create_pit));
    nuvo__create_pit__init(cmd->create_pit);

    cmd->create_pit->vol_uuid = strdup(vs_uuid);
    cmd->create_pit->pit_uuid = strdup(pit_uuid);
    cmd->create_pit->resumeio = strdup("false");

    return cmd;
}

static void free_create_pit(Nuvo__Cmd *cmd)
{
    free(cmd->create_pit->vol_uuid);
    free(cmd->create_pit->pit_uuid);
    free(cmd->create_pit->resumeio);
    if (cmd->create_pit->explanation) {
        free(cmd->create_pit->explanation);
    }
    free(cmd->create_pit);
    free(cmd);
}

START_TEST(create_pit_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_pit("bogus", uuid_str2);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_pit(&api_req, nuvo_vol_test_create_pit);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_pit->has_result);
    ck_assert(NUVO__CREATE_PIT__RESULT__BAD_UUID == reply->create_pit->result);
    ck_assert(NULL != reply->create_pit->explanation);
    free_create_pit(reply);
}
END_TEST

START_TEST(create_pit_bad_puuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_create_pit(uuid_str1, "bogus");
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_create_pit(&api_req, nuvo_vol_test_create_pit);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REPLY == reply->msg_type);
    ck_assert(0 != reply->create_pit->has_result);
    ck_assert(NUVO__CREATE_PIT__RESULT__BAD_UUID == reply->create_pit->result);
    ck_assert(NULL != reply->create_pit->explanation);
    free_create_pit(reply);
}
END_TEST

START_TEST(create_pit_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_EEXIST, NUVO_EBUSY, NUVO_ENOTBLK, NUVO_ENOSPC, NUVO_EPERM };
    nuvo_return_t results[] = {
                                NUVO__CREATE_PIT__RESULT__OK,
                                NUVO__CREATE_PIT__RESULT__PIT_UUID_INUSE,
                                NUVO__CREATE_PIT__RESULT__NOT_PAUSED,
                                NUVO__CREATE_PIT__RESULT__VOLUME_NOT_FOUND,
                                NUVO__CREATE_PIT__RESULT__CANT_CREATE,
                                NUVO__CREATE_PIT__RESULT__ERROR
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_create_pit(uuid_str1, uuid_str2);
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = preprocess_cmd(cmd);
        if (!reply)
        {
            reply = nuvo_api_create_pit(&api_req, nuvo_vol_test_create_pit);
        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REPLY == reply->msg_type);
        ck_assert(0 != reply->create_pit->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__CREATE_PIT__RESULT__OK == reply->create_pit->result);
            ck_assert(NULL == reply->create_pit->explanation);
        } else {
            ck_assert(results[i] == reply->create_pit->result);
            ck_assert(NULL != reply->create_pit->explanation);
        }
        free_create_pit(reply);
    }
}
END_TEST

// Tests for Get Pit Diffs
static Nuvo__Cmd *build_diff_pits(const char *vs_uuid, const char *base_pit_uuid, const char *incr_pit_uuid, uint64_t offset)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REQ;
    cmd->get_pit_diffs = (Nuvo__GetPitDiffs*) malloc(sizeof(*cmd->get_pit_diffs));
    nuvo__get_pit_diffs__init(cmd->get_pit_diffs);

    cmd->get_pit_diffs->vol_uuid = strdup(vs_uuid);
    cmd->get_pit_diffs->base_pit_uuid = strdup(base_pit_uuid);
    cmd->get_pit_diffs->incr_pit_uuid = strdup(incr_pit_uuid);
    cmd->get_pit_diffs->offset = offset;

    return cmd;
}

static void free_diff_pits(Nuvo__Cmd *cmd) {
    free(cmd->get_pit_diffs->vol_uuid);
    if (cmd->get_pit_diffs->base_pit_uuid) {
        free(cmd->get_pit_diffs->base_pit_uuid);
    }
    if (cmd->get_pit_diffs->incr_pit_uuid) {
        free(cmd->get_pit_diffs->incr_pit_uuid);
    }
    if (cmd->get_pit_diffs->explanation) {
        free(cmd->get_pit_diffs->explanation);
    }
    free(cmd->get_pit_diffs);
    free(cmd);
}

static nuvo_return_t nuvo_vol_diff_pits_rc_check(struct nuvo_vol *vol,
                                 const uuid_t base_pit_uuid,
                                 const uuid_t incr_pit_uuid,
                                 Nuvo__GetPitDiffs *msg)
{
    (void)vol;
    (void)base_pit_uuid;
    (void)incr_pit_uuid;
    (void)msg;
    return -forced_rc;
}

START_TEST(get_pit_diffs_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_ENOTBLK, NUVO_ENOENT, NUVO_ENOMEM };
    nuvo_return_t results[] = {
                                NUVO__GET_PIT_DIFFS__RESULT__OK,
                                NUVO__GET_PIT_DIFFS__RESULT__VOLUME_NOT_FOUND,
                                NUVO__GET_PIT_DIFFS__RESULT__PIT_NOT_FOUND,
                                NUVO__GET_PIT_DIFFS__RESULT__ERROR,
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++)
    {
        forced_rc = rcs[i];
        cmd = build_diff_pits(uuid_str1, uuid_str2, uuid_str3, 0);
        api_req.cmd = cmd;
        reply = preprocess_cmd(cmd);
        if (!reply)
        {
            reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
        ck_assert(0 != reply->get_pit_diffs->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__GET_PIT_DIFFS__RESULT__OK == reply->get_pit_diffs->result);
            ck_assert(NULL == reply->get_pit_diffs->explanation);
        } else {
            ck_assert(results[i] == reply->get_pit_diffs->result);
            ck_assert(NULL != reply->get_pit_diffs->explanation);
        }
        free_diff_pits(reply);
    }
}
END_TEST

START_TEST(get_pit_diffs_bad_vol_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_diff_pits("bogus", uuid_str2, uuid_str3, 0);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_pit_diffs->has_result);
    ck_assert(NUVO__GET_PIT_DIFFS__RESULT__BAD_UUID == reply->get_pit_diffs->result);
    ck_assert(NULL != reply->get_pit_diffs->explanation);
    free_diff_pits(reply);
}
END_TEST

START_TEST(get_pit_diffs_bad_base_pit_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_diff_pits(uuid_str1, "bogus", uuid_str3, 0);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_pit_diffs->has_result);
    ck_assert(NUVO__GET_PIT_DIFFS__RESULT__BAD_UUID == reply->get_pit_diffs->result);
    ck_assert(NULL != reply->get_pit_diffs->explanation);
    free_diff_pits(reply);
}
END_TEST

START_TEST(get_pit_diffs_bad_incr_pit_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_diff_pits(uuid_str1, uuid_str2, "bogus", 0);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_pit_diffs->has_result);
    ck_assert(NUVO__GET_PIT_DIFFS__RESULT__BAD_UUID == reply->get_pit_diffs->result);
    ck_assert(NULL != reply->get_pit_diffs->explanation);
    free_diff_pits(reply);
}
END_TEST

START_TEST(get_pit_diffs_misaligned_offset)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_diff_pits(uuid_str1, uuid_str2, uuid_str3, 1);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_pit_diffs->has_result);
    ck_assert(NUVO__GET_PIT_DIFFS__RESULT__OFFSET_MISALIGNED == reply->get_pit_diffs->result);
    ck_assert(NULL != reply->get_pit_diffs->explanation);
    free_diff_pits(reply);
}
END_TEST

START_TEST(get_pit_diffs_empty_base_pit_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_diff_pits(uuid_str1, "", uuid_str3, 0);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
   }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_pit_diffs->has_result);
    ck_assert(NUVO__GET_PIT_DIFFS__RESULT__OK == reply->get_pit_diffs->result);
    ck_assert(NULL == reply->get_pit_diffs->explanation);
    free_diff_pits(reply);
}
END_TEST

START_TEST(get_pit_diffs_null_base_pit_uuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_diff_pits(uuid_str1, "", uuid_str3, 0);
    forced_rc = 0;

    free(cmd->get_pit_diffs->base_pit_uuid);
    cmd->get_pit_diffs->base_pit_uuid = NULL;
    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_diff_pits(&api_req, nuvo_vol_diff_pits_rc_check);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REPLY == reply->msg_type);
    ck_assert(0 != reply->get_pit_diffs->has_result);
    ck_assert(NUVO__GET_PIT_DIFFS__RESULT__OK == reply->get_pit_diffs->result);
    ck_assert(NULL == reply->get_pit_diffs->explanation);
    free_diff_pits(reply);
}
END_TEST

// Tests for Delete PiT
nuvo_return_t nuvo_vol_test_delete_pit(struct nuvo_vol *vol, const uuid_t pit_uuid)
{
    (void)vol;
    (void)pit_uuid;
    return -forced_rc;
}

static Nuvo__Cmd *build_delete_pit(const char *vs_uuid, const char *pit_uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REQ;
    cmd->delete_pit = (Nuvo__DeletePit*) malloc(sizeof(*cmd->delete_pit));
    nuvo__delete_pit__init(cmd->delete_pit);

    cmd->delete_pit->vol_uuid = strdup(vs_uuid);
    cmd->delete_pit->pit_uuid = strdup(pit_uuid);

    return cmd;
}

static void free_delete_pit(Nuvo__Cmd *cmd) {
    free(cmd->delete_pit->vol_uuid);
    free(cmd->delete_pit->pit_uuid);
    if (cmd->delete_pit->explanation) {
        free(cmd->delete_pit->explanation);
    }
    free(cmd->delete_pit);
    free(cmd);
}

START_TEST(delete_pit_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_ENOENT, NUVO_EBUSY, NUVO_ENOTBLK, NUVO_EPERM };
    nuvo_return_t results[] = {
                                NUVO__DELETE_PIT__RESULT__OK,
                                NUVO__DELETE_PIT__RESULT__PIT_NOT_FOUND,
                                NUVO__DELETE_PIT__RESULT__PIT_BUSY,
                                NUVO__DELETE_PIT__RESULT__VOLUME_NOT_FOUND,
                                NUVO__DELETE_PIT__RESULT__ERROR
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_delete_pit(uuid_str1, uuid_str2);
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = preprocess_cmd(cmd);
        if (!reply)
        {
            reply = nuvo_api_delete_pit(&api_req, nuvo_vol_test_delete_pit);
        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REPLY == reply->msg_type);
        ck_assert(0 != reply->delete_pit->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__DELETE_PIT__RESULT__OK == reply->delete_pit->result);
            ck_assert(NULL == reply->delete_pit->explanation);
        } else {
            ck_assert(results[i] == reply->delete_pit->result);
            ck_assert(NULL != reply->delete_pit->explanation);
        }
        free_delete_pit(reply);
    }
}
END_TEST

START_TEST(delete_pit_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_delete_pit("bogus", uuid_str2);
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_delete_pit(&api_req, nuvo_vol_test_delete_pit);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REPLY == reply->msg_type);
    ck_assert(0 != reply->delete_pit->has_result);
    ck_assert(NUVO__DELETE_PIT__RESULT__BAD_UUID == reply->delete_pit->result);
    ck_assert(NULL != reply->delete_pit->explanation);
    free_delete_pit(reply);
}
END_TEST

START_TEST(delete_pit_bad_puuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_delete_pit(uuid_str1, "bogus");
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_delete_pit(&api_req, nuvo_vol_test_delete_pit);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REPLY == reply->msg_type);
    ck_assert(0 != reply->delete_pit->has_result);
    ck_assert(NUVO__DELETE_PIT__RESULT__BAD_UUID == reply->delete_pit->result);
    ck_assert(NULL != reply->delete_pit->explanation);
    free_delete_pit(reply);
}
END_TEST

// Tests for List PiTs
nuvo_return_t nuvo_vol_test_list_pits(struct nuvo_vol *vol, Nuvo__ListPits *msg)
{
    (void)vol;
    (void)msg;
    return -forced_rc;
}

static Nuvo__Cmd *build_list_pits(const char *vs_uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REQ;
    cmd->list_pits = (Nuvo__ListPits*) malloc(sizeof(*cmd->list_pits));
    nuvo__list_pits__init(cmd->list_pits);

    cmd->list_pits->vol_uuid = strdup(vs_uuid);

    return cmd;
}

static void free_list_pits(Nuvo__Cmd *cmd) {
    free(cmd->list_pits->vol_uuid);
    if (cmd->list_pits->explanation) {
        free(cmd->list_pits->explanation);
    }
    free(cmd->list_pits);
    free(cmd);
}

START_TEST(list_pits_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_EPERM };
    nuvo_return_t results[] = {
                                NUVO__LIST_PITS__RESULT__OK,
                                NUVO__LIST_PITS__RESULT__ERROR,
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_list_pits(uuid_str1);
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = preprocess_cmd(cmd);
        if (!reply)
        {
            reply = nuvo_api_list_pits(&api_req, nuvo_vol_test_list_pits);
        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REPLY == reply->msg_type);
        ck_assert(0 != reply->list_pits->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__LIST_PITS__RESULT__OK == reply->list_pits->result);
            ck_assert(NULL == reply->list_pits->explanation);
        } else {
            ck_assert(results[i] == reply->list_pits->result);
            ck_assert(NULL != reply->list_pits->explanation);
        }
        free_list_pits(reply);
    }
}
END_TEST

START_TEST(list_pits_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_list_pits("bogus");
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_list_pits(&api_req, nuvo_vol_test_list_pits);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REPLY == reply->msg_type);
    ck_assert(0 != reply->list_pits->has_result);
    ck_assert(NUVO__LIST_PITS__RESULT__BAD_UUID == reply->list_pits->result);
    ck_assert(NULL != reply->list_pits->explanation);
    free_list_pits(reply);
}
END_TEST

//Test list vols

nuvo_return_t nuvo_vol_test_list_vols(Nuvo__ListVols *msg)
{
    (void)msg;
    return -forced_rc;
}

 /* worker function for getting the list vols for nuvo api
  * for the ENOMEM case */

nuvo_return_t list_vols_work_nomem(Nuvo__ListVols *msg)
{
    char uuid_str[UUID_UNPARSED_LEN];  // max UUID size
    struct nuvo_vol * vol_list[NUVO_MAX_VOL_SERIES_OPEN];
    int n_vols = 0;
    int cnt = nuvo_vol_list_vols(vol_list);

    if (!cnt)
    {
        return (-NUVO_E_NO_VOLUME);
    }
    for (int i = 0; i < cnt; i++)
    {

        msg->vols[n_vols] = malloc(sizeof(*msg->vols[n_vols]));

        /* INJECT ERROR on the second volume to test NUVO_ENOMEM */
        if (msg->vols[n_vols] && n_vols > 0)
        {
            free(msg->vols[n_vols]);
            msg->vols[n_vols] = NULL;
        }

        if (!msg->vols[n_vols])
        {
            /* nuvo__cmd__free_unpacked() gets called after the reply is sent
             * which takes care of the freeing of the memory alloced till now
             */
            return (-NUVO_ENOMEM);
        }

        nuvo__list_vols__vol__init(msg->vols[n_vols]);

        nuvo_mutex_lock(&vol_list[i]->mutex);

        if (NUVO_VOL_FREE != vol_list[i]->type)
        {
            uuid_unparse(vol_list[i]->vs_uuid, uuid_str);
            msg->vols[n_vols]->vol_uuid = strdup(uuid_str);
            n_vols++;
        }

        nuvo_mutex_unlock(&vol_list[i]->mutex);
    }

    msg->n_vols = n_vols;
    return 0;
}

static Nuvo__Cmd *build_list_vols()
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_VOLS_REQ;
    cmd->list_vols = (Nuvo__ListVols*) malloc(sizeof(*cmd->list_vols));
    nuvo__list_vols__init(cmd->list_vols);

    return cmd;
}

static void free_list_vols(Nuvo__Cmd *cmd) {

    if (cmd->list_vols->explanation) {
        free(cmd->list_vols->explanation);
    }

    Nuvo__ListVols *msg = cmd->list_vols;

    for(unsigned int i=0 ; i < msg->n_vols; i++)
    {
        free(msg->vols[i]);
    }

    free(cmd->list_vols);
    free(cmd);
}

START_TEST(list_vols_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_ENOMEM};
    nuvo_return_t results[] = {
                                NUVO__LIST_VOLS__RESULT__OK,
                                NUVO__LIST_VOLS__RESULT__ERROR,
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;
    nuvo_mutex_init(&vol_table.mutex);

    for (i = 0; i < num_rcs; i++) {
        cmd = build_list_vols();
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        if (rcs[i] == NUVO_ENOMEM)
        {
            reply = nuvo_api_list_vols(&api_req, list_vols_work_nomem);
        }
        else
        {
            reply = nuvo_api_list_vols(&api_req, nuvo_vol_test_list_vols);

        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__LIST_VOLS_REPLY == reply->msg_type);
        ck_assert(0 != reply->list_vols->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__LIST_VOLS__RESULT__OK == reply->list_vols->result);
            ck_assert(NULL == reply->list_vols->explanation);
        } else {
            ck_assert(results[i] == reply->list_vols->result);
            ck_assert(NULL != reply->list_vols->explanation);
        }
        free_list_vols(reply);
    }
    nuvo_mutex_destroy(&vol_table.mutex);
}
END_TEST

// Tests for Pause I/O
nuvo_return_t nuvo_vol_test_pause_io(struct nuvo_vol *vol)
{
    (void)vol;
    return -forced_rc;
}

static Nuvo__Cmd *build_pause_io(const char *vs_uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REQ;
    cmd->pause_io = (Nuvo__PauseIo*) malloc(sizeof(*cmd->pause_io));
    nuvo__pause_io__init(cmd->pause_io);

    cmd->pause_io->vol_uuid = strdup(vs_uuid);

    return cmd;
}

static void free_pause_io(Nuvo__Cmd *cmd) {
    free(cmd->pause_io->vol_uuid);
    if (cmd->pause_io->explanation) {
        free(cmd->pause_io->explanation);
    }
    free(cmd->pause_io);
    free(cmd);
}

START_TEST(pause_io_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_ENOTBLK, NUVO_ETIMEDOUT, NUVO_EPERM };
    nuvo_return_t results[] = {
                                NUVO__PAUSE_IO__RESULT__OK,
                                NUVO__PAUSE_IO__RESULT__VOLUME_NOT_FOUND,
                                NUVO__PAUSE_IO__RESULT__TIMED_OUT,
                                NUVO__PAUSE_IO__RESULT__ERROR
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_pause_io(uuid_str1);
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = preprocess_cmd(cmd);
        if (!reply)
        {
            reply = nuvo_api_pause_io(&api_req, nuvo_vol_test_pause_io);
        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REPLY == reply->msg_type);
        ck_assert(0 != reply->pause_io->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__PAUSE_IO__RESULT__OK == reply->pause_io->result);
            ck_assert(NULL == reply->pause_io->explanation);
        } else {
            ck_assert(results[i] == reply->pause_io->result);
            ck_assert(NULL != reply->pause_io->explanation);
        }
        free_pause_io(reply);
    }
}
END_TEST

START_TEST(pause_io_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_pause_io("bogus");
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_pause_io(&api_req, nuvo_vol_test_pause_io);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REPLY == reply->msg_type);
    ck_assert(0 != reply->pause_io->has_result);
    ck_assert(NUVO__PAUSE_IO__RESULT__BAD_UUID == reply->pause_io->result);
    ck_assert(NULL != reply->pause_io->explanation);
    free_pause_io(reply);
}
END_TEST

// Tests for Resume I/O
nuvo_return_t nuvo_vol_test_resume_io(struct nuvo_vol *vol)
{
    (void)vol;
    return -forced_rc;
}

static Nuvo__Cmd *build_resume_io(const char *vs_uuid)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REQ;
    cmd->resume_io = (Nuvo__ResumeIo*) malloc(sizeof(*cmd->resume_io));
    nuvo__resume_io__init(cmd->resume_io);

    cmd->resume_io->vol_uuid = strdup(vs_uuid);

    return cmd;
}

static void free_resume_io(Nuvo__Cmd *cmd) {
    free(cmd->resume_io->vol_uuid);
    if (cmd->resume_io->explanation) {
        free(cmd->resume_io->explanation);
    }
    free(cmd->resume_io);
    free(cmd);
}

START_TEST(resume_io_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_EINVAL, NUVO_ENOTBLK, NUVO_EPERM };
    nuvo_return_t results[] = {
                                NUVO__RESUME_IO__RESULT__OK,
                                NUVO__RESUME_IO__RESULT__NOT_PAUSED,
                                NUVO__RESUME_IO__RESULT__VOLUME_NOT_FOUND,
                                NUVO__RESUME_IO__RESULT__ERROR
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_resume_io(uuid_str1);
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = preprocess_cmd(cmd);
        if (!reply)
        {
            reply = nuvo_api_resume_io(&api_req, nuvo_vol_test_resume_io);
        }

        ck_assert(NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REPLY == reply->msg_type);
        ck_assert(0 != reply->resume_io->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__RESUME_IO__RESULT__OK == reply->resume_io->result);
            ck_assert(NULL == reply->resume_io->explanation);
        } else {
            ck_assert(results[i] == reply->resume_io->result);
            ck_assert(NULL != reply->resume_io->explanation);
        }
        free_resume_io(reply);
    }
}
END_TEST

START_TEST(resume_io_bad_vsuuid)
{
    struct nuvo_api_req api_req;
    Nuvo__Cmd *cmd = build_resume_io("bogus");
    forced_rc = 0;

    api_req.cmd = cmd;
    Nuvo__Cmd *reply = preprocess_cmd(cmd);
    if (!reply)
    {
        reply = nuvo_api_resume_io(&api_req, nuvo_vol_test_resume_io);
    }

    ck_assert(NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REPLY == reply->msg_type);
    ck_assert(0 != reply->resume_io->has_result);
    ck_assert(NUVO__RESUME_IO__RESULT__BAD_UUID == reply->resume_io->result);
    ck_assert(NULL != reply->resume_io->explanation);
    free_resume_io(reply);
}
END_TEST

// Tests for LogLevel
nuvo_return_t nuvo_vol_test_log_level(const char* module_name, uint32_t level)
{
    (void)module_name;
    (void)level;
    return -forced_rc;
}

static Nuvo__Cmd *build_log_level(const char *module_name, uint32_t level)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REQ;
    cmd->log_level = (Nuvo__LogLevel*) malloc(sizeof(*cmd->log_level));
    nuvo__log_level__init(cmd->log_level);

    cmd->log_level->module_name = strdup(module_name);
    cmd->log_level->level = level;

    return cmd;
}

static void free_log_level(Nuvo__Cmd *cmd) {
    free(cmd->log_level->module_name);
    if (cmd->log_level->explanation) {
        free(cmd->log_level->explanation);
    }
    free(cmd->log_level);
    free(cmd);
}


START_TEST(log_level_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_E_NO_MODULE };
    nuvo_return_t results[] = {
                                NUVO__LOG_LEVEL__RESULT__OK,
                                NUVO__LOG_LEVEL__RESULT__NO_MODULE
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_log_level("mfst", 23);
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = nuvo_api_log_level(&api_req, nuvo_vol_test_log_level);

        ck_assert(NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REPLY == reply->msg_type);
        ck_assert(0 != reply->log_level->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__LOG_LEVEL__RESULT__OK == reply->log_level->result);
            ck_assert(NULL == reply->log_level->explanation);
        } else {
            ck_assert(results[i] == reply->log_level->result);
            ck_assert(NULL != reply->log_level->explanation);
        }
        free_log_level(reply);
    }
}
END_TEST

// Tests for Node Status
nuvo_return_t nuvo_vol_test_node_status()
{
    return -forced_rc;
}

static Nuvo__Cmd *build_node_status()
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REQ;
    cmd->node_status = (Nuvo__NodeStatus*) malloc(sizeof(*cmd->node_status));
    nuvo__node_status__init(cmd->node_status);
    return cmd;
}

static void free_node_status(Nuvo__Cmd *cmd) {
    nuvo__cmd__free_unpacked(cmd,  NULL);
}

START_TEST(node_status_rc_check)
{
    struct nuvo_api_req api_req;
    nuvo_return_t rcs[] = { 0, NUVO_ENOMEM };
    nuvo_return_t results[] = {
                                NUVO__NODE_STATUS__RESULT__OK,
                                NUVO__NODE_STATUS__RESULT__ENOMEM
                              };

    int num_rcs = sizeof(rcs)/sizeof(nuvo_return_t);
    int i;
    Nuvo__Cmd *reply;
    Nuvo__Cmd *cmd;

    for (i = 0; i < num_rcs; i++) {
        cmd = build_node_status();
        forced_rc = rcs[i];

        api_req.cmd = cmd;
        reply = nuvo_api_node_status(&api_req, nuvo_vol_test_node_status);

        ck_assert(NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REPLY == reply->msg_type);
        ck_assert(0 != reply->node_status->has_result);
        if (forced_rc == 0) {
            ck_assert(NUVO__NODE_STATUS__RESULT__OK == reply->node_status->result);
            ck_assert(NULL == reply->node_status->explanation);
        } else {
            ck_assert(results[i] == reply->node_status->result);
            ck_assert(NULL != reply->node_status->explanation);
        }
        free_node_status(reply);
    }
}
END_TEST

START_TEST(cmd_category_test)
{
    Nuvo__Cmd *cmd = (Nuvo__Cmd*) malloc(sizeof(*cmd));
    nuvo__cmd__init(cmd);

    // Commands that need to allocate volume structure
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_PASSTHROUGH_REQ;
    ck_assert(cmd_need_alloc_vol(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_VOLUME_REQ;
    ck_assert(cmd_need_alloc_vol(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__OPEN_VOLUME_REQ;
    ck_assert(cmd_need_alloc_vol(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DESTROY_VOL_REQ;
    ck_assert(cmd_need_alloc_vol(cmd));

    // Commands that are volume specific
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__EXPORT_LUN_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__UNEXPORT_LUN_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_PARCELS_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__ALLOC_CACHE_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CLOSE_VOL_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_VOLUME_STATS_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__MANIFEST_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CREATE_PIT_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_PIT_DIFF_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DELETE_PIT_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_PITS_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__PAUSE_IO_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__RESUME_IO_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_SUMMARY_REQ;
    ck_assert(cmd_is_vol_specific(cmd));

    Nuvo__Cmd *cmd2 = build_get_stats(false, true, false, uuid_str3);
    cmd2->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ;
    ck_assert(cmd_is_vol_specific(cmd2));
    free_get_stats(cmd2);

    // Commands that are not volume specific
    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_DEVICE_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CLOSE_DEVICE_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__FORMAT_DEVICE_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DEVICE_LOCATION_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_LOCATION_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_INIT_DONE_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__USE_NODE_UUID_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__CAPABILITIES_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LIST_VOLS_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__LOG_LEVEL_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__NODE_STATUS_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    cmd->msg_type = NUVO__CMD__MESSAGE_TYPE__DEBUG_TRIGGER_REQ;
    ck_assert(!cmd_is_vol_specific(cmd));

    Nuvo__Cmd *cmd3 = build_get_stats(true, true, false, uuid_str3);
    cmd3->msg_type = NUVO__CMD__MESSAGE_TYPE__GET_STATS_REQ;
    ck_assert(!cmd_is_vol_specific(cmd3));
    free_get_stats(cmd3);

    free(cmd);
}
END_TEST

Suite * nuvo_api_suite(void)
{
    Suite *s;
    TCase *tc_use_device;
    TCase *tc_use_cache_device;
    TCase *tc_format_device;
    TCase *tc_device_location;
    TCase *tc_node_location;
    TCase *tc_open_passthrough;
    TCase *tc_export_lun;
    TCase *tc_unexport_lun;
    TCase *tc_open_parcel_vol;
    TCase *tc_destroy_vol;
    TCase *tc_create_parcel_vol;
    TCase *tc_alloc_parcels;
    TCase *tc_get_stats;
    TCase *tc_create_pit;
    TCase *tc_get_pit_diffs;
    TCase *tc_delete_pit;
    TCase *tc_list_pits;
    TCase *tc_list_vols;
    TCase *tc_pause_io;
    TCase *tc_resume_io;
    TCase *tc_log_level;
    TCase *tc_node_status;
    TCase *tc_cmd_category;

    s = suite_create("NuvoApi");

    tc_use_device = tcase_create("UseDevice");
    tcase_add_test(tc_use_device, use_device_basic_hdd);
    tcase_add_test(tc_use_device, use_device_basic);
    tcase_add_test(tc_use_device, use_device_device_already_open);
    tcase_add_test(tc_use_device, use_device_basic_has_result);
    tcase_add_test(tc_use_device, use_device_basic_has_explanation);
    tcase_add_test(tc_use_device, use_device_bad_uuid);
    tcase_add_test(tc_use_device, use_device_table_full);
    tcase_add_test(tc_use_device, use_device_device_exists);
    tcase_add_test(tc_use_device, use_device_unknown_device);
    tcase_add_test(tc_use_device, use_device_random_error);
    tcase_add_test(tc_use_device, use_device_multi_request);
    suite_add_tcase(s, tc_use_device);


    tc_use_cache_device = tcase_create("UseCacheDevice");
    tcase_add_test(tc_use_cache_device, use_cache_device_success);
    tcase_add_test(tc_use_cache_device, use_cache_device_basic_has_result);
    tcase_add_test(tc_use_cache_device, use_cache_device_basic_has_explanation);
    tcase_add_test(tc_use_cache_device, use_cache_device_bad_uuid);
    tcase_add_test(tc_use_cache_device, use_cache_device_table_full);
    tcase_add_test(tc_use_cache_device, use_cache_device_device_exists);
    tcase_add_test(tc_use_cache_device, use_cache_device_unknown_device);
    tcase_add_test(tc_use_cache_device, use_cache_device_random_error);
    suite_add_tcase(s, tc_use_cache_device);

    tc_format_device = tcase_create("FormatDevice");
    tcase_add_test(tc_format_device, format_device_basic);
    tcase_add_test(tc_format_device, format_device_basic_has_result);
    tcase_add_test(tc_format_device, format_device_basic_has_explanation);
    tcase_add_test(tc_format_device, format_device_basic_bad_uuid);
    tcase_add_test(tc_format_device, format_device_basic_no_device);
    tcase_add_test(tc_format_device, format_device_basic_error);
    suite_add_tcase(s, tc_format_device);

    tc_device_location = tcase_create("DeviceLocation");
    tcase_add_test(tc_device_location, device_location_basic);
    tcase_add_test(tc_device_location, device_location_basic_has_result);
    tcase_add_test(tc_device_location, device_location_basic_has_explanation);
    tcase_add_test(tc_device_location, device_location_bad_uuid1);
    tcase_add_test(tc_device_location, device_location_bad_uuid2);
    tcase_add_test(tc_device_location, device_location_table_full);
    tcase_add_test(tc_device_location, device_location_random_error);
    tcase_add_test(tc_device_location, device_location_multi);
    suite_add_tcase(s, tc_device_location);

    tc_node_location = tcase_create("NodeLocation");
    tcase_add_test(tc_node_location, node_location_basic);
    tcase_add_test(tc_node_location, node_location_has_result);
    tcase_add_test(tc_node_location, node_location_has_explanation);
    tcase_add_test(tc_node_location, node_location_port_out_of_range);
    tcase_add_test(tc_node_location, node_location_invalid_uuid);
    tcase_add_test(tc_node_location, node_location_table_full);
    tcase_add_test(tc_node_location, node_location_random_error);
    tcase_add_test(tc_node_location, node_location_multi);
    suite_add_tcase(s, tc_node_location);

    tc_open_passthrough = tcase_create("Open Passthrough");
    tcase_add_test(tc_open_passthrough, open_passthrough_basic);
    tcase_add_test(tc_open_passthrough, open_passthrough_bad_uuid);
    tcase_add_test(tc_open_passthrough, open_passthrough_weird_size);
    // should test more
    suite_add_tcase(s, tc_open_passthrough);

    tc_export_lun = tcase_create("Export Lun");
    tcase_add_test(tc_export_lun, export_lun_basic);
    tcase_add_test(tc_export_lun, export_bad_vsuuid);
    tcase_add_test(tc_export_lun, export_bad_puuid);
    // should test more
    suite_add_tcase(s, tc_export_lun);

    tc_unexport_lun = tcase_create("Unexport Lun");
    tcase_add_test(tc_unexport_lun, unexport_lun_basic);
    tcase_add_test(tc_unexport_lun, unexport_bad_vsuuid);
    tcase_add_test(tc_unexport_lun, unexport_bad_puuid);
    // should test more
    suite_add_tcase(s, tc_unexport_lun);

    tc_create_parcel_vol = tcase_create("Create Volume");
    tcase_add_test(tc_create_parcel_vol, create_volume_basic);
    tcase_add_test(tc_create_parcel_vol, create_volume_bad_vs_uuid);
    tcase_add_test(tc_create_parcel_vol, create_volume_bad_rd_uuid);
    tcase_add_test(tc_create_parcel_vol, create_volume_bad_rp_uuid);
    tcase_add_test(tc_create_parcel_vol, create_volume_random_error);
    tcase_add_test(tc_create_parcel_vol, create_log_volume_size_0);
    tcase_add_test(tc_create_parcel_vol, create_log_volume_size_wonky);
    // should test has result
    // should test has explanation
    suite_add_tcase(s, tc_create_parcel_vol);

    tc_list_vols = tcase_create("List Vols");
    tcase_add_test(tc_list_vols, list_vols_rc_check);
    suite_add_tcase(s, tc_list_vols);

    tc_open_parcel_vol = tcase_create("Open Parcel Volume");
    tcase_add_test(tc_open_parcel_vol, open_parcel_volume_basic);
    tcase_add_test(tc_open_parcel_vol, open_parcel_volume_bad_vs_uuid);
    tcase_add_test(tc_open_parcel_vol, open_parcel_volume_bad_rp_uuid);
    tcase_add_test(tc_open_parcel_vol, open_parcel_volume_bad_rd_uuid);
    tcase_add_test(tc_open_parcel_vol, open_parcel_volume_random_error);
    // should test has result
    // should test has explanation
    suite_add_tcase(s, tc_open_parcel_vol);

    tc_destroy_vol = tcase_create("Open Parcel Volume");
    tcase_add_test(tc_destroy_vol, destroy_volume_basic);
    tcase_add_test(tc_destroy_vol, destroy_volume_bad_vs_uuid);
    tcase_add_test(tc_destroy_vol, destroy_volume_bad_rp_uuid);
    tcase_add_test(tc_destroy_vol, destroy_volume_bad_rd_uuid);
    tcase_add_test(tc_destroy_vol, destroy_volume_random_error);
    // should test has result
    // should test has explanation
    suite_add_tcase(s, tc_destroy_vol);

    tc_alloc_parcels = tcase_create("Alloc Parcels");
    tcase_add_test(tc_alloc_parcels, alloc_parcels_basic);
    tcase_add_test(tc_alloc_parcels, alloc_parcels_bad_vs);
    tcase_add_test(tc_alloc_parcels, alloc_parcels_bad_device);
    // should test has result
    // should test has explanation
    suite_add_tcase(s, tc_alloc_parcels);

    tc_get_stats = tcase_create("Get Stats");
    tcase_add_test(tc_get_stats, get_stats_basic);
    tcase_add_test(tc_get_stats, get_stats_bad_uuid);
    tcase_add_test(tc_get_stats, get_stats_error);
    tcase_add_test(tc_get_stats, get_stats_has_explanation);
    suite_add_tcase(s, tc_get_stats);

    tc_create_pit = tcase_create("Create PiT");
    tcase_add_test(tc_create_pit, create_pit_rc_check);
    tcase_add_test(tc_create_pit, create_pit_bad_vsuuid);
    tcase_add_test(tc_create_pit, create_pit_bad_puuid);
    suite_add_tcase(s, tc_create_pit);

    tc_get_pit_diffs = tcase_create("Get PiT Diffs");
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_rc_check);
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_bad_vol_uuid);
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_bad_base_pit_uuid);
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_bad_incr_pit_uuid);
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_misaligned_offset);
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_empty_base_pit_uuid);
    tcase_add_test(tc_get_pit_diffs, get_pit_diffs_null_base_pit_uuid);
    suite_add_tcase(s, tc_get_pit_diffs);

    tc_delete_pit = tcase_create("Delete PiT");
    tcase_add_test(tc_delete_pit, delete_pit_rc_check);
    tcase_add_test(tc_delete_pit, delete_pit_bad_vsuuid);
    tcase_add_test(tc_delete_pit, delete_pit_bad_puuid);
    suite_add_tcase(s, tc_delete_pit);

    tc_list_pits = tcase_create("List PiT");
    tcase_add_test(tc_list_pits, list_pits_rc_check);
    tcase_add_test(tc_list_pits, list_pits_bad_vsuuid);
    suite_add_tcase(s, tc_list_pits);

    tc_pause_io = tcase_create("Pause I/O");
    tcase_add_test(tc_pause_io, pause_io_rc_check);
    tcase_add_test(tc_pause_io, pause_io_bad_vsuuid);
    suite_add_tcase(s, tc_pause_io);

    tc_resume_io = tcase_create("Resume I/O");
    tcase_add_test(tc_resume_io, resume_io_rc_check);
    tcase_add_test(tc_resume_io, resume_io_bad_vsuuid);
    suite_add_tcase(s, tc_resume_io);

    tc_log_level = tcase_create("Log Level");
    tcase_add_test(tc_log_level, log_level_rc_check);
    suite_add_tcase(s, tc_log_level);

    tc_node_status = tcase_create("Node Status");
    tcase_add_test(tc_node_status, node_status_rc_check);
    suite_add_tcase(s, tc_node_status);


    tc_cmd_category = tcase_create("Cmd Category");
    tcase_add_test(tc_cmd_category, cmd_category_test);
    suite_add_tcase(s, tc_cmd_category);
    return s;
}
