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

#include "nuvo_fuse.h"
#include "nuvo_api.h"
#include "nuvo_exit.h"
#include "parcel_manager.h"
#include "nuvo_pr.h"
#include "map.h"
#include "manifest.h"
#include "nuvo_range_lock.h"
#include "nuvo_sig_handler.h"
#include "nuvo_vol_series.h"
#include "segment.h"
#include "space.h"
#include "cache.h"
#include "fault_inject.h"

#include <version_nuvo.h>
#include <fuse3/fuse.h>
#include <fuse3/fuse_common.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

struct nuvo_cmd_line {
    char    *socket_name;
    uuid_t   node_uuid;
    bool     node_uuid_set;
    uint16_t port;
    bool     port_set;
};

#define SOCKET_OPTION       "socket="
#define NODE_ID_OPTION      "nodeuuid="
#define NODE_PORT_OPTION    "port="
static int nuvo_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    struct nuvo_cmd_line *ncl = (struct nuvo_cmd_line *)data;

    (void)outargs;
    if (key == FUSE_OPT_KEY_NONOPT && 0 == strncmp(arg, SOCKET_OPTION, strlen(SOCKET_OPTION)))
    {
        ncl->socket_name = strdup(arg + strlen(SOCKET_OPTION));
        return (0);
    }
    if (key == FUSE_OPT_KEY_NONOPT && 0 == strncmp(arg, NODE_ID_OPTION, strlen(NODE_ID_OPTION)))
    {
        int ret = uuid_parse(arg + strlen(NODE_ID_OPTION), ncl->node_uuid);
        if (ret == 0)
        {
            ncl->node_uuid_set = true;
            return (0);
        }
        return (1);
    }
    if (key == FUSE_OPT_KEY_NONOPT && 0 == strncmp(arg, NODE_PORT_OPTION, strlen(NODE_PORT_OPTION)))
    {
        unsigned long int port = strtoul(arg + strlen(NODE_PORT_OPTION), NULL, 10);
        if (port > 0 && port < UINT16_MAX)
        {
            ncl->port_set = true;
            ncl->port = port;
            return (0);
        }
        return (1);
    }
    return (1);
}

extern char *nuvo_main_directory;

int main(int argc, char *argv[])
{
    struct fuse_args         args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    struct nuvo_cmd_line     nuvo_cmd;
    struct nuvo_api_params   api_params;
    struct nuvo_exit_ctrl_s  exit_ctrl;
    int err = -1;
    int api_ret = 0;

    if (NULL != getenv("NUVO_WAIT_FOR_GDB") && 0 == strcmp("true", getenv("NUVO_WAIT_FOR_GDB")))
    {
        nuvo_wait_for_gdb();
    }

    memset(&nuvo_cmd, 0, sizeof(nuvo_cmd));
    memset(&api_params, 0, sizeof(api_params));

    if (nuvo_alloc_version_str() != 0)
    {
        goto free_exit;
    }

    fuse_opt_parse(&args, &nuvo_cmd, NULL, nuvo_opt_proc);
    if (fuse_parse_cmdline(&args, &opts) == -1)
    {
        goto free_exit;
    }

    if (opts.show_help)
    {
        if (args.argv[0] != NULL && args.argv[0][0] != '\0')
        {
            printf("Usage: %s [options] mountpoint\n", basename(args.argv[0]));
            printf("Options:\n");
            fuse_cmdline_help();
            fuse_lowlevel_help();
        }
        err = 0;
        goto free_exit;
    }
    else if (opts.show_version)
    {
        fuse_lowlevel_version();
        err = 0;
        goto free_exit;
    }

    if (nuvo_cmd.socket_name)
    {
        api_params.socket_name = strdup(nuvo_cmd.socket_name);
    }
    else
    {
        api_params.socket_name = strdup(NUVO_DEFAULT_API_SOCKET_NAME);
    }

    if (opts.mountpoint == NULL)
    {
        NUVO_ERROR_PRINT("no mountpoint specified");
        goto free_exit;
    }
    nuvo_main_directory = opts.mountpoint;
    opts.mountpoint = NULL;

    // DAEMONIZE
    if (0 != fuse_daemonize(opts.foreground))
    {
        NUVO_ERROR_PRINT("daemonization failed");
        goto free_exit;
    }
    nuvo_exiting_init(&exit_ctrl);
    if (0 != nuvo_register_signal_handlers_fuse(&exit_ctrl))
    {
        goto free_exit;
    }
    // TODO - Go to correct place.

    // START UP LOCKS, PM, PR, MAP
    if (0 != nuvo_range_lock_freelist_init())
    {
        NUVO_ERROR_PRINT("range lock freelist failed");
        goto deregister_signals;
    }
    if (0 != nuvo_pm_init())
    {
        NUVO_ERROR_PRINT("nuvo_pm_init failed");
        goto lock_free_list_destroy;
    }

    int pr_initialized = 0;
    if (nuvo_cmd.port_set)
    {
        if (0 != nuvo_pr_init(nuvo_cmd.port))
        {
            NUVO_ERROR_PRINT("nuvo_pr_init failed");
            goto pm_destroy;
        }
        else
        {
            nuvo_pr_set_vol_notify_fp(nuvo_vol_update_parcel_status);
            pr_initialized = 1;
        }
    }
    else
    {
        NUVO_ERROR_PRINT("Port id not supplied. Not starting parcel router.");
    }

    if (0 != nuvo_io_concat_pool_init(500))
    {
        NUVO_ERROR_PRINT("nuvo_io_concat_pool_init failed");
        goto pr_shutdown;
    }

    if (nuvo_map_init() < 0)
    {
        NUVO_ERROR_PRINT("nuvo_map_init failed");
        goto concat_pool_shutdown;
    }

    if (nuvo_space_init() < 0)
    {
        NUVO_ERROR_PRINT("nuvo_space_init failed");
        goto map_shutdown;
    }
    if (nuvo_cache_init() < 0)
    {
        NUVO_ERROR_PRINT("nuvo_cache_init failed");
        goto space_shutdown;
    }

    // If node uuid is passed in on the command line, use it.
    // Otherwise, wait for it to be set via the API.
    api_params.full_enable = 0;
    if (nuvo_cmd.node_uuid_set)
    {
        // Setting the node uuid enables the parcel router.
        nuvo_pr_set_node_uuid(nuvo_cmd.node_uuid);
        nuvo_pr_enable(true);
        api_params.full_enable = 1;
    }
    else
    {
        // Until people understand the new behavior.
        NUVO_ERROR_PRINT("Node UUID not supplied. PARCEL ROUTER NOT STARTED. Waiting for node uuid.");
    }

    api_params.exit_ctrl = &exit_ctrl;

    // Initialize API worker thread and related items.
    api_ret = nuvo_vol_api_init(&api_params);
    if (api_ret)
    {
        NUVO_ERROR_PRINT("Volume API init failed");
        goto cache_shutdown;
    }

    // Start API dispatcher thread.
    pthread_t api_thread_id;
    api_ret = pthread_create(&api_thread_id, NULL, nuvo_api_thread, &api_params);
    if (api_ret)
    {
        nuvo_exiting_destroy(&exit_ctrl);
        NUVO_ERROR_PRINT("API thread creation failed");
        goto vol_api_shutdown;
    }
    nuvo_exiting_wait(&exit_ctrl);
    err = 0;
    api_ret = pthread_join(api_thread_id, NULL);

    nuvo_exiting_destroy(&exit_ctrl);

vol_api_shutdown:
    nuvo_vol_api_destroy();
cache_shutdown:
    nuvo_cache_destroy();
space_shutdown:
    nuvo_space_halt();
map_shutdown:
    nuvo_map_shutdown();
concat_pool_shutdown:
    nuvo_io_concat_pool_destroy();
pr_shutdown:
    if (pr_initialized)
    {
        nuvo_pr_shutdown();
    }
pm_destroy:
    nuvo_pm_destroy();
lock_free_list_destroy:
    nuvo_range_lock_freelist_destroy();
deregister_signals:
    nuvo_remove_signal_handlers_fuse();
free_exit:
    nuvo_free_version_str();
    nuvo_test_fi_free();

    if (nuvo_main_directory != NULL)
    {
        free(nuvo_main_directory);
    }
    if (api_params.socket_name != NULL)
    {
        free(api_params.socket_name);
    }
    if (nuvo_cmd.socket_name != NULL)
    {
        free(nuvo_cmd.socket_name);
    }
    fuse_opt_free_args(&args);

    NUVO_ERROR_PRINT("Shutdown Complete.");

    return ((err || api_ret) ? 1 : 0);
}
