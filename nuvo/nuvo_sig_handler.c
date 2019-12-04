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
#include "nuvo_sig_handler.h"
#include <signal.h>
#include <string.h>

/*
 * TODO - Put this signal handler stuff and teh other siognal handler
 * into one file together.   That will require moving the nuvo_exit stuff
 * out of the nuvo_api file so that the linking of test will work properly,
 * so doing it now will create a lot of moving code churn that
 * will obfuscate this commit.
 */

struct nuvo_exit_ctrl_s *sig_exit_ctrl;
static void exit_handler_kill_nuvo(int sig)
{
    (void)sig;
    if (sig_exit_ctrl != NULL)
    {
        nuvo_exiting_set(sig_exit_ctrl);
    }
}

static void do_nothing(int sig)
{
    (void)sig;
}

static int set_one_signal_handler(int sig, void (*handler)(int), int remove)
{
    struct sigaction sa;
    struct sigaction old_sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = remove ? SIG_DFL : handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    if (sigaction(sig, NULL, &old_sa) == -1)
    {
        NUVO_ERROR_PRINT("Could not get old signal handler.");
        return (-1);
    }

    if (old_sa.sa_handler == (remove ? handler : SIG_DFL) &&
        sigaction(sig, &sa, NULL) == -1)
    {
        NUVO_ERROR_PRINT("Could not set new signal handler.");
        return (-1);
    }
    return (0);
}

/**
 * Set signal handlers that allow us to call the exit function which
 * triggers unexporting, etc.
 *
 * \param exit_ctrl The exit control struct.
 * \retval 0 on success
 * \retval -1 on failure.
 */
int nuvo_register_signal_handlers_fuse(struct nuvo_exit_ctrl_s *exit_ctrl)
{
    sig_exit_ctrl = exit_ctrl;
    if (set_one_signal_handler(SIGHUP, exit_handler_kill_nuvo, 0) == -1 ||
        set_one_signal_handler(SIGINT, exit_handler_kill_nuvo, 0) == -1 ||
        set_one_signal_handler(SIGTERM, exit_handler_kill_nuvo, 0) == -1 ||
        set_one_signal_handler(SIGPIPE, do_nothing, 0) == -1)
    {
        return (-1);
    }

    return (0);
}

/**
 * Remove signal handlers that allow us to call the exit function which
 * triggers unexporting, etc.
 */
void nuvo_remove_signal_handlers_fuse()
{
    set_one_signal_handler(SIGHUP, exit_handler_kill_nuvo, 1);
    set_one_signal_handler(SIGINT, exit_handler_kill_nuvo, 1);
    set_one_signal_handler(SIGTERM, exit_handler_kill_nuvo, 1);
    set_one_signal_handler(SIGPIPE, do_nothing, 1);
}
