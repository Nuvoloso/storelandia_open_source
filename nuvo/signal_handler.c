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
 * \file signal_handler.c
 * \brief functions for changing program signal handlers
 */
#include <stdio.h>
#include <signal.h>
#include <stdint.h>

int signals_registered_flag = 0;

/**
 *
 * \fn void nuvo_void_handler(int signum)
 * \brief signal handler that does nothing.
 *
 * Used for interrupting blocked syscall.
 *
 * \return none
 */
void nuvo_void_handler(int signum)
{
    (void)signum;
}

/**
 *
 * \fn int_fast64_t nuvo_register_signal_handlers()
 * \brief register program signal handlers
 *
 * not mt safe.
 *
 * \return 0 on success, otherwise -1.
 */
int_fast64_t nuvo_register_signal_handlers()
{
    int ret = 0;

    if (!signals_registered_flag)
    {
        struct sigaction sa;

        signals_registered_flag = 1;

        /* register handler for SIGUSR1 */
        sa.sa_handler = nuvo_void_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        if ((ret = sigaction(SIGUSR1, &sa, NULL)) != 0)
        {
            ret = -1;
            signals_registered_flag = 0;
        }
    }
    return (ret);
}
